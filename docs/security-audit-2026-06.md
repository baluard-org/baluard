# Baluard Security Audit

**Date:** 2026-06-10
**Auditor:** TARS (automated security review, Opus 4.8)
**Scope:** Full codebase (`crates/baluard-core`, `crates/baluard-cli`, `crates/baluard-daemon`, `desktop/`) plus `docs/`.
**Method:** 5 parallel domain audits (storage, IPC/daemon, sync/providers, frontend/import, recovery/devices/emergency) plus direct source read of the crypto core. The crown-jewel finding (nonce reuse, C1) was verified personally in source, not delegated.

---

## Executive Summary

The cryptographic primitives Baluard chooses and implements are sound: Argon2id with validated parameters, an HKDF key hierarchy with clean domain separation, `mlock`'d + zeroized key types, Ed25519 signatures, AES-256-GCM with AAD identity binding. **The risk does not live in the primitives — it lives in how they are composed.**

The serious findings cluster in four areas:

1. **Multi-device nonce derivation** — the deterministic nonce scheme produces AES-GCM nonce reuse during the product's headline feature (concurrent multi-device edit), which is a confidentiality break, not a theoretical one.
2. **Remote-trust integrity gaps** — the non-fast-forward merge path skips the commit signature verification that the fast-forward path performs, voiding the D22 integrity guarantee against the untrusted remote the system was designed around.
3. **Emergency / biometric trust model** — emergency access bypasses the master password with a client-side time gate and an unprotected, synced key file; biometric stores the cleartext master password with no rotation path.
4. **Same-UID IPC boundary** — full-vault unlock and destructive key rotation are reachable without the session token that is supposed to be the entire same-UID defense.

Every finding rated CRITICAL or HIGH is exploitable under Baluard's own stated threat model (untrusted git remote + hostile same-UID local processes). They are ship-blockers for a product that stores identities and PII, not only passwords.

### Severity tally

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 9 |
| Medium | 12 |
| Low / Info | 8 |

---

## CRITICAL

### C1. AES-GCM nonce reuse on concurrent multi-device edit

**Files:** `crates/baluard-core/src/crypto/aead.rs:59-65`, `crates/baluard-core/src/vault/handle.rs:1376-1387`, `crates/baluard-core/src/keys/nonce.rs`
**Status:** Confirmed by direct source read.

**Detail.** The item key is fully deterministic:

```
item_key = sgk.derive_item_key(cipher_id, epoch)   // handle.rs:1376-1377, hierarchy.rs:215
```

It depends only on `(space_group_key, cipher_id, epoch)` — no per-write randomness and no dependency on `update_seq`. The SGK is itself derived deterministically from the Root Key + epoch, so it is identical across every device sharing the vault until a rotation occurs.

The nonce is:

```
nonce = nonce_counter (8 bytes LE) || cipher_id[..4]   // aead.rs:59-65
```

and `update_cipher` sets `nonce_counter = new_update_seq` where `new_update_seq = existing_envelope.header.update_seq + 1` (`handle.rs:1328`, `:1385-1386`). `update_seq` is read from the local file.

**Exploit.** Device A and Device B both hold cipher X at `update_seq = N`. Both edit it while offline (or before syncing). Each computes `new_update_seq = N + 1` and encrypts with:

- key = `derive_item_key(sgk, X, epoch)` — identical on both devices
- nonce = `(N+1) || X[..4]` — identical on both devices
- plaintext — different

This is AES-GCM nonce reuse under a single key. Consequences:

1. **Confidentiality break:** the keystream is identical, so `C_A XOR C_B = P_A XOR P_B` leaks the XOR of the two plaintexts (recovering password/secret content).
2. **Authentication break:** GHASH authentication-key (`H`) recovery becomes possible from two messages under the same nonce, enabling forgery of arbitrary ciphertexts for that cipher.

Both colliding envelopes end up committed to git and pushed to the remote, where any party with repo read access (GitHub admin, a leaked token, a fork) observes them. The expected multi-device sync flow **is** the trigger.

`nonce.rs` comments assert "Nonce reuse within the same cipher+key is prevented by the monotonic counter." The counter is **not** globally monotonic across devices; it is derived from a per-file value that forks on divergence. The nonce has only 32 bits of object separation (`cipher_id[..4]`) and a counter the application resets/derives non-monotonically per device.

Note: the AAD includes `update_seq`, but AAD only authenticates — it does not change the keystream. Differing AAD does not save you from the confidentiality leak.

**Fix.** Use a random 96-bit nonce per write (the attachment path already does this correctly via `OsRng` in `attachment.rs:37-39`), or fold `device_id` + a random salt into the nonce/key derivation. This invalidates the deterministic-nonce design and must be done before any multi-device sync ships.

---

### C2. Merge path skips commit signature verification

**Files:** `crates/baluard-core/src/sync/engine.rs:639-724` (`pull_inner`, non-fast-forward branch), `:752-822` (`resolve_conflicts`)
**Status:** Confirmed by code inspection; recommend the team add a regression test to confirm exploitability end-to-end.

**Detail.** The fast-forward pull branch (`engine.rs:617-619`) explicitly calls `collect_commit_range` + `verify_commit_signatures` **before** updating refs — honoring the D22 guarantee ("verify BEFORE updating any refs or working tree"). The non-fast-forward merge branch does **not**. It calls `repo.merge(&[&annotated], ...)` (`:657`) directly on the unverified `remote_oid`, writing remote blobs into the working tree and index, then creates a merge commit — with zero signature checks on the remote commits.

**Exploit.** A malicious or compromised remote (the core threat: the git host is untrusted) pushes a divergent branch. The victim's local has any unpushed commit, so the pull is non-fast-forward. The attacker's unsigned/forged ciphertext blobs are merged into the working tree and committed as a legitimate Baluard merge commit. This enables:

- **Rollback** to old ciphertext (stale or already-compromised passwords).
- **Injection** of attacker-chosen ciphertext.
- **Replacement** of `meta/*.json` (device registry, epoch state, etc.).

**Path traversal sub-issue.** `resolve_conflicts` (`:752-822`) writes caller-supplied bytes to `self.vault_path.join(path)` with no path-traversal validation (`:760-767`). The `path` values originate from remote-controlled git index entry paths (`String::from_utf8_lossy(&ours.path)`, `:671-673`). A remote that introduces a conflicting entry with a path like `../../.ssh/authorized_keys` or `meta/device-privkey.json` provides a concrete traversal primitive. Remote commit signatures are never verified on this path either.

**Fix.** Verify commit signatures on **all** pull paths (fast-forward, merge, and conflict resolution) before writing anything to the tree/index or updating refs. Sanitize and canonicalize conflict paths, rejecting any that escape the vault directory.

---

### C3. Emergency access defeats the entire password model

**File:** `crates/baluard-core/src/emergency.rs:43-187`
**Status:** Confirmed by direct source read.

Three compounding flaws make the emergency-access feature a full master-password bypass:

1. **Raw Root Key wrapped to a contact, stored unprotected and synced.** `save_emergency_config` (`:43-57`) HPKE-wraps the 64-byte Root Key to a trusted contact's X25519 key and writes it to `meta/emergency.json` — **no `set_permissions(0o600)`** (confirmed: zero `set_permissions`/`from_mode` matches in the file). With git-sync enabled, this wrapped Root Key travels to the remote.

> **⚠️ Disputed sub-claim (pending re-analysis):** The original audit described the write as "bare `std::fs::write`". Source inspection shows `save_emergency_config` actually uses the atomic tmp+rename pattern (`write(&tmp)` → `rename(&tmp, &path)`), consistent with the project's `atomic_write` convention. The missing 0600 permissions concern remains valid. See **Appendix: Disputed Claims** at the end of this document.

2. **Client-side, unsigned time gate.** Authorization (`:151-155`) is `now >= request_time + delay_seconds`, where `request_time` is written by the grantee (`initiate_emergency_request`, `:96-114`) and evaluated on the grantee's own machine. A malicious grantee can: set the system clock forward; directly edit `meta/emergency.json` to `status: "Approved"`; or set `request_time` to the past. There is no signature over the config and no owner-side enforcement. The "delay" is pure honor system.

3. **No owner involvement at recovery.** `recover_emergency_root_key` (`:137-187`) returns the raw Root Key to the grantee with no master password and no owner action once the (bypassable) gate elapses.

**Net effect.** Anyone holding the contact private key — or anyone with access to the unprotected, synced `emergency.json` — decrypts the entire vault without the master password and without waiting.

**Fix.** Set `0600` and keep the wrapped Root Key out of the synced tree; sign the emergency config with a device key; enforce the delay owner-side (or drop the security claim and document the feature as advisory-only).

---

### C4. Full-vault unlock and destructive rekey are not token-gated

**File:** `crates/baluard-daemon/src/handler.rs:151-203` (`TOKEN_REQUIRED_ACTIONS`), `:744-750` (`device.revoke` route), `:776-809` (biometric routes), `crates/baluard-daemon/src/state.rs:1309-1313`, `:1604-1641`
**Status:** Confirmed by direct source read.

**Detail.** The daemon's entire same-UID isolation model rests on the 256-bit session token (peer-cred only verifies UID, so any same-UID process can connect to the socket). Two high-impact actions are missing from `TOKEN_REQUIRED_ACTIONS`:

- **`device.revoke`** — not gated; only checks `handle.is_unlocked()` (`state.rs:1604-1641`). It is even present in `COVER_MUTATION_ACTIONS` (`:225`), confirming it is treated as a mutation but the author forgot the token gate. It triggers `revoke_device_and_rekey()`: full root-key rotation, re-encryption of every cipher and attachment, new keywrap.
- **`vault.biometric_unlock`** — not gated. `biometric_unlock` calls `state.unlock()` internally (`state.rs:1309-1313`), which mints a fresh session token and returns it.

> **⚠️ Disputed sub-claim (pending re-analysis):** The original audit also listed `vault.biometric_enable` as not token-gated. Source inspection confirms `vault.biometric_enable` **is** present in `TOKEN_REQUIRED_ACTIONS` (handler.rs line 211), and therefore IS token-gated. This sub-claim was incorrect. See **Appendix: Disputed Claims** at the end of this document.

**Exploit.** While the vault is unlocked (or with biometric enabled), any same-UID process — a compromised browser-extension host, a rogue script — connects to the socket and:

- calls `vault.biometric_unlock` with no token → triggers a silent OS-keyring unlock (on Linux Secret Service with an unlocked keyring this requires no user interaction) → receives a brand-new valid session token in the response → uses it for all gated cipher reads. The token defense is defeated end-to-end.
- or calls `device.revoke` → forces a full key rotation → denial of service that locks other devices out, with no token required.

**Fix.** Add `device.revoke` and `vault.biometric_unlock` to `TOKEN_REQUIRED_ACTIONS` (`vault.biometric_enable` is already gated). If biometric unlock is intended to bypass the token by design, document explicitly that any same-UID process can therefore unlock the vault, and reconsider that tradeoff.

---

## HIGH

### H1. No master-password change exists; biometric stores the cleartext master password

**Files:** `crates/baluard-core/src/biometric.rs:47`, `:304`, `:355`, `crates/baluard-daemon/src/state.rs:1296`
**Status:** Confirmed (grep finds no master-password-change route anywhere in core/daemon/CLI).

There is no change-password / rekey-KEK flow in the entire codebase. `biometric.rs:355` documents that `disable()` "must be called on master password change to invalidate stale secrets" — but password change is impossible, so that invalidation path is dead. Biometric "enable" stores the **cleartext master password** in the OS keyring (`state.rs:1296` → `biometric::enable(password)` → `biometric.rs:47/304` `set_password(master_password)`).

**Impact.** A user who suspects compromise cannot rotate the password that gates the KEK. On Linux the `keyring` Secret Service entry is readable by any process running as the same UID (no per-app ACL), so any malware in the user session reads the master password directly, bypassing biometrics and the entire Argon2id KDF.

Clarification (answering the original brief): biometric does **not** escrow the master *key*; it escrows the master *password*, and the daemon re-derives the KEK via Argon2id internally — the password never crosses IPC. But it is the password in cleartext, gated only by OS keyring ACLs.

**Fix.** Implement master-password change (re-wrap the KEK / Root Key). Wire `biometric::disable()` into that flow. Prefer storing a high-entropy derived secret rather than the raw password where the platform allows.

---

### H2. Decrypted secrets are never zeroized on the normal read path

**Files:** `crates/baluard-core/src/types.rs:319-760`, `crates/baluard-core/src/vault/cipher.rs:130-161`, `crates/baluard-core/src/vault/padding.rs:46`
**Status:** Confirmed (no `Zeroize`/`ZeroizeOnDrop` in `types.rs`).

`decrypt_cipher` produces `padded` (`cipher.rs:130`) and `json` (`:133`) `Vec<u8>` holding full plaintext, plus a `Cipher` struct whose `LoginData.password`, `CardData.number`, `notes`, TOTP URI, `password_history`, etc. are plain `String`/`Vec`. None implement `Zeroize`/`ZeroizeOnDrop`, and `decrypt_cipher` does not wipe `padded`/`json` before returning. Every `get_cipher`, `list_full`, and index rebuild leaves cleartext passwords in freed heap memory, recoverable via core dump, swap, or heap-spray.

The revoke/rekey loop manually zeroizes (`handle.rs:2300-2316`), proving the team knows the requirement — but it is absent from the hot read paths. This contradicts the peer review.md claim "Zeroize on drop for key material and TOTP secrets."

**Fix.** Implement `ZeroizeOnDrop` on secret-bearing types in `types.rs`; zeroize `padded`/`json` intermediates in `decrypt_cipher`.

---

### H3. Rollback / tamper protection is dead code

**File:** `crates/baluard-core/src/integrity.rs` (declared at `lib.rs:13`, never called)
**Status:** Confirmed (grep finds no callers of `IntegrityManifest::`, `detect_rollback`, `verify_checkpoint`, `.record(` outside the module's own tests).

`integrity.rs` implements signed monotonic checkpoints and `detect_rollback`, but nothing invokes any of it. AES-GCM provides per-record confidentiality/integrity but **zero** protection against whole-file rollback, deletion, or reordering at the vault level.

**Impact.** An attacker with disk/git write access can roll the vault back to an old epoch (re-introduce a revoked device's still-valid old-epoch state, or restore a deleted credential) entirely undetected. The would-be anchor, `meta/integrity.json`, is itself a plain git-synced file with no external root of trust, so even if wired up, an attacker who can write the vault can rewrite data and manifest consistently.

**Fix.** Wire the integrity manifest into the read/sync paths, and anchor it outside the writable tree (e.g., a monotonic counter in the OS keyring, or signed by a device key whose pubkey is pinned at enrollment).

---

### H4. Recovery phrase is a permanent, unrotatable bypass

**Files:** `crates/baluard-core/src/recovery.rs:42-48`, `crates/baluard-core/src/vault/creation.rs:88-95`
**Status:** Confirmed (grep: `meta/recovery.json` never re-wrapped after rotation).

`recover_from_phrase` derives a 64-byte key from the BIP-39 seed with an **empty passphrase** (`to_seed("")`), and creation HPKE-wraps the Root Key to it in `meta/recovery.json`. After `rotate_root_key`/`revoke_device_and_rekey`, `recovery.json` is never re-wrapped, so the recovery phrase still unwraps the *old* Root Key. Because git history retains all old-epoch `.enc` blobs, the original phrase decrypts all pre-rotation history forever. There is also no flow to rotate the phrase itself.

**Impact.** Phrase compromise = total, irrevocable vault compromise. This may be an intended tradeoff (the D3 doc comment implies recovery is a deliberate master-password bypass), but the lack of any remediation path should be a conscious, documented decision.

**Fix.** Re-wrap `recovery.json` on every Root Key rotation; provide a phrase-rotation flow; document the recovery trust model explicitly.

---

### H5. Provider tokens leak into git error strings

**Files:** `crates/baluard-core/src/sync/credentials.rs:96-99`, `crates/baluard-core/src/sync/engine.rs:519` (`push`), `:568` (`fetch`), `:862` (`clone`)
**Status:** Confirmed wrapping is verbatim; whether a given git2 build embeds the token in the error is version-dependent (high likelihood).

The HTTPS PAT is passed to `Cred::userpass_plaintext`. When git2 surfaces an auth/transport error, the engine wraps it verbatim: `SyncError::Git(format!("push: {e}"))`. git2/libcurl transport errors frequently include the effective remote URL and can include userinfo. These `SyncError::Git(String)` values flow to the daemon (`handler.rs:1275` `format!("{e}")`), back to the client as plain error text, and are logged by `env_logger`.

**Impact.** Credential disclosure in logs and IPC error surfaces.

**Fix.** Scrub credentials from all error and log surfaces; never interpolate raw git2 transport errors into user-facing strings.

---

### H6. Session-token file: TOCTOU + plaintext + no expiry

**Files:** `crates/baluard-cli/src/client.rs:54-65` (`set_session_token`), `crates/baluard-daemon/src/state.rs:242-277`, `:1785-1796`
**Status:** Confirmed.

`set_session_token` calls `std::fs::write(&path, token)` (creating the file with the process umask, commonly `0644`) and only afterward calls `set_permissions(... 0o600)`. Between those two syscalls the 64-hex-char token is world/group-readable on disk, with no tmp+rename. A local attacker racing the file open reads the token.

The token is also stored in cleartext for its whole lifetime, never rotates, and never expires — it is invalidated only on explicit `lock()` or auto-lock timeout. If it leaks, it grants full gated access for the entire unlocked session with no re-unlock. The 30s "grant token" from `reprompt_verify` (`state.rs:1656-1663`) is generated and returned to the client but never stored or checked server-side, so reprompt provides no server-enforced guarantee.

(On Linux the token lives under `$XDG_RUNTIME_DIR`, typically `0700`, which limits but does not eliminate the local race. The macOS path `~/Library/Application Support/baluard/` is not guaranteed `0700`.)

**Fix.** Create the file atomically with `OpenOptions::new().mode(0o600).create_new(true)` before writing. Add token expiry/rotation. Either enforce the reprompt grant token server-side or remove it.

---

### H7. Favicon fetch leaks every saved domain to Google, default-on

**File:** `crates/baluard-daemon/src/state.rs:715-739` (`fetch_favicon`)
**Status:** Confirmed.

For every login entry with a URI, the daemon shells out to `curl` and requests `https://www.google.com/s2/favicons?domain={domain}`. This discloses to Google the complete list of services the user holds accounts for. It is **default-on**: `state.rs:715` only disables when `fetch_favicons == Some(false)`, so `None` (a new/unset vault) = enabled.

For a privacy-focused, offline, no-server-backend password manager, this is a meaningful metadata leak to a third party the user never opted into.

(No command injection: the URL is passed as a single positional arg to `Command::new("curl")` with no shell. The domain is not URL-encoded, allowing trivial query-param smuggling into the fixed Google request, but no arg/shell injection — SSRF-to-fixed-host only.)

**Fix.** Default off. Fetch icons directly from the site (or bundle a generic icon set) rather than via a third party.

---

### H8. 1PUX import zip-bomb DoS

**File:** `crates/baluard-core/src/import/onepassword_1pux.rs:180-184`
**Status:** Confirmed by code; not yet weaponized.

`archive.by_name("export.data")` then `read_to_string` with no decompressed-size cap. The daemon caps the input frame at 4MB (`handler.rs:20`), but a 4MB deflate stream can expand to multiple GB. `read_to_string` allocates the full decompressed string. A malicious `.1pux` file (user social-engineered into importing it) can OOM-kill the daemon. The CSV/JSON/XML formats are bounded by the 4MB frame since they are not compressed; only the ZIP path amplifies.

**Fix.** Wrap the zip entry reader in `.take(N)` and reject oversized entries.

---

### H9. Quorum bypass on revocation/eviction; enrollment not bound to vault

**File:** `crates/baluard-core/src/device_manager.rs:1030-1097` (revocation/eviction), `:782-791` (enrollment)
**Status:** Confirmed design gaps.

`revoke_device_and_rotate` (`:1030-1070`) calls `initiate_rotation` then immediately self-acknowledges and `commit_rotation()` regardless of `quorum_required()` — the doc comment at `:1026-1029` admits "For 4+ device vaults, the rotation commits without full quorum verification." `force_evict_and_rotate` (`:1090-1097`) writes a `.committed` file with an empty `commit_barrier`. The two-phase ack/quorum machinery is bypassed on the revocation path.

**Impact.** A single compromised device can revoke any other device and force an epoch rotation that other devices accept on next pull with no signature proof. Other devices cannot distinguish a legitimate eviction from a malicious one.

**Enrollment.** `enroll` (`:782-791`) verifies an Ed25519 signature over `"enroll" || JSON(payload)` only. The payload (`:200-212`) contains device keys, timestamp, nonce, name — but **no vault ID, no epoch, no approver-registry binding**. The ±5-min window + nonce prevents replay within the window, but a captured approval is valid against any vault state, and the out-of-band channel (QR/paste) is trust-on-first-use with no fingerprint confirmation step. An attacker who intercepts and substitutes the `EnrollmentPayload` before the approver signs gets the approver to authorize attacker-controlled keys.

**Fix.** Enforce quorum on eviction; bind enrollment signatures to vault ID + epoch + registry version; add an out-of-band fingerprint confirmation step to enrollment.

---

## MEDIUM

### M1. Avatar stored unencrypted and synced to the remote
**Files:** `crates/baluard-daemon/src/state.rs:589-594`, `crates/baluard-core/src/vault/manifest.rs:107`.
Avatar bytes are written verbatim to `meta/avatar.{ext}` (0600 locally, but committed to git and pushed in plaintext). The user's photo is plaintext-readable by anyone with repo access. The code comment acknowledges this is deliberate ("avoids bloating settings.json diffs"), but it ships identity-linkable PII off-device in the clear. Ext is whitelisted (png/jpg/jpeg/gif/webp), 350KB base64 cap. **Fix:** encrypt the avatar like any other vault object, or keep it strictly local and never sync it.

### M2. Structural metadata leak (one file per cipher)
**Files:** `crates/baluard-core/src/vault/handle.rs:1289`, `crates/baluard-core/src/vault/envelope.rs:27`, `padding.rs`.
Each cipher is its own file `ciphers/<uuid>.enc`, so an attacker with repo read access learns the exact entry count, every entry UUID, per-entry `update_seq`/`key_epoch`/timestamps (file mtime + git history), and the full per-entry edit timeline from git commits. Tombstones live as files in `trash/`. The padding tier is stored as a plaintext byte in the envelope header (`envelope.rs:27`, index 27) and also bound in AAD — so the size class is readable directly without even measuring file size. Padding only buckets content length into 5 tiers; it does nothing for entry count, identities, change frequency, or activity patterns. **Fix:** document honestly; consider a packed single-blob vault format to hide entry count and per-entry timing. (See existing `docs/vault-metadata-leakage-analysis.md`.)

### M3. KDF auto-calibrate can drop memory below the OWASP floor
**File:** `crates/baluard-core/src/crypto/kdf.rs:122-152`.
The "too slow" calibration path reduces memory to `base_mem / 2` (`:124`, `:132`). On the `MobileLow` profile (base 19 MiB, the OWASP Argon2id minimum) this yields ~9.5 MiB, below the recommended floor. **Fix:** clamp `mem` to an absolute minimum (>= 19 MiB) regardless of calibration.

### M4. No rate limiting on unlock / recovery / emergency / biometric
**Files:** `crates/baluard-daemon/src/handler.rs:298-320`, `crates/baluard-core/src/device_manager.rs:1143`, `crates/baluard-core/src/emergency.rs:139`.
None of these paths have an attempt counter, backoff, or lockout. Argon2id cost throttles the master-password path somewhat, but a same-UID process can brute-force indefinitely, and an offline attacker with the vault directory grinds the KEK unrestricted. BIP-39 24-word entropy (256-bit) makes the recovery phrase itself infeasible to brute-force, but the master-password path gains no defense beyond KDF cost. **Fix:** add attempt counters with exponential backoff and a lockout threshold.

### M5. SSH host key not verified; `clone_unchecked` bypasses scheme validation
**File:** `crates/baluard-core/src/sync/credentials.rs:89`, `crates/baluard-core/src/sync/engine.rs:826-883`.
No `certificate_check` callback is registered on `RemoteCallbacks` anywhere, so git2/libssh2 host-key verification against `known_hosts` is not enforced by the app — it relies on libssh2 defaults, which commonly accept unknown hosts (SSH MITM). Separately, `clone_unchecked` is `pub` and performs no URL validation, while only `clone()` validates the scheme — a caller reaching `clone_unchecked` directly accepts `git://`, `file://`, arbitrary paths. No evidence of TLS cert verification being explicitly disabled (good). **Fix:** register a `certificate_check` callback enforcing `known_hosts`; make `clone_unchecked` private or have it validate.

### M6. Provider tokens copied into plain `String`, defeating `SecretString`
**Files:** `crates/baluard-core/src/sync/credentials.rs:21`, `:48`, `:60`, `crates/baluard-core/src/sync/engine.rs:838`.
`ProviderToken` correctly holds the token as `SecretString` (zeroize-on-drop). But `CredentialConfig.https_token: Option<String>` calls `.expose_secret().to_string()` (`credentials.rs:48,60`), copying the secret into a plain heap `String` that is not zeroized, then `.clone()`-ed again in `build_callbacks` (`:81`) and `clone_unchecked` (`engine.rs:838`). These copies live for the sync op and are dropped without wiping. **Fix:** keep the token in `SecretString`/`Zeroizing` end to end.

### M7. TOTP seed crosses IPC into the edit form
**File:** `desktop/src/components/AddEditCipherForm.jsx:298`.
The TOTP field is bound to `newCipher().totp_uri` and rendered as `<input value=...>` containing the full `otpauth://totp/...?secret=...` URI. peer review.md states "TOTP: Seed NEVER crosses IPC. Only derived numeric code sent to frontend." The detail view (`CipherDetail.jsx:52`) correctly uses only the derived code, but the edit form receives and displays the raw seed, which then lives in webview memory. **Fix:** reconcile with the stated invariant — either treat the edit-form exception as accepted-and-documented, or avoid sending the seed to the frontend (edit via a write-only field).

### M8. Attachment size recorded as 0 (zeroize-before-read bug)
**File:** `crates/baluard-daemon/src/state.rs:1362`, `:1384`.
`plaintext.zeroize()` is called at `:1362`, then `size: plaintext.len() as u64` is read at `:1384`. After `zeroize()` the `Vec` length is 0, so every attachment's `size` metadata is stored as 0 and `attach_download` returns size 0 to the frontend. Not a secret leak, but a data-integrity bug and a sign the ordering was not validated. **Fix:** capture `len()` before zeroizing.

### M9. Non-atomic DeviceManager persistence
**File:** `crates/baluard-core/src/device_manager.rs:346-388` (`save_state`).
Performs multiple independent `atomic_write` calls (registry, epoch, nonces, txn, acks); the doc comment (`:308-311`) admits the combination is not atomic. A crash mid-revoke can leave `epoch.json` advanced while `devices.json` still lists the revoked device, or vice versa — partial revocation. The `handle.rs` `RotationGuard` covers cipher-file staging but not these separate state writes. **Fix:** stage all device-manager state changes and commit them with a single atomic rename of a directory or a combined file.

### M10. `emergency.json` / `access_list.json` lack 0600
**Files:** `crates/baluard-core/src/emergency.rs:54`, `crates/baluard-core/src/orgs.rs:57`.
Both use bare `std::fs::write` with no permission hardening, inconsistent with the `device_manager::atomic_write` 0600 convention. `access_list.json` holds HPKE-wrapped group keys. **Fix:** set 0600 (and see C3 for emergency.json's larger problems).

### M11. RFC 8628 `slow_down` ignored
**Files:** `crates/baluard-core/src/providers/github.rs:160`, `crates/baluard-daemon/src/handler.rs:872-874`.
On `slow_down`, the daemon returns `{"interval_increment": 5}` to the client but the core never adjusts `session.interval_secs`, and `device_flow_poll` re-polls at the original interval. RFC 8628 §3.5 requires adding 5s and continuing slower. Also, `device_flow_poll` ignores HTTP status (`github.rs:151`) and parses JSON unconditionally. **Impact:** GitHub may rate-limit or invalidate the device code. **Fix:** honor the increment in core; check HTTP status.

### M12. `auto_lock_minutes: 0` disables auto-lock entirely
**File:** `crates/baluard-daemon/src/state.rs:206` (`if elapsed >= timeout_secs && timeout_secs > 0`).
A settings value of `0` (settable via `settings.set`, `state.rs:454-457`) permanently disables auto-lock, keeping keys resident indefinitely. **Fix:** enforce a maximum auto-lock interval; treat 0 as "use default" rather than "never."

---

## LOW / INFO

### L1. No clipboard auto-clear for copied secrets
`desktop/src/components/CopyButton.jsx:19`, `CipherDetail.jsx:20`/`:145`, `GeneratorModal.jsx:51`, `SshKeyGenerator.jsx:35`, `RecoveryScreen.jsx:13`. All copy secrets (passwords, TOTP codes, SSH private keys, recovery phrase) via `navigator.clipboard.writeText` with no timed clear. Secrets persist in the OS clipboard and clipboard-history managers indefinitely. Common managers clear after ~30s. **Fix:** add a configurable auto-clear timeout.

### L2. `RecoveryPhrase::Drop` is a no-op
`crates/baluard-core/src/recovery.rs:51-59`. The impl does nothing; the comment admits `bip39::Mnemonic` cannot be zeroized. The `String` from `phrase()` and the mnemonic's internal entropy linger in heap after drop. Info-level (requires memory disclosure to exploit). **Fix:** where feasible, copy entropy into a `Zeroizing` buffer and avoid retaining the `Mnemonic`.

### L3. Import parsers never zeroize parsed plaintext
`crates/baluard-core/src/import/` — no `Zeroizing`/`zeroize` anywhere. Parsed passwords/keys live in plain `String`/`CipherInput` (and the decoded 1PUX `Vec<u8>`/`String`) until normal drop. Inconsistent with the zeroization done elsewhere. Low because the data is en route to encryption anyway, but the plaintext window is unmanaged.

### L4. Frontend URL/opener hardening
`desktop/src-tauri/capabilities/default.json:10` grants `opener:default` with no scope restriction (also enables `open-path`); `desktop/src/components/CipherDetail.jsx:259` uses `u.startsWith("http")` rather than `^https?://` for the scheme check. Mitigated today by the opener plugin's default scheme allowlist, so not independently exploitable. **Fix:** scope the capability to `open-url` for `http`/`https`/`mailto`; tighten the scheme regex.

### L5. macOS biometric silently degrades to passcode
`crates/baluard-core/src/biometric.rs:30` (`BIOMETRY_ANY`), `:35-37`. Macs without Touch ID fall back to device passcode, and `is_available()` always returns `true` without verifying biometric hardware. So "biometric unlock" may degrade to passcode unlock. The file-based keychain (chosen at `:79-85` to avoid entitlements) is weaker than the data-protection keychain. **Fix:** verify hardware availability; document the fallback.

### L6. `provider_for` panic reachable from a client
`crates/baluard-daemon/src/handler.rs:246`, `:866`. `provider_for(session.provider)` has an `unreachable!()` for GitLab/Codeberg; a `provider.connect_poll` with a crafted session naming those providers panics the per-connection task. Caught by `tokio::spawn`, so it kills only that connection, not the daemon (DoS-limited). **Fix:** return an error instead of `unreachable!()`.

### L7. Dependency hygiene
`crates/baluard-daemon/Cargo.toml` pins `ssh-key = "0.7.0-rc.10"` — a release candidate in a security product. There is a `rand_core` version split: workspace uses `rand_core = "0.6"` (with `rand 0.8`) while the daemon's `ssh-key` target deps pull `rand_core = "0.10"`. No `cargo-audit`/`cargo-deny` in the toolchain. **Fix:** pin a stable `ssh-key`; reconcile `rand_core`; add `cargo-audit` to CI (`just check`).

### L8. Forward secrecy / post-compromise (inherent, document)
`crates/baluard-core/src/vault/handle.rs:2172+`. Re-keying correctly re-encrypts current ciphers/attachments/trash with the new Root Key and removes the revoked keywrap. But a previously-trusted, now-revoked device that held the old Root Key can decrypt every old-epoch `.enc` blob still present in git history and in any clone it retained. This is inherent to git-native storage but currently silent. **Fix:** document explicitly as a non-goal, and warn users that revocation provides forward security for new writes only.

---

## What's solid (credit where due)

- **KDF:** Argon2id (`Algorithm::Argon2id`, `Version::V0x13`), 32-byte salt validated, parameters from bounded profiles (`crypto/kdf.rs`).
- **Key hierarchy:** HKDF-SHA256 with clean, length-aware domain separation per layer (`baluard-sgk-v1`, `baluard-item-v1`), epoch bound into the SGK to prevent misuse (`keys/hierarchy.rs`).
- **Key material handling:** `RootKey`/`ItemKey`/`SpaceGroupKey` are heap-boxed, `mlock`'d, `Debug`-redacted, and `Zeroize` on `Drop` (`keys/hierarchy.rs:39-262`).
- **AEAD AAD binding:** `build_aad` length-prefixes and domain-separates vault/object-type/object-id/tier/alg/epoch/seq, correctly blocking cut-and-paste, rename, and record-level rollback (`crypto/aead.rs:21-54`; swap test passes). Decrypt fails closed to `AuthTagMismatch` with no oracle.
- **Signatures:** standard Ed25519 via `ed25519-dalek` with `OsRng` keygen (`crypto/signature.rs`).
- **IPC socket:** born 0600 via `umask(0o177)` set before `bind` (no chmod TOCTOU), stale socket removed first (`daemon/main.rs:155-175`).
- **Peer credential check:** `SO_PEERCRED`/`getpeereid` enforced on every connection, fails closed (`daemon/handler.rs:1387-1444`). (Note: UID-only — same-UID isolation is the entire model, which is why C4/H1/H6 matter.)
- **Constant-time token compare** (`daemon/crypto.rs:7-16`); CSPRNG via `OsRng` for token (32 bytes → 64 hex), SSH keygen, salts, and all key generation.
- **Frame DoS guard:** 4MB frame cap, bounded varint decode, no unbounded allocation (`daemon/handler.rs:42-90`).
- **Frontend:** restrictive Tauri CSP (`default-src 'self'`, `script-src 'self'`, no `unsafe-inline`/`unsafe-eval`); no `innerHTML`/`dangerouslySetInnerHTML`; all user data auto-escaped via SolidJS text interpolation; `crypto.getRandomValues` only (no `Math.random`); shell scoped to the daemon sidecar only; webview loads bundled dist only.
- **Import safety:** `roxmltree` resolves no external entities (no XXE); 1PUX reads a single fixed entry by name (no zip-slip); CSV parsers use bounds-checked accessors.
- **Atomic writes:** temp + 0600 + rename for ciphers and most metadata; `RotationGuard` cleans `.tmp` and the crash marker on error.

## Cargo audit report:

Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1124 security advisories (from /Users/esteban/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (495 crate dependencies)
Crate:     rsa
Version:   0.10.0-rc.18
Title:     Marvin Attack: potential key recovery through timing sidechannels
Date:      2023-11-22
ID:        RUSTSEC-2023-0071
URL:       https://rustsec.org/advisories/RUSTSEC-2023-0071
Severity:  5.9 (medium)
Solution:  No fixed upgrade is available!

Crate:     bincode
Version:   1.3.3
Warning:   unmaintained
Title:     Bincode is unmaintained
Date:      2025-12-16
ID:        RUSTSEC-2025-0141
URL:       https://rustsec.org/advisories/RUSTSEC-2025-0141

Crate:     paste
Version:   1.0.15
Warning:   unmaintained
Title:     paste - no longer maintained
Date:      2024-10-07
ID:        RUSTSEC-2024-0436
URL:       https://rustsec.org/advisories/RUSTSEC-2024-0436

error: 1 vulnerability found!
warning: 2 allowed warnings found

---

## Recommended remediation order

1. **C1** — nonce derivation (random per-write nonce). Touches the on-disk/wire format; cheaper to change before release.
2. **C2** — verify signatures on all pull paths + sanitize conflict paths.
3. **C3 / C4** — emergency-access trust model and IPC token gating.
4. **H1–H4** — master-password change + biometric secret handling; zeroize read path; wire up integrity manifest; recovery re-wrap.
5. **H5–H9**, then MEDIUM, then LOW.

The two existential items: **C1** (breaks confidentiality in the headline multi-device feature) and **C2** (breaks integrity against the untrusted remote the system was designed around).

---

## Appendix: Disputed Claims (Flagged by Independent Verification)

A second-pass source verification (TARS, 2026-06-10) identified two sub-claims within Critical findings that do not match the actual code. The parent findings remain valid; only the specific sub-claims below are disputed.

### DC-1. C3 sub-claim: "bare `std::fs::write`" for emergency.json

**Original claim:** `save_emergency_config` writes `emergency.json` using "bare `std::fs::write`" with no atomic write pattern.

**Actual code (`emergency.rs:43-57`):**
```rust
let tmp = path.with_extension("json.tmp");
std::fs::write(&tmp, &json)?;
std::fs::rename(&tmp, &path)?;
```

**Finding:** The write IS atomic (tmp + rename), consistent with the project's `atomic_write` convention. The original audit's description of "bare `std::fs::write`" is inaccurate.

**Still valid:** The missing `0600` permissions concern is confirmed. No `set_permissions` / `from_mode` calls exist in the file. The tmp file inherits the process umask (commonly 0022), so the file is briefly world/group-readable before rename.

**Recommended action:** Update C3's first bullet to read: *"writes to `meta/emergency.json` using the atomic tmp+rename pattern but without `set_permissions(0o600)`"*. No severity change.

---

### DC-2. C4 sub-claim: `vault.biometric_enable` not token-gated

**Original claim:** `vault.biometric_enable` is not in `TOKEN_REQUIRED_ACTIONS` and is therefore not token-gated.

**Actual code (`handler.rs:211`):**
```rust
const TOKEN_REQUIRED_ACTIONS: &[&str] = &[
    // ... (lines 152-210) ...
    "vault.biometric_enable",       // line 211 ← IS present
    "vault.biometric_disable",      // line 212
    // ...
];
```

**Finding:** `vault.biometric_enable` **IS** listed in `TOKEN_REQUIRED_ACTIONS`. The token check at handler.rs:274-277 enforces it. The audit's claim that it is not gated is incorrect.

**Still valid:** `device.revoke` and `vault.biometric_unlock` are confirmed NOT in the list. The exploit scenarios for those two actions remain valid.

**Recommended action:** Remove `vault.biometric_enable` from C4's list of ungated actions. Update the fix recommendation to only add `device.revoke` and `vault.biometric_unlock`. C4 remains CRITICAL based on `device.revoke` and `vault.biometric_unlock` alone.

---

## Appendix: Limitations of This Audit

- C2's path-traversal sub-issue and the exact contents of git2 error strings (H5) are version-dependent; both warrant a confirming test.
- This was a static review. Recommended follow-ups: a property/fuzz test specifically for nonce uniqueness across simulated multi-device divergence (C1), and an integration test that pushes a malicious divergent branch to confirm C2 end-to-end.
