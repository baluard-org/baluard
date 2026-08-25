# Baluard Security Audit — 2026-08-23

**Scope:** Full pre-release audit. Part 1: core crypto primitives, key hierarchy, vault format, runtime, daemon IPC, CLI, native messaging host. Part 2: desktop (Tauri v2 + SolidJS). Part 3: browser extension (MV3). Part 4: Android mobile app.
**Method:** Static source review against the stated threat model (`docs/threat-model.md`). Every finding cites file and line from code read during this audit. Critical and High findings were independently re-verified by the lead auditor. After drafting, an isolated second-model validation pass re-checked all 51 original findings against source: zero were refuted, 12 line citations were corrected, 2 severities were adjusted (C13 up, M5 down), and 5 previously missed findings were added (C21-C25). The remediation plan was then drafted by the second model against the codebase and re-validated by the lead auditor, who corrected four points against source (C1 subkey retention, C22 route inventory, B8 permission source, C9 call-site count). See Appendix.
**Severity scale:** Critical = remotely exploitable or breaks vault confidentiality at rest. High = local attacker, malicious page, or same-user process gains vault access or privilege escalation. Medium = defense-in-depth gap or metadata leak. Low = hardening. Info = observation.

---

## Executive Summary

The cryptographic core is well built. The AES-256-GCM envelope with length-prefixed domain-separated AAD, the recompute-before-decrypt identity check, RFC 9180 HPKE key wrapping, mlock'd zeroizing key material, Ed25519-signed commit verification on every pulled commit, and OWASP-compliant Argon2id parameters all check out against the code, not just the docs.

The problems sit at the boundaries where key material, capabilities, or decrypted secrets leave the protected core: a plaintext device private key fallback on disk, a CLI session token persisted beside the socket, an extension origin check that drops scheme and port, a mobile screenshot guard that never runs, and plaintext provider tokens on Android. One cross-cutting theme: several documented controls (reprompt grants, sender gates, FLAG_SECURE) exist as intent but not as executing code; treat verified behavior, not design, as the source of truth before release.

**Top risks (ordered):**

| # | Severity | Finding | Area |
|---|----------|---------|------|
| 1 | High | Plaintext device private keys written to `meta/device-privkey.json` when no keystore is available; Unix-only 0600, no Windows ACL | Core |
| 2 | High | CLI persists the 256-bit session token to disk (`baluard.tok`) for the entire unlock session; any same-UID process reads it and defeats the R7-2 capability invariant | CLI |
| 3 | High | Quick-unlock master password stored via plain keyring on Linux/Windows: no per-read biometric ACL, silent same-user extraction (macOS is ACL-gated) | Core / biometric |
| 4 | Medium | Master-password rate limiter resets via unauthenticated `vaults.close` + re-unlock cycle; Argon2id is the only remaining cost | Daemon |
| 5 | Medium | Reprompt grant token minted but never verified daemon-side; T11 control is client-side only and composes with finding 2 | Runtime |
| 6 | Medium | Unvalidated slug joined into filesystem paths in `vault.create` / `vault.clone_start` (traversal before `validate_slug`) | Daemon |
| 7 | Medium | NMH always-on debug log at fixed `/tmp` path: symlink-following append, 0644 | NMH |
| 8 | Medium | Attachment blobs unpadded and unbound (size metadata leaks to git provider) | Core |
| 9 | Medium | Tauri `write_text_file(path, contents)` accepts arbitrary paths from the webview; the "scope" is a comment, not code | Desktop |
| 10 | Medium | `daemon_request` forwards every action to the daemon socket; CLI-only destructive routes reachable from the webview | Desktop |
| 11 | Medium | Master password retained in a SolidJS signal for the entire app lifetime after onboarding | Desktop |
| 12 | High | Extension fill-time origin re-check compares hostname only; scheme and port are dropped, so credentials matched on HTTPS can fill into a downgraded HTTP page | Extension |
| 13 | Medium | Extension background `inline.*` sender gates reference an undeclared `sender`; the security check is dead code in the shipped bundle | Extension |
| 14 | Medium | `vault.get` from the bridge is never bound to the requesting origin anywhere in the chain; binding lives only in UI flow | Extension + daemon |
| 15 | High | Mobile FLAG_SECURE is a no-op: application context cast to Activity always fails, recovery phrase visible in recents/screenshots | Mobile |
| 16 | High | Mobile clipboard copies lack `EXTRA_IS_SENSITIVE`; system overlay shows copied passwords and recovery phrase in plaintext | Mobile |
| 17 | High | Git provider OAuth/PAT tokens stored as plaintext files on Android (no keyring; desktop-only keyring gate) | Mobile + core |
| 18 | Medium | Bridge `vault.update` field gate checks only presence, not omission: a well-formed payload silently deletes all passkeys and URIs on a login (the exact capability the gate exists to deny) | Daemon + bridge |
| 19 | Medium | `vault.reprompt_verify` is an unthrottled Argon2id oracle: full unlock attempt with no in-memory rate limit | Runtime |
| 20 | Medium | In-memory rate limiter covers unlock/biometric/PIN only; recovery and emergency paths carry no limiter despite design claim | Runtime |

(Tables per part below; full list in each section.)

---

## Part 1: Core, Runtime, Daemon, CLI, Primitives

### 1.1 Verified-solid patterns

- **AAD identity binding is real.** `vault/cipher.rs:116-129` recomputes the expected AAD from caller context (vault, cipher id, tier, epoch, seq) and compares before decryption; swap attacks across files fail closed. AAD construction is length-prefixed with domain separation `baluard-aad-v2` (`crypto/aead.rs:23-58`).
- **Nonce hygiene.** Cipher and index writes use full 96-bit random nonces (`crypto/aead.rs:73-78`, `vault/index.rs:50`); index documents the A-1 fix that previously left only 64 random bits. Canary envelopes use a deterministic nonce with constant plaintext and per-instance key derivation, which is safe (`vault/canary.rs:21-55`).
- **Key material handling.** `RootKey`/`ItemKey`/`SpaceGroupKey` are heap-boxed with mlock on creation and clone, munlock plus zeroize on drop, and redacted `Debug` impls (`keys/hierarchy.rs:41-200`).
- **KDF.** Argon2id v0x13, profiles 19 MiB/64 MiB/256 MiB (MobileLow sits exactly at the OWASP floor), auto-calibration never drops below 19 MiB (`crypto/kdf.rs:127-131`), salt is 256-bit CSPRNG, benchmark uses a fixed non-secret password.
- **HPKE.** RFC 9180 DHKEM(X25519, HKDF-SHA256) + AES-256-GCM via the `hpke` crate, replacing the homegrown ECIES; low-order point rejection comes with DHKEM (`crypto/hpke_wrap.rs:1-24`).
- **HKDF discipline.** Argon2id stretches the password; HKDF-SHA256 with distinct `info` strings derives session/sync/index/folders/tags/profile/settings keys (`crypto/hkdf_derive.rs`).
- **Commit signing.** Every pulled or merged commit range is signature-verified against enrolled device verifying keys; unsigned commits error; the BFS walks all merge parents (prior second-parent smuggling fixed) (`sync/engine.rs:425-500, 1543-1600`).
- **Rate limiting.** In-memory per-vault limiter with exponential backoff and 1-hour lockout after 10 failures; covers unlock, biometric, and PIN paths (`runtime/rate_limit.rs:1-25`). The module doc claims recovery and emergency coverage too, but `claim_attempt` has exactly three call sites; see C22. Layered with Argon2id cost and the on-disk attempt file.
- **Attachments** use AES-256-GCM under the cipher item key with fresh random nonces and zeroized plaintext (`vault/attachment.rs:30-55`).
- **Recovery.** BIP-39 256-bit entropy in a `Zeroizing` buffer; `meta/recovery.json` stores only the HPKE-wrapped root key (`recovery.rs`, `vault/creation.rs:433-445`).
- **Socket transport.** Peer UID verified on every connection before any read (SO_PEERCRED on Linux, getpeereid on macOS); socket created 0600 through a umask-0177-wrapped bind; stale sockets removed before bind (`daemon/main.rs:266-278`, `daemon/handler.rs:4444-4483`).
- **Session tokens.** 256-bit OsRNG, constant-time compare per vault, 4-hour TTL, fail-closed expiry, cleared on lock (`runtime/state.rs:3386-3492`).
- **PIN escrow.** Verify, counter increment, and 5-strike nuke inside a single mutex hold; Argon2id verifier salted per escrow; KEK zeroized on drop; stale KEK fails closed through canaries (`runtime/pin.rs:128-155`).
- **Bridge scoping.** Read allowlist enforced in both daemon and NMH; `vault.update` field gate blocks fido2_credentials and uris; 30 reads/minute cap with auto-revoke; dot-boundary hostname matching with anti-phishing tests (`runtime/bridge.rs`).
- **Request hygiene.** Daemon logs action names and token-presence only, never payloads; master password, PAT, and recovery-phrase payloads zeroized after use across unlock, reprompt, and enroll paths.

### 1.2 Findings

#### C1 — High: Plaintext device private keys at rest without keystore

- **File:** `crates/baluard-core/src/vault/creation.rs:461-474`, `crates/baluard-core/src/device_manager.rs:1396-1413`, `crates/baluard-runtime/src/state.rs:3205-3221`
- **Evidence:** `"x25519_private": hex::encode(device_x25519_secret.to_bytes()), "ed25519_private": hex::encode(...)` written to `meta/device-privkey.json` when `self.keystore` is `None`.
- **Impact:** The X25519 device private key unwraps the Root Key from the keywrap file. With it, an attacker holding only the vault directory (threat actor D, physical disk access) skips Argon2id brute force entirely: read keywrap, unwrap root key, decrypt everything. The KEK-derived canary path is bypassed. The file is gitignored and 0600 on Unix, but 0600 is not a cryptographic boundary. On the `device_manager.rs` and `state.rs` write paths no Windows ACL is set (the `PermissionsExt` blocks are `#[cfg(unix)]`); the `creation.rs` path cannot reach Windows at all today because `write_vault_file` itself fails to compile there (C24).
- **Fix:** Seal `device-privkey.json` under a purpose-scoped subkey derived via `hkdf_derive` with a new `info` string (`baluard-devkey-v1`) — with one design constraint the initial proposal missed (validated against code): the KEK is not retained after unlock (only the PIN escrow holds it), while post-unlock readers (rotation, enrollment) need the seal key, and a root-key-derived seal is circular (the privkey is needed before the root key exists). Correct shape: derive the subkey from the KEK at unlock, retain the subkey (32 bytes, zeroized on lock) in `VaultState` — not the KEK itself — and let post-unlock readers unwrap through it. Factor one `device_privkey::{seal,open}` helper used by all three writers (`creation.rs:461-475`, `device_manager.rs:1396-1413`, `state.rs:3205-3221`) and every reader. Write through the WS1 primitive.
- **Confidence:** high

#### C2 — High: CLI session token persisted to disk defeats the capability model

- **File:** `crates/baluard-cli/src/client.rs:98-140`, `crates/baluard-core/src/paths.rs:72-76`
- **Evidence:** `set_session_token` writes the token beside the socket as `baluard.tok` (atomic 0600 create on Unix), where it stays for the whole unlock session; `get_session_token` reads it back for every subsequent command.
- **Impact:** Threat model invariant 1 (T2/R7-2) states a same-UID process that did not take part in the unlock exchange holds no capability. A file on disk is exactly that: any same-UID process reads `baluard.tok`, connects to the 0600 socket, and presents a valid capability to read the entire vault for as long as it stays unlocked. The token also survives CLI exit until the next unlock overwrites it. When the CLI was the unlocking client, actor C protection is void.
- **Fix:** Keep the CLI token in the kernel session keyring (keyutils on Linux) or the login keychain with an ACL (macOS), falling back to a documented "CLI unlock is trust-equivalent to same user" mode. At minimum, unlink and truncate the file on vault lock and on daemon shutdown detection.
- **Confidence:** high

#### C3 — High: Quick-unlock keychain entry on Linux/Windows has no per-read gate

- **File:** `crates/baluard-core/src/biometric.rs:14-17, 334-370`
- **Evidence:** macOS path uses `SecAccessControl` with `BIOMETRY_ANY` so every read prompts Touch ID or passcode. Non-macOS path stores the master password through the plain `keyring` crate (libsecret on Linux, Credential Manager on Windows), which has no per-item biometric ACL.
- **Impact:** On Linux and Windows, a same-user process (actor C, within the threat model) can silently read the stored master password with no user-visible prompt. The macOS path at least forces a user-presence event. Quick-unlock is opt-in, which bounds exposure, but the asymmetry is undocumented at the point of activation in the UI.
- **Fix:** On Linux, wrap the stored master password under a key held in a TPM or use `secret-tool` with a prompting collection only; on Windows, move to TPM-backed `KeyCredential` (the planned Windows Hello path). Until then, show an explicit warning at enable time on non-macOS platforms stating that any program running as this user can read the stored master password.
- **Confidence:** high

#### C4 — Medium: Attachment blobs are not padded and carry no AAD binding

- **File:** `crates/baluard-core/src/vault/attachment.rs:30-55`
- **Evidence:** Attachments encrypt to `[nonce | ciphertext+tag]` at true content size; no `Tier` padding, no `build_aad` identity binding.
- **Impact:** The padded-bucket defense (T1) exists so the git provider cannot infer content. Attachments leak exact plaintext sizes (encrypted size minus 28 bytes) and per-attachment edit timing to adversary A/B. Without AAD binding, two attachments of the same cipher can be swapped by an attacker with push access (same item key validates both).
- **Fix:** Pad attachments into the existing tier buckets (XL already allows 2 MB) and bind `[vault_id | cipher_id | attachment_id | seq]` as AAD.
- **Confidence:** high

#### C5 — Medium: Metadata plaintext files expose device names and sync patterns

- **File:** `docs/threat-model.md` residual risk 7; `meta/devices.json`, `meta/device_activity.json` in vault repo
- **Evidence:** Acknowledged in the threat model; listed here for release-blocker triage.
- **Impact:** Device names and activity timestamps are readable by the git provider, enabling user profiling and cross-vault correlation if the same remote account hosts multiple vaults.
- **Fix:** Move device display names into `settings.enc`; keep only opaque UUIDs and public keys in plaintext. Consider padding activity files.
- **Confidence:** high (existence verified; severity per stated threat model)

#### C6 — Low: On-disk unlock attempt counter is attacker-writable

- **File:** `crates/baluard-core/src/vault/handle.rs:2382-2430`
- **Evidence:** `check_attempt_rate_limit` reads `meta/kdf-attempts.json` from disk each attempt; `record_failed_attempt` writes it back.
- **Impact:** A same-UID attacker can edit or delete the counter to reset the on-disk backoff. Layered defenses (in-memory limiter, Argon2id cost) still apply, so this is defense-in-depth erosion only.
- **Fix:** Accept as documented limitation or HMAC the counter under a key held only in daemon memory while unlocked.
- **Confidence:** high

#### C7 — Info: rate limiter and PIN counters reset on daemon restart

- **File:** `crates/baluard-runtime/src/rate_limit.rs:8-10`
- **Evidence:** Design comment states in-memory only, resets on restart.
- **Impact:** A same-UID attacker can SIGKILL the daemon to reset lockout state. Acceptable given Argon2id dominates attack cost; document it.
- **Confidence:** high

#### C8 — Info: RNG hygiene

- **Evidence:** Rust generator uses `OsRng` with unbiased `gen_range` throughout (`generator/mod.rs:114-118,135-137`); zero `thread_rng` in any crate; the Rust code even documents the desktop's `% pool.length` bias (D7). `Math.random` does appear in desktop code (`context/ConflictResolutionContext.jsx:130,146`, `lib/conflictDevTriggers.jsx:63`) but only for mock conflict IDs in the dev trigger module, not for security values.
- **Confidence:** high

### 1.3 Runtime, daemon IPC, CLI, native messaging host

#### C9 — Medium: NMH debug log at fixed /tmp path: symlink-following, always-on, world-readable

- **File:** `crates/baluard-nmh/src/main.rs:28-33`
- **Evidence:** `OpenOptions::new().create(true).append(true).open("/tmp/baluard-nmh.debug.log")` with no `create_new`, no `O_NOFOLLOW`, no mode.
- **Impact:** Any local user can pre-plant a symlink at that path before the victim's first NMH run; the NMH appends log lines into an attacker-chosen victim-writable file (integrity attack; sticky /tmp does not prevent symlink creation). The created file is 0644, leaking extension activity (actions, timing) to other local users on multi-user hosts. The hook is unconditional in release builds ("always-on while stabilizing").
- **Fix:** Gate behind an env var, write to the platform state/log dir, open with `create_new` plus 0600, or delete the hook.
- **Confidence:** high (re-verified)

#### C10 — Medium: master-password rate limiter resets via unauthenticated `vaults.close` + re-unlock

- **File:** `crates/baluard-daemon/src/handler.rs:851` (`vaults.close`, host-level, no token), `crates/baluard-runtime/src/state.rs:89,117,124` (limiter lives per `VaultState`, re-created by `get_or_insert_with`)
- **Evidence:** `pub rate_limiter: crate::rate_limit::RateLimiter` is a field of `VaultState`; `vaults.close` drops the state from the host map; next unlock constructs a fresh limiter.
- **Impact:** A same-UID process interleaving `vaults.close` and failed `vault.unlock` calls grinds the master password at full Argon2id speed with no backoff. The on-disk counter (`kdf-attempts.json`, C6) is editable by the same attacker, so the documented "Argon2id is primary defense" becomes the only defense.
- **Fix:** Move the limiter to a process-global map on `VaultHost` keyed by canonical vault path, surviving close/open cycles, as the `rate_limit.rs` header already prescribes.
- **Confidence:** high (re-verified)

#### C11 — Medium: slug joined into filesystem path before validation in `vault.create` / `vault.clone_start`

- **File:** `crates/baluard-daemon/src/handler.rs:2237-2239` (create), `2394-2395` (clone)
- **Evidence:** `let vault_path = baluard_core::paths::vaults_dir().join(&slug);` where `slug` comes from the request payload; `validate_slug` runs later inside `VaultRegistry::add`, after disk writes.
- **Impact:** `slug = "../../tmp/x"` writes a new vault (kdf params, git init, device-privkey.json) or performs a provider git clone into an arbitrary user-writable path outside the vaults directory. Both routes are pre-token (reachable by any same-UID socket client). Same-UID-only impact, but it breaks the vault-sandbox invariant, and the create path's failure cleanup calls `remove_dir_all` on the traversed target (`handler.rs:2253`).
- **Fix:** Call `validate_slug` before computing any path in both handlers.
- **Confidence:** high (re-verified)

#### C12 — Medium: reprompt grant token minted but never verified daemon-side (T11 divergence)

- **File:** `crates/baluard-runtime/src/state.rs:3063-3092`; `crates/baluard-daemon/src/handler.rs` (zero occurrences of grant verification)
- **Evidence:** `reprompt_verify` returns `grant_token` + 30s expiry to the client; no daemon code ever checks it; `vault.get` serves reprompt-protected ciphers with the session token alone.
- **Impact:** The threat model (T11) claims "the daemon tracks grant state internally". It does not. Reprompt is a client-side UI policy only. Composed with C2 (token file on disk), a same-UID process holding the session token reads reprompt-protected ciphers without the master password.
- **Fix:** Track grants in `VaultState` (cipher scope + expiry) and enforce in `get_cipher` when `reprompt` is set; or correct the threat model to state the control is UI-only.
- **Confidence:** high (re-verified)

#### C13 — Medium: `bridge.pair_complete` is first-caller-wins after approval (upgraded from Low after peer validation)

- **File:** `crates/baluard-daemon/src/handler.rs:1389-1400` (approved fast path), `1414-1418` (waiter path), `1685-1711` (`finalize_pair` returns secret and token)
- **Evidence:** the approved fast path returns `finalize_pair(...)` to whichever process calls `pair_complete` first; the response includes the long-lived pairing secret.
- **Impact:** Approval binds to the first caller, not to the extension that started the ceremony; a same-UID process holding a registered waiter steals the fresh bridge token and the pairing secret the instant the user approves. The pairing secret mints bridge tokens indefinitely (durable vault-read capability), which places this above hardening. Within the same-UID trust model, but it cancels the ceremony's added value.
- **Fix:** Bind `pair_start` to a one-time nonce delivered out-of-band through the NMH spawn; stop returning the pairing secret on this route.
- **Confidence:** medium

#### C14 — Low: CLI plaintext writes leave secret files world-readable or chmod-after-write

- **File:** `crates/baluard-cli/src/commands/mod.rs:2379` (attachment download, no chmod), `2229-2235` (export: write, then chmod 0600)
- **Impact:** Decrypted attachment export lands 0644 (umask-dependent); export has a world-readable window and follows pre-planted symlinks.
- **Fix:** Use `OpenOptions` with `mode(0o600)` + `create_new` semantics for both, mirroring `set_session_token`.
- **Confidence:** high

#### C15 — Low: secrets accepted via CLI flags and environment without warnings

- **File:** `crates/baluard-cli/src/main.rs:247` (`--phrase`), `468,475-476` (card number/CVV), `569` (SSH private key); `commands/mod.rs:1304` (`BALUARD_RECOVERY_PHRASE`); the sole argv warning sits at `main.rs:743`
- **Impact:** The 24-word recovery phrase (vault root authority), card data, and SSH keys are visible in the process list to other local users; env vars propagate to child processes. Only `add login --password` prints an argv warning.
- **Fix:** Print the same warning for all secret-valued flags, or prompt exclusively.
- **Confidence:** high

#### C16 — Low: unauthenticated `vault.clone_start` with unbounded job map

- **File:** `crates/baluard-daemon/src/handler.rs:2356, 2425`
- **Evidence:** `static CLONE_JOBS` grows per call; entries removed only by `clone_finalize`, which an attacker never calls.
- **Impact:** Same-UID DoS: unlimited concurrent clones (network egress with the stored provider token, disk writes) plus unbounded memory growth and blocking-pool saturation.
- **Fix:** Cap concurrent jobs and total entries, add TTL eviction, rate-limit per caller.
- **Confidence:** high

#### C17 — Low: attachment ciphertext written with default permissions

- **File:** `crates/baluard-runtime/src/state.rs:2792`
- **Evidence:** `std::fs::write(&attach_path, &encrypted)` bypasses the atomic 0600 `write_vault_file` used everywhere else.
- **Fix:** Route attachment writes through `write_vault_file`.
- **Confidence:** high

#### C18 — Info: Windows transport not implemented; pipe-ACL claim unenforced

- **File:** `crates/baluard-daemon/src/handler.rs:4486-4489` (no-op `verify_peer_uid` under `cfg(not(unix))`)
- **Impact:** The threat model asserts Windows named-pipe ACLs; no Windows IPC path exists in code today. Documentation gap, not an exploitable path.
- **Fix:** Implement pipe creation with a user-SID-restricted DACL when Windows support lands; until then, soften the claim.
- **Confidence:** high

#### C19 — Info: pre-unlock routes enumerate vault metadata to any socket client

- **File:** `crates/baluard-daemon/src/handler.rs:755-763` (`vaults.list` returns slug, display name, disk path, lock state), `vault.pin_status` / `vault.biometric_status` untokenized
- **Impact:** Any same-UID process learns every vault's name, location, and armed shortcuts before any unlock. Needed by the desktop login screen, but it is the richest unauthenticated surface.
- **Fix:** Return slugs only while locked; gate full rows behind unlock.
- **Confidence:** high

#### C20 — Info: `favicon.get` shells out to `curl` from PATH

- **File:** `crates/baluard-runtime/src/state.rs:1560-1567`
- **Impact:** PATH hijack executes code in the daemon (same-UID only); because `extract_domain` (`state.rs:1608-1623`) strips scheme, path, port, and `?`, the residual injection is limited to appending extra query parameters (`&`, `#`) to the Google favicon URL. Token-gated and default-off.
- **Fix:** Use the in-tree HTTP client; percent-encode the domain.
- **Confidence:** medium

#### C21 — Medium: bridge `vault.update` field gate checks presence only; omission silently deletes passkeys and URIs (added after peer validation)

- **File:** `crates/baluard-daemon/src/handler.rs:1659-1677` (gate), `crates/baluard-runtime/src/state.rs:1688-1693` (update path), `crates/baluard-core/src/types.rs:333-355` (`#[serde(default)]` on every `LoginData` field)
- **Evidence:** `bridge_update_touches_forbidden` rejects only payloads that contain `fido2_credentials` or `uris`; `update_cipher` deserializes `kind` wholesale and replaces the existing kind; `LoginData` fields all default when absent.
- **Impact:** A bridge client sends `{"id":..,"kind":{"type":"login","data":{"username":"x","password":"y"}}}`: the gate passes (forbidden keys absent), and the wholesale replacement silently deletes every passkey and URI on that login. A compromised browser gains exactly the destructive capability the field gate exists to deny (Decision 13), expressed as omission rather than touch.
- **Fix:** Compare the deserialized new kind against the existing kind: reject when previously-present fido2_credentials or uris become absent or shrink; or deny `vault.update` on the bridge entirely (the extension rarely needs it).
- **Confidence:** high

#### C22 — Medium: in-memory rate limiter covers three paths, not five (added after peer validation; corrected after lead validation)

- **File:** `crates/baluard-daemon/src/handler.rs:1915` (unlock), `2108` (biometric), `2174` (PIN) — the only `claim_attempt` call sites
- **Evidence:** `runtime/rate_limit.rs` module docs claim coverage of unlock, recovery, emergency approval, biometric, and PIN; the code wires three. Validation additionally established there is no `emergency.*` or `vault.recover` IPC route at all (`emergency.rs` is library-only behind a feature flag); the one recovery-adjacent route, `vault.enroll_with_phrase` (`handler.rs:3262-3282`, token-gated), is also unwired.
- **Impact:** The design claim and the wiring disagree. Phrase enrollment — the vault's root-of-trust path — carries no in-memory throttle (the phrase verifies via HPKE unwrap of a 256-bit-entropy secret, so the throttle is hygiene rather than brute-force defense, but it should still exist).
- **Fix:** Wire `claim_attempt` into `vault.enroll_with_phrase`; rewrite the module docs to name actual coverage (unlock, biometric, PIN, enroll_with_phrase, reprompt once C23 lands) and state that emergency access has no IPC surface.
- **Confidence:** high (re-verified)

#### C23 — Medium: `vault.reprompt_verify` is an unthrottled Argon2id oracle (added after peer validation)

- **File:** `crates/baluard-daemon/src/handler.rs:3230-3245`, `crates/baluard-runtime/src/state.rs:3063-3071`
- **Evidence:** the route performs a full `VaultHandle::unlock` per attempt and has no `claim_attempt` call; only the attacker-writable on-disk counter (C6) applies.
- **Impact:** A same-UID process grinds the master password through this route with no in-memory backoff, the same hole C10 describes but on a route C10 does not cover. Token-gated, so it composes with C2 (token on disk) for an unattended grind.
- **Fix:** Route `reprompt_verify` through the same limiter as `vault.unlock` (or fold it into the unlock limiter key).
- **Confidence:** high

#### C24 — Low: `baluard-core` does not compile for Windows (added after peer validation)

- **File:** `crates/baluard-core/src/vault/mod.rs:27-34`
- **Evidence:** `write_vault_file` imports `std::os::unix::fs::PermissionsExt` with no `#[cfg(unix)]`; it is used on every vault write path.
- **Impact:** Windows 11 is a stated minimum platform, yet the core cannot build there today. Security-relevant because audit and design reasoning (including C1's Windows ACL discussion) presumes a compiling Windows path. The released artifacts so far are macOS/Linux only, which bounds the impact to a platform gap, not a shipped vulnerability.
- **Fix:** Gate the import and provide a Windows branch (explicit DACL or at minimum an atomic write without the Unix mode call); add Windows to CI before the Windows release.
- **Confidence:** high

#### C25 — Low: provider token file has a world-readable write window (added after peer validation)

- **File:** `crates/baluard-core/src/providers/token.rs:143-149`
- **Evidence:** `std::fs::write(&tmp, secret)` at umask default, then `set_permissions(0o600)` after — the same write-then-chmod pattern as C14, applied to live OAuth/PAT credentials on every keyring-less target.
- **Impact:** Short window where provider tokens are readable by other local users on multi-user hosts.
- **Fix:** Use the `OpenOptions::mode(0o600)` pattern from `set_session_token`, or a shared `write_secret_file` primitive. This and C14/C17 are one fix: a single secret-file writer used everywhere.

---

## Part 2: Desktop (Tauri v2 + SolidJS)

### 2.1 Verified-solid patterns

- **Session tokens never reach the webview.** Tokens ride the protobuf `session_token` field, are stored Rust-side in `Zeroizing<String>` keyed by slug (`src-tauri/src/lib.rs:256`), and `DaemonResponse` exposes only success, payload, and error.
- **XSS posture is clean.** Zero `innerHTML`/`insertAdjacentHTML` in production code; all cipher fields render via Solid text interpolation; notes render as plain pre-wrap text with no Markdown pipeline.
- **External surface tightly ACL'd.** Opener restricted to http/https only (blocks `file:`, `smb:`, custom schemes); shell spawn restricted to the `baluard-daemon` sidecar; no fs/http/request plugins; `withGlobalTauri` unset; devtools not enabled in release; `connect-src ipc:` prevents arbitrary fetches.
- **Favicon fetching is SSRF-safe by construction.** Opt-in (default off), proxied through the Google favicon service (target host never fetched directly), magic-byte validated, 16 KB cap.
- **Clipboard hygiene centralized.** Every secret copy routes through `copyToClipboard` with conditional 30-second auto-clear that will not overwrite a newer user copy; frontend generators use `crypto.getRandomValues` exclusively.
- **Lock lifecycle coherent.** Vault subtree unmounts on lock; blur lock debounced with abort-on-refocus.

### 2.2 Findings

#### D1 — Medium: `write_text_file` exposes arbitrary-path write to the webview

- **File:** `desktop/src-tauri/src/lib.rs:358-361`
- **Evidence:** `fn write_text_file(path: String, contents: String)` writes to any user-writable path; the doc comment claims the path "always comes from the native save dialog" but nothing enforces it.
- **Impact:** Any JS executing in the webview (future XSS, compromised npm dependency, devtools) writes arbitrary contents to `~/.zshrc`, launch agents, or shell rc files: user-level persistence. The app is not App-Sandboxed on macOS. The one legitimate caller (recovery-phrase download, `RecoveryScreen.jsx:84`) always passes a dialog path, so enforcement is free.
- **Fix:** Mint a one-shot token from a `save_dialog` bridge command and validate it in `write_text_file`, or move the whole save flow into Rust (`tauri-plugin-dialog`) and delete the command.
- **Confidence:** high (re-verified)

#### D2 — Medium: `daemon_request` is a transparent RPC with no action allowlist

- **File:** `desktop/src-tauri/src/lib.rs:187-196`
- **Evidence:** `daemon_request(action, payload, slug)` forwards any action string to the daemon socket with the stored session token.
- **Impact:** Token gating protects vault routes, but host-level routes are untokenized by design: `vaults.detach` with `delete_from_disk` + `force` (the deliberately CLI-only destructive arm), `vault.clone_start`, `provider.*`. The daemon cannot distinguish the desktop bridge from the CLI (same socket, same UID), so the destructive detach arm is reachable from the webview. With no XSS found today this is defense-in-depth, but the webview is the least-trusted component in this architecture.
- **Fix:** Allowlist the actions the desktop UI actually uses inside `daemon_request`; require a separate capability for destructive params the desktop never sends.
- **Confidence:** high

#### D3 — Medium: master password retained in signal for entire app lifetime

- **File:** `desktop/src/context/AuthContext.jsx:41,136`, `desktop/src/components/SetupScreen.jsx:49,137-140`
- **Evidence:** `const [createPassword, setCreatePassword] = createSignal("")` is set during onboarding and never cleared after `finish()` transitions to `unlocked`.
- **Impact:** The vault master password stays live in webview heap for hours or days of uptime. JS strings cannot be zeroized; a devtools snapshot, heap dump, or any future webview disclosure reads it. The login-screen password input is correctly cleared, so this is the one copy that outlives its purpose.
- **Fix:** `auth.setCreatePassword("")` in `SetupScreen.finish()` and defensively in `AuthContext.lock()`; re-read from the DOM input when needed.
- **Confidence:** high (re-verified)

#### D4 — Low: copied secrets not marked concealed for clipboard history

- **File:** `desktop/src/lib/clipboard.js:14-16`
- **Evidence:** Secrets go through plain `navigator.clipboard.writeText` with a 30-second auto-clear.
- **Impact:** Clipboard managers and cloud clipboard sync capture passwords, TOTP codes, and the recovery phrase during the window (and permanently if history snapshots it). Native password managers set the concealed pasteboard type (`org.nspasteboard.ConcealedType` / `ExcludeFromClipboardHistory`) so history tools skip the entry.
- **Fix:** Route secret copies through a Rust command that sets the concealed marker in addition to the 30-second overwrite.
- **Confidence:** medium

#### D5 — Low: two Tauri commands do blocking socket I/O on the main thread

- **File:** `desktop/src-tauri/src/lib.rs:310, 323`
- **Evidence:** `fn daemon_status()` and `fn lock_all_vaults()` are synchronous commands doing blocking Unix-socket reads with a 30-second timeout.
- **Impact:** A hung daemon freezes the UI thread up to 30 seconds, including on the blur-triggered lock path (exactly when the user switches away). `daemon_request` already received the async + spawn_blocking fix; these two were missed.
- **Fix:** Make both async and wrap the socket call in `spawn_blocking`, mirroring `daemon_request`.
- **Confidence:** high

#### D6 — Low: favicon mime from synced or imported ciphers flows unvalidated into data: URI

- **File:** `desktop/src/components/CipherAvatar.jsx:17-19,37`
- **Evidence:** `` `data:${f.mime};base64,${f.data}` `` uses the stored mime verbatim; daemon-fetched favicons are validated, but favicons arriving via git sync or import carry attacker-chosen mime.
- **Impact:** Not exploitable today (WebKit disables scripts and external loads in SVG-as-image), but an attacker-influenced content type flows into a URI context from a compromised sync peer.
- **Fix:** Whitelist `image/png|jpeg|webp|x-icon` in `faviconSrc()`; render the initials fallback otherwise.
- **Confidence:** high (finding), low (exploitability)

#### D7 — Low: modulo bias in frontend generators

- **File:** `desktop/src/lib/utils.js:43,83`
- **Evidence:** `result += pool.charAt(arr[i] % pool.length)` over `getRandomValues` output.
- **Impact:** `2^32 % pool.length` is nonzero for all used pool sizes, so earlier characters are marginally more probable (~1e-7 relative). Cryptographically negligible, but rejection sampling is free in a password generator.
- **Fix:** `const limit = 2**32 - (2**32 % pool.length);` redraw while `arr[i] >= limit`.
- **Confidence:** high (math)

#### D8 — Info: `mailto:` entry URIs are dead links

- **File:** `desktop/src/components/CipherDetail.jsx:396-399`, `desktop/src-tauri/capabilities/default.json:12-17`
- **Impact:** The opener ACL correctly allows only http/https (good), which also rejects the deliberately passed-through `mailto:` URIs; the click throws an unhandled rejection and silently does nothing.
- **Fix:** Add `mailto:*` to the opener allow-list or drop the special case; toast on open failure.
- **Confidence:** high

#### D9 — Info: dev conflict-trigger module shipped in production bundle

- **File:** `desktop/src/App.jsx:114`, `desktop/src/lib/conflictDevTriggers.jsx:30`
- **Impact:** Setting the `baluard.dev.conflictTrigger` localStorage flag activates mock conflict-injection UI in production. No secret impact; dev affordances in prod enlarge surface and bundle.
- **Fix:** Gate behind `import.meta.env.DEV` with a dynamic import.
- **Confidence:** high

#### D10 — Info: supply-chain observations

- **File:** `desktop/package.json:15` (community biometry plugin `@choochmeque/tauri-plugin-biometry-api ^0.2.8`), `desktop/src-tauri/tauri.conf.json:28` (CSP `style-src 'unsafe-inline'`), no updater plugin configured.
- **Impact:** Biometry comes from an unofficial community plugin: provenance and maintenance should be a conscious choice for a password manager (its granted scope is appropriately narrow: checkStatus/authenticate only). `style-src 'unsafe-inline'` is required by Solid's inline style attributes and cannot execute script; `script-src 'self'` is strict. No updater means no signature-verification risk, but also no security-patch delivery channel. No known-vulnerable dependency versions were identified.
- **Fix:** Pin exact versions for the biometry plugin and review it on upgrades; plan a signed update channel.
- **Confidence:** medium (provenance judgment), high (CSP and updater facts)

---

## Part 3: Browser Extension (MV3, Chrome + Firefox)

### 3.1 Verified-solid patterns

- **The NMH is not a dumb pipe.** Action allowlist enforced in both NMH and daemon (`baluard-nmh/src/main.rs:227-236`, `baluard-core/src/bridge/token.rs:48-59`), 30 reads/minute cap with auto-revoke on `vault.get`, and `vault.update` field-gated against explicit fido2_credentials and uris mutation (the gate has an omission bypass; see C21). A browser compromise is bounded, not unbounded.
- **Credential delivery is push, never response.** The fill secret travels via `tabs.sendMessage` with `expectedOrigin` derived from privileged `sender.tab.url`; a page-compromised handler cannot read it out of a message response (`background.js:173-193`).
- **Fill requires user gestures on extension-owned UI** in a closed shadow root; no auto-fill on load, no auto-submit; the page cannot synthesize clicks or read rendered entries (`inline.js:37-46,143-162`).
- **Top-frame-only posture.** Inline script registered `allFrames: false`, popup fill injects `frameIds: [0]`; no cross-origin iframe fill surface.
- **No secrets at rest in the browser.** No vault data in `chrome.storage`; bridge token lives in NMH memory; TOTP seed never crosses (only the derived code); clipboard auto-clears after 20 seconds via an alarm that survives service-worker death.
- **Match queries use privileged URLs.** `sender.tab.url` drives matching, non-http(s) senders fail closed, and all extension UI renders with `textContent`/`escapeHtml`, no `innerHTML` with vault data. No `web_accessible_resources`, no `externally_connectable`, no remote code, no eval (MV3 default CSP).

### 3.2 Findings

#### B1 — High: fill-time origin re-check compares hostname only; scheme and port dropped

- **File:** `browser/shared/src/content.js:31-32`, `browser/shared/src/inline.js:217-218`, `browser/shared/src/background.js:158-161,189`
- **Evidence:** `expectedOrigin: hostnameOf(url)` where `hostnameOf` returns `new URL(url).hostname` only; fill site compares `location.hostname.toLowerCase() !== msg.expectedOrigin`.
- **Impact:** A tab that navigates from `https://example.com` to `http://example.com` (same hostname) passes the re-check, so a credential matched on HTTPS can be filled into a plaintext-HTTP page after a downgrade or redirect; a network attacker reads the submitted password. Same-hostname different-port origins also pass. This is the only origin enforcement at fill time.
- **Fix:** Pass `expectedOrigin = new URL(url).origin` and compare `location.origin === msg.expectedOrigin` (scheme + host + port). If HTTP intranet fills are a product requirement, gate them behind an explicit user opt-in rather than silent hostname equality.
- **Confidence:** high (re-verified)

#### B2 — Medium: sender-gated inline routes reference an undeclared `sender`; the gate is dead code

- **File:** `browser/shared/src/background.js:211,231,237` (listener parameter is `_sender`; guards read bare `sender`)
- **Evidence:** `chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => { ... if (msg.action === "inline.matches" && sender && sender.tab)`. There is no global `sender` in a service worker; the minified dist bundle ships the same free reference.
- **Impact:** Any `inline.matches` or `inline.fill` message throws a ReferenceError inside the listener; the two sender-gated routes never execute. Fails closed today (the inline UI shows no logins), but the security gate the inline-autofill design rests on has never run in the shipped build, and tests never invoke the listener.
- **Fix:** Rename the parameter to `sender`; add a test that captures the listener via a mocked `chrome.runtime.onMessage` and drives both routes with fake senders (privileged and not).
- **Confidence:** high (re-verified)

#### B3 — Medium: `vault.get` from the bridge is never bound to the requesting origin

- **File:** `browser/shared/src/background.js:180`, `crates/baluard-daemon/src/handler.rs:1640-1651`
- **Evidence:** `handleInlineFill` validates the sender tab URL, then requests the credential by id alone; the URL never reaches `vault.get`. Daemon-side, `route_bridge_request` delegates `vault.get` to the generic handler with no origin check, and it substitutes the vault's own full desktop session token into the delegated request (`handler.rs:1640-1643`), so the bridge path executes with unrestricted vault authority behind only the action allowlist; the 30 reads/minute cap is the sole bound.
- **Impact:** The only binding between "credential X may fill origin Y" is the extension UI flow. Any extension-context bug that lets a page influence a fill id turns the bridge into "read any vault entry by UUID" from a page-adjacent context, bounded only by the read cap.
- **Fix:** Send the tab URL with the fill request and enforce server-side: reject `vault.get` (and `cipher.totp_code`) unless the cipher's URI set matches the URL under the vault's `default_uri_match` policy. Move the invariant from the UI into the trust boundary holder.
- **Confidence:** high

#### B4 — Medium: generic onMessage fallback forwards arbitrary actions to the NMH with no sender allowlist

- **File:** `browser/shared/src/background.js:242-246`
- **Evidence:** Every action other than `clipboard-copy`, `inline.matches`, `inline.fill` is forwarded verbatim to the native host regardless of sender, including content-script senders that run in the page's principal.
- **Impact:** Latent today (no content script sends other actions, `externally_connectable` absent), but one page-influenced action string becomes daemon access: `vault.get` (secret read), `vault.add`, `vault.update` (credential poisoning), bounded by the NMH/daemon allowlist and read cap.
- **Fix:** Split routing by sender privilege: extension pages (`sender.id === chrome.runtime.id && !sender.tab`) get the full set; content-script senders (`sender.tab` present) get only the two inline routes, everything else dropped.
- **Confidence:** high

#### B5 — Low: credential push uses `tabs.sendMessage` without `frameId`

- **File:** `browser/shared/src/background.js:187-193`, `browser/shared/src/popup.jsx:322-329`
- **Impact:** The fill message carrying username and password is broadcast to every frame in the tab. Safe only because all current listeners live in the top frame; one future frame-scoped listener and credentials reach cross-origin iframes.
- **Fix:** Pass `frameId: 0` in both pushes and mark it load-bearing with a comment.
- **Confidence:** high

#### B6 — Low: offscreen clipboard bridge accepts copy commands from any extension context

- **File:** `browser/shared/src/offscreen.js:9-25`
- **Impact:** Any extension context or a compromised content script can overwrite the user clipboard with arbitrary text (spoofing adjacent to password flows). `offscreen-clear` overwrites with a single space, which some clipboard managers retain.
- **Fix:** Check `sender.id === chrome.runtime.id && !sender.tab` in the handler.
- **Confidence:** high

#### B7 — Low: version-skew gate has a connect-time race and does not cover direct sends

- **File:** `browser/shared/src/background.js:56-79,107-110`
- **Impact:** Between port connect and ping resolution, `versionInfo` is null and skew is unset, so actions can run against an old NMH before the handshake marks skew; the gate covers only the `onMessage` route, not `send()` callers.
- **Fix:** Fail closed: initialize `versionSkew = true`, clear only on successful handshake, and queue non-ping sends until the first ping resolves.
- **Confidence:** medium

#### B8 — Low: Firefox build ships Chrome-only offscreen machinery; clipboard path throws

- **File:** `browser/firefox/dist/manifest.json:19-26`, `browser/shared/src/background.js:269-276`
- **Impact:** Firefox has no `chrome.offscreen`; `clipboardCopy` rejects and copy buttons fail. The `offscreen` permission in the Firefox manifest is an unknown-permission warning at AMO review.
- **Fix:** Feature-detect `chrome.offscreen` and fall back to `navigator.clipboard.writeText` in the popup context; drop the permission from the Firefox merge.
- **Confidence:** medium

#### B9 — Info: all http/https URLs granted; inline icon and fills run on plaintext-HTTP pages

- **File:** `browser/shared/manifest.base.json:19`, `browser/shared/src/background.js:330-339`
- **Impact:** `http://` inclusion means fills into non-TLS origins are structurally allowed (compounds B1). Broad host permissions are standard for password managers, but the scheme policy point is the daemon matcher.
- **Fix:** Make daemon-side matching scheme-aware or https-only with an explicit user override.
- **Confidence:** high

#### B10 — Info: browsing metadata flows to the daemon on every tab switch

- **File:** `browser/shared/src/background.js:294-315`
- **Impact:** Every activated/updated tab URL is sent to the NMH and daemon for badge counts. Local trusted processes, but the NMH debug tee (C9) accumulates a browsing-history side channel if it logs payloads.
- **Fix:** Ensure the NMH debug log excludes URLs (it logs action names only today); document the flow in the privacy statement.
- **Confidence:** medium

#### B11 — Info: dist bundles match shared/src; no stale-build drift

- **Evidence:** dist manifests equal base + extra merges; dist scripts are current minifications of src (including the B2 bug, proving same-source); no CSP override, no `web_accessible_resources`, no `externally_connectable`, no remote code.
- **Fix:** Keep a CI check that fails when dist and src diverge.
- **Confidence:** high

---

## Part 4: Mobile (Android)

### 4.1 Verified-solid patterns

- **Biometric quick-unlock is genuinely cryptographic.** BiometricPrompt.CryptoObject wraps an AndroidKeystore AES-256-GCM key with `setUserAuthenticationRequired(true)` and `AUTH_BIOMETRIC_STRONG` only (no DEVICE_CREDENTIAL fallback), fails closed on KeyPermanentlyInvalidatedException with blob and key deletion, rotates on re-enroll (`platform/Biometric.android.kt:100-190,232-252`). The KEK, not the password, is what is wrapped; Rust still verifies keywrap and canaries.
- **Manifest hygiene.** `allowBackup="false"`, minSdk 32 / targetSdk 35, single exported launcher activity, autofill service gated by `BIND_AUTOFILL_SERVICE`, no `usesCleartextTraffic`, no debuggable flag, no deep links or custom schemes anywhere.
- **No deep-link hijack surface.** OAuth uses the RFC 8628 device flow (user code plus manual browser open); no custom-scheme callback exists to capture tokens.
- **Background sync cannot touch secrets by construction.** The WorkManager job calls only `fetch_locked` (git objects, no unlock, no decrypt, no checkout; `baluard-uniffi/src/lib.rs:920-931`), 15-minute floor, unmetered constraint, opt-in default off.
- **Secret-display discipline.** TOTP seed never crosses the FFI (derived code only), cipher listing masks values, sensitive fields sit behind reveal toggles, unlock errors are generic strings. Vault, KEK blob, and token files live in app-private storage with 0600 atomic writes. No analytics or crash SDKs in the dependency tree. Debug keystore is gitignored; release build is unsigned; `local.properties` holds only `sdk.dir`.

### 4.2 Findings

#### M1 — High: FLAG_SECURE is a no-op; the cast target is never an Activity

- **File:** `mobile/shared/src/androidMain/kotlin/xyz/actitud/baluard/platform/SecureFlag.android.kt:12`, `AppContextHolder.kt` (`get()` returns the application context; the holder tracks the host activity separately)
- **Evidence:** `val window = (AppContextHolder.get() as? android.app.Activity)?.window ?: return` — the stored context is `context.applicationContext`, never an Activity, so the cast is always null and the function returns silently on every call.
- **Impact:** FLAG_SECURE is never applied. The 24-word recovery phrase (full vault recovery material) and every other screen appear in the recents thumbnail and are capturable by unprivileged screen recording. The single call site (`RecoveryPhraseScreen.kt:61`) believes it is protected.
- **Fix:** Use `AppContextHolder.activity()?.window` (the accessor that already exists). Add a debug assertion that the flag actually lands on a window.
- **Confidence:** high (re-verified)

#### M2 — High: clipboard copies lack EXTRA_IS_SENSITIVE and are never cleared

- **File:** `mobile/shared/src/androidMain/kotlin/xyz/actitud/baluard/platform/Clipboard.android.kt:7-11`
- **Evidence:** `cm.setPrimaryClip(ClipData.newPlainText("Baluard", text))` (line 10) with no `ClipDescription.EXTRA_IS_SENSITIVE` extras and no overwrite. Callers copy passwords, TOTP codes, generator output, and the full recovery phrase.
- **Impact:** On Android 13+ the system clipboard overlay renders the copied secret in plaintext on screen and clipboard-history IMEs (Gboard) may retain it. The recovery phrase copy is the worst case.
- **Fix:** Set `clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }` behind an API 33 guard; overwrite the clip after a timeout while foregrounded.
- **Confidence:** high (re-verified)

#### M3 — High: git provider tokens stored as plaintext files on Android

- **File:** `crates/baluard-core/src/providers/token.rs:123-151`
- **Evidence:** `keyring_is_persistent()` lists macOS/iOS/Windows/Linux/BSD only; every other target (Android) falls to `store_token_file`, writing the raw token to app-private storage as plaintext JSON. The 0600 set before rename does apply on Android (it is a `cfg(unix)` target) and app-private storage adds UID isolation, but neither encrypts the credential at rest.
- **Impact:** OAuth device-flow tokens and PATs (full vault-repo read/write against the provider) sit in cleartext on disk. Desktop parity is broken: the same tokens live in the OS keyring there. Root compromise, forensic acquisition, or any future backup-rule loosening yields live provider credentials; the vault itself is encrypted, so the tokens are strictly easier to steal than vault contents.
- **Fix:** Platform hook so Android encrypts the token file under an AndroidKeystore AES-GCM key (EncryptedSharedPreferences or a Keystore-wrapped blob via the UniFFI callback interface), keeping the plaintext path for headless tests only.
- **Confidence:** high (re-verified)

#### M4 — Medium: FLAG_SECURE coverage is per-screen opt-in even if the no-op is fixed

- **File:** `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/onboarding/RecoveryPhraseScreen.kt:60-63` (only call site)
- **Impact:** Unlock screen, vault list, cipher detail with revealed secrets, and generator output have no screenshot or recents protection. Standard password-manager behavior is flag-on for the whole app.
- **Fix:** Set FLAG_SECURE once in MainActivity onCreate (or the root composable), not per-screen.
- **Confidence:** high

#### M5 — Low: secrets cross the FFI boundary as GC-managed Strings and ByteArrays (downgraded from Medium after peer validation)

- **File:** `crates/baluard-uniffi/src/lib.rs:160,288,307,878-882`, `mobile/.../auth/UnlockScreen.kt:57`, acknowledged as DEBT in `platform/Biometric.android.kt:34-39`
- **Evidence:** `pub async fn unlock(&self, master_password: String)` plus Compose `remember { mutableStateOf("") }` produce non-zeroizable JVM copies of the master password, KEK, and recovery phrase.
- **Impact:** Rust-side zeroization does not cover the JVM heap; memory scraping or a heap dump retains master-password and KEK copies indefinitely. Documented tradeoff with a DEBT ceiling and no attacker path short of device compromise; listed for release awareness.
- **Fix:** Within the documented ceiling: derive the KEK in one pass, drop the password String reference immediately, zero-fill ByteArray wrappers after use, and never use `rememberSaveable` for secrets.
- **Confidence:** high (behavior), medium (exploitability)

#### M6 — Medium: PAT input is a cleartext field persisted in saved instance state

- **File:** `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/onboarding/ProviderConnectScreen.kt:63,130-134`
- **Evidence:** `var token by rememberSaveable { mutableStateOf("") }` rendered through `BaluardTextField` without `isPassword = true`.
- **Impact:** The provider token is displayed in cleartext (shoulder-surfing) and `rememberSaveable` serializes it into the instance-state Bundle held by system_server, surviving process death.
- **Fix:** Pass `isPassword = true`; use plain `remember` so the token dies with the composition.
- **Confidence:** high

#### M7 — Low: cipher URIs opened via ACTION_VIEW without scheme allowlist

- **File:** `mobile/.../detail/CipherDetailScreen.kt:237`, `platform/OpenUrl.android.kt:17-21`
- **Impact:** Vault entries (including imported ones) can carry `intent://` or custom-scheme URIs; ACTION_VIEW hands them to the resolver, enabling app-launch redirection and phishing lookalikes from a trusted tap.
- **Fix:** Allowlist http/https; warn on other schemes.
- **Confidence:** medium

#### M8 — Low: autofill service process isolation documented but not wired

- **File:** `mobile/androidApp/src/androidMain/AndroidManifest.xml:22-35`, `mobile/.../autofill/KeystoreKekProvider.kt:11-17`
- **Evidence:** The manifest comment promises a separate process; no `android:process=":autofill"` attribute exists. `retrieveKek()` returns null (Phase 6 TODO), so the service returns empty responses today.
- **Impact:** Safe now, but when the KEK path lands in the default process, the isolation invariants the design relies on will silently not hold.
- **Fix:** Add the `android:process` attribute before enabling the credential path; assert it in a test.
- **Confidence:** high

#### M9 — Info: native TLS stack sits outside Android network security config; no pinning

- **File:** `mobile/androidApp/src/androidMain/AndroidManifest.xml` (no networkSecurityConfig), `crates/baluard-uniffi/src/lib.rs:738-824`
- **Impact:** All network I/O (OAuth device flow, git fetch/push) runs in the Rust cdylib; CA trust and TLS policy are baked into the Rust stack, outside Android's NSC. No pinning: a compromised CA can intercept provider API and git traffic. Accepted tradeoff; document it.
- **Fix:** Document the native-TLS trust decision; optionally pin provider API endpoints only.
- **Confidence:** high

#### M10 — Info: autofill failure callback exposes exception text

- **File:** `mobile/androidApp/src/androidMain/kotlin/xyz/actitud/baluard/autofill/BaluardAutofillService.kt:66`
- **Impact:** Rust error strings (paths, provider details) can surface in system autofill diagnostics. No secrets observed in error variants.
- **Fix:** Map to static error codes when the real implementation lands.
- **Confidence:** medium

---

## Remediation plan (validated)

Every fix path below was proposed against the codebase by the second-model reviewer and then re-validated by the lead auditor against source; where the two disagreed, the correction is noted inline. Notation: Effort S (<1h) / M (half day) / L (multi-day). Class = BLOCKER / FAST-FOLLOW / BACKLOG / DOCS.

### Fix status ledger

Tracks what is fixed and how, so work can resume without re-derivation. Status: DONE / PARTIAL (arms listed) / PENDING.

Progress snapshot (2026-08-23): every DONE row below is committed and pushed to `origin/main` in four commits:

- `2b3b861` fix(security): secret-file writes, rate limiting, slug gates, NMH log — C9, C10, C11, C12, C14, C16, C17, C21, C22, C23, C24 (Rust arm), C25, threat-model corrections
- `c1c2efa` fix(extension): origin-bound fills and sender privilege split — B1, B2, B3, B4, B5, B6, B9, B10 (browser/README.md included)
- `570f634` fix(mobile): app-wide FLAG_SECURE, sensitive clipboard, PAT masking — M1, M2, M4, M6
- `06cb478` fix(security): seal device private keys at rest (C1) — C1 + keyring test gate (`keyring_disabled()`, `BALUARD_DISABLE_KEYRING=1`)
- `e62ee3c` fix(security): move CLI session token to OS keyring (C2) — C2 + CLI harness keyring gate
- `54f78a7` fix(security): encrypt provider tokens at rest on Android (M3) — M3 + sealed-blob helpers + uniffi background_fetch C1-sweep fix

Companion fix shipped with C1 (not a finding): `baluard_core::keyring_disabled()` (`cfg!(test)` or `BALUARD_DISABLE_KEYRING=1`) gates every keyring call reachable from tests — unsigned test binaries were triggering interactive macOS keychain prompts that stalled suites and polluted the user keychain. Gated: `load_device_privkeys` (read + migration write), engine `load_signing_key`, daemon startup `disable_legacy_global`, CLI token store + CLI integration harness, provider token store. RESOLVED (c7af049): the last "mystery" prompts had two causes, both found empirically — (1) orphaned pre-gate test daemons from killed cargo runs (std never kills Child on drop; `DaemonHandle` now kills+reaps on Drop), and (2) the daemon_spawn TEST PROCESS itself: it links baluard-core as a dependency, so core's `cfg!(test)` arm is false there and an in-process keyring call prompted; the harness now sets `BALUARD_DISABLE_KEYRING=1` for its own process. RULE for new tests: any binary linking core that exercises keyring paths in-process needs the env var on the harness process, not just spawned children.

This document itself is deliberately NOT committed (PERMANENT rule: always local only, never stage it). The three L-effort items (C1, C2, M3) are DONE. Remaining PENDING rows: D-series desktop (D1-D10), extension B7/B8/B11, mobile M7/M8/M10. C-series is fully closed (2026-08-25 session: C3, C4, C5-code, C8→D9, C13, C15, C18-code, C19, C20).

| ID | Status | How fixed |
|---|---|---|
| C1 | DONE | New `vault::device_privkey` module: AES-256-GCM envelope over the privkey JSON sealed under `HKDF(KEK, "baluard-devkey-v1")` (file `meta/device-privkey.json` = `{"type":"baluard-devkey-seal-v1","envelope":"<base64>"}`). Both creation writers seal (KEK in scope); `UnlockedState.devkey_seal` retains the subkey (zeroized on lock; accessor on handle + VaultState); `unlock_with_kek` derives/passes it and LAZILY RE-SEALS legacy/phrase-flow plaintext files; `change_master_password` prechecks old-seal-open then rotates (no lockout window); engine `load_signing_key` + SyncEngine::new take `Option<&[u8;32]>` threaded through daemon autosync (3 spawn sites), sync routes, conflict merge/finalize, cover commit. Phrase-only flows (recovery, enroll) still write plaintext by necessity (no KEK exists pre-unlock) — re-sealed at first unlock; that window is the residual exposure, strictly shorter than before. Residual #2: CLI `--direct` sync passes `None` → sealed keystore-less vaults get unsigned commits (keyring still works). Tests: 5 module tests + sealed-at-rest/unlock-roundtrip/wrong-password + legacy-reseal e2e in creation.rs; 433 core tests green; daemon_spawn 8/8 through the real binary |
| C2 | DONE | CLI token store: keyring first (`baluard-cli` service, account `session:<socket>[:<slug>]`, human-readable for `security find-generic-password`), atomic-0600 file fallback when keyring unavailable/disabled (headless, CI, `BALUARD_DISABLE_KEYRING=1`); keyring success removes a stale fallback file; clear removes both stores. CLI integration harness sets the disable env (no keychain prompts). 2 unit tests (account naming, fallback round-trip + clear). Fallback mode = documented trust-equivalent-to-same-user (threat-model invariant 1 exception already recorded in T2) |
| C3 | DONE | `biometric::read_gated()` (macOS-only) added; `vault.biometric_status` + `vault.biometric_enable` responses carry `read_gated`; SettingsModal renders persistent inline warning under the Quick Unlock row when enabled + ungated (en+es: `settings.quickUnlockNoReadGate`); AutoLockButton enable path shows warning toast. biometric.rs header rewritten to state the asymmetry. TPM/KeyCredential arm stays deferred |
| C4 | DONE | Attachments now encrypt through the standard AEAD envelope: `Tier::fit` padding (incl. new `Tier::LENGTH_PREFIX` boundary fix — content exactly == tier size used to truncate silently in pad(), latent cipher-path bug too), `build_attachment_aad` (own domain `baluard-att-aad-v1`, binds vault+cipher+attachment+tier+epoch+seq), R7-1-style pre-decrypt AAD check. `MAX_ATTACHMENT_SIZE` 2MB→1.9MB (runtime+CLI messages updated). Rotation re-encrypt + runtime upload/download + tests updated; new tests: same-cipher swap blocked, cross-cipher/vault replay blocked, tier-uniform encrypted size. Wire break (old blobs undecryptable) accepted pre-1.0 |
| C5 | DONE | Code arm landed: `EncryptedSettings.device_names` map (uuid→name, encrypted under settings key); `VaultHandle::migrate_device_names_into_settings()` fold-and-strip runs on every unlock (idempotent, re-folds legacy-remote reimports; best-effort); `save_settings` preserves the map. Engine identity switched name→device UUID (`SyncEngine::device_id`, `device_id_and_epoch` by uuid, daemon/CLI `first_device_id()` helper); autosync threads device ids; uniffi lifecycle hooks use new `VaultState::device_id()`, `device_name()` reads the encrypted map (registry fallback pre-migration). `vaults.list`-level `devices` route joins the map. Threat-model residual risk 7 updated. Enrollment (pre-unlock) still writes plaintext name; folded at first unlock |
| C6 | DONE | documented advisory-only in threat-model T12 (layer 3); accepted limitation |
| C7 | DONE | documented in threat-model T12 (layer 2, volatile + coverage-scoped) |
| C8 | DONE | Folds into D9, done there: dev trigger dynamically imported behind `import.meta.env.DEV` in App.jsx; mocks extracted to `lib/conflictMocks.js` (dev-trigger-only import). Prod bundle verified: 0 hits for `conflictTrigger`/`Math.random`/`mockSample` |
| C9 | DONE | tee gated behind `BALUARD_DEBUG=1`, relocated to `paths::log_dir()`, create_new 0600 with regular-file-only append fallback (symlink refused). Integration tests spawn the real binary: `debug_tee_never_follows_preplanted_symlink`, `debug_tee_disabled_without_env_and_0600_when_enabled` |
| C10 | DONE | WS2: process-global `rate_limit::global()` (OnceLock), per-state field removed, 3 call sites repointed; tests `global_is_single_instance` + `global_counters_survive_state_lifetimes` prove counters survive close |
| C11 | DONE | WS3: `validate_slug` gate before both `vaults_dir().join` sites (vault.create + clone); attack-string test `slug_gate_rejects_traversal_and_separators` passes |
| C12 | DONE | docs: threat-model T11 rewritten. Code: `grant_token` minting removed from reprompt response (zero consumers verified; grep clean). Daemon-side grant enforcement deliberately deferred with justification (theater until C2 lands) |
| C13 | DONE | `start_pair` mints 8-char no-homoglyph pair code (returned to desktop with request_id; BridgeTab displays it); popup gains code input, sends `code` with pair_complete; `verify_pair_code` gates BEFORE waiter registration (wrong code never supersedes the legit waiter; constant-time compare; 3-strike ceremony cancel; missing code = wrong code). `finalize_pair` returns `pairing_id` + `paired` only — secret and token no longer cross the wire (NMH reads the pairing file, popup refreshes via reauth; both verified no-consumer). Tests: `wrong_pair_code_does_not_supersede_waiter`, `three_wrong_pair_codes_cancel_ceremony`. NOTE: audit's original mechanism (desktop→NMH spawn args) is impossible — browser spawns the NMH; user-typed code is the out-of-band channel |
| C14 | DONE | WS1: CLI export + attachment download route through `baluard_core::secret_file::write_secret_file` (create_new 0600 + atomic rename, symlink replaced not followed) |
| C15 | DONE | `warn_argv_secret(flag)` in commands/mod.rs; called from --password (replaces inline eprintln), --totp-uri, card --number/--code, SSH --private-key, bank --account/--routing/--branch/--swift/--iban (same class as audited card sites), enroll --phrase + BALUARD_RECOVERY_PHRASE env read |
| C16 | DONE | WS3: `started_at` on CloneJob, 30-min TTL eviction via `retain`, 4-job cap before insert. Wiring visually verified (cap logic needs live provider for integration test) |
| C17 | DONE | WS1: runtime attachment write (`state.rs`) routed through `write_secret_file` |
| C18 | DONE | `cfg(not(unix))` `verify_peer_uid` now bails ("not implemented; refusing connection") instead of Ok(()) |
| C19 | DONE | `VaultHost::list()` populates `path` only for Unlocked presence (empty string otherwise); DetachVaultModal hides the path line when empty; CLI never printed it (verified). `VaultSwitcher` openDetach tolerates empty path |
| C20 | DONE | curl spawn replaced by in-tree reqwest client (5s timeout, 10-redirect policy, failure → empty string as before); `favicon_url()` percent-encodes the domain via `Url::query_pairs_mut` — `&`/`=` can no longer inject query params; 16KB cap + magic-byte validation unchanged. Tests: `favicon_url_escapes_ampersand_domain`, `favicon_url_plain_domain_unescaped_happy_path`. reqwest added to runtime Cargo.toml (workspace dep) |
| C21 | DONE | `kind_omits_or_shrinks_protected` + async `bridge_update_preserves_protected` beside the forbidden-field gate; wired as step 3b in the bridge update path (after unlock check, before dispatch; read exempt from bridge cap). Tests: 3 c21_gate_* cases (omission, shrink, kindless/uriless allow) |
| C22 | DONE | WS2: `vault.enroll_with_phrase` wired into global limiter (commit on result, phrase zeroized on every path); module docs rewritten to the real five-route inventory |
| C23 | DONE | WS2: `vault.reprompt_verify` wired into global limiter on the vault's unlock key (deliberate composition: reprompt grind locks unlock too) |
| C24 | PARTIAL | WS1: ungated `PermissionsExt` in `vault/mod.rs` eliminated (delegated to cfg-branched primitive); audit confirms every remaining `os::unix` use in core is already cfg-gated. Full MSVC cross-check blocked by C deps (`ring`, `libz-sys` need MSVC clang, unavailable on macOS) — real verification = Windows CI runner (backlog) |
| C25 | DONE | WS1: `store_token_file` delegates to `write_secret_file` (no write-then-chmod window) |
| D1 | PENDING | Rust-side recovery save |
| D2 | PENDING | DESKTOP_ALLOWED_ACTIONS |
| D3 | PENDING | clear createPassword |
| D4 | PENDING | Rust pasteboard concealment |
| D5 | PENDING | async + spawn_blocking |
| D6 | PENDING | favicon mime whitelist |
| D7 | PENDING | rejection sampling |
| D8 | PENDING | mailto opener entry |
| D9 | PENDING | dev-gate conflict triggers |
| D10 | PENDING | pin biometry plugin |
| B1 | DONE | `originOf` (scheme+host+port) exported from background.js; popup fill + inline fill send it; content.js + inline.js compare `location.origin`. 4 new originOf tests (downgrade, port, fail-closed). Also completes B9's code arm |
| B2 | DONE | `_sender` -> `sender` rename in the onMessage listener. NOTE: this ACTIVATES inline autofill for the first time — shipped atomically with B1+B3+B4 as required |
| B3 | DONE | Client: inline fill sends `{id, url}` to vault.get. Daemon: `bridge_read_matches_page` gate (step 3c) on vault.get/cipher.totp_code reusing the bridge.match hostname matcher; URI-less ciphers allowed + logged (extension-owned UI policy); url-less requests (popup) unaffected |
| B4 | DONE | Listener privilege split before any routing: `sender.tab` present -> only inline.matches/inline.fill (warn+drop otherwise); extension pages (`sender.id === chrome.runtime.id`, no tab) -> full routing; unknown sender -> drop |
| B5 | DONE | `{ frameId: sender.frameId ?? 0 }` options arg on the inline fill `tabs.sendMessage` push |
| B6 | DONE | `handleOffscreenMessage` drops anything not from the extension itself without a tab (`sender.id !== chrome.runtime.id || sender.tab`) |
| B7 | PENDING | version-skew fail-closed |
| B8 | PENDING | offscreen feature-detect + Firefox build merge |
| B9 | DONE | docs: browser/README.md scheme policy. Code arm: B1 originOf (https credential no longer fills http page) |
| B10 | DONE | browser/README.md tab-URL privacy note |
| B11 | PENDING | CI dist diff check |
| M1 | DONE | `SecureFlag.android.kt` uses `AppContextHolder.activity()?.window` (applicationContext cast never was an Activity). Gradle compiles |
| M2 | DONE | `Clipboard.android.kt` sets `EXTRA_IS_SENSITIVE` via PersistableBundle on the clip description (Android 13+ overlay hidden) |
| M3 | DONE | Rust: `set_token_encryption_key` (OnceLock, first-call-wins) + sealed token files via generic `secret_file::{seal,open,is_sealed}_secret_blob` (AES-256-GCM envelope, purpose AAD `baluard-secret-token-file-v1`); sealed+no-key fails closed; legacy plaintext lazily re-sealed on read; keyring path also gated by `keyring_disabled()`. UniFFI: `set_token_encryption_key` exported (32-byte check). Android: `TokenEncryption.android.kt` mints a random 32B key wrapped by a non-exportable AndroidKeystore AES-GCM key (wrapped blob in app prefs), unwraps + installs at MainActivity.onCreate; Keystore failure degrades to the documented plaintext fallback (never blocks access). Also fixed a C1-sweep miss: `background_fetch` engine call in baluard-uniffi now passes `None` (fetch-only, no signing). 4 new Rust tests (roundtrip/no-plaintext, wrong+missing key fail-closed, legacy migration, first-call-wins); Android compiles |
| M4 | DONE | `MainActivity.onCreate` sets FLAG_SECURE app-wide before first frame; per-screen `DisposableEffect` in RecoveryPhraseScreen deleted (it would have CLEARED the app-wide flag on dispose) + orphan imports removed |
| M5 | DONE | documented DEBT ceiling; ledger entry kept (severity Low, no action) |
| M6 | DONE | PAT state: `remember` (never saved instance state) + `isPassword = true` on the field (toggle support built into BaluardTextField) |
| M7 | PENDING | scheme allowlist |
| M8 | PENDING | android:process on service |
| M9 | DONE | threat-model residual risk 9 records decision (OS trust store, no pinning) |
| M10 | PENDING | static error strings |
| Threat-model corrections | DONE | T1 (attachment limit), T2 + row C + inv 4 (Windows honesty), invariant 1 (C2 exception), T11 (grant reality), T12 (three-layer honesty) all applied to docs/threat-model.md |

### Workstreams (collapsed shared fixes)

- **WS1 — `write_secret_file` primitive.** One cross-platform helper in `baluard-core`: Unix `OpenOptions::new().create_new(true).write(true).mode(0o600)` + atomic rename (the pattern proven at `client.rs:106-124`); Windows atomic write + user-SID DACL (or a `TODO(DACL)` atomic write as the floor). Closes **C14, C17, C25, C24-compile** in one primitive; `write_vault_file` (`vault/mod.rs:27-34`) delegates to it so its ~23 call sites change nothing. C9's log open uses the same pattern.
- **WS2 — Global rate limiter.** `static GLOBAL` + `pub fn global()` in `rate_limit.rs` (mirroring the existing `CLONE_JOBS` static at `handler.rs:2356`); delete the per-state field (`state.rs:89,117`); repoint `handler.rs:1915,2108,2174`; wire `vault.enroll_with_phrase` and `reprompt_verify`. Chosen over a `VaultHost` field because `route_request` (`handler.rs:2673`) receives only `&SharedVaultState`, no host, and the field alternative churns 13 `VaultState::new` call sites. Closes **C10, C22, C23**; makes **C7** an honest doc.
- **WS3 — Create/clone hardening.** `validate_slug` before both path joins (`handler.rs:2237,2394`), job cap (4) + 30-min TTL eviction with `started_at: Instant` on `CloneJob`. Closes **C11, C16** in one PR.
- **WS4 — Extension listener rewrite.** `background.js` router + `offscreen.js` guard as one PR: **B2, B4, B5, B6** (+B7 queue if clean).
- **WS5 — Origin binding end-to-end.** Client-side `origin` compare + server-side URI-match on bridge reads: **B1, B3**; turns **B9** into documented policy.
- **WS6 — Bridge capability tightening.** **C13** (nonce-bound `pair_complete`, stop returning the secret) + **C21** (diff-based protected-field gate).
- **WS7 — Android hygiene sweep.** **M1, M2, M4, M6, M7, M8, M10**: small edits across `platform/*.android.kt`, `MainActivity.kt`, two screens, one manifest; one instrumented-test file.
- **WS8 — Webview command surface.** `desktop/src-tauri/src/lib.rs`: **D1, D2, D5**.
- **WS9 — Desktop frontend hygiene.** **D3, D6, D7, D8, D9** (+D4 when the Rust pasteboard command lands).
- **WS10 — Device-key protection.** **C1** alone; depends on WS1 for the write, per the subkey-retention design above.
- **WS11 — Documentation truth pass.** The five threat-model corrections plus disclosure text for **C5, C6, C7, C18, C19, B9, B10, D10, M5, M9**.

### Per-finding fix paths

**C1 — BLOCKER, L, WS10.** Seal under the KEK-derived subkey with retention design above. All three writers + every reader (rotation, enrollment, CLI `--direct`) in one change. Existing keystore-less vaults become unreadable: allowed pre-1.0. Test: create keystore-less vault, lock, assert no 64-hex run in `device-privkey.json`; unlock + `revoke_device_and_rekey` round-trips.

**C2 — BLOCKER, L.** Platform keyring for the CLI token (keyutils session keyring on Linux, keychain on macOS) inside `client.rs:97-147`, keeping the `set/get/clear_session_token` signatures so ~40 call sites stay untouched; unlink on `handle_lock`. File fallback only behind `BALUARD_TOKEN_FILE=1` with a stderr warning (headless CI keeps working). Chosen over re-prompt-per-invocation, which would push users to `--password` flags (C15). Test: CLI unlock, assert nothing readable at `paths::token_path()`, next CLI command still succeeds.

**C3 — FAST-FOLLOW (warning, S) / BACKLOG (TPM, L).** Platform-conditional warning in the `vault.biometric_enable` response (non-macOS) rendered at the desktop toggle; rewrite `biometric.rs:1-36` header to state the asymmetry; both `en.json` and `es.json` keys. TPM/`KeyCredential` path is the real fix and stays deferred.

**C4 — FAST-FOLLOW, M.** New `ObjectType::Attachment` (`types.rs:70-74`); `padding::pad(content, Tier::fit(len))`; `build_aad(vault_id, Attachment, attachment_uuid, Some(tier), alg, epoch, seq)` threaded into `encrypt_attachment`/`decrypt_attachment` (signature change, update `runtime/state.rs` upload/download). Wire-format break, pre-1.0 allowed. Interaction caught in validation: the 2 MB input cap collides with the 2 MB XL padded tier — lower the input cap to ~1.9 MB or add a tier. Test: swap two same-cipher attachment files on disk; both decrypts fail.

**C5 — DOCS now (S) / BACKLOG code (M).** User-facing privacy note; move display names into `settings.enc` later.

**C6 — DOCS, S.** Name the on-disk counter advisory-only (comment at `handle.rs:2379-2381` already honest); HMAC-ing it is theater since the attacker can delete the file. Real control arrives with WS2.

**C7 — DOCS, S.** Already stated in `rate_limit.rs:7-11`; mirror into the threat model. Persisting lockout state recreates C6's attacker-writable-file problem one layer up.

**C8 — no action.** Folds into D9: the `Math.random` hits (dev mock IDs) leave the bundle when the dev-trigger module is dev-gated.

**C9 — BLOCKER, S.** Gate the NMH tee behind `BALUARD_DEBUG=1`, relocate to `paths::log_dir()`, open with the WS1 pattern (`create_new` + 0600, plain append only if the existing entry is a regular file, never a symlink). 15 `dlog` call sites stay. Test: pre-plant a symlink, run NMH, assert the target is unmodified.

**C10 — BLOCKER, S, WS2.** See workstream. Unit tests constructing local `RateLimiter::new()` stay untouched. Test: fail unlock 10x, `vaults.close`, re-unlock — still locked out.

**C11 — BLOCKER, S, WS3.** `validate_slug(&slug)` before both joins; `err_response` on failure. The synthesized fallback slug is already safe. Test: `vault.create` with `slug: "../../tmp/x"` creates nothing outside `vaults_dir()`. Highest fix-value-to-effort ratio in this report.

**C12 — FAST-FOLLOW (docs + field removal, S) / BACKLOG (enforcement, M).** Correct `threat-model.md:104` (UI-only control); delete `grant_token` from the `reprompt_verify` response (`state.rs:3086-3091`) — validated: zero consumers in `desktop/src`, removal is safe. Enforcement adds nothing against its named attacker while C2 stands; ship it only after C2.

**C13 — FAST-FOLLOW, M, WS6.** Stop returning the pairing secret on `pair_complete` (`handler.rs:1699-1707`); add a one-time nonce: `pair_start` returns `request_id` + nonce to the desktop, desktop passes it to the NMH spawn, `pair_complete` requires it before `finalize_pair`. Touches pairing UX end-to-end and the NMH pairing file format. Test: two concurrent `pair_complete` callers; only the nonce-holder succeeds.

**C14 / C17 — FAST-FOLLOW, S each, WS1.** Route both writes through the primitive.

**C15 — BACKLOG, S.** Extract the existing warning at `main.rs:743` into `warn_argv_secret(flag)`; call from `--phrase` (`:247`), card `number`/`code` (`:468,475-476`), SSH `private_key` (`:569`), and the `BALUARD_RECOVERY_PHRASE` env read (`commands/mod.rs:1304`). Keep the flags; scripted enrollment needs them.

**C16 — FAST-FOLLOW, S, WS3.** Same PR as C11. Test: 5 concurrent `clone_start`, 5th errors.

**C18 — DOCS + S code, BACKLOG.** Soften `threat-model.md:14,62` to "Unix: 0600 + peer-UID verification; Windows transport unimplemented, named-pipe DACL is a design commitment"; make the `cfg(not(unix))` no-op return `Err` instead of `Ok` so a future Windows build fails loudly.

**C19 — BACKLOG, S.** Drop `path` from `VaultListRow` while presence is Closed/Locked (detach modal is the only consumer and runs post-unlock); keep slug/display_name/presence for the login screen. Verify `VaultSwitcher` doesn't read `path` pre-unlock.

**C20 — BACKLOG, S.** Replace the `curl` spawn (`state.rs:1559-1567`) with the in-tree reqwest client; preserve 5s timeout, redirect-follow, 16 KB cap, magic-byte validation. Test: domain containing `&` produces an escaped URL.

**C21 — BLOCKER, M, WS6.** New `bridge_update_preserves_protected(existing, incoming) -> bool` beside `bridge_update_touches_forbidden` (`handler.rs:1659-1677`): fetch the existing cipher, deserialize the incoming kind, reject when previously-present `fido2_credentials`/`uris` become absent or shrink; call both gates. Chosen over removing `vault.update` from `BRIDGE_ALLOWED_ACTIONS` (`bridge/token.rs:48-58`) because password-capture is the extension's main write use case. Decide explicitly whether the read counts against the 30/min cap (recommend exempt). Test: bridge update omitting `fido2_credentials` on a login that has one is rejected; the passkey survives; a payload omitting `uris` on a URI-less login still passes.

**C22 — FAST-FOLLOW, S, WS2.** Wire `claim_attempt` into `vault.enroll_with_phrase`; rewrite module docs per the corrected route inventory.

**C23 — BLOCKER, S, WS2.** `claim_attempt` around `reprompt_verify` keyed on the same vault-path string as unlock — deliberate composition: a reprompt grind locks out `vault.unlock` too. Only clean once the limiter is global. Test: 10 wrong reprompts, then correct-password `vault.unlock` is locked out.

**C24 — BACKLOG (blocker only for a Windows release), S compile / M DACL, WS1.** Gate the import, build the primitive cross-platform from birth, add `cargo check --target x86_64-pc-windows-msvc` to CI.

**C25 — BLOCKER, S, WS1.** Token store through the primitive; free once WS1 exists.

**D1 — FAST-FOLLOW, M, WS8.** Delete `write_text_file`; replace with `#[tauri::command] async fn save_recovery_phrase(contents: String)` that opens the dialog Rust-side (`tauri-plugin-dialog` is already a dependency and `dialog:default` granted) and writes via the WS1 pattern. Validated: exactly one caller (`RecoveryScreen.jsx:78-84`). Test: grep returns zero `write_text_file`; manual save still produces the file.

**D2 — FAST-FOLLOW, M, WS8.** `DESKTOP_ALLOWED_ACTIONS` const in `lib.rs`, checked at the top of `daemon_request`, mirroring `BRIDGE_ALLOWED_ACTIONS`/`is_allowed`; build the list from `daemon(` call sites in `desktop/src`; separately reject `delete_from_disk`/`force` on this bridge. Debug-build `log::warn!` on denial; full manual pass through every screen. Test: `daemon_request("vaults.detach", "{\"delete_from_disk\":true}")` refused.

**D3 — FAST-FOLLOW, S.** `auth.setCreatePassword("")` at the top of `SetupScreen.finish()` and in `AuthContext.lock()`. Validated: the only reader (`SetupScreen.jsx:49`) runs earlier. Test: after onboarding, `auth.createPassword()` is `""`.

**D4 — BACKLOG, M.** Rust pasteboard command setting `org.nspasteboard.ConcealedType` / `ExcludeClipboardContentFromMonitorProcessing` / `x-kde-passwordManagerHint`; keep the 30s clear in JS (the read-back-before-clear logic at `clipboard.js:20-26` may not survive the Rust path).

**D5 — FAST-FOLLOW, S, WS8.** Make both commands async, wrap `send_request` in `spawn_blocking`. Validated: `lock_all_vaults` already drops the store mutex at `lib.rs:330` before the blocking call, so the conversion is mechanical.

**D6 — BACKLOG, S.** Mime whitelist `png|jpeg|webp|x-icon` in `faviconSrc()`; null renders initials. All daemon-fetched favicons are PNG; no caller regresses.

**D7 — BACKLOG, S.** Rejection sampling at `utils.js:43,83`.

**D8 — BACKLOG, S.** Add `{ "url": "mailto:*" }` to the opener allow-list; toast on open failure.

**D9 — BACKLOG, S.** Dynamic-import the dev trigger behind `import.meta.env.DEV`; also removes C8's `Math.random` hits from the bundle. Test: prod-bundle grep for `conflictTrigger` is empty.

**D10 — BACKLOG, S.** Pin the biometry plugin to an exact version; record the no-updater decision.

**B1 — BLOCKER, S, WS5.** `hostnameOf` to `originOf` returning `new URL(url).origin`; producers `background.js:189`, `popup.jsx:324`; consumers `content.js:31-32`, `inline.js:217-218` compare `location.origin`. Update vitest suites asserting hostname equality. Test: matched on https, navigated to http, fill refused.

**B2 — BLOCKER, S, WS4 — sequencing trap.** Rename `_sender` to `sender` (`background.js:211`). This activates inline autofill for the first time (the routes currently throw before doing anything): never merge without B1, B3, B4. Test: mocked `chrome.runtime.onMessage`; privileged sender succeeds, `tab`-less sender dropped.

**B3 — BLOCKER, M, WS5.** Send the tab URL with the fill request; enforce server-side on `vault.get`/`cipher.totp_code` by reusing the existing matcher from `bridge.match` (`handler.rs:1554+`) under the vault's `default_uri_match` — do not write a second matcher. Note the amplification: the bridge path substitutes the vault's full desktop session token (`handler.rs:1640-1643`), so this check is the only thing between a bridge token and arbitrary reads. Policy decision: URI-less ciphers remain fillable from extension-owned UI (user picked them) but log it. Test: bridge `vault.get` with non-matching URL is denied.

**B4 — BLOCKER, S, WS4.** Privilege split in the listener (`background.js:242-246`): `sender.tab` present means only `inline.matches`/`inline.fill`; extension pages (`sender.id === chrome.runtime.id && !sender.tab`) get the full set; everything else dropped. The popup is an extension page without `sender.tab`, so it keeps routing. Test: content-script sender issuing `vault.get` is dropped.

**B5 — FAST-FOLLOW, S, WS4.** `{frameId: 0}` on both `tabs.sendMessage` pushes, marked load-bearing.

**B6 — FAST-FOLLOW, S, WS4.** Same sender check in `handleOffscreenMessage`; the `_sender` parameter already exists.

**B7 — FAST-FOLLOW, M.** Initialize `versionSkew = true` (fail closed), clear only in the ping success branch, queue non-ping sends until first ping; add a handshake timeout that surfaces "cannot reach Baluard".

**B8 — FAST-FOLLOW, S.** Feature-detect `chrome.offscreen` at `background.js:269-276`, fall back to `navigator.clipboard.writeText` in the popup. Validation correction: the `offscreen` permission does NOT live in `browser/firefox/manifest.extra.json` (verified: only `browser_specific_settings`); it leaks into the Firefox dist from `manifest.base.json`. The fix belongs in the Firefox build step — subtract base-only permissions during the merge, not in extra.json.

**B9 — DOCS, S.** Once B1 lands, HTTPS-matched credentials can no longer fill HTTP pages; state the scheme policy in the extension README and keep the broad host permissions (standard for the category).

**B10 — DOCS, S.** Document the tab-URL badge flow in the privacy note; C9's fix removes the always-on tee.

**B11 — BACKLOG, S.** CI job rebuilding both extensions, failing on dist diff; pin Vite to avoid nondeterminism.

**M1 — BLOCKER, S, WS7.** `AppContextHolder.activity()?.window ?: return` — the accessor exists (`AppContextHolder.kt:38`) and `MainActivity.onCreate:18` populates it (both validated). Instrumented test asserts the flag after the recovery screen composes.

**M2 — BLOCKER (flag), S, WS7.** `EXTRA_IS_SENSITIVE` behind an API-33 guard before `setPrimaryClip`; timed overwrite later if wanted (needs a lifecycle-aware scope; ship the flag first). minSdk 32 makes the guard mandatory.

**M3 — BLOCKER, L.** `#[uniffi::export] fn set_token_encryption_key(key: Vec<u8>)` called at startup with a Keystore-unwrapped AES-256 key; `store_token_file`/`load_token` (`token.rs:135,189`) seal under it via the existing `crypto::aead` when set, plaintext path only when unset (headless tests). Validated basis: no UniFFI callback interface exists anywhere in `baluard-uniffi`, so the inject-a-key design beats introducing a new FFI mechanism for one caller. Kotlin side mirrors the `Biometric.android.kt` Keystore ceremony minus the biometric gate (background sync needs it usable unattended). `KeyPermanentlyInvalidatedException` must delete tokens and force re-connect, not crash. Test: connect a PAT, kill, grep the token file for the raw token — absent; reconnect works.

**M4 — BLOCKER, S, WS7.** `window.addFlags(FLAG_SECURE)` in `MainActivity.onCreate`; then delete the per-screen `DisposableEffect` in `RecoveryPhraseScreen.kt:60-63` (with app-wide coverage it is dead code that could clear the flag on dispose). Still fix M1 so the helper isn't a landmine.

**M5 — BACKLOG/DOCS, S.** Within the DEBT ceiling: single-pass KEK derivation, drop the password String reference immediately, zero-fill ByteArray wrappers, never `rememberSaveable` for secrets (M6 is the one violation). Record the trigger in the debt ledger.

**M6 — FAST-FOLLOW, S, WS7.** `rememberSaveable` to `remember` (`ProviderConnectScreen.kt:63`); `isPassword = true` (parameter exists with default false at `BaluardComponents.kt:445`, toggle at `:452`). Rotation losing the typed token is correct behavior for a secret.

**M7 — BACKLOG, S, WS7.** Scheme allowlist http/https in `OpenUrl.android.kt`; warn-and-confirm for other schemes rather than hard block.

**M8 — BACKLOG, S, WS7 — but do it now.** Add `android:process=":autofill"` to the service while `retrieveKek()` still returns null; adding it later alongside the KEK path risks shipping credentials in the main process. The service currently touches no shared state.

**M9 — DOCS, S.** Record the native-TLS trust decision in the threat model; skip pinning (rotation-outage risk for marginal gain).

**M10 — BACKLOG, S, WS7.** Static error string in the failure callback; log detail locally.

**Threat-model corrections — DOCS, one PR (Wave 0).** All five rewrites as listed earlier in this document; they close the report's dominant theme ("comment as control") before any code lands.

### Waves

**Wave 0 — Docs truth pass (day 1, no code).** WS11. Removes every overclaim immediately; nothing depends on it, nothing blocks it.

**Wave 1 — Foundations (parallel).** WS1 (`write_secret_file`) unblocks C1, C14, C17, C25, C24. WS2 (global limiter) unblocks C22, C23. C2 (CLI token, L) and M3 (Android token encryption, L) start here — they are the longest poles.

**Wave 2 — Release blockers.** WS3 (C11, C16); C9; C25; C23 + C22; WS10/C1; M1 + M2 + M4 (no dependencies); M3 lands; C21; **WS4 + WS5 as one atomic extension release** (B1-B6: hard rule, B2's rename must never ship without B1 + B3 + B4 because it activates a feature that has never run).

**Wave 3 — Fast follows.** C3 warning, C4 (own window: wire break), C12 docs + field removal, C13, WS8 (D1, D2, D5), D3, M6, B7, B8.

**Wave 4 — Backlog.** WS9 remainder, C5-C7 code arms, C15, C19, C20, C24 DACL, D4, D10, M7, M8, M10, B9-B11, and the deferred arms of C3 (TPM) and C12 (grant enforcement, meaningful only after C2).

### Release call — minimal defensible 1.0 set (13 items)

| Item | Why it cannot slip |
|---|---|
| B1 + B2 + B3 + B4 (atomic) | The only finding class reachable by a remote adversary; B1 lets a network attacker read a password after a downgrade; B2 cannot ship alone |
| M1 + M2 + M4 | Recovery phrase visible in recents and the Android 13 clipboard overlay; zero attacker sophistication required |
| M3 | Live provider credentials in cleartext, strictly easier to steal than the encrypted vault they protect |
| C1 | Keystore-less mode reduces a disk attacker from Argon2id brute force to `cat` |
| C2 | Breaks the stated capability invariant; every same-UID finding composes with it |
| C11 | Path traversal in a pre-token route; one-line fix |
| C21 | A compromised browser silently deletes passkeys — the exact capability the gate exists to deny |
| C10 + C23 (WS2) | Unthrottled Argon2id grinding on two routes; one 30-line shared fix |
| C9 | Symlink-following write to an attacker-chosen path, always on in release builds |
| C25 | World-readable window on live OAuth tokens; free once WS1 exists |
| WS1 | Prerequisite for C1, C9, C25 |
| WS2 | Prerequisite for C10, C22, C23 |
| Wave 0 docs | Shipping a threat model that overclaims five controls is worse than shipping the gaps |

**Deferred with justification:** C12 enforcement (theater until C2 lands — correct the doc now, ship the code later), C4 (real, but a wire-format break deserves its own release window), C3 TPM arm (enable-time warning for 1.0), C24 DACL (blocker only for a Windows release, which is not this one), C13 (same-UID only; C2's fix shrinks the surrounding exposure).

**Two sequencing traps:** B2's rename enables a feature that has never run — never merge without B1/B3/B4. WS2 must land before C22/C23, or two new `claim_attempt` calls get wired into a limiter that `vaults.close` still resets.

## Threat-model corrections

- T11 claims the daemon tracks reprompt grant state internally and that grants are scoped to a single cipher; neither holds (C12, C23).
- T2 claims Windows named-pipe ACLs; no Windows transport exists (C18), and the core does not currently compile for Windows (C24).
- T1's padded-bucket guarantee does not cover attachments (C4).
- Invariant 1 ("a same-UID process that did not take part in the unlock exchange holds no capability") does not hold when the CLI is the unlocking client (C2).
- The rate-limiter module docs claim five covered paths; three are wired (C22).

## Appendix: peer validation

After drafting, an isolated second-model reviewer (no shared context, adversarial instructions) re-checked all 45 original findings against source code.

- **Verdicts:** 50 confirmed, 1 partially confirmed in substance with corrected evidence (C8's blanket no-`Math.random` claim; the occurrences found are non-security dev mock IDs). Zero refuted, zero unverifiable.
- **Citation corrections applied:** 12 findings had line numbers 2-30 off (C13, C15, C20, D3, D10, B1, B6, B8, B9, B10, M2, M10); every quoted code excerpt matched real code nearby, so this was drift, not fabrication. All corrected in place.
- **Severity changes:** C13 raised Low to Medium (the route returns the long-lived pairing secret, a durable vault-read capability); M5 lowered Medium to Low (documented DEBT ceiling, no attacker path short of device compromise).
- **Additions:** C21 (bridge `vault.update` omission bypass of the passkey/URI field gate), C22 (rate limiter covers three paths, not five), C23 (unthrottled Argon2id oracle on `vault.reprompt_verify`), C24 (`baluard-core` does not compile for Windows), C25 (provider token file world-readable write window).
- **Systemic themes reinforced:** "comment as control" (a documented or commented guarantee with no enforcing code) recurs across all four parts: D1, M8, C12, C18, C21, and the T11/T2 threat-model claims. Write-then-chmod for secret material appears four times (C14, C17, C25, and the CLI export path); one shared secret-file-writer primitive closes all of them.
- **Remediation round:** the same session then produced the remediation plan now in this document; the lead auditor re-validated it against source and corrected four points: C1's KEK-derived seal needed a subkey-retention design (the KEK is not resident after unlock, and a root-key-derived seal is circular — the device private key is required before the root key exists); C22's route inventory (there is no emergency or recover IPC route; the uncovered recovery-adjacent route is `vault.enroll_with_phrase`); B8's permission source (the Firefox `offscreen` permission leaks from `manifest.base.json`, not from `manifest.extra.json`, so the fix belongs in the Firefox build merge step); and C9's call-site count (15 `dlog` sites, not ~30 — recommendation unchanged).

---

## UX impact assessment

Framing per project directive (AGENTS.md STATUS + UX PRINCIPLES): during alpha/beta, format and data breaks are not UX regressions and need no migration; the only evaluation axis is ongoing ease of use for non-technical users. Baluard is the author's first product and all technical machinery must stay invisible.

**Verdict: no fix in this plan forces a usability compromise. Nothing safe and working is taken away from a non-technical user.** Full partition of the 56 findings:

### Invisible in normal use (36)

C5, C6, C7, C8, C9, C10, C12, C13, C14, C15, C16, C17, C18, C19, C20, C21, C22, C24, C25, D1, D3, D4, D6, D7, D9, D10, B4, B5, B6, B9, B10, B11, M5, M8, M9, M10. Same clicks, same screens, same flows. C21 is invisible today specifically because no extension code calls bridge `vault.update` yet (verified); when password-capture is built, it must round-trip preserved fields — that requirement belongs in the feature's plan, not a migration.

### Visible changes, all industry-standard (8)

| Finding | What the user sees | Why it is fine |
|---|---|---|
| B1 | Autofill refuses a plain-HTTP page with the same hostname | Only fires in a scenario that was already an attack; Bitwarden matches scheme too |
| M1 + M4 | No screenshots; blank recents preview | Every password manager ships this; one release-note line |
| M2 | Android 13+ clipboard overlay shows nothing | In-app "copied" indicator already exists (`BaluardComponents.kt:708`), so reassurance is covered |
| C3 | One-time text when enabling quick unlock on Linux/Windows | Warning, not a block; matches the project's compromise philosophy |
| M6 | PAT field masked, cleared on rotation | Standard secret-field behavior |
| M7 | Confirm dialog for non-http URIs | Rare path; confirm, not block |
| B7 | "Cannot reach Baluard" instead of silent misbehavior | Improvement |

### Net UX improvements shipped as security fixes (6)

- **B2 activates inline autofill, which has never once executed** (the sender gate is dead code; users currently always get "No logins"). The single biggest usability gain in this plan.
- B8: Firefox copy buttons work (they throw today).
- D5: no more 30-second UI freezes when the daemon hangs.
- D8: mailto links open.
- C11: no more vaults created in wrong directories.
- B3: matching stays consistent client- and server-side (same matcher reused).

### Implementation watch-items, edge-case visible only (4)

- **C23:** 10 consecutive fat-fingered reprompts lock the whole vault for 1 hour (shared limiter key, deliberate: the grind route must hit the unlock counter). Rare; a successful unlock resets the counter. Mitigate with lockout text that states the reason and remaining time, in both locales.
- **D2:** an incomplete action allowlist breaks a feature at runtime, not compile time. Mitigation is in the plan: debug-build denial warning plus a full manual pass through every screen.
- **C2:** headless/scripted CLI loses token persistence without the `BALUARD_TOKEN_FILE` fallback. Scripters only; desktop-session users have a keyring and notice nothing.
- **M3:** visible only on Android credential reset (`KeyPermanentlyInvalidatedException` deletes provider tokens and forces re-connect); must surface as a calm reconnect prompt, never a crash.

### Accepted alpha breakage, not UX debt (2)

- C4: existing attachment blobs become undecryptable; 2 MB cap drops to ~1.9 MB. No migration written.
- C1: existing keystore-less/Android device-privkey files become unreadable. A re-seal-on-first-open is roughly 10 lines if ever wanted; skipping it is acceptable per the breakage policy.
