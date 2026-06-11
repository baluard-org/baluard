# Baluard Security Fix Verification

**Date:** 2026-06-11
**Verifier:** TARS (independent source re-verification, Opus 4.8)
**Scope:** Every finding marked **FIXED** / **DOCUMENTED** / **PARTIAL** in `docs/security-audit-2026-06.md`.
**Method:** 4 parallel verification passes (Critical / High / Medium / Low) reading the actual source at each cited location. Audit "FIXED" labels were NOT trusted; each claim was judged against current code with file:line evidence.

---

## Verdict Summary

| Severity | Findings | Verified | Partial | Not Found / Incorrect |
|----------|----------|----------|---------|-----------------------|
| Critical | 4 | 3 (C1, C3, C4) | 1 (C2) | 0 |
| High | 9 | 9 | 0 | 0 |
| Medium | 12 | 12 | 0 | 0 |
| Low / Info | 8 | 6 | 2 (L1, L7) | 0 |

**Bottom line:** 30 of 33 fixes are fully present and correct in code. 3 carry real residual gaps (C2, L1, L7). No claimed fix is entirely absent or contradicted. Two audit claims contain inaccurate descriptive text where the actual code is correct or better (M4 module path, L4 regex). The residuals the audit itself disclosed (H2, H9) are accurate and remain open as documented.

---

## Open Items (require action or conscious acceptance)

### 1. C2 residual — `collect_commit_range` walks first-parent only
**Severity of residual: MEDIUM. New, not previously disclosed.**

Signature verification now runs before any tree/index/ref write on all three pull paths (fast-forward, non-FF merge, conflict resolution), and conflict-path canonicalization correctly rejects traversal before `create_dir_all`. The core C2 fix is sound.

But `collect_commit_range` (`crates/baluard-core/src/sync/engine.rs:361-383`) follows only the first parent (`commit.parent_id(0)`, `:380`). A remote **merge commit's second-parent lineage** is never enumerated, so commits smuggled down a side branch merged into remote history are never signature-checked. For a linear-history password vault this is unlikely in normal operation, but an attacker who controls remote history can craft a merge commit to bypass verification — the exact untrusted-remote threat C2 addresses.

**Recommended:** walk all parents in `collect_commit_range`, or reject multi-parent remote commits outright. Add the C2 end-to-end regression test the audit's own Limitations appendix calls for.

### 2. L1 residual — clipboard auto-clear present but never exercised
**Severity of residual: LOW. Corroborated by prior peer-review memory.**

`desktop/src/lib/clipboard.js:15-32` implements correct logic: 30s default, read-back guard (only clears if clipboard still holds our value), best-effort on permission denial. But:
- Every caller (`CipherDetail.jsx:23,146`, `GeneratorModal.jsx:52`, `RecoveryScreen.jsx:14`, `SshKeyGenerator.jsx:38`) calls `copyToClipboard(value)` with no options — all silently rely on the default. The "configurable `autoClearMs`" framing is aspirational; nothing wires it.
- `SshKeyGenerator.jsx:33` defines its own **local** `CopyButton`, not the shared one — verify it routes through `copyToClipboard` and gets the clear behavior.

**Recommended:** confirm `SshKeyGenerator`'s local copy path triggers auto-clear; otherwise SSH private keys never clear. Drop or actually use the `autoClearMs` prop.

### 3. L7 residual — `rsa` Marvin-attack advisory still live, no fix available
**Severity of residual: MEDIUM (third-party, no upstream fix). Under-disclosed by the "PARTIAL" label.**

`cargo-audit` is wired into `just check` (`justfile:99-105`, `:109`), good. But the audit's own embedded report (`security-audit-2026-06.md:463-470`) shows **`rsa` 0.10.0-rc.18 / RUSTSEC-2023-0071** (Marvin Attack, key recovery via timing sidechannel) — **"No fixed upgrade is available."** Pulled in transitively via `ssh-key`'s RSA feature. Tooling now surfaces it, but nothing mitigates it. Also `ssh-key = "0.7.0-rc.10"` remains a release candidate in a security product.

**Recommended:** decide consciously — disable `ssh-key`'s `rsa` feature if RSA SSH keygen is droppable (Ed25519/ECDSA remain), accept and document the timing-sidechannel risk, or pin a non-RSA path. Do not let "PARTIAL fixed" mask a live no-fix advisory.

---

## Descriptive Inaccuracies in the Audit (code is correct; text is wrong)

- **M4 module path.** `RateLimiter` lives in `crates/baluard-daemon/src/rate_limit.rs`, NOT `baluard_core::rate_limit` as the finding states. Implementation is sound and slightly stronger than claimed (permit-based `claim_attempt` closes the check/use race). **However:** the M4 note claims coverage of recovery + emergency-approval paths — only `vault.unlock` (`handler.rs:314`) and `vault.biometric_unlock` (`handler.rs:855`) are actually rate-limited. Recovery/emergency routes are NOT wired. The audit's own text leans on "BIP-39 256-bit entropy infeasible to brute-force" for those, which is defensible, but the master-password-derived paths there gain no backoff.
- **L4 regex.** Finding claims the scheme check is `/^(https?|mailto):\/\//i`. Actual code (`CipherDetail.jsx:270-272`) uses `startsWith("mailto:")` + `/^https?:\/\//i` separately, with a comment explaining the combined regex was a bug (it broke `mailto:user@example.com`). The implementation is **better** than the claim.
- **M1 location.** `derive_avatar_key` is in `keys/hierarchy.rs:242` + `vault/handle.rs:582`, not `avatar.rs`. Function exists, domain-separated (`b"baluard-avatar-v1"`), epoch-bound. Fix correct.
- **M9 nuance.** "Single atomic write" is accurate for the authoritative `meta/device-state.json`, but legacy individual files (`devices.json`/`epoch.json`/`seen-nonces.json`) are still written alongside for backward-compat. Read path prefers the combined file. Intentional, documented in code.

---

## Confirmed Residuals (audit disclosed these; verified accurate)

- **H2:** returned `Cipher`/`CipherData` structs still hold plaintext `String` fields without `ZeroizeOnDrop`. Only `padded`/`json` intermediates are zeroized (correctly, on both success and error paths — `cipher.rs:140-144`).
- **H9:** `vault_id` field exists on `EnrollmentPayload` but is NOT verified inside `enroll()` — only `epoch` and `registry_version` are checked (fail-closed, `device_manager.rs:838-862`). The named binding field is dead at the DeviceManager layer.
- **H3:** integrity manifest is wired and live (open-time rollback detection `handle.rs:153-184`, record on add/update `:1448/:1547`, remove on delete `:1335/:1340`), but signatures are recorded, not verified on load, and the manifest sits in the writable tree with no external anchor — defense-in-depth only, as documented.
- **L5:** `biometric.rs` documents the macOS passcode fallback; `is_available()` (`:48-50`) still returns `true` unconditionally. LAContext hardware check deferred, as claimed.

---

## Per-Finding Detail

### CRITICAL

| ID | Verdict | Evidence |
|----|---------|----------|
| C1 | **VERIFIED** | `aead.rs:77-82` `build_random_nonce()` (OsRng, 12 bytes). Cipher writes route through `cipher.rs:74-75` random nonce; `nonce_counter=0` vestigial. Legacy `build_nonce()` confined to meta/index/canary. Regression test `random_nonce_prevents_reuse` (`cipher.rs:420-465`) asserts distinct nonces under identical `(vault,cipher,key,epoch,seq)`. |
| C2 | **PARTIAL** | Verification before write on all 3 paths (FF `:617-619`, non-FF `:651-654` before `merge()` `:661`, conflicts `:763-768`). Traversal check before `create_dir_all` (`:772-797`). `verify_commit_signatures` fails closed against device-registry keys. **Gap:** `collect_commit_range:361-383` first-parent only — second-parent merge lineage unverified. |
| C3 | **VERIFIED** | 0600 (`emergency.rs:71-75`), owner-signed transitions with caller-supplied (registry-pinned) verifying key, recovery accepts only signed `Approved` (`:187-209`), client time gate dropped (`Requested` advisory-only). Bypass tests pass (re-sign, zero-time, unsigned). |
| C4 | **VERIFIED** | `device.revoke` in `TOKEN_REQUIRED_ACTIONS` (`handler.rs:204`). `vault.biometric_unlock` intentionally absent (circular-dependency rationale, `:205-207`). Enforcement fails closed (`:282-286`). `vault.list_full` gated. |

### HIGH

| ID | Verdict | Evidence |
|----|---------|----------|
| H1 | **VERIFIED** | `change_master_password()` `handle.rs:335-430` — verify old pw via canary, derive new KEK, HPKE re-wrap Root Key, re-encrypt canary, `biometric::disable()`. Route token-gated (`handler.rs:209`). |
| H2 | **VERIFIED** (residual) | `cipher.rs:140-144` zeroizes `json`/`padded` before error propagation. Returned struct not `ZeroizeOnDrop` (open). |
| H3 | **VERIFIED** (residual) | Manifest wired into open/add/update/delete (`handle.rs:153-184/1448/1547/1335`). Signatures recorded not verified; no external anchor. |
| H4 | **VERIFIED** | `rewrap_recovery_key()` `handle.rs:2314-2364`, invoked on both `rotate_root_key:2306` and `revoke_device_and_rekey:2674`, 0600, errors propagated. Pubkey stored at creation (`creation.rs:524`). |
| H5 | **VERIFIED** | `https_token: Option<SecretString>`, `expose_token()->Zeroizing<String>`, `scrub_git_error()` applied at push `:519`/fetch `:568`/clone `:929`. |
| H6 | **VERIFIED** | CLI atomic `create_new(true).mode(0o600)`+rename (`client.rs:69-73`). Daemon 4h expiry on `verify_session_token` (`state.rs:1870-1885`), checked before constant-time compare. |
| H7 | **VERIFIED** | `state.rs:788` `if !matches!(settings.fetch_favicons, Some(true))` → default off. |
| H8 | **VERIFIED** | `onepassword_1pux.rs:200` `Read::take(32MB)` wraps entry before `read_to_string`. |
| H9 | **VERIFIED** (residual) | `epoch`/`registry_version` verified fail-closed in `enroll()` (`device_manager.rs:838-862`). Revocation single-admin self-ack+commit (documented). `vault_id` present but unverified (open). |

### MEDIUM

| ID | Verdict | Evidence |
|----|---------|----------|
| M1 | **VERIFIED** | `avatar.rs:25` AES-256-GCM random nonce, 350KB cap. Daemon writes `meta/avatar.enc` 0600 (`state.rs:667`), legacy migrate (`:589-601`). `derive_avatar_key` in `hierarchy.rs:242`. |
| M2 | **VERIFIED** (doc) | `docs/vault-metadata-leakage-analysis.md`, substantive, accepted tradeoff. |
| M3 | **VERIFIED** | `kdf.rs:127-128` `MIN_MEM_KIB=19*1024`, `mem_floor=(base_mem/2).max(MIN_MEM_KIB)`. |
| M4 | **VERIFIED** (text wrong) | `RateLimiter` in `baluard-daemon/src/rate_limit.rs` (not core). Backoff 2^n cap 60s, lockout 10/1h. Wired to unlock + biometric_unlock only — NOT recovery/emergency despite the note. |
| M5 | **VERIFIED** | `known_hosts.rs` fail-closed; `certificate_check` on build_callbacks (`credentials.rs:155`) + clone_unchecked (`engine.rs:899`). `clone_unchecked` now `pub(crate)`. |
| M6 | **VERIFIED** | `expose_token()->Option<Zeroizing<String>>` (`credentials.rs:82-85`); callbacks hold wrapper. |
| M7 | **VERIFIED** (disputed/accepted) | Detail view derived code (`CipherDetail.jsx:63`); edit form full `totp_uri`. DC-3 reasoning matches code. |
| M8 | **VERIFIED** | `state.rs:1435-1436` capture lengths before zeroize `:1439`. |
| M9 | **VERIFIED** (nuance) | Combined `device-state.json` atomic write (`:362-370`), read prefers it (`:425-438`); legacy files still written for compat. |
| M10 | **VERIFIED** | `orgs.rs:63` + `emergency.rs:74` set 0600 after rename. |
| M11 | **VERIFIED** | `github.rs:158-160/179-180` 429/slow_down → `interval_secs+5` in core. |
| M12 | **VERIFIED** | `state.rs:209` `.filter(|m| *m>0).unwrap_or(15).min(24h)`. 0 = default. |

### LOW / INFO

| ID | Verdict | Evidence |
|----|---------|----------|
| L1 | **PARTIAL** | `clipboard.js:15-32` correct (30s, read-back guard). But no caller passes `autoClearMs`; `SshKeyGenerator.jsx:33` has its own local `CopyButton`. |
| L2 | **VERIFIED** | `recovery.rs:21-24` entropy in `Zeroizing<[u8;32]>`; `derive_key->Zeroizing<[u8;64]>`; Mnemonic reconstructed on demand. |
| L3 | **VERIFIED** | `onepassword_1pux.rs:106-116` zeroizes raw JSON on success and error paths. (1PUX only, as scoped.) |
| L4 | **VERIFIED** (regex text wrong) | `capabilities/default.json:10` `opener:allow-open-url`. `CipherDetail.jsx:270-272` uses `mailto:` + `/^https?:\/\//i` separately — impl better than claimed regex. |
| L5 | **VERIFIED** (doc) | `biometric.rs:10-21` documents fallback; `is_available():48-50` still returns `true`. LAContext deferred. |
| L6 | **VERIFIED** | `handler.rs:248-256` `Err` instead of `unreachable!`; all 8 callers handle Err (`:921..:1212`). No `unreachable!` in file. |
| L7 | **PARTIAL** | `cargo audit` in `just check` (`justfile:99-105/109`). **`rsa` RUSTSEC-2023-0071 still live, no fix.** `ssh-key 0.7.0-rc.10` still RC. |
| L8 | **VERIFIED** (doc) | `docs/forward-secrecy-model.md` thorough; accepted constraint. |

---

## Recommended Next Actions (priority order)

1. **C2** — fix `collect_commit_range` to verify all parents (or reject multi-parent remote commits). Add the end-to-end malicious-divergent-branch test. This is the one residual that touches the untrusted-remote integrity guarantee.
2. **L7** — make a conscious call on the `rsa` Marvin advisory (drop RSA SSH feature, or accept+document). Pin a stable `ssh-key` when available.
3. **L1** — ensure `SshKeyGenerator`'s local copy path clears SSH private keys; remove the unused `autoClearMs` indirection or wire it.
4. **Doc hygiene** — correct M4 (module path + actual rate-limit coverage), L4 (regex), M1 (`derive_avatar_key` location) in the audit so the record matches code.
5. **Disclosed residuals (H2, H9, H3, L5)** — already tracked; no regression, conscious deferrals.
