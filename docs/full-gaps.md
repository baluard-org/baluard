# IDtty: Full Gap Analysis

> Comprehensive diff between documented architecture and implemented code.
> Cross-referenced against all 14 docs/ files.
> Generated: 2026-06-01 | **Updated: 2026-06-01 (Round 13 — security hardening complete)**

---

## Legend

| Status | Meaning |
|--------|---------|
| **Done** | Implemented, tested, peer-reviewed |
| **Stub** | File exists with TODO comment (5-6 lines), no logic |
| **Partial** | Some pieces built, core piece missing |
| **Not started** | Referenced in docs, no code exists |
| **Deferred** | Explicitly deferred in PRD or architecture doc |

---

## 1. Stub Modules

Files with TODO comments, no production logic. Each has a design decision (D-number) in `01-architecture-decisions.md`.

| File | Doc Ref | What's Documented | Status |
|------|---------|-------------------|--------|
| `crates/idtty-core/src/emergency.rs` | D18 | Break-glass access. Pre-wrapped Root Key in `meta/emergency.json`. Advisory time gate. Setup, request, approve, revoke, recovery flows. | **Done** |
| `crates/idtty-core/src/orgs.rs` | D17, D19 | Team/org sharing. X25519 + HPKE authenticated key wrapping. Member add/remove. Auto-rekey all shared items on member removal. | **Done** |
| `crates/idtty-core/src/providers.rs` | D15 | Git provider adapters (GitHub, GitLab). OAuth flow. PAT fallback. Auto-create `idtty-vault` repo. `ProviderAdapter` trait. | **Stub** |

### Dependencies Between Stubs

```
providers.rs ──→ (unblocks OAuth enrollment for new devices)
emergency.rs ──→ (depends on orgs.rs for trusted contact model)
orgs.rs ──→ (depends on access_list.json, Space Group Key rotation)
integrity.rs ──→ DONE (sequence manifest, signed checkpoints, rollback detection, bootstrap)
```

---

## 2. Architecture Decisions Not Yet Implemented

Decisions documented in `01-architecture-decisions.md` that have no code backing them.

### D2: Padded Buckets + `index.enc`

**Documented**: Plaintext Protobuf payloads padded to uniform bucket sizes (1KB/8KB/64KB/1MB) before encryption. Encrypted lookup table (`index.enc`) maps human-readable metadata (URLs, titles) to hashed filenames under `entries/`.

**Current state**: **Padding fully implemented**. `padding.rs` provides `pad()`/`unpad()` with 5 tiers. **`index.enc` fast-lookup table fully implemented**. `index.rs` encrypts/decrypts `index.enc` lookup table under derived key. `list_cipher_meta` performs O(1) decryption on search. `rebuild_index` updates the index on add/update/delete/restore.

**Remaining gap**: None.

### D4: Index Auto-Heal

**Documented**: If `index.enc` has a Git conflict or corruption, idtty-core decrypts the entire ciphers folder, rebuilds the index from scratch, and silently rewrites the index.

**Current state**: **Auto-healing fully implemented**. If index decryption fails (due to corruption, conflicts, or stale keys), `list_cipher_meta()` triggers an automatic self-healing routine: scans the ciphers folder, rebuilds the lookup table, and overwrites `index.enc` with the healthy copy.

**Gap**: None.

### D5: Mobile JIT Sync

**Documented**: Mobile autofill triggers `git fetch` to check remote SHA delta. If delta exists, pulls and decrypts before biometric prompt. Circumvents aggressive OS background termination.

**Current state**: `sync/engine.rs` has fetch/pull/push. No JIT hook. No mobile app to trigger it.

**Gap**: Blocked on UniFFI annotations (D8) and mobile app scaffold.

### D8: UniFFI Bindings

**Documented**: `#[uniffi::export]` proc-macros on idtty-core's public API. UniFFI generates Kotlin (Android) and Swift (iOS) bindings. No intermediate language.

**Current state**: Zero UniFFI annotations in idtty-core. `mobile/` has `build.gradle.kts` placeholder only.

**Gap**:
- No `#[uniffi::export]` on any public function
- No `uniffi.toml` or UDL file
- No generated bindings
- Mobile app is placeholder

### D9: Zero-Knowledge RBAC / Team Sharing

**Documented**: `metadata/access_list.json` contains member public keys mapped to HPKE-wrapped Space Group Keys. Admin rotates Group Key on offboarding. Re-encrypts all entries. Force-pushes.

**Current state**: **Zero-knowledge sharing fully implemented**. `orgs.rs` implements member enrollment via X25519 HPKE wrapping of the Space Group Key. Members are tracked in `meta/access_list.json` alongside their wrapped keys. Revocation of a member automatically triggers Space Group Key rotation and re-wrapping of the new key for all remaining members.

**Gap**: None.

---

## 3. Key Lifecycle Gaps (`03-key-lifecycle.md`)

| Item | Doc Says | Code Status |
|------|----------|-------------|
| Space Group Key (256-bit AES) | Per-Space symmetric key, wrapped per member in `access_list.json` | **Not implemented**. Item Keys derive from RootKey directly. |
| `metadata/access_list.json` | Member public keys → wrapped Group Keys | **Not created** |
| `index.enc` | Encrypted lookup table for fast search | **Done**. Rebuilt on mutations; decrypted in O(1) time; auto-healing on corruption. |
| Git commit signing (Ed25519) | All commits cryptographically signed, unsigned rejected | **Done**. Native git2 signing via `commit_create_buffer` + Ed25519 + `commit_signed`. Signature embedded in commit `gpgsig` header. `extract_signature` verifies on pull. Unsigned commits rejected. Merge + conflict resolution commits also signed. |
| OAuth PAT escrow | PAT stored in OS keyring, never in git config | **Not wired** (PAT stored in standard git credential storage) |
| Offboarding rekey flow | Remove member, rotate Group Key, re-encrypt all entries | **Not built** (depends on orgs + access_list) |

---

## 4. Threat Model Gaps (`02-threat-model.md`)

Controls documented as implemented or planned that are not yet in code.

| Threat ID | Control | Status |
|-----------|---------|--------|
| T1 (metadata leakage) | Uniform bucket padding | **Done**. 5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()`. |
| T3 (JIT timing) | Randomized network delay on JIT fetch | **Done**. `jitter_delay()` with CSPRNG-backed uniform selection. `push_with_jitter`/`pull_with_jitter` wrappers. |
| T4 (evicted member) | Group Key rotation + re-encryption + access list update | **Not started** (no access_list, no org layer) |
| T5 (git remote adversary) | Unsigned commits rejected | **Done**. Native git2 signing: signature embedded in commit object `gpgsig` header (not mutable sidecar). `verify_commit_signatures` uses `extract_signature` on pull. Verify runs before ref/checkout update. Shallow-clone gap detected. |
| T5 (cover commits) | Cover commits to mask usage timing | **Done**. `cover_commit()` creates no-op commits with identical message. |
| Residual Risk 2 | Cover commits to mask usage timing | **Done** (same as T5 cover commits) |
| Residual Risk 3 | Force-evict quorum override requires hardware proof | **Partial** (force_evict_and_rotate works, no hardware proof) |
| D3/D22 (rollback) | Per-device sequence manifest, signed checkpoints | **Done**. `integrity.rs` with `IntegrityManifest`, Ed25519-signed checkpoints, `detect_rollback()`, `bootstrap()` for fresh devices. 7 tests. |

---

## 5. 2FA Analysis (`07-2fa-analysis.md`)

All tiers are design-only. No implementation.

| Tier | Description | Effort | Value | Priority |
|------|-------------|--------|-------|----------|
| 1 | Document "local-only = 2FA" framing in UX | Hours | Framing | Now |
| 2 | FIDO2 vault unlock (hardware second factor via `libfido2`) | Weeks | Real second factor | After mobile MVP |
| 3 | OS keychain sync gate (separate auth for git push/pull) | Days | Compartmentalization | After Tier 2 |
| 4 | TOTP for device enrollment confirmation (ephemeral, liveness check) | Days | Enrollment safety | With multi-device |
| 5 | FIDO2-only mode (no master password) | Weeks | Max security | Future (orgs) |

### Open Questions from Doc

1. `libfido2` Rust crate maturity and audit status
2. Android/iOS FIDO2 via UniFFI vs platform-specific FFI
3. OS keychain availability in headless CI (mock trait needed)
4. Multiple FIDO2 credentials per vault
5. Recovery after FIDO2 credential loss
6. Org/team vault 2FA requirements (deferred)

---

## 6. BW Parity PRD (`prd-bitwarden-parity.md`) Deferred Items

### Cipher Types (not in Phases 1-10)

| Type | BW Fields | Status |
|------|-----------|--------|
| Bank Account | bankName, nameOnAccount, accountType, accountNumber, routingNumber, branchNumber, pin, swiftCode, iban, bankContactPhone | **Deferred** |
| Driver's License | firstName, middleName, lastName, dateOfBirth, licenseNumber, issuingCountry, issuingState, issueDate, expirationDate, issuingAuthority, licenseClass | **Deferred** |
| Passport | surname, givenName, dateOfBirth, sex, birthPlace, nationality, issuingCountry, passportNumber, passportType, nationalIdentificationNumber, issuingAuthority, issueDate, expirationDate | **Deferred** |

### Features (not in Phases 1-10)

| Feature | Notes |
|---------|-------|
| FIDO2 credential storage on Login | Requires hardware auth infrastructure |
| Encrypted JSON export (IDtty-native format) | BW-compatible JSON export exists. IDtty-native encrypted export with Argon2id + AES-256-GCM not built |
| Archive entries | Hide from main list (distinct from trash) |
| Collections | Org-level groupings. Out of scope (no org) |
| Breach report (HaveIBeenPwned) | Requires external API. Out of scope |
| Send (encrypted file/text sharing) | Requires server relay. Out of scope |

---

## 7. Design Debt

| ID | Description | Severity | Effort |
|----|-------------|----------|--------|
| DESIGN-1 | `DeviceManager` fields are `pub`. Any caller can bypass invariant gates via `registry.enroll()` directly. Fix: `pub(crate)` + `#[cfg(test)]` accessors. | Low | ~30 min |
| DESIGN-2 | Persistence (`save_to_vault`/`load_from_vault`) mixed into `DeviceManager` lifecycle. I/O coupled to logic. Fix: split into `DeviceManagerStore`. VaultHandle owns the store. | Low | ~2-3 hours |
| Mock Engine | `MOCK_BACKEND=true` build flag for frontend contributors. Bypasses native compilation, feeds hardcoded Protobuf payloads to components. Referenced in `04-software-architecture.md`. Not built. | Low | ~1 day |
| Pre-existing clippy | **Fixed**. 0 clippy errors workspace-wide after Round 11 cleanup |

---

## 8. Platform Placeholders

| Platform | Directory | Status | Blockers |
|----------|-----------|--------|----------|
| Mobile (KMP) | `mobile/` | `build.gradle.kts` only | UniFFI annotations (D8), Compose Multiplatform UI |
| Browser Extension (MV3) | `extension/` | `package.json` only | SolidJS popup, native messaging host |

---

## 9. Summary by Priority

### Priority 1: Unblocks Other Work

| Item | Why |
|------|-----|
| UniFFI annotations (D8) | Unblocks mobile app development |
| `providers.rs` (D15) | Unblocks OAuth enrollment flow for new devices |

### Priority 2: Security Hardening

| Item | Why | Status |
|------|-----|--------|
| Uniform bucket padding (D2) | Prevents metadata leakage (T1) | **Done** (5 tiers, wired into encrypt/decrypt) |
| Git commit signing | Prevents rollback/swap from git remote (T5) | **Done** (native git2 gpgsig, Ed25519, all commit sites) |
| `integrity.rs` (D3/D22) | Rollback detection | **Done** (7 tests, atomic saves, monotonicity) |
| Cover commits / timing randomization | Masks usage patterns from remote adversary | **Done** (`cover_commit` indistinguishable, `jitter_delay`) |
| `index.enc` fast lookup (D2/D4) | Performance at scale | **Done** |
| FIDO2 vault unlock (2FA Tier 2) | Real hardware second factor | Not started (weeks of effort) |

### Priority 3: Multi-User Features

| Item | Why |
|------|-----|
| `orgs.rs` (D17/D19) | Team/org sharing | **Done** |
| `access_list.json` + Space Group Key | Zero-knowledge RBAC (D9) | **Done** |
| Offboarding rekey flow | Forward secrecy after member removal | **Done** |
| `emergency.rs` (D18) | Break-glass access for trusted contacts | **Done** |

### Priority 4: Polish

| Item | Why |
|------|-----|
| `index.enc` fast lookup (D2/D4) | Performance at scale | **Done** |
| DESIGN-1 (`pub` → `pub(crate)`) | Encapsulation |
| DESIGN-2 (persistence split) | Testability |
| Pre-existing clippy cleanup | Code hygiene |
| Mock Engine | Frontend contributor onboarding |
| Extra cipher types (Bank, DL, Passport) | BW parity completeness |
| Encrypted JSON export (IDtty-native) | Export security |

---

## 10. What IS Done (for context)

All of the following is implemented, tested, and peer-reviewed:

- **Crypto core**: AES-256-GCM, Argon2id, HKDF, HPKE (X25519), Ed25519, TOTP (RFC 6238)
- **Key hierarchy**: MasterPassword → KEK → DevicePrivateKey → RootKey → ItemKey
- **Key lifecycle**: Epoch state machine, rotation with atomic re-encryption, recovery via BIP-39
- **Device lifecycle**: Enrollment, force eviction, two-phase rotation, observer hooks, auto-save
- **Vault CRUD**: 5 cipher types (Login, Card, Identity, SSH Key, Secure Note), create/read/update/delete/clone
- **Folders**: CRUD with nested parents (depth 16), cascade delete
- **Trash**: Soft delete, restore, purge
- **Attachments**: AES-256-GCM encrypted file storage (max 2MB), upload/download/delete
- **TOTP**: SHA1/256/512, 6/8 digits, 30/60s periods. Code gen daemon-side, seed never crosses IPC
- **Password generator**: CSPRNG + EFF 7776-word passphrase
- **Password health**: Weak/reused/old detection
- **Import/Export**: 8 parsers (bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1p_1pux, 1p_csv, keepass_xml) + 2 export formats
- **Biometric unlock**: OS keychain via keyring crate (macOS Keychain, Windows Credential Manager, Linux libsecret)
- **Reprompt**: Per-entry master password challenge with 30s grant
- **Custom fields**: Text, Hidden, Boolean, Linked (24 variants across Login/Card/Identity)
- **Git sync**: git2-rs engine, init/commit/push/pull/fetch, conflict auto-heal, native Ed25519 commit signing (gpgsig header), signature verification on pull, cover commits (indistinguishable from real), timing jitter
- **Integrity**: Sequence manifest (meta/integrity.json), Ed25519-signed checkpoints, rollback detection, fresh device bootstrap, atomic saves, monotonicity enforcement
- **IPC daemon**: tokio Unix socket, Protobuf wire, 30+ routes, session tokens, auto-lock timer
- **CLI**: Dual-mode (daemon-first + --direct), all CRUD/sync/device/health/import commands
- **Desktop**: Tauri v2, SolidJS/Tailwind, full CRUD UI, dark/light themes
- **Security**: 13 review rounds (Round 12: security hardening + 2 re-reviews), 182 idtty-core tests, zeroize + mlock on key material, AAD binding, CSP enforcement, uniform bucket padding, native git2 commit signing, integrity checkpoints, cover commits, timing jitter

---

## 11. Security Review Log

| Round | Focus | Findings | Outcome |
|-------|-------|----------|----------|
| 1-7 | Original crypto + vault + sync | 107+ findings | All fixed |
| 8 | Multi-URI + settings | 4 findings | All fixed |
| 9 | Device lifecycle bugs | 7 findings | All fixed |
| 10 | MISS-1 through MISS-5 implementation | 4C, 7H, 8M, 4L | All fixed |
| 11 | Clippy cleanup + docs | 6 findings (0C, 2H, 3M, 1L) | All fixed |
| 12 | Security hardening batch | 2C, 4H, 3M, 3L | All fixed |
| 12-re | Round 12 fixes re-review | 1C, 1H, 2M, 2L (new) | All fixed |
| 13 | Native git2 signing + final verification | Confirmed clean | Ship-ready |, timing jitter
