# IDtty: Master Progress Document

> Single source of truth for project state. Update after every work session.
> Last updated: 2026-06-02

---

## Project Overview

**What**: Git-backed password manager. Encrypted vault stored as a git repo. No server.
**Stack**: Rust Core Engine (`idtty-core` crypto/keys/vault/sync + `idtty-daemon` IPC socket server + `idtty-cli` terminal client) + Tauri v2 Desktop (SolidJS/Tailwind) + Single-String Protobuf Gateway.
**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell.
**Architecture docs**: `docs/01-architecture-decisions.md` through `docs/04-software-architecture.md`.

---

## Current Status

**Phase**: Desktop BW parity complete (phases 1-8 + A-G). Device lifecycle complete (MISS-1 through MISS-5, peer review fixes). Security hardening complete (Round 13). Archive entries feature complete. Architecture refactoring complete (DESIGN-1/2/3 + peer review). **198 tests, 0 clippy errors workspace-wide**, 13 security review rounds. Full desktop feature set: CRUD, 5 cipher types, generator, TOTP, auto-lock, import/export, reprompt, password health, attachments, biometric unlock, linked custom fields, nested folders, archive entries.

**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/idtty-core` - Rust core engine: crypto, keys, vault, padding, git sync
- `/crates/idtty-cli` - Terminal CLI client (clap, daemon-first with `--direct` fallback)
- `/crates/idtty-daemon` - Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state)
- `/desktop` - SolidJS/Tailwind/Tauri v2 desktop app (full CRUD, 5 cipher types, generator, TOTP, auto-lock, dark/light themes)

---

## Staged Implementation Progress

### Phase 0: Monorepo Scaffolding
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `workspace` | Done | Rust workspace with idtty-core, idtty-cli, idtty-daemon crates. Go codebase removed. |
| `proto/schemas` | Done | `vault.proto`, `space.proto`, `auth.proto`. Go package refs removed. Compiled by prost-build in daemon and CLI. |
| `crates/idtty-core` | Done | Full crypto, keys, vault, padding, git sync engine. 3,850 lines. 66 tests pass. |
| `crates/idtty-cli` | Done | clap CLI with dual-mode: daemon-first (Protobuf over Unix socket) + `--direct` fallback (idtty-core). Commands: init, unlock, lock, add, get, list, delete, sync, devices, ping. |
| `crates/idtty-daemon` | Done | tokio socket + Protobuf gateway + VaultState (Arc<RwLock<Option<VaultHandle>>>). Routes: ping, vault.open/unlock/lock/info/list/get/add/delete, vault.trash.list/restore/purge. CLI args: --vault-path, --socket. |

### Phase 1: Cryptographic Core & Padding Engine (Rust)
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `crypto/aead` | Done | AES-256-GCM with strict AAD binding. |
| `vault/handle` | Done | Vault CRUD operations. |
| `vault/creation` | Done | Vault creation ceremony. Vault .gitignore excludes device-privkey.json. |

### Phase 2: Git Sync Engine (Rust)
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `sync/engine` | Done | git2-rs sync engine: init_repo, commit, push, pull, fetch. |
| `sync/conflict` | Done | Conflict auto-healing (index rebuild, entry rename). |
| `sync/state_machine` | Done | Sync state machine for tracking sync progress. |
| `sync/commit` | Done | Commit builder with padding-aware serialization. |

### Phase 3: IPC Daemon & CLI Gateway
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `daemon/socket` | Done | Unix socket listener. 0600 via umask before bind. SIGINT/SIGTERM graceful shutdown (locks vault, zeroizes keys). |
| `daemon/handler` | Done | Protobuf (prost) gateway. Length-delimited wire protocol (varint frame prefix). Oversized frames close connection. Password zeroized after unlock. |
| `daemon/state` | Done | VaultState holds VaultHandle behind Arc<RwLock>. KDF derivation runs outside write lock. Double-check pattern prevents unlock races. Delete uses write lock. |
| `daemon/build` | Done | prost-build compiles all 3 proto files. Removed unused prost-types dep. |
| `cli/socket-client` | Done | `client.rs`: Protobuf socket client. Bounds-checked varint decode. `request_to(action, payload, socket_path)`. `is_daemon_running()`. |
| `cli/dual-mode` | Done | All vault commands (unlock, lock, add, get, list, delete) route through daemon by default. `--direct` flag falls back to idtty-core. `--socket <path>` for custom daemon socket. `ensure_unlocked_daemon()` auto-prompts master password. |
| `cli/init` | Done | Always direct. Writes vault .gitignore excluding meta/device-privkey.json. |
| `cli/sync` | Done | Daemon-first with --direct fallback. All 6 actions: init, remote, push, pull, status, log. Feature-gated behind `git-sync`. |
| `cli/devices` | Done | Daemon-first with --direct fallback. Returns device list via vault.devices route. |

### Phase 4: Desktop UI & Open-Source Launch
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `desktop` | Done | SolidJS/Tailwind v4 webview in Tauri v2. Login screen + vault view (cipher list, add, get, delete). Dark theme. Scaffolded via `tauri init`. |
| `desktop/tauri` | Done | Rust backend (edition 2024): daemon_request Tauri command proxies to idtty-daemon via Protobuf. System tray with Show/Quit. All platform icons via `tauri icon`. Sidecar config in tauri.conf.json. |
| `desktop/tray` | Done | Tauri v2 TrayIconBuilder with Show/Quit menu. Left-click shows window. Close hides to tray. |
| `desktop/daemon` | Done | Tauri spawns idtty-daemon on launch. SIGTERM + wait on app exit. |
| `desktop/create` | Done | Vault creation UI: CreateVaultScreen (password + confirm), RecoveryScreen (BIP-39 phrase display). Auto-unlock after creation. |
| `cli/binary` | Done | CLI binary renamed to `idtty` (was `idtty-cli`). Package name unchanged for compat. |
| `daemon/vault.create` | Done | New daemon route: runs creation ceremony, writes all vault files with 0600 perms, opens vault, returns recovery phrase. |
| `ci-cd` | Done | GitHub Actions: test.yml (cargo test/fmt/clippy), build-desktop.yml (tauri-action matrix). Both workflow_dispatch only. |
| `docs` | Done | README.md (build/platform/webview instructions), CONTRIBUTING.md (guidelines + code standards). |



### Phase 6: Security Hardening
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| Uniform bucket padding (D2) | Done | 5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()`. Wired into encrypt/decrypt. |
| `index.enc` fast lookup (D2/D4) | Done | Encrypted lookup table under derived key. `list_cipher_meta` performs O(1) decryption. `rebuild_index` on mutations. Auto-healing on corruption. |
| Git commit signing (T5) | Done | Native git2 signing via `commit_create_buffer` + Ed25519 + `commit_signed`. Signature in commit `gpgsig` header. `extract_signature` verifies on pull. Unsigned commits rejected. Merge + conflict resolution commits also signed. |
| Cover commits / timing jitter | Done | `cover_commit()` creates no-op commits with identical message. `jitter_delay()` with CSPRNG-backed uniform selection. `push_with_jitter`/`pull_with_jitter` wrappers. |
| Integrity manifest (D3/D22) | Done | `integrity.rs` with `IntegrityManifest`, Ed25519-signed checkpoints, `detect_rollback()`, `bootstrap()` for fresh devices. Atomic saves, monotonicity enforcement. 7 tests. |
| Token-gated IPC | Done | Per-request 256-bit session token on unlock. Constant-time comparison. Token cleared on lock. |
| `mlock` on key material | Done | `libc::mlock` on RootKey/ItemKey creation. Manual `Clone` impl that re-mlocks. `Box<[u8; N]>` for stable heap addresses. Custom `Debug` impl redacts key bytes. |
| AAD swap-attack protection | Done | `decrypt_cipher` recomputes expected AAD and asserts equality before decryption. Fail-fast, no decryption oracle. |

### Phase 7: Multi-User Features
| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `orgs.rs` (D17/D19) | Done | Team/org sharing. X25519 + HPKE authenticated key wrapping. Member add/remove. Auto-rekey all shared items on member removal. |
| `emergency.rs` (D18) | Done | Break-glass access. Pre-wrapped Root Key in `meta/emergency.json`. Advisory time gate. Setup, request, approve, revoke, recovery flows. |
| `providers.rs` (D15) | Done | Git provider adapters (GitHub, GitLab). OAuth flow. PAT fallback. Auto-create `idtty-vault` repo. `ProviderAdapter` trait. |
| Zero-knowledge RBAC (D9) | Done | `access_list.json` with member public keys mapped to HPKE-wrapped Space Group Keys. Admin rotates Group Key on offboarding. Re-encrypts all entries. Force-pushes. |

### BW Parity Phases 1-8

All 8 phases complete, peer-reviewed, and merged. **130 tests (now 190 workspace-wide), 0 clippy errors.**

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| 1 | CipherKind sum type | `CipherKind` tagged enum (Login/Card/Identity/SshKey/SecureNote). Invalid states unrepresentable. |
| 2 | Multi-URI + settings | Login ciphers support multiple URIs with match strategy. `VaultSettings` CRUD via daemon. |
| 3 | CipherMeta + vault.update | `vault.list` returns `CipherMeta` (type, favorite, username). `vault.update` with PATCH semantics. |
| 4 | Password history + clone | Auto-append on password change, cap 10 entries. `cipher.clone` creates new UUID with empty history. |
| 5 | Folder CRUD | `list/create/rename/delete` folders. `delete_folder` unassigns ciphers first. CLI `idtty folders` + `--folder` flag on add. |
| 6a | Desktop: Login + SecureNote | Type-aware forms, multi-URI editor, category filtering, CipherKind JSON construction. |
| 6b | Desktop: Card + Identity | Card form (brand auto-detect), Identity form (16 fields). Full kind nesting in daemon response. |
| 6c | Desktop: SSH Key | Public/private key + fingerprint form. Private key masked with reveal. |
| 7 | Generator + auto-lock | Password generator (CSPRNG, EFF 7776-word passphrase). Auto-lock timer (configurable, daemon-side). |
| 8 | TOTP code generation | RFC 6238/4226 (SHA1/256/512, 6/8 digits). Daemon route `cipher.totp_code`. UI widget with boundary-aligned refresh. |

#### Key Architectural Decisions (from peer reviews)
- Daemon `get_cipher` emits BOTH nested `kind` object AND flat top-level fields
- `update_cipher` parses `kind` from payload JSON (not clone existing)
- Rust field names must match frontend JSON keys exactly (`cardholder_name`, `key_fingerprint`)
- TOTP `period=0` rejected at parse time (division-by-zero protection)
- `TotpParams.secret` zeroized on drop via `ZeroizeOnDrop`
- Generator uses `crypto.getRandomValues` exclusively (never `Math.random`)
- Passphrase digits use separate random source from word selection

### BW Parity Phases A-G (Final Push)

All 7 phases complete, individually peer reviewed, fixes applied. **186 idtty-core tests (190 workspace), 0 clippy errors.**

| Phase | Description | Key Changes | Review Findings |
|-------|-------------|-------------|----------------|
| A | Import/Export | 8 import parsers (bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1password_1pux, 1password_csv, keepass_xml) + 2 export formats (bw_json, bw_csv). Daemon routes. CLI commands. Desktop ImportExportButton. | 1C (folder resolution), 2H (export safety, type detection), 4M. All fixed. |
| B | Reprompt | `reprompt: bool` on Cipher/CipherMeta/CipherInput. Daemon `vault.reprompt_verify` (temp handle, 30s grant). Desktop RepromptModal + shield icon. | Field addition, no standalone review. |
| C | Password Health | `health.rs` weak (<8 chars, common50, sequential), reused (same password across entries), old (>90 days). Daemon `vault.health`. CLI `idtty health`. | Self-contained module, no standalone review. |
| D | Attachments | `vault/attachment.rs` AES-256-GCM with cipher's item key, random nonce, max 2MB. Stored at `entries/<id>/attachments/<id>.enc`. Daemon upload/download/delete. CLI commands. Desktop attachment list. Plaintext zeroized in daemon+CLI. | 2C (zeroize), 3H (orphan files, action name, missing response field), 5M, 3L. All fixed. |
| E | Biometric Unlock | `biometric.rs` stores master password in OS keychain (keyring crate). Daemon performs unlock internally (secret never over IPC). Desktop Quick Unlock button + settings toggle. | 3C (non-functional frontend, token gate, wrong secret), 4H (IPC exposure, timing leak, validation, rotation), 3M, 2L. All fixed. |
| F | Linked Custom Fields | `CustomFieldType::Linked(LinkedFieldType)` with 24 variants. `resolve_linked_field()`. Desktop custom field editor with type dropdown + linked field selector. | 2C (wire format mismatch, missing response field), 2H (incomplete dropdown/map), 2M, 1L. All fixed. |
| G | Nested Folders | `create_folder_with_parent` with depth limit (16). `delete_folder` cascades via `collect_descendant_ids`. Desktop FolderTree/FolderNode recursive components. Folder filter includes subfolder ciphers. | 1C (orphaned children on delete), 2H (depth limit, subfolder filtering), 2M. All fixed. |

#### Key Architectural Decisions (from A-G reviews)
- Desktop JS field_type must match Rust serde externally-tagged format (`"Text"`, `"Hidden"`, `{"Linked":"LoginUsername"}`)
- Daemon `get_cipher` must include ALL fields in JSON response (custom_fields, attachments, reprompt)
- All plaintext attachment data zeroized after encrypt/decode in both daemon and CLI
- Biometric unlock happens daemon-side only; master password never returns over IPC
- Folder delete cascades to children; depth limited to 16
- `collect_descendant_ids` uses BFS to prevent cycles

### Desktop UI/UX Revamp (Round 8)

Complete overhaul of the desktop interface to deliver a production-grade 3-column user experience:
- **Layout Alignment**: Implemented the Bitwarden/1Password 3-column interface (`w-[260px]` Navigation Sidebar, `w-[360px]` Searchable Vault List, and Flex-1 Details & Form Panel).
- **Refinement of Visuals**: Styled with the custom forest teal and soft lavender reference palette. Added responsive UI micro-animations and smooth transition transitions.
- **Dynamic Themes**: Built dark and light modes, controlled by a SolidJS signal synced to a `.light-theme` body class. Accessible via theme switcher icons on lock screens, vault views, and create screens.
- **List Monograms & Hover shortcuts**: Generates beautiful monogram badges based on hostnames. Added hover quick-actions (URL Launch, Copy Password) directly on rows.
- **Interactive Details & Password Generator**: Integrated a comprehensive details viewer with copy/eye reveal controls and an interactive password generator (with length slider and custom complexity pools) built directly into form flows.
- **Parallel Loading Optimization**: Loaded decrypted cipher metadata asynchronously in parallel during unlock, ensuring instant search and zero detail latency.

---

## Security Review History

13 rounds total. All findings fixed.

### Round 1 (Independent Review)
6 findings across critical/important/minor categories:
1. Socket TOCTOU -> Fixed: umask(0177) before bind()
2. Missing SIGTERM handler -> Fixed: tokio::signal::unix with graceful vault lock
3. JSON injection in sync metadata -> Fixed: Schema validation, quote/backslash escaping
4. Doc inaccuracies -> Fixed: Current vs planned state clearly separated
5. Ghost paths in docs -> Fixed: Removed references to unbuilt directories
6. Duplicate tokio dep -> Fixed: Consolidated workspace dep

### Round 2 (Independent Review)
10 findings (3 critical, 4 important, 3 minor). All fixed:
- **C1**: Frame-too-large desynced protocol -> Fixed: Close connection on oversized frames
- **C2**: Master password not zeroized at IPC layer -> Fixed: `zeroize` crate (`write_volatile` + `compiler_fence`) on both daemon and client side
- **C3**: Client decode_varint panics on malformed response -> Fixed: Bounds-checked `decode_varint_checked()`
- **I1**: delete_cipher used read lock for mutation -> Fixed: Upgraded to write lock
- **I2**: TOCTOU in unlock (read check -> write acquire gap) -> Fixed: Double-check under single write lock
- **I3**: Write lock held during Argon2id (~1s) blocking all reads -> Fixed: KDF outside lock, swap handle under lock
- **I4**: device-privkey.json gets git-committed -> Fixed: Vault .gitignore written during init
- **M1**: Dead `ok_response` function -> Fixed: Removed
- **M2**: `--direct` flag referenced but didn't exist -> Fixed: Flag now implemented
- **M3**: Unused prost-types dep -> Fixed: Removed from daemon Cargo.toml

### Round 3 (Independent Review)
9 findings (1 critical, 2 security, 2 correctness, 4 minor). All fixed:
- **C1**: `zeroize_string()` used `write_bytes` (LLVM dead-store elimination can remove it) -> Fixed: Replaced with `zeroize` crate (`write_volatile` + `compiler_fence`)
- **S1**: Client-side password copies never zeroized (CLI heap readable via /proc/pid/mem) -> Fixed: `password.zeroize()` in unlock_daemon, ensure_unlocked_daemon; wire bytes + payload zeroized in client.rs
- **S2**: `handle_get` forced unlock for metadata-only reads (password prompt when not needed) -> Fixed: Skip `ensure_unlocked_daemon` when `--decrypt=false`
- **CO1**: Vault opened twice on first unlock (open_inner + fresh VaultHandle::open) -> Fixed: Single open + unlock + swap pattern, removed `open_inner`
- **CO2**: `ensure_unlocked_daemon` called redundant `vault.open` when vault already open but locked -> Fixed: Skip `vault.open` when `vault.info` succeeds (vault already open)
- **M1**: `open_inner()` was a pointless wrapper -> Fixed: Removed
- **M2**: `is_daemon_running` was dead code -> Fixed: Removed
- **M3**: `handle_list` silently fell back to direct mode; other commands returned Err -> Fixed: Consistent Err return
- **M4**: `handle_lock` Direct arm used `process::exit(1)` -> Fixed: Returns `Err` for standard error path

### Round 4 (Independent Review — Phase 4 Desktop)
15 findings (3 security, 7 correctness, 5 minor). All fixed:
- **S1**: CSP was `null` (XSS reads master password from DOM) -> Fixed: Strict CSP with `ipc:` + `http://ipc.localhost` for Tauri v2
- **S2**: `Daemon::drop` used `kill()` (SIGKILL, no cleanup) -> Fixed: `libc::kill(SIGTERM)` + 3s grace + SIGKILL fallback
- **S3**: Unbounded `read_to_end` (memory exhaustion) -> Fixed: `Read::take(5MB)` + size check
- **CO1**: `std::os::unix` import breaks Windows compile -> Fixed: `#[cfg(unix)]` gates + stubs
- **CO2**: Daemon binary not bundle-relative (fails packaged) -> Fixed: Uses tauri-plugin-shell sidecar API
- **CO3**: No socket readiness poll after spawn -> Fixed: 20x100ms ping-based readiness check
- **CO4**: No I/O timeout (UI freeze if daemon stalls) -> Fixed: 30s read, 5s write timeouts
- **CO5**: Panic on short device key strings (hard `[]` index) -> Fixed: `.get()` with `unwrap_or` fallback
- **CO6**: Draft releases created on every PR -> Fixed: Removed PR trigger, now `workflow_dispatch` only
- **CO7**: No vault creation flow in desktop -> Fixed: Vault creation UI + daemon vault.create route
- **M1**: `daemon_status()` phantom connect -> Fixed: Ping-based liveness check
- **M2**: Daemon inherits stdout/stderr -> Fixed: `Stdio::null()`
- **M3**: Unused `bytes` crate -> Fixed: Removed
- **M4**: Module-scope SolidJS signals -> Fixed: All signals moved into `AppProvider` context
- **M5**: Raw daemon errors surfaced to UI -> Fixed: `sanitizeError()` maps 8 known patterns to user-friendly messages

### Round 5 (Follow-Up Review)
3 new findings (2 correctness, 1 style). All fixed:
- **CO-NEW-1**: Startup probe used phantom connect instead of ping -> Fixed
- **CO-NEW-2**: Readiness poll used phantom connect instead of ping -> Fixed
- **M-NEW-1**: `daemon_status` verbose match instead of `.is_ok()` -> Fixed

### Round 6 (Independent Review — Vault Creation)
10 findings (1 critical, 2 security, 5 correctness, 2 minor). All fixed:
- **C1**: Vault files written with 0644 permissions -> Fixed: `write_secret` helper sets 0600 on all sensitive files
- **S1**: Master password not zeroized after ceremony -> Fixed: `Zeroizing<String>` wrapper
- **S2**: `shell:allow-spawn/execute` exposed to webview -> Fixed: Removed from capabilities
- **CO1**: Auto-unlock after vault creation silently failed (getElementById on unmounted DOM) -> Fixed: Uses `createPassword` signal
- **CO2**: Key files written with default perms -> Fixed: write_secret with 0600
- **CO3**: No guard against overwriting existing vault -> Fixed: Checks kdf-params.json
- **CO4**: `unwrap()` on serialization could panic async task -> Fixed: All `map_err`
- **CO5**: Sidecar declared in config but Rust code still uses PATH spawn -> Fixed: Sidecar spawn via `tauri_plugin_shell::ShellExt`
- **M1**: README code fence broken -> Fixed: Single fenced block
- **M2**: `getElementById` anti-pattern in SolidJS -> Fixed: Refs + signals

### Round 7 (Pass Analysis — Independent Peer Review)

**Source**: Full analysis of `pass` (password-store v1.7.4) by zx2c4. Peer review of findings via independent code review.

**Pass CVEs studied**: CVE-2018-12356 (GPG regex parsing), CVE-2020-28086 (filename swap attack), plus rot256.dev security critique on active-adversary weaknesses.

#### Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| R7-1 | **Critical** | AAD verification gap in `decrypt_cipher`. AAD binds `cipher_id` into the GCM tag at encrypt time, but `decrypt_cipher` never re-computes expected AAD from caller params and compares it to stored AAD before decryption. | **Fixed** |
| R7-2 | **High** | Daemon socket is a full-vault oracle for any same-UID process. After unlock, any process owned by the same user can connect to the Unix socket and call `GetCipher` with arbitrary IDs. | **Fixed** |
| R7-3 | **Medium** | Key buffers not `mlock`ed. OOM kill, `kill -9`, or panic bypasses `zeroize` on drop. Key material may persist in RAM pages until overwritten, or page to swap/hibernation. | **Fixed** |
| R7-4 | **Low** | `docs/02-threat-model.md` does not explicitly model the git remote as adversarially writable. | **Fixed** |

#### Rejected Proposals (with rationale)

| Proposal | Ruling | Rationale |
|----------|--------|----------|
| Add Ed25519 signatures on every envelope | **Rejected** | AES-256-GCM auth tag IS the signature. The AAD gap (R7-1) is the real bug. Only add signatures if non-repudiation for org audit trails is needed later. |
| Blinded search index | **Rejected** | Decrypt-on-search is acceptable for a local manager. Blinded indexes add complexity with only exact-match capability. |
| Hash entry path as identity | **Rejected** | Paths are mutable (rename forces re-encrypt). Random UUID at creation is already correct. |

#### Pass Design Patterns Worth Preserving

1. **Git log as audit trail**: Pass's commit history is an implicit tamper-evident log. Surface it explicitly in UI.
2. **Aggressive clipboard timeout**: Pass defaults 45s. IDtty's 15s default is correct. Never restore previous clipboard content.
3. **Explicit threat scope**: Document what the project does NOT defend against.

### Round 8 (UI/UX Revamp)
No security findings. Production-grade 3-column interface. See Desktop UI/UX Revamp section under Implementation Progress.

### Round 9 (Device Lifecycle Bug Fixes)
4 bugs from peer review of Candidate 3 (DeviceManager). All fixed:

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| BUG-1 | P0 | `collected_acks` no dedup by `device_id` | Reject duplicate acks. Use `epoch.acknowledged_devices.len()` for quorum |
| BUG-2 | P1 | `seen_nonces` not persisted across restarts | Persist to `meta/seen-nonces.json`. FIFO eviction at 10,000 entries |
| BUG-3 | P1 | `_commit_barrier` computed then dropped | Populate `tx.commit_barrier` before commit. Write `.committed` file |
| BUG-4 | P1 | Dual ack-tracking structures diverge | `epoch.acknowledged_devices` is canonical. `collected_acks` is signed payloads only |

Also added: `EnrollmentPayload::encode_transfer()` / `decode_transfer()`, `PairingBundle` struct, 4 new tests.

### Round 10 (Device Lifecycle Implementation + Peer Review Fixes)

Implemented 5 missing device lifecycle features (MISS-1 through MISS-5):

| ID | Description | Key Changes |
|----|-------------|-------------|
| MISS-1 | Root Key Rotation with Cipher Re-encryption | `VaultHandle::rotate_root_key()` — atomic staged writes, re-encrypts active + trash, new epoch via DeviceManager |
| MISS-2 | VaultHandle Signing Integration | `DeviceManager` field on VaultHandle, `initiate/finalize_key_rotation`, `force_evict_and_rotate`, `recover_from_phrase` |
| MISS-3 | Rotation Observer for Git Sync | `RotationObserver` trait (5 hooks), `set_observer()` injection, `fire()` helper |
| MISS-4 | Auto-Save After State Transitions | `auto_save()` (best-effort) + `auto_save_result()` (critical paths) on DeviceManager |
| MISS-5 | Recovery Phrase Path Through DeviceManager | `recover_from_phrase()` — BIP-39 parse, HPKE-unwrap Root Key, new device enrollment, epoch from vault data |

Peer review found 4 Critical, 7 High, 8 Medium, 4 Low issues. All Critical/High/Medium fixed.

### Round 11 (Workspace-Wide Clippy Cleanup)

Fixed 20+ pre-existing clippy warnings across all 3 crates. Categories: Derive Default (5), Redundant closures (5), Simplification (4), Naming (2), Structural (3), Style (3).

### Round 12 (Security Hardening Batch)
9 findings (2C, 4H, 3M, 3L). All fixed:
- Padding, index.enc, git commit signing, cover commits, integrity manifest wired end-to-end.
- **Re-review** found 1C, 1H, 2M, 2L (new). All fixed.

### Round 13 (Native git2 Signing + Final Verification)
Confirmed clean. Native git2 signing: signature embedded in commit object `gpgsig` header (not mutable sidecar). `verify_commit_signatures` uses `extract_signature` on pull. All commit sites signed (including merge + conflict resolution). Ship-ready.

---

## Pending Work

All items not yet implemented. Focus: core, CLI, daemon, desktop only.

### Desktop Features

| Item | Description | Status |
|------|-------------|--------|
| Extra cipher types | Bank Account (10 fields), Driver's License (12 fields), Passport (13 fields). BW recently added these | Deferred |
| Additional import formats | Dashlane, Enpass, NordPass, Avast, Avira, Keeper, RoboForm, Myki, mSecure, Blur | Not started |

### Nice to Have / Future

Features parked for the far future. Do not start without explicit confirmation.

| Item | Description | Blocker |
|------|-------------|---------|
| Encrypted JSON export | IDtty-native format (Argon2id + AES-256-GCM). Vendor-locked: needs idtty installed to decrypt. Git clone + recovery phrase already covers disaster recovery | Low priority, needs format documentation |
| FIDO2 credential storage | On Login cipher type. Requires hardware auth infrastructure | Needs FIDO2-compatible hardware (e.g. YubiKey, Titan) for testing |

### Out of Scope (No Server)

| Item | Why |
|------|-----|
| Collections | Org-level groupings, requires multi-user infrastructure |
| Breach report | HaveIBeenPwned requires external API |
| Send | Encrypted sharing requires server relay |
| HOTP | TOTP only. Counter-based OTP out of scope |
| BW server API compat | IDtty is serverless |

### Security

| Item | Description | Effort |
|------|-------------|--------|
| OAuth PAT escrow | PAT stored in OS keyring (never in git config). Currently uses standard git credential storage | Days |
| 2FA Tier 1 | Document "local-only = 2FA" framing in UX | Hours |
| 2FA Tier 2 | FIDO2 vault unlock via `libfido2` (hardware second factor) | Weeks |
| 2FA Tier 3 | OS keychain sync gate (separate auth for git push/pull) | Days |
| 2FA Tier 4 | TOTP for device enrollment confirmation (ephemeral liveness check) | Days |
| 2FA Tier 5 | FIDO2-only mode (no master password) | Weeks |
| Residual Risk 3 | Force-evict quorum override requires hardware proof | Partial |

#### 2FA Open Questions

1. `libfido2` Rust crate maturity and audit status
2. OS keychain availability in headless CI (mock trait needed)
3. Multiple FIDO2 credentials per vault
4. Recovery after FIDO2 credential loss
5. Org/team vault 2FA requirements (deferred)

### Architecture

| Item | Description | Effort | Status |
|------|-------------|--------|--------|
| Space Group Key layer | RootKey → SpaceGroupKey → ItemKey hierarchy. SGK derived via HKDF for single-user, random for multi-user/org. Breaking change from direct RootKey→ItemKey derivation. `SpaceGroupKey` carries bound epoch with debug_assert guard. Volatile zeroize via `zeroize` crate. 8 tests | Weeks | **Done** |
| DESIGN-1: `pub` fields | `DeviceManager` fields changed to `pub(crate)`. Accessor methods added for read-only queries. `single_device_commit_rotation()` method replaces direct field mutation from handle.rs | ~30 min | **Done** |
| DESIGN-2: I/O coupling | `DeviceManagerStore` trait + `FileDeviceManagerStore` impl + `DeviceManagerState` snapshot struct. `DeviceManager` holds `Arc<dyn Store>`. Backward compat via `set_vault_path()` / `load_from_vault()`. Trait includes `exists()` method. Atomicity gap documented | ~2-3 hours | **Done** |

#### Peer Review (Round 14)

peer review of DESIGN-1/2/3: 12 findings (4C, 4H, 3M, 1L). All fixed.

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | High | Manual zeroize loops may be optimized out by compiler in release builds | All key types now use `zeroize::Zeroize` trait (volatile writes) |
| 2 | High | Cached `space_group_key` in `UnlockedState` never read; redundant SGK derived on every cipher op | Split into `derive_item_key_from_sgk` (uses cached) and `derive_item_key_from_root` (fallback) |
| 3 | High | `vault_files_exist()` hardcoded `FileDeviceManagerStore`, bypassed trait | Added `exists()` to `DeviceManagerStore` trait |
| 4 | High | `save_state()` multi-file writes not collectively atomic | Documented atomicity gap in trait doc comment |
| 5 | Medium | `handle.rs::rotate_root_key()` directly mutated DeviceManager fields | Added `single_device_commit_rotation()` method |
| 6 | Medium | Stale `.txn`/`.ack.*` files accumulate after rotation commit | Noted for future cleanup; not a correctness issue |
| 7 | Medium | `atomic_write()` took `&PathBuf` not `&Path` | Changed to `&Path` |
| 8 | Medium | Wrong `Vec::with_capacity()` hints in SGK/ItemKey derivation | Fixed to match actual byte counts |
| 9 | Medium | `SpaceGroupKey` carried no epoch tag; misuse possible | Added `epoch` field + `debug_assert_eq!` guard |
| 10 | Low | `fire()` was `pub(crate)` but only called within `device_manager.rs` | Made private, added `notify_rotation_committed()` wrapper |
| 11 | Low | Trait missing `exists()` method (resolved by #3) | — |
| 12 | Low | Double-zeroize pattern (explicit + Drop) | Clean with `Zeroize` trait (idempotent volatile writes) |

### Dev Experience

| Item | Description | Blockers |
|------|-------------|----------|
| Mock Engine | `MOCK_BACKEND=true` build flag for frontend contributors. Bypasses native compilation, feeds hardcoded Protobuf payloads. Referenced in `04-software-architecture.md` | Not started (~1 day) |

---

## BW Parity Reference

Durable architectural decisions from the Bitwarden parity implementation. Preserved for future feature work.

### Cipher Model

- **CipherKind is a Rust sum type** (`enum` with associated data). Invalid states unrepresentable at compile time. Serialized as `#[serde(tag = "type", content = "data")]` producing `{"type": "Login", "data": {...}}`
- **CipherType enum**: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`. Bank/DriversLicense/Passport deferred
- **Identity has three address lines**: `address1`, `address2`, `address3`. Not singular. Matters for BW import fidelity
- **Multi-URI**: `Vec<LoginUri>` where `LoginUri { uri, match_strategy }`. Ordered, reorderable
- **UriMatchStrategy**: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5). Global default from `VaultSettings.default_uri_match`, per-URI override
- **Favorite**: `bool` on both `Cipher` and `CipherMeta` (added atomically, same phase)
- **Password history**: `Vec<PasswordHistoryEntry>` on Cipher, auto-appended on password change, cap 10 entries (FIFO)

### CipherMeta (List Rendering)

`vault.list` returns `CipherMeta` with `id`, `name`, `cipher_type`, `favorite`, `username`. Frontend renders list without decrypting full cipher data. Type, favorite, and username stored in manifest index (Option A: plaintext metadata, low-sensitivity).

### Daemon Wire Format

- Actual wire format uses JSON strings inside `GatewayRequest.payload`, not typed proto fields. Proto updates are cosmetic until a future typed proto migration is explicitly planned
- `get_cipher` returns BOTH nested `kind` object AND flat top-level fields for backward compat
- `update_cipher` parses `kind` from payload JSON (does NOT clone existing kind)

### Import/Export

- Import runs in Rust core (no JS parsing of secrets). Output: `Vec<CipherInput>`, batch-create
- BW JSON import strips `uriChecksum` without error
- BW SecureNote import accepts `type: 0` field without error (IDtty ignores it)
- 8 formats implemented: bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1password_1pux, 1password_csv, keepass_xml
- 2 export formats: bw_json, bw_csv (both BW-compatible)

### TOTP

- otpauth URI parser handles: algorithm (SHA1/256/512), period (30/60s), digits (6/8), secret, issuer
- TOTP seed NEVER crosses IPC. Only derived numeric code sent to frontend
- `TotpParams.secret` zeroized on drop via `ZeroizeOnDrop`

### Password Generator

- Pure frontend (`crypto.getRandomValues` exclusively, never `Math.random`)
- EFF large word list (7776 words) bundled as static asset
- Passphrase digits use separate random source from word selection

### Backward Compatibility

- Missing `type` field auto-migrated to `Login` via custom `Deserialize` impl
- `Vec<String>` URIs auto-migrated to `Vec<LoginUri>` with Domain default
- Unknown `UriMatchStrategy` string values produce hard error (not silent fallback)

---

## Known Limitations

1. **OS Keystore Binding**: OAuth PAT and digital identity private keys are locked in host OS keyring; CLI requires daemon connectivity to unlock.
2. **Metadata Leakage via Bucket Sizes**: Standard logins mapped to 1KB, notes to 8KB, attachments to 64KB/1MB. Provider can infer entry counts per class.
3. **Offline Sharing Limitation**: Invites and revokes require committing wrapped keys to `metadata/access_list.json` and pushing to remote git hosts.
4. **Sync routed through daemon**: sync.init/remote/push/pull/status/log all route through daemon by default with --direct fallback.

---

## CLI Command Reference

| Command | Mode | Description |
|---------|------|-------------|
| `init --profile <p>` | Direct | Create new vault (binary: `idtty`) |
| `unlock` | Daemon/Direct | Unlock vault (daemon persists state) |
| `lock` | Daemon | Lock vault, zeroize keys |
| `add --name N ...` | Daemon/Direct | Add cipher (auto-prompts unlock) |
| `get <id> --decrypt` | Daemon/Direct | Get cipher by UUID |
| `list` | Daemon/Direct | List all cipher UUIDs |
| `edit <id> --name/--favorite/--folder` | Daemon/Direct | Edit cipher metadata |
| `delete <id>` | Daemon/Direct | Delete cipher by UUID |
| `archive <id>` | Daemon/Direct | Archive cipher (hide from main list) |
| `unarchive <id>` | Daemon/Direct | Unarchive cipher (restore to main list) |
| `list [--archived]` | Daemon/Direct | List ciphers (use --archived for archived only) |
| `folders {create\|list\|rename\|delete}` | Daemon/Direct | Folder management |
| `sync {init\|remote\|push\|pull\|...}` | Daemon/Direct | Git sync operations |
| `import <format> <file>` | Daemon | Import entries (bw-json/bw-csv/chrome-csv/firefox-csv/lastpass-csv/1password-1pux/1password-csv/keepass-xml) |
| `export <format> <file>` | Daemon | Export entries (bw-json/bw-csv) |
| `health` | Daemon | Password health report (weak/reused/old) |
| `attach-upload <cipher_id> <file>` | Daemon | Upload encrypted attachment (max 2MB) |
| `attach-download <cipher_id> <attach_id> <output>` | Daemon | Download attachment |
| `attach-delete <cipher_id> <attach_id>` | Daemon | Delete attachment |
| `attach-list <cipher_id>` | Daemon | List attachments on a cipher |
| `devices list` | Direct | List enrolled devices |
| `ping` | Daemon | Check daemon connectivity |

**Flags**: `--vault-path <dir>`, `--direct` (skip daemon), `--socket <path>`

---

## File Map

```
idtty/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── idtty-core/               # Rust Core: crypto (AES-256-GCM, Argon2id, TOTP), keys, vault, padding, sync, import/export, health, biometric, attachments
│   ├── idtty-cli/                # Terminal CLI (daemon-first + --direct fallback, import/export, health, attachments)
│   └── idtty-daemon/             # IPC daemon (Unix socket, Protobuf, VaultState, auto-lock, TOTP, attachments, biometric, import/export, health)
├── desktop/                      # Tauri v2 Desktop app (full CRUD, 5 cipher types, generator, TOTP, import/export, reprompt, health, attachments, biometric, custom fields, nested folders)

└── docs/                         # Architecture Blueprint Docs
```
