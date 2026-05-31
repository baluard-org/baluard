# IDtty: Master Progress Document

> Single source of truth for project state. Update after every work session.
> Last updated: 2026-05-31

---

## Project Overview

**What**: Git-backed password manager. Encrypted vault stored as a git repo. No server.
**Stack**: Rust Core Engine (`idtty-core` crypto/keys/vault/sync + `idtty-daemon` IPC socket server + `idtty-cli` terminal client) + Tauri v2 Desktop (SolidJS/Tailwind) + Kotlin Multiplatform via UniFFI (Mobile) + SolidJS Browser Extension + Single-String Protobuf Gateway.
**Platforms**: Windows, Linux (deb/rpm), macOS, Android, iOS. CLI: bash, zsh, PowerShell.
**Terminology Translations (Consumer-Facing)**:
- Git Repository -> **Space**
- Git Clone/SSH/PAT -> **Sign in with GitHub** (OAuth background setup)
- Git Merge Conflict -> **"Two updates happened at once. Which do you keep?"**
- Asymmetric Keypair -> **Device Digital Identity**
**Architecture docs**: `docs/01-architecture-decisions.md` through `docs/04-software-architecture.md`.

---

## Current Status

**Phase**: Rust core built, tested, and security-reviewed (2 rounds). IPC daemon with full CRUD, TOTP, auto-lock. CLI dual-mode. Desktop app with 5 cipher types, generator, TOTP widget. 130 tests, 0 clippy errors.
**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/idtty-core` - Rust core engine: crypto, keys, vault, padding, git sync
- `/crates/idtty-cli` - Terminal CLI client (clap, daemon-first with `--direct` fallback)
- `/crates/idtty-daemon` - Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state)
- `/desktop` - SolidJS/Tailwind/Tauri v2 desktop app (full CRUD, 5 cipher types, generator, TOTP, auto-lock, dark/light themes)
- `/extension` - Browser UI thin client (MV3, placeholder)
- `/mobile` - Kotlin Multiplatform (KMP) UI via UniFFI bindings (placeholder)

---

## Staged Implementation Progress

### Phase 0: Monorepo Scaffolding
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `workspace` | Done | Rust workspace with idtty-core, idtty-cli, idtty-daemon crates. Go codebase removed. |
| `proto/schemas` | Done | `vault.proto`, `space.proto`, `auth.proto`. Go package refs removed. Compiled by prost-build in daemon and CLI. |
| `crates/idtty-core` | Done | Full crypto, keys, vault, padding, git sync engine. 3,850 lines. 66 tests pass. |
| `crates/idtty-cli` | Done | clap CLI with dual-mode: daemon-first (Protobuf over Unix socket) + `--direct` fallback (idtty-core). Commands: init, unlock, lock, add, get, list, delete, sync, devices, ping. |
| `crates/idtty-daemon` | Done | tokio socket + Protobuf gateway + VaultState (Arc<RwLock<Option<VaultHandle>>>). Routes: ping, vault.open/unlock/lock/info/list/get/add/delete, vault.trash.list/restore/purge. CLI args: --vault-path, --socket. |

### Phase 1: Cryptographic Core & Padding Engine (Rust)
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `crypto/aead` | Done | AES-256-GCM with strict AAD binding. |
| `vault/handle` | Done | Vault CRUD operations. |
| `vault/creation` | Done | Vault creation ceremony. Vault .gitignore excludes device-privkey.json. |

### Phase 2: Git Sync Engine (Rust)
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `sync/engine` | Done | git2-rs sync engine: init_repo, commit, push, pull, fetch. |
| `sync/conflict` | Done | Conflict auto-healing (index rebuild, entry rename). |
| `sync/state_machine` | Done | Sync state machine for tracking sync progress. |
| `sync/commit` | Done | Commit builder with padding-aware serialization. |

### Phase 3: IPC Daemon & CLI Gateway
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
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
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `desktop` | Done | SolidJS/Tailwind v4 webview in Tauri v2. Login screen + vault view (cipher list, add, get, delete). Dark theme. Scaffolded via `tauri init`. |
| `desktop/tauri` | Done | Rust backend (edition 2024): daemon_request Tauri command proxies to idtty-daemon via Protobuf. System tray with Show/Quit. All platform icons via `tauri icon`. Sidecar config in tauri.conf.json. |
| `desktop/tray` | Done | Tauri v2 TrayIconBuilder with Show/Quit menu. Left-click shows window. Close hides to tray. |
| `desktop/daemon` | Done | Tauri spawns idtty-daemon on launch. SIGTERM + wait on app exit. |
| `desktop/create` | Done | Vault creation UI: CreateVaultScreen (password + confirm), RecoveryScreen (BIP-39 phrase display). Auto-unlock after creation. |
| `cli/binary` | Done | CLI binary renamed to `idtty` (was `idtty-cli`). Package name unchanged for compat. |
| `daemon/vault.create` | Done | New daemon route: runs creation ceremony, writes all vault files with 0600 perms, opens vault, returns recovery phrase. |
| `ci-cd` | Done | GitHub Actions: test.yml (cargo test/fmt/clippy), build-desktop.yml (tauri-action matrix). Both workflow_dispatch only. |
| `docs` | Done | README.md (build/platform/webview instructions), CONTRIBUTING.md (guidelines + code standards). |

### Phase 5: Mobile & Extension
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `uniffi-bindings` | Planned | Annotate idtty-core public API with `#[uniffi::export]`. Generate Kotlin/Swift. |
| `mobile/kmp` | Planned | Compose Multiplatform shared UI with UniFFI-generated bindings. |
| `mobile/jit` | Planned | Autofill hook with JIT `git fetch` checking remote SHA delta before biometric prompts. |
| `extension` | Planned | Browser extension popup (SolidJS) and native messaging hook. |

---

## Security Review History

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
15 findings (3 security, 7 correctness, 5 minor). 10 fixed, 3 deferred, 2 partial:
- **S1**: CSP was `null` (XSS reads master password from DOM) -> Fixed: Strict CSP with `ipc:` + `http://ipc.localhost` for Tauri v2
- **S2**: `Daemon::drop` used `kill()` (SIGKILL, no cleanup) -> Fixed: `libc::kill(SIGTERM)` + 3s grace + SIGKILL fallback
- **S3**: Unbounded `read_to_end` (memory exhaustion) -> Fixed: `Read::take(5MB)` + size check
- **CO1**: `std::os::unix` import breaks Windows compile -> Fixed: `#[cfg(unix)]` gates + stubs
- **CO2**: Daemon binary not bundle-relative (fails packaged) -> **Fixed**: Uses tauri-plugin-shell sidecar API (`app.shell().sidecar("idtty-daemon")`). Shell plugin registered in builder. Sidecar permission in capabilities.
- **CO3**: No socket readiness poll after spawn -> Fixed: 20x100ms ping-based readiness check
- **CO4**: No I/O timeout (UI freeze if daemon stalls) -> Fixed: 30s read, 5s write timeouts
- **CO5**: Panic on short device key strings (hard `[]` index) -> Fixed: `.get()` with `unwrap_or` fallback
- **CO6**: Draft releases created on every PR -> Fixed: Removed PR trigger, now `workflow_dispatch` only
- **CO7**: No vault creation flow in desktop -> Fixed: Vault creation UI + daemon vault.create route
- **M1**: `daemon_status()` phantom connect -> Fixed: Ping-based liveness check
- **M2**: Daemon inherits stdout/stderr -> Fixed: `Stdio::null()`
- **M3**: Unused `bytes` crate -> Fixed: Removed
- **M4**: Module-scope SolidJS signals -> **Fixed**: All signals moved into `AppProvider` context (`createContext`/`useContext`). Actions in `useActions()` hook. No module-level mutable state.
- **M5**: Raw daemon errors surfaced to UI -> **Fixed**: `sanitizeError()` maps 8 known patterns to user-friendly messages. Unknown errors fully redacted (no partial leakage).

### Round 5 (Follow-Up Review)
3 new findings (2 correctness, 1 style). All fixed:
- **CO-NEW-1**: Startup probe used phantom connect instead of ping -> Fixed
- **CO-NEW-2**: Readiness poll used phantom connect instead of ping -> Fixed
- **M-NEW-1**: `daemon_status` verbose match instead of `.is_ok()` -> Fixed

### Round 7 (Pass Analysis — Independent Peer Review)

**Source**: Full analysis of `pass` (password-store v1.7.4) by zx2c4. Peer review of findings via independent code review. Reviewer read IDtty source (`vault/envelope.rs`, `vault/cipher.rs`, `crypto/aead.rs`, `keys/hierarchy.rs`) before responding.

**Pass CVEs studied**: CVE-2018-12356 (GPG regex parsing), CVE-2020-28086 (filename swap attack), plus rot256.dev security critique on active-adversary weaknesses.

#### Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| R7-1 | **Critical** | AAD verification gap in `decrypt_cipher`. AAD binds `cipher_id` into the GCM tag at encrypt time, but `decrypt_cipher` never re-computes expected AAD from caller params and compares it to stored AAD before decryption. A file-swap/renamed entry attack succeeds: GCM auth tag validates against the original AAD, caller receives wrong plaintext. | **Fixed** |
| R7-2 | **High** | Daemon socket is a full-vault oracle for any same-UID process. After unlock, any process owned by the same user can connect to the Unix socket and call `GetCipher` with arbitrary IDs to extract all secrets without knowing the master password. Peer credential check only blocks other UIDs. | **Fixed** |
| R7-3 | **Medium** | Key buffers not `mlock`ed. OOM kill, `kill -9`, or panic bypasses `zeroize` on drop. Key material may persist in RAM pages until overwritten, or page to swap/hibernation. `mlock`/`mlockall` prevents kernel paging. | **Fixed** |
| R7-4 | **Low** | `docs/02-threat-model.md` does not explicitly model the git remote as adversarially writable. Pass's author admitted "focus on secrecy without authenticity." IDtty defends against this but the threat model doesn't state it. | **Fixed** |

#### Rejected Proposals (with rationale)

| Proposal | From | Ruling | Rationale |
|----------|------|--------|----------|
| Add Ed25519 signatures on every envelope | TARS (pass analysis) | **Rejected** by peer review | AES-256-GCM auth tag IS the signature. The AAD gap (R7-1) is the real bug, not missing signatures. Only add signatures if non-repudiation for org audit trails is needed later. |
| Blinded search index | TARS (pass analysis) | **Rejected** by peer review | Decrypt-on-search is acceptable for a local manager. Blinded indexes (Bloom over HMAC n-grams) add complexity with only exact-match capability. Document the tradeoff instead. |
| Hash entry path as identity | TARS (pass analysis) | **Rejected** by peer review | Paths are mutable (rename forces re-encrypt). Random UUID at creation is already correct and already implemented. |

#### Pass Design Patterns Worth Preserving

1. **Git log as audit trail**: Pass's commit history is an implicit tamper-evident log. IDtty has this. Surface it explicitly in UI.
2. **Aggressive clipboard timeout**: Pass defaults 45s. IDtty's 15s default is correct. Never restore previous clipboard content.
3. **Explicit threat scope**: Pass documents what it doesn't defend against. IDtty should state "git remote is adversarially writable" in threat model.

#### Action Items

- [x] **R7-1**: Add AAD verification to `decrypt_cipher` in `crates/idtty-core/src/vault/cipher.rs`. Before `aead::decrypt`, recompute expected AAD from `(vault_id, ObjectType::Cipher, cipher_id, tier, alg_id, key_epoch, update_seq)` and assert equality with `enc_envelope.aad`. Return `VaultError::Corrupt("cipher identity mismatch")` on mismatch. Fail fast, no decryption oracle. **Done.** Added swap attack test. **Peer review: PASS.**
- [x] **R7-2**: Add per-request session authorization token. Daemon generates 256-bit random token on unlock, returns it in `GatewayResponse.session_token`. CLI stores in thread-local, sends with every request via `GatewayRequest.session_token`. Daemon verifies with constant-time comparison. Token cleared on lock. Proto updated. **Done.** **Peer review: 2 bugs found and fixed:** (1) `vault.info` removed from `TOKEN_REQUIRED_ACTIONS` (tokenless: reveals no secrets, used as pre-flight by CLI). (2) `vault.create` now returns token via proto field, not just JSON payload.
- [x] **R7-3**: Add `mlock` on key material buffers in `keys/hierarchy.rs` (RootKey, ItemKey). Use `libc::mlock` on creation, `munlock` on drop. Best-effort (silent on failure). Prevents key material from paging to swap. **Done.** **Peer review: 2 gaps found and fixed:** (1) `derive(Clone)` replaced with manual `Clone` impl that calls `from_bytes` (which mlocks the new copy). (2) Stack-allocated arrays replaced with `Box<[u8; N]>` for stable heap addresses across moves. Custom `Debug` impl redacts key bytes.
- [x] **R7-4**: Update `docs/02-threat-model.md` to explicitly model the git remote as adversarially writable. Added T5 (Active Git Remote Adversary) and T6 (Key Material Paged to Swap). Updated adversary table with classes C, E, G. **Done.** **Peer review: PASS.**

---

### Round 6 (Independent Review — Vault Creation)
10 findings (1 critical, 2 security, 5 correctness, 2 minor). All fixed except CO5:
- **C1**: Vault files written with 0644 permissions -> Fixed: `write_secret` helper sets 0600 on all sensitive files
- **S1**: Master password not zeroized after ceremony -> Fixed: `Zeroizing<String>` wrapper
- **S2**: `shell:allow-spawn/execute` exposed to webview -> Fixed: Removed from capabilities
- **CO1**: Auto-unlock after vault creation silently failed (getElementById on unmounted DOM) -> Fixed: Uses `createPassword` signal
- **CO2**: Key files written with default perms -> Fixed: write_secret with 0600
- **CO3**: No guard against overwriting existing vault -> Fixed: Checks kdf-params.json
- **CO4**: `unwrap()` on serialization could panic async task -> Fixed: All `map_err`
- **CO5**: Sidecar declared in config but Rust code still uses PATH spawn -> **Fixed**: Sidecar spawn via `tauri_plugin_shell::ShellExt`. `Daemon` wraps `CommandChild`. Removed `libc` dep from desktop.
- **M1**: README code fence broken -> Fixed: Single fenced block
- **M2**: `getElementById` anti-pattern in SolidJS -> Fixed: Refs + signals

### Round 8 (UI/UX Revamp — 1Password/Bitwarden Structure)
Complete overhaul of the desktop interface to deliver a production-grade 3-column user experience:
- **Layout Alignment**: Implemented the Bitwarden/1Password 3-column interface (`w-[260px]` Navigation Sidebar, `w-[360px]` Searchable Vault List, and Flex-1 Details & Form Panel).
- **Refinement of Visuals**: Styled with the custom forest teal and soft lavender reference palette. Added responsive UI micro-animations and smooth transition transitions.
- **Dynamic Themes**: Built dark and light modes, controlled by a SolidJS signal synced to a `.light-theme` body class. Accessible via theme switcher icons on lock screens, vault views, and create screens.
- **List Monograms & Hover shortcuts**: Generates beautiful monogram badges based on hostnames. Added hover quick-actions (URL Launch, Copy Password) directly on rows.
- **Interactive Details & Password Generator**: Integrated a comprehensive details viewer with copy/eye reveal controls and an interactive password generator (with length slider and custom complexity pools) built directly into form flows.
- **Parallel Loading Optimization**: Loaded decrypted cipher metadata asynchronously in parallel during unlock, ensuring instant search and zero detail latency.

### Round 9 (Device Lifecycle Bug Fixes)
4 bugs from peer review of Candidate 3 (DeviceManager). All fixed:

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| BUG-1 | P0 | `collected_acks` no dedup by `device_id` — single device reaches quorum with N acks | Reject duplicate acks. Use `epoch.acknowledged_devices.len()` for quorum (canonical deduped tracker) |
| BUG-2 | P1 | `seen_nonces` not persisted across restarts | Persist to `meta/seen-nonces.json`. FIFO eviction at 10,000 entries |
| BUG-3 | P1 | `_commit_barrier` computed then dropped — audit trail hollow | Populate `tx.commit_barrier` before commit. Write `.committed` file |
| BUG-4 | P1 | Dual ack-tracking structures (`epoch.acknowledged_devices` vs `collected_acks`) diverge | `epoch.acknowledged_devices` is canonical. `collected_acks` is signed payloads only |

Also added:
- `EnrollmentPayload::encode_transfer()` / `decode_transfer()` — base64url JSON for QR or manual copy
- `PairingBundle` struct — formalized pairing response with transfer encoding
- Enrollment transfer methods documented as first-class (QR, manual copy, file export) — not fallbacks
- 4 new tests: duplicate ack rejection (2), nonce persistence, FIFO eviction
- 87 tests passing, 0 clippy errors

---

### Bitwarden Desktop Parity (Phases 1-8)

All 8 phases complete, peer-reviewed, and merged. **130 tests, 0 clippy errors.**

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

---

## Known Limitations

1. **OS Keystore Binding**: OAuth PAT and digital identity private keys are locked in host OS keyring; CLI requires daemon connectivity to unlock.
2. **Metadata Leakage via Bucket Sizes**: Standard logins mapped to 1KB, notes to 8KB, attachments to 64KB/1MB. Provider can infer entry counts per class.
3. **JIT Sync Latency on Mobile**: JIT `git fetch` adds sub-second network latency before biometric prompt on slow connections.
4. **Offline Sharing Limitation**: Invites and revokes require committing wrapped keys to `metadata/access_list.json` and pushing to remote git hosts.
5. **Sync routed through daemon**: sync.init/remote/push/pull/status/log all route through daemon by default with --direct fallback.

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
| `folders {create\|list\|rename\|delete}` | Daemon/Direct | Folder management |
| `sync {init\|remote\|push\|pull\|...}` | Daemon/Direct | Git sync operations |
| `devices list` | Direct | List enrolled devices |
| `ping` | Daemon | Check daemon connectivity |

**Flags**: `--vault-path <dir>`, `--direct` (skip daemon), `--socket <path>`

---

## File Map

```
idtty/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── idtty-core/               # Rust Core: crypto (AES-256-GCM, Argon2id, TOTP), keys, vault, padding, sync
│   ├── idtty-cli/                # Terminal CLI (daemon-first + --direct fallback)
│   └── idtty-daemon/             # IPC daemon (Unix socket, Protobuf, VaultState, auto-lock, TOTP)
├── desktop/                      # Tauri v2 Desktop app (full CRUD, 5 cipher types, generator, TOTP)
├── extension/                    # Browser extension (placeholder)
├── mobile/                       # Kotlin Multiplatform (KMP) Mobile App (placeholder)
└── docs/                         # Architecture Blueprint Docs
```
