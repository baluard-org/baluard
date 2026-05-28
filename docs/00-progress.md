# IDtty: Master Progress Document

> Single source of truth for project state. Update after every work session.
> Last updated: 2026-05-28

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

**Phase**: Rust core built, tested, and security-reviewed (2 rounds). IPC daemon with full CRUD wired. CLI dual-mode (daemon-first + direct fallback). Go codebase removed. Pure Rust + UniFFI architecture.
**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/idtty-core` - Rust core engine: crypto, keys, vault, padding, git sync
- `/crates/idtty-cli` - Terminal CLI client (clap, daemon-first with `--direct` fallback)
- `/crates/idtty-daemon` - Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state)
- `/desktop` - SolidJS/Tailwind Tauri v2 Webviews (placeholder)
- `/extension` - Browser UI thin client (MV3, placeholder)
- `/mobile` - Kotlin Multiplatform (KMP) UI via UniFFI bindings (placeholder)

---

## Staged Implementation Progress

### Phase 0: Monorepo Scaffolding
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `workspace` | Done | Rust workspace with idtty-core, idtty-cli, idtty-daemon crates. Go codebase removed. |
| `proto/schemas` | Done | `vault.proto`, `space.proto`, `auth.proto`. Go package refs removed. Compiled by prost-build in daemon and CLI. |
| `crates/idtty-core` | Done | Full crypto, keys, vault, padding, git sync engine. 3,673 lines. 64 tests pass. |
| `crates/idtty-cli` | Done | clap CLI with dual-mode: daemon-first (Protobuf over Unix socket) + `--direct` fallback (idtty-core). Commands: init, unlock, lock, add, get, list, delete, sync, devices, ping. |
| `crates/idtty-daemon` | Done | tokio socket + Protobuf gateway + VaultState (Arc<RwLock<Option<VaultHandle>>>). Routes: ping, vault.open/unlock/lock/info/list/get/add/delete. CLI args: --vault-path, --socket. |

### Phase 1: Cryptographic Core & Padding Engine (Rust)
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `crypto/aead` | Done | AES-256-GCM with strict AAD binding. |
| `crypto/kdf` | Done | Argon2id password stretching. |
| `crypto/hkdf` | Done | HKDF-SHA256 key derivation. |
| `crypto/hpke` | Done | HPKE key wrapping (X25519). |
| `crypto/signature` | Done | Ed25519 commit signatures. |
| `keys/*` | Done | Full key hierarchy: epochs, rotation, nonces, hierarchy tree. |
| `vault/padding` | Done | 1KB, 8KB, 64KB, 1MB secure random padding buckets. |
| `vault/envelope` | Done | Envelope format for encrypted entries. |
| `vault/manifest` | Done | Encrypted lookup index (index.enc equivalent). |
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
| `cli/sync` | Done | Direct-only (not yet routed through daemon). Feature-gated behind `git-sync`. |
| `cli/devices` | Done | Direct-only (not yet routed through daemon). |

### Phase 4: Desktop UI & Open-Source Launch
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `desktop` | Planned | SolidJS/Tailwind desktop views inside Tauri v2. |
| `desktop/tray` | Planned | Tauri v2 tray hooks and Rust lifecycle wrappers to prevent close and keep daemon alive. |
| `ci-cd` | Planned | GitHub Actions matrix for multi-platform compilation. |

### Phase 5: Mobile & Extension
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `uniffi-bindings` | Planned | Annotate idtty-core public API with `#[uniffi::export]`. Generate Kotlin/Swift. |
| `mobile/kmp` | Planned | Compose Multiplatform shared UI with UniFFI-generated bindings. |
| `mobile/jit` | Planned | Autofill hook with JIT `git fetch` checking remote SHA delta before biometric prompts. |
| `extension` | Planned | Browser extension popup (SolidJS) and native messaging hook. |

---

## Security Review History

### Round 1 (peer review Review)
6 findings across critical/important/minor categories:
1. Socket TOCTOU -> Fixed: umask(0177) before bind()
2. Missing SIGTERM handler -> Fixed: tokio::signal::unix with graceful vault lock
3. JSON injection in sync metadata -> Fixed: Schema validation, quote/backslash escaping
4. Doc inaccuracies -> Fixed: Current vs planned state clearly separated
5. Ghost paths in docs -> Fixed: Removed references to unbuilt directories
6. Duplicate tokio dep -> Fixed: Consolidated workspace dep

### Round 2 (peer review Review)
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

### Round 3 (peer review Review)
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

---

## Known Limitations

1. **OS Keystore Binding**: OAuth PAT and digital identity private keys are locked in host OS keyring; CLI requires daemon connectivity to unlock.
2. **Metadata Leakage via Bucket Sizes**: Standard logins mapped to 1KB, notes to 8KB, attachments to 64KB/1MB. Provider can infer entry counts per class.
3. **JIT Sync Latency on Mobile**: JIT `git fetch` adds sub-second network latency before biometric prompt on slow connections.
4. **Offline Sharing Limitation**: Invites and revokes require committing wrapped keys to `metadata/access_list.json` and pushing to remote git hosts.
5. **Sync not routed through daemon**: sync.init/push/pull/status/log remain direct-only. Daemon returns error for these actions.

---

## CLI Command Reference

| Command | Mode | Description |
|---------|------|-------------|
| `init --profile <p>` | Direct | Create new vault with master password |
| `unlock` | Daemon/Direct | Unlock vault (daemon persists state) |
| `lock` | Daemon | Lock vault, zeroize keys |
| `add --name N ...` | Daemon/Direct | Add cipher (auto-prompts unlock) |
| `get <id> --decrypt` | Daemon/Direct | Get cipher by UUID |
| `list` | Daemon/Direct | List all cipher UUIDs |
| `delete <id>` | Daemon/Direct | Delete cipher by UUID |
| `sync {init\|push\|pull\|...}` | Direct | Git sync operations |
| `devices list` | Direct | List enrolled devices |
| `ping` | Daemon | Check daemon connectivity |

**Flags**: `--vault-path <dir>`, `--direct` (skip daemon), `--socket <path>`

---

## File Map

```
idtty/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── idtty-core/               # Rust Core: crypto, keys, vault, padding, sync
│   ├── idtty-cli/                # Terminal CLI (daemon-first + --direct fallback)
│   └── idtty-daemon/             # IPC daemon (Unix socket, Protobuf, VaultState)
├── desktop/                      # Tauri v2 Desktop app (placeholder)
├── extension/                    # Browser extension (placeholder)
├── mobile/                       # Kotlin Multiplatform (KMP) Mobile App (placeholder)
└── docs/                         # Architecture Blueprint Docs
```
