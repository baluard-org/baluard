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

**Phase**: Rust core built, tested, and security-reviewed (2 rounds). IPC daemon stub created. Repository migrated from Go to pure Rust + UniFFI.
**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/idtty-core` - Rust core engine: crypto, keys, vault, padding, git sync
- `/crates/idtty-cli` - Terminal CLI client (clap, links idtty-core directly; socket client is Phase 3 target)
- `/crates/idtty-daemon` - Background IPC daemon (tokio Unix socket server)
- `/desktop` - SolidJS/Tailwind Tauri v2 Webviews
- `/extension` - Browser UI thin client (MV3)
- `/mobile` - Kotlin Multiplatform (KMP) UI via UniFFI bindings

---

## Staged Implementation Progress

### Phase 0: Monorepo Scaffolding
| Module | Status | What's Planned / Implemented |
|--------|--------|------------------------------|
| `workspace` | Done | Rust workspace with idtty-core, idtty-cli, idtty-daemon crates. |
| `proto/schemas` | Done | Drafted `vault.proto`, `space.proto`, and `auth.proto` schemas. |
| `crates/idtty-core` | Done | Full crypto, keys, vault, padding, git sync engine. 3,673 lines. |
| `crates/idtty-cli` | Done | clap CLI with command dispatch. |
| `crates/idtty-daemon` | Stub | tokio Unix socket listener (0600 via umask), JSON echo handler. No vault state. Protobuf wiring pending. |

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
| `vault/creation` | Done | Vault creation ceremony. |

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
| `daemon/socket` | Stub | Unix socket listener (0600 via umask, SIGINT/SIGTERM handling), JSON echo handler.
| `daemon/handler` | Stub | JSON echo router. Needs Protobuf codegen (prost) and idtty-core wiring.
| `cli/commands` | Done | Command handlers calling idtty-core directly (init, unlock, add, get, list, delete, sync, devices). Socket client conversion is Phase 3. |

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
6 critical issues identified:
1. Plaintext device keys in memory -> Fixed: Zeroize on drop
2. Nonce reuse potential -> Fixed: Per-entry unique nonces
3. Missing AAD binding -> Fixed: Envelope AAD
4. Weak KDF parameters -> Fixed: OWASP-recommended Argon2id params
5. No key rotation -> Fixed: Epoch-based rotation
6. Timing side-channels -> Fixed: Constant-time comparisons

### Round 2 (peer review Review)
3 critical, 6 important, 4 minor issues identified. All criticals addressed:
- C1: JSON injection in sync metadata -> Fixed: Schema validation
- C2: Missing integrity checks on pull -> Fixed: Canary verification
- C3: Unbounded recursion in conflict resolution -> Fixed: Depth limits

---

## Known Limitations

1. **OS Keystore Binding**: OAuth PAT and digital identity private keys are locked in host OS keyring; CLI requires daemon connectivity to unlock.
2. **Metadata Leakage via Bucket Sizes**: Standard logins mapped to 1KB, notes to 8KB, attachments to 64KB/1MB. Provider can infer entry counts per class.
3. **JIT Sync Latency on Mobile**: JIT `git fetch` adds sub-second network latency before biometric prompt on slow connections.
4. **Offline Sharing Limitation**: Invites and revokes require committing wrapped keys to `metadata/access_list.json` and pushing to remote git hosts.

---

## File Map

```
idtty/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── idtty-core/               # Rust Core: crypto, keys, vault, padding, sync
│   ├── idtty-cli/                # Terminal CLI client (clap, links core directly)
│   └── idtty-daemon/             # Background IPC daemon (tokio socket server, stub)
├── desktop/                      # Tauri v2 Desktop app (placeholder)
├── extension/                    # Browser extension (placeholder)
├── mobile/                       # Kotlin Multiplatform (KMP) Mobile App (placeholder)
├── docs/                         # Architecture Blueprint Docs
└── docs/                         # Architecture Blueprint Docs
```
