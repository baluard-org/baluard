# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-28

## OVERVIEW
Project: **IDtty** (Git-native password manager / Space Manager)
Stack: Rust (core crypto + CLI + daemon), SolidJS/Tailwind/Tauri v2 (desktop), Kotlin Multiplatform via UniFFI (mobile, planned), SolidJS (browser extension, planned), Protobuf (IPC schema, planned)
License: MIT

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets. Mobile apps will bind directly to the Rust core via UniFFI-generated Kotlin/Swift bindings.

**Supported platforms**: Windows, Linux (deb/rpm), macOS, Android, iOS. CLI: bash, zsh, PowerShell.

## STRUCTURE
```
idtty/
├── crates/                     # Rust workspace
│   ├── idtty-core/             # Core library: crypto, vault format, key lifecycle, git sync
│   │   └── src/
│   │       ├── crypto/         # KDF (Argon2id), AEAD (AES-256-GCM), HKDF, HPKE, Ed25519 signatures
│   │       ├── keys/           # Key hierarchy (Root/Item/Session), epochs, rotation, nonces
│   │       ├── vault/          # Vault handle, cipher CRUD, envelope format, creation ceremony, padding
│   │       ├── sync/           # Git sync engine (git2-rs), commit, conflict resolution, state machine
│   │       ├── devices.rs      # Device registry (enrollment, public keys)
│   │       ├── emergency.rs    # Emergency access / break-glass
│   │       ├── integrity.rs    # Canary checks (KEK/RK verification)
│   │       ├── orgs.rs         # Organization / team sharing
│   │       ├── providers.rs    # Credential provider abstraction
│   │       ├── recovery.rs     # BIP-39 recovery phrase
│   │       ├── types.rs        # Shared types (CipherInput, KdfProfile, etc.)
│   │       └── error.rs        # IdttyError enum
│   ├── idtty-cli/              # CLI binary (clap) - currently links idtty-core directly
│   │   └── src/
│   │       ├── main.rs         # Command dispatch (init/unlock/add/get/list/delete/sync/devices)
│   │       └── commands/       # Direct idtty-core calls (will become socket client)
│   └── idtty-daemon/           # Background IPC daemon (vault state + Protobuf gateway)
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM handling, 0600 perms
│           └── handler.rs      # JSON echo stub (Protobuf wiring pending)
├── desktop/                    # Tauri v2 desktop app [PLACEHOLDER]
│   └── package.json            # vite, solid-js, @tauri-apps/cli
├── mobile/                     # Kotlin Multiplatform mobile app [PLACEHOLDER]
│   └── build.gradle.kts        # KMP targets: Android, iOS (x64/arm64/sim)
├── extension/                  # MV3 browser extension (SolidJS thin client) [PLACEHOLDER]
│   └── package.json            # vite, solid-js
├── proto/                      # Shared Protobuf schemas (compiled into Rust via prost)
│   ├── vault.proto             # VaultEntry, CustomField
│   ├── space.proto
│   └── auth.proto
└── docs/                       # Architecture & design docs (authoritative)
    ├── 00-progress.md
    ├── 01-architecture-decisions.md
    ├── 02-threat-model.md
    ├── 03-key-lifecycle.md
    └── 04-software-architecture.md
```

## COMMANDS
| Action | Command |
|--------|---------|
| Build entire workspace | `cargo build` |
| Test core library | `cargo test -p idtty-core` |
| Test all crates | `cargo test` |
| Test (release) | `cargo test --release` |
| Run CLI command | `cargo run -p idtty-cli -- <command>` |
| Run daemon | `cargo run -p idtty-daemon` |
| Install desktop deps | `cd desktop && npm install` |
| Dev desktop | `cd desktop && npm run tauri dev` |
| Build extension | `cd extension && npm run build` |

## CODING STANDARDS
* **Rust**: Edition 2024, MSRV 1.85. Workspace deps in root `Cargo.toml`. Feature flags: `git-sync`, `org`, `emergency`. `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind utility classes for layout.
* **Kotlin**: KMP 1.9.20, Android compileSdk 34, iOS multi-target. Compose Multiplatform for shared UI.
* **Protobuf**: proto3 syntax, `idtty.vault` package. Compiled into Rust types via prost in idtty-daemon.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket permissions 0600 (umask before bind). Zeroize on drop for key material.

## WHERE TO LOOK
* **Rust crypto primitives**: `crates/idtty-core/src/crypto/`
* **Key hierarchy & lifecycle**: `crates/idtty-core/src/keys/`
* **Vault CRUD & format**: `crates/idtty-core/src/vault/`
* **Git sync engine**: `crates/idtty-core/src/sync/`
* **CLI commands**: `crates/idtty-cli/src/commands/mod.rs`
* **Daemon IPC handler**: `crates/idtty-daemon/src/handler.rs`
* **Design docs**: `docs/01-architecture-decisions.md` (authoritative for all decisions)
* **Protobuf schemas**: `proto/` (schemas only, no codegen yet)

## NOTES
* **Single Rust core**: All crypto, vault format, padding, key lifecycle, and git sync live in `idtty-core`. No duplicate implementations.
* **CLI currently links core directly**: `idtty-cli` calls `idtty-core` functions in-process. Each command prompts for master password. Phase 3 will convert CLI to a socket client that talks to the daemon, eliminating repeated password prompts.
* **Daemon holds vault state**: `idtty-daemon` runs a tokio Unix socket server with vault CRUD via Protobuf gateway. Supports open, unlock, lock, info, list, get, add, delete. Accepts `--vault-path` and `--socket` args. Locks vault (zeroizes keys) on SIGTERM.
* **Protobuf schemas compiled**: `proto/*.proto` define the IPC message formats. Rust codegen via prost-build in idtty-daemon's build.rs. Generated types: GatewayRequest, GatewayResponse, VaultEntry, AccessList, DeviceIdentityEscrow.
* **Mobile via UniFFI (planned)**: `idtty-core` will export its public API via `#[uniffi::export]` proc-macros. UniFFI will generate native Kotlin (Android) and Swift (iOS) bindings at build time. No cgo, no gomobile, no Go. Not yet annotated.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.
* **Padded buckets**: All vault entries are padded to uniform sizes (1KB/8KB/64KB/1MB) to prevent metadata leakage.
* **IPC via Unix sockets (target)**: Daemon will listen on `/tmp/idtty.sock` with 0600 perms. All UI layers will communicate through the Protobuf gateway. Socket is born with 0600 via umask (no TOCTOU race).
* **MOCK_BACKEND build flag (planned)**: Desktop and mobile UIs will support `MOCK_BACKEND=true` for frontend-only development.
* **Key hierarchy**: Master Password -> KEK (Argon2id) -> Device Private Key (escrowed) -> Space Group Key -> Item Keys.
* **BIP-39 recovery**: Vault creation generates a recovery phrase for key recovery.
* **CodeGraph available**: `.codegraph/` index exists for codebase navigation.

## IMPLEMENTATION STATUS
| Component | Status |
|-----------|--------|
| `idtty-core` crypto/keys/vault | Built, tested, security-reviewed (2 rounds) |
| `idtty-core` sync engine | Built, tested |
| `idtty-cli` (direct core) | Functional, links core in-process |
| `idtty-daemon` socket server | Protobuf wire, vault CRUD working |
| Protobuf codegen | Compiled via prost in daemon build.rs |
| UniFFI annotations | Not yet applied to idtty-core |
| Desktop Tauri app | Placeholder |
| Mobile KMP app | Placeholder |
| Browser extension | Placeholder |
