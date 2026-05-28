# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-28

## OVERVIEW
Project: **IDtty** (Git-native password manager / Space Manager)
Stack: Rust (core crypto + CLI + daemon), SolidJS/Tailwind/Tauri v2 (desktop, scaffolded), Kotlin Multiplatform via UniFFI (mobile, planned), SolidJS (browser extension, planned), Protobuf (IPC schema, wired)
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
│   ├── idtty-cli/              # CLI binary (clap) - daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch, --direct/--socket flags
│   │       ├── client.rs       # Protobuf socket client (request_to)
│   │       └── commands/       # Dual-mode handlers (daemon + direct)
│   └── idtty-daemon/           # Background IPC daemon (vault state + Protobuf gateway)
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM, 0600 perms
│           ├── handler.rs      # Protobuf routing, password zeroize, varint framing
│           └── state.rs        # VaultState (Arc<RwLock<Option<VaultHandle>>>)
├── desktop/                    # Tauri v2 desktop app (scaffolded: daemon proxy, tray, SolidJS webview)
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
* **CLI commands**: `crates/idtty-cli/src/commands/mod.rs` (dual-mode: daemon + direct)
* **CLI socket client**: `crates/idtty-cli/src/client.rs`
* **Daemon IPC handler**: `crates/idtty-daemon/src/handler.rs`
* **Daemon vault state**: `crates/idtty-daemon/src/state.rs`
* **Design docs**: `docs/01-architecture-decisions.md` (authoritative for all decisions)
* **Protobuf schemas**: `proto/` (compiled by prost-build in daemon + CLI)

## NOTES
* **Single Rust core**: All crypto, vault format, padding, key lifecycle, and git sync live in `idtty-core`. No duplicate implementations.
* **CLI dual-mode (daemon-first)**: All vault commands (unlock, lock, add, get, list, delete) route through the daemon via Protobuf over Unix socket by default. `--direct` flag falls back to idtty-core in-process. `--socket <path>` accepts custom daemon socket. `ensure_unlocked_daemon()` auto-prompts master password if vault is locked.
* **Daemon holds vault state**: `idtty-daemon` runs a tokio Unix socket server with vault CRUD and sync via Protobuf gateway. Vault actions: open, unlock, lock, info, list, get, add, delete. Sync actions: init, remote, push, pull, status, log. Accepts `--vault-path` and `--socket` args. Locks vault (zeroizes keys) on SIGTERM. All passwords zeroized via `zeroize` crate.
* **Protobuf schemas compiled**: `proto/*.proto` define the IPC message formats. Rust codegen via prost-build in idtty-daemon's build.rs. Generated types: GatewayRequest, GatewayResponse, VaultEntry, AccessList, DeviceIdentityEscrow.
* **Mobile via UniFFI (planned)**: `idtty-core` will export its public API via `#[uniffi::export]` proc-macros. UniFFI will generate native Kotlin (Android) and Swift (iOS) bindings at build time. No cgo, no gomobile, no Go. Not yet annotated.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.
* **Padded buckets**: All vault entries are padded to uniform sizes (1KB/8KB/64KB/1MB) to prevent metadata leakage.
* **IPC via Unix sockets**: Daemon listens on platform-aware socket path (Linux: `$XDG_RUNTIME_DIR/idtty.sock`, macOS: `~/Library/Application Support/idtty/idtty.sock`, fallback: `/tmp/idtty.sock`). Socket born with 0600 via umask. Peer credential verification (SO_PEERCRED on Linux, getpeereid on macOS) rejects connections from other UIDs. `--socket` overrides default.
* **MOCK_BACKEND build flag (planned)**: Desktop and mobile UIs will support `MOCK_BACKEND=true` for frontend-only development.
* **Key hierarchy**: Master Password -> KEK (Argon2id) -> Device Private Key (escrowed) -> Space Group Key -> Item Keys.
* **BIP-39 recovery**: Vault creation generates a recovery phrase for key recovery.
* **CodeGraph available**: `.codegraph/` index exists for codebase navigation.

## IMPLEMENTATION STATUS
| Component | Status |
|-----------|--------|
| `idtty-core` crypto/keys/vault | Built, tested, security-reviewed (2 rounds) |
| `idtty-core` sync engine | Built, tested |
| `idtty-cli` (dual-mode) | Daemon-first + `--direct` fallback. All CRUD working. |
| `idtty-daemon` socket server | Protobuf wire, VaultState, full CRUD. SIGTERM safe. |
| Protobuf codegen | Compiled via prost in daemon + CLI build.rs |
| UniFFI annotations | Not yet applied to idtty-core |
| Desktop Tauri app | Placeholder |
| Mobile KMP app | Placeholder |
| Browser extension | Placeholder |
