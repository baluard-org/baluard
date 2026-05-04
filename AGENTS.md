# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-28

## OVERVIEW
Project: **IDtty** (Git-native password manager / Space Manager)
Stack: Rust (core crypto + daemon + CLI), SolidJS/Tailwind/Tauri v2 (desktop), Kotlin Multiplatform via UniFFI (mobile), SolidJS (browser extension), Protobuf (IPC schema)
License: MIT

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets. Mobile apps bind directly to the Rust core via UniFFI-generated Kotlin/Swift bindings.

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
│   ├── idtty-cli/              # CLI binary (clap) - socket client, no crypto logic
│   │   └── src/
│   │       ├── main.rs         # Command dispatch (init/unlock/add/get/list/delete/sync/devices)
│   │       └── commands/       # Command handler implementations
│   └── idtty-daemon/           # Background IPC daemon (tokio Unix socket server)
│       └── src/
│           ├── main.rs         # Socket listener, signal handling, graceful shutdown
│           └── handler.rs      # Protobuf gateway: deserializes request, routes to idtty-core
├── desktop/                    # Tauri v2 desktop app (SolidJS + Tailwind webview)
│   ├── package.json            # vite, solid-js, @tauri-apps/cli
│   ├── src/                    # SolidJS frontend
│   └── src-tauri/              # Rust native: system tray, spawns daemon on boot
├── mobile/                     # Kotlin Multiplatform mobile app (UniFFI bindings)
│   ├── build.gradle.kts        # KMP targets: Android, iOS (x64/arm64/sim)
│   ├── sharedLogic/            # UniFFI-generated Kotlin + biometric expect/actual gates
│   └── sharedUI/               # Compose Multiplatform UI (shared Android/iOS)
├── extension/                  # MV3 browser extension (SolidJS thin client)
│   └── package.json            # vite, solid-js
├── proto/                      # Shared Protobuf schemas
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
| Generate UniFFI Kotlin bindings | `cargo run -p idtty-core --features uniffi -- uniffi-bindgen generate --library --language kotlin` |
| Generate UniFFI Swift bindings | `cargo run -p idtty-core --features uniffi -- uniffi-bindgen generate --library --language swift` |

## CODING STANDARDS
* **Rust**: Edition 2024, MSRV 1.85. Workspace deps in root `Cargo.toml`. Feature flags: `git-sync`, `org`, `emergency`. `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind utility classes for layout.
* **Kotlin**: KMP 1.9.20, Android compileSdk 34, iOS multi-target. Compose Multiplatform for shared UI.
* **Protobuf**: proto3 syntax, `idtty.vault` package.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket permissions 0600. Zero-copy avoided at FFI boundary (UniFFI serialization).

## WHERE TO LOOK
* **Rust crypto primitives**: `crates/idtty-core/src/crypto/`
* **Key hierarchy & lifecycle**: `crates/idtty-core/src/keys/`
* **Vault CRUD & format**: `crates/idtty-core/src/vault/`
* **Git sync engine**: `crates/idtty-core/src/sync/`
* **CLI commands**: `crates/idtty-cli/src/commands/mod.rs`
* **Daemon IPC handler**: `crates/idtty-daemon/src/handler.rs`
* **Design docs**: `docs/01-architecture-decisions.md` (authoritative for all decisions)
* **Protobuf schemas**: `proto/`
* **UniFFI bindings**: Generated at build time from `idtty-core` proc-macros

## NOTES
* **Single Rust core**: All crypto, vault format, padding, key lifecycle, and git sync live in `idtty-core`. No duplicate implementations.
* **Daemon architecture**: `idtty-daemon` is a tokio-based Unix socket server (or Windows Named Pipes). Started by Tauri on boot. Holds unlocked vault in `zeroize`-protected memory. CLI and browser extension talk to it over the socket.
* **Mobile via UniFFI**: `idtty-core` exports its public API via `#[uniffi::export]` proc-macros. UniFFI generates native Kotlin (Android) and Swift (iOS) bindings at build time. No cgo, no gomobile, no Go.
* **Feature flags control sync**: `git-sync` feature gate; CLI and daemon enable it by default.
* **Padded buckets**: All vault entries are padded to uniform sizes (1KB/8KB/64KB/1MB) to prevent metadata leakage.
* **IPC via Unix sockets**: Daemon listens on `/tmp/idtty.sock` with 0600 perms. All UI layers communicate through the Protobuf gateway.
* **MOCK_BACKEND build flag**: Desktop and mobile UIs support `MOCK_BACKEND=true` for frontend-only development.
* **Key hierarchy**: Master Password -> KEK (Argon2id) -> Device Private Key (escrowed) -> Space Group Key -> Item Keys.
* **BIP-39 recovery**: Vault creation generates a recovery phrase for key recovery.
* **CodeGraph available**: `.codegraph/` index exists for codebase navigation.
