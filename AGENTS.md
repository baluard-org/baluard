# PROJECT KNOWLEDGE BASE

**Updated:** 2026-06-03

## OVERVIEW
Project: **IDtty** (Git-native password manager)
Stack: Rust (core crypto + CLI + daemon), SolidJS/Tailwind/Tauri v2 (desktop), Protobuf (IPC schema)
License: GPL-3.0

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets.

**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell.

## STRUCTURE
```
idtty/
├── crates/
│   ├── idtty-core/             # Core library: crypto, keys, vault, sync
│   │   └── src/
│   │       ├── crypto/         # KDF (Argon2id), AEAD (AES-256-GCM), HKDF, HPKE, Ed25519, TOTP
│   │       ├── keys/           # Key hierarchy (Root/SGK/Item/Session), epochs, rotation
│   │       ├── vault/          # Vault handle, cipher CRUD, envelope, padding, attachments
│   │       ├── sync/           # Git sync engine (git2-rs), conflict resolution
│   │       ├── import/         # Import parsers (8 formats) + export (2 formats)
│   │       ├── device_manager.rs # Device fleet: registry, rotation, activity, enrollment
│   │       ├── types.rs        # CipherKind, CipherInput, CipherMeta, CustomFieldType, etc.
│   │       └── error.rs        # IdttyError enum
│   ├── idtty-cli/              # CLI (clap) — daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch
│   │       ├── client.rs       # Protobuf socket client
│   │       └── commands/       # Dual-mode handlers
│   └── idtty-daemon/           # Background IPC daemon
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM, 0600 perms
│           ├── handler.rs      # Protobuf routing, token-gated IPC
│           └── state.rs        # VaultState (Arc<RwLock>), auto-lock
├── desktop/                    # Tauri v2 + SolidJS frontend
│   └── src/
│       ├── App.jsx             # Main UI (2500+ lines)
│       └── i18n/locales/       # en.json, _template.json
├── proto/                      # Protobuf schemas (compiled via prost)
│   ├── vault.proto
│   ├── space.proto
│   └── auth.proto
├── docs/                       # Architecture & design docs
└── justfile                    # Build system
```

## COMMANDS
| Action | Command |
|--------|--------|
| Build (debug) | `just build` |
| Build (release) | `just build-release` |
| Run all tests | `just test` |
| Core tests only | `just test-core` |
| Full CI check | `just check` |
| Format | `just fmt` |
| Lint (clippy) | `just lint` |
| Format check | `just fmt-check` |
| Lint fix | `just lint-fix` |
| Install to ~/.local/bin | `just install-local` |
| Install to /usr/local/bin | `just install` |
| Desktop dev server | `just desktop-dev` |
| Desktop debug mode | `just desktop-debug` |
| Desktop production build | `just desktop-build` |
| Desktop npm deps | `just desktop-deps` |
| Clean | `just clean` |

## CODING STANDARDS
* **Rust**: Edition 2024, MSRV 1.85. Feature flags: `full` (default) = `git-sync` + `org` + `emergency`. `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind for layout. `crypto.getRandomValues` only (never `Math.random`).
* **Protobuf**: proto3, `idtty.vault` package. Compiled via prost in daemon + CLI.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket 0600. Zeroize on drop for key material and TOTP secrets.

## DEBUG LOGGING
`just desktop-debug` runs the desktop app with `IDTTY_DEBUG=1`. Logs go to `./logs/` at cwd.
* `daemon.log` -- IPC routing, vault CRUD, serde errors, crypto ops (via `env_logger`)
* `desktop.log` -- Tauri bridge: every daemon request with action, payload size, success/error (via `tauri-plugin-log`)

Env vars (set automatically by `just desktop-debug`):
* `IDTTY_DEBUG=1` -- enables Debug level (otherwise Warn only)
* `IDTTY_LOG_DIR=<path>` -- overrides log directory (defaults to `~/.config/idtty/`)

Share logs: paste the file contents or `zip logs/ logs.zip`.

## WHERE TO LOOK
* **Crypto primitives**: `crates/idtty-core/src/crypto/`
* **Key hierarchy & lifecycle**: `crates/idtty-core/src/keys/`
* **Vault CRUD & format**: `crates/idtty-core/src/vault/`
* **CipherKind & data structs**: `crates/idtty-core/src/types.rs`
* **Git sync**: `crates/idtty-core/src/sync/`
* **CLI commands**: `crates/idtty-cli/src/commands/mod.rs`
* **Daemon IPC**: `crates/idtty-daemon/src/handler.rs`
* **Daemon vault state**: `crates/idtty-daemon/src/state.rs`
* **Desktop frontend**: `desktop/src/App.jsx`
* **Device fleet**: `crates/idtty-core/src/device_manager.rs`
* **Protobuf schemas**: `proto/`
* **Design docs**: `docs/architecture-decisions.md` (authoritative)

## KEY CONCEPTS

### Key Hierarchy
Master Password -> KEK (Argon2id) -> Device Private Key (X25519, HPKE-escrowed) -> Root Key (512-bit, per-epoch) -> Space Group Key (256-bit) -> Item Keys (256-bit, HKDF-derived).

### CipherKind
Serde-tagged enum: `#[serde(tag = "type", content = "data")]`. 8 variants: Login, Card, Identity, SshKey, BankAccount, DriversLicense, Passport, SecureNote. Invalid states unrepresentable. Tagged JSON: `{type: "login", data: {...}}`.

### CipherMeta
`vault.list` returns `CipherMeta` with `id`, `name`, `cipher_type`, `favorite`, `username`. Desktop uses `vault.list_full` (batch endpoint: all decrypted ciphers + folders + trash + archived in 1 IPC call) instead of N+1 `vault.list` + N×`vault.get`.

### Daemon Wire Format
JSON strings inside `GatewayRequest.payload`. `get_cipher` returns BOTH nested `kind` object AND flat top-level fields. `update_cipher` parses `kind` from payload (does NOT clone existing kind). `vault.list_full` returns all decrypted ciphers + folders + trash + archived in a single IPC call (used by desktop for fast unlock).

### IPC
Unix domain sockets. 0600 via umask. Peer credential verification (SO_PEERCRED/getpeereid). `--socket` overrides default. Token-gated: 256-bit session token on unlock, constant-time comparison.

### Padded Buckets
5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()`. Prevents metadata leakage.

### Device Lifecycle
Epoch state machine: CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED. `revoke_device_and_rekey()` performs full rotation: validates preconditions, writes crash marker, re-encrypts all ciphers + attachments, writes keywrap, updates in-memory state. `rotate_root_key()` for non-revocation rotation. Recovery via BIP-39 phrase.

### CLI Dual-Mode
All vault commands route through daemon by default. `--direct` falls back to idtty-core in-process. `--socket <path>` accepts custom socket.

### Attachments
AES-256-GCM encrypted with cipher's item key. Max 2MB. Stored at `<vault>/entries/<cipher_id>/attachments/<id>.enc`. Plaintext zeroized after use.

## GOTCHAS
* **Password history**: Auto-appended on password change. Cap 10 entries (FIFO).
* **Folder depth**: Max 16 levels. `delete_folder` cascades via BFS descendant collection.
* **TOTP**: Seed NEVER crosses IPC. Only derived numeric code sent to frontend.
* **`RotationGuard`**: RAII guard cleans up `.tmp` files and crash marker on error. Disarmed after successful atomic commit.
* **CodeGraph available**: `.codegraph/` index exists. Route codebase exploration through CodeGraph tools when available.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.

## UX PRINCIPLES
* **Plain language**: No hard tech terms in user-facing UI. "Cipher" -> "entry", "UUID" -> hidden.
* **No server backend**: Desktop and mobile apps work standalone/offline. Git sync is optional.
* **i18n**: All user-facing strings in `desktop/src/i18n/locales/en.json`. Use `t("key")` in components.
