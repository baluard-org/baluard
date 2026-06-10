# Dev Setup & Workflow

Everything you need to build, test, and develop Baluard locally.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.85+ (edition 2024) | [rustup.rs](https://rustup.rs) |
| just | latest | `cargo install just` |
| protoc | 3.x | `brew install protobuf` (macOS/Linux) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| npm | 9+ | bundled with Node |

### macOS

```bash
brew install protobuf
```

No other extras needed. macOS uses system WebKit (WKWebView) and system libgit2/openssl are resolved via Homebrew automatically.

### Linux (Debian/Ubuntu) extras

Desktop app requires WebKitGTK dev headers:

```bash
sudo apt install libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev libgtk-3-dev libssl-dev pkg-config
```

### Linuxbrew (libgit2/openssl)

If building on a system where libgit2/openssl aren't in system paths (e.g. codespaces, some CI), the justfile auto-detects linuxbrew and sets `PKG_CONFIG_PATH`/`LD_LIBRARY_PATH`. No manual setup needed.

If you prefer to set it yourself:

```bash
export PKG_CONFIG_PATH="/home/linuxbrew/.linuxbrew/Cellar/libgit2/1.9.3/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/home/linuxbrew/.linuxbrew/Cellar/libgit2/1.9.3/lib:/home/linuxbrew/.linuxbrew/opt/zlib-ng-compat/lib:/home/linuxbrew/.linuxbrew/Cellar/openssl@3/3.6.2/lib:$LD_LIBRARY_PATH"
```

## Quick Start

```bash
git clone https://github.com/EstebanForge/Baluard.git
cd Baluard

# Build everything
just build

# Run tests
just test

# Full CI check (fmt + clippy + test + build)
just check

# Seed a demo vault (31 entries, password: demo)
just seed-demo

# See all available commands
just
```

## Build Commands

All commands run from the project root. `just` reads the `justfile`.

| Target | What it does |
|--------|-------------|
| `just build` | Debug build of all Rust crates |
| `just build-release` | Optimized release build |
| `just build-signed` | Release build + codesign (macOS only; no-op on Linux) |
| `just test` | Run all tests (Rust suites + desktop vitest) |
| `just test-core` | Run `baluard-core` tests only |
| `just test-release` | Tests in release mode |
| `just test-verbose` | Tests with `--nocapture` (see println output) |
| `just e2e` | Full smoke test: init -> daemon -> unlock -> add -> get -> delete -> lock |
| `just check` | CI parity: `fmt-check` + `clippy` + `test` + `build` |
| `just fmt` | Format all Rust code |
| `just fmt-check` | Check formatting without modifying files |
| `just lint` | Run clippy with `-D warnings` |
| `just lint-fix` | Run clippy with `--fix` |
| `just install-local` | Build release + copy to `~/.local/bin/` |
| `just install` | Build release + copy to `/usr/local/bin/` (sudo) |
| `just desktop-deps` | `npm install` in `desktop/` |
| `just desktop-dev` | Run Tauri dev server (hot reload) |
| `just desktop-build` | Production desktop bundle |
| `just release` | Build tar.gz + SHA256 checksums in `dist/` |
| `just cross-compile` | Build for linux/macOS x amd64/arm64 |
| `just clean` | `cargo clean` + remove `bin/` `dist/` |
| `just version` | Print current version |

## Architecture (for development)

```
crates/baluard-core/     # All crypto, vault format, key lifecycle, git sync
  src/crypto/          # KDF, AEAD, HKDF, HPKE, Ed25519, TOTP (RFC 6238)
  src/keys/            # Key hierarchy, epochs, rotation
  src/vault/           # Vault handle, cipher CRUD, padding, folders
  src/sync/            # Git sync engine (git2-rs)
  src/paths.rs         # Platform-correct base dirs (data, socket, logs, token)
  src/types.rs         # CipherKind, CipherInput, CipherMeta, all data structs
crates/baluard-cli/      # Terminal client (clap)
  src/client.rs        # Protobuf socket client, session tokens
  src/commands/        # Dual-mode handlers (daemon + --direct)
crates/baluard-daemon/   # Background IPC daemon
  src/handler.rs       # Protobuf routing, password zeroize
  src/state.rs         # VaultState (Arc<RwLock<Option<VaultHandle>>>)
desktop/               # Tauri v2 + SolidJS + Tailwind
  src-tauri/           # Rust backend (sidecar daemon management)
  src/                 # SolidJS frontend
    __tests__/          # Vitest tests (96 tests: payload, utils, filters, cipherSchema)
    components/         # 19 components including Icon.jsx (40+ SVG icons)
    context/            # AuthContext, VaultContext, errorSignal, themeSignal
    lib/                # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, eff-words.js
proto/                 # Protobuf schemas (compiled via prost)
docs/                  # Architecture & design docs
```

### Key flows

- **CLI -> Daemon**: CLI sends Protobuf over Unix socket. Session token persisted alongside the socket (see `baluard_core::paths::token_path()`).
- **CLI -> Direct**: `--direct` flag loads `baluard-core` in-process. No daemon. State dies with the process.
- **Desktop -> Daemon**: Tauri app spawns daemon as sidecar via `tauri_plugin_shell`. Communicates over the same Unix socket.
- **Daemon -> Core**: Daemon links `baluard-core` directly. All crypto happens in-process.

## Testing

```bash
just test              # All tests
just test-core         # Core library only (crypto, vault, keys)
just e2e               # Full daemon-mode smoke test
```

### Writing tests

- Unit tests go in the same file: `#[cfg(test)] mod tests { ... }`
- Property-based tests use `proptest`
- Security-critical tests (AAD verification, zeroization, token auth) live in `baluard-core/src/vault/cipher.rs` and `baluard-core/src/keys/hierarchy.rs`

## Desktop Development

```bash
just desktop-dev       # Starts Tauri dev server with hot reload
just desktop-build     # Production bundle (dmg/msi/deb)
```

The desktop app:
1. Spawns `baluard-daemon` as a sidecar on startup
2. Communicates via the same Protobuf-over-Unix-socket as the CLI
3. Sends SIGTERM on quit (daemon zeroizes keys before exit)
4. SolidJS frontend in `desktop/src/`, Rust backend in `desktop/src-tauri/src/lib.rs`

## Release Process

```bash
just release           # tar.gz + checksums in dist/
just build-signed      # macOS codesign (or CI with Apple Developer cert)
```

For cross-compilation:

```bash
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
  x86_64-apple-darwin aarch64-apple-darwin
just cross-compile
```

## CLI Usage

```bash
# Create a vault
just install-local
baluard init --vault-path ~/.baluard

# Unlock and add a credential
baluard unlock
baluard add --name "GitHub" --username "user" --password "secret"
baluard add --name "Work VPN" --folder <folder-id>

# List and retrieve
baluard list
baluard get <uuid>

# Edit metadata
baluard edit <uuid> --name "New Name" --favorite

# Folder management
baluard folders create "Personal"
baluard folders list
baluard folders rename <id> "Work"
baluard folders delete <id>

# Sync
baluard sync init
baluard sync remote <git-url>
baluard sync push

# Daemon mode (background)
baluard-daemon --vault-path ~/.baluard
```

All commands route through the daemon by default. Use `--direct` to run in-process (no daemon needed).

## Key Features

- **AES-256-GCM** encryption with Argon2id key derivation
- **Padded buckets** (5KB/30KB/100KB/250KB/2MB tiers) prevent metadata leakage
- **8 cipher types**: Login, Card, Identity, SSH Key, Secure Note, Bank Account, Driver's License, Passport/ID
- **TOTP code generation** (RFC 6238, SHA1/256/512, 6/8 digits)
- **Password generator** with CSPRNG + EFF 7776-word passphrase
- **Password history** (auto-tracked, 10 entries FIFO)
- **Folder organization** with CRUD
- **BIP-39 recovery phrase** for key recovery
- **HPKE key wrapping** (X25519 + Ed25519 device identity)
- **Git-native sync** - vault is a git repository
- **SO_PEERCRED** peer UID verification on Unix sockets
- **Auto-lock timer** (configurable, daemon-side)
- **Zeroize** all sensitive memory after use
- **CSP-enforced** webview security
- **Dark/light themes**

## Common Issues

### `cargo build` fails with `libgit2 not found`

The justfile auto-detects linuxbrew. If you're running raw `cargo` commands:

```bash
# Option 1: Use just (recommended)
just build

# Option 2: Set env vars manually (see Linuxbrew section above)
export PKG_CONFIG_PATH=... LD_LIBRARY_PATH=...
cargo build
```

### `protoc not found`

```bash
brew install protobuf         # macOS
sudo apt install protobuf-compiler  # Linux
```

### Desktop build fails on Linux (WebKitGTK)

```bash
sudo apt install libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev libgtk-3-dev
```

### `just` not found

```bash
cargo install just
```
