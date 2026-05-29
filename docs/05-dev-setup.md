# Dev Setup & Workflow

Everything you need to build, test, and develop IDtty locally.

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
git clone https://github.com/EstebanForge/IDtty.git
cd IDtty

# Build everything
just build

# Run tests
just test

# Full CI check (fmt + clippy + test + build)
just check

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
| `just test` | Run all tests (69 tests across 4 suites) |
| `just test-core` | Run `idtty-core` tests only |
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
crates/idtty-core/     # All crypto, vault format, key lifecycle, git sync
  src/crypto/          # KDF, AEAD, HKDF, HPKE, Ed25519
  src/keys/            # Key hierarchy, epochs, rotation
  src/vault/           # Vault handle, cipher CRUD, padding
  src/sync/            # Git sync engine (git2-rs)
crates/idtty-cli/      # Terminal client (clap)
  src/client.rs        # Protobuf socket client, session tokens
  src/commands/        # Dual-mode handlers (daemon + --direct)
crates/idtty-daemon/   # Background IPC daemon
  src/handler.rs       # Protobuf routing, password zeroize
  src/state.rs         # VaultState (Arc<RwLock<Option<VaultHandle>>>)
desktop/               # Tauri v2 + SolidJS + Tailwind
  src-tauri/           # Rust backend (sidecar daemon management)
  src/                 # SolidJS frontend
proto/                 # Protobuf schemas (compiled via prost)
docs/                  # Architecture & design docs
```

### Key flows

- **CLI -> Daemon**: CLI sends Protobuf over Unix socket. Session token persisted to `/tmp/idtty.tok`.
- **CLI -> Direct**: `--direct` flag loads `idtty-core` in-process. No daemon. State dies with the process.
- **Desktop -> Daemon**: Tauri app spawns daemon as sidecar via `tauri_plugin_shell`. Communicates over the same Unix socket.
- **Daemon -> Core**: Daemon links `idtty-core` directly. All crypto happens in-process.

## Testing

```bash
just test              # All tests
just test-core         # Core library only (crypto, vault, keys)
just e2e               # Full daemon-mode smoke test
```

### Writing tests

- Unit tests go in the same file: `#[cfg(test)] mod tests { ... }`
- Property-based tests use `proptest`
- Security-critical tests (AAD verification, zeroization, token auth) live in `idtty-core/src/vault/cipher.rs` and `idtty-core/src/keys/hierarchy.rs`

## Desktop Development

```bash
just desktop-dev       # Starts Tauri dev server with hot reload
just desktop-build     # Production bundle (dmg/msi/deb)
```

The desktop app:
1. Spawns `idtty-daemon` as a sidecar on startup
2. Communicates via the same Protobuf-over-Unix-socket as the CLI
3. Sends SIGTERM on quit (daemon zeroizes keys before exit)
4. SolidJS frontend in `desktop/src/App.jsx`, Rust backend in `desktop/src-tauri/src/lib.rs`

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
idtty init --vault-path ~/.idtty

# Unlock and add a credential
idtty unlock
idtty add --name "GitHub" --username "user" --password "secret"

# List and retrieve
idtty list
idtty get <uuid>

# Sync
idtty sync init
idtty sync remote <git-url>
idtty sync push

# Daemon mode (background)
idtty-daemon --vault-path ~/.idtty
```

All commands route through the daemon by default. Use `--direct` to run in-process (no daemon needed).

## Key Features

- **AES-256-GCM** encryption with Argon2id key derivation
- **Padded buckets** (1KB/8KB/64KB/1MB) prevent metadata leakage
- **BIP-39 recovery phrase** for key recovery
- **HPKE key wrapping** (X25519 + Ed25519 device identity)
- **Git-native sync** - vault is a git repository
- **SO_PEERCRED** peer UID verification on Unix sockets
- **Zeroize** all sensitive memory after use
- **CSP-enforced** webview security

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
