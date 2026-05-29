# IDtty

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients.

## Architecture

```
idtty-core    → Pure Rust: crypto (AES-256-GCM, Argon2id, HPKE, Ed25519), vault format, key lifecycle, git sync
idtty-daemon  → Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state in memory)
idtty-cli     → Terminal client (daemon-first with --direct fallback)
desktop/      → Tauri v2 desktop app (SolidJS + Tailwind v4)
mobile/       → Kotlin Multiplatform via UniFFI (planned)
extension/    → MV3 browser extension (planned)
```

All UI layers communicate with `idtty-core` through a single Protobuf-over-Unix-socket gateway. The daemon holds the vault unlocked in `zeroize`-protected memory.

## Build

```bash
# Rust workspace (core + daemon + CLI)
cargo build
cargo test

# Desktop app
cd desktop && npm install && npm run tauri dev
```

Requires Rust 1.85+ (edition 2024). Desktop uses the system's native webview (WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux):

```bash
# Linux (Debian/Ubuntu) — install WebKitGTK dev packages
sudo apt install libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev libgtk-3-dev

# macOS — no extra packages needed (uses system WebKit)
# Windows — no extra packages needed (WebView2 pre-installed on Win11, Tauri installer handles Win10)
```

## CLI Usage

```bash
# Create a vault
cargo run -p idtty-cli -- init --vault-path ~/.idtty

# Or after `cargo install --path crates/idtty-cli`:
# idtty init --vault-path ~/.idtty
```

# Unlock and add a credential
cargo run -p idtty-cli -- unlock
cargo run -p idtty-cli -- add --name "GitHub" --username "user" --password "secret"

# List and retrieve
cargo run -p idtty-cli -- list
cargo run -p idtty-cli -- get <uuid>

# Sync
cargo run -p idtty-cli -- sync init
cargo run -p idtty-cli -- sync remote <git-url>
cargo run -p idtty-cli -- sync push

# Daemon mode (background)
cargo run -p idtty-daemon
```

All commands route through the daemon by default. Use `--direct` to run in-process (no daemon needed).

## Key Features

- **AES-256-GCM** encryption with Argon2id key derivation
- **Padded buckets** (1KB/8KB/64KB/1MB) prevent metadata leakage
- **BIP-39 recovery phrase** for key recovery
- **HPKE key wrapping** (X25519 + Ed25519 device identity)
- **Git-native sync** — vault is a git repository
- **SO_PEERCRED** peer UID verification on Unix sockets
- **Zeroize** all sensitive memory after use
- **CSP-enforced** webview security

## License

GPL-3.0
