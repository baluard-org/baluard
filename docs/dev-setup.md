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
git clone https://github.com/baluard-org/baluard.git
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
| `just build-nmh` | Build the `baluard-nmh` native messaging host binary (release) |
| `just test` | Run all tests (Rust suites + desktop vitest) |
| `just test-core` | Run `baluard-core` tests only |
| `just test-release` | Tests in release mode |
| `just test-verbose` | Tests with `--nocapture` (see println output) |
| `just e2e` | Full smoke test: init -> daemon -> unlock -> add -> get -> delete -> lock |
| `just check` | CI parity: `fmt-check` + `clippy` + `audit` + `test` + `build` |
| `just fmt` | Format all Rust code |
| `just fmt-check` | Check formatting without modifying files |
| `just lint` | Run clippy with `-D warnings` |
| `just lint-fix` | Run clippy with `--fix` |
| `just audit` | Run cargo-audit (skipped silently if not installed) |
| `just install-local` | Build release + copy to `~/.local/bin/` |
| `just install` | Build release + copy to `/usr/local/bin/` (sudo) |
| `just install-nmh-manifest <browser> <ext_id>` | Point the OS-native-messaging host manifest at the release NMH binary for `<browser>` (chromium/chrome/firefox) pinned to `<ext_id>` |
| `just nmh-path` | Print the NMH binary path (for hand-writing a host manifest) |
| `just uninstall-local` / `just uninstall` | Reverse of install-local / install |
| `just desktop-deps` | `npm install` in `desktop/` |
| `just desktop-dev` | Run Tauri dev server (hot reload) |
| `just desktop-build` | Production desktop bundle |
| `just desktop-debug` | Tauri dev with `BALUARD_DEBUG=1` (logs to `./logs/`) |
| `just codesign` | Codesign the Tauri debug binary (run after first desktop-debug or when Rust changes; macOS) |
| `just ext-build` | Build both Chrome and Firefox extension bundles (Vite) |
| `just ext-build-chrome` / `just ext-build-firefox` | Build a single target |
| `just ext-dev-chrome` / `just ext-dev-firefox` | Dev: build + print load-unpacked / about:debugging instructions |
| `just app-icons SOURCE OUT` | Generate platform icons (macOS/Win/Linux/Android/iOS + tray monochrome) from a source PNG into `OUT` |
| `just seed-demo` | Seed a 31-entry demo vault (password: `demo`) |
| `just release` | Build tar.gz + SHA256 checksums in `dist/` |
| `just cross-compile` | Build for linux/macOS x amd64/arm64 |
| `just clean` | `cargo clean` + remove `bin/` `dist/` |
| `just version` | Print current version |

## Architecture (for development)

```
crates/baluard-core/     # All crypto, vault format, key lifecycle, git sync, providers, browser bridge
  src/crypto/          # AEAD, KDF, HKDF, HPKE-wrap, Ed25519, TOTP (RFC 6238), webauthn/ (ceremony + store)
  src/keys/            # Key hierarchy, epochs, rotation, nonces
  src/vault/           # Vault handle, cipher CRUD, padding, folders, manifest, canary, attachment, avatar, slug, registry, keywrap, index
  src/sync/            # Git sync engine (git2-rs), conflict 3-way merge, state machine, known_hosts, credentials, operations, commit
  src/import/          # 8 import parsers (bw_json/csv, chrome/firefox/lastpass/1password_csv, 1pux, keepass) + 2 exports
  src/providers/       # Git provider abstraction: github, gitlab, codeberg adapters + token store + shared types
  src/bridge/          # Browser extension bridge: pairing file (pairing), bridge token mint/verify (token)
  src/biometric.rs     # OS-keychain-backed MP escrow (per-vault scoped, deterministic vault_id from KDF salt)
  src/device_manager.rs# Device registry, rotation, activity, enrollment, recovery-phrase enrollment
  src/devices.rs       # Device entry types
  src/emergency.rs     # Break-glass access
  src/health.rs        # Password health report
  src/integrity.rs     # Canary checks + rollback manifest
  src/orgs.rs          # Team sharing / RBAC
  src/recovery.rs      # BIP-39 recovery
  src/paths.rs         # Platform-correct base dirs (data, socket, logs, token)
  src/types.rs         # CipherKind, CipherInput, CipherMeta, all data structs
  src/error.rs         # BaluardError enum
crates/baluard-cli/      # Terminal client (clap)
  src/main.rs          # Command dispatch + clap definitions
  src/client.rs        # Protobuf socket client, session tokens
  src/commands/        # Dual-mode handlers (daemon + --direct) -- single mod.rs file
crates/baluard-daemon/   # Background IPC daemon
  src/main.rs          # tokio listener, SIGINT/SIGTERM, 0600 perms
  src/handler.rs       # Protobuf routing (~72 routes), password zeroize, token-gated, bridge allowlist
  src/state.rs         # VaultState (Arc<RwLock<Option<VaultHandle>>>) + per-vault PIN escrow
  src/host.rs          # VaultHost multi-vault: RwLock<VaultHostInner> with HashMap + active pointer
  src/autosync.rs      # Debounced push + event-driven pull + 30-min idle fallback + offline retry
  src/pin.rs           # Session PIN escrow (PinEscrow), 5-strike nuke
  src/bridge.rs        # Bridge token registry + TokenKind::Bridge branch + allowlist enforcement
  src/rate_limit.rs    # Per-action rate limiting
  src/socket_path.rs   # Platform socket path resolution
  src/crypto.rs        # Crypto module glue
  src/lib.rs           # Test surface (re-exports host/state/handler for integration tests)
crates/baluard-nmh/      # Native messaging host (browser extension bridge)
  src/                 # stdio-JSON <-> varint-protobuf. Stateless. Reads pairing entry on spawn.
desktop/               # Tauri v2 + SolidJS + Tailwind
  src-tauri/           # Rust backend (daemon sidecar + baluard-nmh sidecar + tray + proto codegen)
  src/                 # SolidJS frontend
    __tests__/          # Vitest tests (~117 cases: payload, utils, filters, cipherSchema, cloneFlow, conflictResolution, ConflictResolutionPanel, conflictSwitchClear)
    components/         # 38 components including Icon.jsx (40+ SVG icons), BridgeTab, ConflictResolutionPanel, DetachVaultModal, SwitchUnlockModal, AutoSyncIndicator, CloneFromProviderScreen, WelcomeScreen, VaultSwitcher
    context/            # AuthContext.jsx, VaultContext.jsx, VaultSwitcherContext.jsx, AutoSyncContext.jsx, ConflictResolutionContext.jsx, themeSignal.js, toastSignal.js
    lib/                # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, helpers.js, biometry.js, clipboard.js, vaultPrefetch.js, vaultTimeout.js, slug.js, cloneFlow.js, providerConnect.js, disableAutofill.js, eff-words.js, wordlist-{en,es}.js
browser/                # MV3 browser extensions (Chromium + Firefox, shared codebase)
  shared/               # 95% of code (SolidJS popup, service worker, content script, nmh wrapper, autofill, pair)
  chrome/               # Chrome MV3 wrapper (manifest.extra.json)
  firefox/              # Firefox MV3 wrapper (manifest.extra.json)
proto/                 # Protobuf schemas (compiled via prost)
docs/                  # Architecture, design, plans, PRDs, threat model, post-quantum, 2fa, brand, app icons
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
- **FIDO2/WebAuthn passkeys** (Phase 0+1) embedded in `LoginData::fido2_credentials`. ES256 only.
- **Multi-vault** (Phase 6): keep-unlocked / switch-pointer daemon model. Per-vault session tokens. Single auto-lock walker. Lock-all on window blur.
- **Browser extensions** (Phase 0+1): KeePassXC-Browser-style bridge. Chromium + Firefox MV3. `baluard-nmh` native messaging host. Paired-companion auth, scoped bridge token, action allowlist.
- **Per-vault biometric unlock**: macOS `SecAccessControl BIOMETRY_ANY`, other platforms via `keyring` crate. Deterministic `vault_id` from KDF salt scopes the keychain entry.
- **Session PIN** (Linux + Windows-without-Hello fallback): in-memory KEK + Argon2id PIN verifier, 5-strike nuke, survives soft-lock, dies on close/restart.
- **Password generator** with CSPRNG + EFF 7776-word passphrase
- **Password history** (auto-tracked, 10 entries FIFO)
- **Folder organization** with CRUD
- **BIP-39 recovery phrase** for key recovery; optional `enroll-with-phrase` per `EnrollmentPolicy`
- **HPKE key wrapping** (X25519 + Ed25519 device identity)
- **Git-native sync** - vault is a git repository. Debounced push + event-driven pull + 30-min idle fallback + offline retry + keep-local conflict resolve.
- **Git online providers**: GitHub (device flow), GitLab (device flow + 2h refresh), Codeberg (web-OAuth PKCE). PAT fallback under Advanced Options for all three.
- **Vault detach**: safe UI arm (drops registry entry); destructive `--delete-from-disk` arm is CLI-only.
- **SO_PEERCRED** peer UID verification on Unix sockets
- **Auto-lock timer** (configurable per vault, daemon-side)
- **Zeroize** all sensitive memory after use; `mlock` on key material; aggregate `mlock_budget` logged per unlock
- **CSP-enforced** webview security
- **Dark/light/system themes**
- **i18n** (English + Spanish; all user-facing strings go through `t()`)

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
