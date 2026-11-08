# OVERVIEW
Project: **Baluard** (Git-native password manager)
Stack: Rust (core crypto + daemon runtime + CLI + NMH + UniFFI), SolidJS/Tailwind/Tauri v2 (desktop), JS/MV3 (browser extension), Kotlin Multiplatform/Compose (mobile), Protobuf (IPC schema)
License: GPL-3.0
Trademark: All rights reserved on name, logo, and brand assets; GPL-3.0 covers code only.

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets.
Absolute primary focuses: Security, privacy, and ease of use for non-technical users.
Platforms: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell. Browser: Chrome + Firefox (MV3). Mobile: Android, iOS.

## STATUS
Baluard is public beta 0.1.x, bug fixing releases. **No breaking changes.** Assume users already operate with Baluard.
* **Security can push format breaks, with a migration path.** If a security fix requires breaking a format, route, or storage layout, do it, with a migration path for existing users.
* **DO NOT break:** Crypto and security invariants (AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 socket, token-gating).

## STRUCTURE
For the detailed source tree, see [Software Architecture](docs/dev/software-architecture.md#1-monorepo-structure).

```text
baluard/
├── crates/
│   ├── baluard-core/        # Core library: crypto, keys, vault, git sync, providers, imports
│   ├── baluard-runtime/     # Shared vault-session runtime: host, state, autosync, pin, bridge, rate limiting
│   ├── baluard-daemon/      # Background IPC daemon: Unix domain socket listener and protobuf handler
│   ├── baluard-cli/         # CLI client (clap): daemon-first with --direct fallback
│   ├── baluard-nmh/         # Browser native messaging host: stdio JSON <-> daemon protobuf relay
│   └── baluard-uniffi/      # UniFFI bindings for Kotlin Multiplatform mobile app
├── desktop/                 # Tauri v2 + SolidJS frontend
├── browser/                 # Browser extension (MV3, Chrome + Firefox)
├── mobile/                  # Kotlin Multiplatform app (Compose Multiplatform UI)
├── services/entitlements/   # Cloud Run Google Play entitlement verification
├── proto/                   # Protobuf schemas (compiled via prost)
└── docs/                    # Architecture records (ADRs), developer guides, and security specifications
```

## COMMANDS
| Action | Command |
|--------|---------|
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

## MINIMUM PLATFORM COMPATIBILITY
| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| macOS | 15 (Sequoia) | Apple Silicon + Intel. Security framework SecAccessControl + Touch ID. |
| Windows | 11 (2025 update) | Windows Hello (PIN + biometric). Credential Manager via keyring. |
| Ubuntu | 26.04 | Secret Service (gnome-keyring or compatible) at runtime for keyring storage. |
| Fedora | 43 | Secret Service (gnome-keyring or compatible) at runtime for keyring storage. |

Rust edition 2024, MSRV 1.85. The optional `fido2` feature requires Rust 1.89 (ctap-hid-fido2 requirement); default builds stay 1.85.
Linux build dependencies: `protoc`, WebKitGTK/GTK dev headers. Run `just sysdeps` for distro-specific packages.

## CODING STANDARDS
* **Compatibility:** Pre-1.0 WIP (see STATUS). Backwards compatibility is not a goal yet. You can break vault format, IPC routes/payloads, CLI flags, protobuf, and config freely, but update all call sites in the same change.
* **Rust:** Edition 2024, MSRV 1.85. Feature flags: `full` (default) = `git-sync` + `passkey-ceremony` + `uri-match`. Use `thiserror` for library errors, `anyhow` for CLI, and `proptest` for property-based tests.
* **JS/TS:** ES modules, SolidJS, Vite, Tailwind. Use `crypto.getRandomValues` only (never `Math.random`).
* **Protobuf:** proto3, `baluard.vault` package. Compiled via prost in daemon and CLI.
* **Security:** AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket permissions 0600. Zeroize on drop for key material, TOTP secrets, and passkey private keys.
* **WebAuthn/Passkey:** passkey-rs 0.5.x for ceremony. ES256 only. Private key encrypted under item key, never crosses IPC, zeroized on drop. Counter: Synced/provider passkeys pin counter to 0 (W3C L3 multi-device guidance); `max(local, remote)` applies only to device-bound legacy counters on git-sync.

## DOCUMENTATION REFERENCES
Detailed domain concepts, architecture, and edge cases live in `docs/`:
* [Documentation Index](docs/index.md): Complete list of ADRs, architecture docs, security specs, and dev guides.
* [Software Architecture](docs/dev/software-architecture.md): Monorepo structure, protobuf gateway, platform tier architecture, and key lifecycle.
* [Key Concepts & Domain Architecture](docs/dev/key-concepts.md): Key hierarchy, cipher data models, IPC mechanics, auto-sync, device lifecycle, passkeys, and Android autofill.
* [Engineering Invariants & Gotchas](docs/dev/gotchas.md): Implementation gotchas, Git sync invariants, IPC safety rules, platform quirks, and release procedures.
* [Release Protocol](docs/dev/release-protocol.md): Authoritative runbook for version bumps, multi-platform builds, and distribution.
* [Security White Paper](docs/security/security-white-paper.md): Trust model, threat analysis, and cryptographic proofs.

## WHERE TO LOOK
* **Crypto primitives:** `crates/baluard-core/src/crypto/`
* **Key hierarchy & lifecycle:** `crates/baluard-core/src/keys/`
* **Vault CRUD & format:** `crates/baluard-core/src/vault/`
* **Platform paths (data, socket, logs):** `crates/baluard-core/src/paths.rs`
* **CipherKind & data structs:** `crates/baluard-core/src/types.rs`
* **Git sync engine:** `crates/baluard-core/src/sync/`
* **Git providers (ForgeProvider trait, OAuth/PAT):** `crates/baluard-core/src/providers/`
* **CLI commands:** `crates/baluard-cli/src/commands/mod.rs`
* **Daemon runtime:** `crates/baluard-runtime/src/` (`host.rs`, `state.rs`, `autosync.rs`, `pin.rs`, `bridge.rs`, `rate_limit.rs`)
* **Daemon IPC:** `crates/baluard-daemon/src/handler.rs` (protobuf dispatcher) and `main.rs` (Unix socket listener)
* **Browser extension:** `browser/shared/src/` (background, content, inline, offscreen, autofill) and `crates/baluard-nmh/`
* **Mobile app:** `mobile/shared/src/` (commonMain UI/VMs, androidMain/iosMain platform impls) and `crates/baluard-uniffi/`
* **Desktop frontend:** `desktop/src/App.jsx` and `desktop/src/components/`
* **Protobuf schemas:** `proto/vault.proto` and `proto/auth.proto`

## CRITICAL SAFETY INVARIANTS
* **Master Password Verification:** `vault.unlock` must verify the master password against the KEK canary on every path, even when already unlocked.
* **Hermetic Keyring Testing:** `just test` sets `BALUARD_DISABLE_KEYRING=1` to prevent tests from hanging on system secret service prompts.
* **Zeroization:** Key material, passkey secrets, TOTP seeds, and session PIN escrow buffers must zeroize on drop.
* **Socket Security:** Daemon socket must be created with mode 0600 (`umask(0177)`).
* **No Private or Sensitive Material in Commits:** Never commit credentials, tokens, API keys, passwords, private keys, signing material, `.env` files, provider tokens, vault data, or anything from machine-local secret stores (`~/.secrets`, Bitwarden exports, keychain dumps). Secrets live only in Bitwarden or machine-local files outside the repo. This covers file contents, commit messages, and embedded test fixtures alike; test secrets must be synthetic. If sensitive material ever lands, treat the exposure as real and rotate the credential before rewriting history.
* **Git Sync Integrity:** Sync cycle must always run `commit -> pull -> push`. Pull operations must use force checkout.
* For the complete catalog of subsystem gotchas and failure modes, consult [docs/dev/gotchas.md](docs/dev/gotchas.md).

## DEBUG LOGGING
`just desktop-debug` runs the desktop app with `BALUARD_DEBUG=1`. Logs go to `./logs/` at cwd.
* `daemon.log`: IPC routing, vault CRUD, serde errors, crypto ops (via `env_logger`).
* `desktop.log`: Tauri bridge: every daemon request with action, payload size, success/error (via `tauri-plugin-log`).

Env vars (set automatically by `just desktop-debug`):
* `BALUARD_DEBUG=1`: Enables Debug level (otherwise Warn only).
* `BALUARD_LOG_DIR=<path>`: Overrides log directory.

## UX PRINCIPLES
* **Hide the machinery:** The user sees entries, folders, and a sync status dot. Never expose Git terms, crypto terms, epochs, tokens, sockets, or raw error codes in user-facing UI.
* **Ease of use is the evaluation axis:** A change breaks UX if it removes working functionality, adds friction, or confuses a non-technical user.
* **Plain language:** Use "entry" instead of "cipher". Hide UUIDs. Collections are "Shared folders" in UI.
* **No vault server backend:** Desktop and mobile apps work standalone and offline. Git sync is optional. Cloud Run verifies Play subscriptions only and never receives vault data.
* **The app prints commands, the user runs them:** When a system component is missing (e.g. Secret Service on Linux), display the install command for the user to run. Never execute privileged commands directly or prompt for sudo.
* **i18n:** All user-facing strings must use `t()` translation keys with parity maintained across `en.json`, `es.json`, and `pt.json`.
