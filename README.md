# Baluard

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients.

## Architecture

```
baluard-core    -> Pure Rust: crypto (AES-256-GCM, Argon2id, HPKE, Ed25519, TOTP), vault format, key lifecycle, sharing, git sync, import/export (incl. the encrypted .bldbak container)
baluard-runtime -> Shared orchestration runtime: VaultHost, VaultState, auto-sync coordinator, PIN escrow, provider connect, cross-vault copy
baluard-daemon  -> Background IPC daemon (tokio Unix socket, Protobuf gateway, ~150 actions, thin runtime shell)
baluard-cli     -> Terminal client: 35 commands - daemon-first with --direct fallback; vault CRUD, search, generator/TOTP/SSH keygen, providers, sharing, contacts, rotation, backups
baluard-nmh     -> Native messaging host (browser extension bridge, stdio-JSON <-> varint-protobuf)
baluard-uniffi  -> UniFFI bindings consumed by the Kotlin Multiplatform mobile app
desktop/        -> Tauri v2 desktop app (SolidJS + Tailwind v4: all cipher types, sharing/family admin, backups, health, merged vault view)
browser/        -> MV3 browser extension for Chromium and Firefox (paired companion, merged matches, inline autofill)
mobile/        -> Kotlin Multiplatform / Compose app (Android shipped; iOS pending): multi-vault, sharing/family, biometric, autofill + accessibility fill, backups
```

## Features

- **Encrypted vault as a git repo** - no server; padded buckets (5 tiers) hide metadata; device identity with signed commits and enrollment proofs
- **All 8 cipher types**, TOTP, SSH keys, passkeys (view/delete), custom fields, attachments, password health
- **Sharing & Spaces** - invite-code joins with roles and grants, family Spaces (purpose flag, minors, phrase-only recovery kit, D61 claim window), merged search/autofill across eligible vaults
- **Backups** - full-fidelity `baluard.vault` JSON, logins-only CSV, and a passphrase-encrypted `.bldbak` container that restores into any vault
- **Git providers** - GitHub/GitLab/Codeberg device-flow or PAT connect, repo creation, clone, auto-sync
- **Quick unlock** - Touch ID / Windows Hello keychain, Android biometric, session PIN (Linux)
- **Clients** - desktop (Tauri), Android app with system autofill, browser extension, and a first-class CLI

## Quick Start

```bash
cargo install just      # Build runner
git clone https://github.com/baluard-org/baluard.git
cd Baluard
just build
just test
```

See **[docs/dev-setup.md](docs/dev-setup.md)** for prerequisites, platform setup, and all build commands. For mobile development setup, see **[docs/mobile-dev-setup.md](docs/mobile-dev-setup.md)**.

### Try the demo vault

```bash
just seed-demo            # seeds two demo vaults (password: baluard99)
baluard --direct list    # list entries
just desktop-debug       # open in GUI
```

Seeds two demo vaults (`baluard-personal` with 100 entries across all 8 cipher types, and `baluard-work`) plus national IDs, folders, and tags. Password for both vaults: `baluard99`. No daemon needed; runs in `--direct` mode. If existing demo vaults are found, offers to replace them before seeding.

## Documentation

For full documentation, see **[docs/index.md](docs/index.md)**.

| Document | Description |
|----------|-------------|
| [Architecture Decisions](docs/software-architecture-decisions.md) | Design rationale, device fleet (DOMAIN 5), device lifecycle & rotation (DOMAIN 6) |
| [Software Architecture](docs/software-architecture.md) | Component diagram, data flows, IPC protocol, key lifecycle, cryptographic ceremonies |
| [Threat Model](docs/threat-model.md) | Adversaries, attack surfaces, mitigations |
| [2FA Analysis](docs/2fa-analysis.md) | TOTP implementation, RFC 6238/4226 compliance |
| [Dev Setup & Workflow](docs/dev-setup.md) | Prerequisites, build commands, architecture, testing, troubleshooting |
| [Mobile Dev Setup](docs/mobile-dev-setup.md) | Android SDK, NDK, OpenJDK 17, and Gradle setup for mobile development |
| [Translations & Localization](docs/translations.md) | Guide for adding and maintaining desktop and mobile language translations |
| [Brand Guidelines](docs/brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Progress](docs/progress.md) | Implementation status and review history |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Start with `just check` before pushing.

## License

[GPL-3.0](LICENSE)
