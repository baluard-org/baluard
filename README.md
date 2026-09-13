# Baluard

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients.

## Architecture

```
baluard-core    -> Pure Rust: crypto (AES-256-GCM, Argon2id, HPKE, Ed25519, TOTP), vault format, key lifecycle, git sync
baluard-runtime -> Shared orchestration runtime: VaultHost, VaultState, auto-sync coordinator, PIN escrow
baluard-daemon  -> Background IPC daemon (tokio Unix socket, Protobuf gateway, thin runtime shell)
baluard-cli     -> Terminal client (daemon-first with --direct fallback, folders, edit)
baluard-nmh     -> Native messaging host (browser extension bridge, stdio-JSON <-> varint-protobuf)
baluard-uniffi  -> UniFFI bindings consumed by Kotlin Multiplatform mobile app
desktop/        -> Tauri v2 desktop app (SolidJS + Tailwind v4, 8 cipher types, generator, TOTP widget, switcher)
browser/        -> MV3 browser extension for Chromium and Firefox (paired companion model)
mobile/         -> Kotlin Multiplatform / Compose app for Android and iOS (home hub, filters, biometric, sync)
```

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
| [Brand Guidelines](docs/brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Progress](docs/progress.md) | Implementation status and review history |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Start with `just check` before pushing.

## License

[GPL-3.0](LICENSE)
