# Baluard

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients.

## Architecture

```
baluard-core    -> Pure Rust: crypto (AES-256-GCM, Argon2id, HPKE, Ed25519, TOTP), vault format, key lifecycle, git sync
baluard-daemon  -> Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state, auto-lock, TOTP)
baluard-cli     -> Terminal client (daemon-first with --direct fallback, folders, edit)
desktop/      -> Tauri v2 desktop app (SolidJS + Tailwind v4, 8 cipher types, generator, TOTP widget)
mobile/       → Kotlin Multiplatform via UniFFI (planned)
extension/    → MV3 browser extension (planned)
```

## Quick Start

```bash
cargo install just      # Build runner
git clone https://github.com/baluard-org/baluard.git
cd Baluard
just build
just test
```

See **[docs/dev-setup.md](docs/dev-setup.md)** for prerequisites, platform setup, and all build commands.

### Try the demo vault

```bash
just seed-demo            # seeds vault at platform-default location (password: demo)
baluard --direct list    # list entries
just desktop-debug       # open in GUI
```

Seeds 31 entries across all 8 cipher types (logins, cards, notes, identities, SSH keys, bank accounts, driver licenses, passports), plus national IDs (Chilean Carnet/RUT), 5 folders, and 11 tags. No daemon needed -- runs in `--direct` mode. If an existing vault is found, offers to back it up before seeding.

## Documentation

For full documentation, see **[docs/index.md](docs/index.md)**.

| Document | Description |
|----------|-------------|
| [Architecture Decisions](docs/software-architecture-decisions.md) | Design rationale, device fleet (DOMAIN 5), device lifecycle & rotation (DOMAIN 6) |
| [Software Architecture](docs/software-architecture.md) | Component diagram, data flows, IPC protocol, key lifecycle, cryptographic ceremonies |
| [Threat Model](docs/threat-model.md) | Adversaries, attack surfaces, mitigations |
| [2FA Analysis](docs/2fa-analysis.md) | TOTP implementation, RFC 6238/4226 compliance |
| [Dev Setup & Workflow](docs/dev-setup.md) | Prerequisites, build commands, architecture, testing, troubleshooting |
| [Brand Guidelines](docs/brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Progress](docs/progress.md) | Implementation status and review history |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Start with `just check` before pushing.

## License

[GPL-3.0](LICENSE)
