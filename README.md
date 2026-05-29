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

## Quick Start

```bash
cargo install just      # Build runner
git clone https://github.com/EstebanForge/IDtty.git
cd IDtty
just build
just test
```

See **[docs/05-dev-setup.md](docs/05-dev-setup.md)** for prerequisites, platform setup, and all build commands.

## Documentation

| Doc | Description |
|-----|-------------|
| [Dev Setup & Workflow](docs/05-dev-setup.md) | Prerequisites, build commands, architecture, testing, troubleshooting |
| [Architecture Decisions](docs/01-architecture-decisions.md) | Design rationale and tradeoffs |
| [Threat Model](docs/02-threat-model.md) | Adversaries, attack surfaces, mitigations |
| [Key Lifecycle](docs/03-key-lifecycle.md) | Key hierarchy, derivation, rotation |
| [Software Architecture](docs/04-software-architecture.md) | Component diagram, data flows, IPC protocol |
| [Progress](docs/00-progress.md) | Implementation status and review history |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Start with `just check` before pushing.

## License

GPL-3.0
