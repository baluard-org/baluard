# Baluard Documentation

> Architecture, security, and development documentation. Implementation history lives in git; the docs below describe the system as it ships. User-facing changes per release are listed in the root [CHANGELOG.md](../CHANGELOG.md).

## Architecture Decision Records

Every design decision has a numbered record in [docs/adr/](adr/). The numbering follows the design chronology: the original core and platform records, the frontend and sharing series, the larger design records in lineage order, and the domain appendix.

| Range | Content |
|-------|---------|
| 0001-0011 | Core: Rust memory security, padded buckets, key hierarchy, conflict resolution, sync, the protobuf gateway, daemon and mobile tiers, zero-knowledge sharing |
| 0012-0061 | Frontend architecture, quick unlock, browser bridge, conflict panel, Android autofill, item sharing, collections, roles, and mobile surfaces |
| 0062-0084 | Quorum and power-pack records, enrollment proofs, updater and Linux distribution, scoped agent credential access, signing keys and certificates |
| 0085-0100 | The larger design records: sharing, family spaces, power pack, git providers, mobile apps, Android autofill and tile, browser extension, conflict panel, passkeys, YubiKey seal, hardware-backed keys, merged search, encrypted backup, legacy contact |
| 0101 | Domain appendix: device fleet, lifecycle, terminology, tags |

See [the ADR index](adr/index.md) for the full numbered list.

## Security

| Document | Description |
|----------|-------------|
| [Security White Paper](security/security-white-paper.md) | The public trust document: architecture as security model, key hierarchy, hardware sealing, sync verification, threat residuals, assurance status |
| [Threat Model](security/threat-model.md) | Adversaries, attack surfaces, mitigations (incl. T15 multi-vault key material, T10 biometric) |
| [Cover Commit Policy](security/threat-model.md#t14-cover-commit-correlation) | Timing-noise scheduling rules and rationale |
| [2FA Analysis](security/2fa-analysis.md) | TOTP implementation, RFC 6238/4226 compliance, second-factor roadmap |
| [Forward Secrecy Model](security/forward-secrecy-model.md) | Tradeoff documentation for post-revocation ciphertext (audit finding L8) |
| [Post-Quantum Readiness](security/post-quantum-readiness.md) | Cryptographic assessment and transition roadmap for quantum safety |
| [Legacy Contact](security/legacy-contact.md) | The trusted-contact recovery feature: arming, silence windows, the contact's read-only view, and its honest limits (shipped 2026-10-26) |
| [Emergency Org Identity](security/emergency-org-identity.md) | How the Space Recovery Kit escrows org identity and what recovery restores |

## Architecture

| Document | Description |
|----------|-------------|
| [Software Architecture](dev/software-architecture.md) | Component diagram, data flows, IPC protocol, key lifecycle, cryptographic ceremonies |
| [Key Concepts & Domain Architecture](dev/key-concepts.md) | Key hierarchy, cipher models, IPC, multi-vault host, auto-sync, passkeys, Android autofill |
| [Engineering Invariants & Gotchas](dev/gotchas.md) | Core invariants, Git sync mechanics, IPC rules, platform quirks, and implementation edge cases |

## Development

| Document | Description |
|----------|-------------|
| [Dev Setup & Workflow](dev/dev-setup.md) | Prerequisites, platform-specific setup, build commands, testing, troubleshooting |
| [Mobile Dev Setup](dev/dev-setup-mobile.md) | Android SDK, NDK, OpenJDK 17, and Gradle setup for mobile development |
| [Translations & Localization](dev/translations.md) | Guide for adding and maintaining desktop and mobile language translations |
| [Linux Repositories](dev/linux-repositories.md) | GPG-verified apt and dnf package repositories: user setup, key fingerprint, direct-download verification |
| [Release Protocol](dev/release-protocol.md) | Shipping runbook for every variant: version bump, signing keys and store credentials, build matrix (Linux/macOS/Windows/extension/Android), the release pipeline, store publishing, update channels |
| [Google Play](dev/google-play.md) | Play Console runbook: signing and version-code rules, testing tracks, console declarations, listing kit, the subscription model, and the per-release flow |
| [Git Provider Apps & Tokens](dev/git-provider-apps-and-tokens.md) | App registration credentials and token management for GitHub, GitLab, and Codeberg |

## Design

| Document | Description |
|----------|-------------|
| [Brand Guidelines](brand/brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Design Language Tokens](brand/design-language-tokens.json) | Machine-readable design tokens (single source for the CSS pipeline) |
| [App Icons](brand/app-icons.md) | Generate platform icons (macOS/Win/Linux/Android/iOS) from one source image via `just app-icons` |
