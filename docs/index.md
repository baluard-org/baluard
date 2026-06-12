# Baluard Documentation

> Single source of truth for architecture, security, and implementation status.

## Architecture & Design

| Document | Description |
|----------|-------------|
| [Architecture Decisions](architecture-decisions.md) | Design rationale, tradeoffs, device fleet (DOMAIN 5), device lifecycle & rotation (DOMAIN 6), frontend architecture (DOMAIN 7) |
| [Software Architecture](software-architecture.md) | Component diagram, data flows, IPC protocol, key lifecycle, cryptographic ceremonies |
| [Threat Model](threat-model.md) | Adversaries, attack surfaces, mitigations |

## Security

| Document | Description |
|----------|-------------|
| [2FA Analysis](2fa-analysis.md) | TOTP implementation, RFC 6238/4226 compliance, second-factor roadmap |
| [Security Audit 2026-06](security-audit-2026-06.md) | Full audit findings (Critical, High, Medium, Low) with remediation status |
| [Security Fix Verification 2026-06](security-fix-verification-2026-06.md) | Verification report on the post-audit fixes |
| [Forward Secrecy Model](forward-secrecy-model.md) | Tradeoff documentation for post-revocation ciphertext (audit finding L8) |
| [Vault Metadata Leakage Analysis](vault-metadata-leakage-analysis.md) | What the git remote can observe about your vault (audit finding M2) |

## Development

| Document | Description |
|----------|-------------|
| [Dev Setup & Workflow](dev-setup.md) | Prerequisites, platform-specific setup, build commands, testing (89 desktop vitest tests), troubleshooting |
| [Progress](progress.md) | Implementation status, review history, pending work |
| [Cover Commit Policy](cover-commit-policy.md) | Timing-noise scheduling rules and rationale |

## Design

| Document | Description |
|----------|-------------|
| [Brand Guidelines](brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Design Language Tokens](design-language-tokens.json) | Machine-readable design tokens (single source for the CSS pipeline) |
| [Dev-Mode App Icon](dev-mode-app-icon.md) | Known limitation: third-party macOS app switchers show a generic icon in dev mode |

## Product Planning

| Document | Description |
|----------|-------------|
| [PRD: Git Providers & Multi-Vault](prd-git-providers-multi-vault.md) | Product requirements for the multi-vault and online git provider feature |
| [Plan: Git Providers & Multi-Vault](plan-git-providers-multi-vault.md) | Phased implementation plan tracking the PRD progress |
| [Plan: Passkey Support](plan-passkey-support.md) | FIDO2/WebAuthn passkey storage + ceremony. Phase 0+1 complete (schema, BW import, ceremony wiring, CLI, daemon IPC). Phase 2+ pending (browser extension, mobile). |
| [ADR 0007: passkey-rs Evaluation](adr/0007-passkey-rs-evaluation.md) | Decision to adopt `passkey-rs` 0.5.x as the WebAuthn authenticator library |
