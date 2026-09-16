# Baluard Documentation

> Single source of truth for architecture, security, and implementation status.

## Architecture & Design

| Document | Description |
|----------|-------------|
| [Architecture Decisions](software-architecture-decisions.md) | Design rationale, tradeoffs, device fleet (DOMAIN 5), device lifecycle & rotation (DOMAIN 6), frontend architecture (DOMAIN 7), quick unlock (D20), browser extension (D21), conflict resolution panel (D22), event-driven sync (D24) |
| [Software Architecture](software-architecture.md) | Component diagram, data flows, IPC protocol, key lifecycle, cryptographic ceremonies |
| [Threat Model](threat-model.md) | Adversaries, attack surfaces, mitigations (incl. T15 multi-vault key material, T10 biometric) |

## Security

| Document | Description |
|----------|-------------|
| [2FA Analysis](2fa-analysis.md) | TOTP implementation, RFC 6238/4226 compliance, second-factor roadmap |
| [Forward Secrecy Model](forward-secrecy-model.md) | Tradeoff documentation for post-revocation ciphertext (audit finding L8) |
| [Post-Quantum Readiness](post-quantum-readiness.md) | Cryptographic assessment and transition roadmap for quantum safety |

## Development

| Document | Description |
|----------|-------------|
| [Dev Setup & Workflow](dev-setup.md) | Prerequisites, platform-specific setup, build commands, testing, troubleshooting |
| [Mobile Dev Setup](mobile-dev-setup.md) | Android SDK, NDK, OpenJDK 17, and Gradle setup for mobile development |
| [Progress](progress.md) | Implementation status, review history, pending work |
| [Cover Commit Policy](threat-model.md#t14-cover-commit-correlation) | Timing-noise scheduling rules and rationale |

## Design

| Document | Description |
|----------|-------------|
| [Brand Guidelines](brand-guidelines.md) | Color palette, design tokens, visual identity rules |
| [Design Language Tokens](design-language-tokens.json) | Machine-readable design tokens (single source for the CSS pipeline) |
| [App Icons](app-icons.md) | Generate platform icons (macOS/Win/Linux/Android/iOS) from one source image via `just app-icons` |

## Product Planning

| Document | Description |
|----------|-------------|
| [PRD: Git Providers & Multi-Vault](prd-git-providers-multi-vault.md) | Product requirements for the multi-vault and online git provider feature |
| [Plan: Git Providers & Multi-Vault](plan-git-providers-multi-vault.md) | Phased implementation plan tracking the PRD progress. Phases 1-6 complete. |
| [Plan: Git Providers Settings Tab](plan-git-providers-multi-vault-settings-tab.md) | Settings tab implementation plan for git provider connections and account status |
| [Git Provider Apps & Tokens](git-provider-apps-and-tokens.md) | App registration credentials and token management for GitHub, GitLab, and Codeberg |
| [Plan: Browser Extension](plan-browser-extension.md) | KeePassXC-Browser-style bridge client (MV3 Chromium + Firefox). Phases 0+1 complete (NMH binary, paired-companion auth, scoped bridge token, action allowlist). Phase 2 deferred. |
| [Plan: Conflict Resolution Panel](plan-conflict-resolution-panel.md) | Top-floating slide-down panel for destructive field-level merge outcomes. Phase 2 complete (2026-07-02): engine conflict pipeline, daemon decrypt+merge_ciphers, keep_both, frontend IPC. F1 auto-merges; F2/F3/F4 surface the panel. Open: stuck-queue escape. |
| [Plan: Passkey Support](plan-passkey-support.md) | FIDO2/WebAuthn passkey storage + ceremony. Phase 0+1 complete (schema, BW import, ceremony wiring, CLI, daemon IPC). Phase 2+ pending (browser extension, mobile). |
| [Plan: Mobile Apps (Android + iOS)](plan-mobile-apps.md) | Compose Multiplatform client consuming `baluard-runtime` + `baluard-core` in-process via UniFFI. Android Phases 0-5 complete (runtime, UniFFI, auth, home hub, list/detail, edit/generator/TOTP, sync/settings, multi-vault), edit/create at desktop parity (URIs + match strategy, custom fields, tags, folder, reprompt, SSH generation, favicons) and deep search over every field. Phase 6 (Autofill Service) is next. |
| [Plan: Mobile Onboarding](plan-mobile-onboarding.md) | Onboarding root flow for mobile clients (create new vault, provider clone, device enrollment). Slices 0-C complete. |
| [ADR 0007: passkey-rs Evaluation](plan-passkey-rs-evaluation.md) | Decision to adopt `passkey-rs` 0.5.x as the WebAuthn authenticator library |
