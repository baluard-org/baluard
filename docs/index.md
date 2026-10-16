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
| [Translations & Localization](translations.md) | Guide for adding and maintaining desktop and mobile language translations |
| [Progress](progress.md) | Implementation status, review history, pending work |
| [E2E Testing Plan](e2e-testing.md) | The four-surface E2E strategy (CLI+daemon, Android Maestro, desktop WebdriverIO, extension Playwright): principles, harness conventions, phases, CI design. Phase 1 done; Phase 2 flows green on device |
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
| [Plan: Mobile Apps (Android + iOS)](plan-mobile-apps.md) | Compose Multiplatform client consuming `baluard-runtime` + `baluard-core` in-process via UniFFI. Android Phases 0-6 complete (runtime, UniFFI, auth, home hub, list/detail, edit/generator/TOTP, sync/settings, multi-vault, autofill service, inline suggestions, save prompt, domain equivalence, app-to-web trust matching, quick-settings tile fill), edit/create at desktop parity, and deep search over every field. Phase 7 (iOS credential extension) parked past 1.0. |
| [Plan: Android Autofill](plan-android-autofill.md) | System autofill provider implementation (Phase 6): isolated process, biometric KEK unlock, URI matcher in core, domain equivalence groups, app-to-web matching with per-app trust, AssistStructure parsing, inline suggestions, save handoff. Complete. |
| [Plan: Android Accessibility Tile](plan-android-accessibility-tile.md) | Quick-settings tile accessibility fill implementation (Phase 6.5): opt-in tile trigger, browser URL-bar scraping, ACTION_SET_TEXT injection, clipboard-only TOTP. Complete. |
| [Plan: Mobile Onboarding](plan-mobile-onboarding.md) | Onboarding root flow for mobile clients (create new vault, provider clone, device enrollment). Slices 0-C complete. |
| [ADR 0007: passkey-rs Evaluation](plan-passkey-rs-evaluation.md) | Decision to adopt `passkey-rs` 0.5.x as the WebAuthn authenticator library |
| [ADR 0008: Desktop UI Stack Evaluation](plan-desktop-ui-evaluation.md) | WebView exit analysis: GPUI-CE, Ely, GPUI Kit evaluated (2026-10-03). Stay on Tauri v2 + SolidJS through 1.0; GPUI Kit is the only credible exit path. Decision triggers recorded. |
| [Feature Parity Matrix](feature-parity.md) | CLI/desktop/mobile capability matrix audited against source, 25 numbered gaps in five tracks, the CLI-first-class product principle, and the closed-gap ledger |
| [Plan: Encrypted Backup](plan-encrypted-backup.md) | The .bldbak passphrase-protected container spec (Argon2id + HKDF + age-style STREAM AES-256-GCM, golden vector, reference decryptor). Shipped 2026-10-05 |
| [Plan: Family Spaces](plan-family-spaces.md) | One family vault born team-shaped: purpose flag, minors, kit rules, approved departure, contest window, founding copy. Steps 1-8 landed backend-side |
| [Plan: Merged Search & Autofill](plan-merged-search.md) | G24: daemon fan-out over merge-eligible unlocked vaults with the personal_merge/merge_opt_in consent model. Steps 1-9 landed |
| [Plan: Mobile Second Vault](plan-mobile-second-vault.md) | Create a named personal vault from the phone switcher (FFI display_name, phase-scoped cancel). Shipped 2026-10-16 |
