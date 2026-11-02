# ADR 0020. Vault Creation Wizard

> Status: Accepted (completed 2026-06-10); the desktop step 3 has since changed, see Consequences

## Context

Vault creation needs to collect profile and preference information in the CLI and desktop flows. The desktop collects profile information after `vault.create`, while the CLI can include it in the builder before execution. The creation payload of `vault.create` therefore cannot carry the profile on desktop, which is why the two paths differ.

## Decision

The CLI chains profile and preferences into the `VaultCreator` builder before calling `execute()`. The desktop creates the vault first, then applies profile and preferences through separate `settings.set` and `locale.save` IPC calls.

The schema uses a case-insensitive `ThemeMode` enum with `Light`, `Dark`, and `System`, replacing `Option<String>` for `VaultSettings.theme`. `VaultSettings` also has a `lang` field. `VaultHandle::save_locale()` and `load_locale()` handle the language preference. Since 2026-06-26, `lang` and `theme` are stored together in plaintext `meta/settings-pub.json`; the former `meta/locale` sidecar is deprecated and migrated on read. The `locale.save` daemon route writes this file so the login screen can read the language before unlock.

The CLI command `baluard init` supports `--profile`, `--name`, `--slug`, `--theme`, `--lang`, and `--auto-lock`. Here `--profile` selects the KDF cost profile (`mobile-low`, `desktop-std`, `desktop-high`), not the user profile; the display name is `--name`. The `--subtitle` flag was removed on 2026-06-11 once the profile step absorbed it, and it is not supported. Locale detection uses `$LANGUAGE` (which may be colon-separated), then `$LC_ALL`, `$LC_MESSAGES`, and `$LANG`. A value such as `es_CL.UTF-8` reduces to `es`, only `en` and `es` are recognized, and the fallback is `en`. Interactive prompts are used on a TTY; piped input produces hard errors. The password must have at least eight characters; a shorter value is a hard error.

The desktop flow has three steps:

1. `CreateVaultScreen` selects a language, auto-detected from `navigator.language`, and collects the password.
2. `RecoveryScreen` displays and copies the recovery phrase, then transitions to `setup`.
3. `SetupScreen` collects profile fields, theme, and auto-lock settings. It uses `FocusTrap` and applies settings through IPC.

The auth state machine, as decided, has seven states (`locked`, `unlocking`, `unlocked`, `init`, `creating`, `recovery`, `setup`). The wizard path is `init -> creating -> recovery -> setup -> unlocked`; the `setup` state exists so that profile and preferences are applied before the vault is shown. Avatar selection is deferred to Settings because it is rarely urgent on first run.

Two failure and output choices were deliberate. A crash after vault creation but before profile writing is accepted, because the profile is cosmetic and a missing profile means defaults. The CLI prints the recovery phrase to stdout without a confirmation prompt, because a prompt would break piped and CI use. The recovery phrase is therefore shown exactly once and is the user's responsibility to record.

Language is persisted in plaintext `meta/settings-pub.json` as the single source because the login screen needs it before unlock. Before 2026-06-26 it was duplicated in encrypted settings and `meta/locale`; both were consolidated into `settings-pub.json`.

## Consequences

The desktop and CLI collect profile and preference data at different points in creation. A crash between desktop vault creation and profile persistence can leave default profile values. The recovery phrase can be piped from CLI stdout without an additional confirmation step. Pre-unlock language and theme remain readable in the public settings file.

The desktop flow has evolved since 2026-06-10, and the code is authoritative where it differs from the Decision above:

- A `welcome` state now precedes `init` (new vault, open a local vault, or download from a provider), so the auth table has eight states.
- Step 3 no longer collects profile fields, theme, or auto-lock. The daemon persists the display name from the vault name during `vault.create`, and `SetupScreen` applies the `system` theme and the selected locale through `settings.set` and `locale.save`. The screen then offers the optional connection to a Git provider for sync (ADR 0088). Profile and avatar are edited later in Settings.
- Family vault creation shows the Space Recovery Kit phrase once on the recovery screen, next to the vault phrase (ADR 0086), and the CLI exposes `--family` and `--json`.
- Every vault slug and remote repository name is normalized to carry the `baluard-` prefix at all entry points.
- The language and theme writers are subject to the managing-device write gate (ADR 0060), and `settings-pub.json` writers preserve unknown keys such as the space flag and purpose (ADR 0032).

## References

- ADR 0021 for the settings split that defines `settings-pub.json`.
- ADR 0012 for the auth provider, and ADR 0015 for `FocusTrap`.
- `VaultCreator`
- `VaultHandle::save_locale()`, `VaultHandle::load_locale()`
- `locale.save`
- `meta/settings-pub.json`
- `CreateVaultScreen`, `RecoveryScreen`, `SetupScreen`
