# Baluard mobile

Compose Multiplatform (Android + iOS) client for Baluard.

**Status: Android Phases 0-6 implemented, edit/create at desktop parity.** The Rust FFI layer, Kotlin ViewModels, Compose UI, and system autofill framework are complete and verified. Verification on host builds includes Kotlin metadata compile and Android packaging via `just android-apk`. Phase 7 (iOS credential extension) and store packaging are next.

## Structure

- `shared/`: KMP module with Compose UI, ViewModels, `VaultRepository`, and generated UniFFI bindings
- `androidApp/`: Android host application (single-Activity Compose host, `BaluardAutofillService`, `BaluardAccessibilityService`, `BaluardA11yTileService`, adaptive icons, Proguard/R8 rules)
- `scripts/`: Binding generation and helper scripts (`regen-bindings.sh`, `build-android-apk.sh`)

## Build

See [`docs/mobile-dev-setup.md`](../docs/mobile-dev-setup.md) for full prerequisites (Android SDK/NDK, OpenJDK 17) and environment setup.

```bash
just android-apk          # Build release Android APK
just android-apk-fast     # Build debug Android APK
just android-bindings     # Regenerate UniFFI bindings
```

## Implemented Features

- **Onboarding**: Create new vault with BIP-39 recovery phrase, or connect to Git providers (GitHub, GitLab, Codeberg) to clone and enroll devices.
- **Home Hub**: Categorized vault hub with lock state badge, cipher type badges, count pills, tags list, and vault switch bar.
- **Vault Views**: Filtered entry lists (all items, favorites, folders, tags), deep search matching every entry field (password excluded; trash and archived entries excluded), detail view, and editing for all 8 cipher types at desktop parity: URIs with match detection, TOTP seed, custom fields (Text/Hidden/Boolean/Linked), tags, folder, reprompt, configurable password generator, card number formatting with brand detection, SSH keypair generation, and favicon fetch-on-save (opt-in, Settings > Security).
- **Tools**: Password and passphrase generator, TOTP generator widget with boundary-aligned refresh.
- **Security**: Biometric unlock via BiometricPrompt ceremony, auto-lock on timer and backgrounding, screenshot protection toggle, and clipboard auto-clear.
- **Sync & Conflict**: Manual sync button with explicit progress phases, pull-on-unlock, push-after-mutation, and inline conflict resolution panel.
- **Multi-Vault**: Owner-prefixed vault slugs, per-vault clone directories, and home switch bar.
- **Autofill**: System autofill provider via `BaluardAutofillService` in an isolated `:autofill` process. Inline IME suggestions with dropdown menu fallback, response-level authentication with transparent `AutofillActivity` biometric unlock, save prompt on submission prefilling the create form, and per-vault URI match strategy (Domain/Host/StartsWith/Exact/Regex/Never) with scheme isolation. Quick-settings tile accessibility fill (`BaluardA11yTileService` + `BaluardAccessibilityService`) for apps and browsers without standard autofill support.
- **i18n**: English and Spanish translations.

## Pending Work

- iOS AutoFill Credential Provider extension (Phase 7)
- Play Store and App Store packaging
