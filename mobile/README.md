# Baluard mobile

Compose Multiplatform (Android + iOS) client for Baluard.

# Baluard mobile

Compose Multiplatform (Android + iOS) client for Baluard.

**Status: Android Phases 0-5 implemented.** The Rust FFI layer, Kotlin ViewModels, and Compose UI are complete and verified. Verification on host builds includes Kotlin metadata compile and Android packaging via `just android-apk`. Phase 6 (Android Autofill Service) and iOS credential extension are next.

## Structure

- `shared/`: KMP module with Compose UI, ViewModels, `VaultRepository`, and generated UniFFI bindings
- `androidApp/`: Android host application (single-Activity Compose host, adaptive icons, Proguard/R8 rules)
- `scripts/`: Binding generation and helper scripts (`regen-bindings.sh`)

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
- **Vault Views**: Filtered entry lists (all items, favorites, folders, tags), detail view, and editing for all 8 cipher types.
- **Tools**: Password and passphrase generator, TOTP generator widget with boundary-aligned refresh.
- **Security**: Biometric unlock via BiometricPrompt ceremony, auto-lock on timer and backgrounding, screenshot protection toggle, and clipboard auto-clear.
- **Sync & Conflict**: Manual sync button with explicit progress phases, pull-on-unlock, push-after-mutation, and inline conflict resolution panel.
- **Multi-Vault**: Owner-prefixed vault slugs, per-vault clone directories, and home switch bar.
- **i18n**: English and Spanish translations.

## Pending Work

- Android Autofill Service (Phase 6)
- iOS AutoFill Credential Provider extension (Phase 7)
- Play Store and App Store packaging
