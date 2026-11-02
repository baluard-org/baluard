# ADR 0028. Android Autofill & Quick-Settings Accessibility Architecture

> Status: Accepted (2026-09-16)

## Context

Android autofill must evaluate credentials without disturbing the main Compose UI, must survive the low-memory killer, and must not expose passwords during matching. Some browsers and apps do not support standard autofill. This was recorded as D25.

## Decision

- **Isolated service process.** `BaluardAutofillService` runs under `android:process=":autofill"` to separate credential evaluation from the main Compose UI.
- **OOM-guard invariant.** Unlock inside `:autofill` uses only `unlock_with_kek` with the biometric-gated KEK from the Android Keystore. The Argon2id master-password KDF (64 to 256 MB) never runs in `:autofill`.
- **Rust-native URI matching.** `UriMatchStrategy::matches` is implemented in `baluard-core` with 6 strategies: BaseDomain (through `public-suffix` eTLD+1), Host, StartsWith, Exact, RegularExpression, and Never. It enforces scheme isolation (`androidapp://` never cross-matches `https://`) and treats trailing slashes as segment boundaries.
- **Secret-absence batch query.** `VaultState::autofill_query` filters login ciphers and returns candidate metadata without passwords or "password" JSON keys. Plaintext credentials cross FFI only on explicit dataset selection.
- **Response-level authentication.** Cold sessions render an "Unlock Baluard" placeholder. User interaction launches a transparent `AutofillActivity` that runs a `BiometricPrompt` with `CryptoObject` before matched datasets are shown.
- **Presentation modes.** Both inline IME keyboard suggestions (`supportsInlineSuggestions`, default INLINE) and dropdown `RemoteViews` are supported.
- **Secure save handoff.** `onSaveRequest` writes a single-use token (`AutofillSaveToken`) to app sandbox storage before launching `MainActivity`. This protects credential creation from intent spoofing across all supported Android API levels.
- **Accessibility fill tile fallback.** `BaluardA11yTileService` and `BaluardAccessibilityService` provide an opt-in fill flow for browsers and apps without standard autofill support. The flow scrapes browser URL bars, presents an in-process picker (`AutofillA11yBridge`), injects credentials with `ACTION_SET_TEXT`, copies TOTP to the clipboard, and bounds retries to 3 attempts per selection.

## Consequences

Process isolation keeps credential evaluation off the main UI process, and the OOM-guard invariant prevents the Android low-memory killer from terminating `:autofill` during the Argon2id derivation.

## References

- `docs/adr/0090-android-autofill.md` and `docs/adr/0091-android-accessibility-tile.md` for requirements and verification
