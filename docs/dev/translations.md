# Translations & Localization

This document describes how to add and maintain translations across Baluard desktop and mobile clients.

## Overview

Baluard supports multi-language localization on both Desktop (SolidJS) and Mobile (Compose Multiplatform). All user-facing strings stay isolated in dedicated locale files. Automated parity tests verify that every language exposes the complete key set before changes merge.

### Supported Languages

| Code | Language | Desktop | Mobile | Android Resources |
|------|----------|---------|--------|-------------------|
| `en` | English (Source of truth) | `desktop/src/i18n/locales/en.json` | `mobile/.../i18n/StringsEn.kt` | `values/strings.xml` |
| `es` | Spanish | `desktop/src/i18n/locales/es.json` | `mobile/.../i18n/StringsEs.kt` | `values-es/strings.xml` |
| `pt` | Portuguese (Brazil focus) | `desktop/src/i18n/locales/pt.json` | `mobile/.../i18n/StringsPt.kt` | `values-pt/strings.xml` |

## Architecture

Desktop and mobile platforms use different runtime localization mechanisms while keeping identical key naming conventions.

### Desktop Architecture

Desktop translations live in `desktop/src/i18n/locales/*.json`.
The runtime `desktop/src/i18n/index.jsx` loads English synchronously and imports non-English locale files dynamically on demand.
The `t(key, vars)` helper flattens JSON objects into dot-separated paths (for example, `login.passwordPlaceholder`).
Variables use `{name}` syntax and replace matching keys from the passed object.
Plural strings use the `_plural` suffix (for example, `entryCount` and `entryCount_plural`).
The key parity test `desktop/src/__tests__/i18n-parity.test.js` flattens all locales and asserts identical key sets against `en.json`.

### Mobile Architecture

Mobile translations live in `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/`.
The source of truth map is `EN` in `StringsEn.kt`. Additional languages define parallel maps (`ES` in `StringsEs.kt`, `PT` in `StringsPt.kt`).
The `I18n` singleton in `I18n.kt` tracks the active language as Compose mutable state so UI components recompose on language change.
The `t(key, vararg args)` function replaces `{0}`, `{1}`, and sequential positional tokens with passed arguments.
System-level strings for Android services (such as accessibility autofill and quick settings tiles) live in `mobile/androidApp/src/main/res/values-<lang>/strings.xml`.
The test `mobile/shared/src/commonTest/kotlin/xyz/actitud/baluard/i18n/I18nParityTest.kt` verifies that all dictionary maps contain the exact same keys as `EN`.

## Adding a Language to Desktop

Follow these steps to add a new language to the desktop application:

1. Copy `desktop/src/i18n/locales/_template.json` (or `en.json`) to `desktop/src/i18n/locales/<lang>.json` where `<lang>` is the two-letter ISO 639-1 language code.
2. Translate all string values. Keep all keys, nesting, and dot paths exactly identical to `en.json`.
3. Preserve all variable placeholders such as `{count}`, `{name}`, `{slug}`, and `{provider}`.
4. Provide both singular and plural forms for keys that support counts (for example, `entryCount` and `entryCount_plural`).
5. Register the language in `desktop/src/components/CreateVaultScreen.jsx`:
   - Add `{ code: "<lang>", label: "<Language Name>" }` to `AVAILABLE_LOCALES`.
   - Add `"<lang>"` to the supported list in `detectOsLocale()`.
6. Add the new language row to the table in `desktop/src/i18n/locales/README.md`.
7. Add a parity assertion to `desktop/src/__tests__/i18n-parity.test.js`:
   - Import the new JSON file.
   - Add an `it("en.json and <lang>.json expose the same dot-path key set")` test block.
8. Run tests with `npm test` inside `desktop/` to verify parity.

## Adding a Language to Mobile

Follow these steps to add a new language to the mobile application:

1. Create `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/Strings<Lang>.kt`.
2. Define `internal val <LANG>: Map<String, String> = mapOf(...)` matching all keys in `StringsEn.kt`.
3. Translate all string values. Keep all positional placeholders such as `{0}` and `{1}` intact.
4. Register the new dictionary in `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/I18n.kt`:
   - Add `"<lang>" to <LANG>` to the private `DICTS` map.
   - Update documentation comments on `language` code examples.
5. Create Android system string resources in `mobile/androidApp/src/main/res/values-<lang>/strings.xml`:
   - Translate `accessibility_service_description`, `a11y_service_label`, and `a11y_tile_label`.
6. Add parity test coverage to `mobile/shared/src/commonTest/kotlin/xyz/actitud/baluard/i18n/I18nParityTest.kt`:
   - Add a test verifying `EN.keys - <LANG>.keys` and `<LANG>.keys - EN.keys` are empty.
7. Run tests with `./gradlew testDebugUnitTest` inside `mobile/`.

## Translation Guidelines

Maintain consistency and clarity across all translations:

- **Audience**: Baluard targets non-technical users. Avoid technical jargon whenever plain language works. Explain concepts clearly (see the `gitWhat` explainer section).
- **Core terminology**:
  - `vault`: Use standard regional terms ("bóveda" in Spanish, "cofre" in Portuguese).
  - `master password`: Use clear equivalents ("contraseña maestra" in Spanish, "senha mestra" in Portuguese).
  - `recovery phrase`: Use "frase de recuperación" (es) / "frase de recuperação" (pt).
  - `quick unlock`: Use "desbloqueo rápido" (es) / "desbloqueio rápido" (pt).
- **Punctuation rules**: Do not use em-dashes. Use colons, parentheses, commas, or periods instead.
- **Safety checks**: Validate JSON syntax with `jq . <file>.json` before submitting.

## Verification Checklist

Before opening a pull request for a new translation, run the following checks:

- [ ] All keys in `desktop/src/i18n/locales/en.json` exist in `desktop/src/i18n/locales/<lang>.json`.
- [ ] Desktop test passes: `cd desktop && npm test`.
- [ ] All keys in `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEn.kt` exist in `Strings<Lang>.kt`.
- [ ] Mobile test passes: `cd mobile && ./gradlew testDebugUnitTest`.
- [ ] Android strings file exists at `mobile/androidApp/src/main/res/values-<lang>/strings.xml`.
- [ ] Full project check passes: `just check`.
