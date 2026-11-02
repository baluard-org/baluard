# ADR 0021. Settings Split: Encrypted Identity and Public Display Preferences

> Status: Accepted (2026-06-26)

## Context

The legacy plaintext `meta/settings.json` was synchronized through Git and exposed the vault `slug`, language, theme, enrollment policy, favicon-fetch setting, and default URI matching strategy to anyone with read access to the remote. These fields are not secrets, but exposing vault metadata conflicts with the privacy goals of the password manager.

## Decision

Settings are split between two files:

- `meta/settings-pub.json` is plaintext and readable before unlock. It contains only `theme` and `lang`, which the login screen needs before the master password is entered.
- `meta/settings.enc` is encrypted with AES-256-GCM under the root key through `derive_settings_key`. It contains `vault_timeout`, `default_uri_match`, `fetch_favicons`, `slug`, and `enrollment_policy`. No pre-unlock consumer needs these values. The encryption pattern matches `profile.enc`, `folders.enc`, and `tags.enc`.

The runtime uses the `.baluard` marker and vault registry as the authoritative sources for routing, never `settings.json`. The settings copy of `slug` is populated at creation and is not read for routing or display, so it can be encrypted.

The language preference previously appeared in both plaintext `settings.json` and `meta/locale`. Both values are consolidated into `settings-pub.json`; `meta/locale` is deprecated and migrated on read.

On the first `save_settings` after the split, the legacy `settings.json` is read through a fallback path, split into the two new files, and deleted. `get_settings` reassembles the complete `VaultSettings` structure from both new files, with a legacy fallback so callers remain unchanged.

The split does not alter `kdf-params.json`, whose salt and cost are public by design and cannot be encrypted without circularity; `recovery.json`, which contains an HPKE-wrapped blob and public keys; or `keywrap/*.json`, which contains wrapped material.

The rule for placing a field is whether any consumer needs it before unlock. A field with no pre-unlock consumer belongs in `settings.enc`; only a field the login screen must read before the master password is entered may live in plaintext. The remaining plaintext fields are a deliberate residual leak to anyone with read access to the remote: the theme and the language.

## Consequences

Only theme and language remain plaintext for pre-unlock use by this decision. Identity and policy settings are encrypted at rest in the Git-synchronized vault. The first save after the split performs the legacy-file conversion; callers continue to receive a complete `VaultSettings` value. Theme and language are still visible to the remote operator, which is accepted because the login screen needs them before unlock.

Later records extend the plaintext file and must be read with this one:

- `settings-pub.json` also carries the Space classification fields, the `space` flag and the `purpose` enum (ADR 0032, ADR 0086), because they must be readable before unlock. They are non-secret classification, but they are a second deliberate plaintext leak. Writers of this file (`save_settings`, `save_locale`) must merge with the existing JSON and preserve unknown keys, because an earlier version rebuilt the file and silently dropped the space flag (ADR 0032).
- `settings.enc` now also holds per-device display names, keyed by device id (the device registry is Git-tracked, and a name such as "Esteban's laptop" is personal data, so it moved into the encrypted file).
- Writes to settings and locale on a Space are limited to the managing device (ADR 0060), including the pre-unlock locale write, so that a member device cannot create a commit that peers refuse.
- Settings migration is one-way and happens on first save: a vault that still holds `settings.json` is converted and the plaintext file is deleted. Until that first save, readers fall back to the legacy file so that callers are unaffected.

## References

- `meta/settings-pub.json`
- `meta/settings.enc`
- `meta/locale` (deprecated, migrated on read)
- `derive_settings_key`
- `.baluard` marker and vault registry
- ADR 0016 for `meta/profile.enc`, which follows the same encryption pattern.
- ADR 0032, ADR 0060, and ADR 0086 for the later plaintext fields and write rules.
