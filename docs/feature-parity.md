# Feature parity: CLI / Desktop / Mobile

Snapshot: 2026-10-03, main @ `92e91ae`. Owner: Esteban.

## Purpose

One place that states which features exist on which surface, so parity gaps can be decided and closed one by one. Desktop is the reference surface: it carries the full product. CLI and Mobile trail by design in places, and those places need a decision: close the gap, park it, or declare it out of scope.

## Surfaces

- CLI (`crates/baluard-cli`): daemon-first with `--direct` fallback. Power-user escape hatch, scriptable, English only.
- Desktop (Tauri v2 + SolidJS): the complete product. Windows, macOS, Linux.
- Mobile (Kotlin Multiplatform, Compose): Android shipped, iOS pending platform work. Shares the Rust core through UniFFI.

## How to read this document

Status words: **Yes** = shipped. **Partial** = shipped with a stated limit. **None** = absent. **n/a** = does not apply to that surface. Every cell was checked against source (CLI command enums, UniFFI exports, `VaultRepository` methods, desktop components, i18n strings) on the snapshot date. Cells marked "(not audited)" need a check before any decision that relies on them.

## Matrix

### Vault lifecycle and security

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Create vault (wizard) | Yes (flags + interactive) | Yes | Yes |
| Recovery phrase shown at creation | Yes | Yes | Yes |
| Phrase sheet export (TXT + PDF) | None (deferred, D77) | Yes | Yes (creation only) |
| Unlock with master password | Yes | Yes | Yes |
| Biometric quick unlock | n/a | Yes (Touch ID; Windows Hello planned) | Yes (Android; iOS pending) |
| Session PIN unlock | n/a | Yes (Linux, Windows) | None |
| Auto-lock timer | Yes (`settings set`) | Yes | Yes |
| Phrase rotation ceremony | None | Yes | None |
| Space Recovery Kit | None | Yes | None |
| Emergency escrow (S4) | None | Yes | None |
| Enroll this device | None | Yes | Yes (phrase enrollment) |
| Device fleet (list / revoke / rotate) | Partial (list only) | Yes | Partial (enroll only) |

### Entries

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Cipher CRUD (8 types) | Yes | Yes | Yes |
| Favorites | Yes (via edit) | Yes | Yes |
| Folders | Yes | Yes | Yes |
| Tags | Yes | Yes | Yes |
| Trash + restore | Partial (no restore command found) | Yes | Yes |
| Archive | Yes | Yes | Yes |
| Attachments | Yes (upload, download, list, delete) | Yes | Partial (view only) |
| TOTP code | Partial (printed by get/list) | Yes | Yes |
| Passkeys: view | Yes (list) | Yes | Yes |
| Passkeys: delete / rename | Yes | Yes (delete; rename via CLI) | None |
| Passkey ceremonies (register / assert) | None | Partial (routes live, UI arrives with extension Phase 2) | None |
| SSH key entry (store) | Yes | Yes | Yes |
| SSH key generation | None | Yes | Yes |
| Import (8 formats) | Yes (bw-json, bw-csv, chrome-csv, firefox-csv, lastpass-csv, 1password-1pux, 1password-csv, keepass-xml) | Yes | None |
| Export (bw-json, bw-csv) | Yes | Yes | None |
| Password + passphrase generator | None | Yes | Yes |
| Re-prompt on sensitive fields | n/a | Yes | (not audited) |

### Sync and multi-vault

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Git remote setup | Yes (`sync init`, `sync remote`) | Yes | Yes |
| Manual sync cycle | Yes | Yes | Yes |
| Auto-sync | None (manual only) | Yes (debounced push, event pull) | Partial (pull on open, background fetch) |
| Conflict resolution | Partial (auto keep-local) | Yes | Partial (not audited) |
| Provider OAuth device flow | None | Yes | Yes |
| PAT connect | None | Yes | Yes |
| Provider repo picker | None | Yes | Yes |
| Clone from provider | Yes (URL) | Yes | Yes |
| Multi-vault (switch, close, prune, detach) | Yes | Yes | Yes |
| Offline state | Yes | Yes | Yes |

### Sharing and Spaces

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Space create / flip | None | Yes | Yes |
| Members (invite, remove, transfer, claim, reset) | None | Yes | Yes |
| Join approvals | None | Yes | Yes |
| Collections CRUD + grants | None | Yes | Yes |
| Access asks / requests | None | Yes | Yes |
| Space settings (all knobs) | Partial (`settings` covers 3 keys only) | Yes | Yes |
| Policies | None | Yes | Yes |
| Approvals / quorum | None | Yes | Yes |
| Activity log | None | Yes | Yes |
| Contact cards + outbox publish | None | Yes | None |
| Open shared reveal (guest / contact file) | None | Yes | None |
| Guest reveal create | None | Yes | None |

### Autofill and platform

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Browser extension (Chrome, Firefox) | n/a | Yes (Phase 1) | n/a |
| Android system autofill | n/a | n/a | Yes |
| Android accessibility tile | n/a | n/a | Yes |
| iOS autofill credential provider | n/a | n/a | None (Phase 7, next) |
| Languages (en / es / pt) | None (English only) | Yes | Yes |

## Gaps

Effort: S = a day or less, M = 2 to 4 days, L = a week or more. Value states who needs it and why.

### G1. CLI space settings knobs
Surface: CLI. Missing: `settings set` accepts only `vault_timeout`, `theme`, `default_uri_match`. The space knobs (guest sharing, invite authority, viewer export, trash policy, join approval, quorum, collection authority) and `lang` / `fetch_favicons` have no CLI path. Effort: S (extend the `match` in `handle_settings_set`). Value: headless administration of a shared space. Decision: close.

### G2. Mobile import / export
Surface: Mobile. Missing: no import of the 8 formats, no export. Effort: M (parsers already live in core; the work is UI + file access). Value: the largest real user gap. Migration onto the product is desktop-only today; users on phones cannot leave or arrive. Decision: close.

### G3. Mobile phrase rotation ceremony
Surface: Mobile. Missing: no rotation UI, no Recovery Kit surface. A user who created a vault on a phone must rotate on desktop. Effort: M to L (ceremony flow + kit export reuse). Value: security lifecycle parity; recovery independence per platform. Decision: close.

### G4. Mobile open shared reveals
Surface: Mobile. Missing: cannot open a guest or contact reveal file. Effort: S. Value: a phone receives the share file; it should open it. Decision: close.

### G5. Mobile device fleet management
Surface: Mobile. Missing: fleet list, revoke, rotate. Enrollment exists. Effort: S to M. Value: lost-phone response without a desktop. Decision: close.

### G6. Mobile emergency escrow + Recovery Kit
Surface: Mobile. Missing: escrow and kit surfaces. Effort: M. Value: full S4 lifecycle on phones. Decision: needed - close now or park behind G3.

### G7. CLI utility commands (generator, TOTP, SSH generation)
Surface: CLI. Missing: password / passphrase generation, standalone TOTP code, SSH key generation (storage exists). Effort: S as a bundle. Value: scripting and headless workflows. Decision: close.

### G8. CLI provider connect
Surface: CLI. Missing: OAuth device flow and PAT connect; clone works by URL only. Effort: M. Value: headless sync setup. Decision: close (URL-only is the documented workaround meanwhile).

### G9. CLI rotation
Surface: CLI. Missing: `rotate_root_key` and revoke path. Effort: M. Value: headless incident response. Decision: close.

### G10. Mobile passkey ceremonies
Surface: Mobile. Missing: register / assert. Platform WebAuthn APIs make this the hardest mobile item. Effort: L. Value: real, but display-only may be the right 1.0 scope. Decision: needed - park or schedule after 1.0.

### G11. CLI sharing surface
Surface: CLI. Missing: every sharing command. Effort: L. Value: only if the CLI is meant to administer shared spaces. Decision: needed - this decides what the CLI is for. If the CLI stays an escape hatch for personal vaults, declare out of scope and remove the row's weight.

### G12. iOS depth
Surface: Mobile. Missing: autofill provider (Phase 7) plus the iOS actuals behind several partial cells above. Effort: L. Value: the second mobile platform. Decision: already planned as Phase 7; the remaining iOS actuals ride along.

## Recommended order

1. G1 (S) - smallest, unlocks headless admin.
2. G2 (M) - largest user-facing gap.
3. G4, G5 (S) - phone becomes self-sufficient for daily incidents.
4. G7 (S) - completes the CLI toolkit.
5. G3, G8, G9 (M) - security lifecycle parity.
6. Decision items: G11 first (defines the CLI), then G6, G10, G12.

## Out of parity scope by design

- CLI as a GUI: no themes, languages, or autofill.
- Browser extension Phase 2 (passkey ceremony, QR cross-device assertion): tracked in the browser extension plan, not here.
- Desktop-only platform features (Touch ID, Windows Hello, tray) stay platform features.
- iOS lags Android until Phase 7 lands; rows already say so.

## Keeping this document current

1. Re-run the five inventories: CLI command enums (`crates/baluard-cli/src/main.rs`), UniFFI exports (`crates/baluard-uniffi/src/lib.rs`), `VaultRepository` methods, `ls desktop/src/components/`, i18n string keys.
2. Update the snapshot line at the top.
3. Move closed gaps into a "Closed" list at the bottom with the commit that closed them.
4. Any row change needs a source reference in the commit message.
