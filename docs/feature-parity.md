# Feature parity: CLI / Desktop / Mobile

Snapshot: 2026-10-03, main @ `92e91ae`, second audit pass (every cell re-verified against source, then cross-checked by an independent peer audit). Owner: Esteban.

## Purpose

One place that states which features exist on which surface, so parity gaps can be decided and closed one by one. Desktop is the reference surface: it carries the full product. CLI and Mobile trail by design in places, and those places need a decision: close the gap, park it, or declare it out of scope.

## Surfaces

- CLI (`crates/baluard-cli`): daemon-first with `--direct` fallback. Power-user escape hatch, scriptable, English only.
- Desktop (Tauri v2 + SolidJS): the complete product. Windows, macOS, Linux.
- Mobile (Kotlin Multiplatform, Compose): Android shipped, iOS pending platform work. Shares the Rust core through UniFFI.

## How to read this document

Status words: **Yes** = shipped. **Partial** = shipped with a stated limit. **None** = absent. **n/a** = does not apply to that surface. Every cell was checked against source (CLI command enums and handlers, UniFFI exports, `VaultRepository` methods, desktop components and their daemon calls, i18n strings) on the snapshot date.

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
| Space Recovery Kit | Partial (recover with an existing kit phrase; no kit management) | Yes | None |
| Emergency escrow (S4) | None | Yes | None |
| Enroll this device | Yes (phrase enrollment) | Yes | Yes (phrase enrollment) |
| Device fleet (list / revoke / rotate) | Yes (list, revoke, rotation status + abort) | Yes | None |
| Search and filters | None (`get` accepts an id prefix only) | Yes (category, folder, tag, deep search) | Yes (deep search over content, URIs, notes, custom fields) |
| Password health report | Yes (`baluard health`) | None | None |

### Entries

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Cipher CRUD (8 types) | Yes | Yes | Yes |
| Favorites | Yes (via edit) | Yes | Yes |
| Folders | Yes | Yes | Yes |
| Tags | Yes | Yes | Yes |
| Trash + restore | Partial (no restore, no list-trash, no purge) | Yes | Yes |
| Empty trash (purge all) | None | Yes | Yes |
| Archive | Yes | Yes | Yes |
| Attachments | Yes (upload, download, list, delete) | Yes | Partial (view only) |
| TOTP code | Partial (code printed by `get` / `list` in daemon mode; no standalone command) | Yes | Yes |
| Passkeys: view | Yes (list) | Yes | Yes |
| Passkeys: delete / rename | Yes | Partial (delete only) | None |
| Passkey ceremonies (register / assert) | None | Partial (routes live, UI arrives with extension Phase 2) | None |
| SSH key entry (store) | Yes | Yes | Yes |
| SSH key generation | None | Yes | Yes |
| Custom fields | Partial (raw JSON on `add` only, no flags) | Yes (all 4 types) | Yes (all 4 types) |
| Import (8 formats) | Yes (bw-json, bw-csv, chrome-csv, firefox-csv, lastpass-csv, 1password-1pux, 1password-csv, keepass-xml) | Yes | None |
| Export (bw-json, bw-csv) | Yes | Yes | None |
| Password + passphrase generator | None | Yes | Yes |
| Generator history | None | Yes | None |
| Password history view | Partial (present in `get --output json`) | None | None |
| Re-prompt on sensitive fields | n/a | Yes | Partial (flag saved on edit, never enforced on view) |
| Favicons (website icons) | None | Yes | Yes (opt-in, fetched on save) |
| Vault avatar / profile picture | None | Yes | None |

### Sync and multi-vault

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Git remote setup | Yes (`sync init`, `sync remote`) | Yes | Yes |
| Manual sync cycle | Yes | Yes | Yes |
| Auto-sync | None (manual only) | Yes (debounced push, event pull) | Partial (pull on open, background fetch) |
| Conflict resolution | None (conflicts error out) | Yes | Yes |
| Provider OAuth device flow | None | Yes | Yes |
| PAT connect | None | Yes | Yes |
| Provider repo picker | None | Yes | Yes |
| Repo creation on provider | None | Yes | None |
| Clone from provider | Yes (by provider + repo, or URL) | Yes | Yes |
| Remote repoint / migrate | Yes (`vaults repoint`) | Yes (`space.migrate`) | None |
| Commit revocation (signed manifest) | Yes (`sync revoke`) | None | None |
| Multi-vault (switch, close, prune, detach) | Yes | Yes | Partial (switch only) |
| Offline state | Yes | Yes | Yes |

### Sharing and Spaces

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Space create / flip | None | Yes | Yes |
| Members (invite, remove, transfer, claim, reset) | None | Yes | Yes |
| Join approvals | None | Yes | Yes |
| Space user groups | None | Yes | None |
| Collections CRUD + grants | None | Yes | Yes |
| Access asks / requests | None | Yes | Yes |
| Space settings (all knobs) | None (the `settings` keys are client preferences, not space knobs) | Yes | Yes |
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
Surface: CLI. Missing: the space knobs (guest sharing, invite authority, viewer export, trash policy, join approval, quorum, collection authority) have no CLI path; `settings set` covers client preferences only. Effort: S (a `settings space set` surface over the daemon's space-settings routes). Value: headless administration of a shared space. Decision: close.

### G2. Mobile import / export
Surface: Mobile. Missing: no import of the 8 formats, no export. Effort: M (parsers already live in core; the work is UI + file access). Value: the largest real user gap. Migration onto the product is desktop-only today; users on phones cannot leave or arrive. Decision: close.

### G3. Mobile phrase rotation ceremony
Surface: Mobile. Missing: no rotation UI, no Recovery Kit surface. A user who created a vault on a phone must rotate on desktop. Effort: M to L (ceremony flow + kit export reuse). Value: security lifecycle parity; recovery independence per platform. Decision: close.

### G4. Mobile open shared reveals
Surface: Mobile. Missing: cannot open a guest or contact reveal file. Effort: S. Value: a phone receives the share file; it should open it. Decision: close.

### G5. Mobile device fleet management
Surface: Mobile. Missing: fleet list, revoke, rotate (enrollment exists). Revocation triggers a full rekey on-device, so the crypto path is heavy and the flow needs care. Effort: M to L. Value: lost-phone response without a desktop. Decision: close.

### G6. Mobile emergency escrow + Recovery Kit
Surface: Mobile. Missing: escrow and kit surfaces. Effort: M. Value: full S4 lifecycle on phones. Decision: needed - close now or park behind G3.

### G7. CLI utility commands (generator, TOTP, SSH generation, list search)
Surface: CLI. Missing: password / passphrase generation, standalone TOTP code command, SSH key generation (storage exists), `list --search`. Effort: M (three command trees plus a filter flag; not a one-day bundle). Value: scripting and headless workflows. Decision: close.

### G8. CLI provider connect
Surface: CLI. Missing: OAuth device flow and PAT connect. Cloning already works by provider + repo using daemon-stored tokens; what is missing is the interactive connect step, so a fresh headless machine cannot attach its own credentials. Effort: M. Value: headless sync setup without borrowing a desktop. Decision: close.

### G9. CLI rotation without revocation
Surface: CLI. Missing: standalone `rotate_root_key`. Device revoke (which rotates as a side effect) already exists. Effort: M. Value: scheduled key rotation and incident response that keeps all devices enrolled. Decision: close.

### G10. Mobile passkey ceremonies
Surface: Mobile. Missing: register / assert. Platform WebAuthn APIs make this the hardest mobile item. Effort: L. Value: real, but display-only may be the right 1.0 scope. Decision: needed - park or schedule after 1.0.

### G11. CLI sharing surface
Surface: CLI. Missing: every sharing command (members, approvals, collections, groups, policies, activity). Effort: L. Value: only if the CLI is meant to administer shared spaces. Decision: needed - this decides what the CLI is for. If the CLI stays an escape hatch for personal vaults, declare out of scope.

### G12. iOS depth
Surface: Mobile. Missing: autofill provider (Phase 7) plus the iOS actuals behind several partial cells above. Effort: L. Value: the second mobile platform. Decision: already planned as Phase 7; the remaining iOS actuals ride along.

### G13. Space user groups on mobile
Surface: Mobile. Missing: group CRUD and membership (desktop has the full GroupsTab). Effort: M. Value: batch access management for larger spaces on phones. Decision: close after G3/G5, or with G11's CLI part if the CLI becomes an admin surface.

### G14. CLI trash surface
Surface: CLI. Missing: list trash, restore, purge. Effort: S. Value: scripting cleanup; parity with both GUIs. Decision: close.

### G15. Mobile vault detach / prune
Surface: Mobile. Missing: drop a vault from the list, prune stale vaults (both GUIs have it; the destructive delete arm stays desktop/CLI by design). Effort: S. Value: unclutter the vault list after a vault is removed elsewhere. Decision: close.

### G16. Repo creation on provider (mobile, then CLI)
Surface: Mobile + CLI. Missing: `provider.create_repo` (desktop-only today). Effort: S on CLI (route + flag), M on mobile (wizard step). Value: first-run setup without a desktop. Decision: close; CLI part rides with G8.

### G17. Desktop passkey rename UI
Surface: Desktop. Missing: rename exists on CLI only. Effort: S. Value: naming credentials is a daily-use nicety. Decision: close.

### G18. Mobile re-prompt enforcement
Surface: Mobile. Missing: the flag saves but nothing enforces it on view or reveal. Effort: S to M. Value: security parity with desktop's RepromptModal; a silent unenforced security flag is worse than none. Decision: close.

### G19. Password health on desktop and mobile
Surface: Desktop + Mobile. Missing: the `vault.health` report (weak, reused, old passwords) has no GUI surface anywhere. Effort: M. Value: the CLI should not be the only place users learn their passwords are weak. Decision: close after 1.0 or schedule with the 1.0 polish pass.

### G20. Generator history on mobile
Surface: Mobile. Missing: history drawer (UniFFI bindings already exist). Effort: S. Value: recovering a generated password you did not save yet. Decision: close.

### G21. Vault avatar on mobile
Surface: Mobile. Missing: set / view vault avatar (desktop-only today). Effort: S to M. Value: multi-vault recognition on the list screen. Decision: close.

### G22. Password history view
Surface: Desktop + Mobile. Missing: no GUI renders `password_history` (CLI exposes it in JSON). Effort: S. Value: "what was the old password" is a real support question. Decision: close.

### G23. Mobile admin ops: repoint / migrate, commit revocation
Surface: Mobile. Missing: remote repoint and signed-manifest revocation. Effort: S each. Value: recovery from a bad remote without a desktop. Decision: fold into G5's admin surface or park.

## Recommended order

1. G1 (S), G14 (S), G17 (S), G20 (S) - small closes, immediate parity wins.
2. G2 (M) - largest user-facing gap.
3. G4 (S), G15 (S), G18 (S-M) - the phone becomes self-sufficient for daily incidents and honest security flags.
4. G7 (M), G16 (M) - completes the CLI toolkit and first-run setup.
5. G3, G5, G8, G9 (M-L) - security lifecycle and headless setup parity.
6. Decision items: G11 first (defines the CLI), then G6, G10, G12, G13, G19, G21, G22, G23.

## Out of parity scope by design

- CLI as a GUI: no themes, languages, avatars, or autofill.
- Browser extension Phase 2 (passkey ceremony, QR cross-device assertion): tracked in the browser extension plan, not here.
- Desktop-only platform features (Touch ID, Windows Hello, tray) stay platform features.
- iOS lags Android until Phase 7 lands; rows already say so.
- CLI-only by usefulness, not by omission: commit revocation lives where signed history is audited. If G11 makes the CLI an admin surface, revisit.

## Keeping this document current

1. Re-run the six inventories: CLI command enums and handlers (`crates/baluard-cli/src/main.rs`, `commands/mod.rs`), daemon route dispatcher (`crates/baluard-daemon/src/handler.rs`), UniFFI exports (`crates/baluard-uniffi/src/lib.rs`), `VaultRepository` methods and screens, desktop components and their daemon calls, i18n string keys.
2. Update the snapshot line at the top.
3. Move closed gaps into a "Closed" list at the bottom with the commit that closed them.
4. Any row change needs a source reference in the commit message.
