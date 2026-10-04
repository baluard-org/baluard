# Feature parity: CLI / Desktop / Mobile

Snapshot: 2026-10-03, main @ `92e91ae`; second audit pass (every cell re-verified against source, then cross-checked by an independent peer audit), revised the same day with the CLI-first-class decision below. Owner: Esteban.

## Purpose

One place that states which features exist on which surface, so parity gaps can be decided and closed one by one. Desktop is the reference surface: it carries the full product. CLI and Mobile trail by design in places, and those places need a decision: close the gap, park it, or declare it out of scope.

## Surfaces

- CLI (`crates/baluard-cli`): daemon-first with `--direct` fallback. A first-class surface, not an escape hatch: scriptable, English only, and the first consumer of every new daemon route.
- Desktop (Tauri v2 + SolidJS): the complete product. Windows, macOS, Linux.
- Mobile (Kotlin Multiplatform, Compose): Android shipped, iOS pending platform work. Shares the Rust core through UniFFI.

## How to read this document

Status words: **Yes** = shipped. **Partial** = shipped with a stated limit. **None** = absent. **n/a** = does not apply to that surface. Every cell was checked against source (CLI command enums and handlers, UniFFI exports, `VaultRepository` methods, desktop components and their daemon calls, i18n strings) on the snapshot date.

## Product principle: CLI first-class, primitives jump

The daemon (`baluard-runtime`) is the shared brain; CLI, desktop, and mobile are clients over it (socket IPC or UniFFI). Therefore:

1. **Every daemon route must be reachable from all three surfaces.** A feature is not done while one surface cannot reach it. "None" cells in the matrix are debt, not scope choices.
2. **New features land daemon + CLI first, then desktop, then mobile.** The CLI is the cheapest, most testable surface and doubles as the executable spec of the daemon route.
3. **Primitives jump, flows do not.** A CLI command proves the logic and becomes the foundation the GUIs wrap; each UI still gets its own design pass. Proven already: the recovery sheet is one Rust renderer with three consumers, and `vault.health` + generator history are CLI-only primitives waiting for their GUI twins (G19, G20).

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
| Trash + restore | Yes (list, restore) | Yes | Yes |
| Empty trash (purge all) | Yes (`trash purge --days 0`) | Yes | Yes |
| Archive | Yes | Yes | Yes |
| Attachments | Yes (upload, download, list, delete) | Yes | Partial (view only) |
| TOTP code | Partial (code printed by `get` / `list` in daemon mode; no standalone command) | Yes | Yes |
| Passkeys: view | Yes (list) | Yes | Yes |
| Passkeys: delete / rename | Yes | Yes | None |
| Passkey ceremonies (register / assert) | None | Partial (routes live, UI arrives with extension Phase 2) | None |
| SSH key entry (store) | Yes | Yes | Yes |
| SSH key generation | None | Yes | Yes |
| Custom fields | Partial (raw JSON on `add` only, no flags) | Yes (all 4 types) | Yes (all 4 types) |
| Import (8 formats) | Yes (bw-json, bw-csv, chrome-csv, firefox-csv, lastpass-csv, 1password-1pux, 1password-csv, keepass-xml) | Yes | None |
| Export (bw-json, bw-csv) | Yes | Yes | None |
| Password + passphrase generator | None | Yes | Yes |
| Generator history | None | Yes | Yes |
| Password history view | Partial (present in `get --output json`) | Yes | Yes |
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
| Space settings (all knobs) | Yes (`settings space get` / `space-set`) | Yes | Yes |
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
Surface: CLI. Missing: OAuth device flow and PAT connect. Cloning already works by provider + repo using daemon-stored tokens; what is missing is the interactive connect step, so a fresh headless machine cannot attach its own credentials. Effort: M. Value: a first-class CLI must be self-sufficient on first run - setup cannot require borrowing a desktop. Decision: scheduled in the CLI parity track.

### G9. CLI rotation without revocation
Surface: CLI. Missing: standalone `rotate_root_key`. Device revoke (which rotates as a side effect) already exists. Effort: M. Value: scheduled key rotation and incident response that keeps all devices enrolled - the headless machine stays the security console, not a second-class device. Decision: scheduled in the CLI parity track.

### G10. Mobile passkey ceremonies
Surface: Mobile. Missing: register / assert. Platform WebAuthn APIs make this the hardest mobile item. Effort: L. Value: real, but display-only may be the right 1.0 scope. Decision: needed - park or schedule after 1.0.

### G11. CLI sharing surface (phased)
Surface: CLI. Missing: every sharing command (members, approvals, collections, groups, policies, activity). With the CLI first-class, this is in scope, in two phases:

- **Phase 1 (M) - the Bitwarden shape:** share an item to a space, collection list/assign, member list, member confirm. The item-level ops people actually script.
- **Phase 2 (L) - full admin:** invite, remove, roles, groups, policies, approvals, activity. Peer precedent: the 1Password CLI is a full admin surface (`user provision/confirm/suspend`, `group` CRUD, vault permission grants); the Bitwarden CLI deliberately keeps deep admin in the web console. A first-class Baluard CLI ships both phases - phase 2 may land just after 1.0.

Decision: committed (2026-10-03, Esteban). Phase 1 in the CLI parity track; phase 2 first item after 1.0.

### G12. iOS depth
Surface: Mobile. Missing: autofill provider (Phase 7) plus the iOS actuals behind several partial cells above. Effort: L. Value: the second mobile platform. Decision: already planned as Phase 7; the remaining iOS actuals ride along.

### G13. Space user groups on mobile
Surface: Mobile + CLI. Missing: group CRUD and membership (desktop has the full GroupsTab; CLI follows G11 phase 2). Effort: M. Value: batch access management for larger spaces on phones. Decision: close after G3/G5 on mobile; the CLI part rides with G11 phase 2.

### G14. CLI trash surface
Surface: CLI. Missing: list trash, restore, purge. Effort: S. Value: scripting cleanup; parity with both GUIs. Decision: close.

### G15. Mobile vault detach / prune
Surface: Mobile. Missing: drop a vault from the list, prune stale vaults (both GUIs have it; the destructive delete arm stays desktop/CLI by design). Effort: S. Value: unclutter the vault list after a vault is removed elsewhere. Decision: close.

### G16. Repo creation on provider (mobile + CLI)
Surface: Mobile + CLI. Missing: `provider.create_repo` (desktop-only today). Effort: S on CLI (route + flag), M on mobile (wizard step). Value: first-run setup without a desktop, on either client. Decision: close; CLI part rides with G8 in the CLI parity track.

### G17. Desktop passkey rename UI
Surface: Desktop. Missing: rename exists on CLI only. Effort: S. Value: naming credentials is a daily-use nicety. Decision: close.

### G18. Desktop + mobile re-prompt enforcement
Surface: Desktop + Mobile. Missing: the flag saves but nothing enforces it on view or reveal on either GUI. Effort: S to M. Value: security parity; a silent unenforced security flag is worse than none. Decision: close.

### G19. Password health on desktop and mobile
Surface: Desktop + Mobile. Missing: the `vault.health` report (weak, reused, old passwords) has no GUI surface anywhere. Effort: M, cheapened by the CLI-first rule - the primitive exists (`vault.health` route + `baluard health`), so this is UI wiring, not new logic. Value: the CLI should not be the only place users learn their passwords are weak. Decision: close after 1.0 or schedule with the 1.0 polish pass.

### G20. Generator history on mobile
Surface: Mobile. Missing: history drawer (UniFFI bindings already exist). Effort: S. Value: recovering a generated password you did not save yet. Decision: close.

### G21. Vault avatar on mobile
Surface: Mobile. Missing: set / view vault avatar (desktop-only today). Effort: S to M. Value: multi-vault recognition on the list screen. Decision: close.

### G22. Password history view
Surface: Desktop + Mobile. Missing: no GUI renders `password_history` (CLI exposes it in JSON). Effort: S. Value: "what was the old password" is a real support question. Decision: close.

### G23. Mobile admin ops: repoint / migrate, commit revocation
Surface: Mobile. Missing: remote repoint and signed-manifest revocation. Effort: S each. Value: recovery from a bad remote without a desktop. Decision: fold into G5's admin surface or park.

## Recommended order

1. **Small closes (S batch):** G1, G14, G17, G20, G22.
2. **Adoption (the phone stands alone):** G2 (import/export), G4 (open reveals), G15 (detach), G18 (reprompt enforcement).
3. **CLI parity track:** G7 (utilities), G16-CLI + G8 (repo creation and connect), G9 (rotation), G11 phase 1 (sharing). Each gap lands a daemon + CLI primitive that the desktop and mobile twins then wrap.
4. **Security lifecycle:** G3 (rotation ceremony), G5 + G23 (fleet and admin ops), G6 (escrow + kit).
5. **Post-1.0:** G11 phase 2 (full CLI admin), G10 (mobile passkey ceremonies), G12 (iOS depth), G13 (groups on mobile + CLI), G19 (health GUI), G21 (avatar).

## Out of parity scope by design

- CLI as a GUI: no themes, languages, avatars, or autofill.
- Browser extension Phase 2 (passkey ceremony, QR cross-device assertion): tracked in the browser extension plan, not here.
- Desktop-only platform features (Touch ID, Windows Hello, tray) stay platform features.
- iOS lags Android until Phase 7 lands; rows already say so.
- Commit revocation is CLI-first by usefulness, not by omission: signed history is audited where scripts run. G11 phase 1 brings the sharing item ops to the CLI; the full admin surface follows in phase 2.

## Closed

| Gap | Closed in | Note |
|---|---|---|
| G1 | `1d691ba` | `settings space get` / `space-set`; whitelist mirrors the daemon, quorum bound enforced CLI-side |
| G14 | `1d691ba` | `trash list` / `restore` / `purge --days`, daemon + `--direct` |
| G17 | `d27eceb` | inline rename on the passkey card; the route was missing from the desktop host allowlist, now admitted |
| G20 | `c0bc684` | generator history section over the existing UniFFI bindings |
| G22 | `d27eceb` + `c0bc684` | password history on desktop (collapsible, masked rows) and mobile (masked field rows) |
| G2 | this wave | mobile import (8 core formats via SAF open + format dialog) and export (bw-json / bw-csv via SAF create), bytes-only UniFFI wrappers over the same daemon-shaped runtime paths; review fixes: dedicated json/csv SAF contracts, scrolling format dialog |
| G18 | this wave | re-prompt enforced on both GUIs behind a 30s master-password grant. Review round made the gate REAL: verification rides `vault.reprompt_verify` / a new `repromptVerify` FFI (opening a temp handle), because `vault.unlock` short-circuits Ok on an already-unlocked vault and would have accepted any password; desktop gates all sensitive field classes (not just logins), edit flows are gated, autofill refuses reprompt-protected entries, and the modal's show() binds its callback at confirm time (fixing a dead wiring where the rotation gate never fired) |

## Keeping this document current

1. Re-run the six inventories: CLI command enums and handlers (`crates/baluard-cli/src/main.rs`, `commands/mod.rs`), daemon route dispatcher (`crates/baluard-daemon/src/handler.rs`), UniFFI exports (`crates/baluard-uniffi/src/lib.rs`), `VaultRepository` methods and screens, desktop components and their daemon calls, i18n string keys.
2. Update the snapshot line at the top.
3. Move closed gaps into a "Closed" list at the bottom with the commit that closed them.
4. Any row change needs a source reference in the commit message.
