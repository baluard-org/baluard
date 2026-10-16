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
| File an entry into a collection | Yes (`collections assign <cipher>`) | Yes (detail-view move, `cipher.set_collection`) | None (G25) |
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
Surface: Mobile. CLOSED (2026-10-10): Settings > Security rotates the phrase behind the current master password (D74); the new 24 words show once with copy, and flipped Spaces surface the kit-refusal error text. See the Closed table.

### G4. Mobile open shared reveals
Surface: Mobile. Missing: cannot open a guest or contact reveal file. Effort: S. Value: a phone receives the share file; it should open it. Decision: close. CLOSED: shipped — see the Closed table.

### G5. Mobile device fleet management
Surface: Mobile. CLOSED (2026-10-10): Settings > Devices lists the fleet with a this-device marker and revokes with confirmation; the rekey is the daemon's existing `device.revoke` (no new on-device crypto was needed - the design-pass worry dissolved once the route already carried the ceremony), surfaced with a busy state. See the Closed table.

### G6. Mobile emergency escrow + Recovery Kit
Surface: Mobile. CLOSED (2026-10-10) as kit-only: Settings > Space carries kit status/replace/disable (the fixed threshold's asks render in the pending list with approve actions, and gate errors ship the ask promptly), and onboarding gains phrase-only kit recovery for a discovered-but-unopenable vault, handing off to the unlock stage. The S4 emergency escrow (EmergencyConfig wrapped root key) stays desktop-shaped on mobile - it has no mobile consumer story yet and the kit covers the loss scenario. See the Closed table.

### G7. CLI utility commands (generator, TOTP, SSH generation, list search)
Surface: CLI. CLOSED (2026-10-09): `baluard generate password|passphrase` (flags for length/words/transforms, best-effort history like the apps), `baluard totp <id-or-name>` (name-substring resolution with ambiguity refusal), `baluard ssh-keygen` (daemon-side generation, printed once, optional `--store`); list search arrived with G24 step 6 as `baluard search`. See the Closed table.

### G8. CLI provider connect
Surface: CLI. CLOSED (2026-10-09): `baluard provider connect <name>` runs the device flow where supported (code printed, poll loop honors slow-down) and `--pat` prompts for a token; `status`, `list`, `disconnect`, `repos`, and `vault-repos` complete the account surface. The connect routes are sentinel-exempt, so connect works before any vault is unlocked. See the Closed table.

### G9. CLI rotation without revocation
Surface: CLI. CLOSED (2026-10-09): `baluard rotate-root` rides the daemon rotation route (quorum-gated in core, so a family vault with quorum 2 still needs its co-approver); the autosync enrollment verifier refreshes daemon-side per D78. See the Closed table.

### G10. Mobile passkey ceremonies
Surface: Mobile. Missing: register / assert. Platform WebAuthn APIs make this the hardest mobile item. Effort: L. Value: real, but display-only may be the right 1.0 scope. Decision: needed - park or schedule after 1.0.

### G11. CLI sharing surface (phased)
Surface: CLI. Missing: every sharing command (members, approvals, collections, groups, policies, activity). With the CLI first-class, this is in scope, in two phases:

- **Phase 1 (M) - the Bitwarden shape:** share an item to a space, collection list/assign, member list, member confirm. LANDED (2026-10-09): `baluard collections list|create|assign|grant|revoke` and `baluard members list|requests|approve-join|deny-join|approve|deny` (two queues: joins via `requests.*`, access asks via `collections.requests_*`). Phase 2 stays first item after 1.0.
- **Phase 2 (L) - full admin:** invite, remove, roles, groups, policies, approvals, activity. Peer precedent: the 1Password CLI is a full admin surface (`user provision/confirm/suspend`, `group` CRUD, vault permission grants); the Bitwarden CLI deliberately keeps deep admin in the web console. A first-class Baluard CLI ships both phases - phase 2 may land just after 1.0.

Decision: committed (2026-10-03, Esteban). Phase 1 in the CLI parity track; phase 2 first item after 1.0.

### G12. iOS depth
Surface: Mobile. Missing: autofill provider (Phase 7) plus the iOS actuals behind several partial cells above. Effort: L. Value: the second mobile platform. Decision: already planned as Phase 7; the remaining iOS actuals ride along.

### G13. Space user groups on mobile
Surface: Mobile + CLI. CLOSED (2026-10-10): mobile half landed - People > Groups card (create, rename, member add/remove, two-tap delete whose copy states that access given only through the group is removed, matching the core's grant-row pruning). The CLI part still rides G11 phase 2.

### G14. CLI trash surface
Surface: CLI. Missing: list trash, restore, purge. Effort: S. Value: scripting cleanup; parity with both GUIs. Decision: close.

### G15. Mobile vault detach / prune
Surface: Mobile. Missing: drop a vault from the list, prune stale vaults (both GUIs have it; the destructive delete arm stays desktop/CLI by design). Effort: S. Value: unclutter the vault list after a vault is removed elsewhere. Decision: close. CLOSED: detach shipped; prune has no mobile shape (the list is a filesystem scan and cannot go stale) — the stale-active-pointer self-heal is its equivalent. See the Closed table.

### G16. Repo creation on provider (mobile + CLI)
Surface: Mobile + CLI. CLOSED (2026-10-10): CLI `provider create-repo` (2026-10-09) plus the mobile half — Settings > Sync "Back up through your own Git account" (provider chips, optional PAT, optional repo name) riding a new runtime `setup_sync_remote` over UniFFI: create-or-reuse the private repo (self-heals a repo left by a prior attempt via paginated listing), wire origin, first push, registry entry. The daemon `vault.setup_sync` arm is unchanged (unification parked). See the Closed table.

### G17. Desktop passkey rename UI
Surface: Desktop. Missing: rename exists on CLI only. Effort: S. Value: naming credentials is a daily-use nicety. Decision: close.

### G18. Desktop + mobile re-prompt enforcement
Surface: Desktop + Mobile. Missing: the flag saves but nothing enforces it on view or reveal on either GUI. Effort: S to M. Value: security parity; a silent unenforced security flag is worse than none. Decision: close.

### G19. Password health on desktop and mobile
Surface: Desktop + Mobile. CLOSED (2026-10-10): mobile half landed - Settings > Security > Security check (decrypting pass, findings by entry name, read-only). Known wart parked: the core's reason strings are English-only on es/pt devices. Desktop remains the 1.0 polish item.

### G20. Generator history on mobile
Surface: Mobile. Missing: history drawer (UniFFI bindings already exist). Effort: S. Value: recovering a generated password you did not save yet. Decision: close.

### G21. Vault avatar on mobile
Surface: Mobile. CLOSED (2026-10-10): Settings > Vault picture - picked images are downscaled and recompressed on-device (512px JPEG steps) to fit the core's cap before the encrypted set; iOS renders nothing yet (decoder stub, fail-closed).

### G22. Password history view
Surface: Desktop + Mobile. Missing: no GUI renders `password_history` (CLI exposes it in JSON). Effort: S. Value: "what was the old password" is a real support question. Decision: close.

### G23. Mobile admin ops: repoint / migrate, commit revocation
Surface: Mobile. PARKED (2026-10-10): commit revocation stays CLI-first by usefulness (its own row above); repoint/migrate rides the CLI and desktop today - the family kit-recovery path now covers the "lost remote" recovery story on phones, so the mobile rows return with the first real demand. Decision: park.

### G24. Merged search and autofill across personal vault and Spaces
Surface: Extension + Android + Mobile + CLI (the desktop app is already merged via `vaults.list_full_all`, D31). Missing: extension autofill, Android autofill, mobile search, and the CLI each read one active vault, so family or organization items are invisible until a vault switch. Effort: M. Value: the 1Password/Bitwarden expectation — one list, one badge per origin vault. Decision: planned. Spec: docs/plan-merged-search.md (fan-out over unlocked, browser-consented vaults; per-vault quick unlock instead of a shared secret).

### G25. File an entry into a collection on mobile
Surface: Mobile. Missing: the edit/create screens have no collection field and no assign surface, so a phone member cannot file an entry into a granted collection (the space's core act: putting the Wi-Fi password where the family can see it). Desktop moves the open entry from the detail view; the CLI has `collections assign`. Verified against source 2026-10-16 (zero collection references in EditCipherScreen/EditCipherViewModel). Effort: S-M (a collection picker on the edit form routed through `cipher.set_collection`, plus the create-time default). Value: high for family/org spaces - without it a member's new entries land flat or refused. Decision: close next.

## Recommended order

1. **Small closes (S batch):** G1, G14, G17, G20, G22.
2. **Adoption (the phone stands alone):** G2 (import/export), G4 (open reveals), G15 (detach), G18 (reprompt enforcement), G24 (merged search and autofill), G25 (file into a collection on mobile).
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
| G2 | this wave | mobile import (8 core formats via SAF open + format dialog) and export, bytes-only UniFFI wrappers over the same daemon-shaped runtime paths; review fixes: dedicated json/csv SAF contracts, scrolling format dialog. Follow-up wave: the Baluard backup (baluard.vault v1) — a first-party, versioned, full-fidelity JSON export (folders with hierarchy, tags, re-prompt, history, passkey private keys) with a roundtrip guarantee, auto-detected on import by its header; export surfaces now say "Baluard backup" and "Spreadsheet (logins only)" with zero Bitwarden branding; the desktop export route was found broken (it sent JSON while the daemon raw-matched the payload) and now accepts both shapes; CLI `baluard export` defaults to `--format baluard` |
| G18 | this wave | re-prompt enforced on both GUIs behind a 30s master-password grant. Review round made the gate REAL: verification rides `vault.reprompt_verify` / a new `repromptVerify` FFI (opening a temp handle), because `vault.unlock` short-circuits Ok on an already-unlocked vault and would have accepted any password; desktop gates all sensitive field classes (not just logins), edit flows are gated, autofill refuses reprompt-protected entries, and the modal's show() binds its callback at confirm time (fixing a dead wiring where the rotation gate never fired) |
| G4 | this wave | mobile opens shared `.baluard-share` files: one reusable flow composable serves the full chain (one-shot package import → view-only contact reveal → passphrase guest leg, surfacing the contact leg's error when the guest open also fails) from Settings > Data, and a guest-only entry on the onboarding screen so a recipient without an account can open a passphrase share — the S2 IS-6 core promise; new FFI: `import_shared_package`, `open_shared_contact`, and a vault-agnostic `open_shared_guest` mirroring the daemon's host-level route; secrets masked with copy, everything selectable |
| G15 | this wave | detach drops a vault from the switcher without deleting anything: the directory moves aside under a detached folder (collision-counted, never auto-deleted), the cached session and biometric KEK are dropped first, and the active pointer self-heals when its directory is gone. Prune is deliberately not a button on mobile — the list is a filesystem scan and entries cannot go stale |
| G7 | this wave | `generate`, `totp`, `ssh-keygen` (search arrived with G24 step 6); generation is direct core compute with best-effort history, TOTP resolves name substrings with ambiguity refusal, SSH material prints once with an optional `--store` into the vault |
| G8 | this wave | `provider connect` (device flow with slow-down handling, or `--pat`), `status`, `list`, `disconnect`, `repos`, `vault-repos`; connect rides the sentinel-exempt routes so it works pre-unlock |
| G9 | this wave | `rotate-root` over the quorum-gated core rotation; survivors adopt on next unlock, the D78 verifier refreshes daemon-side |
| G16 (CLI) | 2026-10-09 wave | `provider create-repo` with slug normalization; demands an unlocked vault (it is not sentinel-exempt) |
| G16 (mobile) | this wave | Git-backup wizard on Settings > Sync: runtime `setup_sync_remote` (create-or-reuse + origin + first push + registry, self-healing an already-created repo through paginated reuse), UniFFI `setup_sync` (locked-refusing, devkey_seal carried for signed commits — an enrolled vault refuses unsigned commits fail-closed), PAT never enters the sync path (ensure_valid_token loads from keyring); daemon `vault.setup_sync` left as-is, unification parked |
| G13 (mobile) | this wave | People > Groups card riding the groups.* daemon wire shapes; group delete prunes grant rows and the confirm copy says so |
| G19 (mobile) | this wave | Security check over vault.health; core reason strings English-only on es/pt (parked) |
| G21 | this wave | Vault picture with on-device downscale/recompress; iOS decoder stubbed fail-closed |
| G11 phase 1 | this wave | collections list/create/assign/grant/revoke plus members list and both pending queues: `approve-join`/`deny-join` over `requests.*` and `approve`/`deny` over `collections.requests_*`; the review caught that join confirmation and access asks are separate route families and the first draft wired only one |

## Keeping this document current

1. Re-run the six inventories: CLI command enums and handlers (`crates/baluard-cli/src/main.rs`, `commands/mod.rs`), daemon route dispatcher (`crates/baluard-daemon/src/handler.rs`), UniFFI exports (`crates/baluard-uniffi/src/lib.rs`), `VaultRepository` methods and screens, desktop components and their daemon calls, i18n string keys.
2. Update the snapshot line at the top.
3. Move closed gaps into a "Closed" list at the bottom with the commit that closed them.
4. Any row change needs a source reference in the commit message.
| G3 | this wave | phrase rotation in Settings > Security: master-password gated, new words shown once with copy, flipped Spaces surface the kit refusal |
| G5 | this wave | Devices card: fleet with this-device marker, confirmed revoke riding `device.revoke` (the rekey ceremony was already daemon-side, so no new on-device crypto), busy state + post-revoke refresh |
| G6 | this wave (kit) | kit status/replace/disable in Settings > Space with the fixed-threshold asks approved in the pending list, plus phrase-only kit recovery from onboarding that adopts the vault and hands off to unlock; the emergency escrow stays desktop-shaped |
| G23 | parked | commit revocation stays CLI-first; repoint/migrate covered by CLI and desktop, kit recovery covers the phone-side loss story - rows return on demand |
