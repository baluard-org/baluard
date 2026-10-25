# Feature parity: CLI / Desktop / Mobile

Snapshot: 2026-10-25, main @ `b03217b`; fourth audit pass - parity cells re-spot-checked against source during the wave-17 review program (D4). Owner: Esteban.

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
| Phrase rotation ceremony | None (`rotate-root` turns the root key, not the phrase) | Yes | Yes (Settings > Security, D74) |
| Space Recovery Kit | Yes (`space kit-enable/disable/status` + `vaults recover-kit`) | Yes | Yes (kit status/replace/disable + onboarding phrase-only recovery) |
| Emergency escrow (S4) | None | Yes | None |
| Enroll this device | Yes (phrase enrollment) | Yes | Yes (phrase enrollment) |
| Device fleet (list / revoke / rotate) | Yes (list, revoke, rotation status + abort) | Yes | Yes (Devices card with this-device marker, revoke) |
| Search and filters | Yes (`baluard search` over name+username; `--all` fans out over unlocked merge-eligible vaults, `--vault` targets one explicitly) | Yes (category, folder, tag, deep search) | Yes (deep search over content, URIs, notes, custom fields; hub merges other unlocked eligible vaults) |
| Password health report | Yes (`baluard health`) | Yes (Security check, localized findings) | Yes (Security check, localized findings) |

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
| TOTP code | Yes (`baluard totp <id-or-name>`) | Yes | Yes |
| Passkeys: view | Yes (list) | Yes | Yes |
| Passkeys: delete / rename | Yes | Yes | None |
| Passkey ceremonies (register / assert) | None | Partial (routes live, UI arrives with extension Phase 2) | Yes (Android credential provider; iOS pending platform) |
| SSH key entry (store) | Yes | Yes | Yes |
| SSH key generation | Yes (`baluard ssh-keygen`, optional `--store`) | Yes | Yes |
| Custom fields | Partial (raw JSON on `add` only, no flags) | Yes (all 4 types) | Yes (all 4 types) |
| Import (10 formats: baluard-encrypted .bldbak, baluard.vault, 8 migration) | Yes (magic-sniff hint before read) | Yes (auto-detects Baluard backups by header) | Yes (SAF picker, header sniff, format dialog) |
| Export (baluard.vault backup, spreadsheet logins-only CSV, encrypted .bldbak) | Yes (`--format baluard` default; `--encrypted`) | Yes (Rust-side save dialog, 0600) | Yes (SAF saver incl. encrypted) |
| Password + passphrase generator | Yes (`baluard generate`) | Yes | Yes |
| Generator history | Partial (`generate` adds best-effort; no list/clear command) | Yes | Yes |
| Password history view | Partial (present in `get --output json`) | Yes | Yes |
| Re-prompt on sensitive fields | n/a | Yes | Yes |
| Favicons (website icons) | None | Yes | Yes (opt-in, fetched on save) |
| Vault avatar / profile picture | None | Yes | Yes (on-device downscale/recompress) |

### Sync and multi-vault

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Git remote setup | Yes (`sync init`, `sync remote`) | Yes | Yes |
| Custom Git server (own URL + token/SSH key) | Yes (`credentials set`, `git-probe`, `git-trust`) | Yes (Sync tab, own-server expansion) | Yes (git-backup wizard, Custom chip) |
| Manual sync cycle | Yes | Yes | Yes |
| Auto-sync | Partial (daemon mode rides the daemon's autosync; `--direct` is manual) | Yes (debounced push, event pull) | Yes (debounced push, event pull, activates when a remote attaches) |
| Conflict resolution | None (conflicts error out) | Yes | Yes |
| Provider OAuth device flow | Yes (`provider connect`) | Yes | Yes |
| PAT connect | Yes (`provider connect --pat`) | Yes | Yes |
| Provider repo picker | Yes (`provider repos`, `vault-repos`) | Yes | Yes |
| Repo creation on provider | Yes (`provider create-repo`) | Yes | Yes (git-backup wizard, create-or-reuse) |
| Clone from provider | Yes (by provider + repo, or URL) | Yes | Yes |
| Remote repoint / migrate | Yes (`vaults repoint`) | Yes (`space.migrate`) | None |
| Commit revocation (signed manifest) | Yes (`sync revoke`) | None | None |
| Multi-vault (switch, create, close, prune, detach) | Yes | Yes | Partial (switch, create second vault, detach; no close/prune - the scan list cannot go stale) |
| Offline state | Yes | Yes | Yes |

### Sharing and Spaces

| Feature | CLI | Desktop | Mobile |
|---|---|---|---|
| Space create / flip | Yes (`space` prepare/flip/set-purpose + kit + migrate) | Yes | Yes |
| Members (invite, remove, transfer, claim, reset) | Yes (full admin: remove, reset, transfer, claim + contest window, set-email, set-minor, leave journey) | Yes | Yes |
| Join approvals | Yes (`members stage` + `approve-join` / `deny-join`) | Yes | Yes |
| Space user groups | Yes (`groups` CRUD + membership) | Yes | Yes |
| Collections CRUD + grants | Yes (`collections` list/create/assign/grant/revoke/delete) | Yes | Yes |
| File an entry into a collection | Yes (`collections assign <cipher>`) | Yes (detail-view move, `cipher.set_collection`) | Yes (edit/create picker, `setCollection`) |
| Access asks / requests | Yes (`members requests` + `approve` / `deny`) | Yes | Yes |
| Space settings (all knobs) | Yes (`settings space get` / `space-set`) | Yes | Yes |
| Policies | Yes (`policies list/set`) | Yes | Yes |
| Approvals / quorum | None | Yes | Yes |
| Activity log | Yes (`activity`) | Yes | Yes |
| Contact cards + outbox publish | Partial (list, my-card, import, Level-2 verify, remove; no outbox publish) | Yes | Partial (my code + Level-2 verify from the People screen; no card-import UI, no outbox) |
| Open shared reveal (guest / contact file) | None | Yes | Yes (Settings > Data + a guest-only onboarding entry) |
| Guest reveal create | None | Yes | Yes (Share as file on a Login; 7-day expiry) |
| Member role changes (set_role) | Yes (`members set-role`, owner-row and trust-dial guards) | Yes (People tab role select, typed demote confirm) | Yes (People role dialog, my_role-gated surfaces) |
| Ownership claim + contest window (D61) | Yes (`members claim/contest-status/contest-cancel`) | Yes (claim-notice card, owner-gated cancel) | Yes (Settings/People claim action) |
| Family vault creation + kit display | Yes (`init --family` + wizard) | Yes (purpose cards, kit words-once with TXT/PDF) | Yes (purpose selector, kit screen) |
| Stolen-device replacement (`members.replace_device`) | Yes (`members replace-device`, `--no-revoke`) | Yes (People tab, typed confirm, one-time code card) | Yes (People screen, confirm dialog, one-time code dialog) |
| Encrypted backup (.bldbak, cross-vault) | Yes (`export --encrypted`, env/`--generate`) | Yes (passphrase dialog, Rust-side save/open) | Yes (passphrase dialog, SAF) |

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
Surface: CLI. CLOSED (2026-10-03): see the Closed table.
### G2. Mobile import / export
Surface: Mobile. CLOSED (2026-10-04), extended twice: the Baluard backup (baluard.vault v1, full-fidelity with folders, tags, re-prompt, history, passkeys; header auto-detect) and the encrypted .bldbak container (2026-10-05). See the Closed table.

### G3. Mobile phrase rotation ceremony
Surface: Mobile. CLOSED (2026-10-10): Settings > Security rotates the phrase behind the current master password (D74); the new 24 words show once with copy, and flipped Spaces surface the kit-refusal error text. See the Closed table.

### G4. Mobile open shared reveals
Surface: Mobile. CLOSED (2026-10-05): shipped — see the Closed table.

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
Surface: Mobile. CLOSED (2026-10-19/20): Android credential-provider ceremonies shipped (`BaluardCredentialProviderService`, `passkeyProviderRegister`/`passkeyProviderAssert` over UniFFI; commits bb4f12f, c5175ca). iOS waits on the platform effort below. Original assessment: Platform WebAuthn APIs make this the hardest mobile item. Effort: L. Value: real, but display-only may be the right 1.0 scope. Decision: needed - park or schedule after 1.0.

### G11. CLI sharing surface (phased)
Surface: CLI. Missing: approvals commands (the only sharing surface still desktop/mobile-only; tracked as post-1.0 debt per principle 1). Landed: members, collections, groups, policies, activity). With the CLI first-class, this is in scope, in two phases:

- **Phase 1 (M) - the Bitwarden shape:** share an item to a space, collection list/assign, member list, member confirm. LANDED (2026-10-09): `baluard collections list|create|assign|grant|revoke` and `baluard members list|requests|approve-join|deny-join|approve|deny` (two queues: joins via `requests.*`, access asks via `collections.requests_*`).
- **Phase 2 (L) - full admin.** LANDED (2026-10-19): `members remove|reset|transfer|claim|contest-status|contest-cancel|set-email|set-minor|leave|leaves|approve-leave` (irreversible verbs gated behind a typed confirm or `--yes`), `groups list|create|rename|delete|add-member|remove-member`, `policies list|set`, `space prepare|status|flip|set-purpose|kit-enable|kit-disable|kit-status|migrate`, and `activity`. Every verb rides an existing daemon route; the e2e flow `e2e_cli_org_admin_surface` pins the surface.

Decision: committed (2026-10-03, Esteban); phase 2 promoted into the 1.0 scope (2026-10-19) and landed the same day. CLOSED.

### G12. iOS depth
Surface: Mobile. Missing: autofill provider (Phase 7) plus the iOS actuals behind several partial cells above. Effort: L. Value: the second mobile platform. Decision: already planned as Phase 7; the remaining iOS actuals ride along.

### G13. Space user groups on mobile
Surface: Mobile + CLI. CLOSED (2026-10-10 mobile, 2026-10-19 CLI): mobile landed the People > Groups card (create, rename, member add/remove, two-tap delete whose copy states that access given only through the group is removed, matching the core's grant-row pruning); the CLI half landed as `baluard groups` in the G11 phase 2 wave.

### G14. CLI trash surface
Surface: CLI. CLOSED (2026-10-03): see the Closed table.
### G15. Mobile vault detach / prune
Surface: Mobile. CLOSED (2026-10-05): detach shipped; prune has no mobile shape (the list is a filesystem scan and cannot go stale) — the stale-active-pointer self-heal is its equivalent. See the Closed table.

### G16. Repo creation on provider (mobile + CLI)
Surface: Mobile + CLI. CLOSED (2026-10-10): CLI `provider create-repo` (2026-10-09) plus the mobile half — Settings > Sync "Back up through your own Git account" (provider chips, optional PAT, optional repo name) riding a new runtime `setup_sync_remote` over UniFFI: create-or-reuse the private repo (self-heals a repo left by a prior attempt via paginated listing), wire origin, first push, registry entry. The daemon `vault.setup_sync` arm is unchanged (unification parked). See the Closed table.

### G17. Desktop passkey rename UI
Surface: Desktop. CLOSED (2026-10-03): see the Closed table.
### G18. Desktop + mobile re-prompt enforcement
Surface: Desktop + Mobile. CLOSED (2026-10-04): see the Closed table.

### G19. Password health on desktop and mobile
Surface: Desktop + Mobile. CLOSED (2026-10-10 mobile, 2026-10-17 desktop): Settings > Security > Security check on both GUIs. The English-reasons wart is closed too - core emits machine `kind`/`n` fields (2026-10-16) and both GUIs localize them with positional interpolation.

### G20. Generator history on mobile
Surface: Mobile. CLOSED (2026-10-03): see the Closed table.
### G21. Vault avatar on mobile
Surface: Mobile. CLOSED (2026-10-10): Settings > Vault picture - picked images are downscaled and recompressed on-device (512px JPEG steps) to fit the core's cap before the encrypted set; iOS renders nothing yet (decoder stub, fail-closed).

### G22. Password history view
Surface: Desktop + Mobile. CLOSED (2026-10-03): see the Closed table.
### G23. Mobile admin ops: repoint / migrate, commit revocation
Surface: Mobile. PARKED (2026-10-10): commit revocation stays CLI-first by usefulness (its own row above); repoint/migrate rides the CLI and desktop today - the family kit-recovery path now covers the "lost remote" recovery story on phones, so the mobile rows return with the first real demand. Decision: park.

### G24. Merged search and autofill across personal vault and Spaces
Surface: Extension + Android + Mobile + CLI. CLOSED (2026-10-09, steps 5-9; steps 1-4 landed 2026-10-07): daemon fan-out gated by the two-knob merge ceiling (family purpose merges, organizations never do), `bridge.match` + slug-scoped reads + unlock asks for the extension, merged Android autofill and hub search, `baluard search`, unlock-request banner on desktop. Spec: docs/plan-merged-search.md. See the Closed table.

### G25. File an entry into a collection on mobile
Surface: Mobile. CLOSED (2026-10-16): a Shared-folder picker on the edit/create form (three-state: keep current / none / assign) riding the UniFFI `set_collection` wrapper, with create-time routing through the state layer's collection defaults. Shipped alongside the Collections -> "Shared folders" terminology wave. See the Closed table.

### G26. Stolen-device replacement surfaces
Surface: Desktop + Mobile + CLI. CLOSED (2026-10-18): see the Closed table.

## Recommended order (2026-10-18 state)

Every 1.0-track gap is closed; what remains is scheduled or parked:

1. **1.0 track:** G11 phase 2 LANDED (2026-10-19); G10 (mobile passkey ceremonies) CLOSED 2026-10-19/20 on Android. The backlog holds one post-1.0 item: CLI approvals commands. 1.0 release-engineering scoping is the remaining conversation. **Post-1.0:** G12 (iOS depth).
2. **Scheduled, not landed:** G12 (iOS depth) waits on the platform.

3. **Parked on demand:** G23 (mobile admin ops: repoint/migrate, commit revocation).

## Out of parity scope by design

- CLI as a GUI: no themes, languages, avatars, or autofill.
- Browser extension Phase 2 (passkey ceremony, QR cross-device assertion): tracked in the browser extension plan, not here.
- Desktop-only platform features (Touch ID, Windows Hello, tray) stay platform features.
- iOS lags Android until Phase 7 lands; rows already say so.
- Commit revocation is CLI-first by usefulness, not by omission: signed history is audited where scripts run. The CLI sharing surface is complete (phase 1 2026-10-09, phase 2 2026-10-19).

## Closed

| Gap | Closed in | Note |
|---|---|---|
| G1 | `1d691ba` | `settings space get` / `space-set`; whitelist mirrors the daemon, quorum bound enforced CLI-side |
| Custom Git remote | `ebb075e`..`53ad861` (2026-10-22/23) | Own-server wave across every surface: host-bound credentials, in-memory SSH keys with attempt caps, daemon-observed hostkey trust (attempt-id stash, `[host]:port` entries, conflict/hashed refusal), setup/clone/probe routes, CLI verbs, a CI-hermetic HTTPS git server e2e plus a live-sshd trust journey; forge automation (repo creation, seat grants) is manual for custom hosts by design |
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
| G19 (mobile) | 2026-10-10 wave | Security check over vault.health; reason localization landed 2026-10-16 (machine kind/n fields), desktop half landed 2026-10-17 |
| G21 | this wave | Vault picture with on-device downscale/recompress; iOS decoder stubbed fail-closed |
| G3 | this wave | phrase rotation in Settings > Security: master-password gated, new words shown once with copy, flipped Spaces surface the kit refusal |
| G5 | this wave | Devices card: fleet with this-device marker, confirmed revoke riding `device.revoke` (the rekey ceremony was already daemon-side, so no new on-device crypto), busy state + post-revoke refresh |
| G6 | this wave (kit) | kit status/replace/disable in Settings > Space with the fixed-threshold asks approved in the pending list, plus phrase-only kit recovery from onboarding that adopts the vault and hands off to unlock; the emergency escrow stays desktop-shaped |
| G23 | parked | commit revocation stays CLI-first; repoint/migrate covered by CLI and desktop, kit recovery covers the phone-side loss story - rows return on demand |
| G11 phase 1 | this wave | collections list/create/assign/grant/revoke plus members list and both pending queues: `approve-join`/`deny-join` over `requests.*` and `approve`/`deny` over `collections.requests_*`; the review caught that join confirmation and access asks are separate route families and the first draft wired only one |
| G10 | bb4f12f + c5175ca | Android credential-provider passkey ceremonies shipped (`BaluardCredentialProviderService`, `passkeyProviderRegister`/`passkeyProviderAssert` over UniFFI); iOS waits on platform effort (G12) |
| G11 phase 2 | this wave | full CLI org admin: member remove/reset/transfer/claim/contest/set-email/set-minor plus the leave journey, `groups` CRUD, `policies`, `space` lifecycle + kit + migrate, `activity`; typed-confirm gate on irreversible verbs |
| G24 | 2026-10-09 wave | merged search and autofill across surfaces: daemon fan-out behind the personal_merge/merge_opt_in ceiling, extension chips + slug-scoped reads + unlock asks, Android autofill/hub merge, `baluard search` |
| G26 | 2026-10-18 wave | `members replace-device` CLI verb, desktop People-tab typed-confirm action with the one-time-code card, mobile People-screen confirm + code dialogs over the new UniFFI wrapper; the e2e pins the happy path, the tombstone and own-row refusals, and the revoke-stop warning |
| G25 | 2026-10-16 wave | Shared-folder picker on the edit/create form (keep/none/assign three-state) over UniFFI `set_collection`; create-time routing rides the state layer's defaults |

## Keeping this document current

1. Re-run the six inventories: CLI command enums and handlers (`crates/baluard-cli/src/main.rs`, `commands/mod.rs`), daemon route dispatcher (`crates/baluard-daemon/src/handler.rs`), UniFFI exports (`crates/baluard-uniffi/src/lib.rs`), `VaultRepository` methods and screens, desktop components and their daemon calls, i18n string keys.
2. Update the snapshot line at the top.
3. Move closed gaps into a "Closed" list at the bottom with the commit that closed them.
4. Any row change needs a source reference in the commit message.
