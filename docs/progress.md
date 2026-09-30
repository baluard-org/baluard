# Baluard: Master Progress Document

> Single source of truth for project state. Update after every work session.
> Last updated: 2026-09-29 (S4 power pack: wave 1 SHIPPED — Q5 owner recovery + the S4-3 ratchet, D61; wave 2 SHIPPED — S4-4 access review + the S4-8 exposure summary, D62; wave 3 SHIPPED — S4-6 advisory org policies, D63; wave 4 SHIPPED — S4-7 emergency × org × identity doc + the Space Recovery Kit core + the recovery ceremony, routes, desktop surface, and CLI disaster path, D64 + D65. Sharing plan COMPLETED and closed: all planned phases shipped through S4-1 plus the P5 staged-path-set remainder (D60); the wave log lives in git history and the D-records. iOS (Phase 7 AutoFill extension + sharing parity) is parked past 1.0 per Esteban's 2026-09-27 call. S2 closed, S1b closed 2026-09-22. Mobile: Android Phases 0-6 complete; iOS parked past 1.0. Test infra: daemon test-harness leak fixed (Drop guards + BALUARD_DAEMON_DIE_WITH_PARENT die-with-parent watchdog) after the 1816-orphan crash of 2026-09-23.)
>
> Next up: the **S4 power pack is COMPLETE** — all eight items shipped, tracked in `docs/plan-power-pack.md`. Seven waves: wave 1 (2026-09-28) closed Q5 owner recovery (`ownership_claim` + owner-targeted reset) plus the S4-3 ratchet (D61); wave 2 (2026-09-29) shipped the S4-4 access review with the S4-8 exposure summary (D62); wave 3 (2026-09-29) shipped S4-6 advisory org policies (D63); wave 4 (2026-09-29) shipped the S4-7 emergency × org × identity doc, the Space Recovery Kit core, and the recovery ceremony with its routes, desktop surface, and CLI disaster path (D64 + D65); wave 5 (2026-09-29) shipped the S4-9 mobile multi-Space host (D66); wave 6 (2026-09-29) shipped S4-2 groups as a key layer (D67); wave 7 (2026-09-30) shipped the S4-5 derived activity timeline (D68). Deferred and parked items stay in its section 11; the P5 staged-path-set remainder shipped 2026-09-28 (D60). Post-pack peer-review follow-ups: the general-pass fixes (D69, commit ffe6efd + 53b2629), signed approval records (D70, aa7d3dc), and role-aware flipped keywraps so post-flip admin invitees hold full powers (D71).

---

## Current Frontier (read this first on session start)

Active work: **S4 power pack** (`docs/plan-power-pack.md`). Mobile Phase 7 (iOS AutoFill Credential Provider extension) parked past 1.0 (2026-09-27). Android Phases 0 through 6 are complete.

| Wave / Phase | Work | State |
|---|---|---|
| Phase 0 | Architecture split: `baluard-runtime` + `baluard-uniffi` extraction | ✅ done |
| Phase 1 | Foundation: UniFFI bindings, Android scaffold, SecureFlag, Biometric stubs | ✅ done |
| Phase 2 | Core Flows: Auth, VaultList, Detail, Edit (all 8 types), Generator, TOTP | ✅ done |
| Phase 3 | Sync Lifecycle: on_foreground pull, on_mutation push, sync indicator | ✅ done |
| Phase 4 | Edge Cases: ConflictResolutionPanel, multi-vault switcher, settings | ✅ done |
| Phase 5 | Release Polish: Material 3 brand theme, R8 rules, unit tests | ✅ done |
| Parity polish | Mobile edit/create at desktop parity (URIs + match strategy, TOTP seed, custom fields Text/Hidden/Boolean/Linked, tags, folder, reprompt, configurable generator, card formatting + brand, exp-month/sex dropdowns, SSH keypair generation, favicon fetch-on-save), deep search over every field (password excluded, trash/archived excluded), TOTP card + settings fixes | ✅ done |
| Phase 6 | Android Autofill Service (`BaluardAutofillService`, inline suggestions, save handoff, domain equivalence, app-to-web trust matching, biometric KEK unlock) | ✅ done |
| Phase 6.5 | Android Accessibility Tile (`BaluardA11yTileService` + `BaluardAccessibilityService`, browser URL scraping) | ✅ done |
| Phase 7 | iOS AutoFill Credential Provider extension (`ASCredentialProviderViewController`, shared UniFFI) | ⏳ post-1.0 |

Docs: `docs/plan-mobile-apps.md`, `docs/plan-android-autofill.md`, `docs/plan-android-accessibility-tile.md`, `mobile/README.md`.

---

## Project Overview

**What**: Git-backed password manager. Encrypted vault stored as a git repo. No server.
**Stack**: Rust Core Engine (`baluard-core` crypto/keys/vault/sync + `baluard-daemon` IPC socket server + `baluard-cli` terminal client + `baluard-runtime` orchestration + `baluard-uniffi` FFI bindings) + Tauri v2 Desktop (SolidJS/Tailwind) + Single-String Protobuf Gateway.
**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell. Mobile: Android, iOS.
**Architecture docs**: `docs/software-architecture-decisions.md` through `docs/software-architecture.md`.

---

## Current Status

Full desktop feature set: CRUD, 8 cipher types, generator, TOTP, auto-lock, import/export, reprompt, password health, attachments, biometric unlock, linked custom fields, nested folders, archive entries. **Passkey support Phase 0+1 done**. **Mobile: Android Phases 0-6 implemented with Compose Multiplatform + baluard-uniffi (onboarding, home hub, filtered entry lists, 8 cipher types, detail/edit at desktop parity, deep search, generator, TOTP, favicon opt-in, biometric ceremony, auto-lock, sync, conflict panel, multi-vault, R8 release build, Android Autofill Service with inline suggestions, save prompt, domain equivalence, app-to-web matching with per-app trust, and quick-settings tile accessibility fill). Phase 7 iOS parked past 1.0**.

**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/baluard-core` - Rust core engine: crypto, keys, vault, padding, git sync, providers, bridge
- `/crates/baluard-runtime` - In-process orchestration engine: VaultHost, VaultState, AutoSyncHandle, PinEscrow, ProviderManager
- `/crates/baluard-uniffi` - UniFFI C-FFI / Kotlin / Swift bindings over baluard-runtime + baluard-core
- `/crates/baluard-cli` - Terminal CLI client (clap, daemon-first with `--direct` fallback)
- `/crates/baluard-daemon` - Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state, SSH key generation, auto-sync coordinator, multi-vault host, browser bridge)
- `/crates/baluard-nmh` - Native messaging host binary (browser extension bridge, stdio-JSON <-> varint-protobuf)
- `/desktop` - SolidJS/Tailwind/Tauri v2 desktop app (full CRUD, 8 cipher types, generator, TOTP, auto-lock, dark/light themes, i18n en/es, 38 components)
- `/browser` - Chromium + Firefox MV3 extensions (shared codebase, two targets). KeePassXC-Browser-style bridge client. Paired companion model (rides the desktop's unlock state)
- `/mobile` - Kotlin Multiplatform app (Compose UI + UniFFI integration; onboarding create + provider flows, vault list with type/tag/favorite filters + deep search, detail + edit for all 8 cipher types at desktop parity, generator, TOTP, settings incl. favicon opt-in, Android Autofill service with inline suggestions, domain equivalence, app-to-web trust matching, save prompt, quick-settings tile accessibility fill, i18n EN/ES)
- `/docs` - Architecture, design, threat model, plans, PRDs, ADRs

---

## Implementation Progress

| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `workspace` | Done | Rust workspace with baluard-core, baluard-runtime, baluard-uniffi, baluard-cli, baluard-daemon, baluard-nmh crates |
| `baluard-runtime` | Done | Extracted in-process vault runtime: VaultHost, VaultState, AutoSyncHandle, PinEscrow, ProviderManager, RateLimiter |
| `baluard-uniffi` | Done | UniFFI C-FFI / Kotlin Multiplatform / Swift bindings over baluard-runtime + baluard-core |
| `mobile/android` | Done (Phases 0-6 + parity) | Compose Multiplatform Android client: onboarding (create + clone + device enrollment), home hub, filtered entry lists, deep search over every field (password excluded, trash/archived excluded), 8 cipher types detail/edit at desktop parity (URIs + match strategy, TOTP seed, custom fields Text/Hidden/Boolean/Linked, tags, folder, reprompt, generator knobs, card formatting + brand, SSH keypair generation, favicon fetch-on-save), generator, TOTP, biometric unlock ceremony, auto-lock, sync feedback, conflict resolution panel, multi-vault switcher, R8 release build. System autofill service (`BaluardAutofillService`) with inline suggestions, response-level auth, split save prompt (`AutofillSaveToken`), domain equivalence (global + custom), app-to-web matching with per-app trust, and quick-settings tile accessibility fill (`BaluardA11yTileService` + `BaluardAccessibilityService`). Phase 7 (iOS) parked past 1.0 |
| `core/autofill-matcher` | Done | `UriMatchStrategy::matches` and `matches_with` in baluard-core (6 strategies, public-suffix eTLD+1, bundled Bitwarden global equivalent domains, custom equivalent groups, scheme isolation, trailing slash segment boundary). Batch query `VaultState::autofill_query` in baluard-runtime / baluard-uniffi returning `{matches, app_suggestions}` (secret-absence invariant: no passwords in matching output) |
| `proto/schemas` | Done | `vault.proto`, `space.proto`, `auth.proto`. Compiled by prost-build in daemon and CLI |
| `crypto/aead` | Done | AES-256-GCM with strict AAD binding |
| `crypto/webauthn` | Done (Phase 0+1) | FIDO2/WebAuthn ceremony via `passkey-rs` 0.5.x. ES256 only. `BaluardCredentialStore` (Arc<Mutex> mutation tracking), `PasskeyIndex` (in-vault passkey lookup), `CeremonyCache` (300s TTL, max 64 pending, FIFO eviction, OsRng challenges). Passkeys embedded in `LoginData::fido2_credentials`. |
| `vault/handle` | Done | Vault CRUD operations |
| `vault/creation` | Done | Vault creation ceremony with BIP-39 recovery phrase |
| `sync/engine` | Done | git2-rs sync: init_repo, commit, push, pull, fetch, Ed25519 signed commits |
| `sync/conflict` | Done | Field-level 3-way merge (`merge_ciphers`, semantic atomic groups); `resolve_conflict_keep_local` for keep-local conflict resolution |
| `sync/state_machine` | Done | Sync state machine for tracking sync progress |
| `daemon/socket` | Done | Unix socket listener. 0600 via umask. SIGINT/SIGTERM graceful shutdown |
| `daemon/handler` | Done | Protobuf gateway. Length-delimited wire. Token-gated IPC. Password zeroized. ~72 routes including bridge, vault_host, autosync |
| `daemon/state` | Done | VaultState with Arc<RwLock>. KDF outside write lock. Double-check unlock pattern |
| `daemon/host` | Done (Phase 6) | `VaultHost` multi-vault: `RwLock<VaultHostInner>` over `HashMap<String, Arc<VaultState>>` + `active: Option<String>` pointer. Per-vault session tokens. Integration tests in phase6_switching |
| `daemon/autosync` | Done | Event-driven pull (unlock + window focus w/ 10-min guard) + 30-min idle fallback + offline retry (30s probe). `cycle_lock` tokio mutex (C3). Network errors classified via `is_network_error` |
| `daemon/pin` | Done | Session PIN escrow (`PinEscrow`). In-memory only. Argon2id PIN verifier. 5-strike nuke. Survives soft-lock, dies on close/restart |
| `daemon/bridge` | Done (Phase 0+1) | Bridge token registry on `VaultHost`. `TokenKind::Bridge { pairing_id }` branches off `TokenKind::Vault` in `verify_session_token`. Allowlist enforcement. Field-gated `vault.update` (reject `fido2_credentials` + `uris` from bridge) |
| `daemon/passkey-ipc` | Done (Phase 1) | 7 passkey routes: list, delete, rename, challenge_register, finish_register, challenge_assert, finish_assert. All token-gated. `delete` and `rename` take `credential_id` (not cipher_id) for multi-passkey Logins. |
| `core/bridge` | Done (Phase 0+1) | Pairing file format + atomic writes, bridge token mint/verify, action allowlist. New module: `crates/baluard-core/src/bridge/{mod,pairing,token}.rs` |
| `nmh/binary` | Done (Phase 0+1) | `baluard-nmh` standalone Rust binary. stdio-JSON <-> varint-protobuf. Stateless. Reads pairing entry on spawn, re-mints ephemeral bridge token. Per-OS manifest install via `just install-nmh-manifest <browser> <ext_id>` |
| `cli/dual-mode` | Done | All commands: daemon-first + `--direct` fallback. `--socket <path>` override |
| `desktop` | Done | SolidJS/Tailwind v4 + Tauri v2. 3-column layout, dark/light themes, tray, daemon spawn |
| Uniform bucket padding | Done | 5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()` |
| Git commit signing | Signing: Done. Verification: Done (P2, 2026-09-18) | Ed25519 signatures in commit `gpgsig` header. P2 repaired verification: rosters resolve per commit from the first-parent tree's `meta/devices.json` (UUID-keyed), unsigned commits refused at creation on enrolled vaults (fail-closed), clone paths verify full fetched history, signing key mismatches warn, `device-registry.json` fixture path deleted. Known boundaries: merge-commit content smuggling closed by the P8a merge-residue rule (2026-09-19); forged fully-stripped parallel histories are a TOFU limit at first clone, closed at pull time
| Cover commits / jitter | Done | No-op cover commits + CSPRNG-backed timing jitter on push/pull |
| Integrity manifest | Done | Ed25519-signed checkpoints, rollback detection, bootstrap for fresh devices |
| Token-gated IPC | Done; **default-deny (P6, 2026-09-18)** | 256-bit session token on unlock. Constant-time comparison. Cleared on lock. P6 inverted the daemon gate: everything except `TOKEN_EXEMPT_ACTIONS` (12 pre-token routes: 4 vault ops — lock/info/biometric_status/pin_status — plus 8 provider sentinel routes) requires the per-vault token; unknown actions fail closed. Coverage tests: exempt-surface exact-set pin, sentinel-forwarding invariant, host-only tripwire before the token gate |
| `mlock` on key material | Done | `libc::mlock` on RootKey/ItemKey. Re-mlocked on Clone. Redacted Debug |
| AAD swap protection | Done | `decrypt_cipher` recomputes expected AAD, asserts before decryption |
| Device lifecycle | Done | Enrollment, quorum, force-evict, epoch rotation, recovery phrase path |
| Space Group Key | Done | RootKey -> SpaceGroupKey -> ItemKey hierarchy. Epoch-bound. Volatile zeroize |
| Import/Export | Done | 8 import parsers + 2 export formats (BW-compatible) |
| Reprompt | Done | Per-entry master password challenge with 30s grant |
| Password Health | Done | Weak/reused/old password detection |
| Attachments | Done | AES-256-GCM encrypted, max 2MB. Plaintext zeroized after use |
| Biometric Unlock | Done | OS keychain (macOS `security-framework` v3 with `SecAccessControl BIOMETRY_ANY`; other platforms via `keyring` crate: Linux `linux-native`+`sync-secret-service`+`crypto-rust`, Windows `windows-native` DPAPI). Per-vault scoped by deterministic `vault_id` from KDF salt (stable across renames + git-sync). Legacy global `quick-unlock` wiped once at daemon startup. Daemon-side unlock, secret never over IPC |
| Session PIN | Done | In-memory `PinEscrow` on `VaultState::pin` (KEK + Argon2id PIN verifier, both zeroized on drop, NEVER on disk). `vault.pin_status`/`vault.pin_enable`/`vault.pin_disable`/`vault.pin_unlock` daemon routes. 5-strike nuke (`MAX_PIN_FAILURES`). Survives soft-lock, dies on close/restart. Skips Argon2id master KDF via `unlock_with_kek` (still verifies keywrap + canaries). Linux + Windows-without-Hello fallback |
| Linked Custom Fields | Done | 24 LinkedFieldType variants with type-safe resolution |
| Nested Folders | Done | Max depth 16. Cascade delete. BFS descendant collection |
| Archive | Done | Archive/unarchive ciphers. Separate list view |
| Extra cipher types | Done | BankAccount (10 fields), DriversLicense (12 fields), Passport & ID (13 fields)
| SSH key generation | Done | Ed25519 (default), ECDSA P-256. RSA 4096 removed (L7 fix: rsa crate had RUSTSEC-2023-0071 Marvin Attack, no fix). Daemon-side via `ssh-key` crate. OpenSSH format output. **Mobile parity**: `ssh_generate_key` uniffi wrapper + generator section on the sshKey edit form |
| User profile | Done | Display name, subtitle, avatar in VaultSettings. Avatar file in vault dir. Sidebar reads from context |
| Modal accessibility | Done | FocusTrap component (Tab trap, Escape dismiss, auto-focus, restore focus). Applied to all 9 modals (Add/Edit, DeleteConfirm, ArchiveConfirm, Reprompt, Generator, Settings, EmptyTrash, SetupScreen, DetachVault, SwitchUnlock) |
| Tag deletion | Done | Hover X on sidebar pills, confirmation modal, tag.delete daemon command |
| Archive confirmation | Done | ArchiveConfirmModal with FocusTrap. Prompts before archiving entries |
| i18n completion | Done | All hardcoded strings replaced with t() keys. en.json + es.json in sync |
| Toast notifications | Done | toastSignal.js standalone signals. All user feedback via toasts |
| Favicons | Done | Opt-in persisted website icons (`favicon` cipher field). Fetched at save time. 16KB cap + magic-byte check + default-off. `desktop/src/lib/cipherSchema.js` + `Avatar`/`CipherRow` chip treatment. **Mobile parity**: `fetch_favicon` uniffi wrapper (self-gated on the setting), fetch at edit-save, Settings > Security toggle with risk hint |
| App icons | Done | `just app-icons SOURCE OUT` builds 48/128 PNG variants from brand logo for all platforms (macOS/Windows/Linux/Android/iOS + tray monochrome + system tray). `desktop/src-tauri/icons/` |
| Vault detach | Done | UI: `DetachVaultModal` in `VaultSwitcher` dropdown (safe detach only: drops registry entry). Destructive arm (`delete_from_disk`) NOT exposed in UI; CLI-only via `baluard vaults detach <slug> --delete-from-disk` (slug retyping + `.baluard` marker check). `vaults.detach` daemon route still supports both for the CLI caller |
| Browser extension Phase 0+1 | Done | NMH binary + bridge module + paired-companion pairing flow. `bridge.pair_start` (desktop-initiated, token-gated, one-shot pending approval) + `bridge.pair_complete` (held pending Approve click in desktop UI). Scoped bridge token (`TokenKind::Bridge { pairing_id }`) on host registry; allowlist (no `vault.list_full`, no `vault.delete`, no `settings.*`, no `passkey.*`, no `sync.*` mutations). Per-`pairing_id` rate cap on `bridge.match`+`vault.get`. Top-frame-only content script, popup-driven fill (no auto-fill on load). See `docs/plan-browser-extension.md` |
| Sync header refactor | Done | One-click sync UI replaces git jargon. Sidebar header shows provider + repo link (`cc09c51`). `AutoSyncIndicator` shows status pill (idle/syncing/dirty/offline). Sync label gated with `Show` inside `Transition` to silence background pulls. Provider state scoped to active vault (`58016d4`) |
| Conflict resolution panel (UI) | Done | Top-floating slide-down panel (`ConflictResolutionPanel.jsx`) driven by `ConflictResolutionContext.jsx`. **Phase 2 backend wired (2026-07-02)**: engine hook (`run_sync_cycle_with_resolver`, `NeedsDecision`, `finalize_conflicts`), daemon decrypt + `merge_ciphers` (`conflict_decrypt_and_merge`), `keep_both` (`conflict_resolve_keep_both`), frontend real IPC (`conflictFlow.js`, AutoSyncContext poll). F1 auto-merges (no prompt); F2/F3/F4 surface the panel. Cross-epoch decrypt failure bails to keep-local raw blob with a UI flag. See `docs/plan-conflict-resolution-panel.md` |
| Orgs | Primitives only — NOT shippable | `orgs.rs`: HPKE wrap/unwrap + access-list I/O. Zero callers (no CLI, daemon route, or UI). Design superseded by `docs/plan-sharing.md` |
| Sharing | P shipped + S1a-1..8 + S1b-1..5 + S2-1/S2-2 + §4.8-1/2/3 + P8c-1/2 — P2 + P6 + P5a/P5b/P5c + P4 + P1a + P1c + P1d + P3 + P7 + P8a + P8b + S1a-1..8 + S1b-1/2/3/4/5 (notices; D21 read scope + `ensure_access_accepted`) + S2-1 (IS-3 one-shot item packages: contact card v2 with wrap-pubkey binding, HPKE package seal/open with sender-attribution signature, daemon `packages.export`/`packages.import`) + S2-2 (IS-6 reveals both flavors: contact-key + passphrase-guest, expiry-in-AAD, sender signature binding recipient/expiry/created/label/fields, untrusted-KDF clamp, host-level tokenless guest route) + S2-3 (IS-5 pair Space: `space_slug` slug forcing + `space:true` settings-pub shape flag, pair gate at invite mint + join approval counting bound live non-tombstoned rows, `space.create` host route, `vaults.list` space field, space-aware ownership-transfer demotion to Editor, settings-pub writers merge-preserve the flag) + S2-4 (per-recipient outboxes: standalone per-recipient git repo with HPKE content-key wrap + owner signature, digest-driven live mirror on the post-CRUD hook, view-only recipient link/read with link-time owner pinning, revoke = unpublish + keywrap drop, rotation-covered registries) + S2-5 (merged multi-vault item list: `vaults.list_full_all` host route token-gated on the active session, sibling rows ciphers-only, foreign entries view-only with source-vault chip + slug-routed TOTP/attachments, staleness bounded by focus/heartbeat re-pull) + S3-1 (collections core: meta/collections/<id>.json with plaintext grants + name sealed under a random per-collection content key wrapped by an SGK-derived epoch-bound key, admin-gated create/rename/delete/grant/revoke + open list returning grant rows, daemon routes with mutating five in COVER_MUTATION_ACTIONS, rotation re-seal in both rekey paths, tombstone member validation, malformed-row skip + filename/id pin) + S3-2 (collection-scoped paths: salted-hash cipher dirs per collection, path IS membership with a local write-grant gate on both move ends mirroring the policy table, CollectionScope built from the verified commit tree and enforced before the role rows, recursive index/cipher scans with UUID dedup, restore lands flat, cipher.set_collection route; review round 5 accepted incl. the wedge-prevention Blocker + 2 declined) + S3-3 (expiry-that-rotates: admin sweep drops expired grants + rotates collection keys in one atomic save, executed post-pull at unlock and on demand via collections.sweep, notices grant_expiring/grant_expired member-visible in en/es/pt, verification stays clock-free; review round 5 accepted incl. the unlock-before-pull discard Blocker, 0 declined) + P1 groundwork (per-member identity wraps: MemberFile.identity_wrap_pubkey from the verified intro card, meta/collections/<c>/<m>.wrap HPKE wraps bound to collection+member, grant/revoke/rotation/sweep lifecycle, identity-rotation self-heal two-phase before the identity swap; review round 8 accepted incl. the tombstoned-wrap-survives-rotation Blocker, 1 partial) + S3-4 (role templates: meta/templates.enc sealed store under a root-key HKDF, admin-gated create/delete + open list, mint-time template snapshot embedded in PendingInviteFile so the invite is the contract, approval applies embedded grants best-effort fail-toward-less-access with per-member wrap minting, rotation re-seal in both rekey paths, viewer+write refused at template mint AND at the grant root, approval-side grant cap in the peek phase, fail-closed mistyped-input parsing) + S3-5 (delegated manage: CollectionAccess::manage for Editor+ holding a live grant on that one collection — grant/revoke/rename without admin, create/delete stay admin; sync policy admits `meta/collections/<id>.json` + `<id>/**` writes from PARENT-tree manage authority with the Editor floor intact, so managers cannot self-grant in the same commit; local gate mirrors the policy so no unpushable commit can be minted; review caught the def-id-rebranding scope hijack, delegable def deletion, demoted-Viewer stale-grant wedges, the unscoped conflict-strip loop, and the pre-existing wave-12 own-wrap identity-rotation wedge — fixed with the stem pin, a deletion flag, up-front Viewer refusals, scoped strip-loop authority, and an own-wrap structural rule) + S3-6 (request-access JIT + optional catalog: `meta/members/<m>/requests/<id>.json` asks under the own-subtree Any policy row, plaintext collection_id/access with the note HPKE-sealed to the approver set (live Owner/Admin rows with wrap pubkeys), sealed-vs-plaintext agreement makes tampered files inert, member mine/withdraw + admin inbox (decrypted, deterministic walk with per-member cap, malformed count) + approve (collection/requester always from the seal; admin may override access/expiry; upsert_grant rules incl. viewer+write refusal apply) + deny, optional `meta/collections/catalog.json` plaintext name catalog as the explicit opt-in (publish validates, list caps + filters dead rows); review round (agy) 8 accepted incl. 2 blockers — crafted manage asks refused at submit/decrypt/approve, seals bind the requester so transplanted files go inert; plus grant-aware submit (covered asks refuse, expired lapse, upgrades allowed), inbox determinism + walk caps, desktop D21 allowlist, key zeroize) + S3-7c (member collection access — read scope now equals key scope: ciphers inside collection dirs carry item keys HKDF'd from the collection CONTENT KEY under the same baluard-item-v1 info (derive_item_key_from_ck), flat personal ciphers stay SGK-keyed admin surface; a path-domain resolver (CipherDomain from the on-disk location, CK from role — admins unwrap via SGK, members open their grant wrap) drives get/update/clone/archive/unarchive/folder-delete/heal/index/rotation/conflict-merge; add_cipher_in_collection creates inside a granted collection; assign re-encrypts across key domains (same epoch, seq+1); trash preserves the origin subdir so restore is same-domain with bytes unchanged; rotation re-keys collection ciphers as ck@new_epoch — CK values rotation-invariant so member grant wraps survive — and the loop is domain-aware (it previously built flat-only paths and SILENTLY SKIPPED collection ciphers: latent S3-2 gap); verify_root_key scans domain-aware canaries; sync policy: Owner/Admin hold known collection dirs structurally (admin-authored collection ciphers were refused at peer pulls — second latent gap), trash/<dir> scope-checked, flat ciphers+root trash Admin-only once the shape marker rides the commit tree (pre-flip Editor flat writes keep legacy rows), member identity-rotation deltas validate wrap-pubkey hex; integrity containment: checkpoint seq floor unconditional (seq = envelope update_seq, rises on every cross-device edit) so a handoff cannot launder a higher seq; review round (agy) 12 findings ALL accepted after source verification — 3 Blockers (integrity seq laundering via device-change, update/archive missing the collection write gate so Read-grantees wedge sync, my own deleted Viewer-refusal branch was load-bearing S3-5 behavior), 5 Majors (perpetual member heal loop — scan set must equal staleness set, the trash/flat policy gap, member flat delete/restore ungated, member assign still sgk-bound, clone dropping collection scope), 4 Minors (non-recursive rotation tmp sweep, trash dedup, collection-only canary false-reject, ghost trash after collection deletion)) + §4.8-4 (shared-collection surfaces: `collections.list` went role-aware — admins keep the full grant table with an access:"admin" marker, members get only their own openable rows with names decrypted through their grant wrap (`list_member_collections`, inert skips, no group key involved); `CipherMeta.collection_id` is path-derived at list time (fill pass over a single dir-map, heal + index reads) and `vault.add` accepts `collection_id` to create straight inside a granted collection (no create-then-move window); desktop: Shared sidebar section with live counts, member ask-for-access dialog (catalog picker + paste-id fallback + note + my asks with withdraw), People-tab access-requests inbox (approve with grant-choice or deny), admin Collections tab (create/rename/delete, grant/revoke with optional expiry computed client-side, catalog publish); review round (agy) — 7 accepted, 1 refuted: corrupted VaultView import block + sidebar count reading the wrong surface (Blocker), approve/deny payloads missing requester_member_id so every inbox action refused (Blocker), grant expiry sent as expires_in_days the daemon never parsed (Major, now computed client-side), manage-access badge mislabeled, clear-filter button reused the tag label, fill-pass hoisted to one dir-map parse per list; refuted: requests_mine rows carry `id` as claimed; BONUS pre-existing find: `vite build` was broken on main (solid 2.0.0-rc.1 dropped `onMount` from the default entry) — PeopleTab + CollectionsTab moved to the codebase's `onSettled` convention and the build is green again) + §4.8-5 (collection polish: entry detail gains move-to-collection — admin: anywhere incl. back out to personal; member: only live write/manage targets, with a read-only-source plain-label fallback and select snap-back on daemon refusal, cipher id pinned across awaits, archived-entry pane refreshed from the archived list; trash rows carry their origin collection end to end (`list_trash_entries` flats-first walk matching `trash_file_path` priority -> runtime `list_trash_meta` + `full_envelope` `_meta`); admin catalog gains clear (empty publish = opt-out). Review round (agy): F0 blocker self-refuted (member moves halt at the source/target gates or target-key derivation); F1 refuted against source (`daemon.js` stringifies non-string payloads); F4 refuted against the diff (`full_envelope` trash `_meta` already carried the id); F5/F6 already satisfied on disk (flats-first ordering + honest ghost doc); F2/F3/F7/F8 accepted and fixed) + S3-8 (remote migration + auto-adopt: admin-invoked move of the vault's sync to a new remote — history ships to the new remote FIRST via a temporary named remote, then the plaintext `meta/remote.json` pointer commits and pushes to the OLD remote (one last sync every peer watches), then origin re-points and the pointer commit ships to the new address; every device's pull reads the pointer from VERIFIED COMMITTED HEAD (never the worktree) and auto-follows within the same forge host (same-host gate: a pointer can never auto-move a device across providers); `space.migrate` + `space.remote` daemon routes (admin-gated, cycle-locked, COVER_MUTATION_ACTIONS), desktop Move-sync card in the sync tab with confirm, and `baluard vaults repoint <slug> <url>` as the keyless power-user escape hatch (records itself adopted so the hook never fights it). Failure windows converge without wedges: a failed history push aborts before any peer sees anything (origin restored, no reset --hard — the aborted attempt's commit stays local and unpushed); a failed post-swap push self-heals on the next sync. Review round (agy, killed at timeout mid-remediation) landed its own fixes which survived Zero-Trust triage alongside mine: history-first sequencing (F1 blocker), HEAD-only pointer reads (F2 blocker), cycle-lock (F4), CLI validation + adopted marker (F5), post-migration convergence assert (F6); my additions: same-host follow gate plus agy's credential-callback host gate (F3 was fully real — provider tokens previously went to any host on an auth challenge; now keyring tokens are refused outside their provider's enrolled instances, and the follow gate covers env/file tokens), and the no-reset rollback; declined: member-visible card (daemon refuses with plain language) and removing `space.remote` (status surface). **§4.8-6 DONE (2026-09-26, tracer)**: mobile member surfaces — the uniffi bridge gained the sharing + join surfaces as thin delegation to the SAME runtime wrappers the desktop daemon routes through (collections_list role-aware, the request-access JIT set, catalog), so the JSON payload contracts keep exactly one authoritative parser; member join (clone → invite code + chosen password → intro code → 10s poll with best-effort pull only in the locked introduced-not-approved window → auto-unlock on approval), the Shared hub section with per-collection entry lists (MobileCipherMeta.collection_id), and the ask dialog (catalog picker or paste-id fallback, read/write, note, my asks + withdraw). Review round (agy): all seven attacked invariants refuted (password handling, contract duplication, join_poll semantics, authorization, poll-loop lifecycle, secret hygiene, parse robustness); two confirmed fixes — the ask entry hid inside an empty-collections gate so a fresh member could never ask (desktop renders the section unconditionally; mobile now matches), and the multi-line note field built JSON without escaping control characters (escapes added; the daemon's newline refusal still gives the clear message). **§4.8-7 DONE (2026-09-26, tracer)**: mobile admin surfaces — seven thin uniffi methods (members list + invite, join-queue list/approve/deny, collection grant/revoke) over the SAME runtime wrappers the desktop daemon routes through; the People screen (settings entry, admin-gated on the same access:"admin" signal as desktop) carries the join-queue inbox with the secret-check warning, the access-request inbox with grant-read/grant-edit presets (payloads carry requester_member_id per the desktop contract), tombstoned-member rows greyed, the invite dialog (role chips fail closed server-side, optional git username, one-time code with clipboard copy), and a per-collection grants editor (revoke + inline add-grant with member picker, access chips, optional expiry days converted client-side to an epoch the daemon validates). Review round (agy): invariants A/B/D/E/F/G refuted; two confirmed fixes — the invite username escaped only quotes so a pasted backslash could terminate the JSON string and inject keys (backslash-first escape added), and the grants editor re-fetched collectionsList per collection (N+1 bridge round-trips; one parse now serves rows + grants). **§4.8-8 DONE (2026-09-26, tracer)**: mobile member offboarding — the destructive controls from the §4.8-7 deferral list cross to the phone: three typed-args uniffi methods (member_reset, member_transfer, member_remove(member_ids, offline_override); the bridge builds the JSON payloads so the app never hand-escapes ids), People-screen per-row Transfer (owner, non-owner targets) / Reset / Remove (owner+admin, never the own row, hidden on the Owner row for admins), a typed-confirmation dialog whose confirm stays disabled until the typed word trim-matches the member name and the name is non-empty (desktop TypedConfirmModal parity: no instant bypass on empty names, no keyboard-space lockout), the remove strike-failure path keeping the dialog open with the override checkbox UNCHECKED, the members.remove report parsed fail-loud (malformed payload never reads as success), and the one-time reset code in its own dialog with clipboard copy. Flip/prepare stay off the phone because desktop has no flip surface either — parity first. Review round (agy): authorization/payload/strike/hygiene invariants refuted against core; four confirmed fixes — reset-code loss on a malformed payload (success toast without showing the code), empty-display-name confirm bypass, dismiss-during-strike silencing the failure, and owner-row buttons that could only ever error. **S2 UI DONE (2026-09-26, tracer; see D48)**: item-sharing desktop surfaces — the S2 core+daemon routes get their UI. Send: a Share button on login-type entry details creates a passphrase-guest reveal (expiry presets 1d/7d/30d + optional TOTP inclusion), shows the one-time passphrase with an auto-clearing clipboard copy, and saves the .baluard-share file via Blob download; the copy instructs sending file and passphrase by different channels. Receive: one Open-shared-file flow auto-detects the flavor — packages.import (one-shot entry import, sync indicator armed), then reveals.open_contact (view-only), then the passphrase-guest open, with a 4MB client-side file guard so a mis-picked huge file cannot lock the webview and the contact leg's specific error (expired, wrong recipient) surfacing when the guest open then fails. Guest receive lives on the login screen (reveals.open_guest is tokenless host-level; no vault needed). Contact-key and package SEND flavors deferred: no address-book UI exists anywhere (core contacts_list has zero routes), so that is its own future wave. Review round (agy): allowlist/chain-crypto/guest-mode/i18n invariants refuted (domain-separated AAD makes reveal-vs-package mis-import cryptographically impossible; the retry path cannot double-import); five accepted fixes — raw clipboard write bypassing the auto-clear+conceal utility, missing pre-read file-size guard, sticky passphrase-stage state across file reselection (would route a package file to the guest open), swallowed contact-leg error, packages.import missing from the desktop sync-indicator set; declined: TOTP countdown in the transient reveal view.  **Address book + contact flavors DONE (2026-09-26, tracer; see D49)**: the contact half of S2 sharing — core gains contacts_remove (the address book had no removal primitive); five new contacts.* daemon routes (list, my_card, import_card, mark_verified, remove) with the three mutating ones in COVER_MUTATION_ACTIONS + the token-gate pin list (contacts.enc is git-tracked); the Contacts settings tab (my card + verification code, card-code import, trust chips, per-contact code reveal, mark-verified, remove behind ConfirmModal); the Share dialog gains the contact flavor — contact-key reveals for logins, packages for every entry type, no passphrase (decryption rides the recipient's identity key); the Share button widens to all own entries. Review round (agy) — four majors: the verification code was a 32-bit unilateral hash (offline pubkey-swap preimage search was practical; widened to 64 bits with a length-assert regression), the card CODE was never shown (the UI displayed only the verification code, so users could not share their card at all), non-login sharing was dead (the guest flavor was forced and the daemon refuses logins-only — contact flavor now default for non-logins), plus malformed `{` responses on two wrappers; minors: expiry options hidden for packages (they have none), removal failures now reload. Chain-crypto, route-gating, and i18n invariants refuted.  **Outbox management UI DONE (2026-09-26, tracer; see D50)**: the last UI-less S2 surface — owner side mirrors items into a folder a recipient carries (live: resync re-mirrors on change), recipient side links such a folder and reads entries view-only (masked password, auto-clear copy); ten pre-existing outbox routes gained their allowlist entries, one new Outboxes settings tab, no Rust beyond the allowlist. Review round (agy) — one major (the new tab label landed in the wrong locale group: dot-in-key check inverted, so the tab rendered its raw key) plus three minors (ambient outbox id replaced with an explicit parameter, the entry viewer gained FocusTrap + dialog semantics + Escape, singular item count); payload-contract, secret-hygiene, recipient-read-gating, destructive-flow, and modal-contract invariants all refuted.  **Mobile collection CRUD DONE (2026-09-26, tracer; see D51)**: four uniffi methods (collection create/rename/delete + typed-args catalog set, bridge-built JSON per the D47 rule), the CollectionsScreen (list + dialogs + catalog publish/clear behind confirms), admin-gated Settings entry, 21 collections.* i18n keys per locale. Review round (agy) — one major confirmed and fixed at the source: the admin entry marker (counting access:"admin" rows) goes false for zero-collection vaults, hiding People and Collections from a real admin; replaced with a new is_admin_device() uniffi export over holds_root, the same marker collections_list branches on. Minors: publish disabled while the list is empty (an empty publish IS a clear), busy guards on row + dialog buttons; bridge-payload, deletion-safety, catalog-semantics, and i18n invariants refuted. **S3-9 DONE (2026-09-27, tracer; see D52)**: Space settings foundation + provider checklist — three §6.5 knobs on the encrypted settings store (invite_authority admins|owners, allow_viewer_export default false, guest_enabled default on as an Option toggle), enforcement wired at the gates (member invites honor the authority with the legacy-founder pass; both export routes refuse viewers by default and refuse None resolutions on strict vaults so a struck member's live session cannot fall through the catch-all — review fix; guest reveals refuse when the door closes while already-created reveal files stay openable), admin-gated `space.settings`/`space.settings_set` daemon routes (COVER + pin list + desktop allowlist) with fail-closed parses, and `docs/provider-org-readiness.md` recording the verified S3 gate: GitHub ready (ToS allows data in private repos; org app-approval + fine-grained scoping is the corporate story), GitLab ready with the 5-member free-group cap, Codeberg personal-only (100 MiB non-promoted bucket for private repos + the FLOSS-mission clause). Review round (agy): persistence/gate-correctness/guest/authorization/sync/checklist-doc invariants refuted; the export-gate fail-open (tombstoned-role None fall-through) confirmed and fixed, plus the role-matrix route test (editor/viewer/admin/tombstoned rebinds). **§6.5 settings surface DONE (2026-09-27, tracer; see D53)**: the wave-30 routes get UI — a desktop Space tab (invite-authority chips, viewer-export and guest-sharing toggles; renders for everyone per the tab convention with the daemon as validator, reloads daemon truth on refusal) and a mobile admin-gated Settings card (is_admin_device-gated, typed-args uniffi pair with the bridge emitting present-fields-only JSON after review caught null-vs-absent breaking the partial parser). Review round (agy): the bridge null finding was the real catch — json! serializes None as JSON null and the runtime partial parser treats a present-null key as a mistyped value, so every mobile write failed; plus desktop rapid-click torn state (busy guard + disabled), the mobile busy race (flag set synchronously before launch), a swallowed CancellationException, and vault-keyed remember. **Mobile notices + activity DONE (2026-09-27, tracer; see D54)**: the S1b routes get phone surfaces — a typed-args uniffi trio (notices_list(refresh_transport) with the phone passing false so no forge network runs, activity_events(limit), activity_refusals(limit)) over the unlocked-gated wrappers, an ungated Activity screen (notices, per-device share events newest-first, refusal lines — per-device local data, no admin gate; blank while loading rather than a false all-clear), and an Activity settings entry. Review round (agy): authorization/i18n/bindings refuted; the event-order contract was the real catch — the core emits CHRONOLOGICAL oldest-first and the screen was rendering oldest at top (parser now reverses, docs fixed); plus JsonNull-safe parsing via the house str() accessor, false-empty during load, and section keys. **§6.5 trash/restore policies DONE (2026-09-27, tracer; see D55)**: trash_policy (write_scope_can_trash | admins_only, default = today) gates collection trash; restore_policy ships single-valued admins_only per the §6.5 table — the serde default tightens every legacy vault, members-with-Write can trash but not restore, and the owner restores; the review round caught the other half of the §4.4 row: permanent delete of trashed entries and purge_old_trash were ungated (a member could purge what it cannot restore, and purging flat trash would wedge its own sync) — both now admin-gated with the unlock-time purge call best-effort swallowing the member refusal; space.settings carries both knobs, desktop SpaceTab + mobile card render trash chips and a read-only restore line.  **Team-mode flip surfaces DONE (2026-09-27, tracer; see D56)**: the S3-7b flip became reachable — desktop SpaceTab and the mobile admin space card both carry status, prepare (with the missing-member count), and the one-way upgrade behind a typed “team” confirm; three new uniffi methods (space_status/space_prepare/space_flip); the review round fixed a count-versus-array wire misread on the mobile status parser (SpaceStatus.missing_wrap_pubkey is a count, PrepareReport's is the id array), the double-prefixed space.space.* locale keys, the TypedConfirmModal that never auto-closes (that contract belongs to plain ConfirmModal), a false-success toast on a failed prepare, the swallowed flip-refusal detail, and a typed-word leak across dialog opens.  **Avatar re-home + member meta-write gates DONE (2026-09-27, tracer; see D57) **§6.5 join_approval DONE (2026-09-27, tracer; see D58)**: code mode auto-approves secret-checked introductions through the manual path**: the avatar key moved from the epoch-bound SGK derivation to the member-visible meta domain (read fallback covers legacy blobs; flip converges it — files_reencrypted 6 with an avatar; post-flip rotation skips the leg, the SMK is rotation-invariant) and every member-reachable write to git-tracked meta now refuses on non-managing devices (settings, avatar, locale at any state, contacts mutations, generator history) — converting the silent peer-pull wedge into plain-language refusals. | S1b | L | (Team-shape flip, admin-invoked `space.flip`: plaintext `meta/space-shape.json` marker flips the seven member-visible meta derivations (index/folders/tags/profile/settings/contacts/events) from the Root Key to HKDF(SMK); member devices unlock via identity seed + space.wrap with root/SGK absent from UnlockedState (Option-typed, refusals via .root()/.sgk()); the five tracked meta files re-seal in the flip and admin unlock convergence heals crash windows; member device keywraps stripped at flip and rotation staging + the quorum txn path + adopt are all shape-aware so the Root Key never re-reaches a member; approve_join ships no keywrap post-flip (join_status reads the space.wrap); review round (agy) — all 7 findings accepted: F1 join wedge post-flip (Blocker), F2 rotation events save used Root Key bytes instead of the meta IKM, F3 member index auto-heal crashed rootless, F4 avatar derive handed a zero key to member encrypt paths, F5 quorum txn leaked Root Key wraps to member devices (txn + adopt both closed), F6 readiness gate treated a None wrap pubkey as usable, F7 convergence now strips keywraps; member cipher access is the S3-7c boundary) + S3-7a (Space Meta Key groundwork, additive: random 32-byte SMK with two distribution paths — `meta/space.enc` sealed store under a Root-Key HKDF re-sealed by BOTH rotation paths, and per-member HPKE wraps `meta/members/<m>/space.wrap` context-bound to the member; `space.prepare` idempotent mint + full re-wrap with a convergent re-mint over a missing or damaged store, `space.status` readiness counts for the 7b flip gate, identity-rotation self-heal two-phase, reset/removal wrap cleanup, approval-side best-effort minting, offboarding SMK rotation via `space_meta::rotate`; nothing derives from the SMK yet — the 7b flip switches meta derivations and keywrap distribution once every live member is wrapped; review round (agy) — F1 accepted as a PRE-EXISTING bug: the identity-rotation None-refusal fired after the sealed seed/escrow/member-unlock had been overwritten, orphaning wraps; the self-heal + refusal now run before any identity byte is written; F2 accepted (malformed wrap pubkey no longer aborts prepare — invalid keys count missing), F4 partially accepted (SMK rotates on member removal, best-effort until 7b), F6/F7/F8 test gaps closed (tamper + size-cap + convergence + policy-routing pins, old-root refusal); F3 declined — propagating a damaged store at rotation pre-swap would let a hostile meta file wedge offboarding rotation, the convergence path is the fix; F5/F9/F10 declined or deferred (sync-engine pubkey validation + route-dispatch-style tests are 7b concerns; space.status is default-deny gated without a pin)) + §4.8-1/2/3 (People tab incl. destructive controls + join-side flow + daemon routes) + P8c-1/2 (seat grant/upgrade + removal strike with pre-flight) done (2026-09-19/24), P5 remainder (staged path sets, D60) and P1 Space parts (shipped as the SMK design, S3-7a/b) done | Sharing plan COMPLETED: every phase and remainder shipped through S4-1 (D59) plus the P5 remainder (D60); active work = the S4 power pack (`docs/plan-power-pack.md`) | | `docs/plan-sharing.md` Rev 8.1 is the authoritative plan: identity-rooted Spaces (one personal vault per human holds the member identity; Spaces have no master password), roles, collections, item sharing via pair Spaces / outbox repos / packages / reveals, org granularity. P2 (signature-verification repair), P6 (default-deny IPC), P5a (deterministic devices.json + registry-union conflict auto-resolve), P5b (index untracked + sharded + staleness guard + invalidation hooks), P5c (per-fact folders/tags + aarch64 hardware AES), P4 (full rotation coverage + propagated failures + emergency rewrap), P1a (per-human identity keypair: keystore-sealed, escrow-protected, rotatable), P1c (lock chokepoint: session generation bump + generation-tagged tokens on all four mint sites — stale tokens die on mismatch), P1d (quick-unlock shared-enrollment warnings, en/es/pt), P7a (context-bound HPKE wraps — transplant/rollback rejection), P3 (keywrap distribution: routine rotation stages wraps for every enrolled device; revoke-path survivors adopt their entry from the epoch-bound rekey txn at unlock — fail-closed, before the F1 heal), P7 (policy table as data + net-diff consumption in both verification walks — deny-by-default on uncovered paths, merge commits governed by the P8a merge-residue rule; role resolution via the S1a-1 member directory), and P8b (append-only revocation manifests: roster-snapshot entry signatures, per-transition append-only verification, tracker-cached pulls, targeted signed restore commits, `baluard sync revoke` + `sync.revoke`) shipped; all P phases shipped (P2, P6, P5a/b/c + the staged-path-set remainder per D60, P4, P1a/c/d, P3, P7, P8a/b/c) — see that doc |
| Emergency access | Done | Break-glass access. Pre-wrapped Root Key. Advisory time gate |
| Providers | Done | GitHub (device flow) / GitLab (device flow + 2h refresh) / Codeberg (web-OAuth PKCE) adapters. OAuth + PAT fallback. Advanced Options for self-hosted + user-owned apps. Auto-create vault repo |

### BW Parity Phases 1-8

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| 1 | CipherKind sum type | Tagged enum (Login/Card/Identity/SshKey/SecureNote). Invalid states unrepresentable |
| 2 | Multi-URI + settings | Multiple URIs with match strategy. `VaultSettings` CRUD |
| 3 | CipherMeta + vault.update | `vault.list` returns CipherMeta. `vault.update` with PATCH semantics |
| 4 | Password history + clone | Auto-append on change, cap 10. `cipher.clone` with new UUID |
| 5 | Folder CRUD | Create/rename/delete. Delete unassigns ciphers first |
| 6a-c | Desktop: All forms | Login, SecureNote, Card, Identity, SSH Key forms |
| 7 | Generator + auto-lock | CSPRNG generator, EFF passphrase. Configurable auto-lock timer |
| 8 | TOTP | RFC 6238/4226. SHA1/256/512, 6/8 digits. Daemon route + UI widget |

### BW Parity Phases A-G

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| A | Import/Export | 8 parsers + 2 export formats. Daemon routes. CLI commands |
| B | Reprompt | Per-entry MP challenge. 30s grant. Shield icon |
| C | Password Health | Weak/reused/old detection. CLI + desktop reports |
| D | Attachments | AES-256-GCM encrypted files. Max 2MB. Zeroized after use |
| E | Biometric Unlock | OS keychain (macOS security-framework, keyring for other platforms). Daemon-side. Quick Unlock button |
| F | Linked Custom Fields | 24 variants. Type dropdown + linked field selector |
| G | Nested Folders | Depth 16. Cascade delete. Recursive tree UI |

---

## Completed Features & Subsystems

Completed core, CLI, daemon, and desktop implementations.

### Resolved Code TODOs (2026-06-08)

| File | Item | Resolution |
|------|------|------------|
| `crypto/kdf.rs` | Iterative Argon2 calibration loop | **Done**: `auto_calibrate()` now ramps memory/time_cost within profile bounds via timed derivation benchmarks |
| `sync/engine.rs` | Local push/pull roundtrip test | **Done**: Fixed `#[ignore]` test; allow `file://` URLs in `validate_git_url`, ensure `save_last_head` creates `meta/` dir |
| `vault/handle.rs` | Store vault_id in meta file | **Done**: `derive_vault_id()` deterministically derives UUID from KDF salt; no persistence needed. Stale TODO removed |

### Tags

**Storage**: Encrypted `tags: Vec<String>` on cipher envelope + `meta/tag_index.json` plaintext cache. See DOMAIN 8 in `docs/software-architecture-decisions.md`.

| Component | Description | Status |
|-----------|-------------|--------|
| Core data model | `tags` field on CipherInput, CipherEnvelopeData, Cipher, CipherMeta | **Done** |
| Tag validation | 64-char max (chars), UTF-8, lowercase-normalized, max 20 per cipher | **Done** |
| Tag index cache | `meta/tag_index.json` rebuilt on vault.list_full | **Done** |
| Tag CRUD | create_tag, rename_tag, delete_tag, list_tags in VaultHandle | **Done** |
| Daemon IPC routes | tag.list, tag.create, tag.rename, tag.delete, tag.rebuild_index | **Done** |
| CLI commands | `baluard tags list/create/rename/delete` | **Done** |
| Desktop: tag input | Free-text + autocomplete in Add/Edit form | **Done** |
| Desktop: tag pills | CipherDetail header badges | **Done** |
| Desktop: tag sidebar | Tag section in sidebar with click-to-filter | **Done** |
| Desktop: filter | filterByTag in filters.js | **Done** |
| Import: 1Password | Preserve all tags from 1PUX import | **Done** |
| Import: BW export | Tags skipped (no BW field). Preserved in git. | **Done** |

### Device Fleet Visibility

**Architecture**: See DOMAIN 5 in `docs/software-architecture-decisions.md`

| Phase | Description | Effort | Status |
|-------|-------------|--------|--------|
| 1 | Activity index (`meta/device_activity.json`) + daemon route | 1-2 days | **Done** |
| 2 | Enhanced DeviceEntry (`enrolled_by`, `last_seen_epoch`) + revocation cleanup | 1 day | **Done** |
| 3 | Epoch timeout + deterministic coordinator election | 1 day | **Done** |
| 4 | CLI fleet commands (`devices list/revoke/info/rotation-status/rotation-abort`) | 0.5 days | **Done** |
| 5 | Fleet dashboard (desktop: devices tab, status badges, revoke UI) | 2-3 days | **Done** |

### Desktop Features

| Item | Description | Status |
|------|-------------|--------|
| Auto-sync | Debounced push after CRUD (5s), event-driven pull (unlock + window focus with 10-min guard) + 30-min idle fallback, offline retry, conflict auto-resolve (keep-local Phase 1). Daemon coordinator `autosync.rs`, desktop `AutoSyncContext` + status dot + transient label + conflict banner. See D5-bis in `docs/software-architecture-decisions.md` | **Done** |
| Browser autofill suppression | Global `autocomplete=off` via MutationObserver; opt-in `data-autofill="on"`. `desktop/src/lib/disableAutofill.js` | **Done** |
| UI freeze fix | `daemon_request` async + `spawn_blocking` (sync command was blocking the webview event loop) | **Done** |
| macOS keychain stable signing | `_sign-sidecar` just recipe signs daemon with Apple Development identity so "Always Allow" persists across rebuilds | **Done** |

### Vault Creation Wizard

**Architecture**: See D18 in `docs/software-architecture-decisions.md`

| Item | Description | Status |
|------|-------------|--------|
| Core: VaultCreator builder | `.profile()` + `.preferences()` methods, chain writes on creation | **Done** |
| CLI: hybrid wizard | Flags + interactive fallback, OS locale detection | **Done** |
| Desktop: 3-step wizard | Language+Password → Recovery → Profile+Preferences | **Done** |
| Daemon: locale.save route | Plaintext meta/locale write for pre-unlock access | **Done** |

### Icon Audit

| Item | Description | Status |
|------|-------------|--------|
| Icon review | Audit all icons across desktop for visual correctness | **Done** |
| Broken/wrong icons | Identify and fix misaligned, missing, or incorrect icons | **Done** |

### Git Online Providers Auth & Sync

| Item | Description | Status |
|------|-------------|--------|
| **Phase 1** | Slug + .baluard marker + vault registry + multi-vault CLI | **Done** |
| **Phase 2** | Provider trait + GitHub auth (device flow + PAT) + keyring + daemon routes | **Done** |
| **Phase 3** | GitHub repo operations + first sync + credential wiring | **Done** |
| Phase 4 | Remote vault clone + three-button wizard: **implemented**. `vault.clone_start/progress/finalize` daemon job flow (host-level, pre-unlock, NOT token-gated) + `SyncEngine::clone_remote` (provider-hinted creds + git2 `transfer_progress` -> live `CloneProgress`). CLI `baluard sync clone <provider> <repo>` (daemon-only). Desktop: `WelcomeScreen` (new vault / open local / download from provider) + `CloneFromProviderScreen` (provider pick -> auth -> `provider.vault_repos` list -> clone w/ progress bar -> master-pw unlock). `vaults.register_local` route (open-local, no copy). `provider.repos`/`vault_repos` un-gated (sentinel-safe, pre-unlock). 2FA warning banner (dismissible, per-provider). Orphan-dir cleanup on clone failure. `tauri-plugin-dialog` for the dir picker. Core + JS tests (clone progress, unreachable source, poll/finalize, failure path). | **Done** |
| **Phase 5** | GitLab (device flow + PAT + 2h refresh) + Codeberg (web-OAuth PKCE + PAT) providers | **Done** |
| **Phase 6** | Vault switching + CLI polish: **implemented**. Keep-unlocked/switch-pointer model: daemon holds `RwLock<VaultHostInner>` with `HashMap<String, Arc<VaultState>>` + `active` pointer (one critical section). Switch = pointer flip (no zeroization, no token change). Per-vault session tokens. `vaults.list/switch/active/close/set_active` routes. `vault.unlock` returns `{slug, token}`. Single auto-lock checker walks the map. Integration tests pass. Lock-all on `Tauri WindowEvent::Focused(false)` (frontend token cache clear + focus-regain refresh); OS suspend / screen-lock / lid-close hooks documented as follow-up (macOS NSWorkspace, Linux login1 D-Bus PrepareForSleep, Windows WM_POWERBROADCAST/SessionSwitch). | **Done** |
| Provider selection UI | Desktop SyncTab: device-flow (GitHub/GitLab) + web-OAuth (Codeberg) + PAT under Advanced Options | **Done** |
| Sync header refactor | One-click sync UI replaces git jargon. Sidebar header shows provider + repo link (`cc09c51`). `AutoSyncIndicator` status pill (idle/syncing/dirty/offline). Sync label gated with `Show` inside `Transition` to silence background pulls. Provider state scoped to active vault (`58016d4`). | **Done** |
| Vault detach | UI: `DetachVaultModal` in `VaultSwitcher` dropdown (safe detach only). Destructive arm (`delete_from_disk`) NOT exposed in UI; CLI-only via `baluard vaults detach <slug> --delete-from-disk`. `vaults.detach` daemon route still supports both | **Done** |

---

## Active Frontiers & Pending Milestones

### Vault Onboarding & Recovery Export

| Item | Description | Status |
|------|-------------|--------|
| Recovery key export (TXT, MD, PDF) | Allow non-technical users to export their 24-word recovery key during vault creation as TXT, Markdown, or PDF. Warn users explicitly about plaintext risks if left in unprotected downloads or desktop folders. Advise storing the file on an encrypted disk (FileVault, BitLocker, LUKS) or on a dedicated external offline drive stored in a secure location. | **Planned** |

### Browser Extension (KeePassXC-Browser-style bridge)

| Item | Description | Status |
|------|-------------|--------|
| **Phase 0** | `baluard-nmh` standalone Rust binary + `core/bridge/{mod,pairing,token}.rs` module + paired-companion auth model. Desktop pairing UI (`BridgeTab`). Per-OS NMH manifest install via `just install-nmh-manifest <browser> <ext_id>`. `baluard-nmh` shipped as Tauri sidecar (desktop builds include it) | **Done** |
| **Phase 1** | Chromium + Firefox MV3 extension builds (`just ext-build`, `ext-build-chrome`, `ext-build-firefox`). SolidJS popup (NO unlock). Top-frame-only content script (no auto-fill on load, popup-driven fill). Scoped `TokenKind::Bridge { pairing_id }` token on host registry. Action allowlist (no `vault.list_full`, no `vault.delete`, no `settings.*`, no `passkey.*`, no `sync.*` mutations). Field-gated `vault.update` (reject `fido2_credentials` + `uris` from bridge). Per-`pairing_id` rate cap on `bridge.match`+`vault.get`. Desktop-initiated approve-don't-type pairing flow (no codes to transcribe) | **Done** |
| **Phase 2** | Phase 2 deferred: passkey ceremony in the browser, cross-device assertion via QR pairing, mobile (iOS/Android) | **Pending** |

### Mobile Apps (Compose Multiplatform)

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Architecture extraction: `baluard-runtime` + `baluard-uniffi` crates | **Done** |
| **Phase 1** | UniFFI bindings generation, Android scaffold, SecureFlag, Biometric foundation | **Done** |
| **Phase 2** | Core UI: Auth, Home Hub, VaultList, Detail + Edit (all 8 types), Generator, TOTP | **Done** |
| **Phase 3** | Sync lifecycle: on_foreground pull, on_mutation push, sync indicator with feedback phases | **Done** |
| **Phase 4** | Edge cases: ConflictResolutionPanel, multi-vault switcher, settings (remove-from-device, screenshot toggle) | **Done** |
| **Phase 5** | Release polish: Material 3 brand theme, R8 shrinker rules, unit tests | **Done** |
| **Phase 6** | Android Autofill Service (`BaluardAutofillService`, inline suggestions, save handoff, domain equivalence, app-to-web trust matching, biometric KEK unlock) | **Done** |
| **Phase 6.5** | Android Accessibility Tile (`BaluardA11yTileService` + `BaluardAccessibilityService`, browser URL scraping) | **Done** |
| **Phase 7** | iOS Autofill Credential Provider extension (`ASCredentialProviderViewController`, shared UniFFI) | **Next** |
| **App-to-web matching** | Web-saved logins fill inside native apps via package-derived domain candidates + per-app trust (path B) | **Done** |

### Nice to Have / Future

Features parked for the far future. Do not start without explicit confirmation.

#### App-to-web domain matching (path B: trust-on-first-use)

**Status:** Done. Shipped in `feat(mobile): app-to-web autofill matching with per-app trust` (517b671). Target: Android autofill (mobile/androidApp `:autofill` process), extendable to iOS in Phase 7.

**Problem:** web-saved logins (e.g. `https://mybank.com`) do not autofill inside native apps (`com.mybank.app`) because the matcher enforces strict scheme isolation between `androidapp://` and `https://` targets. Bitwarden bridges this gap by crudely reversing the package name into a domain (`com.mybank.app` -> `mybank.com`), which is phishing-adjacent: a malicious app can name itself `com.mybank.evil` and receive the user's real mybank.com credentials.

**Approved design: trust-on-first-use.**

1. **Setting:** "Suggest web logins in native apps" - default OFF (opt-in, consistent with Baluard's security-first posture). Stored in vault settings (encrypted, git-synced) as `suggest_app_logins: Option<bool>`.

2. **Candidate generation:** when the setting is on and the fill target is `androidapp://<package>`, parse the package labels:
   - Reverse the first two labels: `com.mybank` -> `mybank.com`
   - PSL-validate: the result must be a registrable domain
   - Only reverse `com.<x>` and similar reverse-TLD patterns (`com.github.android` -> also try `github.com` via label-skip)
   - Candidates are hints, not matches: they only widen what the picker shows, never auto-fill silently

3. **Trust-on-first-use:** the first time an app requests fills for a given candidate domain, the picker shows the matching entries with a banner: "These look like logins for mybank.com. Trust this app?"
   - User confirms -> persist `(package_name, registrable_domain)` in a trust list (vault settings, encrypted + git-synced)
   - User denies -> persist as rejected; never suggest again for that package
   - Trust is scoped per (package, domain) pair, not global

4. **Matching extension:** after trust exists, the package's registrable domain is added as a virtual equivalent group for that package in `autofill_query`, so web-saved entries flow into native app fills through the same pipeline as explicit `androidapp://` URIs.

5. **Security boundaries:**
   - Trust list is user-consented, never heuristic-auto-trusted
   - Reversal candidates never cross the `androidapp://` vs `https://` scheme boundary in the matcher itself; they only widen which entries the PICKER shows (the user still confirms by tapping)
   - The trust list is per-vault, git-synced, and auditable
   - Package-name lookalikes (`com.mybank.evil`) are rejected: the candidate's registrable domain must exactly equal the entry's registrable domain

6. **Implementation notes:**
   - Candidate generation: `crates/baluard-core/src/types.rs` via `app_domain_candidates`
   - Trust list: `VaultSettings.trusted_app_packages: Option<Vec<AppDomainTrust>>` and `rejected_app_packages: Option<Vec<AppDomainTrust>>` in `settings.enc`
   - Picker integration: `VaultState::autofill_query` surfaces `{matches, app_suggestions}`
   - UI: `AutofillActivity` shows trust prompt banner on first encounter per package and records decision via `autofill_app_trust` / `autofill_app_reject`

| Item | Status |
|------|--------|
| Setting + storage | **Done** |
| Candidate generation | **Done** |
| Trust UI | **Done** |
| Fill extension | **Done** |

### Out of Scope (No Server)

| Item | Why |
|------|-----|
| Collections | Org-level groupings, requires multi-user infrastructure |
| Breach report | HaveIBeenPwned requires external API |
| Send | Encrypted sharing requires server relay |
| HOTP | TOTP only. Counter-based OTP out of scope |
| BW server API compat | Baluard is serverless |

### Security

| Item | Description | Status |
|------|-------------|--------|
| OAuth PAT escrow | PAT stored in OS keyring (never in git config), 0600 file fallback | **Done** |
| 2FA Tier 1 | Document "local-only = 2FA" framing in UX | Planned |
| 2FA Tier 2 | FIDO2 vault unlock via `libfido2` (hardware second factor) | Planned |
| 2FA Tier 3 | OS keychain sync gate (separate auth for git push/pull) | Planned |
| 2FA Tier 4 | TOTP for device enrollment confirmation (ephemeral liveness check) | Planned |
| 2FA Tier 5 | FIDO2-only mode (no master password) | Planned |

#### 2FA Open Questions

1. `libfido2` Rust crate maturity and audit status
2. OS keychain availability in headless CI (mock trait needed)
3. Multiple FIDO2 credentials per vault
4. Recovery after FIDO2 credential loss
5. Org/team vault 2FA requirements (deferred)

---

## Architecture Reference

### Cipher Model

- **CipherKind**: serde-tagged enum `#[serde(tag = "type", content = "data")]`. 8 variants: Login, Card, Identity, SshKey, BankAccount, DriversLicense, Passport, SecureNote
- **CipherType enum**: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`, `BankAccount`, `DriversLicense`, `Passport` (Passport covers national ID documents)
- **Multi-URI**: `Vec<LoginUri>` where `LoginUri { uri, match_strategy }`. Ordered, reorderable
- **UriMatchStrategy**: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5)
- **Favorite**: `bool` on both `Cipher` and `CipherMeta`
- **Password history**: `Vec<PasswordHistoryEntry>` on Cipher, cap 10 entries (FIFO)

### Daemon Wire Format

- JSON strings inside `GatewayRequest.payload`. Proto updates cosmetic until typed migration planned
- `get_cipher` returns BOTH nested `kind` object AND flat top-level fields
- `update_cipher` parses `kind` from payload JSON (does NOT clone existing kind)

### VaultHost (Phase 6 Multi-Vault)

- Daemon shares an `Arc<VaultHost>` across all connection handlers (replaces the pre-Phase 6 single `Arc<VaultState>`).
- `VaultHost` wraps a single `RwLock<VaultHostInner>` holding both `vaults: HashMap<String, Arc<VaultState>>` AND the `active: Option<String>` pointer. ONE lock for both → the invariant "if `active` is `Some(slug)`, slug is in the map" is provably maintained (no two-lock race).
- **Switch = pointer flip only.** `vaults.switch` sets `active`, touches registry `last_opened` OUTSIDE the host lock, returns `{active, presence}`. No zeroization, no token change.
- **Per-vault session tokens.** `vault.unlock` returns `{slug, token}`. Token check is per-vault: a request must carry the token matching the TARGETED vault (constant-time compare against that vault's token only). Desktop keeps a `Map<slug, token>` in `SessionTokens`.
- **Handler snapshots the target `Arc<VaultState>` once per request** via `snapshot_target(slug_or_none)`. Removes the TOCTOU where a mid-request `switch` would re-route an in-flight op.
- **`vaults.close` = Arc-drain.** Removes the entry, clears `active` if it was active, returns immediately. In-flight handlers holding a cloned Arc finish and zeroize on last drop. `Arc::strong_count` is NOT used as a sync primitive.
- **Auto-lock is a single walker.** One tokio task ticks every 30s, iterates the map, applies each vault's own `auto_lock_minutes` + `last_activity`. Active-pointer-on-autolock policy: when the active vault auto-locks, `active` is LEFT pointing at it (re-unlock UX for the same vault, not the picker).
- **Cover timers are per-`VaultState`**, keyed to locked/unlocked, never to `active`. A switch touches no cover timer.
- **Routes:** `vaults.list`, `vaults.switch`, `vaults.active`, `vaults.close`, `vaults.set_active` (host-level, no token); `vault.unlock`/`vault.lock`/`vault.open`/`vault.create` take an explicit `slug` (or fall back to active); all cipher/sync/settings routes accept a `slug` in the JSON payload or fall back to active.
- **CLI:** `baluard vaults list` shows STATE column (unlocked/locked/closed). `baluard vaults switch <slug>` prompts for password if locked. `baluard vaults close <slug>` unloads. `baluard vaults set-default <slug>` persists registry `active_vault`. `baluard --vault <slug>` uses the daemon when the vault is open in the map, `--direct` otherwise.
- **Desktop:** `VaultSwitcher` dropdown in sidebar header. `VaultSwitcherContext` polls `vaults.list` on mount + 30s heartbeat. Picking an unlocked vault = instant switch + `vault.list_full` refetch. Picking a locked/closed vault routes through AuthContext's `switchTarget` signal to the unlock screen for that slug.

### Import/Export

- Import runs in Rust core (no JS parsing of secrets). Output: `Vec<CipherInput>`, batch-create
- 8 formats: bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1password_1pux, 1password_csv, keepass_xml
- 2 export formats: bw_json, bw_csv (both BW-compatible)

### TOTP

- RFC 6238/4226. SHA1/256/512, 6/8 digits, 30/60s periods
- Seed NEVER crosses IPC. Only derived numeric code sent to frontend
- `TotpParams.secret` zeroized on drop

### Password Generator

- `crypto.getRandomValues` exclusively (never `Math.random`)
- EFF large word list (7776 words) bundled as static asset

### Backward Compatibility

- Missing `type` field auto-migrated to `Login`
- `Vec<String>` URIs auto-migrated to `Vec<LoginUri>` with Domain default
- Unknown `UriMatchStrategy` string values produce hard error

### Key Hierarchy

```
Master Password -> KEK (Argon2id) -> Device Private Key (X25519, HPKE-escrowed)
  -> Root Key (512-bit, per-epoch) -> Space Group Key (256-bit, per-space)
    -> Item Keys (256-bit, per-cipher)
```

### Epoch State Machine

`CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED`

Root key rotation generates new RootKey, re-encrypts all entries, wraps KEK only for surviving devices.

### Device Registry

- `DeviceRegistry`: enroll, revoke, force-evict, quorum (ceil(N/2))
- Stored in `meta/devices.json` (plaintext, per DOMAIN 5/D1 in architecture decisions)
- Epoch rotation with two-phase commit via git-mediated ack files

---

## Known Limitations

1. **No real-time revocation**: Revoked device retains data until it pulls. Root key rotation limits damage to stale snapshot.
2. **Git credentials out-of-band**: Revoking vault access does NOT revoke git push access. User must rotate deploy keys / PATs manually.
3. **Metadata leakage via bucket sizes**: Standard logins mapped to 5KB, notes to 30KB/100KB, attachments to 250KB/2MB.
4. **Offline sharing limitation**: Invites and revokes require push to remote git host.
5. **Sync routed through daemon**: All sync commands default to daemon with `--direct` fallback.

---

## CLI Command Reference

| Command | Mode | Description |
|---------|------|-------------|
| `init [OPTIONS]` | Direct | Create new vault. Flags: `--profile`, `--name`, `--slug`, `--theme`, `--lang`, `--auto-lock` (no `--subtitle`: removed 2026-06-11) |
| `unlock` | Daemon/Direct | Unlock vault (returns `{slug, token}`) |
| `lock` | Daemon | Lock vault, zeroize keys |
| `add <type> ...` | Daemon/Direct | Add cipher (8 subcommands: login, card, secure-note, identity, ssh-key, bank-account, drivers-license, passport) |
| `tags {create\|list\|rename\|delete}` | Daemon/Direct | Tag management |
| `get <id> --decrypt` | Daemon/Direct | Get cipher by UUID |
| `list` | Daemon/Direct | List all cipher UUIDs |
| `edit <id>` | Daemon/Direct | Edit cipher metadata |
| `delete <id>` | Daemon/Direct | Delete cipher |
| `archive <id>` / `unarchive <id>` | Daemon/Direct | Archive/restore cipher |
| `folders {create\|list\|rename\|delete}` | Daemon/Direct | Folder management |
| `sync {init\|remote\|push\|pull\|clone\|...}` | Daemon/Direct | Git sync operations |
| `import <format> <file>` | Daemon | Import entries |
| `export <format> <file>` | Daemon | Export entries |
| `health` | Daemon | Password health report |
| `attach-*` | Daemon | Attachment upload/download/delete/list |
| `devices {list\|revoke\|info\|rotation-status\|rotation-abort\|enroll-with-phrase}` | Direct/Daemon | Device fleet |
| `passkey {list\|delete\|rename}` | Daemon | FIDO2 passkey management |
| `vaults {list\|switch\|close\|set-default\|add\|detach\|prune}` | Daemon | Multi-vault CLI |
| `provider {list\|connect\|disconnect\|repos\|vault-repos\|status}` | Daemon | Git provider ops |
| `ssh-key` | Daemon | SSH key generation |
| `biometric {enable\|disable\|status}` | Daemon | Per-vault biometric quick-unlock |
| `pin {enable\|disable\|status}` | Daemon | Session PIN quick-unlock (Linux + Windows-without-Hello) |
| `bridge {list\|pair-start\|pair-complete\|revoke\|reauth}` | Daemon | Browser extension pairing (desktop UI drives these) |
| `ping` | Daemon | Check daemon connectivity |

**Flags**: `--vault-path <dir>`, `--vault <slug>`, `--direct` (skip daemon), `--socket <path>`

**Env vars**: `BALUARD_PASSWORD` (bypass TTY prompt for scripting), `BALUARD_DEBUG=1`, `BALUARD_LOG_DIR=<path>`, `BALUARD_DISABLE_KEYRING=1` (hermetic test mode, routes keyring paths to fail-closed fallbacks)

---

## File Map

```
baluard/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── baluard-core/               # Rust Core: crypto, keys, vault, padding, sync, import/export, health, biometric, attachments, providers, orgs, emergency, integrity, recovery, bridge
│   │   └── src/                    # crypto/{aead,hkdf_derive,hpke_wrap,kdf,signature,totp}.rs + webauthn/
│   │                                 # keys/{epoch,hierarchy,nonce,rotation}.rs
│   │                                 # vault/{attachment,avatar,canary,cipher,creation,envelope,handle,index,keywrap,manifest,padding,registry,slug}.rs
│   │                                 # sync/{commit,conflict,credentials,engine,known_hosts,operations,state_machine}.rs
│   │                                 # import/ + providers/{codeberg,github,gitlab,mod,token,types}.rs
│   │                                 # bridge/{mod,pairing,token}.rs
│   │                                 # resources/global_equivalent_domains.json
│   │                                 # biometric.rs, device_manager.rs, devices.rs, emergency.rs, health.rs, integrity.rs, orgs.rs, recovery.rs, paths.rs, types.rs, error.rs, lib.rs
│   ├── baluard-runtime/            # Shared vault-session runtime (hosted in-process by daemon, NMH, mobile)
│   │   └── src/                    # host.rs, state.rs, autosync.rs, pin.rs, bridge.rs, rate_limit.rs, providers.rs, crypto.rs, lib.rs
│   ├── baluard-uniffi/             # UniFFI bindings consumed by mobile/shared (Kotlin Multiplatform)
│   │   └── src/                    # lib.rs, baluard.udl
│   ├── baluard-cli/                # Terminal CLI (daemon-first + --direct fallback)
│   │   └── src/                    # main.rs, client.rs, commands/mod.rs (~112K)
│   ├── baluard-daemon/             # IPC daemon shell (Unix socket, Protobuf gateway, 0600 perms)
│   │   └── src/                    # main.rs, handler.rs, socket_path.rs, lib.rs
│   └── baluard-nmh/                # Native messaging host (browser extension bridge). stdio-JSON <-> varint-protobuf. Stateless
├── desktop/                      # Tauri v2 Desktop (SolidJS/Tailwind)
│   ├── src-tauri/                  # Rust backend: daemon sidecar, baluard-nmh sidecar, tray, proto codegen
│   ├── src/
│   │   ├── components/         # 38 components (VaultView, CipherDetail, SshKeyGenerator, SetupScreen, FocusTrap, WelcomeScreen, CloneFromProviderScreen, BridgeTab, ConflictBanner, ConflictResolutionPanel, DetachVaultModal, SwitchUnlockModal, VaultSwitcher, AutoSyncIndicator, DeviceFleetPanel, SyncTab, SettingsModal, ...)
│   │   ├── context/             # AuthContext.jsx, VaultContext.jsx, VaultSwitcherContext.jsx, AutoSyncContext.jsx, ConflictResolutionContext.jsx, themeSignal.js, toastSignal.js
│   │   ├── lib/                 # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, helpers.js, biometry.js, clipboard.js, vaultPrefetch.js, vaultTimeout.js, slug.js, cloneFlow.js, providerConnect.js, disableAutofill.js, eff-words.js, wordlist-{en,es}.js
│   │   ├── __tests__/           # vitest tests (payload, utils, filters, cipherSchema, sync)
│   │   └── i18n/locales/        # en.json, es.json (all user-facing strings)
├── browser/                      # MV3 Browser extensions (Chromium + Firefox, shared codebase)
│   ├── shared/                    # 95% of code (popup SolidJS, service worker, content script, nmh wrapper, autofill, pair, vitest tests)
│   ├── chrome/                    # Chrome MV3 wrapper
│   └── firefox/                   # Firefox MV3 wrapper
├── mobile/                       # Kotlin Multiplatform app (Compose Multiplatform UI, baluard-uniffi bindings; Phases 0-6 implemented, Phase 7 iOS next)
│   ├── shared/                    # commonMain (UI + ViewModels + VaultRepository), androidMain, iosMain
│   └── androidApp/                # Android host app (single-Activity, BaluardAutofillService, BaluardAccessibilityService, BaluardA11yTileService, AutofillActivity), resources, R8 release build
├── docs/                         # Architecture & design docs (index, arch, decisions, plans, PRDs, threat model, 2fa, post-quantum, brand, app icons)
└── justfile                      # Build system (`just` recipes for build, test, lint, fmt, desktop, ext-*, android-*, app-icons, build-nmh, install-nmh-manifest, codesign)
```
