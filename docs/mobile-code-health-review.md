# Mobile Code Health Review: DRY / YAGNI / KISS / Dead Code

Scope: `mobile/` only (shared commonMain + androidMain + iosMain, androidApp). Excludes generated code (`baluard_uniffi.kt`, `generated/`, build outputs).

Method: full read of all hand-written Kotlin (~11.8k lines), symbol-level caller search for every suspect, i18n key parity + usage check, test read.

Status: findings only. No code changed. Action order proposed at the end; several items need a product decision before edits.

---

## Verdict summary

The mobile codebase is in good shape for its age. The sync package (`SyncCoordinator`, `ConflictModels`, `ConflictViewModel`) is small, tested, and single-purpose. `UriSchemes.kt` is the model citizen: one shared, tested decision point with platform actuals kept dumb. `Biometric.android.kt` documents its security properties and its own debt honestly. i18n EN/ES keys are in exact parity.

The debt is concentrated in three places: UI copy-paste (ToggleRow x3, Copied badge x3, search field x2, sync-runner x2, TopAppBar colors x7), leftovers from the pre-hub list UI (dead filter machinery in `VaultListViewModel`), and i18n discipline breaks (~12 hardcoded user-facing strings, plus 8 dead keys, two of which the screens should be using).

---

## 1. Dead code (verified: zero callers)

All of the following have no references outside their own declaration. Verified by symbol search across `mobile/shared/src` and `mobile/androidApp/src`.

### 1.1 `VaultListViewModel` pre-hub filter machinery

Files: `shared/src/commonMain/kotlin/xyz/actitud/baluard/vault/VaultListViewModel.kt`

The hub redesign (`VaultHomeScreen` + `EntryListKind`) replaced the old chip-filter list, but the old filter plumbing survived. Dead today:

- `typeFilter`, `tagFilter`, `folderFilter`, `favoritesOnly` + `setTypeFilter` / `setTagFilter` / `setFolderFilter` / `setFavoritesOnly` (~L44-L74)
- `allTags()`, `allTypes()`, `allFolders()`, `folderName()` (~L155-L177), written for the old chip rows
- Inside `filtered()` (~L205-L235): the `type` / `tag` / `folder` / `favOnly` branches are unreachable in practice. The only caller (`VaultHomeScreen` search, L344) never sets them, so every call evaluates four always-null guards.

Fix: delete the four state flows + setters + the four aggregate helpers, and reduce `filtered()` to the query + deep-index check it actually performs. ~50 lines gone, and `filtered()` stops lying about what it filters.

### 1.2 `VaultRepository` orphan wrappers

File: `shared/src/commonMain/kotlin/xyz/actitud/baluard/data/VaultRepository.kt`

- `createVault()` (L64): superseded by `createVaultWithRecovery()` (L73); no callers. The create flow is `CreateVaultViewModel.create` -> `createVaultWithRecovery`.
- `generateRecoveryPhrase()` (L47): no callers. The phrase surfaces through `MobileCreateResult.recoveryPhrase`.
- `deriveKek()` (L61) is alive (UnlockScreen enroll path), do not touch.

### 1.3 `AuthViewModel.isUnlocked()`

File: `shared/src/commonMain/kotlin/xyz/actitud/baluard/auth/AuthViewModel.kt` (L103). No caller. Lock state is tracked by `App.kt`'s `unlocked` flag; the runtime's `shouldAutoLock()` covers the rest.

### 1.4 `autoLockToken` in `App.kt`: correction, not dead

File: `shared/src/commonMain/kotlin/xyz/actitud/baluard/ui/App.kt`

Peer review correction: `autoLockToken` (declared L151, written L507 in `onVaultTimeoutChange`) IS read, at L481, where it is passed into `SettingsScreen(vaultTimeoutToken = autoLockToken, ...)` to seed the auto-lock dropdown's current selection. This item is withdrawn: the state is live, not dead code.

### 1.5 Autofill scaffold pieces

- `androidApp/src/androidMain/kotlin/xyz/actitud/baluard/autofill/KeystoreKekProvider.kt`: whole object returns `null` behind a Phase 6 TODO, and nothing calls it (the autofill service's TODO mentions the mechanism but never references the object). Delete; restore from git when Phase 6 lands.
- `BaluardAutofillService.presentation()` (`androidApp/.../BaluardAutofillService.kt` ~L124): `@Suppress("unused")` placeholder for the future Dataset UI. The author already flagged this as intentionally-dead scaffolding (it is the only `@Suppress("unused")` in the codebase), so this is confirming a known state, not a fresh discovery. Same call: delete, restore when needed. Keeping dead scaffolding in-tree means it rots uncompiled against real APIs.

### 1.6 `SyncCoordinator.offlineTick()` + `SyncConfig.offlineRetryForegroundSecs`

File: `shared/src/commonMain/kotlin/xyz/actitud/baluard/sync/SyncCoordinator.kt`

The doc block says "the host schedules `offlineTick` while the vault is Offline AND foregrounded". No host does: only the test calls it. `offlineRetryForegroundSecs` is parsed by `SyncConfigStore.android.kt` but read by no logic.

This one needs a decision, not a blind delete:

- Wire it (App.kt already runs a 15s unlocked poll; one more `state == offline` check + `offlineTick` call is ~5 lines), or
- Delete `offlineTick` + the config field + its store persistence + the test case.

Recommendation: wire it. The offline-retry probe is a plan commitment (plan §3.5), the coordinator method is tested, and the runtime already classifies network errors. The current state is "built, tested, never plugged in".

### 1.7 `ProviderFlowViewModel.clear()`

File: `shared/src/commonMain/kotlin/xyz/actitud/baluard/onboarding/ProviderFlowViewModel.kt` (L118). Never called; the `vmScope` it cancels is app-lifetime anyway (the VM is a root `remember`). Delete `clear()`, and drop the `vmScope.cancel()` intent from it, or call it from `onVaultRemoved`. Keeping an uncancellable scope with no cleanup hook is fine; keeping an unused cleanup method is not.

### 1.8 Unused FFI surface (note only, cross-cutting)

- `MobileVaultInterface.resolveConflictKeepBoth()` is never called by the app: the UI sends the `keep_both` verdict string through `resolveConflict()`. The method exists because the UniFFI surface exports it. Removing it is a Rust-side change (`crates/baluard-runtime`/uniffi regen), out of mobile-only scope. Listed so it is not mistaken for live mobile API.
- Tag/folder CRUD methods (`createTag`, `deleteTag`, `renameFolder`, `createFolder`, `deleteFolder`, `listTags`) are unused by mobile UI. Same story: part of the generated interface, potentially future autofill/edit parity. No action.

### 1.9 Dead i18n keys

Files: `shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEn.kt`, `StringsEs.kt`

Keys defined in both locales, referenced nowhere (checked against literal use; `detail.type.*` is NOT on this list because `typeLabelKey()` builds those keys dynamically):

- `vault.favorite`, `vault.favorites` (the live screens use `home.favorites`)
- `provider.title`, `provider.selected`
- `deviceCode.title`, `enroll.title`
- `generator.length`, `generator.wordCount`

The last two are special: the generator screen shows English literals ("Length", "Word count") where these keys were clearly meant to go. Delete the key pair or use it; using it is the fix I would take (see 4.1).

---

## 2. DRY violations

### 2.1 Sync-now runner duplicated

`App.kt` `startSync` (L192-L214) and `SettingsScreen` sync-now button (L135-L165) implement the same choreography twice: mark-now -> `pullNow` -> 600 ms minimum spinner hold -> phase "synced"/"offline" -> 2.5 s -> idle. Identical magic constants (600 ms, 2500 ms) pasted in both places. Settings' copy omits the toast and conflict refresh, so the two already drifted.

Fix: one shared runner (e.g. `runSyncPhase(vault, coordinator, onPhase: (String) -> Unit): Boolean` in the sync package) used by both callers. App's version keeps its extra refresh/toast by passing callbacks or wrapping.

### 2.2 ToggleRow x3

`SettingsScreen.ToggleRow` (~L242) and `GeneratorScreen.ToggleRow` (~L360) are the same composable with a 2 dp padding difference. The biometric row in `SettingsScreen` inlines a fourth variant of the same Switch + colors. Move one `ToggleRow` into `BaluardComponents.kt`, delete the copies.

### 2.3 "Copied" badge + reset timer x3

`CopyableFieldRow` (`BaluardComponents.kt` ~L730-L766), `GeneratorScreen` (~L170-L190 + L69-L75), `TotpWidget` (~L155-L180 + L47-L53) each build: `copied` state, a `LaunchedEffect(copied) { delay(1500); copied = false }`, an animated pill with hardcoded "Copied", and a copy IconButton. Extract a `CopiedBadge` (+ a `rememberCopiedFeedback()` helper or a `copyWithFeedback(value, onCopied)` wrapper) into `BaluardComponents.kt`. This also kills the hardcoded "Copied" string three times over.

### 2.4 Search field x2

`VaultHomeScreen` (L268-L310) and `EntryListScreen` (`VaultListScreen.kt` L113-L155) duplicate the search OutlinedTextField: leading search icon, trailing clear icon wired to `setQuery("")`, rounded corners, surface-container colors. Extract `BaluardSearchField(value, onValueChange, modifier)`.

### 2.5 Cipher type tags: three unmanaged copies of the same list

The 8 cipher types are spelled out in three places with two different casings:

- `EditCipherScreen.TYPE_TAGS` (L31): camelCase wire tags (`"secureNote"`, `"sshKey"`, ...), correct for daemon payloads.
- `VaultHomeScreen.typeRows` (L84-L86): lowercase debug tags (`"securenote"`, ...) matching `MobileCipherMeta.cipherType`.
- `BaluardComponents.typeBrushes` (L320) + `typeAccentColors` (L341): lowercase, and duplicated between the two maps.

`normalizeTypeTag()` (`CipherFields.kt` L17) exists to bridge the casings, which proves the model is confused. Fix without ceremony: one `CipherTypeTags` object in `detail/` (next to `fieldsFor`) holding the wire-tag list, plus `debugTagOf(wireTag)` / `wireTagOf(debugTag)`; derive `typeBrushes` from `typeAccentColors` (`mapValues { Brush.linearGradient(it.value) }`) so the hex pairs exist once.

### 2.6 Preset dropdown picker x2

`SettingsScreen`: the auto-lock dropdown (L285-L310) and the clipboard-clear dropdown (L318-L345) are the same Box + OutlinedButton + DropdownMenu + presets-loop shape. Extract `PresetDropdown(label, presets: List<labeledPreset>, selected, onSelect)`.

### 2.7 TopAppBar styling block x7

`TopAppBarDefaults.topAppBarColors(containerColor = surface, titleContentColor = onSurface)` is pasted in `VaultHomeScreen`, `TagListScreen`, `EntryListScreen`, `CipherDetailScreen`, `GeneratorScreen`, `SettingsScreen`, `EditCipherScreen`. Small, but it is the single most repeated block in the app; a `BaluardTopBar(title, navIcon, actions)` wrapper removes 7 copies and gives every screen the same header for free.

### 2.8 Smaller repeats

- `HorizontalDivider` with `outlineVariant.copy(alpha = 0.35-0.5f)` + padding: ~15 occurrences across 5 files. A `BaluardDivider(startPadding)` helper.
- `vaultsRoot()` duplicated: `AppPaths.android.kt` L16 and `VaultRegistry.android.kt` L12 both define `File(filesDir, "vaults")`. One `internal` helper (e.g. in `AppContextHolder` or `AppPaths`), one definition.
- Toast colors hardcode theme tokens that already exist as `Theme.kt` privates: `0xFF193236` (DetailPanel), `0xFFF3F4F6` (TextPrimary), `0xFFA2B7BA` (MutedDark). Read them from `MaterialTheme.colorScheme` (surfaceContainerHigh / onBackground / onSurfaceVariant) instead of re-spelling hex.
- `ProviderFlowViewModel.fail()` fallbacks are hardcoded English ("Connection failed", "Clone failed", "Enrollment failed", "Authorization failed"). These are user-visible errors; they need i18n keys like every other string.

### 2.9 Onboarding card shell x4

`CreateVaultScreen.kt` (L73-L90), `DeviceCodeScreen.kt` (L82-L99), `EnrollDeviceScreen.kt` (L63-L80), and `ProviderConnectScreen.kt` (L71-L88) repeat the identical container structure: `BaluardAmbientBackground`, centered scrollable Column with 24 dp padding, `BaluardLogoBadge(64.dp, showTitle = true, subtitle = ...)`, 28 dp spacer, and `BaluardCard`. Extract a shared `OnboardingScaffold(subtitle, content)` composable.

---

## 3. YAGNI

### 3.1 Fake configurability in `Toast.show`

File: `ui/toast/Toast.kt` L57. `show(type, message, durationMs = 4000, manual = false)` accepts `durationMs` and never uses it; `AutoDismissingToast` hardcodes 6000/4000 from the type. `Toast.warning(..., durationMs = 5000)` (itself uncalled anywhere) is triple-d dead: unused method + ignored parameter + value that would be ignored anyway.

Fix: drop the `durationMs` parameter, drive dismissal from `manual` + type only. Delete or wire `Toast.warning` (a warning type with zero production emitters is speculative; keep only if a near-term emitter exists).

### 3.2 `EntryListKind.All` never constructed

`vault/EntryListKind.kt`. `Nav.EntryList(...)` is only built with `Totp`, `Favorites`, `Type`, `Folder`, `Tag`, `Archive`, `Trash`. `All` exists for `when` exhaustiveness in two screens. Delete the variant and its two branches (the compiler will find them).

### 3.3 `VaultListViewModel` deep-search index: keep, but measure

`indexSlice()` decrypts every active + archived + trashed cipher (one `getCipher(decrypt = true)` FFI round-trip each) on every `refresh()`, and `refresh()` runs on every hub load, every revision bump, and every sync completion. For a 500-entry vault that is ~1500 decrypt round-trips per refresh cycle.

Not flagging this for deletion: content search is a real feature with desktop parity. Flagging the cost profile: when a vault report says "unlock feels slow", look here first. Cheap mitigation if it bites: index lazily on first search query per vault, or index only name/username/notes from `list`-level metadata when available. No change now.

### 3.4 Stale doc comments (delete or correct)

- `totp/TotpViewModel.kt` L67: "expect/actual could be added for JS targets"; there is no JS target (build has android + 3 iOS targets). Also the sentence sits under a `Clock` that exists and is used elsewhere.
- `platform/Clipboard.kt`: "toasts land with the mobile design pass"; they landed (`ToastHost`).
- `onboarding/ProviderFlowViewModel.kt` ~L59: orphaned one-line comment ("Current poll interval for the device-code screen's loop.") stranded above the `canGoBack` doc block; its function lives 20 lines lower.
- `settings/SettingsViewModel.kt`: "host persists to DataStore"; the host is `SyncConfigStore` (SharedPreferences).
- `sync/SyncCoordinator.kt` class doc: promises a host-scheduled 30s offline probe that no host performs (see 1.6).

---

## 4. KISS

### 4.1 i18n discipline breaks (also a project-rule violation)

The project rule says all user-facing strings go through `t()` with EN + ES in sync. Hardcoded English found in UI:

- `GeneratorScreen.kt`: "GENERATED RESULT" (L157), "Copied" (L176), "Password Settings", "Passphrase Settings", "Length" (L288), "16 chars" (L298), "Word count" (L334), "5 words" (L344)
- `TotpWidget.kt`: "ONE-TIME CODE" (L128), "Copied" (L161), "Next code in" (L203)
- `CipherDetailScreen.kt`: "Credentials & Details" (~L175), "Websites" (~L330), plus contentDescriptions "Favorite" (L170), "Open in browser" (L373)
- `EditCipherScreen.kt`: "Item Details" (~L102), "Credentials" (~L133), placeholder "e.g. GitHub, Netflix, Main Card" (~L110)
- `OnboardingScreen.kt`: all six feature strings (~L70-L90)
- `DeviceCodeScreen.kt`: "Browser Authorization" (L102)
- `EnrollDeviceScreen.kt`: placeholder "Enter the 24 recovery words..." (L88)
- `RecoveryPhraseScreen.kt`: "Copy recovery phrase" (L138)
- `ProviderConnectScreen.kt`: subtitles "Fast device-code login" (L92), "Cloud or self-hosted GitLab" (L101), "Personal access token" (L110), placeholder "ghp_... / glpat-... / token" (L141), contentDescription "Selected" (L271)
- `ProviderFlowViewModel.kt`: error fallback strings (2.8)

Fix: add the keys to `StringsEn.kt` + `StringsEs.kt` in the same change; the existing unused keys `generator.length` / `generator.wordCount` cover two of these.

### 4.2 Onboarding hero copy violates the product's own UX principles

`OnboardingScreen.kt` shows first-launch visitors: "AES-256-GCM + Argon2id client-side security", "Git-Native Sync", "You hold the master keys, no cloud telemetry".

AGENTS.md UX PRINCIPLES: "Never a git term, a crypto term". The first screen of the app does exactly what the principles forbid, in hardcoded English. This needs a product rewrite (proposal: "Encrypted on your device", "Sync through your own account", "Your keys stay yours") and is a decision item, not a mechanical fix.

### 4.3 `TotpViewModel.start` swallows `CancellationException`

File: `totp/TotpViewModel.kt` L28-L53. `start()` runs an infinite 1 s tick loop; when the widget leaves composition the scope cancels, `delay` throws `CancellationException`, and `catch (e: Exception)` converts "user navigated away" into `TotpState.Error("...")` on the shared VM. `ProviderFlowViewModel.fail()` (L247) shows the correct pattern in the same codebase: rethrow `CancellationException` before handling.

Related, same file: `secondsIntoWindow()` (L55) calls `System.currentTimeMillis()` in commonMain while a perfectly good `expect object Clock` is declared 13 lines below (and is consumed by `platform/AppBackground.kt`). If Kotlin/Native lacks `System.currentTimeMillis` this breaks the declared iOS targets at compile time; either way it bypasses the codebase's own abstraction. Use `Clock.currentTimeMillis()`.

### 4.4 `Clock` lives in the wrong package

`expect object Clock` is declared in `totp/TotpViewModel.kt`, with actuals in `totp/Clock.android.kt` / `Clock.ios.kt`, but its only consumer is `platform/AppBackground.kt` (importing `xyz.actitud.baluard.totp.Clock` into a platform file). Move the expect/actual trio to `platform/` next to its consumer; the totp package keeps zero evidence of it once 4.3 lands.

### 4.5 Sync phase is a stringly-typed enum in waiting

`"idle" | "syncing" | "synced" | "offline"` appears as raw strings in `App.kt` (two independent state vars: `homeSyncPhase`, `listSyncPhase`), `SettingsScreen`, and `SyncIconButton`'s `when`. Combined with 2.1: introduce `enum class SyncPhase`, one runner, three call sites, and the typo-class of bug ("syncng") disappears.

### 4.6 `App.kt` is a god composable

642 lines holding: 11 root-scoped ViewModels, the Nav/RootStage state machines, 3 AnimatedContent transition specs, the sync runner, auto-lock timers + background hooks, settings persistence effects, vault switching, conflict overlay, and every screen's full callback wiring. It works, and flat navigation was a reasonable Phase 5 choice. But every new screen adds to one file that cannot be unit-tested and recomposes wholesale.

Not a rewrite proposal. Two cheap moves when next touched: (a) extract the transition specs (they are 60 lines of pure styling) to `ui/Transitions.kt`; (b) group the auto-lock + lifecycle + sync-glue effects into a `VaultSessionEffects` composable. The ViewModels-at-root model is fine; leave it.

### 4.7 Silent failure paths (inconsistent error discipline)

The codebase's own convention is `runCatching` + `platformLogE` + user-visible error (see `VaultListViewModel.refresh`, `UnlockScreen` enroll path, `ProviderFlowViewModel.fail`). Three spots break it:

- `CreateVaultViewModel.create()` catches everything, returns false, logs nothing. The screen then shows a generic "create failed" with the real cause (KDF OOM, disk full, path collision) invisible even in logs.
- `EditCipherViewModel.load()` wraps in `runCatching` with no error state: a corrupt cipher opens the edit form as a blank new-entry form, and saving would overwrite nothing but silently reset nothing either, so the user just sees empty fields.
- `BackgroundFetchWorker.doWork()` (`platform/BackgroundSyncScheduler.android.kt` L47-L60, the worker class lives in this file, not a standalone `BackgroundFetchWorker.kt`) catches `Exception` -> `Result.retry()`, which includes `CancellationException` (WorkManager cancel triggers a pointless retry).

Each fix is 2-4 lines and follows an existing in-repo pattern.

### 4.8 Vault wiring inconsistency

`App.kt` creates one `VaultRepository` and passes it into `SettingsScreen` (as `repo: VaultRepository? = null`; the nullability is also dead weight: the only caller always passes it, and the screen gates the remove-vault row on `repo != null`, a state that never occurs). Meanwhile `CreateVaultScreen` builds its own `VaultRepository()` + `CreateVaultViewModel` locally (L59-L60). One repo instance at the root, passed down; make the SettingsScreen parameter non-null and delete the `enabled = repo != null` guards.

### 4.9 Biometric.android enroll/unlock boilerplate

`Biometric.android.kt`: `enroll()` and `unlock()` duplicate the context/activity guards, prompt-info building, callback plumbing, and error mapping (~80 shared lines across two 120-line functions). A private `runPrompt(activity, cipher, onCipherResult, onError)` helper would halve it. Low urgency: security code values explicitness, and both paths are already reviewed; do it only alongside other work in that file. Listed for completeness.

---

## 5. What is explicitly NOT a problem

- `VaultRepository` as a thin UniFFI wrapper: most methods are one-line delegates, but the wrapper is the only Kotlin-side seam for test fakes and JSON normalization (`listFolders`, `vaultTimeoutToken`). Keep.
- `formatEpochDate` hand-rolled civil-from-days (`CipherDetailViewModel.kt`): avoids a datetime dependency for one display string, documented, tested. Correct call.
- `EditCipherViewModel` merge-on-save payload semantics (preserving unmodeled fields like passkeys/TOTP seeds): subtle but documented against the daemon wire format, and the riskiest logic in the app. It deserves a test (see 6.3) but the design is right.
- Root-scoped ViewModels: stateless or session-scoped by design; matches the single-activity model.
- `UriSchemes.kt`, sync package, `ConflictResolutionPanel`: no findings.

---

## 6. Correctness risks spotted in passing

1. `TotpViewModel` CancellationException-as-Error (4.3): user-visible; returning to a TOTP detail after leaving can briefly show a stale error state.
2. `secondsIntoWindow()` common-source `System.currentTimeMillis()` (4.3): potential iOS-target compile failure; verify with one `:shared:compileKotlinIosSimulatorArm64` run.
3. `EditCipherViewModel.save()` merge-on-save has no test. It is the one function where a regression silently corrupts user data (drops passkeys/TOTP/URIs). A commonTest with a JSON in -> JSON out table belongs in `commonTest/`.
4. `VaultListViewModel.filtered()`'s `contentIndex` lookup is O(vault) per keystroke over decrypted-content strings; fine at current scale, revisit with 3.3 if large vaults arrive.
5. `AuthViewModel.sessionKek` is a public `var` of raw key material on the JVM (heap-managed, GC-copied). The file documents this as accepted v1 debt; keeping the doc current is the action.

---

## 7. Proposed action order

P1, mechanical, low risk, no behavior change (one sitting):

1. Delete 1.1-1.3, 1.5, 1.7 dead code + 1.9 unused keys + 3.2 `EntryListKind.All` + 3.4 stale docs. (1.4 `autoLockToken` withdrawn, see peer review note: it is live, not dead.)
2. Fix 4.3 (rethrow CancellationException; use `Clock`) and 4.4 (move Clock to platform).
3. Add missing i18n keys for 4.1 strings (EN + ES together).
4. Fix 4.7 silent failures (log + surface).

P2, dedupe pass (one sitting, still mechanical):

5. Shared sync runner + `SyncPhase` enum (2.1, 4.5).
6. `ToggleRow`, `CopiedBadge`, `BaluardSearchField`, `BaluardTopBar`, `PresetDropdown`, divider helper, `OnboardingScaffold` into `BaluardComponents.kt` (2.2-2.4, 2.6-2.7, 2.9).
7. Single cipher-type tag source + brush/accent merge (2.5); `vaultsRoot()` single definition (2.8); Toast colors from theme (2.8).

Decision needed from Esteban before P3:

- 1.6 offline probe: WIRED. `offlineTick` now spaces calls to `offlineRetryForegroundSecs` (the field is live) and App.kt's 15s poll calls it every tick; the runtime no-ops unless Offline.
- 4.2 onboarding copy: REWRITTEN in plain language (EN+ES). Git stays (product decision: git is the backbone and safe to name); crypto vocabulary is gone.
- 3.3 deep-search index: LAZY. `VaultListViewModel.ensureContentIndex()` builds the index on the first search keystroke; `refresh()` and every slice reload only invalidate it. EntryListScreen + VaultHomeScreen collect `indexVersion` so content matches appear once the index lands.
- Peer review: not run for this pass. The review CLI stalls on tool-use turns; rerun with a no-tool prompt when needed.
- Desktop parity: `GitExplainerModal.jsx` added to the Sync tab + `gitWhat` i18n section (EN/ES), matching the mobile explainer.

## 8. Implementation record (2026-09-14)

All P1 + P2 items plus the three product decisions are implemented and verified.

Executed:

1. Dead code deleted: VaultListViewModel filter machinery (~50 lines), VaultRepository.createVault + generateRecoveryPhrase, AuthViewModel.isUnlocked, ProviderFlowViewModel.clear (cancelClone kept: RepoPicker uses it), KeystoreKekProvider, BaluardAutofillService.presentation, EntryListKind.All, Toast.warning + the ignored durationMs parameter, 2 dead i18n keys (vault.favorites, provider.title), stale docs (Clipboard, TotpViewModel JS note, ProviderFlowViewModel orphan, SettingsViewModel DataStore note).
2. i18n: 293 keys per locale, EN/ES in exact parity, no duplicates. Reused dead keys (vault.favorite, deviceCode.title repurposed, generator.length/wordCount reshaped, common.selected new). All hardcoded UI strings now go through t().
3. Shared components in BaluardComponents.kt: BaluardTopBar (with titleContent variant for the hub's brand row), BaluardSearchField, ToggleRow, PresetDropdown + LabeledPreset, CopiedBadge + rememberCopied, BaluardDivider. Toast colors now read MaterialTheme tokens; SyncIconButton takes SyncPhase.
4. Sync: SyncPhase enum + shared runSyncCycle (single copy of the 600ms/2500ms choreography); offline probe wired; SyncCoordinator doc corrected.
5. Platform: Clock expect/actual moved totp -> platform (used by AppBackground + TotpViewModel); secondsIntoWindow no longer calls System.currentTimeMillis (iOS native compile risk removed); single vaultsRoot; BackgroundFetchWorker rethrows CancellationException and logs failures.
6. Lazy deep-search index (see decisions).
7. Silent failures surfaced: CreateVaultViewModel logs + exposes the real error; EditCipherViewModel.load has a loadError state; TotpViewModel rethrows CancellationException instead of showing it as an error.
8. Tests: new EditCipherPayloadTest (merge-on-save contract: unmodeled fields survive, cleared fields send null, new entries omit id); StubVault extended for interface members it had missed.
9. Onboarding hero rewritten; first FeatureRow is now "Encrypted on your device"; git named plainly in the sync feature line.

Verification: `:shared:compileDebugKotlinAndroid` PASS; `:shared:testDebugUnitTest` PASS (all suites, incl. the new payload test); desktop `vite build` PASS + vitest 229/229 PASS.

Known blockers, pre-existing, unrelated to this pass:

- Gradle on this Linux box fails configuration under JDK 26 (Kotlin's JavaVersion parser rejects the 4-segment "26.0.2.1" string). Workaround used for verification: run Gradle with JAVA_HOME=openjdk@17.
- `:shared:compileKotlinIosSimulatorArm64` cannot pass anywhere while the JNA-based generated bindings (baluard_uniffi.kt) sit in commonMain; iOS compile needs the generated set moved to androidMain or expect/actual split (pre-existing; out of scope here).
- androidApp/build.gradle.kts now pins ndkVersion 27.2.12479018 (installed locally); AGP 8.7's default 26.0.2.1 is absent and its auto-download fails on this machine.

Not done (deferred by decision): App.kt transition/effects extraction (4.6) stays out of this pass; Biometric.android enroll/unlock helper (4.9) unchanged.
Out of mobile scope, noted for the backlog: remove `resolveConflictKeepBoth` from the mobile-unused FFI surface (Rust + uniffi regen), and the `formatEpochDate`-style utilities stay as they are.

---

## Peer review

Verified against source (grep + read) on 2026-09-14: all Section 1 dead-code claims (1.1-1.3, 1.5-1.9), all Section 2 DRY claims (2.1-2.5, 2.7-2.8 `vaultsRoot()`/Toast.warning), Section 3.2 `EntryListKind.All`, Section 4.3-4.4 (`Clock` split), 4.6 line count (642, confirmed exact), 4.7 (`CreateVaultViewModel`, `BackgroundFetchWorker`), and 4.8 (duplicate `VaultRepository()` construction in `App.kt` and `CreateVaultScreen.kt`, nullable `repo` param never actually null).

Corrected: 1.4 `autoLockToken` was wrong. It is read at `App.kt:481` (`vaultTimeoutToken = autoLockToken`, seeds the SettingsScreen auto-lock dropdown), not write-only. The item and the P1 delete list were amended; it is withdrawn as a dead-code finding.

Added: a note on 1.5 that `presentation()`'s `@Suppress("unused")` is the only one in the codebase, meaning the author already marked it as known-dead scaffolding rather than an accidental leftover; a file-path correction on 4.7's `BackgroundFetchWorker` (it is a class inside `platform/BackgroundSyncScheduler.android.kt`, not its own file).

No other false positives found. No significant missed dead-code, DRY, YAGNI, or KISS issues surfaced in the mobile-only scope beyond what the document already lists.

Second peer review on 2026-09-14: verified items 1.1 (zero callers for filters and helpers in `VaultListViewModel.kt`), 1.2 (zero callers for `createVault` and `generateRecoveryPhrase` in `VaultRepository.kt`), 1.9 (unused i18n keys `vault.favorite`, `provider.title`, `deviceCode.title`, `enroll.title`), 2.2/2.3 (`ToggleRow` and "Copied" badge duplicated across screens), and 4.3 (`TotpViewModel` catches `Exception` without rethrow of `CancellationException`, and `secondsIntoWindow()` calls `System.currentTimeMillis()` instead of `Clock`). All five claims verified. Corrected `CopyableFieldRow` line reference in 2.3 (~L730-L766). Added missed findings: hardcoded English in onboarding screens (`EnrollDeviceScreen.kt` placeholder, `RecoveryPhraseScreen.kt` button text, `ProviderConnectScreen.kt` subtitles and placeholder) in 4.1, and duplicate onboarding card shell across four screens in 2.9. Agreed with proposed P1 and P2 action order: P1 handles correctness, crash risks, dead code, and i18n parity without functional risk; P2 consolidates duplicated UI components and helpers.

## Peer review round 2

Review of the full implementation of this plan (P1 dead-code, P2 dedup, offlineTick wiring, lazy content index, Clock package move, i18n rework, git explainer, silent-failure fixes, EditCipherPayloadTest, ndkVersion pin).

### What was checked

- Full diff of `mobile/` and the touched desktop files (`SyncTab.jsx`, desktop `en.json`/`es.json`).
- Suspected regression list: Toast colors, ToggleRow padding, archived-item filter guard, `EntryListKind.All` removal, sync toast timing.
- Every `t("...")` / `Strings.EN`/`Strings.ES` key literal used in touched screens and view models, cross-checked against both locale maps (mobile Kotlin maps and desktop JSON).
- Every new key literal in `GitExplainerModal.jsx` and `SyncTab.jsx` against desktop `en.json`/`es.json`.
- `EditCipherPayloadTest.kt` against the current `EditCipherViewModel.buildPayload` signature and `EditForm` shape.
- Log statements in touched files for secret leakage (password, TOTP seed, token, master password).
- The lazy content index (`VaultListViewModel.indexContent`) for password/TOTP/hidden-field exclusion.
- `KeystoreKekProvider.kt` deletion: grepped the full `mobile/` tree for remaining references.
- Modal accessibility (`role="dialog"`, `aria-modal`, `aria-labelledby`) on the new `GitExplainerModal.jsx` against the existing modal pattern (`DeleteConfirmModal.jsx`).

### Fixes applied

- `desktop/src/components/GitExplainerModal.jsx`: dismiss button called `t("common.continue")`, a key that does not exist in `desktop/src/i18n/locales/en.json` or `es.json` (mobile has it, desktop does not). It would have rendered the literal string "common.continue" to the user. Changed to `t("entry.close")`, an existing key already used in the same file.
- `desktop/src/components/GitExplainerModal.jsx`: the outer dialog div was missing `role="dialog"`, required by every other modal in the app (see "Modal Accessibility" in project conventions). Added it.
- `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/vault/VaultListScreen.kt`: duplicate `import androidx.compose.material.icons.filled.Inbox` (imported twice). Removed the duplicate.
- `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/detail/CipherDetailViewModel.kt`: `load()` and `delete()` caught `Exception` and set `error = e.message` with no `CancellationException` rethrow and no log call, even though `platformLogE` was already imported (dead import, half-finished fix). This is the same silent-failure class fixed elsewhere in this same plan (`EditCipherViewModel`, `CreateVaultViewModel`) but missed in this file. Added the rethrow + `platformLogE` call to both catch blocks.
- Removed 4 dead imports left over from the `BaluardTopBar` dedup (screens stopped building their own `TopAppBar` but kept the now-unused `IconButton` / `ArrowBack` imports): `CipherDetailScreen.kt`, `EditCipherScreen.kt`, `SettingsScreen.kt`, `VaultHomeScreen.kt`.

### Remaining risks / left as-is

- Toast background/text colors changed from hardcoded dark values (always dark navy, regardless of app theme) to `MaterialTheme.colorScheme`-driven values that follow light/dark theme. This is a real visible behavior change in light mode. Judged intentional and correct: the app already supports light/dark theme everywhere else (`ui/theme/Theme.kt`), and a toast that ignored the light theme was the actual pre-existing inconsistency. Not reverted.
- `ToggleRow`'s shared padding is 6dp (previously Settings used 6dp, Generator used 4dp locally). Generator rows now render with 2dp more vertical padding than before. Cosmetic only, not misaligned with anything. Left as-is.
- `EntryListKind.All` and the i18n key `home.allEntries` still exists in `StringsEn.kt`/`StringsEs.kt` but is now unreferenced (the "all entries" list was only ever reachable through the removed sealed variant). Left as unused-string debt; low value to chase further this round.
- `runSyncCycle`'s `setPhase(Syncing)` now happens as the first statement inside the launched coroutine rather than synchronously before `scope.launch`. In theory this opens a narrow double-launch race on a very fast double-tap; in practice `rememberCoroutineScope()` in Compose runs with an immediate dispatcher so the state update happens before control returns to the caller. Not changed.
- `generator/GeneratorScreen.kt` has an unused `androidx.compose.ui.graphics.Color` import; confirmed pre-existing (not introduced by this refactor, not touched by this diff). Left alone per "don't delete existing dead code you didn't create," just flagged here.

### Confirmed NOT a regression (suspected items that turned out fine)

- Archived-item filter guard: `VaultListViewModel.filtered()` dropped its `!m.archived` check, but the only caller passes `_ciphers.value`, which is sourced from `list_cipher_meta()` (Rust, `handle.rs`) — that call already excludes archived entries server-side. The guard was redundant, not load-bearing.
- `EntryListKind.All` removal: zero remaining references anywhere in `mobile/`; the `when` blocks in `listFor()` and the screen title switch are exhaustive over the 7 remaining variants.
- `KeystoreKekProvider.kt` deletion: zero references left anywhere in `mobile/`. It was a stub that always returned `null` (`// TODO Phase 6`), never wired into the autofill unlock path.
- i18n parity: EN and ES key sets in `StringsEn.kt`/`StringsEs.kt` are identical (303 keys each, no diff either direction). All literal `t("...")` calls in touched screens/view models resolve to a real key.
