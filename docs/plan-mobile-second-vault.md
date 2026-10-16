# A Second Vault on the Phone (mobile create-vault entry point)

- Status: Draft for review
- Date: 2026-10-16
- Author: Esteban

## 1. Problem

A phone that already holds one vault cannot create another one. Vault creation
on mobile exists only on the first-run onboarding root; every later entry point
routes to the provider clone flow instead. The two-phone org share journey
pinned the consequence: the founder-side merge-exclusion check (G24 §4.2, an
org Space must never merge into a personal vault) is untestable on device
because the founder phone cannot make the personal second vault it needs. The
journey carries a documented skip for exactly this reason. The same gap bites
real users: someone who cloned a family or organization vault has no way to
give the phone its own personal vault.

Current behavior, grounded in source:

- `VaultHomeScreen`'s switcher dialog carries one action row, "Add vault"
  (`home.addVault`), wired to `onAddVault` (VaultHomeScreen.kt ~325).
- `App.kt` stages that as `unlocked = false; showOpen = true` (App.kt ~507),
  and `showOpen` routes to `RootStage.OpenProvider` in the `currentRoot`
  when-chain (App.kt ~394) — the provider clone flow, creation is unreachable.
- `RootStage.CreateVault` mounts `CreateVaultScreen`, but the only caller that
  sets `showCreate = true` is `OnboardingScreen` (App.kt ~725), which mounts
  only when no vault exists (`!hasVault -> RootStage.Onboarding`).
- Cancelling the clone flow drops the user to the unlock screen
  (`hasVault = AppPaths.vaultExists(path); showOpen = false`, App.kt ~689)
  even though the current vault is still unlocked in the session — the staged
  `unlocked = false` is a UI flip only, and nothing restores it.

## 2. Product rule

The vault set is managed in one place: the switcher. A phone gets two ways to
grow it, in plain language:

- "Create a new vault" — a fresh, empty vault born on this device.
- "Add vault" (today's row, unchanged) — bring a synced vault over from
  another device through the provider clone flow.

No git term, no slug, no path ever reaches the user. The vault's directory
name and storage layout stay invisible; the switcher shows display names only.

## 3. Design

### 3.1 Entry point

The switcher dialog gains a "Create a new vault" row above the existing
"Add vault" row. Both rows close the dialog and stage a root flip. New
`onCreateVault` callback on `VaultHomeScreen`, new App.kt staging arm:

```
onCreateVault = {
    unlocked = false          // same stage-flip pattern as onAddVault
    createTarget = AppPaths.nextCreatedVaultPath()
    showCreate = true
    nav = Nav.List
}
```

The current vault stays unlocked in the session (MultiVaultSession keeps it);
cancel and completion both return without a second unlock.

### 3.2 Path assignment

New expect/actual `AppPaths.nextCreatedVaultPath(): String` — a fresh,
never-existing directory under the vaults root (`vaults/vault-2`, `-3`, ...).
The collision scan covers BOTH `filesDir/vaults/` and `filesDir/detached/`:
detaching moves a directory aside, so without the check a reused name would
drift to `vault-2-1` on a later detach (detach is collision-guarded, so this
is hygiene, not a safety hole). The first vault keeps its `filesDir/vault`
home; every later created vault lives under `filesDir/vaults/` beside the
clones, so `VaultRegistry.listVaults()` discovers it with zero registry
changes. The directory name is machinery; display identity comes from the
marker slug (§3.3). The stale "mobile is one-vault-at-a-time" doc comment on
`AppPaths` is corrected.

The mount changes with it: `RootStage.CreateVault` passes
`vaultPath = createTarget ?: path` where `createTarget` is the new App state,
and first-run staging (`OnboardingScreen`'s `onCreateVault`) sets
`createTarget = path` so both entries flow through one variable. Without the
mount change the form would create into the CURRENT vault's directory — the
plan's first draft missed exactly this, caught in review.

### 3.3 Naming (the one FFI change)

A created vault with no name renders as "Vault" or "Vault-2" in the switcher —
machine-flavored and indistinguishable. The design adds one optional display
name to creation, riding the existing `VaultCreator` builder:

- `create_vault_with_recovery(path, master_password, device_name)` gains a
  fourth parameter `display_name: Option<String>` (pre-1.0 signature break,
  no compat shim).
- Core wiring inside the wrapper: `.profile(display_name, None)` and
  `.slug(suggest_slug(&name))` so the `.baluard` marker carries the
  normalized slug; `VaultRegistry.displayName` already renders
  `baluard-work` as "Work" with no further changes.
- The name field is PRE-FILLED with "Personal" (the CLI's own default) and
  fully editable, so a first-run vault created without touching it is
  `baluard-personal` / "Personal" instead of the directory-derived "Vault".
  Disclosed behavior change for newly created vaults only; nothing on disk
  migrates. A cleared field also resolves to "Personal".
- `CreateVaultScreen` gains one "Vault name" text field above the password
  field. No shipped Maestro flow asserts the created-vault hub title (flows
  assert entry names, `e2e/list/search`, or clone-derived slugs), so flows
  01 and 14a are unaffected. The journey leg that consumes this feature
  (§5, 14e) names its second vault explicitly so the switcher never shows
  two identical rows, and its rewrite retires the stale `"Vault (1)"`
  pill selector the old 14e text carried.

### 3.4 Completion and cancel bookkeeping

`onCreated` in App.kt currently only flips `hasVault`/`unlocked` — correct
for first run, wrong for a second vault (the App `path` state would keep
pointing at the old vault). The staged flow mirrors `switchVault`'s
post-unlock bookkeeping:

```
onCreated = {
    path = createTarget
    VaultRegistry.saveActiveVault(createTarget)
    hasVault = true
    showCreate = false
    unlocked = true
    nav = Nav.List
    // session adoption already happened in CreateVaultViewModel (auth.adopt);
    // run the same post-unlock tail a switch gets:
    sync.onUnlock(vault); conflictVm.refresh(vault)
}
```

`auth.adopt` (CreateVaultViewModel.create) already seats the new unlocked
handle in the session under the new path; LRU eviction beyond
`MAX_UNLOCKED = 3` locks the evicted vault by construction, so the
OOM/keys-resident invariant holds.

Cancel is phase-scoped. The creation ceremony has two phases inside
`CreateVaultScreen`: the form (before the FFI call) and the recovery phrase
(after it). Cancel exists only in the form phase — `onCancelled` restores the
live session via the `auth.switchTo(path)` fast path and returns to
`Unlocked`, falling back to today's drop-to-unlock only when the session is
not live. This fixes the pre-existing clone-flow quirk too (§1, last bullet):
both cancel arms (`showCreate = false`, `showOpen = false`) get the same
fast-path restore. Once the phrase is on screen the flow is non-cancellable
(the words-once rule, same as the kit-rotation dialog's non-dismissable
contract): `CreateVaultScreen` registers its own
`BackHandler(enabled = !phraseShown)` so the system back gesture cancels the
form but does nothing during the phrase, and App's central back chain stays
untouched. An app kill mid-phrase leaves an unacknowledged vault directory
behind, discovered on next launch — the same blast radius first-run carries
today, accepted as a boundary.

### 3.5 What deliberately does not change

- The clone flow, provider staging, and enroll handoff are untouched.
- `CreateVaultScreen`'s ceremony (password + confirm + device name ->
  recovery phrase shown once -> acknowledgment) is the same flow first-run
  users get; a second vault gets identical treatment, including the TXT/PDF
  recovery-sheet save.
- G24 eligibility needs no work: a fresh personal vault has no
  `settings-pub.json`, the Kotlin `isMergeEligible` sniff reads absent as
  eligible, and the vault is unlocked in-session so the main-process hub
  search includes it immediately. Autofill is a SEPARATE process
  (`android:process=":autofill"`) with its own handle map and biometric-gated
  unlock: a new vault appears there only after quick-unlock enrollment, and
  until then it surfaces as a locked entry (unlock chip), never as
  credentials — which is the correct secure behavior, not a gap.
- First-run's unlocked handle adoption is unchanged; the second-vault flow
  reuses it verbatim.
- iOS: all changes are commonMain plus expect/actuals that already exist;
  the iOS `VaultRegistry` stays an in-memory stub, so second-vault
  switching there remains launch-scoped (iOS surface work is parked
  project-wide).

## 4. Non-goals

- No vault rename or delete UI (detach exists; rename is desktop/CLI only —
  adjacent gap, separate wave).
- No creation entry from the unlock screen (the switcher is the vault-set
  surface; scope stays minimal).
- No desktop or CLI changes; the desktop wizard remains the reference flow.
- No migration of previously created vaults (they keep directory-derived
  names until renamed, which §4 defers).

## 5. Test plan

- UniFFI contract test (`create_vault_with_recovery_returns_phrase_...`)
  extends to pass a display name and assert the marker slug on disk, plus
  the empty-name default leg.
- commonTest: `MultiVaultSession` is unaffected (adoption path unchanged);
  no new unit surface — the routing layer is App.kt state with no harness.
- E2E: un-skip journey leg 14e. The founder phone creates a personal second
  vault through the new switcher row (name "Personal"), completes the
  recovery acknowledgment, and the existing positive-control search then
  asserts the org entry is absent from the personal hub — closing the
  documented G24 on-device coverage gap. Fresh APK required.
- Manual checklist: create a second vault while the first stays unlocked;
  cancel in the form phase and confirm return without re-unlock; confirm
  back does nothing during the recovery-phrase phase; create a third vault
  and confirm the oldest session locks (LRU); switcher names render for
  named, default-named, and cloned vaults side by side.

## 6. Landing order

1. `AppPaths.nextCreatedVaultPath()` expect/actual trio (vaults + detached
   collision scan) + stale doc fix.
2. One compiling unit: FFI `display_name` parameter + core profile/slug
   wiring + regenerated bindings + the pre-filled name field on
   `CreateVaultScreen` (with its phase-scoped `BackHandler`) + the App.kt
   entry point, `createTarget` mount wiring, staged create routing,
   cancel/back fast-path restore, and `onCreated` bookkeeping + i18n keys
   (en/es/pt). The FFI signature change breaks the commonMain callers, so
   the wrapper and its consumers must land together.
3. Wave verification (gradle compiles, uniffi tests, APK rebuild).
4. Peer review, then 14e un-skip and the two-phone org journey re-fire.
