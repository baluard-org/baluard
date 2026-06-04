# RFC: Split AppContext into Focused Stores

**Date:** 2026-06-04
**Status:** Accepted
**Scope:** `desktop/src/context/`, `desktop/src/hooks/useActions.js`
**Type:** Architecture refactor, no behavioral changes

---

## Problem

`AppProvider` (102 lines) holds 30 signals in a single context. Every component imports `useApp()` and destructures from the monolith. `useActions` (243 lines) mutates 20+ signals across 4 domains.

**Symptoms:**

1. **Stale state bugs.** `lock()` manually resets 7 signals across auth, cipher, navigation, and UI domains. A `revokeWarning` not-cleared bug already shipped from this pattern.
2. **Untestable actions.** `useActions` requires mocking the entire 30-signal context. Zero tests exist for it.
3. **Over-exposure.** LoginScreen pulls the entire store to reach 3 signals. Modal components reach through 28 unrelated signals to toggle one boolean.
4. **Flat buffer fragility.** `newCipher` is a 60+ field object shared between AddEditCipherForm, CipherDetail, and payload.js with no type safety and no documented contract.

---

## Solution

Split the monolith into:

- **AuthProvider** (3 signals) — lifecycle + session metadata
- **VaultProvider** (12 signals) — cipher data, navigation, device fleet
- **Standalone signals** (2) — error, theme (module-level, not in a provider)
- **Local state** (8 signals) — moved to owning components

Actions co-locate in their owning store. `useActions.js` is deleted.

---

## Store Layout

### AuthProvider (3 signals)

Only signals needed before unlock or that gate the app lifecycle.

| Signal | Purpose |
|---|---|
| `status` | Auth state machine: locked/unlocking/unlocked/init/creating/recovery |
| `vaultInfo` | Session metadata from daemon. Needed by AppInner before VaultProvider mounts. |
| `biometricAvailable` | One-time capability check. Read-only after init. |

**Provider nesting:** Outermost. Wraps entire app.

**Actions:** `lock()` (sets status="locked", vaultInfo=null), `unlock(password)`, `createVault(password)`. All co-located in AuthContext.

**Removed from Auth vs original proposal:**
- `error` → standalone (vault errors must not flow up to auth layer)
- `theme` → standalone (survives lock/unlock, syncs to `<body>`, not auth state)
- `recoveryPhrase` → local in RecoveryScreen
- `createPassword` → local in CreateVaultScreen

### VaultProvider (12 signals)

Only mounts inside `<Show when={status() === "unlocked"}>`. Unmounts on lock. All signals destroyed automatically.

| Signal | Purpose |
|---|---|
| `ciphers` | Active cipher list |
| `trashCiphers` | Soft-deleted ciphers |
| `archivedCiphers` | Archived ciphers |
| `folders` | Folder tree |
| `deviceFleet` | Registered devices |
| `selfDeviceId` | Current device identifier |
| `revokeWarning` | Revocation confirmation state |
| `selectedCategory` | Category filter |
| `selectedFolder` | Folder filter |
| `searchQuery` | Text search |
| `activePane` | View router: welcome/detail/add/edit |
| `showSettingsModal` | Settings modal toggle |

**Actions co-located:** `refreshCiphers()`, `addCipher()`, `updateCipher()`, `getCipher()`, `deleteCipher()`, `restoreCipher()`, `archiveCipher()`, `unarchiveCipher()`, `refreshDeviceFleet()`.

**Why these 12 and not more:** Every signal here is consumed by 2+ components or passed across component boundaries. Single-consumer signals are local state (see below).

### Standalone Signals (2)

Module-level `createSignal` calls, imported directly. Not wrapped in a provider.

| Signal | File | Why standalone |
|---|---|---|
| `error` | `context/errorSignal.js` | Consumed by VaultView's error banner (inside VaultProvider) AND by auth actions. Errors are truly global. Duplication in both providers is worse. |
| `theme` | `context/themeSignal.js` | Survives lock/unlock. Syncs to `<body>` via `createEffect`. ThemeToggleFloating renders on every screen. Auth-layer signal that vault components also read. |

```js
// context/errorSignal.js
import { createSignal } from "solid-js";
export const [error, setError] = createSignal("");
```

```js
// context/themeSignal.js
import { createSignal, createEffect } from "solid-js";
export const [theme, setTheme] = createSignal("dark");

createEffect(() => {
  document.body.classList.toggle("light-theme", theme() === "light");
});
```

No provider needed. No context lookup. Direct import. Works because SolidJS signals are reactive outside component trees.

### Local State (8 signals moved out of context)

| Signal | New location | Why |
|---|---|---|
| `viewCipher` | `VaultView.jsx` local signal | Consumed by VaultView, CipherDetail (via props), CipherRow (via props) |
| `newCipher` | `VaultView.jsx` local signal | Consumed by VaultView, AddEditCipherForm (via props) |
| `showDeleteConfirm` | `VaultView.jsx` local signal | Only VaultView + DeleteConfirmModal |
| `showReprompt` | `CipherDetail.jsx` local signal | Only CipherDetail + RepromptModal |
| `repromptCallback` | `CipherDetail.jsx` plain `let` | Function reference, not reactive. Use module-scoped `let`. |
| `showGenerator` | `VaultView.jsx` local signal | Only VaultView + GeneratorModal |
| `recoveryPhrase` | `RecoveryScreen.jsx` local signal | Only RecoveryScreen |
| `createPassword` | `CreateVaultScreen.jsx` local signal | Only CreateVaultScreen |

**Impact:** 3 components (VaultView, CipherDetail, AddEditCipherForm) currently access `viewCipher` and `newCipher` via `useApp()`. After this change, VaultView owns them and passes down via props. This is standard SolidJS prop drilling — the component tree is 2 levels deep (VaultView → CipherDetail → CopyableField). No prop-drilling problem exists at this depth.

---

## Provider Nesting

```
<I18nProvider>
  <AuthProvider>
    <AppInner />
  </AuthProvider>
</I18nProvider>

AppInner renders:
  locked   → <LoginScreen />         (useAuth only)
  init     → <CreateVaultScreen />   (useAuth only)
  creating → <CreateVaultScreen />
  recovery → <RecoveryScreen />      (useAuth only)
  unlocked → <VaultProvider>
                <VaultView />        (useAuth + useVault + local state)
             </VaultProvider>
```

No circular deps. VaultProvider reads AuthStore via `useAuth()`. AuthStore never reads VaultStore.

---

## Structural Reset: How lock() Works

### Before (manual 7 resets)

```js
async function lock(t) {
  await daemon("vault.lock");
  app.setStatus("locked");
  app.setCiphers([]);
  app.setVaultInfo(null);
  app.setViewCipher(null);
  app.setActivePane("welcome");
  app.setShowDeleteConfirm(false);
  app.setRevokeWarning(null);     // ← this was the bug (was missing)
}
```

### After (2 resets + structural destroy)

```js
async function lock() {
  try {
    await daemon("vault.lock");
    setStatus("locked");       // AuthProvider signal
    setVaultInfo(null);        // AuthProvider signal
    setError("");              // standalone signal
    // VaultProvider unmounts next render via <Show>.
    // All 12 vault signals + 6 local signals destroyed.
    // No manual reset. Zero risk of forgetting one.
  } catch (e) {
    setError(sanitizeError(e));
  }
}
```

18 signals reset to defaults by unmount. Zero manual code. Impossible to forget one.

---

## Migration Path

### Phase 1: Create new files (non-breaking)

1. Create `context/AuthContext.jsx` (3 signals + lock/unlock/createVault actions)
2. Create `context/VaultContext.jsx` (12 signals + cipher CRUD actions)
3. Create `context/errorSignal.js` (standalone)
4. Create `context/themeSignal.js` (standalone)
5. Keep `AppContext.jsx` untouched

### Phase 2: Wire providers

1. Update `main.jsx` and `App.jsx` to use `AuthProvider` + `VaultProvider`
2. Mount `VaultProvider` inside `<Show when={status() === "unlocked"}>`
3. Import `errorSignal` and `themeSignal` where needed

### Phase 3: Migrate components (leaf-first, no logic changes)

| Component | From | To |
|---|---|---|
| `LoginScreen` | `useApp()` | `useAuth()` + `errorSignal` |
| `CreateVaultScreen` | `useApp()` | `useAuth()` + local `createPassword` |
| `RecoveryScreen` | `useApp()` | `useAuth()` + local `recoveryPhrase` |
| `ThemeToggleFloating` | `useApp()` | `themeSignal` direct import |
| `GeneratorModal` | `useApp()` | `showGenerator` via props from VaultView |
| `RepromptModal` | `useApp()` | `showReprompt` via props from CipherDetail |
| `DeleteConfirmModal` | `useApp()` | `showDeleteConfirm` via props from VaultView |
| `CipherRow` | `useApp()` | `useVault()` for activePane; viewCipher via props |
| `DeviceFleetPanel` | `useApp()` | `useVault()` |
| `CipherDetail` | `useApp()` + `useActions()` | `useVault()` + local state + props |
| `AddEditCipherForm` | `useApp()` + `useActions()` | `useVault()` + props |
| `SettingsModal` | `useApp()` + `useActions()` | `useAuth()` (nothing) + `useVault()` + `themeSignal` |
| `VaultView` | `useApp()` (22 signals) + `useActions()` | `useAuth()` + `useVault()` + local state |

### Phase 4: Delete old files

1. Delete `context/AppContext.jsx`
2. Delete `hooks/useActions.js`
3. Clean up any remaining `useApp()` references

### Phase 5: Audit

1. Audit all Tauri `listen()` calls for `onCleanup`
2. Verify lock/unlock cycle works end-to-end
3. Verify all 8 cipher types can be added/edited/deleted
4. Verify theme toggle works on all screens
5. Run existing tests (`just test`)

---

## File Structure (after migration)

```
context/
  AuthContext.jsx       // AuthProvider, useAuth (~60 lines)
  VaultContext.jsx      // VaultProvider, useVault (~120 lines)
  errorSignal.js        // standalone error signal (~5 lines)
  themeSignal.js        // standalone theme signal (~10 lines)
hooks/
  useActions.js         // DELETED
components/
  VaultView.jsx         // + local signals for viewCipher, newCipher, modals
  CipherDetail.jsx      // + local signal for showReprompt, plain let for repromptCallback
  CreateVaultScreen.jsx // + local signal for createPassword
  RecoveryScreen.jsx    // + local signal for recoveryPhrase
```

---

## What This Does NOT Change

- No behavioral changes. Same UI, same IPC, same daemon protocol.
- No new dependencies. Pure SolidJS primitives.
- No Tailwind changes. Only JS/JSX structure.
- No i18n key changes.
- No changes to `daemon.js`, `payload.js`, `utils.js`.
- No changes to `app.css` or `index.html`.

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Prop drilling for viewCipher/newCipher | Tree is 2 levels deep. Acceptable. If depth grows, reintroduce a focused context. |
| `error` as standalone signal is unconventional | Pragmatic for a desktop app. If multiple error consumers appear, wrap in a context later. |
| `theme` side effect (`createEffect` on body) runs at module load time | Intentional. Theme must apply before any component mounts to avoid FOUC. |
| VaultProvider mount cost on every unlock | 12 `createSignal` calls + defaults. Microseconds. SolidJS signal creation is O(1). |
| SettingsModal spans auth (theme) + vault (fleet, modal) | Only dual-store consumer outside VaultView. Imports `themeSignal` directly + `useVault()`. |
| `repromptCallback` as plain `let` won't trigger re-renders | Correct — it shouldn't. The callback is read imperatively, not reactively. The modal visibility (`showReprompt`) IS a signal. |

---

## Key Insight from peer review Review

> 6 modal signals (viewCipher, newCipher, showDeleteConfirm, showReprompt, repromptCallback, showGenerator) should be local state — single-consumer state doesn't need context.

This reduced VaultProvider from 18 → 12 signals and eliminated the need for a third UIStore. The principle: **if a signal is consumed by exactly one component subtree, it's local state. Context is for cross-component communication.**

---

## Reviewer Notes

peer review (peer peer review) reviewed this proposal. Key corrections incorporated:
1. Modal signals → local state (reduces VaultProvider from 18 to 12)
2. `error` → standalone signal (vault errors don't flow up to auth)
3. `recoveryPhrase`, `createPassword` → screen-local (not auth state)
4. `repromptCallback` → plain `let` (not reactive)
5. Audit Tauri `listen()` calls for `onCleanup`
6. Eliminate `useActions` entirely (zero cross-store compound actions after split)
