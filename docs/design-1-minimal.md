# Design 1: Minimal Store Split

**Date:** 2026-06-04
**Status:** Draft

## Problem

Single `AppProvider` holds 30 signals. `useApp()` exposes all to all consumers. `useActions` is a 243-line god hook touching 20+ signals across every domain. `VaultView` destructures 22 signals. Modal components pull the entire store to reach 2 signals.

## Design Principle

**3 stores. No more.** Split on lifecycle boundary, not data shape. Every store exposes exactly one context hook. Actions stay in the store that owns the signals they mutate.

---

## 1. Store Split

### AuthStore (8 signals)

Owns vault lifecycle: locked -> unlocking -> unlocked -> creating -> recovery.

| Signal | R/W | Notes |
|---|---|---|
| `status` | RW | Auth state machine |
| `error` | RW | Global error display |
| `vaultInfo` | RW | Vault metadata from daemon |
| `biometricAvailable` | RO | One-time check |
| `createPassword` | RW | Vault creation buffer |
| `recoveryPhrase` | RW | Shown once after creation |
| `theme` | RW | Persists across lock/unlock |
| `showSettingsModal` | RW | Settings lives outside vault |

**Actions (live in store):** `unlock()`, `lock()`, `createVault()`, `reset()`.

`lock()` is the cross-domain reset trigger. It calls `reset()` on VaultStore (see below).

### VaultStore (14 signals)

Only mounted when `status === "unlocked"`. Destroyed on lock.

| Signal | R/W | Notes |
|---|---|---|
| `ciphers` | RW | Active cipher list |
| `trashCiphers` | RW | Soft-deleted |
| `archivedCiphers` | RW | Archived |
| `deviceFleet` | RW | Device management |
| `selfDeviceId` | RW | Current device |
| `revokeWarning` | RW | Revoke confirmation |
| `selectedCategory` | RW | Filter |
| `selectedFolder` | RW | Filter |
| `folders` | RW | Folder tree |
| `searchQuery` | RW | Search |
| `activePane` | RW | welcome/detail/add/edit |
| `viewCipher` | RW | Currently viewed cipher |
| `newCipher` | RW | Add/edit form buffer |
| `showDeleteConfirm` | RW | Delete modal gate |

**Actions (live in store):** `refreshCiphers()`, `refreshTrashCiphers()`, `refreshArchivedCiphers()`, `refreshDeviceFleet()`, `addCipher()`, `updateCipher()`, `getCipher()`, `deleteCipher()`, `restoreCipher()`, `archiveCipher()`, `unarchiveCipher()`, `reset()`.

### UIStore (4 signals)

Modal gates. Survives lock/unlock. Lightweight.

| Signal | R/W | Notes |
|---|---|---|
| `showGenerator` | RW | Password generator modal |
| `showReprompt` | RW | Re-prompt modal |
| `repromptCallback` | RW | Re-prompt continuation |
| `searchQuery` | RW | **NO** - moved to VaultStore |

**Correction:** `searchQuery` belongs in VaultStore. UIStore is only modal toggles.

Revised UIStore (3 signals):

| Signal | R/W | Notes |
|---|---|---|
| `showGenerator` | RW | |
| `showReprompt` | RW | |
| `repromptCallback` | RW | |

---

## 2. Interface Signatures

### `useAuth()` -> AuthStore

```jsx
// context/AuthContext.jsx
import { createSignal, createContext, useContext, createEffect } from "solid-js";
const AuthContext = createContext();

function AuthProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  const [createPassword, setCreatePassword] = createSignal("");
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [theme, setTheme] = createSignal("dark");
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);

  // Reset callback - set by VaultProvider when it mounts
  let vaultReset = () => {};
  const onVaultReset = (fn) => { vaultReset = fn; };

  async function lock() {
    try {
      await daemon("vault.lock");
      vaultReset();        // <-- cross-domain reset
      setStatus("locked");
      setVaultInfo(null);
      setError("");
    } catch (e) {
      setError(sanitizeError(e));
    }
  }

  async function unlock(password) { /* ... */ }
  async function createVault(password) { /* ... */ }

  // Theme sync
  createEffect(() => { /* body classList toggle */ });

  // Biometric check
  createEffect(() => { /* daemon call */ });

  const store = {
    // Signals (read + write)
    status, setStatus, error, setError,
    vaultInfo, setVaultInfo, biometricAvailable,
    createPassword, setCreatePassword,
    recoveryPhrase, setRecoveryPhrase,
    theme, setTheme,
    showSettingsModal, setShowSettingsModal,
    // Actions
    unlock, lock, createVault,
    // Internal
    onVaultReset,
  };

  return <AuthContext.Provider value={store}>{props.children}</AuthContext.Provider>;
}

function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
export { AuthProvider, useAuth };
```

### `useVault()` -> VaultStore

```jsx
// context/VaultContext.jsx
import { createSignal, createContext, useContext } from "solid-js";
const VaultContext = createContext();

function VaultProvider(props) {
  const auth = useAuth();

  // Data
  const [ciphers, setCiphers] = createSignal([]);
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);
  const [deviceFleet, setDeviceFleet] = createSignal([]);
  const [selfDeviceId, setSelfDeviceId] = createSignal(null);
  const [revokeWarning, setRevokeWarning] = createSignal(null);

  // Navigation
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [folders, setFolders] = createSignal([]);
  const [searchQuery, setSearchQuery] = createSignal("");
  const [activePane, setActivePane] = createSignal("welcome");
  const [viewCipher, setViewCipher] = createSignal(null);

  // Form
  const [newCipher, setNewCipher] = createSignal(DEFAULT_CIPHER);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);

  // Register reset with auth store
  auth.onVaultReset(() => {
    setCiphers([]);
    setTrashCiphers([]);
    setArchivedCiphers([]);
    setDeviceFleet([]);
    setSelfDeviceId(null);
    setRevokeWarning(null);
    setActivePane("welcome");
    setViewCipher(null);
    setShowDeleteConfirm(false);
    setSearchQuery("");
    setSelectedCategory("All items");
    setSelectedFolder(null);
  });

  async function refreshCiphers() { /* ... daemon calls ... */ }
  async function addCipher() { /* ... */ }
  async function updateCipher(id) { /* ... */ }
  // ... other actions

  const store = {
    // All signals
    ciphers, setCiphers, trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    deviceFleet, setDeviceFleet, selfDeviceId, setSelfDeviceId,
    revokeWarning, setRevokeWarning,
    selectedCategory, setSelectedCategory,
    selectedFolder, setSelectedFolder,
    folders, setFolders, searchQuery, setSearchQuery,
    activePane, setActivePane, viewCipher, setViewCipher,
    newCipher, setNewCipher, showDeleteConfirm, setShowDeleteConfirm,
    // Actions
    refreshCiphers, refreshDeviceFleet,
    addCipher, updateCipher, getCipher, deleteCipher,
    restoreCipher, archiveCipher, unarchiveCipher,
  };

  return <VaultContext.Provider value={store}>{props.children}</VaultContext.Provider>;
}

function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used within VaultProvider");
  return ctx;
}
export { VaultProvider, useVault };
```

### `useUI()` -> UIStore

```jsx
// context/UIContext.jsx
import { createSignal, createContext, useContext } from "solid-js";
const UIContext = createContext();

function UIProvider(props) {
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showReprompt, setShowReprompt] = createSignal(false);
  const [repromptCallback, setRepromptCallback] = createSignal(null);

  const store = {
    showGenerator, setShowGenerator,
    showReprompt, setShowReprompt,
    repromptCallback, setRepromptCallback,
  };
  return <UIContext.Provider value={store}>{props.children}</UIContext.Provider>;
}

function useUI() {
  const ctx = useContext(UIContext);
  if (!ctx) throw new Error("useUI must be used within UIProvider");
  return ctx;
}
export { UIProvider, useUI };
```

---

## 3. Provider Nesting Order

```
<AuthProvider>         {/* outermost: auth lifecycle, theme, error */}
  <UIProvider>         {/* modal toggles, survives lock/unlock */}
    <Show when={status() === "unlocked"}>
      <VaultProvider>  {/* cipher data, nav, form - only when unlocked */}
        <VaultView />
      </VaultProvider>
    </Show>
    {/* LoginScreen, CreateVaultScreen, RecoveryScreen render here, outside VaultProvider */}
  </UIProvider>
</AuthProvider>
```

**No circular deps.** VaultProvider reads AuthStore via `useAuth()`. AuthStore never reads VaultStore. Cross-domain reset via callback registration pattern.

---

## 4. Usage Examples

### VaultView (was 22 destructured signals, now split)

```jsx
// components/VaultView.jsx - BEFORE
const { ciphers, trashCiphers, archivedCiphers, vaultInfo, error, selectedCategory,
        setSelectedCategory, selectedFolder, setSelectedFolder, folders,
        searchQuery, setSearchQuery, activePane, setActivePane, viewCipher,
        setNewCipher, theme, setTheme, showGenerator, setShowGenerator,
        showSettingsModal, setShowSettingsModal } = useApp();
const { lock, refreshCiphers } = useActions();

// AFTER
const auth = useAuth();                  // error, vaultInfo, theme, showSettingsModal
const vault = useVault();                // ciphers, trashCiphers, activePane, etc.
const ui = useUI();                      // showGenerator
const { lock } = useAuth();              // lock() moved to auth store
```

**Signal count per consumer drops.** VaultView reads from 3 focused interfaces instead of 1 monolith. Each re-render scope is narrower.

### useActions -> Eliminated

The 243-line `useActions` hook ceases to exist. Its functions split into:

| Function | New Home |
|---|---|
| `unlock`, `lock`, `createVault` | `useAuth()` (actions on AuthStore) |
| `refreshCiphers`, `addCipher`, `updateCipher`, `getCipher`, `deleteCipher`, `restoreCipher`, `archiveCipher`, `unarchiveCipher`, `refreshDeviceFleet` | `useVault()` (actions on VaultStore) |
| (none) | `useUI()` |

**`useActions` is deleted.** Consumers call `useAuth().lock()` or `useVault().addCipher()` directly. No indirection.

### LoginScreen (only needs auth)

```jsx
// BEFORE
const app = useApp();
const { unlock, setLoginPasswordRef } = useActions();

// AFTER
const auth = useAuth();
// auth.status, auth.error, auth.unlock() - nothing else reachable
```

### GeneratorModal (2 signals)

```jsx
// BEFORE
const { showGenerator, setShowGenerator } = useApp();

// AFTER
const { showGenerator, setShowGenerator } = useUI();
```

### CipherDetail (was 8 signals from useApp + 3 from useActions)

```jsx
// BEFORE
const { viewCipher, setViewCipher, setActivePane, setNewCipher,
        setShowDeleteConfirm, setShowReprompt, setRepromptCallback,
        selectedCategory } = useApp();
const { restoreCipher, archiveCipher, unarchiveCipher } = useActions();

// AFTER
const vault = useVault();
// vault.viewCipher, vault.setViewCipher, vault.setActivePane, vault.setNewCipher,
// vault.setShowDeleteConfirm, vault.restoreCipher, vault.archiveCipher, vault.unarchiveCipher
const ui = useUI();
// ui.setShowReprompt, ui.setRepromptCallback
```

---

## 5. How `lock()` Cross-Domain Reset Works

**Problem:** `lock()` must reset signals in both AuthStore and VaultStore.

**Solution: Callback registration.** VaultProvider registers a `reset()` function with AuthStore on mount. AuthStore's `lock()` calls it.

```jsx
// AuthProvider
let vaultReset = () => {};
const onVaultReset = (fn) => { vaultReset = fn; };

async function lock() {
  await daemon("vault.lock");
  vaultReset();            // Reset all VaultStore signals
  setStatus("locked");     // Reset own signals
  setVaultInfo(null);
}
```

```jsx
// VaultProvider (mounts inside <Show when="unlocked">)
const auth = useAuth();

auth.onVaultReset(() => {
  setCiphers([]);
  setTrashCiphers([]);
  setArchivedCiphers([]);
  setDeviceFleet([]);
  setSelfDeviceId(null);
  setRevokeWarning(null);
  setActivePane("welcome");
  setViewCipher(null);
  setShowDeleteConfirm(false);
  setSearchQuery("");
  setSelectedCategory("All items");
  setSelectedFolder(null);
});
```

**Why not `<Show>` destroy?** The `<Show when={status() === "unlocked"}>` around VaultProvider already destroys VaultStore on lock. All its signals are garbage collected. The callback registration is defensive: it ensures reset happens *before* AuthStore signals change, avoiding flash-of-stale-data during the render cycle where `<Show>` unmounts.

**Simpler alternative (recommended):** Drop the callback entirely. Trust `<Show>` to destroy VaultProvider. When status becomes "locked", VaultProvider unmounts, all signals vanish. On next unlock, fresh VaultProvider creates fresh signals. No stale data possible.

```jsx
// Simplified lock() - no cross-domain reset needed
async function lock() {
  await daemon("vault.lock");
  setStatus("locked");
  setVaultInfo(null);
  // VaultProvider unmounts via <Show>, all vault signals destroyed
}
```

**This is the recommended approach.** The `<Show>` boundary is the reset mechanism. Zero coupling.

---

## 6. Migration Path (per component)

| Component | Current | Migration |
|---|---|---|
| `App.jsx` | `useApp()` (4 signals) | `useAuth()` only |
| `LoginScreen` | `useApp()` + `useActions()` | `useAuth()` only |
| `CreateVaultScreen` | `useApp()` + `useActions()` | `useAuth()` only |
| `RecoveryScreen` | `useApp()` + `useActions()` | `useAuth()` only |
| `VaultView` | `useApp()` (22) + `useActions()` (2) | `useAuth()` + `useVault()` + `useUI()` |
| `CipherDetail` | `useApp()` (8) + `useActions()` (3) | `useVault()` + `useUI()` |
| `CipherRow` | `useApp()` (2) + `useActions()` (1) | `useVault()` only |
| `AddEditCipherForm` | `useApp()` (4) + `useActions()` (2) | `useVault()` only |
| `DeleteConfirmModal` | `useApp()` (4) + `useActions()` (1) | `useVault()` only |
| `RepromptModal` | `useApp()` (3) | `useUI()` only |
| `GeneratorModal` | `useApp()` (2) | `useUI()` only |
| `SettingsModal` | `useApp()` (7) + `useActions()` (1) | `useAuth()` + `useVault()` |
| `DeviceFleetPanel` | `useApp()` (entire store) | `useVault()` only |
| `ThemeToggleFloating` | `useApp()` (2) | `useAuth()` only |

**SettingsModal** spans auth (theme, modal toggle) + vault (deviceFleet). Needs both `useAuth()` and `useVault()`. This is the only dual-store consumer outside VaultView.

---

## 7. Trade-offs

### Wins

| What | Why |
|---|---|
| **Destroy-on-unmount** | VaultStore signals vanish on lock. No manual reset. Zero stale data risk. |
| **Narrow reactivity** | CipherRow changing `viewCipher` no longer pulls in 28 unrelated signals. SolidJS granularity works. |
| **`useActions` eliminated** | 243 lines of indirection replaced by co-located actions in owning store. Functions live where state lives. |
| **Auth screens isolated** | LoginScreen, RecoveryScreen, CreateVaultScreen import `useAuth()` only. No vault leak. |
| **Modal independence** | RepromptModal and GeneratorModal import `useUI()` only. No dependency on auth or vault state. |
| **Testability** | Each store testable in isolation with `render(() => <XProvider>...</XProvider>)`. |
| **No new deps** | Pure SolidJS primitives. `createSignal`, `createContext`, `useContext`. |

### Costs

| What | Why |
|---|---|
| **3 imports instead of 1** | VaultView imports `useAuth` + `useVault` + `useUI`. Marginal verbosity. |
| **SettingsModal spans 2 stores** | Only component outside VaultView that needs both auth + vault. Acceptable. |
| **`<Show>` creates/remounts** | VaultProvider mounts fresh on every unlock. `refreshCiphers()` must be called after unlock (already the case). |
| **Callback registration (if used)** | Adds indirection. Mitigated by using `<Show>` destroy as primary reset. |
| **Actions no longer centralized** | Functions split across stores. No single `useActions` to audit. Counter: easier to audit *per domain*. |

### What this does NOT do (by design)

- No reactive graph or derived store pattern. Raw signals.
- No action dispatchers, reducers, or middleware. Functions on the store object.
- No persistence layer. Theme persists via existing mechanism.
- No selector API. SolidJS fine-grained reactivity makes selectors unnecessary.

---

## 8. File Structure

```
context/
  AuthContext.jsx    // AuthProvider, useAuth  (~80 lines)
  VaultContext.jsx   // VaultProvider, useVault (~200 lines)
  UIContext.jsx      // UIProvider, useUI       (~25 lines)
hooks/
  useActions.js      // DELETED
```

`useActions.js` is deleted. All its functions move into the store that owns the signals they mutate.

---

## 9. Implementation Order

1. Create `UIContext.jsx` (trivial, no deps)
2. Create `AuthContext.jsx` (extract from AppContext, add `lock()`)
3. Create `VaultContext.jsx` (extract from AppContext, co-locate actions from useActions)
4. Update `App.jsx` nesting: AuthProvider > UIProvider > Show > VaultProvider
5. Migrate components top-down (VaultView last, it touches all 3)
6. Delete `AppContext.jsx` and `useActions.js`
7. Test lock/unlock cycle. Verify VaultProvider unmount resets all vault signals.
