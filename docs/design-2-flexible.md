# Design 2: Flexible Store Split

**Date:** 2026-06-04
**Approach:** Domain-driven store decomposition. Maximum extensibility. Pure SolidJS.

---

## 1. Architecture Overview

Split the monolithic `AppProvider` (30 signals) into **6 domain stores** + **1 orchestrator layer** for cross-store operations.

```
┌─────────────────────────────────────────────────────┐
│  App (entry)                                        │
│  ┌─────────────────────────────────────────────────┐│
│  │ AuthProvider                                    ││
│  │  ┌──────────────────────────────────────────┐   ││
│  │  │ PrefsProvider                            │   ││
│  │  │  ┌───────────────────────────────────┐   │   ││
│  │  │  │ CipherStoreProvider               │   │   ││
│  │  │  │  ┌────────────────────────────┐   │   │   ││
│  │  │  │  │ NavigationProvider         │   │   │   ││
│  │  │  │  │  ┌─────────────────────┐   │   │   │   ││
│  │  │  │  │  │ FormProvider        │   │   │   │   ││
│  │  │  │  │  │  ┌──────────────┐   │   │   │   │   ││
│  │  │  │  │  │  │ DeviceProvider│   │   │   │   │   ││
│  │  │  │  │  │  └──────────────┘   │   │   │   │   ││
│  │  │  │  │  └────────────────────┘   │   │   │   ││
│  │  │  │  └────────────────────────────┘   │   │   ││
│  │  │  └───────────────────────────────────┘   │   ││
│  │  └──────────────────────────────────────────┘   ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

### Nesting Order (innermost to outermost)

| # | Store | Why this position |
|---|-------|--------------------|
| 1 | **AuthProvider** | Outermost. Login/Recovery/CreateVault screens only need auth. No vault data exists before unlock. |
| 2 | **PrefsProvider** | Theme applies everywhere. Modals can fire from any screen. No dependency on auth status. |
| 3 | **CipherStoreProvider** | Requires auth (only populated after unlock). Holds all vault data. |
| 4 | **NavigationProvider** | Requires cipher data for filtering/search. Controls which pane is active. |
| 5 | **FormProvider** | Requires cipher types + navigation. Holds temporary form buffers. |
| 6 | **DeviceProvider** | Requires auth. Inside cipher store so it can trigger cipher refresh on revoke. |

---

## 2. Store Definitions

### 2.1 AuthStore

**Domain:** Vault lifecycle, session state, error reporting.

```js
// context/AuthContext.jsx
import { createSignal, createContext, useContext, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";

const AuthContext = createContext();

export function AuthProvider(props) {
  const [status, setStatus] = createSignal("locked");    // locked | unlocking | unlocked | init | creating | recovery
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);

  // Auto-detect biometric support
  createEffect(() => {
    daemon("vault.biometric_status").then(r => {
      const s = JSON.parse(r);
      setBiometricAvailable(s.available && s.enabled);
    }).catch(() => {});
  });

  /** Reset auth-related state to locked defaults */
  function reset() {
    setStatus("locked");
    setError("");
    setVaultInfo(null);
  }

  const store = {
    // Signals
    status, error, vaultInfo, biometricAvailable,
    // Setters
    setStatus, setError, setVaultInfo,
    // Lifecycle
    reset,
  };

  return (
    <AuthContext.Provider value={store}>
      {props.children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { AuthContext };
```

**Interface:**
```ts
// Pseudocode interface for documentation
interface AuthStore {
  // Read-only signals
  status: Accessor<"locked"|"unlocking"|"unlocked"|"init"|"creating"|"recovery">
  error: Accessor<string>
  vaultInfo: Accessor<VaultInfo | null>
  biometricAvailable: Accessor<boolean>

  // Setters
  setStatus: Setter<string>
  setError: Setter<string>
  setVaultInfo: Setter<VaultInfo | null>

  // Lifecycle
  reset(): void    // Called by lock() orchestrator
}
```

---

### 2.2 PrefsStore

**Domain:** User preferences, UI toggles, modal state, theme.

```js
// context/PrefsContext.jsx
import { createSignal, createContext, useContext, createEffect } from "solid-js";

const PrefsContext = createContext();

export function PrefsProvider(props) {
  const [theme, setTheme] = createSignal("dark");

  // Modal toggles
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  const [showReprompt, setShowReprompt] = createSignal(false);
  const [repromptCallback, setRepromptCallback] = createSignal(null);

  // Sync theme class on <body>
  createEffect(() => {
    document.body.classList.toggle("light-theme", theme() === "light");
  });

  /** Reset all modal/toggle state */
  function reset() {
    setShowDeleteConfirm(false);
    setShowReprompt(false);
    setRepromptCallback(null);
    // theme persists across lock/unlock — intentionally NOT reset
  }

  const store = {
    theme, setTheme,
    showGenerator, setShowGenerator,
    showSettingsModal, setShowSettingsModal,
    showDeleteConfirm, setShowDeleteConfirm,
    showReprompt, setShowReprompt,
    repromptCallback, setRepromptCallback,
    reset,
  };

  return (
    <PrefsContext.Provider value={store}>
      {props.children}
    </PrefsContext.Provider>
  );
}

export function usePrefs() {
  const ctx = useContext(PrefsContext);
  if (!ctx) throw new Error("usePrefs must be used within PrefsProvider");
  return ctx;
}

export { PrefsContext };
```

**Interface:**
```ts
interface PrefsStore {
  // Theme (persists across lock)
  theme: Accessor<"dark"|"light">
  setTheme: Setter<string>

  // Modals (2-3 signals each, isolated)
  showGenerator: Accessor<boolean>
  setShowGenerator: Setter<boolean>
  showSettingsModal: Accessor<boolean>
  setShowSettingsModal: Setter<boolean>
  showDeleteConfirm: Accessor<boolean>
  setShowDeleteConfirm: Setter<boolean>
  showReprompt: Accessor<boolean>
  setShowReprompt: Setter<boolean>
  repromptCallback: Accessor<Function | null>
  setRepromptCallback: Setter<Function | null>

  // Lifecycle
  reset(): void
}
```

**Extensibility note:** New modals follow the same pattern: add `[showX, setShowX]` here. Modal components only import `usePrefs`. Example future additions: `showExportModal`, `showBulkMoveModal`, `showShareModal`, `showBreachReportModal`.

---

### 2.3 CipherStore

**Domain:** All vault data. The data layer.

```js
// context/CipherContext.jsx
import { createSignal, createContext, useContext } from "solid-js";

const CipherContext = createContext();

export function CipherStoreProvider(props) {
  // Core cipher collections
  const [ciphers, setCiphers] = createSignal([]);
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);

  // Folder hierarchy
  const [folders, setFolders] = createSignal([]);

  /** Reset all cipher data to empty */
  function reset() {
    setCiphers([]);
    setTrashCiphers([]);
    setArchivedCiphers([]);
    setFolders([]);
  }

  const store = {
    ciphers, setCiphers,
    trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    folders, setFolders,
    reset,
  };

  return (
    <CipherContext.Provider value={store}>
      {props.children}
    </CipherContext.Provider>
  );
}

export function useCipherStore() {
  const ctx = useContext(CipherContext);
  if (!ctx) throw new Error("useCipherStore must be used within CipherStoreProvider");
  return ctx;
}

export { CipherContext };
```

**Interface:**
```ts
interface CipherStore {
  // Cipher collections
  ciphers: Accessor<Cipher[]>
  trashCiphers: Accessor<Cipher[]>
  archivedCiphers: Accessor<Cipher[]>
  setCiphers: Setter<Cipher[]>
  setTrashCiphers: Setter<Cipher[]>
  setArchivedCiphers: Setter<Cipher[]>

  // Folders
  folders: Accessor<Folder[]>
  setFolders: Setter<Folder[]>

  // Lifecycle
  reset(): void
}
```

**Extensibility note:** Future collections slot in naturally: `sharedCiphers`, `breachedCiphers`, `recentlyUsed`. Each is a signal pair. New cipher types (e.g., `WifiPassword`, `CryptoWallet`) require zero store changes; they are just new `CipherKind` variants in the Rust backend, rendered by the frontend's category filter map.

---

### 2.4 NavigationStore

**Domain:** Where the user is. Pane state, selection, search.

```js
// context/NavigationContext.jsx
import { createSignal, createContext, useContext } from "solid-js";

const NavigationContext = createContext();

export function NavigationProvider(props) {
  const [activePane, setActivePane] = createSignal("welcome");  // welcome | detail | add | edit
  const [viewCipher, setViewCipher] = createSignal(null);
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [searchQuery, setSearchQuery] = createSignal("");

  /** Reset navigation to welcome state */
  function reset() {
    setActivePane("welcome");
    setViewCipher(null);
    setSearchQuery("");
    // selectedCategory and selectedFolder persist across view changes
    // (user preference, cleared only by explicit action)
  }

  const store = {
    activePane, setActivePane,
    viewCipher, setViewCipher,
    selectedCategory, setSelectedCategory,
    selectedFolder, setSelectedFolder,
    searchQuery, setSearchQuery,
    reset,
  };

  return (
    <NavigationContext.Provider value={store}>
      {props.children}
    </NavigationContext.Provider>
  );
}

export function useNavigation() {
  const ctx = useContext(NavigationContext);
  if (!ctx) throw new Error("useNavigation must be used within NavigationProvider");
  return ctx;
}

export { NavigationContext };
```

**Interface:**
```ts
interface NavigationStore {
  activePane: Accessor<"welcome"|"detail"|"add"|"edit">
  setActivePane: Setter<string>
  viewCipher: Accessor<Cipher | null>
  setViewCipher: Setter<Cipher | null>
  selectedCategory: Accessor<string>
  setSelectedCategory: Setter<string>
  selectedFolder: Accessor<string | null>
  setSelectedFolder: Setter<string | null>
  searchQuery: Accessor<string>
  setSearchQuery: Setter<string>

  reset(): void
}
```

**Extensibility note:** Future panes (e.g., `"totp-manage"`, `"bulk-edit"`, `"share"`) are just new string variants. Multi-pane layouts add `secondaryPane` as a sibling signal. Tab state for settings pages stays local to that component, not here.

---

### 2.5 FormStore

**Domain:** Temporary form buffers. Short-lived, cleared on navigation away.

```js
// context/FormContext.jsx
import { createSignal, createContext, useContext } from "solid-js";

const BLANK_CIPHER = Object.freeze({
  name: "", username: "", password: "", uris: [], notes: "",
  cipherType: "login", favorite: false, reprompt: false,
  attachments: [], folder_id: null, custom_fields: [], totp_uri: "",
});

const FormContext = createContext();

export function FormProvider(props) {
  const [newCipher, setNewCipher] = createSignal({ ...BLANK_CIPHER });
  const [createPassword, setCreatePassword] = createSignal("");
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");

  /** Reset all form buffers to initial state */
  function reset() {
    setNewCipher({ ...BLANK_CIPHER });
    setCreatePassword("");
    setRecoveryPhrase("");
  }

  const store = {
    newCipher, setNewCipher,
    createPassword, setCreatePassword,
    recoveryPhrase, setRecoveryPhrase,
    reset,
  };

  return (
    <FormContext.Provider value={store}>
      {props.children}
    </FormContext.Provider>
  );
}

export function useForm() {
  const ctx = useContext(FormContext);
  if (!ctx) throw new Error("useForm must be used within FormProvider");
  return ctx;
}

export { FormContext };
```

**Interface:**
```ts
interface FormStore {
  newCipher: Accessor<CipherInput>
  setNewCipher: Setter<CipherInput>
  createPassword: Accessor<string>
  setCreatePassword: Setter<string>
  recoveryPhrase: Accessor<string>
  setRecoveryPhrase: Setter<string>

  reset(): void
}
```

**Extensibility note:** New form types add new signals: `editCipher`, `importFormState`, `shareFormState`. The `BLANK_CIPHER` constant makes default values explicit and new-cipher-type-friendly.

---

### 2.6 DeviceStore

**Domain:** Device fleet management, revocation warnings.

```js
// context/DeviceContext.jsx
import { createSignal, createContext, useContext } from "solid-js";

const DeviceContext = createContext();

export function DeviceProvider(props) {
  const [deviceFleet, setDeviceFleet] = createSignal([]);
  const [selfDeviceId, setSelfDeviceId] = createSignal(null);
  const [revokeWarning, setRevokeWarning] = createSignal(null);

  function reset() {
    setDeviceFleet([]);
    setSelfDeviceId(null);
    setRevokeWarning(null);
  }

  const store = {
    deviceFleet, setDeviceFleet,
    selfDeviceId, setSelfDeviceId,
    revokeWarning, setRevokeWarning,
    reset,
  };

  return (
    <DeviceContext.Provider value={store}>
      {props.children}
    </DeviceContext.Provider>
  );
}

export function useDevices() {
  const ctx = useContext(DeviceContext);
  if (!ctx) throw new Error("useDevices must be used within DeviceProvider");
  return ctx;
}

export { DeviceContext };
```

**Interface:**
```ts
interface DeviceStore {
  deviceFleet: Accessor<Device[]>
  setDeviceFleet: Setter<Device[]>
  selfDeviceId: Accessor<string | null>
  setSelfDeviceId: Setter<string | null>
  revokeWarning: Accessor<RevokeWarning | null>
  setRevokeWarning: Setter<RevokeWarning | null>

  reset(): void
}
```

---

## 3. Provider Wiring

### 3.1 Top-Level Composition

```js
// context/RootProvider.jsx
import { AuthProvider } from "./AuthContext.jsx";
import { PrefsProvider } from "./PrefsContext.jsx";
import { CipherStoreProvider } from "./CipherContext.jsx";
import { NavigationProvider } from "./NavigationContext.jsx";
import { FormProvider } from "./FormContext.jsx";
import { DeviceProvider } from "./DeviceContext.jsx";

export function RootProvider(props) {
  return (
    <AuthProvider>
      <PrefsProvider>
        <CipherStoreProvider>
          <NavigationProvider>
            <FormProvider>
              <DeviceProvider>
                {props.children}
              </DeviceProvider>
            </FormProvider>
          </NavigationProvider>
        </CipherStoreProvider>
      </PrefsProvider>
    </AuthProvider>
  );
}
```

### 3.2 App.jsx Change

```js
// App.jsx  (diff from current)
import { RootProvider } from "./context/RootProvider.jsx";

export default function App() {
  return (
    <RootProvider>
      <AppInner />
    </RootProvider>
  );
}
```

The old `AppProvider` import is removed. `AppInner` and all children now import from the specific stores they need.

---

## 4. Cross-Domain Operations: The Orchestrator Pattern

### 4.1 Problem: `lock()` resets 4+ stores

Current `lock()` touches signals across auth, cipher, navigation, prefs, and device domains. No single store should know about the others.

### 4.2 Solution: Orchestrator hooks

Create a `useOrchestrator()` hook (not a context) that composes store resets. It is a plain function that imports the store hooks. Since it is called inside the provider tree, all `useContext` calls resolve correctly.

```js
// hooks/useOrchestrator.js
import { useAuth } from "../context/AuthContext.jsx";
import { useCipherStore } from "../context/CipherContext.jsx";
import { useNavigation } from "../context/NavigationContext.jsx";
import { usePrefs } from "../context/PrefsContext.jsx";
import { useDevices } from "../context/DeviceContext.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";

export function useOrchestrator() {
  const auth = useAuth();
  const ciphers = useCipherStore();
  const nav = useNavigation();
  const prefs = usePrefs();
  const devices = useDevices();

  async function lock(t) {
    try {
      await daemon("vault.lock");
      // Each store resets its own domain
      auth.reset();
      ciphers.reset();
      nav.reset();
      prefs.reset();
      devices.reset();
    } catch (e) {
      auth.setError(sanitizeError(e, t));
    }
  }

  async function unlock(password, t) {
    auth.setStatus("unlocking");
    auth.setError("");
    try {
      await daemon("vault.open");
      await daemon("vault.unlock", password);
      auth.setStatus("unlocked");
      const info = JSON.parse(await daemon("vault.info"));
      auth.setVaultInfo(info);
    } catch (e) {
      auth.setError(sanitizeError(e, t));
      auth.setStatus("locked");
    }
  }

  return { lock, unlock };
}
```

**Why a hook, not a context:** The orchestrator has no state of its own. It reads from existing contexts. Avoids an extra provider in the tree and keeps the dependency graph flat.

**Adding new cross-domain operations:** Just add functions to `useOrchestrator`. Examples:
- `revokeDevice()` -> resets devices + refreshes ciphers
- `switchVault()` -> full reset + auth change
- `importComplete()` -> refreshes ciphers + closes modal

---

## 5. Usage Examples

### 5.1 VaultView (was 22 destructured signals)

```js
// Before (monolithic):
const { ciphers, trashCiphers, archivedCiphers, vaultInfo, error,
        selectedCategory, setSelectedCategory, selectedFolder, setSelectedFolder,
        folders, searchQuery, setSearchQuery, activePane, setActivePane,
        viewCipher, setNewCipher, theme, setTheme, showGenerator, setShowGenerator,
        showSettingsModal, setShowSettingsModal } = useApp();

// After (domain-specific):
const auth     = useAuth();
const ciphers  = useCipherStore();
const nav      = useNavigation();
const prefs    = usePrefs();
```

No signal names change. Access is just namespaced: `ciphers.ciphers()` instead of `ciphers()`, `nav.activePane()` instead of `activePane()`.

**Impact on filtered list memo:**
```js
// Before:
const filteredCiphers = () => {
  const cat = selectedCategory();
  let list = cat === "Trash" ? trashCiphers() : ciphers();

// After:
const filteredCiphers = () => {
  const cat = nav.selectedCategory();
  let list = cat === "Trash" ? ciphers.trashCiphers() : ciphers.ciphers();
```

Mechanical rename. Same reactivity graph. Same performance.

### 5.2 LoginScreen (was full useApp, needs 3 signals)

```js
// Before:
const app = useApp();          // gets ALL 30 signals
// uses: app.error(), app.status(), app.biometricAvailable()

// After:
const auth = useAuth();        // gets 4 signals + 2 setters
// uses: auth.error(), auth.status(), auth.biometricAvailable()
```

LoginScreen, CreateVaultScreen, and RecoveryScreen only import `useAuth()`. Zero cipher/navigation/form/device imports.

### 5.3 RepromptModal (was 3 signals from useApp)

```js
// Before:
const { showReprompt, setShowReprompt, repromptCallback } = useApp();

// After:
const prefs = usePrefs();
// uses: prefs.showReprompt(), prefs.setShowReprompt(), prefs.repromptCallback()
```

### 5.4 GeneratorModal (was 2 signals)

```js
// Before:
const { showGenerator, setShowGenerator } = useApp();

// After:
const prefs = usePrefs();
// uses: prefs.showGenerator(), prefs.setShowGenerator()
```

### 5.5 CipherDetail (was 8 signals from useApp)

```js
// Before:
const { viewCipher, setViewCipher, setActivePane, setNewCipher,
        setShowDeleteConfirm, setShowReprompt, setRepromptCallback,
        selectedCategory } = useApp();

// After:
const nav   = useNavigation();   // viewCipher, setViewCipher, setActivePane, selectedCategory
const prefs = usePrefs();        // setShowDeleteConfirm, setShowReprompt, setRepromptCallback
const form  = useForm();         // setNewCipher
```

### 5.6 useActions Migration

The `useActions` hook becomes **two files**:

1. **`useOrchestrator.js`** (shown above) - cross-domain operations: `lock`, `unlock`, `createVault`
2. **`useCipherActions.js`** - single-domain cipher CRUD:

```js
// hooks/useCipherActions.js
import { useCipherStore } from "../context/CipherContext.jsx";
import { useNavigation } from "../context/NavigationContext.jsx";
import { useForm } from "../context/FormContext.jsx";
import { usePrefs } from "../context/PrefsContext.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload } from "../lib/payload.js";

export function useCipherActions() {
  const ciphers = useCipherStore();
  const nav     = useNavigation();
  const form    = useForm();
  const prefs   = usePrefs();
  const auth    = useAuth();

  async function refreshCiphers(t) {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      const metas = data.ciphers || [];
      const fullCiphers = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify(buildGetPayload(meta.id)));
            return { ...JSON.parse(detailStr), _meta: meta };
          } catch (e) {
            return { ...meta, name: meta.name || "Decryption Error", username: "", uris: [] };
          }
        })
      );
      ciphers.setCiphers(fullCiphers);

      try {
        const folderData = JSON.parse(await daemon("folder.list"));
        ciphers.setFolders(Array.isArray(folderData) ? folderData : []);
      } catch {}

      await refreshTrashCiphers(t);
      await refreshArchivedCiphers(t);
    } catch (e) {
      auth.setError(sanitizeError(e, t));
    }
  }

  async function refreshTrashCiphers(t) { /* same pattern, uses ciphers.setTrashCiphers */ }
  async function refreshArchivedCiphers(t) { /* same pattern, uses ciphers.setArchivedCiphers */ }

  async function addCipher(t) {
    const c = form.newCipher();
    if (!c.name) { auth.setError(t("entry.namePlaceholder") + " required"); return; }
    try {
      await daemon("vault.add", JSON.stringify(buildAddPayload(c)));
      form.setNewCipher({ name: "", username: "", password: "", uris: [], notes: "",
        cipherType: "login", favorite: false, reprompt: false, attachments: [],
        folder_id: null, custom_fields: [], totp_uri: "" });
      nav.setActivePane("welcome");
      await refreshCiphers(t);
    } catch (e) {
      auth.setError(sanitizeError(e, t));
    }
  }

  async function updateCipher(id, t) { /* uses form, nav, ciphers */ }
  async function getCipher(id, t) { /* uses nav, auth */ }
  async function deleteCipher(id, t) { /* uses nav, prefs, ciphers, auth */ }
  async function restoreCipher(id, t) { /* uses nav, ciphers, auth */ }
  async function archiveCipher(id) { /* uses nav, ciphers, auth */ }
  async function unarchiveCipher(id) { /* uses nav, ciphers, auth */ }

  return {
    refreshCiphers, addCipher, updateCipher, getCipher,
    deleteCipher, restoreCipher, archiveCipher, unarchiveCipher,
  };
}
```

### 5.7 SettingsModal (was 7 signals)

```js
// After:
const prefs   = usePrefs();     // showSettingsModal, setShowSettingsModal, theme, setTheme
const devices  = useDevices();  // deviceFleet, selfDeviceId, revokeWarning, setRevokeWarning
const ciphers  = useCipherStore(); // for refresh after import
```

### 5.8 DeviceFleetPanel (was full useApp)

```js
// After:
const devices = useDevices();    // deviceFleet, setRevokeWarning
```

---

## 6. lock() Cross-Domain Reset

The critical operation. Here is the exact flow:

```
User clicks "Lock"
        │
        ▼
useOrchestrator.lock(t)
        │
        ├── daemon("vault.lock")          ← IPC call
        │
        ├── auth.reset()                   → status="locked", error="", vaultInfo=null
        ├── ciphers.reset()                → all arrays=[], folders=[]
        ├── nav.reset()                    → activePane="welcome", viewCipher=null, searchQuery=""
        ├── prefs.reset()                  → all modals=false, repromptCallback=null
        └── devices.reset()                → fleet=[], selfDeviceId=null, revokeWarning=null
```

**Why each store has its own `reset()`:**
1. **Single responsibility.** Each store knows its own defaults.
2. **Composable.** Orchestrator calls the combination it needs. `lock()` calls all 5. `switchVault()` calls a different subset.
3. **Testable.** Each `reset()` is independently unit-testable.
4. **Extensible.** New store? Add its `reset()` to the orchestrator.

**Alternative patterns considered:**

| Pattern | Why rejected |
|---------|-------------|
| Event bus (`emit("lock")`) | Implicit coupling. Hard to trace. SolidJS reactivity is already the "bus". |
| `createEffect` on `status` change | Side-effect ordering is non-deterministic. Reset must be synchronous. |
| Single context with `resetAll()` | Back to monolith. No domain isolation. |
| Store that holds references to other stores | Circular dependency risk. Violates tree constraint. |

---

## 7. Migration Path

### Phase 1: Create stores alongside existing AppProvider (zero breakage)

1. Create all 6 context files + RootProvider
2. Create useOrchestrator + useCipherActions
3. Mount `<RootProvider>` inside `<AppProvider>` (both active)
4. No components changed yet

### Phase 2: Migrate components one at a time

Priority order (leaf-first, consumers change first):

1. **Modals** (RepromptModal, GeneratorModal, DeleteConfirmModal, SettingsModal)
   - Only need `usePrefs` + optionally `useDevices`
   - Zero risk, no downstream dependents

2. **LoginScreen, CreateVaultScreen, RecoveryScreen**
   - Only need `useAuth` + `useForm`
   - Clean boundary, easy to verify

3. **CipherDetail, AddEditCipherForm**
   - Need `useNavigation`, `usePrefs`, `useForm`, `useCipherActions`
   - Test add/edit/delete flows

4. **CipherRow, FolderTree, DeviceFleetPanel**
   - Each needs 1-2 stores
   - Low risk

5. **VaultView** (last, highest fan-out)
   - Needs all 4 data stores
   - Most signals consumed
   - Migrate destructuring to namespaced access

6. **Remove old AppProvider + useApp** once all consumers migrated

### Phase 3: Remove useApp entirely

Delete `AppContext.jsx`. All imports go through domain-specific hooks.

---

## 8. Trade-offs

### Advantages of this approach

| Benefit | Why it matters |
|---------|---------------|
| **Domain isolation** | LoginScreen re-renders zero times when ciphers change. Current: it re-renders on every cipher mutation because `useApp()` subscribes to all signals. |
| **Extensibility** | New cipher types, screens, features add signals to the relevant store. No 30-signal god object to edit. |
| **Discoverability** | `useAuth()` tells you exactly what auth signals exist. `useApp()` required grepping 30 lines to find what you need. |
| **Testability** | Each store is independently testable with a single provider wrapper. Current: every test needs the full `AppProvider`. |
| **Bundle locality** | SolidJS `createContext` is per-provider. Components only re-render when their specific store signals change. |
| **Team scalability** | Different devs can work on different domains without merge conflicts in a single file. |
| **Future stores** | `AuditLogStore`, `BreachMonitorStore`, `SharedVaultStore` slot in as new providers. Zero changes to existing stores. |
| **lock() stays clean** | Orchestrator pattern keeps cross-domain resets explicit and in one place. |

### Costs and risks

| Cost | Mitigation |
|------|-----------|
| **More imports** | Components import 1-3 hooks instead of 1. Verbose but explicit. Use object destructuring: `const { theme } = usePrefs()`. |
| **Provider nesting depth** | 6 providers deep. Acceptable for SolidJS (React apps routinely hit 10+). No perf impact: providers are cheap wrappers. |
| **Orchestrator is a magnet** | `useOrchestrator` could grow into a second god-object. Mitigate: it should only contain operations that span 2+ stores. Single-domain logic stays in domain hooks. |
| **Migration is not atomic** | Must run both old and new providers during migration. Short-lived duplication. Mitigate: Phase 1 is a single commit. Phase 2 is incremental PRs. |
| **Namespace verbosity** | `ciphers.ciphers()` is redundant. Mitigate: destructure at call site: `const { ciphers: allCiphers } = useCipherStore()`. Or rename the signal to `list`. |
| **No TypeScript** | Interfaces shown are pseudocode. Pure JS means no compile-time store shape checking. Mitigate: JSDoc annotations provide IDE autocomplete. |

### What this approach deliberately does NOT do

| Rejected | Why |
|----------|-----|
| External state lib (Zustand, Jotai, Nano Stores) | Constraint: pure SolidJS primitives. No new deps. |
| Event bus / pub-sub | Implicit. Hard to debug. SolidJS signals ARE the reactive layer. |
| Store-as-class (OOP pattern) | Classes don't play well with SolidJS reactivity. Signals are the primitive. |
| Proxy-based stores | `createStore` from SolidJS is an option, but the current codebase uses `createSignal` exclusively. Migration to `createStore` is orthogonal to this split. Can be done later per-store. |
| Global singletons | Breaks testability. Context tree is the SolidJS-idiomatic pattern. |

---

## 9. Signal-to-Store Assignment Reference

| Signal | Store | Rationale |
|--------|-------|-----------|
| `status` | Auth | Auth lifecycle state machine |
| `error` | Auth | Error display is auth-scoped (login errors, vault errors) |
| `vaultInfo` | Auth | Session metadata, populated on unlock |
| `biometricAvailable` | Auth | Auth capability detection |
| `ciphers` | CipherStore | Core vault data |
| `trashCiphers` | CipherStore | Vault data subset |
| `archivedCiphers` | CipherStore | Vault data subset |
| `folders` | CipherStore | Vault structure metadata |
| `activePane` | Navigation | View routing |
| `viewCipher` | Navigation | Selection state |
| `selectedCategory` | Navigation | Filter state |
| `selectedFolder` | Navigation | Filter state |
| `searchQuery` | Navigation | Filter state |
| `newCipher` | Form | Temporary form buffer |
| `createPassword` | Form | Vault creation buffer |
| `recoveryPhrase` | Form | Recovery flow buffer |
| `showDeleteConfirm` | Prefs | UI toggle |
| `showReprompt` | Prefs | UI toggle |
| `repromptCallback` | Prefs | UI toggle (paired with showReprompt) |
| `showGenerator` | Prefs | UI toggle |
| `showSettingsModal` | Prefs | UI toggle |
| `theme` | Prefs | User preference |
| `deviceFleet` | Device | Device management data |
| `selfDeviceId` | Device | Device management data |
| `revokeWarning` | Device | Device management UI state |

---

## 10. Future Extension Scenarios

### Adding a new cipher type (e.g., `CryptoWallet`)

1. Backend: Add `CipherKind::CryptoWallet` variant
2. Frontend: Add category entry in VaultView's `categories` array
3. Frontend: Add form fields in AddEditCipherForm
4. **Zero store changes needed.** The `newCipher` signal in FormStore is a plain object. New fields are just new keys.

### Adding a new screen (e.g., Breach Monitor)

1. Add `BreachStore` as a new context file
2. Add `<BreachProvider>` inside `<RootProvider>` (at the appropriate nesting level)
3. Create `useBreach()` hook
4. Add `activePane: "breach"` variant to NavigationStore (optional: could be a separate route)
5. Existing stores: **zero changes**

### Adding a new modal

1. Add `[showX, setShowX]` signal pair to PrefsStore
2. Create modal component importing `usePrefs`
3. Done. No other store touched.

### Adding shared vaults (future feature)

1. New `SharedVaultStore` with `sharedCiphers`, `invitations`, `permissions` signals
2. New `<SharedVaultProvider>` in RootProvider
3. Orchestrator gains `acceptInvitation()`, `leaveVault()` cross-domain ops
4. NavigationStore gains `"shared-vault"` pane
5. Existing CipherStore: **unchanged**. Shared vaults are a separate data domain.

### Adding audit log

1. New `AuditStore` with `logEntries`, `filters` signals
2. New `<AuditProvider>` in RootProvider
3. New `useAudit()` hook
4. Settings gains an "Audit Log" tab
5. Existing stores: **zero changes**
