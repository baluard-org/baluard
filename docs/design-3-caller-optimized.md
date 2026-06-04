# Store Split Design: Caller-Optimized

**Date:** 2026-06-04
**Constraint:** Optimize for VaultView (22 signals) + useActions (20+ mutations). Other components are secondary.

---

## 1. The Split: 3 Stores

The principle: **group by co-location of consumption, not by domain taxonomy.** VaultView and useActions touch nearly everything. Auth screens touch almost nothing. The split must make the hot path trivial and let cold paths opt-in.

```
AuthProvider       -- auth lifecycle, error, biometric, theme, recovery, createPassword
VaultProvider      -- ALL vault session data (ciphers, nav, form, UI toggles, fleet, view)
 └─ (no children)  -- VaultProvider wraps the entire unlocked subtree
```

Two stores. Not three. Why: VaultView destructures 22 signals. Splitting "cipher data" from "navigation" from "form buffer" from "UI toggles" would make VaultView import from 4 contexts instead of 1. The optimization target demands **one call, all the goods.**

AuthProvider lives outside VaultView (it gates the entire app). VaultProvider lives inside VaultView (it owns the unlocked session).

### Signal Assignment

| Store | Signals |
|-------|---------|
| **AuthProvider** | `status`, `error`, `vaultInfo`, `biometricAvailable`, `theme`, `recoveryPhrase`, `createPassword` |
| **VaultProvider** | `ciphers`, `trashCiphers`, `archivedCiphers`, `deviceFleet`, `selfDeviceId`, `selectedCategory`, `selectedFolder`, `folders`, `searchQuery`, `activePane`, `viewCipher`, `newCipher`, `showDeleteConfirm`, `showReprompt`, `repromptCallback`, `showGenerator`, `showSettingsModal`, `revokeWarning` |

### Rationale

- **AuthProvider** (7 signals): Everything needed before unlock + cross-session prefs (theme). Auth screens only touch this.
- **VaultProvider** (18 signals): Everything that only exists during an unlocked session. Cleared atomically on `lock()`.
- `vaultInfo` stays in Auth because `AppInner` reads it to decide `status("unlocked")` before VaultProvider exists.
- `theme` stays in Auth because `ThemeToggleFloating` renders on every screen including login.
- `recoveryPhrase` and `createPassword` stay in Auth: they're part of vault creation flow, which happens before VaultProvider mounts.

---

## 2. Provider Nesting

```
<AuthProvider>
  <AppInner />
</AuthProvider>

AppInner renders:
  locked  -> <LoginScreen />       (uses useAuth only)
  init    -> <CreateVaultScreen /> (uses useAuth only)
  recovery -> <RecoveryScreen />   (uses useAuth only)
  unlocked -> <VaultProvider>       (uses useAuth + useVault)
                <VaultView />
              </VaultProvider>
```

**Key insight:** VaultProvider only mounts when status === "unlocked". On `lock()`, VaultProvider unmounts entirely. All 18 signals are destroyed. No manual reset needed for most signals.

**This is the trick.** The original `lock()` resets 7 signals across 4 domains. With VaultProvider lifetime-bound to the unlocked state, unmounting the provider destroys all vault signals for free. Only AuthProvider signals need manual reset: `status`, `vaultInfo`.

### Tree diagram

```
AuthProvider
  ├── LoginScreen
  ├── CreateVaultScreen
  ├── RecoveryScreen
  └── VaultProvider          ← only mounts when unlocked
        └── VaultView
              ├── CipherDetail
              ├── AddEditCipherForm
              ├── DeleteConfirmModal
              ├── GeneratorModal
              ├── RepromptModal
              ├── SettingsModal
              └── CipherRow, FolderTree, etc.
```

No circular nesting. VaultProvider is a child of AuthProvider. No VaultProvider signal is ever read outside VaultProvider.

---

## 3. Interface Signatures

### `useAuth()` -- consumed by auth screens, AppInner, ThemeToggle

```ts
interface AuthActions {
  setStatus: (s: "locked"|"unlocked"|"init"|"creating"|"recovery"|"unlocking") => void;
  setError: (e: string) => void;
  setVaultInfo: (info: object | null) => void;
  setTheme: (t: "dark" | "light") => void;
  setRecoveryPhrase: (p: string) => void;
  setCreatePassword: (p: string) => void;
}

type AuthStore = {
  // Signals (reactive getters)
  status: Accessor<string>;
  error: Accessor<string>;
  vaultInfo: Accessor<object | null>;
  biometricAvailable: Accessor<boolean>;
  theme: Accessor<string>;
  recoveryPhrase: Accessor<string>;
  createPassword: Accessor<string>;
} & AuthActions;
```

### `useVault()` -- consumed by VaultView, useActions, all vault-scoped components

```ts
interface VaultActions {
  setCiphers: (c: Cipher[]) => void;
  setTrashCiphers: (c: Cipher[]) => void;
  setArchivedCiphers: (c: Cipher[]) => void;
  setDeviceFleet: (d: Device[]) => void;
  setSelfDeviceId: (id: string | null) => void;
  setSelectedCategory: (c: string) => void;
  setSelectedFolder: (f: string | null) => void;
  setFolders: (f: Folder[]) => void;
  setSearchQuery: (q: string) => void;
  setActivePane: (p: "welcome"|"detail"|"add"|"edit") => void;
  setViewCipher: (c: object | null) => void;
  setNewCipher: (c: CipherInput) => void;
  setShowDeleteConfirm: (b: boolean) => void;
  setShowReprompt: (b: boolean) => void;
  setRepromptCallback: (cb: (() => void) | null) => void;
  setShowGenerator: (b: boolean) => void;
  setShowSettingsModal: (b: boolean) => void;
  setRevokeWarning: (w: object | null) => void;
}

type VaultStore = {
  ciphers: Accessor<Cipher[]>;
  trashCiphers: Accessor<Cipher[]>;
  archivedCiphers: Accessor<Cipher[]>;
  deviceFleet: Accessor<Device[]>;
  selfDeviceId: Accessor<string | null>;
  selectedCategory: Accessor<string>;
  selectedFolder: Accessor<string | null>;
  folders: Accessor<Folder[]>;
  searchQuery: Accessor<string>;
  activePane: Accessor<string>;
  viewCipher: Accessor<object | null>;
  newCipher: Accessor<CipherInput>;
  showDeleteConfirm: Accessor<boolean>;
  showReprompt: Accessor<boolean>;
  repromptCallback: Accessor<(() => void) | null>;
  showGenerator: Accessor<boolean>;
  showSettingsModal: Accessor<boolean>;
  revokeWarning: Accessor<object | null>;
} & VaultActions;
```

---

## 4. Implementation

### `context/AuthContext.jsx`

```jsx
import { createSignal, createContext, useContext, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";

const AuthContext = createContext();

function AuthProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  const [theme, setTheme] = createSignal("dark");
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");

  createEffect(() => {
    daemon("vault.biometric_status").then(r => {
      const s = JSON.parse(r);
      setBiometricAvailable(s.available && s.enabled);
    }).catch(() => {});
  });

  createEffect(() => {
    if (theme() === "light") {
      document.body.classList.add("light-theme");
    } else {
      document.body.classList.remove("light-theme");
    }
  });

  const store = {
    status, setStatus,
    error, setError,
    vaultInfo, setVaultInfo,
    biometricAvailable,
    theme, setTheme,
    recoveryPhrase, setRecoveryPhrase,
    createPassword, setCreatePassword,
  };

  return (
    <AuthContext.Provider value={store}>
      {props.children}
    </AuthContext.Provider>
  );
}

function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { AuthContext, AuthProvider, useAuth };
```

### `context/VaultContext.jsx`

```jsx
import { createSignal, createContext, useContext } from "solid-js";

const VaultContext = createContext();

const EMPTY_CIPHER = {
  name: "", username: "", password: "", uris: [], notes: "",
  cipherType: "login", favorite: false, reprompt: false,
  attachments: [], folder_id: null, custom_fields: [], totp_uri: "",
};

function VaultProvider(props) {
  const [ciphers, setCiphers] = createSignal([]);
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);
  const [deviceFleet, setDeviceFleet] = createSignal([]);
  const [selfDeviceId, setSelfDeviceId] = createSignal(null);

  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [folders, setFolders] = createSignal([]);
  const [searchQuery, setSearchQuery] = createSignal("");

  const [activePane, setActivePane] = createSignal("welcome");
  const [viewCipher, setViewCipher] = createSignal(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  const [showReprompt, setShowReprompt] = createSignal(false);
  const [repromptCallback, setRepromptCallback] = createSignal(null);
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);
  const [revokeWarning, setRevokeWarning] = createSignal(null);
  const [newCipher, setNewCipher] = createSignal({ ...EMPTY_CIPHER });

  const store = {
    ciphers, setCiphers,
    trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    deviceFleet, setDeviceFleet,
    selfDeviceId, setSelfDeviceId,
    selectedCategory, setSelectedCategory,
    selectedFolder, setSelectedFolder,
    folders, setFolders,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    viewCipher, setViewCipher,
    showDeleteConfirm, setShowDeleteConfirm,
    showReprompt, setShowReprompt,
    repromptCallback, setRepromptCallback,
    showGenerator, setShowGenerator,
    showSettingsModal, setShowSettingsModal,
    revokeWarning, setRevokeWarning,
    newCipher, setNewCipher,
  };

  return (
    <VaultContext.Provider value={store}>
      {props.children}
    </VaultContext.Provider>
  );
}

function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used within VaultProvider");
  return ctx;
}

export { VaultContext, VaultProvider, useVault };
```

---

## 5. Usage Examples

### VaultView (the primary optimization target)

**Before (22 signals from one context):**
```jsx
const { ciphers, trashCiphers, archivedCiphers, vaultInfo, error, selectedCategory, setSelectedCategory, selectedFolder, setSelectedFolder, folders, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, theme, setTheme, showGenerator, setShowGenerator, showSettingsModal, setShowSettingsModal } = useApp();
```

**After (22 signals from two contexts):**
```jsx
const { error, vaultInfo, theme, setTheme } = useAuth();
const { ciphers, trashCiphers, archivedCiphers, selectedCategory, setSelectedCategory, selectedFolder, setSelectedFolder, folders, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, showGenerator, setShowGenerator, showSettingsModal, setShowSettingsModal } = useVault();
```

Net change: one import becomes two. Same destructuring pattern. VaultView already imports 12 things; two lines instead of one is negligible. The 18 `useVault()` signals come from a single call. The 4 `useAuth()` signals come from a single call. No third or fourth context.

### useActions (the second optimization target)

**Before:**
```jsx
const app = useApp();
// then: app.setStatus(...), app.setCiphers(...), app.setActivePane(...)
```

**After:**
```jsx
const auth = useAuth();
const vault = useVault();

// Example: lock() -- the cross-domain reset
async function lock(t) {
  try {
    await daemon("vault.lock");
    auth.setStatus("locked");       // AuthProvider signal
    auth.setVaultInfo(null);        // AuthProvider signal
    // VaultProvider unmounts next render.
    // All 18 vault signals destroyed automatically.
    // No manual reset needed for: ciphers, viewCipher, activePane,
    //   showDeleteConfirm, revokeWarning, newCipher, etc.
  } catch (e) {
    auth.setError(sanitizeError(e, t));
  }
}
```

**The `lock()` simplification is the biggest win.** Before: 7 manual resets. After: 2 manual resets. The other 5 (setCiphers([]), setViewCipher(null), setActivePane("welcome"), setShowDeleteConfirm(false), setRevokeWarning(null)) are unnecessary because VaultProvider unmounts and destroys all its signals.

**Other action patterns:**
```jsx
// unlock -- touches both stores
async function unlock(t) {
  const password = loginPasswordRef?.value;
  if (!password) return;
  auth.setStatus("unlocking");
  auth.setError("");
  try {
    await daemon("vault.open");
    await daemon("vault.unlock", password);
    auth.setStatus("unlocked");          // triggers VaultProvider mount
    if (loginPasswordRef) loginPasswordRef.value = "";
    await refreshCiphers();
    const info = JSON.parse(await daemon("vault.info"));
    auth.setVaultInfo(info);
  } catch (e) {
    auth.setError(sanitizeError(e, t));
    auth.setStatus("locked");
  }
}

// addCipher -- only vault store
async function addCipher(t) {
  const c = vault.newCipher();
  if (!c.name) { auth.setError(t("entry.namePlaceholder") + " required"); return; }
  try {
    await daemon("vault.add", JSON.stringify(buildAddPayload(c)));
    vault.setNewCipher({ ...EMPTY_CIPHER });
    vault.setActivePane("welcome");
    await refreshCiphers();
  } catch (e) {
    auth.setError(sanitizeError(e, t));
  }
}
```

Pattern: `auth.setError()` for error reporting (cross-cutting), `vault.setX()` for vault mutations. Clean.

### Auth-only component: LoginScreen

**Before:**
```jsx
const app = useApp();
// uses: app.error(), app.biometricAvailable(), app.setStatus(), app.setError()
```

**After:**
```jsx
const auth = useAuth();
// uses: auth.error(), auth.biometricAvailable(), auth.setStatus(), auth.setError()
```

No change in complexity. Still one context. Now it's semantically correct: LoginScreen has zero access to vault signals. It literally cannot import `useVault()` because VaultProvider doesn't exist in the tree yet.

### Modal component: GeneratorModal

**Before:**
```jsx
const { showGenerator, setShowGenerator } = useApp();
```

**After:**
```jsx
const { showGenerator, setShowGenerator } = useVault();
```

Same shape. Different import.

### App.jsx

```jsx
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { VaultProvider } from "./context/VaultContext.jsx";
import { useActions } from "./hooks/useActions.js";
import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import VaultView from "./components/VaultView.jsx";

export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}

function AppInner() {
  const { setStatus, setError, setVaultInfo, status } = useAuth();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (/Cannot connect/i.test(e.message)) {
        setError("");
      } else {
        setStatus("init");
      }
      return;
    }
    try {
      const info = JSON.parse(await daemon("vault.info"));
      if (info.unlocked) {
        setStatus("unlocked");
        setVaultInfo(info);
        await refreshCiphers();
      }
    } catch {}
  });

  return (
    <Show when={status() === "unlocked"} fallback={
      <Show when={status() === "init" || status() === "creating"} fallback={
        <Show when={status() === "recovery"} fallback={<LoginScreen />}>
          <RecoveryScreen />
        </Show>
      }>
        <CreateVaultScreen />
      </Show>
    }>
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    </Show>
  );
}
```

---

## 6. How `lock()` Cross-Domain Reset Works

### Before (manual reset of 7 signals)

```jsx
async function lock(t) {
  await daemon("vault.lock");
  app.setStatus("locked");               // auth domain
  app.setCiphers([]);                    // cipher domain
  app.setVaultInfo(null);                // auth domain
  app.setViewCipher(null);               // view domain
  app.setActivePane("welcome");          // nav domain
  app.setShowDeleteConfirm(false);       // ui domain
  app.setRevokeWarning(null);            // misc domain
}
```

### After (structural reset via unmount)

```jsx
async function lock(t) {
  await daemon("vault.lock");
  auth.setStatus("locked");              // triggers status !== "unlocked"
  auth.setVaultInfo(null);
  // VaultProvider unmounts. All 18 signals garbage-collected.
  // Next unlock creates fresh VaultProvider with default signal values.
}
```

**Mechanism:** `auth.setStatus("locked")` causes the `<Show when={status() === "unlocked"}>` in AppInner to switch to fallback. VaultProvider unmounts. SolidJS destroys all 18 signals. When the user unlocks again, `auth.setStatus("unlocked")` mounts a fresh VaultProvider with all signals at their initial defaults.

**What gets reset for free:**
- `ciphers` -> `[]`
- `trashCiphers` -> `[]`
- `archivedCiphers` -> `[]`
- `deviceFleet` -> `[]`
- `selfDeviceId` -> `null`
- `selectedCategory` -> `"All items"`
- `selectedFolder` -> `null`
- `folders` -> `[]`
- `searchQuery` -> `""`
- `activePane` -> `"welcome"`
- `viewCipher` -> `null`
- `showDeleteConfirm` -> `false`
- `showReprompt` -> `false`
- `repromptCallback` -> `null`
- `showGenerator` -> `false`
- `showSettingsModal` -> `false`
- `revokeWarning` -> `null`
- `newCipher` -> fresh empty object

All 18 signals reset to default. Zero manual code. Zero risk of forgetting one.

---

## 7. Migration Path

### Phase 1: Create new context files (non-breaking)
- Create `context/AuthContext.jsx` and `context/VaultContext.jsx`
- Keep `context/AppContext.jsx` untouched

### Phase 2: Wrap VaultProvider
- In `App.jsx`, wrap `<VaultView />` with `<VaultProvider>` inside the unlocked `<Show>`
- Auth screens remain outside VaultProvider

### Phase 3: Update imports (component by component)
- `VaultView.jsx`: `useApp()` -> `useAuth()` (4 signals) + `useVault()` (18 signals)
- `CipherDetail.jsx`: `useApp()` -> `useVault()` (8 signals)
- `useActions.js`: `useApp()` -> `useAuth()` + `useVault()`
- `LoginScreen.jsx`: `useApp()` -> `useAuth()`
- `CreateVaultScreen.jsx`: `useApp()` -> `useAuth()`
- `RecoveryScreen.jsx`: `useApp()` -> `useAuth()`
- `GeneratorModal.jsx`: `useApp()` -> `useVault()`
- `RepromptModal.jsx`: `useApp()` -> `useVault()`
- `DeleteConfirmModal.jsx`: `useApp()` -> `useVault()`
- `SettingsModal.jsx`: `useApp()` -> `useAuth()` (theme) + `useVault()` (fleet, revokeWarning, settingsModal)
- `DeviceFleetPanel.jsx`: `useApp()` -> `useVault()`
- `CipherRow.jsx`: `useApp()` -> `useVault()`
- `AddEditCipherForm.jsx`: `useApp()` -> `useVault()`
- `ThemeToggleFloating.jsx`: `useApp()` -> `useAuth()`

### Phase 4: Delete AppContext.jsx

Each component changes exactly one import line (split into two at most). No logic changes.

---

## 8. Trade-offs

### Wins

| Win | Detail |
|-----|--------|
| **VaultView unchanged DX** | Still 2 destructuring lines vs 1. Trivial. Gets 18/22 signals from one call. |
| **useActions simpler** | `lock()` goes from 7 resets to 2. Eliminates a whole class of "forgot to reset" bugs. |
| **Auth isolation** | LoginScreen literally cannot access vault data. Enforced by tree structure, not convention. |
| **Automatic reset** | VaultProvider unmount = all vault signals destroyed. Impossible to leak stale state. |
| **Zero new deps** | Pure SolidJS primitives. No store library. |
| **Smaller re-render surface** | Auth signal changes (e.g., `error`) don't trigger VaultProvider subscriptions and vice versa. |
| **Clear ownership** | Every signal has exactly one owner. No "which store does `error` live in?" ambiguity. |

### Costs

| Cost | Detail |
|------|--------|
| **Two imports instead of one** | VaultView, useActions, and SettingsModal need both `useAuth()` + `useVault()`. |
| **SettingsModal split** | Reads `theme` (auth) and `deviceFleet`/`revokeWarning`/`showSettingsModal` (vault). Most complex migration: 2 contexts. |
| **Provider nesting** | One extra level in the tree. Trivial runtime cost, but a concept to teach. |
| **VaultProvider mount cost** | On unlock, all 18 signals created fresh. In practice: microseconds. SolidJS `createSignal` is cheap. |
| **`error` lives in Auth** | All vault error reporting goes through `auth.setError()`. Conceptually cross-cutting. But `error` is truly global (shown on every screen), so Auth is the right home. |
| **`newCipher` default duplication** | `EMPTY_CIPHER` constant must be shared between VaultContext and any action that resets it. Could export from a shared constant file. |
| **No lazy loading** | All 18 vault signals mount together. Fine for a desktop app. Would need a different approach for mobile/memory-constrained environments. |

### What This Design Explicitly Does NOT Do

- **No 5-store split** (auth, ciphers, nav, form, UI). That optimizes for domain purity. VaultView would need 4 imports. The requirement says optimize for VaultView.
- **No signal proxy/store pattern** (createStore, proxy objects). Adds complexity, breaks SolidJS debugging, and the 30-signal surface doesn't warrant it.
- **No event bus for lock().** The structural reset (unmount) is simpler, provably correct, and requires zero infrastructure.

### Risk: "What if a vault signal is needed outside VaultProvider?"

Won't happen in the current codebase. Every vault signal consumer is a descendant of VaultView. If a future feature needs vault data on the login screen (e.g., "last sync time"), it goes in AuthProvider as `vaultInfo.lastSync` or similar. The split is defined by component tree topology, not abstract domain theory.

---

## 9. Component-to-Store Mapping

| Component | useAuth | useVault | Notes |
|-----------|---------|----------|-------|
| AppInner | x | | status, vaultInfo |
| LoginScreen | x | | error, biometricAvailable |
| CreateVaultScreen | x | | error, createPassword |
| RecoveryScreen | x | | recoveryPhrase |
| ThemeToggleFloating | x | | theme |
| VaultView | x | x | 4 auth + 18 vault |
| CipherDetail | | x | 8 vault signals |
| CipherRow | | x | viewCipher, activePane |
| AddEditCipherForm | | x | newCipher, viewCipher, activePane |
| DeleteConfirmModal | | x | 3 vault signals |
| GeneratorModal | | x | 2 vault signals |
| RepromptModal | | x | 3 vault signals |
| SettingsModal | x | x | theme (auth) + fleet/revokeWarning/modal (vault) |
| DeviceFleetPanel | | x | deviceFleet, selfDeviceId |
| useActions | x | x | Both: auth.setError + vault mutations |

12 of 15 components use a single store. Only 3 use both. The primary optimization target (VaultView) uses both but gets 82% of its signals from one call.
