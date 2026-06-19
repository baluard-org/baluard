import { createSignal, createContext, useContext, onMount } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildCreatePayload } from "../lib/payload.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { toastError, toastWarning } from "./toastSignal.js";

const AuthContext = createContext();

// Valid auth state transitions. Dev-only guard.
const VALID_AUTH_TRANSITIONS = {
  locked:    ["unlocking", "init"],
  unlocking: ["unlocked", "locked"],
  unlocked:  ["locked"],
  init:      ["creating", "locked"],
  creating:  ["recovery", "init"],
  recovery:  ["setup", "init", "locked"],
  setup:     ["unlocked", "locked"],
};

function guardedSetStatus(setStatus, from, to) {
  if (!VALID_AUTH_TRANSITIONS[from]?.includes(to)) {
    console.warn(`[auth] Invalid transition: ${from} → ${to}`);
  }
  setStatus(to);
}

function AuthProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [activeVault, setActiveVault] = createSignal(null);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");
  // Phase 6: when the user picks a locked/closed vault from the switcher,
  // this holds the target slug so the unlock screen unlocks THAT vault
  // (not the previously-active one). Cleared on successful unlock.
  const [switchTarget, setSwitchTarget] = createSignal(null);

  async function refreshActiveVault() {
    try {
      const r = await daemon("vault.active");
      setActiveVault(JSON.parse(r));
    } catch {
      setActiveVault(null);
    }
  }

  onMount(() => {
    // Fetch active vault name from plaintext registry (pre-unlock)
    refreshActiveVault();
    // Check if quick unlock is enabled (daemon keychain + biometry available)
    daemon("vault.biometric_status").then(r => {
      const s = JSON.parse(r);
      setBiometricAvailable(s.available && s.enabled);
    }).catch(() => {});
  });

  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return;
    const target = switchTarget();
    guardedSetStatus(setStatus, status(), "unlocking");
    try {
      // Phase 6: if a switch target is set, unlock THAT vault; otherwise
      // unlock the active one. vault.unlock opens + unlocks + inserts into
      // the daemon map + makes it active in one round-trip.
      const payload = target
        ? JSON.stringify({ slug: target, password })
        : password;
      const slugArg = target || null;
      await daemon("vault.open", "", slugArg);
      const infoStr = await daemon("vault.unlock", payload, slugArg);
      if (loginPasswordRef) loginPasswordRef.value = "";
      try { setVaultInfo(JSON.parse(infoStr)); } catch {}
      setSwitchTarget(null);
      startVaultPrefetch();
      guardedSetStatus(setStatus, status(), "unlocked");
    } catch (e) {
      toastError(sanitizeError(e, t));
      guardedSetStatus(setStatus, status(), "locked");
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      guardedSetStatus(setStatus, status(), "locked");
      setVaultInfo(null);
      // VaultProvider unmounts via <Show>. All vault signals destroyed.
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function createVault(t) {
    const pw = createPassword();
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { toastWarning(t("create.errorMinLength")); return; }
    if (pw !== confirm) { toastWarning(t("create.errorMismatch")); return; }
    setCreatePassword(pw);
    guardedSetStatus(setStatus, status(), "creating");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw))));
      setRecoveryPhrase(result.recovery_phrase);
      guardedSetStatus(setStatus, status(), "recovery");
    } catch (e) {
      toastError(sanitizeError(e, t));
      guardedSetStatus(setStatus, status(), "init");
    }
  }

  const store = {
    status, setStatus,
    vaultInfo, setVaultInfo,
    activeVault,
    biometricAvailable,
    recoveryPhrase, setRecoveryPhrase,
    createPassword, setCreatePassword,
    switchTarget, setSwitchTarget,
    setLoginPasswordRef: (r) => { loginPasswordRef = r; },
    unlock, lock, createVault, refreshActiveVault,
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
