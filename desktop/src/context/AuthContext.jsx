import { createSignal, createContext, useContext, onMount } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildCreatePayload } from "../lib/payload.js";
import { setError } from "./errorSignal.js";

const AuthContext = createContext();

// Valid auth state transitions. Dev-only guard.
const VALID_AUTH_TRANSITIONS = {
  locked:    ["unlocking", "init"],
  unlocking: ["unlocked", "locked"],
  unlocked:  ["locked"],
  init:      ["creating"],
  creating:  ["recovery", "init"],
  recovery:  ["init", "locked"],
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
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");

  onMount(() => {
    daemon("vault.biometric_status").then(r => {
      const s = JSON.parse(r);
      setBiometricAvailable(s.available && s.enabled);
    }).catch(() => {});
  });

  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return;
    guardedSetStatus(setStatus, status(), "unlocking");
    setError("");
    try {
      await daemon("vault.open");
      await daemon("vault.unlock", password);
      if (loginPasswordRef) loginPasswordRef.value = "";
      guardedSetStatus(setStatus, status(), "unlocked");
    } catch (e) {
      setError(sanitizeError(e, t));
      guardedSetStatus(setStatus, status(), "locked");
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      guardedSetStatus(setStatus, status(), "locked");
      setVaultInfo(null);
      setError("");
      // VaultProvider unmounts via <Show>. All vault signals destroyed.
    } catch (e) {
      setError(sanitizeError(e, t));
    }
  }

  async function createVault(t) {
    const pw = createPassword();
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { setError(t("create.errorMinLength")); return; }
    if (pw !== confirm) { setError(t("create.errorMismatch")); return; }
    setCreatePassword(pw);
    guardedSetStatus(setStatus, status(), "creating");
    setError("");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw))));
      setRecoveryPhrase(result.recovery_phrase);
      guardedSetStatus(setStatus, status(), "recovery");
    } catch (e) {
      setError(sanitizeError(e, t));
      guardedSetStatus(setStatus, status(), "init");
    }
  }

  const store = {
    status, setStatus,
    vaultInfo, setVaultInfo,
    biometricAvailable,
    recoveryPhrase, createPassword,
    setLoginPasswordRef: (r) => { loginPasswordRef = r; },
    unlock, lock, createVault,
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
