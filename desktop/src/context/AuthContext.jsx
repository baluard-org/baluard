import { createSignal, createContext, useContext, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildCreatePayload } from "../lib/payload.js";
import { setError } from "./errorSignal.js";

const AuthContext = createContext();

function AuthProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);

  createEffect(() => {
    daemon("vault.biometric_status").then(r => {
      const s = JSON.parse(r);
      setBiometricAvailable(s.available && s.enabled);
    }).catch(() => {});
  });

  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return;
    setStatus("unlocking");
    setError("");
    try {
      await daemon("vault.open");
      await daemon("vault.unlock", password);
      if (loginPasswordRef) loginPasswordRef.value = "";
      setStatus("unlocked");
    } catch (e) {
      setError(sanitizeError(e, t));
      setStatus("locked");
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      setStatus("locked");
      setVaultInfo(null);
      setError("");
      // VaultProvider unmounts via <Show>. All vault signals destroyed.
    } catch (e) {
      setError(sanitizeError(e, t));
    }
  }

  async function createVault(t) {
    const pw = document.querySelector('[data-create-password]')?.value;
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { setError(t("create.errorMinLength")); return null; }
    if (pw !== confirm) { setError(t("create.errorMismatch")); return null; }
    setStatus("creating");
    setError("");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw))));
      setStatus("recovery");
      return result.recovery_phrase;
    } catch (e) {
      setError(sanitizeError(e, t));
      setStatus("init");
      return null;
    }
  }

  const store = {
    status, setStatus,
    vaultInfo, setVaultInfo,
    biometricAvailable,
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
