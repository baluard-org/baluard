import { createSignal, createContext, useContext, onSettled } from "solid-js";
// Note: per-vault Quick Unlock status is reactive. The login/switcher UIs
// call refreshBiometric(slug) when the selected vault changes so the button
// reflects THAT vault's keychain entry, not a stale global value.
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildCreatePayload } from "../lib/payload.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { toastError, toastWarning } from "./toastSignal.js";

const AuthContext = createContext(null);

// Valid auth state transitions. Dev-only guard.
const VALID_AUTH_TRANSITIONS = {
  locked:    ["unlocking", "init", "welcome"],
  unlocking: ["unlocked", "locked"],
  unlocked:  ["locked"],
  init:      ["creating", "locked"],
  creating:  ["recovery", "init"],
  recovery:  ["setup", "init", "locked"],
  setup:     ["unlocked", "locked"],
  welcome:   ["init", "locked"],
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
  // Distro install command shown when Quick Unlock is unavailable because
  // the Linux Secret Service is missing ("app prints, user runs").
  const [keyringHint, setKeyringHint] = createSignal(null);
  // Session PIN Quick Unlock: available THIS session only (in-memory escrow).
  // Independent of biometric; both can be enabled at once (both buttons shown).
  const [pinAvailable, setPinAvailable] = createSignal(false);
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

  onSettled(() => {
    // Resolve the active vault (plaintext registry read, pre-unlock).
    // The daemon startup opens + activates the resolved default vault
    // before listening on the socket, so once the daemon is reachable this
    // returns the slug. Quick Unlock probes are owned by the view that
    // shows the buttons (LoginScreen effect), which tracks the resolved
    // slug so it re-fires once the daemon is ready instead of racing it
    // with a no-slug probe that logs at WARN on cold start.
    void refreshActiveVault();
  });

  // Query Quick Unlock availability for a specific vault (slug). When slug
  // is omitted, the daemon resolves the active vault. The keychain check is
  // pre-unlock: vault_id is derivable from on-disk kdf-params without
  // decryption, so this works for a locked-but-open vault.
  async function refreshBiometric(slug = null) {
    try {
      const s = JSON.parse(await daemon("vault.biometric_status", "", slug));
      setBiometricAvailable(s.available && s.enabled);
      // Install command when the system keyring (Linux Secret Service) is
      // missing: the app prints it, the user runs it.
      setKeyringHint(s.install_hint || null);
    } catch {
      // Slug not open in the daemon, or keychain unavailable: hide button.
      setBiometricAvailable(false);
      setKeyringHint(null);
    }
  }

  // Query session-PIN Quick Unlock availability for a specific vault. The
  // daemon holds the KEK escrow in memory; pin_status is an in-memory check,
  // so it works for a locked-but-open vault. Survives soft-lock within the
  // session; dies on daemon restart (then this returns false).
  async function refreshPin(slug = null) {
    try {
      const s = JSON.parse(await daemon("vault.pin_status", "", slug));
      setPinAvailable(!!s.enabled);
    } catch {
      setPinAvailable(false);
    }
  }

  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return false;
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
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      guardedSetStatus(setStatus, status(), "locked");
      return false;
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      guardedSetStatus(setStatus, status(), "locked");
      setVaultInfo(null);
      // D3: defensive — if onboarding was abandoned mid-setup, the vault
      // password signal must not survive a lock cycle either.
      setCreatePassword("");
      // VaultProvider unmounts via <Show>. All vault signals destroyed.
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function createVault(t, { slug, name } = {}) {
    const pw = createPassword();
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { toastWarning(t("create.errorMinLength")); return; }
    if (pw !== confirm) { toastWarning(t("create.errorMismatch")); return; }
    setCreatePassword(pw);
    guardedSetStatus(setStatus, status(), "creating");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw, { slug, name }))));
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
    biometricAvailable, refreshBiometric,
    keyringHint,
    pinAvailable, refreshPin,
    recoveryPhrase, setRecoveryPhrase,
    createPassword, setCreatePassword,
    switchTarget, setSwitchTarget,
    setLoginPasswordRef: (r) => { loginPasswordRef = r; },
    unlock, lock, createVault, refreshActiveVault,
  };

  return (
    <AuthContext value={store}>
      {props.children}
    </AuthContext>
  );
}

function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { AuthContext, AuthProvider, useAuth };
