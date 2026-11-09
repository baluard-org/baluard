import { createSignal, createContext, useContext, onSettled } from "solid-js";
import { clearHeldPhrase } from "../lib/heldPhrase.js";
// Note: per-vault Quick Unlock status is reactive. The login/switcher UIs
// call refreshBiometric(slug) when the selected vault changes so the button
// reflects THAT vault's keychain entry, not a stale global value.
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { makeTransitionGuard } from "../lib/transitionGuard.js";
import { buildCreatePayload } from "../lib/payload.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { toastError, toastWarning } from "./toastSignal.js";
import { useI18n } from "../i18n/index.jsx";

const AuthContext = createContext(null);

// Valid auth state transitions. Dev-only guard.
const VALID_AUTH_TRANSITIONS = {
  // "unlocked": biometric/PIN quick unlock flips directly (no unlocking
  // intermediate — the credential prompt IS the unlocking state).
  locked:    ["unlocking", "unlocked", "init", "welcome"],
  unlocking: ["unlocked", "locked"],
  unlocked:  ["locked"],
  init:      ["creating", "locked"],
  creating:  ["recovery", "init"],
  recovery:  ["setup", "init", "locked"],
  setup:     ["unlocked", "locked"],
  welcome:   ["init", "locked"],
};

// DEV-only diagnostics; the state write always runs (see transitionGuard.js).
const guardStatus = makeTransitionGuard(VALID_AUTH_TRANSITIONS, "auth");

function AuthProvider(props) {
  const { t } = useI18n();
  // Expiry coordination: one in-flight lock at a time, and an epoch that
  // invalidates an expiry whose lock call outlives a fresh unlock.
  let expiryInFlight = false;
  let authEpoch = 0;
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
  // Family creation: the Space Recovery Kit phrase, shown once on the
  // recovery screen alongside the vault phrase; zeroed on acknowledgment.
  const [kitPhrase, setKitPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");
  // Phase 6: when the user picks a locked/closed vault from the switcher,
  // this holds the target slug so the unlock screen unlocks THAT vault
  // (not the previously-active one). Cleared on successful unlock.
  const [switchTarget, setSwitchTarget] = createSignal(null);
  // Raw last unlock failure so the login screen can tell a hardware-seal
  // failure (never a wrong password) from a credential rejection.
  const [lastUnlockError, setLastUnlockError] = createSignal(null);

  // Shared tail for biometric/PIN quick unlock: mirror unlock()'s post-
  // unlock bookkeeping so quick unlock is not a second-class path.
  function finishQuickUnlock(infoStr) {
    if (loginPasswordRef) loginPasswordRef.value = "";
    if (infoStr) {
      try { setVaultInfo(JSON.parse(infoStr)); } catch {}
    }
    setLastUnlockError(null);
    setSwitchTarget(null);
    startVaultPrefetch();
    authEpoch += 1;
    guardStatus(status(), "unlocked", setStatus);
  }


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
    // daemon.js signals a rejected session token here. Cached entries keep
    // rendering otherwise while every live call fails, which reads as
    // features silently missing (e.g. TOTP) instead of a dead session.
    const onExpired = (e) => { void expireSession(e.detail); };
    window.addEventListener("baluard:session-expired", onExpired);
    return () => window.removeEventListener("baluard:session-expired", onExpired);
  });

  // Query Quick Unlock availability for a specific vault (slug). When slug
  // is omitted, the daemon resolves the active vault. The keychain check is
  // pre-unlock: vault_id is derivable from on-disk kdf-params without
  // decryption, so this works for a locked-but-open vault.
  async function refreshBiometric(slug = null) {
    try {
      // Reset while the per-vault query is in flight so a stale enabled
      // state from the previously targeted vault can never act on the new
      // one (the login screen auto-prompts off this signal).
      setBiometricAvailable(false);
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
    setLastUnlockError(null);
    const target = switchTarget();
    guardStatus(status(), "unlocking", setStatus);
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
      setLastUnlockError(null);
      setSwitchTarget(null);
      startVaultPrefetch();
      authEpoch += 1;
      guardStatus(status(), "unlocked", setStatus);
      return true;
    } catch (e) {
      setLastUnlockError(e?.message || String(e || ""));
      toastError(sanitizeError(e, t));
      guardStatus(status(), "locked", setStatus);
      return false;
    }
  }

  function lockLocal() {
    guardStatus(status(), "locked", setStatus);
    setVaultInfo(null);
    // D3: defensive — if onboarding was abandoned mid-setup, the vault
    // password signal must not survive a lock cycle either.
    setCreatePassword("");
    setKitPhrase("");
    setRecoveryPhrase("");
    // A locked vault must not leave a display-once phrase in module memory.
    clearHeldPhrase();
    // VaultProvider unmounts via <Show>. All vault signals destroyed.
  }

  async function expireSession(detail) {
    const slug = detail?.slug || null;
    // A dead token in a secondary vault must not kill the active session.
    if (slug && slug !== activeVault()?.slug) return;
    // The in-flight guard also stops re-entry when the lock call below
    // rejects with the same invalid-token error and re-emits the event.
    if (status() !== "unlocked" || expiryInFlight) return;
    expiryInFlight = true;
    const epoch = authEpoch;
    try {
      // The token is already dead server-side, so the lock call itself can
      // fail: lock locally regardless instead of leaving a stale UI up.
      try { await daemon("vault.lock"); } catch { /* session already invalid */ }
      // A re-unlock while the lock call was in flight wins over the expiry.
      if (epoch !== authEpoch || status() !== "unlocked") return;
      lockLocal();
      // Shown on the login screen and as a toast so the drop is explained.
      setLastUnlockError("Invalid session token");
      toastWarning(t("errors.sessionExpired"));
    } finally {
      expiryInFlight = false;
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      lockLocal();
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function createVault(t, { slug, name, family } = {}) {
    const pw = createPassword();
    if (!pw || pw.length < 8) { toastWarning(t("create.errorMinLength")); return; }
    setCreatePassword(pw);
    guardStatus(status(), "creating", setStatus);
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw, { slug, name, family }))));
      setRecoveryPhrase(result.recovery_phrase);
      setKitPhrase(result.kit_phrase || "");
      guardStatus(status(), "recovery", setStatus);
    } catch (e) {
      toastError(sanitizeError(e, t));
      guardStatus(status(), "init", setStatus);
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
    kitPhrase, setKitPhrase,
    createPassword, setCreatePassword,
    switchTarget, setSwitchTarget,
    setLoginPasswordRef: (r) => { loginPasswordRef = r; },
    lastUnlockError, unlock, lock, finishQuickUnlock, createVault, refreshActiveVault,
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
