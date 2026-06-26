import { Show, createSignal } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { daemon } from "../lib/daemon.js";
import { biometryPrompt } from "../lib/biometry.js";
import { toastError } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";
import { IconLock, IconFingerprint, IconSpinner } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import VaultSwitcher from "./VaultSwitcher.jsx";

export default function LoginScreen() {
  const auth = useAuth();
  const switcher = useVaultSwitcher();
  const { t } = useI18n();
  let passwordRef;

  const [wrongPassword, setWrongPassword] = createSignal(false);
  const [bruteLock, setBruteLock] = createSignal(false);

  async function handleUnlock() {
    if (bruteLock() || auth.status() === "unlocking") return;
    const success = await auth.unlock(t);
    if (!success) {
      setWrongPassword(true);
      setBruteLock(true);
      setTimeout(() => {
        setWrongPassword(false);
      }, 500);
      setTimeout(() => {
        setBruteLock(false);
        passwordRef?.focus();
      }, 2000);
    }
  }

  return (
    <div class="login-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />

      <div class="login-screen__card w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast animate-fade-in-up">
        {/* Static gradient accents (contained glow, replaces expensive blur-3xl for GPU performance) */}
        <div class="login-screen__glow-top absolute -top-10 -left-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-primary) 0%, transparent 70%)"}}></div>
        <div class="login-screen__glow-bottom absolute -bottom-10 -right-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-accent) 0%, transparent 70%)"}}></div>

        <div class="login-screen__header text-center mb-8">
          <div class="login-screen__logo-container w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <IconLock class="w-8 h-8 text-[var(--color-primary)]" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
          <Show when={switcher.vaults().length > 1} fallback={
            <Show when={auth.activeVault()}>
              <p class="text-xs text-[var(--color-primary)] mt-2 font-medium">{auth.activeVault().display_name}</p>
            </Show>
          }>
            <div class="w-full mt-4 text-left">
              <VaultSwitcher onLockedTarget={async (row) => {
                // Pre-unlock: moving the active pointer is safe (nothing is
                // unlocked yet) and is what makes the pick visibly change the
                // selection. Contrast with the unlocked view, where the
                // pointer must NOT move until the target actually unlocks.
                await switcher.switchTo(row.slug);
                auth.setSwitchTarget(row.slug);
                auth.refreshActiveVault();
              }} />
            </div>
          </Show>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); handleUnlock(); }} class="login-screen__form space-y-4">
          <div>
            <input
              ref={(el) => { passwordRef = el; auth.setLoginPasswordRef(el); }}
              type="password"
              autocomplete="current-password"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              placeholder={t("login.passwordPlaceholder")}
              class={`login-screen__input w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border text-[var(--color-text)] outline-none transition-all-fast ${
                wrongPassword()
                  ? "animate-shake border-red-500 ring-1 ring-red-500 text-red-500 focus:border-red-500 focus:ring-red-500"
                  : "border-[var(--color-border)] focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
              }`}
              disabled={auth.status() === "unlocking" || bruteLock()}
              autofocus
            />
          </div>

          <button
            type="submit"
            disabled={auth.status() === "unlocking" || bruteLock()}
            class="login-screen__submit-btn w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg shadow-black/10 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
          >
            <Show when={auth.status() === "unlocking"}>
              <IconSpinner class="w-4 h-4" />
            </Show>
            {auth.status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
          </button>

          {/* Quick Unlock (Biometric) */}
          <Show when={auth.biometricAvailable()}>
            <button
              type="button"
              onClick={async () => {
                if (bruteLock()) return;
                try {
                  // Touch ID prompt (UX gate)
                  await biometryPrompt();
                  // Daemon reads password from file-based keychain + unlocks vault
                  await daemon("vault.open");
                  await daemon("vault.biometric_unlock");
                  auth.setStatus("unlocked");
                } catch (e) {
                  if (!/cancelled|canceled|user cancel/i.test(e?.message || "")) {
                    toastError(sanitizeError(e, t));
                  }
                }
              }}
              disabled={bruteLock()}
              class="login-screen__quick-unlock-btn w-full mt-2 py-3 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <IconFingerprint class="w-4 h-4" />
              {t("login.quickUnlock")}
            </button>
          </Show>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => auth.setStatus("welcome")}
            class="login-screen__create-btn text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("login.useDifferent")}
          </button>
        </div>
      </div>
    </div>
  );
}
