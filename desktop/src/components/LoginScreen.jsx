import { Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { error } from "../context/errorSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { IconLock, IconAlert, IconUser } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";

export default function LoginScreen() {
  const auth = useAuth();
  const { t } = useI18n();
  let passwordRef;

  async function handleUnlock() {
    await auth.unlock(t);
  }

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />

      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast animate-fade-in-up">
        {/* Static gradient accents (contained glow, replaces expensive blur-3xl for GPU performance) */}
        <div class="absolute -top-10 -left-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-primary) 0%, transparent 70%)"}}></div>
        <div class="absolute -bottom-10 -right-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-accent) 0%, transparent 70%)"}}></div>

        <div class="text-center mb-8">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <IconLock class="w-8 h-8 text-[var(--color-primary)]" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
        </div>

        <Show when={error()}>
          <div class="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2">
            <IconAlert class="w-5 h-5 shrink-0 text-red-400" />
            {error()}
          </div>
        </Show>

        <form onSubmit={(e) => { e.preventDefault(); handleUnlock(); }} class="space-y-4">
          <div>
            <input
              ref={(el) => { passwordRef = el; auth.setLoginPasswordRef(el); }}
              type="password"
              autocomplete="current-password"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              placeholder={t("login.passwordPlaceholder")}
              value="estebancuevas"
              class="w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] transition-all-fast"
              autofocus
            />
          </div>

          <button
            type="submit"
            disabled={auth.status() === "unlocking"}
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg shadow-black/10 active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {auth.status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
          </button>

          {/* Quick Unlock (Biometric) */}
          <Show when={auth.biometricAvailable()}>
            <button
              type="button"
              onClick={async () => {
                try {
                  await daemon("vault.biometric_unlock");
                  auth.setStatus("unlocked");
                } catch (e) { /* Biometric failed or cancelled */ }
              }}
              class="w-full mt-2 py-3 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <IconUser class="w-4 h-4" />
              {t("login.quickUnlock")}
            </button>
          </Show>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => auth.setStatus("init")}
            class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("login.createNew")}
          </button>
        </div>
      </div>
    </div>
  );
}
