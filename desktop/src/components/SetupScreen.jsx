import { createSignal, For } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { toastError } from "../context/toastSignal.js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { setTheme as setGlobalTheme } from "../context/themeSignal.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { IconKey } from "./Icon.jsx";
import { VAULT_TIMEOUT_PRESETS, DEFAULT_VAULT_TIMEOUT } from "../lib/vaultTimeout.js";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import FocusTrap from "./FocusTrap.jsx";

const THEME_OPTIONS = [
  { value: "system", key: "setup.themeSystem" },
  { value: "light", key: "setup.themeLight" },
  { value: "dark", key: "setup.themeDark" },
];

export default function SetupScreen() {
  const auth = useAuth();
  const { t, locale } = useI18n();
  const [theme, setTheme] = createSignal("system");
  const [timeoutToken, setTimeoutToken] = createSignal(DEFAULT_VAULT_TIMEOUT);
  const [displayName, setDisplayName] = createSignal("");
  const [subtitle, setSubtitle] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (submitting()) return;
    setSubmitting(true);

    try {
      const pw = auth.createPassword();
      if (pw) {
        await daemon("vault.open");
        await daemon("vault.unlock", pw);
      }

      // Apply preferences via settings.set
      const settingsPayload = {
        theme: theme(),
        lang: locale(),
        vault_timeout: timeoutToken(),
      };
      await daemon("settings.set", JSON.stringify(settingsPayload));

      // Save plaintext locale for pre-unlock access
      await daemon("locale.save", locale());

      // Apply profile if name provided
      const name = displayName().trim();
      const sub = subtitle().trim();
      if (name || sub) {
        const profilePayload = {};
        if (name) profilePayload.display_name = name;
        if (sub) profilePayload.subtitle = sub;
        await daemon("settings.set", JSON.stringify(profilePayload));
      }

      startVaultPrefetch();
      auth.setStatus("unlocked");
    } catch (err) {
      toastError(sanitizeError(err, t));
      auth.setStatus("locked");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <FocusTrap>
        <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
          <div class="text-center mb-8">
            <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg">
              <IconKey class="w-8 h-8 text-white" />
            </div>
            <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("setup.title")}</h1>
            <p class="text-sm text-[var(--color-muted)] mt-1">{t("setup.subtitle")}</p>
          </div>

          <form onSubmit={handleSubmit} class="space-y-6">
            {/* Profile section */}
            <fieldset>
              <legend class="text-sm font-semibold text-[var(--color-muted)] uppercase tracking-wider mb-3">
                {t("setup.profileSection")}
              </legend>
              <div class="space-y-3">
                <input
                  id="setup-display-name"
                  type="text"
                  autocomplete="name"
                  placeholder={t("setup.displayNamePlaceholder")}
                  onInput={e => setDisplayName(e.target.value)}
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                />
                <input
                  id="setup-subtitle"
                  type="text"
                  placeholder={t("setup.subtitlePlaceholder")}
                  onInput={e => setSubtitle(e.target.value)}
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                />
              </div>
            </fieldset>

            {/* Preferences section */}
            <fieldset>
              <legend class="text-sm font-semibold text-[var(--color-muted)] uppercase tracking-wider mb-3">
                {t("setup.prefsSection")}
              </legend>
              <div class="space-y-4">
                {/* Theme selector */}
                <div>
                  <label class="block text-sm font-medium text-[var(--color-text)] mb-2">{t("setup.themeLabel")}</label>
                  <div class="flex gap-2">
                    {THEME_OPTIONS.map(opt => (
                      <button
                        type="button"
                        onClick={() => {
                          setTheme(opt.value);
                          setGlobalTheme(opt.value);
                        }}
                        classList={{
                          "flex-1 py-2.5 px-3 rounded-xl text-sm font-medium transition-all cursor-pointer border": true,
                          "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]": theme() === opt.value,
                          "bg-[var(--color-bg)] text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-primary)]": theme() !== opt.value,
                        }}
                      >
                        {t(opt.key)}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Auto-lock */}
                <div>
                  <label for="setup-auto-lock" class="block text-sm font-medium text-[var(--color-text)] mb-2">
                    {t("setup.autoLockLabel")}
                  </label>
                  <select
                    id="setup-auto-lock"
                    value={timeoutToken()}
                    onChange={(e) => setTimeoutToken(e.currentTarget.value)}
                    class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
                  >
                    <For each={VAULT_TIMEOUT_PRESETS}>
                      {(p) => <option value={p.token}>{t(`setup.timeoutPreset.${p.token}`)}</option>}
                    </For>
                  </select>
                </div>
              </div>
            </fieldset>

            <button
              type="submit"
              disabled={submitting()}
              class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg active:scale-[0.99] disabled:opacity-50 cursor-pointer"
            >
              {submitting() ? t("setup.submitting") : t("setup.submit")}
            </button>
          </form>
        </div>
      </FocusTrap>
    </div>
  );
}
