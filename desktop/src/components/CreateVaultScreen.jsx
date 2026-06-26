import { onMount } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import logoImg from "../assets/logo.png";

const AVAILABLE_LOCALES = [
  { code: "en", label: "English" },
  { code: "es", label: "Espa\u00f1ol" },
];

function detectOsLocale() {
  try {
    const lang = navigator.language?.split("-")[0];
    if (lang === "en" || lang === "es") return lang;
  } catch {}
  return "en";
}

export default function CreateVaultScreen() {
  const auth = useAuth();
  const { t, locale, setLocale } = useI18n();

  // Auto-detect OS locale on first mount (before user has a saved preference)
  onMount(() => {
    const stored = localStorage.getItem("baluard-locale");
    if (!stored) {
      const detected = detectOsLocale();
      if (detected !== locale()) setLocale(detected);
    }
  });

  const handleLangChange = (e) => {
    const code = e.target.value;
    if (code !== locale()) setLocale(code);
  };

  return (
    <div class="create-vault-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="create-vault-screen__card w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

        <div class="create-vault-screen__header text-center mb-8">
          <div class="create-vault-screen__logo-container w-24 h-24 mx-auto mb-4 flex items-center justify-center">
            <img src={logoImg} alt="Baluard" class="w-24 h-24 object-contain" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("create.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("create.subtitle")}</p>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); auth.createVault(t); }} class="create-vault-screen__form space-y-4">
          <select
            value={locale()}
            onChange={handleLangChange}
            class="create-vault-screen__lang-select w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
          >
            {AVAILABLE_LOCALES.map(l => (
              <option value={l.code}>{l.label}</option>
            ))}
          </select>
          <input
            id="create-password"
            data-create-password
            type="password"
            autocomplete="new-password"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            placeholder={t("create.passwordPlaceholder")}
            onInput={e => auth.setCreatePassword(e.target.value)}
            class="create-vault-screen__input w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <input
            id="create-confirm"
            type="password"
            autocomplete="new-password"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            placeholder={t("create.confirmPlaceholder")}
            class="create-vault-screen__input w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <button
            type="submit"
            disabled={auth.status() === "creating"}
            class="create-vault-screen__submit-btn w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {auth.status() === "creating" ? t("create.creating") : t("create.submit")}
          </button>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => auth.setStatus("locked")}
            class="create-vault-screen__back-btn text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("create.alreadyHaveVault")}
          </button>
        </div>
      </div>
    </div>
  );
}
