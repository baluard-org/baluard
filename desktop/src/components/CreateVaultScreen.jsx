import { createSignal, createMemo, Show, onMount } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { suggestSlug, cleanSlug, validateSlug } from "../lib/slug.js";
import { IconPencil, IconCheck } from "./Icon.jsx";
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

  const [vaultName, setVaultName] = createSignal("");
  const [customSlug, setCustomSlug] = createSignal("");
  const [editingSlug, setEditingSlug] = createSignal(false);

  // Auto-detect OS locale on first mount (before user has a saved preference)
  onMount(() => {
    const stored = localStorage.getItem("baluard-locale");
    if (!stored) {
      const detected = detectOsLocale();
      if (detected !== locale()) setLocale(detected);
    }
  });

  // Slug: follows the name unless the user edits it manually.
  const suggestedSlug = createMemo(() => suggestSlug(vaultName()));
  const activeSlug = createMemo(() => editingSlug() ? customSlug() : suggestedSlug());
  const slugError = createMemo(() => validateSlug(activeSlug()));

  const handleLangChange = (e) => {
    const code = e.target.value;
    if (code !== locale()) setLocale(code);
  };

  const handleEditToggle = () => {
    if (!editingSlug()) {
      // Seed the editable field with the current suggestion.
      setCustomSlug(suggestedSlug());
      setEditingSlug(true);
    } else {
      setEditingSlug(false);
      setCustomSlug("");
    }
  };

  const handleSlugInput = (e) => {
    const cleaned = cleanSlug(e.target.value);
    setCustomSlug(cleaned);
    e.target.value = cleaned;
  };

  const canSubmit = createMemo(() => vaultName().trim().length > 0 && !slugError());

  const handleSubmit = (e) => {
    e.preventDefault();
    if (auth.status() === "creating" || !canSubmit()) return;
    auth.createVault(t, { slug: activeSlug(), name: vaultName().trim() });
  };

  return (
    <div class="create-vault-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="create-vault-screen__card w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

        <div class="create-vault-screen__header text-center mb-8">
          <div class="create-vault-screen__logo-container w-24 h-24 mx-auto mb-4 flex items-center justify-center">
            <img src={logoImg} alt="Baluard" class="w-24 h-24 object-contain logo-shadow" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("create.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("create.subtitle")}</p>
        </div>

        <form onSubmit={handleSubmit} class="create-vault-screen__form space-y-4">
          <select
            value={locale()}
            onChange={handleLangChange}
            class="create-vault-screen__lang-select w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
          >
            {AVAILABLE_LOCALES.map(l => (
              <option value={l.code}>{l.label}</option>
            ))}
          </select>
          <div>
            <input
              id="create-vault-name"
              type="text"
              autocomplete="off"
              placeholder={t("create.namePlaceholder")}
              onInput={e => setVaultName(e.target.value)}
              class="create-vault-screen__input w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
            />

            {/* Slug caption: subtle, editable. Sits under the name. */}
            <div class="flex items-center gap-1.5 px-1 mt-1.5 -mb-0.5">
              <span class="text-[11px] text-[var(--color-muted)] shrink-0">{t("create.slugLabel")}:</span>
              <div class="min-w-0 flex-1">
                <Show when={!editingSlug()} fallback={
                  <input
                    type="text"
                    value={customSlug()}
                    onInput={handleSlugInput}
                    class="w-full bg-transparent text-[11px] font-mono text-[var(--color-text-muted)] outline-none"
                  />
                }>
                  <div class="text-[11px] font-mono text-[var(--color-muted)] truncate">{activeSlug()}</div>
                </Show>
              </div>
              <button
                type="button"
                onClick={handleEditToggle}
                title={editingSlug() ? t("create.slugDone") : t("create.slugEdit")}
                class="shrink-0 p-1 rounded-md text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-all cursor-pointer"
              >
                <Show when={!editingSlug()} fallback={<IconCheck class="w-3.5 h-3.5" />}>
                  <IconPencil class="w-3.5 h-3.5" />
                </Show>
              </button>
            </div>
            <Show when={slugError()}>
              <div class="text-[11px] text-red-400 px-1 mt-1">{slugError()}</div>
            </Show>
          </div>

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
            disabled={auth.status() === "creating" || !canSubmit()}
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
