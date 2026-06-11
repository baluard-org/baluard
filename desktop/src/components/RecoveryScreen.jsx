import { createSignal, Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { IconNote, IconCopy, IconCheck } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import { copyToClipboard } from "../lib/clipboard.js";

export default function RecoveryScreen() {
  const auth = useAuth();
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);

  const handleCopy = async () => {
    await copyToClipboard(auth.recoveryPhrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg">
            <IconNote class="w-8 h-8 text-white" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-2 font-semibold">{t("recovery.warning")}</p>
        </div>

        <div class="relative group p-5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed text-[var(--color-text)] break-words select-all mb-6 text-center select-all shadow-inner pr-12">
          {auth.recoveryPhrase()}
          <button
            onClick={handleCopy}
            class="absolute top-2 right-2 p-1.5 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-detail)] transition-all cursor-pointer shadow-sm flex items-center gap-1 text-xs"
            title={t("recovery.copyToClipboard")}
          >
            <Show when={copied()} fallback={
              <IconCopy class="w-4 h-4" />
            }>
              <span class="copy-feedback"><IconCheck class="w-4 h-4 text-[var(--color-success)]" /></span>
            </Show>
          </button>
        </div>

        <form onSubmit={async (e) => {
          e.preventDefault();
          // Zero recovery phrase from memory, transition to setup wizard
          auth.setRecoveryPhrase("");
          auth.setStatus("setup");
        }} class="space-y-4">
          <button
            type="submit"
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg cursor-pointer"
          >
            {t("recovery.confirm")}
          </button>
        </form>
      </div>
    </div>
  );
}
