import { createSignal, Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";

export default function RecoveryScreen() {
  const app = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(app.recoveryPhrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-2 font-semibold">{t("recovery.warning")}</p>
        </div>

        <div class="relative group p-5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed text-[var(--color-text)] break-words select-all mb-6 text-center select-all shadow-inner pr-12">
          {app.recoveryPhrase()}
          <button
            onClick={handleCopy}
            class="absolute top-2 right-2 p-1.5 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-detail)] transition-all cursor-pointer shadow-sm flex items-center gap-1 text-xs"
            title="Copy to clipboard"
          >
            <Show when={copied()} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 002 2h2a2 2 0 002-2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
            }>
              <span class="text-emerald-500 font-sans font-medium text-xs">Copied!</span>
              <svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
            </Show>
          </button>
        </div>

        <form onSubmit={async (e) => {
          e.preventDefault();
          app.setStatus("unlocking");
          const pw = app.createPassword();
          if (pw) {
            try {
              await daemon("vault.unlock", pw);
              app.setStatus("unlocked");
              app.setCreatePassword("");
              await refreshCiphers();
            } catch (err) { app.setError(sanitizeError(err, t)); app.setStatus("locked"); }
          } else { app.setStatus("locked"); }
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
