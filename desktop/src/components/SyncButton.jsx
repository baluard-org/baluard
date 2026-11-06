import { createSignal } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { IconRefresh } from "./Icon.jsx";

// Toolbar sync trigger: the same bidirectional pull + push the settings
// screen runs, with a spinning icon while in flight. Kept as a real button
// because the titlebar indicator is display-only (no reliable hit area).
export default function SyncButton() {
  const { t } = useI18n();
  const [syncing, setSyncing] = createSignal(false);

  async function doSync() {
    if (syncing()) return;
    setSyncing(true);
    // Arm the titlebar indicator's waiting phase so it tracks this cycle.
    window.dispatchEvent(new CustomEvent("baluard:local-mutation"));
    try {
      await daemon("sync.pull");
      await daemon("sync.push");
      toastSuccess(t("sync.statusActive"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setSyncing(false);
    }
  }

  return (
    <button
      type="button"
      data-testid="sync-now"
      onClick={doSync}
      disabled={syncing()}
      title={t("sync.syncNow")}
      aria-label={t("sync.syncNow")}
      class="p-2 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-accent)] transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <IconRefresh class={`w-4 h-4 ${syncing() ? "animate-spin" : ""}`} />
    </button>
  );
}
