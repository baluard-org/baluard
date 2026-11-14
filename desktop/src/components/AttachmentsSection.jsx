import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError } from "../context/toastSignal.js";
import { IconSpinner } from "./Icon.jsx";

// Attachment storage lives off the vault's main history (an append-only
// git line), so deleting an entry does not shrink the repository until
// this compaction runs. The daemon refuses when any entry is unreadable
// locally (shared vaults: owner/admin action) or when an upload is still
// in flight, so the button is always safe to press — failures come back
// as mapped, actionable toasts.
function formatBytes(n) {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export default function AttachmentsSection() {
  const { t } = useI18n();
  const [busy, setBusy] = createSignal(false);
  const [report, setReport] = createSignal(null);

  async function runCompact() {
    if (busy()) return;
    setBusy(true);
    try {
      const raw = await daemon("vault.attach_compact");
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = null;
      }
      setReport(parsed ?? { reclaimed: 0, reclaimed_bytes: 0, kept: 0 });
    } catch (e) {
      toastError(sanitizeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="space-y-3 mb-6" data-testid="attachments-section">
      <div class="flex items-center justify-between">
        <div class="flex flex-col flex-1 pr-4">
          <span class="text-xs font-bold text-[var(--color-text)]">
            {t("sync.attachTitle")}
          </span>
          <span class="text-[10px] text-[var(--color-muted)] mt-0.5">
            {t("sync.attachDesc")}
          </span>
        </div>
        <button
          data-testid="attach-compact-btn"
          onClick={runCompact}
          disabled={busy()}
          class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
        >
          <Show when={busy()}>
            <IconSpinner class="w-3.5 h-3.5 inline mr-1.5 -mt-0.5" />
          </Show>
          {busy() ? t("common.pleaseWait") : t("sync.attachCompact")}
        </button>
      </div>
      <Show when={report()}>
        <span
          data-testid="attach-result"
          class="text-[10px] text-[var(--color-muted)]"
        >
          {t("sync.attachResult", {
            reclaimed: report().reclaimed ?? 0,
            bytes: formatBytes(report().reclaimed_bytes ?? 0),
            kept: report().kept ?? 0,
          })}
        </span>
      </Show>
    </div>
  );
}
