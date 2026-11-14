import { createSignal, onSettled, Show } from "solid-js";
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
  const [notice, setNotice] = createSignal(null);
  const [ackBusy, setAckBusy] = createSignal(false);

  // The line is shared with every synced device, so another device can
  // compact (rewrite) it under this one. The daemon classifies the
  // freshly fetched tip against the tip this device last accepted;
  // switching over is automatic and safe (files, pins, and downloads all
  // keep working) — the notice exists so a cleanup that deleted history
  // is never silent, and Accept records that the user was told.
  async function refreshStatus() {
    try {
      const raw = await daemon("vault.attach_status");
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = null;
      }
      if (parsed && parsed.tip && (parsed.rewritten || parsed.foreign)) {
        setNotice(parsed);
      } else {
        setNotice(null);
      }
    } catch {
      // Status is advisory: a failure (offline, no remote) shows nothing.
    }
  }

  async function acceptNotice() {
    if (ackBusy() || !notice()) return;
    setAckBusy(true);
    try {
      await daemon("vault.attach_ack", { tip: notice().tip });
      setNotice(null);
    } catch (e) {
      toastError(sanitizeError(e));
    } finally {
      setAckBusy(false);
    }
  }

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

  onSettled(() => {
    void (async () => {
      await refreshStatus();
    })();
  });

  return (
    <div class="space-y-3 mb-6" data-testid="attachments-section">
      <Show when={notice()}>
        <div
          data-testid="attach-notice"
          class="rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)] px-3.5 py-3 space-y-2"
        >
          <span class="block text-[11px] font-bold text-[var(--color-text)]">
            {notice().foreign
              ? t("sync.attachForeign")
              : t("sync.attachCleaned")}
          </span>
          <span class="block text-[10px] text-[var(--color-muted)]">
            {notice().foreign
              ? t("sync.attachForeignHint")
              : notice().compaction
                ? t("sync.attachCleanedDetails", {
                    device: notice().compaction.device_id.slice(0, 8),
                    count: notice().compaction.reclaimed,
                    size: formatBytes(notice().compaction.reclaimed_bytes),
                  })
                : notice().rewrite_signed === true
                  ? t("sync.attachCleanedVerifiedHint")
                  : t("sync.attachCleanedHint")}
          </span>
          <Show when={!notice().foreign}>
            <button
              data-testid="attach-accept-btn"
              onClick={acceptNotice}
              disabled={ackBusy()}
              class="px-4 py-1.5 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-[10px] font-bold transition-all cursor-pointer disabled:opacity-40"
            >
              {ackBusy() ? t("common.pleaseWait") : t("sync.attachAccept")}
            </button>
          </Show>
        </div>
      </Show>
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
