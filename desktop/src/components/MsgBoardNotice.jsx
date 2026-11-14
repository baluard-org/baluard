import { createSignal, onSettled, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError } from "../context/toastSignal.js";

// The advisory message board (refs/notes/baluard-msgs) is shared with
// every synced device, so another device can compact (rewrite) it under
// this one. The daemon classifies the freshly fetched tip against the
// tip this device last accepted; the notice exists so a rewrite is
// never silent, and Accept records that the user was told. Messages are
// advisory and re-derivable, so switching over is automatic and safe —
// there is nothing to opt into beyond being told.
export default function MsgBoardNotice() {
  const { t } = useI18n();
  const [notice, setNotice] = createSignal(null);
  const [ackBusy, setAckBusy] = createSignal(false);

  async function refreshStatus() {
    try {
      const raw = await daemon("vault.msg_status");
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
      await daemon("vault.msg_ack", { tip: notice().tip });
      setNotice(null);
    } catch (e) {
      toastError(sanitizeError(e));
    } finally {
      setAckBusy(false);
    }
  }

  onSettled(() => {
    void (async () => {
      await refreshStatus();
    })();
  });

  return (
    <Show when={notice()}>
      <div
        data-testid="msg-notice"
        class="rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)] px-3.5 py-3 space-y-2 mb-6"
      >
        <span class="block text-[11px] font-bold text-[var(--color-text)]">
          {notice().foreign ? t("sync.msgForeign") : t("sync.msgCleaned")}
        </span>
        <span class="block text-[10px] text-[var(--color-muted)]">
          {notice().foreign
            ? t("sync.msgForeignHint")
            : notice().compaction
              ? t("sync.msgCleanedDetails", {
                  device: notice().compaction.device_id.slice(0, 8),
                  count: notice().compaction.compacted_entries,
                })
              : notice().rewrite_signed === true
                ? t("sync.msgCleanedVerifiedHint")
                : t("sync.msgCleanedHint")}
        </span>
        <Show when={!notice().foreign}>
          <button
            data-testid="msg-accept-btn"
            onClick={acceptNotice}
            disabled={ackBusy()}
            class="px-4 py-1.5 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-[10px] font-bold transition-all cursor-pointer disabled:opacity-40"
          >
            {ackBusy() ? t("common.pleaseWait") : t("sync.msgAccept")}
          </button>
        </Show>
      </div>
    </Show>
  );
}
