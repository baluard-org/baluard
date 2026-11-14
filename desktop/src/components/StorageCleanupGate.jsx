import { createSignal, onSettled, onCleanup, createEffect, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { useVault } from "../context/VaultContext.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { IconSpinner } from "./Icon.jsx";

// When another device compacts the shared attachments line, this
// device must not push again until the user has accepted the cleanup:
// the push would republish the stale local copies and undo it for
// everyone. So a rewrite is blocking: a near-full-screen alert on
// detection, collapsing to a persistent bar if the user chooses to
// keep reading. Reads and autofill keep working; the daemon refuses
// writes while this is pending. Non-dismissable: there is no close
// affordance, only the two actions.
function formatBytes(n) {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export default function StorageCleanupGate() {
  const { t } = useI18n();
  const vault = useVault();
  const switcher = useVaultSwitcher();
  const [pending, setPending] = createSignal(false);
  const [notice, setNotice] = createSignal(null);
  const [overlayOpen, setOverlayOpen] = createSignal(true);
  const [busy, setBusy] = createSignal(false);
  let disposed = false;
  onCleanup(() => {
    disposed = true;
  });

  async function check() {
    try {
      const raw = await daemon("vault.attach_status");
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = null;
      }
      if (disposed) return;
      const needs = !!(parsed && parsed.tip && parsed.rewritten && !parsed.foreign);
      setPending(needs);
      setNotice(needs ? parsed : null);
    } catch {
      // Status is advisory: a failure (offline, no remote) shows nothing.
    }
  }

  onSettled(() => {
    void (async () => {
      await check();
    })();
  });
  // Re-check when the active vault changes: the gate guards whatever
  // vault is open, and the daemon classifies the active one.
  createEffect(
    () => switcher.activeSlug(),
    () => {
      void (async () => {
        await check();
      })();
    },
  );

  async function resolve() {
    if (busy()) return;
    setBusy(true);
    try {
      const raw = await daemon("vault.attach_resolve");
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = null;
      }
      if (disposed) return;
      // The pull may have brought remote changes; refresh before the
      // user sees the vault again.
      await vault.refreshCiphers(t);
      window.dispatchEvent(new CustomEvent("baluard:local-mutation"));
      const count = parsed?.discarded ?? 0;
      toastSuccess(
        count > 0
          ? t("sync.cleanupDone", { count })
          : t("sync.cleanupDoneNone"),
      );
      setPending(false);
      setNotice(null);
      setOverlayOpen(true);
    } catch (e) {
      toastError(sanitizeError(e));
    } finally {
      setBusy(false);
    }
  }

  const n = () => notice();
  const detail = () => {
    const c = n();
    if (!c) return null;
    if (c.compaction)
      return t("sync.attachCleanedDetails", {
        device: c.compaction.device_id.slice(0, 8),
        count: c.compaction.reclaimed,
        size: formatBytes(c.compaction.reclaimed_bytes),
      });
    if (c.rewrite_signed === true) return t("sync.attachCleanedVerifiedHint");
    return t("sync.attachCleanedHint");
  };
  return (
    <>
      <Show when={pending() && overlayOpen()}>
        <div
          class="fixed inset-0 z-[100] bg-black/70 flex items-center justify-center p-6"
          data-testid="cleanup-gate"
        >
          <div class="bg-[var(--color-bg)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto p-8 space-y-4">
            <h2 class="text-lg font-bold text-[var(--color-text)]">
              {t("sync.cleanupTitle")}
            </h2>
            <p class="text-sm text-[var(--color-muted)]">{t("sync.cleanupBody")}</p>
            <Show when={detail()}>
              <p class="text-xs text-[var(--color-muted)]" data-testid="cleanup-detail">
                {detail()}
              </p>
            </Show>
            <details class="text-xs text-[var(--color-muted)]">
              <summary class="cursor-pointer font-bold">
                {t("sync.cleanupAdvanced")}
              </summary>
              <p class="mt-2 leading-relaxed">{t("sync.cleanupAdvancedBody")}</p>
            </details>
            <div class="flex items-center justify-end gap-3 pt-2">
              <button
                data-testid="cleanup-keep-reading"
                onClick={() => setOverlayOpen(false)}
                class="px-4 py-2 rounded-xl text-xs font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
              >
                {t("sync.cleanupKeepReading")}
              </button>
              <button
                data-testid="cleanup-resolve"
                onClick={resolve}
                disabled={busy()}
                class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Show when={busy()}>
                  <IconSpinner class="w-3.5 h-3.5 inline mr-1.5 -mt-0.5" />
                </Show>
                {busy() ? t("sync.cleanupBusy") : t("sync.cleanupAction")}
              </button>
            </div>
          </div>
        </div>
      </Show>
      <Show when={pending() && !overlayOpen()}>
        <div
          data-testid="cleanup-bar"
          class="fixed top-0 left-0 right-0 z-[90] bg-[var(--color-sidebar)] border-b border-[var(--color-border)] px-4 py-2 flex items-center justify-between gap-3"
        >
          <span class="text-xs font-bold text-[var(--color-text)]">
            {t("sync.cleanupBar")}
          </span>
          <button
            data-testid="cleanup-bar-resolve"
            onClick={resolve}
            disabled={busy()}
            class="px-4 py-1.5 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-[10px] font-bold transition-all cursor-pointer disabled:opacity-40 shrink-0"
          >
            {busy() ? t("sync.cleanupBusy") : t("sync.cleanupAction")}
          </button>
        </div>
      </Show>
    </>
  );
}
