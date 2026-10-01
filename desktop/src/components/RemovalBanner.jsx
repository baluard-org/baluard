import { Show, createSignal } from "solid-js";
import { useAutoSync } from "../context/AutoSyncContext.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { daemon } from "../lib/daemon.js";
import { IconAlert, IconX } from "./Icon.jsx";

// Non-blocking banner fired when THIS device looks removed from the
// Space it is viewing: either the removal commit reached the local
// clone (confirmed) or sync keeps failing with access errors
// (probable). Honest hygiene, not enforcement — the daemon is the
// validator, and the files are never deleted without the user's
// explicit choice (real deletion stays CLI-only per the recorded
// Vault Detach decision, so the app prints the command instead).
export default function RemovalBanner() {
  const autosync = useAutoSync();
  const switcher = useVaultSwitcher();
  const auth = useAuth();
  const { t } = useI18n();
  const [busy, setBusy] = createSignal(false);

  const detach = async () => {
    const slug = switcher.activeSlug();
    if (!slug || busy()) return;
    setBusy(true);
    try {
      // Lock FIRST, while the vault is still active: detaching closes the
      // vault and unsets the active pointer, so a lock after detach fails
      // with no-active-vault and strands the UI (review F3). Locking also
      // deactivates the autosync loop before the registry entry goes.
      await auth.lock();
      await daemon("vaults.detach", { slug });
      toastSuccess(t("removal.detachedToast"));
    } catch (e) {
      toastError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show when={autosync.removalNotice()}>
      {(notice) => (
        <div
          role="alert"
          class="flex items-start gap-3 px-4 py-2.5 mx-4 mt-2 rounded-xl bg-amber-950/30 border border-amber-900/40 text-amber-200 text-xs"
        >
          <IconAlert class="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
          <div class="flex-1 leading-snug">
            <p>
              {notice().status === "removed"
                ? notice().reason === "local-reset"
                  ? t("removal.bodyReset")
                  : t("removal.bodyConfirmed")
                : t("removal.bodyProbable")}
            </p>
            <p class="mt-1 text-[var(--color-muted)]">
              {t("removal.cliHint", { slug: switcher.activeSlug() ?? "" })}
            </p>
            <button
              onClick={detach}
              disabled={busy()}
              class="mt-1.5 px-2.5 py-1 rounded-lg bg-amber-900/40 hover:bg-amber-900/60 text-amber-100 font-bold transition-colors cursor-pointer disabled:opacity-50"
            >
              {t("removal.detachAction")}
            </button>
          </div>
          <button
            onClick={() => autosync.dismissRemoval()}
            title={t("common.dismiss")}
            class="p-1 rounded-md hover:bg-amber-900/30 text-amber-300 hover:text-amber-100 transition-colors cursor-pointer shrink-0"
          >
            <IconX class="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </Show>
  );
}
