import { createSignal, onSettled, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import ConfirmModal from "./ConfirmModal.jsx";
import { Button } from "./Primitives.jsx";
import { IconAlert } from "./Icon.jsx";

/**
 * Owner-side Legacy Contact banner: when the silence window has
 * elapsed and the kit holder can reach the vault copy, the owner sees
 * a one-tap refusal on every unlock and window focus. Polling rides
 * the same triggers the desktop already refreshes on.
 */
export default function LegacyBanner() {
  const { t } = useI18n();
  const [open, setOpen] = createSignal(false);
  const [confirming, setConfirming] = createSignal(false);
  const [dismissed, setDismissed] = createSignal(false);
  let alive = true;

  async function check() {
    try {
      const res = JSON.parse(await daemon("legacy.status", {}));
      if (alive) setOpen(res?.phase === "open");
    } catch {
      // Locked vaults and not-set-up vaults are both quiet here.
      if (alive) setOpen(false);
    }
  }

  function deny() {
    setConfirming(true);
  }

  async function confirmDeny() {
    try {
      await daemon("legacy.close", { reason: "denied" });
      setOpen(false);
      toastSuccess(t("legacy.closedToast"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setConfirming(false);
    }
  }

  onSettled(() => {
    void check();
    window.addEventListener("focus", check);
    return () => {
      alive = false;
      window.removeEventListener("focus", check);
    };
  });

  return (
    <>
      <Show when={open() && !dismissed()}>
        <div
          role="alert"
          class="flex items-center gap-3 px-4 py-2.5 mx-4 mt-2 rounded-xl bg-amber-950/30 border border-amber-900/40 text-amber-200 text-xs"
          data-testid="legacy-banner"
        >
          <IconAlert class="w-4 h-4 shrink-0 text-amber-400" />
          <span class="flex-1 leading-snug">{t("legacy.bannerOpen")}</span>
          <Button variant="danger" onClick={deny} data-testid="legacy-banner-deny" class="!py-1 !px-2.5 text-xs">
            {t("legacy.deny")}
          </Button>
          <button
            onClick={() => setDismissed(true)}
            title={t("common.dismiss")}
            class="p-1 rounded-md hover:bg-amber-900/30 text-amber-300 hover:text-amber-100 transition-colors cursor-pointer shrink-0"
          >
            ✕
          </button>
        </div>
      </Show>
      <ConfirmModal
        show={confirming()}
        idPrefix="legacy-banner-confirm"
        title={t("legacy.denyTitle")}
        body={t("legacy.denyBody")}
        confirmLabel={t("legacy.deny")}
        confirmClass="bg-[var(--color-danger)] text-white"
        onConfirm={confirmDeny}
        onClose={() => setConfirming(false)}
      />
    </>
  );
}
