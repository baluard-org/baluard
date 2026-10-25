// G24 §4.7 v2: banner for a pending browser unlock request. The extension
// asked for a locked vault to be unlocked so its entries can fill. The
// desktop's approval IS the unlock: the button hands the row to the caller
// (which routes to that vault's unlock screen) and consumes the request.
// Dismiss consumes it too — the extension can ask again.

import { Show } from "solid-js";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { useI18n } from "../i18n/index.jsx";

function BridgeUnlockBanner(props) {
  const switcher = useVaultSwitcher();
  const { t } = useI18n();
  const req = () => switcher.unlockRequest();

  async function act() {
    const row = await switcher.takeUnlockRequest();
    if (row && props.onUnlock) props.onUnlock(row);
  }

  async function dismiss() {
    await switcher.takeUnlockRequest();
  }

  return (
    <Show when={req()}>
      <div
        data-testid="bridge-unlock-banner"
        class="mx-4 mt-3 flex items-center justify-between gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2"
      >
        <p class="text-xs text-[var(--color-text)] truncate">
          {t("bridgeUnlock.unlockRequested", { name: req().display_name })}
        </p>
        <div class="flex items-center gap-2 shrink-0">
          <button
            class="text-xs font-medium text-[var(--color-primary)] hover:underline"
            onClick={act}
          >
            {t("bridgeUnlock.unlockNow")}
          </button>
          <button
            class="text-xs text-[var(--color-text-secondary)] hover:underline"
            onClick={dismiss}
          >
            {t("bridgeUnlock.dismiss")}
          </button>
        </div>
      </div>
    </Show>
  );
}

export default BridgeUnlockBanner;
