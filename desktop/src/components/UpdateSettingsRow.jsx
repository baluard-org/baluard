// Updates row for Settings > General (D79). Self-contained so suites that
// mount SettingsModal without the UpdateProvider simply render nothing.

import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useUpdater } from "../context/UpdateContext.jsx";
import { toastSuccess } from "../context/toastSignal.js";
import {
  autoChecksEnabled,
  setAutoChecksEnabled,
} from "../lib/update.js";

export default function UpdateSettingsRow() {
  const { t } = useI18n();
  const u = useUpdater();
  if (!u) return null;

  const [auto, setAuto] = createSignal(autoChecksEnabled());

  async function checkNow() {
    await u.check({ manual: true });
    if (u.available()) {
      // The banner takes over from here.
      return;
    }
    if (!u.error()) {
      toastSuccess(t("update.upToDate"));
    }
  }

  function toggleAuto() {
    const next = !auto();
    setAutoChecksEnabled(next);
    setAuto(next);
  }

  return (
    <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
      <div class="flex items-center justify-between">
        <div class="flex flex-col flex-1 pr-4">
          <span class="text-xs font-bold text-[var(--color-text)]">{t("update.settingsTitle")}</span>
          <Show
            when={u.status()?.configured}
            fallback={<span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("update.managed")}</span>}
          >
            <span class="text-[10px] text-[var(--color-muted)] mt-0.5">
              {t("update.settingsDesc", { channel: u.status()?.channel ?? "" })}
            </span>
          </Show>
        </div>
        <Show when={u.status()?.configured}>
          <button
            data-testid="update-check-now"
            onClick={checkNow}
            disabled={u.checking()}
            class="px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer disabled:opacity-50 bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"
          >
            {u.checking() ? t("update.checking") : t("update.checkNow")}
          </button>
        </Show>
      </div>
      <Show when={u.status()?.configured}>
        <div class="flex items-center justify-between">
          <span class="text-[10px] text-[var(--color-muted)] flex-1 pr-4">{t("update.autoChecks")}</span>
          <button
            data-testid="update-auto-toggle"
            onClick={toggleAuto}
            class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${auto() ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
          >
            {auto() ? t("settings.enabled") : t("settings.disabled")}
          </button>
        </div>
      </Show>
    </div>
  );
}
