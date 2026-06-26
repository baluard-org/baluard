import { Show } from "solid-js";
import { useAutoSync } from "../context/AutoSyncContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { IconAlert, IconX } from "./Icon.jsx";

// Non-blocking banner shown when the auto-sync coordinator resolved a true
// conflict (same item edited on two devices). We keep the newest version and
// surface this so the user knows to review it in the Sync tab. Plain language:
// no git jargon. Dismissable; re-arms on the next resolved conflict.
export default function ConflictBanner() {
  const autosync = useAutoSync();
  const { t } = useI18n();

  return (
    <Show when={autosync.active() && !autosync.bannerDismissed() && autosync.conflictsResolved() > 0}>
      <div
        role="status"
        class="flex items-center gap-3 px-4 py-2.5 mx-4 mt-2 rounded-xl bg-amber-950/30 border border-amber-900/40 text-amber-200 text-xs"
      >
        <IconAlert class="w-4 h-4 shrink-0 text-amber-400" />
        <span class="flex-1 leading-snug">
          {t("autosync.conflictResolved", { count: autosync.conflictsResolved() })}
        </span>
        <button
          onClick={() => autosync.dismissBanner()}
          title={t("common.dismiss")}
          class="p-1 rounded-md hover:bg-amber-900/30 text-amber-300 hover:text-amber-100 transition-colors cursor-pointer shrink-0"
        >
          <IconX class="w-3.5 h-3.5" />
        </button>
      </div>
    </Show>
  );
}
