import { Show, Switch, Match } from "solid-js";
import { useAutoSync } from "../context/AutoSyncContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { IconRefresh, IconCheck, IconAlert, IconSpinner } from "./Icon.jsx";

// Compact auto-sync status pill for the sidebar header.
//
// Shows nothing when auto-sync isn't active (no remote connected). Otherwise
// reflects the daemon coordinator state: syncing (spinner), dirty (pending),
// offline (alert), or idle (check). The detailed Sync tab remains the home for
// manual push/pull and conflict review; this is just a glanceable indicator.
export default function AutoSyncIndicator() {
  const autosync = useAutoSync();
  const { t } = useI18n();

  return (
    <Show when={autosync.active()}>
      <Switch>
        <Match when={autosync.state() === "syncing"}>
          <span
            title={t("autosync.syncing")}
            class="flex items-center justify-center w-7 h-7 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] text-[var(--color-primary)]"
          >
            <IconSpinner class="w-3.5 h-3.5" />
          </span>
        </Match>
        <Match when={autosync.state() === "dirty"}>
          <span
            title={t("autosync.pending", { count: autosync.pending() })}
            class="flex items-center justify-center w-7 h-7 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] text-yellow-400"
          >
            <IconRefresh class="w-3.5 h-3.5" />
          </span>
        </Match>
        <Match when={autosync.state() === "offline"}>
          <span
            title={t("autosync.offline")}
            class="flex items-center justify-center w-7 h-7 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] text-[var(--color-muted)]"
          >
            <IconAlert class="w-3.5 h-3.5" />
          </span>
        </Match>
        <Match when={autosync.state() === "idle"}>
          <span
            title={t("autosync.upToDate")}
            class="flex items-center justify-center w-7 h-7 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] text-green-400"
          >
            <IconCheck class="w-3.5 h-3.5" />
          </span>
        </Match>
      </Switch>
    </Show>
  );
}
