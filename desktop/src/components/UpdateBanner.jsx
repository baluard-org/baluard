// Update banner (D79): the only surface that offers an install. Manual
// errors and progress live here too. Fixed to the top center so it reads as
// app-level, above auth screens and the vault alike.

import { Show, Switch, Match } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useUpdater } from "../context/UpdateContext.jsx";
import { formatProgress } from "../lib/update.js";

export default function UpdateBanner() {
  const { t } = useI18n();
  const u = useUpdater();
  if (!u) return null;

  const visible = () =>
    (u.available() && u.available().version !== u.dismissedVersion()) ||
    u.installing() ||
    u.error();

  const IconClose = (props) => (
    <svg viewBox="0 0 24 24" class={props.class} fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  );

  return (
    <Show when={visible()}>
      <div
        data-testid="update-banner"
        role="status"
        class="fixed top-3 left-1/2 -translate-x-1/2 z-[60] w-[min(560px,calc(100vw-2rem))] rounded-2xl border border-[var(--color-border)] bg-[var(--color-sidebar)] shadow-xl px-4 py-3"
      >
        <Switch>
          {/* Install in progress: progress bar, no dismiss — the app will
              restart into the new version on its own. */}
          <Match when={u.installing()}>
            <div class="flex items-center gap-3">
              <div class="flex-1 min-w-0">
                <div class="text-xs font-bold text-[var(--color-text)]">
                  {t("update.installing", { version: u.available()?.version ?? "" })}
                </div>
                <div class="mt-1.5 h-1.5 rounded-full bg-[var(--color-border)] overflow-hidden">
                  <div
                    class="h-full bg-[var(--color-primary)] transition-all"
                    style={{ width: `${formatProgress(u.progress()?.received, u.progress()?.total) ?? 0}%` }}
                  />
                </div>
              </div>
            </div>
          </Match>

          {/* Update available: version, notes, install + dismiss. */}
          <Match when={u.available() && u.available().version !== u.dismissedVersion()}>
            <div class="flex items-start gap-3">
              <div class="flex-1 min-w-0">
                <div class="text-xs font-bold text-[var(--color-text)]">
                  {t("update.availableTitle", { version: u.available().version })}
                </div>
                <Show when={u.available().notes}>
                  <p class="text-[10px] text-[var(--color-muted)] mt-0.5 whitespace-pre-line line-clamp-3">
                    {u.available().notes}
                  </p>
                </Show>
                <div class="mt-2 flex items-center gap-2">
                  <button
                    data-testid="update-install"
                    onClick={u.install}
                    class="px-3 py-1.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-[10px] font-bold transition-all cursor-pointer"
                  >
                    {t("update.installNow")}
                  </button>
                  <button
                    data-testid="update-dismiss"
                    onClick={u.dismiss}
                    aria-label={t("update.dismiss")}
                    title={t("update.dismiss")}
                    class="p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer"
                  >
                    <IconClose class="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          </Match>

          {/* Manual-check failure. Background checks never land here. */}
          <Match when={u.error()}>
            <div class="flex items-start gap-3">
              <div class="flex-1 min-w-0">
                <div class="text-xs font-bold text-[var(--color-text)]">{t("update.checkFailed")}</div>
                <p class="text-[10px] text-[var(--color-muted)] mt-0.5 break-words">{u.error()}</p>
              </div>
              <button
                data-testid="update-error-dismiss"
                aria-label={t("update.dismiss")}
                onClick={() => u.clearError()}
                class="p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer"
              >
                <IconClose class="w-3.5 h-3.5" />
              </button>
            </div>
          </Match>
        </Switch>
      </div>
    </Show>
  );
}
