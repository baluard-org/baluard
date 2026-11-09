import { createSignal, Show, onSettled, onCleanup } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastWarning } from "../context/toastSignal.js";
import { useVault } from "../context/VaultContext.jsx";
import { IconSpinner } from "./Icon.jsx";

// Batch site-icon backfill for imported entries: entries saved through the
// editor fetch their favicon at save time, imported ones never do. This
// section starts the daemon-side job (one entry at a time, 2s per-entry
// budget, slow sites skipped), polls its progress, and can cancel it. The
// job outlives this component: reopening the tab re-reads daemon status and
// a run that finished while closed shows its counts without re-toasting.
export default function IconBackfillSection() {
  const { t } = useI18n();
  const vault = useVault();
  const [iconsState, setIconsState] = createSignal(null);
  const [iconsBusy, setIconsBusy] = createSignal(false);
  const [faviconsEnabled, setFaviconsEnabled] = createSignal(null); // null = unknown
  let iconsPollTimer = null;
  // The deferred daemon reads and the poll interval must not outlive the
  // component: a poll tick that lands after unmount would otherwise start
  // a fresh interval nothing will ever clean up.
  let disposed = false;

  function stopIconsPolling() {
    if (iconsPollTimer) {
      clearInterval(iconsPollTimer);
      iconsPollTimer = null;
    }
  }

  onCleanup(() => {
    disposed = true;
    stopIconsPolling();
  });

  async function refreshIconStatus() {
    try {
      const s = JSON.parse(await daemon("favicon.backfill_status"));
      setIconsState(s);
      if (s.running) startIconsPolling();
    } catch {
      // Vault may be locked; leave the section inert.
    }
  }

  function startIconsPolling() {
    if (disposed || iconsPollTimer) return;
    iconsPollTimer = setInterval(async () => {
      if (disposed) return;
      try {
        const s = JSON.parse(await daemon("favicon.backfill_status"));
        setIconsState(s);
        if (!s.running) {
          stopIconsPolling();
          onIconsFinished(s);
        }
      } catch {
        stopIconsPolling();
      }
    }, 500);
  }

  async function onIconsFinished(s) {
    // The vault list itself must re-read: the job wrote through the
    // daemon, so no local signal knows the icons changed.
    await vault.refreshCiphers(t);
    window.dispatchEvent(new CustomEvent("baluard:local-mutation"));
    if (s.error) {
      // The user asked to cancel: returning to idle IS the feedback.
      if (s.error === "Cancelled.") return;
      toastWarning(sanitizeError(s.error, t));
      return;
    }
    if (s.total === 0) {
      toastSuccess(t("sync.iconsUpToDate"));
    } else {
      toastSuccess(t("sync.iconsDone", { fetched: s.fetched, skipped: s.skipped }));
    }
  }

  async function startIcons() {
    setIconsBusy(true);
    try {
      const s = JSON.parse(await daemon("favicon.backfill_start"));
      setIconsState(s);
      if (s.running) {
        startIconsPolling();
      } else {
        onIconsFinished(s);
      }
    } catch (e) {
      toastWarning(sanitizeError(e, t));
    } finally {
      setIconsBusy(false);
    }
  }

  async function cancelIcons() {
    try {
      await daemon("favicon.backfill_cancel");
    } catch {
      // Status polling reflects the cancel; nothing else to do.
    }
  }

  onSettled(() => {
    // The daemon calls must not run (and their state updates render)
    // under the onSettled owner: Solid forbids cleanup registration in
    // that scope, and the spinner uses it. Macrotask defer sheds it.
    setTimeout(() => {
      if (disposed) return;
      daemon("settings.get")
        .then((d) => setFaviconsEnabled(d.fetch_favicons === true))
        .catch(() => setFaviconsEnabled(null));
      refreshIconStatus();
    }, 0);
  });

  return (
    <div class="border-t border-[var(--color-border)] pt-3 space-y-2">
      <h5 class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wider">
        {t("sync.iconsTitle")}
      </h5>
      <p class="text-[10px] text-[var(--color-muted)] leading-relaxed">{t("sync.iconsDesc")}</p>
      <Show
        when={faviconsEnabled()}
        fallback={<p class="text-[10px] text-yellow-400/90">{t("errors.backfillDisabled")}</p>}
      >
        <Show when={!iconsState()?.running && iconsState()?.finished && (iconsState()?.total ?? 0) > 0}>
          <p class="text-[10px] text-[var(--color-muted)]">
            {t("sync.iconsDone", { fetched: iconsState()?.fetched ?? 0, skipped: iconsState()?.skipped ?? 0 })}
          </p>
        </Show>
        <Show
          when={iconsState()?.running}
          fallback={
            <button
              onClick={startIcons}
              disabled={iconsBusy()}
              class="w-full py-2.5 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Show when={iconsBusy()}>
                <IconSpinner class="w-3.5 h-3.5 text-[var(--color-muted)]" />
              </Show>
              {t("sync.iconsStart")}
            </button>
          }
        >
          <div class="p-3 rounded-xl bg-[var(--color-sidebar)]/60 border border-[var(--color-border)] space-y-2">
            <div class="flex items-center justify-between text-[10px]">
              <span class="flex items-center gap-1.5 text-[var(--color-text)] font-bold">
                <IconSpinner class="w-3.5 h-3.5 text-[var(--color-primary)]" />
                {t("sync.iconsRunning", {
                  done: iconsState()?.done ?? 0,
                  total: iconsState()?.total ?? 0,
                })}
              </span>
              <button
                onClick={cancelIcons}
                class="text-[10px] text-[var(--color-muted)] hover:text-red-400 cursor-pointer font-bold"
              >
                {t("sync.iconsCancel")}
              </button>
            </div>
            <Show when={iconsState()?.current_domain}>
              <p class="text-[10px] text-[var(--color-muted)] font-mono truncate">
                {iconsState().current_domain}
              </p>
            </Show>
          </div>
        </Show>
      </Show>
    </div>
  );
}
