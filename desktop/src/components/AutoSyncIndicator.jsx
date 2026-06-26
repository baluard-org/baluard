import { Show, createMemo, createSignal, createEffect, onCleanup } from "solid-js";
import { Transition } from "solid-transition-group";
import { useAutoSync } from "../context/AutoSyncContext.jsx";
import { useI18n } from "../i18n/index.jsx";

// Subtle top-right sync indicator. Sits in the macOS titlebar drag padding
// band (top-right corner, free of the traffic lights). Pure glance: no border,
// pointer-events-none so window dragging passes straight through.
//
// Two parts:
//   • dot — always present while auto-sync is active. Glanceable health.
//   • label — transient text to the LEFT of the dot, sliding in right-to-left.
//
// Label visibility:
//   • dirty  (post-CRUD, debounced)  -> "Waiting..." shown
//   • syncing                        -> "Syncing..." shown
//   • idle   (after real sync only)  -> "Synced" shown for 10s, then fades
//   • offline                        -> shown persistently
// "Synced" only appears when arriving from dirty/syncing, not on every unlock,
// so the top-right stays empty at rest. Detailed controls live in the Sync tab.
export default function AutoSyncIndicator() {
  const autosync = useAutoSync();
  const { t } = useI18n();
  const [showLabel, setShowLabel] = createSignal(false);

  const cfg = createMemo(() => {
    switch (autosync.state()) {
      case "syncing":
        return { dot: "bg-[var(--color-primary)]", halo: "bg-[var(--color-primary)]", label: t("autosync.syncing"), pulse: true };
      case "dirty":
        return { dot: "bg-amber-400", halo: "bg-amber-400", label: t("autosync.pending", { count: autosync.pending() }), pulse: false };
      case "offline":
        return { dot: "bg-[var(--color-muted)]", halo: "bg-[var(--color-muted)]", label: t("autosync.offline"), pulse: false };
      case "idle":
        return { dot: "bg-emerald-400", halo: "bg-emerald-400", label: t("autosync.upToDate"), pulse: false };
      default:
        return null;
    }
  });

  // Drive label visibility from state transitions.
  let idleTimer = null;
  let prev = null;
  createEffect(() => {
    const state = autosync.state();
    if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
    if (state === "idle") {
      // Only announce "synced" after real sync activity (dirty/syncing -> idle).
      if (prev === "dirty" || prev === "syncing") {
        setShowLabel(true);
        idleTimer = setTimeout(() => setShowLabel(false), 10000);
      } else {
        setShowLabel(false);
      }
    } else if (state === "dirty" || state === "syncing" || state === "offline") {
      setShowLabel(true);
    }
    prev = state;
  });

  onCleanup(() => { if (idleTimer) clearTimeout(idleTimer); });

  return (
    <Show when={autosync.active() && cfg()}>
      {(c) => (
        <div
          title={c().label}
          class="absolute top-2 right-3 z-[60] pointer-events-none select-none flex items-center justify-end gap-1.5 h-5"
        >
          <Transition name="sync-status" when={showLabel()}>
            <span class="text-[11px] font-medium text-[var(--color-muted)] whitespace-nowrap">
              {c().label}
            </span>
          </Transition>
          <span class="relative flex h-2 w-2">
            {/* soft expanding halo (visible only while syncing) */}
            <Show when={c().pulse}>
              <span class={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 ${c().halo}`} />
            </Show>
            <span class={`relative inline-flex rounded-full h-2 w-2 ${c().dot}`} />
          </span>
        </div>
      )}
    </Show>
  );
}
