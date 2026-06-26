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
// Label visibility (gated on observed user activity, not background sync):
//   • dirty  (post-CRUD, debounced)  -> "Waiting..." shown
//   • syncing (user-armed only)       -> "Syncing..." shown
//   • idle   (after armed sync)       -> "Synced" shown for 10s, then fades
//   • offline                         -> shown persistently
// Background sync the daemon does on its own (initial pull at unlock, periodic
// pull) stays silent, so the top-right is empty at rest. Detailed controls in
// the Sync tab.
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
  //
  // The label is GATED on observed user activity: only a CRUD (-> dirty)
  // arms it. Background sync the daemon does on its own (initial pull at
  // unlock, periodic pull every 3 min) stays silent, so the top-right is empty
  // until you actually edit something. Offline is always shown.
  let hideTimer = null;
  let sawUserChange = false;
  const clearHide = () => { if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; } };

  createEffect(() => {
    const state = autosync.state();

    // Reset the gate when the vault locks (active drops) so a re-unlock's
    // background pull doesn't inherit a prior session's sawUserChange flag.
    if (!autosync.active()) {
      sawUserChange = false;
      clearHide();
      setShowLabel(false);
      return;
    }

    if (state === "offline") {
      clearHide();
      setShowLabel(true);
      return;
    }
    if (state === "dirty") {
      // User made a change (CRUD entered the debounce window). Arm + show.
      sawUserChange = true;
      clearHide();
      setShowLabel(true);
      return;
    }
    if (state === "syncing") {
      // Only noisy if the user actually changed something. A background
      // periodic pull (sawUserChange false) stays silent.
      if (sawUserChange) setShowLabel(true);
      return;
    }
    if (state === "idle") {
      if (sawUserChange) {
        // Real sync just finished -> announce "Synced", then auto-hide.
        sawUserChange = false;
        setShowLabel(true);
        clearHide();
        hideTimer = setTimeout(() => setShowLabel(false), 10_000);
      }
      // else: background idle, leave state as-is.
    }
  });

  onCleanup(clearHide);

  return (
    <Show when={autosync.active() && cfg()}>
      {(c) => (
        <div
          title={c().label}
          class="absolute top-2 right-3 z-[60] pointer-events-none select-none flex items-center justify-end gap-1.5 h-5"
        >
          {/* solid-transition-group's <Transition> has no `when` prop — it animates
              the enter/leave of control-flow children (here, the inner <Show>).
              Do NOT put `when` on <Transition>; it is silently ignored and the
              label would always render. */}
          <Transition name="sync-status">
            <Show when={showLabel()}>
              <span class="text-[11px] font-medium text-[var(--color-muted)] whitespace-nowrap">
                {c().label}
              </span>
            </Show>
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
