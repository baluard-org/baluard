import { Show, createSignal, createEffect, onSettled, onCleanup } from "solid-js";
import { Transition } from "../lib/transition";
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
// Why a LOCAL phase signal (not the polled state):
// The daemon reports `dirty` for only the 5s push-debounce window, but the UI
// polls status every 10s — so the poll frequently misses `dirty` entirely and
// the label never showed. Instead we arm a local phase INSTANTLY from the
// `baluard:local-mutation` event dispatched by daemon.js on every successful
// CRUD. The polled state then reconciles the phase forward (syncing → synced).
//
// Phase flow (user activity):
//   waiting  — armed immediately on CRUD (before the daemon even debounces)
//   syncing  — polled state catches the push in flight
//   synced   — polled state returns to idle; shown for 10s, then fades out
//   offline  — polled state offline; shown persistently
// Background sync (initial unlock pull, periodic 30-min idle pulls) never arms the
// local phase, so the top-right stays empty at rest.
export default function AutoSyncIndicator() {
  const autosync = useAutoSync();
  const { t } = useI18n();

  // localPhase: null = nothing to show. Set by the mutation event and advanced
  // by the polled-state effect below.
  const [localPhase, setLocalPhase] = createSignal(null);
  // Whether the current cycle is user-armed (so idle → "synced" is announced).
  let armed = false;
  let hideTimer = null;
  const clearHide = () => { if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; } };

  const LABELS = {
    waiting: () => t("sync.statusChangesPending"),
    syncing: () => t("autosync.syncing"),
    synced: () => t("autosync.upToDate"),
    offline: () => t("autosync.offline"),
  };
  const DOT = {
    waiting: { dot: "bg-amber-400", halo: "bg-amber-400", pulse: false },
    syncing: { dot: "bg-[var(--color-primary)]", halo: "bg-[var(--color-primary)]", pulse: true },
    synced: { dot: "bg-emerald-400", halo: "bg-emerald-400", pulse: false },
    offline: { dot: "bg-[var(--color-muted)]", halo: "bg-[var(--color-muted)]", pulse: false },
  };

  function onMutation() {
    // A local CRUD succeeded -> immediately show "waiting", arm the cycle.
    armed = true;
    clearHide();
    setLocalPhase("waiting");
  }

  // Polled state reconciles the armed cycle forward. Non-armed background
  // activity (initial pull, periodic pull) is ignored.
  createEffect(
    () => [autosync.active(), autosync.state()],
    ([active, state]) => {
      // Vault locked / inactive: reset everything.
      if (!active) {
      armed = false;
      clearHide();
      setLocalPhase(null);
      return;
    }

    // Offline always wins, armed or not (user needs to know).
    if (state === "offline") {
      clearHide();
      setLocalPhase("offline");
      return;
    }

    if (!armed) return; // background dirty/syncing/idle: stay silent

    if (state === "syncing") {
      clearHide();
      setLocalPhase("syncing");
      return;
    }
    if (state === "idle") {
      // Armed cycle just completed -> announce "synced", then auto-hide.
      armed = false;
      setLocalPhase("synced");
      clearHide();
      hideTimer = setTimeout(() => setLocalPhase(null), 10_000);
      }
      // dirty while armed: keep showing "waiting" (already set on mutation).
    },
  );

  onSettled(() => window.addEventListener("baluard:local-mutation", onMutation));
  onCleanup(() => {
    window.removeEventListener("baluard:local-mutation", onMutation);
    clearHide();
  });

  const phase = () => localPhase();

  // Dot color: phase-driven while a cycle is active, else idle emerald.
  const dotClass = () => {
    const p = phase();
    if (p && DOT[p]) return DOT[p];
    return { dot: "bg-emerald-400", halo: "bg-emerald-400", pulse: false };
  };

  return (
    <Show when={autosync.active()}>
      <div
        title={phase() ? LABELS[phase()]() : t("autosync.upToDate")}
        class="absolute top-2 right-3 z-[60] pointer-events-none select-none flex items-center justify-end gap-1.5 h-5"
      >
        {/* solid-transition-group's <Transition> has no `when` prop — it animates
            the enter/leave of control-flow children (here, the inner <Show>). */}
        <Transition name="sync-status">
          <Show when={phase()}>
            <span class="text-[11px] font-medium text-[var(--color-muted)] whitespace-nowrap">
              {LABELS[phase()]()}
            </span>
          </Show>
        </Transition>
        <span class="relative flex h-2 w-2">
          {/* soft expanding halo (visible only while syncing) */}
          <Show when={dotClass().pulse}>
            <span class={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 ${dotClass().halo}`} />
          </Show>
          <span class={`relative inline-flex rounded-full h-2 w-2 ${dotClass().dot}`} />
        </span>
      </div>
    </Show>
  );
}
