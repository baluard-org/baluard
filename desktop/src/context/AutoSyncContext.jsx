import { createSignal, createContext, useContext, onSettled, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { fetchPendingConflict, toPendingConflict } from "../lib/conflictFlow.js";
import { useConflictResolution } from "./ConflictResolutionContext.jsx";
import { useVaultSwitcher } from "./VaultSwitcherContext.jsx";

// Auto-sync coordinator state, polled from the daemon every 10s.
//
// The daemon owns the real sync engine (debounced push after CRUD, periodic
// pull, offline retry). This context is a thin poller that drives the status
// indicator in the vault header and the conflict banner. See
// crates/baluard-daemon/src/autosync.rs for the authoritative logic.
//
// State values mirror the daemon's AutoSyncState enum:
//   idle    - connected, nothing pending
//   dirty   - local change in the debounce window
//   syncing - pull/merge/push in flight
//   offline - remote unreachable, retrying

const POLL_MS = 10_000;

const AutoSyncContext = createContext(null);

export function AutoSyncProvider(props) {
  // Phase 2b-4: when the daemon enters NeedsDecision, fetch the real conflict
  // and feed it to the panel's queue. Idempotent on cipherId so re-polls don't
  // duplicate. Lives here (not in ConflictResolutionContext) because the poll
  // cadence + NeedsDecision trigger belong to the sync coordinator.
  const conflicts = useConflictResolution();
  const [active, setActive] = createSignal(false);
  const [state, setState] = createSignal("idle");
  const [lastSync, setLastSync] = createSignal(null);
  const [pending, setPending] = createSignal(0);
  // Count of conflicts auto-resolved since mount. Drives the banner.
  const [conflictsResolved, setConflictsResolved] = createSignal(0);
  // Tracks whether the banner for the latest conflict batch was dismissed.
  const [bannerDismissed, setBannerDismissed] = createSignal(true);
  // Removal notice: null | {status: "removed"|"probable", reason}. The
  // device looks removed from this Space (local tombstone or a persistent
  // access-denied sync streak). Cleared on vault switch like conflicts.
  const [removalNotice, setRemovalNotice] = createSignal(null);

  let poll;
  let lastSeenConflicts = 0;
  let lastSeenActive = null;

  // M3 fix: the daemon's conflicts_resolved counter is per-VaultState (resets
  // to 0 on each vault). This context lives at App root and survives vault
  // switches, so without resetting, switching A(3 conflicts)->B would suppress
  // B's first 3 conflicts (0 > 3 is false) and flash A's stale count. Reset on
  // active-slug change.
  //
  // Phase 4: also clear the conflict-resolution queue. The daemon side drains
  // its pending_conflicts on deactivate (lock), but a vault SWITCH keeps both
  // vaults unlocked (keep-unlocked model) — the ConflictResolutionProvider
  // does NOT unmount, so without this clear a conflict surfaced for vault A
  // would persist in the queue while viewing vault B. The queue re-populates
  // from the real sync.conflict poll if B has its own pending conflict.
  const switcher = useVaultSwitcher();
  createEffect(
    () => switcher.activeSlug(),
    (slug) => {
      if (lastSeenActive !== null && slug !== lastSeenActive) {
        lastSeenConflicts = 0;
        setConflictsResolved(0);
        setBannerDismissed(true);
        conflicts.clear();
        setRemovalNotice(null);
      }
      lastSeenActive = slug;
    },
  );

  async function refresh() {
    try {
      // Phase 4 review fix: capture the active slug BEFORE the awaits so we can
      // detect a vault switch that happened while the poll was in flight. A
      // conflict enqueued for vault A must NOT land in the queue after the user
      // switched to vault B — the createEffect on activeSlug already clears the
      // queue on switch, but a stale poll resuming after the clear would
      // re-introduce A's conflict into B's view.
      const targetSlug = switcher.activeSlug();
      const raw = await daemon("sync.autosync_status");
      const s = JSON.parse(raw);
      setActive(s.active);
      setState(s.state);
      setLastSync(s.last_sync ?? null);
      setPending(s.pending ?? 0);

      // A new conflict was auto-resolved since last poll → fire the banner.
      if ((s.conflicts_resolved ?? 0) > lastSeenConflicts) {
        setConflictsResolved(s.conflicts_resolved);
        setBannerDismissed(false);
      }
      lastSeenConflicts = s.conflicts_resolved ?? 0;

      // Phase 2b-4: NeedsDecision → fetch the real conflict and feed the panel.
      // If the daemon auto-merged, fetchPendingConflict returns {auto_merged}:
      // no queue entry; the sync badge just reflects the resolved state.
      // Phase 4: re-check the slug after the second await — if the user
      // switched vaults while the poll was in flight, drop the result (it
      // belongs to the old vault; the new vault's poll will surface its own).
      if (s.state === "needsdecision") {
        try {
          const body = await fetchPendingConflict();
          if (switcher.activeSlug() !== targetSlug) return;
          const pending = toPendingConflict(body);
          if (pending) conflicts.enqueue(pending);
        } catch {
          // Best-effort: the next poll retries. Don't crash the status poll.
        }
      }

      // Removal notice: keyless and cheap — one route answering a status
      // word. Same slug re-check as the conflict fetch above.
      try {
        const rn = JSON.parse(await daemon("sync.removal_notice"));
        if (switcher.activeSlug() !== targetSlug) return;
        setRemovalNotice(rn.status && rn.status !== "none" ? rn : null);
      } catch {
        // Best-effort: the next poll retries.
      }
    } catch {
      // Daemon unreachable or not connected to a remote — leave signals as-is.
    }
  }

  function dismissBanner() {
    setBannerDismissed(true);
  }

  function dismissRemoval() {
    setRemovalNotice(null);
  }

  // Fire a focus-triggered pull on window focus / tab becoming visible. The
  // daemon applies a 10-min server-side guard so rapid focus flicker collapses
  // to at most one pull per 10 min; safe to call on every focus event.
  // B2 fix: visibilitychange fires in BOTH directions (hide + show); ignore
  // the hide transition so we pull on arrival, not on leaving the app.
  // Best-effort: errors (daemon down, no remote) are swallowed.
  async function nudgePull() {
    if (document.hidden) return;
    try { await daemon("sync.autosync_nudge_pull"); } catch { /* best-effort */ }
    refresh();
  }

  onSettled(() => {
    refresh();
    poll = setInterval(refresh, POLL_MS);
    window.addEventListener("focus", nudgePull);
    document.addEventListener("visibilitychange", nudgePull);
    return () => {
      clearInterval(poll);
      window.removeEventListener("focus", nudgePull);
      document.removeEventListener("visibilitychange", nudgePull);
    };
  });

  const value = {
    active,
    state,
    lastSync,
    pending,
    conflictsResolved,
    bannerDismissed,
    removalNotice,
    refresh,
    dismissBanner,
    dismissRemoval,
  };

  return (
    <AutoSyncContext value={value}>
      {props.children}
    </AutoSyncContext>
  );
}

export function useAutoSync() {
  const ctx = useContext(AutoSyncContext);
  if (!ctx) throw new Error("useAutoSync must be used within AutoSyncProvider");
  return ctx;
}
