import { createSignal, createContext, useContext, onMount, onCleanup, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";
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

const AutoSyncContext = createContext();

export function AutoSyncProvider(props) {
  const [active, setActive] = createSignal(false);
  const [state, setState] = createSignal("idle");
  const [lastSync, setLastSync] = createSignal(null);
  const [pending, setPending] = createSignal(0);
  // Count of conflicts auto-resolved since mount. Drives the banner.
  const [conflictsResolved, setConflictsResolved] = createSignal(0);
  // Tracks whether the banner for the latest conflict batch was dismissed.
  const [bannerDismissed, setBannerDismissed] = createSignal(true);

  let poll;
  let lastSeenConflicts = 0;
  let lastSeenActive = null;

  // M3 fix: the daemon's conflicts_resolved counter is per-VaultState (resets
  // to 0 on each vault). This context lives at App root and survives vault
  // switches, so without resetting, switching A(3 conflicts)->B would suppress
  // B's first 3 conflicts (0 > 3 is false) and flash A's stale count. Reset on
  // active-slug change.
  const switcher = useVaultSwitcher();
  createEffect(() => {
    const slug = switcher.activeSlug();
    if (lastSeenActive !== null && slug !== lastSeenActive) {
      lastSeenConflicts = 0;
      setConflictsResolved(0);
      setBannerDismissed(true);
    }
    lastSeenActive = slug;
  });

  async function refresh() {
    try {
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
    } catch {
      // Daemon unreachable or not connected to a remote — leave signals as-is.
    }
  }

  function dismissBanner() {
    setBannerDismissed(true);
  }

  onMount(() => {
    refresh();
    poll = setInterval(refresh, POLL_MS);
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
  });
  onCleanup(() => {
    clearInterval(poll);
    window.removeEventListener("focus", refresh);
    document.removeEventListener("visibilitychange", refresh);
  });

  const value = {
    active,
    state,
    lastSync,
    pending,
    conflictsResolved,
    bannerDismissed,
    refresh,
    dismissBanner,
  };

  return (
    <AutoSyncContext.Provider value={value}>
      {props.children}
    </AutoSyncContext.Provider>
  );
}

export function useAutoSync() {
  const ctx = useContext(AutoSyncContext);
  if (!ctx) throw new Error("useAutoSync must be used within AutoSyncProvider");
  return ctx;
}
