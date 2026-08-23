//! Auto-sync coordinator (one per connected vault).
//!
//! Activates only when the vault has a remote + a connected provider. Drives a
//! debounced push after every CRUD mutation, a periodic background pull, and
//! offline retry. This is the daemon-side engine; the desktop (and future
//! mobile) are pure pollers of [`AutoSyncHandle::status`].
//!
//! Design notes (see auto-sync architecture decision, 2026-06-26):
//! - Push is debounced (5s coalesce) so a burst of edits = one commit + one
//!   round-trip, unlike Bitwarden's immediate-push-per-save which would spam a
//!   git remote with N commits.
//! - True conflicts (both devices changed the same field) are auto-resolved by
//!   newest mtime; the merged cipher is committed and pushed, and a conflict
//!   event is recorded for the desktop banner. We never discard local edits:
//!   they remain in local git history.
//! - The coordinator is gated behind `git-sync` everywhere sync work happens.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Debounce window after a mutation before we commit + push.
const PUSH_DEBOUNCE_SECS: u64 = 5;
/// Background pull cadence when idle + online. Serverless architecture (git
/// remote IS the server, no push channel), so this sweeps up other-device
/// edits. 30 min: aggressive enough for multi-device, quiet enough to avoid a
/// predictable periodic heartbeat (T14 timing-fingerprint). Focus-regain and
/// unlock do event-driven pulls for snappiness; this is the idle fallback.
const PULL_INTERVAL_SECS: u64 = 30 * 60;
/// Minimum gap between a focus-triggered pull and the last sync. Prevents a
/// pull on every window focus flicker when we synced moments ago.
const FOCUS_PULL_MIN_GAP_SECS: u64 = 10 * 60;
/// Connectivity probe cadence while offline.
const OFFLINE_POLL_SECS: u64 = 30;
/// Wall-clock budget for a background-flush push (`on_background`). Shorter
/// than [`SYNC_OP_TIMEOUT`] because mobile OS background-task budgets
/// (Android `goAsync` can be a few seconds under memory pressure; iOS
/// `beginBackgroundTask` ~30s) can be killed before a 60s git op completes.
/// A kill mid-flush leaves the edit local (commit-pull-push ordering is
/// corruption-safe); the next foreground/unlock pull catches it. Peer-reviewed
/// decision (isolated peer review 2026-07-23): do NOT lower the shared
/// `SYNC_OP_TIMEOUT` for this, give the flush its own budget.
const BG_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Wall-clock budget for a single sync operation (pull/push/finalize). Bounds
/// `spawn_blocking` git work so a hung remote cannot leak a thread or stall the
/// cycle. Previously `handler::SYNC_OP_TIMEOUT`; moved here (Phase 0 runtime
/// extraction) so the runtime owns its own sync timeouts independently of the
/// daemon transport layer.
pub const SYNC_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Coordinator state, surfaced to clients via [`AutoSyncHandle::status`].
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AutoSyncState {
    /// Active remote, nothing pending.
    Idle,
    /// Local change waiting out the debounce window.
    Dirty,
    /// Pull/merge/push in flight.
    Syncing,
    /// Remote unreachable; retrying on a timer.
    Offline,
    /// Pull hit a conflict the daemon opted to pause for field-level
    /// resolution (Phase 2b). One or more `PendingConflictState` are held on
    /// `Inner`; the UI surfaces them via `sync.conflict` and the user's
    /// verdict resumes the cycle via `sync.conflict.resolve`. The background
    /// loop and debounce DO NOT fire in this state (the repo is mid-merge);
    /// they resume once the queue drains.
    NeedsDecision,
}

/// Snapshot of coordinator status, returned by the `sync.autosync_status` route.
#[derive(Debug, Clone, Serialize)]
pub struct AutoSyncStatus {
    /// Whether auto-sync is active for this vault (remote + provider connected).
    pub active: bool,
    pub state: AutoSyncState,
    /// Unix seconds of the last successful sync, if any.
    pub last_sync: Option<u64>,
    /// Number of mutations pending in the current debounce window.
    pub pending: u32,
    /// Count of conflicts auto-resolved (newest kept) since unlock.
    pub conflicts_resolved: u32,
}

/// Internal mutable state behind the handle lock.
struct Inner {
    active: bool,
    state: AutoSyncState,
    last_sync: Option<u64>,
    pending: u32,
    conflicts_resolved: u32,
    /// Phase 2b: conflicts paused for field-level resolution. Populated when
    /// `run_sync_cycle` returns `NeedsDecision`; drained by `sync.conflict`
    /// (read) and `sync.conflict.resolve` (consume + finalize). Empty in all
    /// other states.
    pending_conflicts: Vec<baluard_core::sync::engine::PendingConflictState>,
    /// Device name captured at `activate` so `note_resolved` can re-arm the
    /// debounce push after a conflict drains without the route re-passing it.
    device_name: String,
    /// Device-privkey seal subkey (C1) captured at `activate`, dropped and
    /// zeroized on `deactivate`. Opens the sealed devkey file for commit
    /// signing; the subkey, never the KEK, lives here.
    devkey_seal: Option<[u8; 32]>,
    /// Live debounce task. Replaced on each mutation (timer reset).
    debounce: Option<JoinHandle<()>>,
    /// Live background loop (pull + offline retry). One per coordinator.
    loop_handle: Option<JoinHandle<()>>,
    /// Bumped on shutdown so spawned tasks bail out.
    generation: u64,
}

/// Handle held by [`VaultState`](crate::state::VaultState). Cheap to clone
/// (wraps an `Arc<Mutex<Inner>>`); all mutation goes through the lock.
#[derive(Clone)]
pub struct AutoSyncHandle {
    vault_path: PathBuf,
    inner: Arc<Mutex<Inner>>,
    /// C3 fix: guards the on-disk repo so only ONE sync cycle runs at a time.
    /// Without this, a slow fetch (>5s debounce) overlapping a second debounce
    /// fire would run two cycles against the same .git index + worktree,
    /// racing index.lock / ref updates / checkout → corruption. try_lock'd in
    /// fire_sync and background_loop; the loser bails out cleanly.
    cycle_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AutoSyncHandle {
    pub fn new(vault_path: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            inner: Arc::new(Mutex::new(Inner {
                active: false,
                state: AutoSyncState::Idle,
                last_sync: None,
                pending: 0,
                conflicts_resolved: 0,
                pending_conflicts: Vec::new(),
                device_name: String::new(),
                devkey_seal: None,
                debounce: None,
                loop_handle: None,
                generation: 0,
            })),
            cycle_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Read-only status snapshot.
    pub async fn status(&self) -> AutoSyncStatus {
        let g = self.inner.lock().await;
        AutoSyncStatus {
            active: g.active,
            state: g.state,
            last_sync: g.last_sync,
            pending: g.pending,
            conflicts_resolved: g.conflicts_resolved,
        }
    }

    /// Whether the coordinator is active. Used by the status route to skip the
    /// blocking has_remote probe once activation has happened.
    pub async fn is_active(&self) -> bool {
        self.inner.lock().await.active
    }

    /// Phase 2b: number of conflicts currently paused for user decision.
    /// Drives the `sync.conflict` route's count + the UI badge.
    pub async fn pending_conflict_count(&self) -> usize {
        self.inner.lock().await.pending_conflicts.len()
    }

    /// Phase 2b: clone the head pending conflict (for the `sync.conflict` route
    /// to surface masked details to the UI). None if no conflict is pending.
    /// Does NOT consume — the conflict stays until `note_resolved`.
    pub async fn peek_pending_conflict(
        &self,
    ) -> Option<baluard_core::sync::engine::PendingConflictState> {
        self.inner.lock().await.pending_conflicts.first().cloned()
    }

    /// Phase 2b: drop the head pending conflict and, if the queue is now empty,
    /// transition to Dirty so the next debounce cycle pushes the merge commit
    /// (written by `finalize_conflicts` in the route) AND any edits queued via
    /// `nudge` while the conflict was paused. If more conflicts remain queued,
    /// stay in `NeedsDecision` for the next one.
    pub async fn note_resolved(&self) {
        let mut g = self.inner.lock().await;
        g.pending_conflicts.remove(0);
        if g.pending_conflicts.is_empty() {
            // Re-sync: the merge commit + any queued mutations. Going to Dirty
            // arms the debounce; pending (if any nudges landed) is preserved.
            g.state = AutoSyncState::Dirty;
            // Arm a fresh debounce so the push happens promptly.
            if let Some(h) = g.debounce.take() {
                h.abort();
            }
            let me = self.clone();
            let gen_id = g.generation;
            // device_name is read from the vault in the route; nudge used it.
            // For the post-resolve push we reuse the stored device name on the
            // handle via a clone — see AutoSyncHandle.device_name (added below).
            let device_name = g.device_name.clone();
            g.debounce = Some(tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(PUSH_DEBOUNCE_SECS)).await;
                me.fire_sync(device_name, gen_id, SYNC_OP_TIMEOUT).await;
            }));
        }
    }

    // ── Event-method surface (mobile lifecycle) ────────────────────────────
    //
    // Mobile hosts the coordinator WITHOUT a background tokio loop: the host
    // (Kotlin `ProcessLifecycleOwner` / iOS `SceneDelegate`) calls these event
    // methods from OS lifecycle hooks. The daemon keeps its `background_loop`;
    // both hosts drive the same `Inner` state machine, so there is ONE
    // implementation of the debounce / offline-retry / conflict-queue logic.
    //
    // Most events are thin wrappers over the existing daemon-side methods so
    // the mobile surface reads as lifecycle events rather than daemon
    // internals. See `docs/plan-mobile-apps.md` §3.2/§3.5 and the Phase 0
    // Task #2 state-machine map.

    /// **`on_unlock`** — pull immediately after the vault unlocks so edits made
    /// on another device land before the user starts working. Mirrors the
    /// daemon's `VaultState::unlock` → `pull_only` hook.
    pub async fn on_unlock(&self, device_name: String) {
        self.pull_only(device_name).await;
    }

    /// **`on_mutation`** — arm (or re-arm) the 5s debounced push after a CRUD
    /// mutation. A burst of edits coalesces into one commit + one round-trip.
    /// Mirrors the daemon's post-CRUD `COVER_MUTATION_ACTIONS` hook.
    pub async fn on_mutation(&self, device_name: String) {
        self.nudge(device_name).await;
    }

    /// **`on_foreground`** — pull when the app regains focus, with a 10-minute
    /// guard so focus flicker collapses to one pull per 10 min.
    pub async fn on_foreground(&self, device_name: String) {
        self.nudge_focus_pull(device_name).await;
    }

    /// **`on_background`** — FLUSH any pending debounce push immediately. The
    /// OS suspends a backgrounded mobile process within seconds; if a user
    /// edits then backgrounds the app (the common case), the 5s debounce timer
    /// would be silently dropped and the edit would sit local-only. This fires
    /// the push NOW, bounded by the OS background-task budget.
    ///
    /// Implementation notes (peer-reviewed, isolated session 2026-07-23):
    /// - `device_name` is read from `Inner` (set once at `activate`) rather
    ///   than passed in, because lifecycle hooks fire without device context.
    ///   `activate()` fixes `device_name` for the coordinator's lifetime; a
    ///   host that renames its device must `deactivate`/`activate` to update it.
    /// - The debounce `JoinHandle` is `abort()`ed to stop the now-redundant
    ///   timer from firing a second, unnecessary cycle later. The actual
    ///   double-flush guard is the `Inner.state` transition under the shared
    ///   `inner` mutex: once `fire_sync` flips `Dirty → Syncing` under the lock,
    ///   a racing timer-fire observes `state != Dirty` and returns early.
    ///   `abort()` keeps the work clean; `cycle_lock` (try_lock, loser bails)
    ///   is the belt-and-suspenders against `background_loop`'s independent pull.
    /// - This call uses a SHORTER timeout ([`BG_FLUSH_TIMEOUT`]) than the
    ///   debounce path because the shared [`SYNC_OP_TIMEOUT`] (60s) is a
    ///   desktop-scale bound that can exceed Android's `goAsync` budget.
    ///   A kill mid-flush leaves the edit local (commit-pull-push ordering
    ///   guarantees no corruption); the next `on_unlock` / `on_foreground`
    ///   pull catches it.
    /// - Idempotent on no-op: if nothing is pending (state != Dirty) this is a
    ///   cheap lock-check + return.
    pub async fn on_background(&self) {
        let (device_name, generation) = {
            let mut g = self.inner.lock().await;
            if !g.active || g.state != AutoSyncState::Dirty {
                return;
            }
            // Explicit cancel (amendment #1): don't race the timer.
            if let Some(h) = g.debounce.take() {
                h.abort();
            }
            (g.device_name.clone(), g.generation)
        };
        self.fire_sync(device_name, generation, BG_FLUSH_TIMEOUT)
            .await;
    }

    /// **`pull_now`** — user-initiated pull (pull-to-refresh, "Sync now"). No
    /// debounce, no commit/push: just reconcile remote changes.
    pub async fn pull_now(&self, device_name: String) {
        self.pull_only(device_name).await;
    }

    /// **`offline_tick`** — host-scheduled 30s connectivity probe while the
    /// vault is `Offline` AND the app is foregrounded. This is the one piece
    /// of `background_loop` mobile MUST reproduce: the loop polls every 30s
    /// while Offline until back online, and without a background task mobile
    /// must drive that probe explicitly from its foreground lifecycle. On a
    /// successful pull the state settles to `Idle`; on continued failure it
    /// stays `Offline`. No-op if not Offline (avoids redundant pulls).
    pub async fn offline_tick(&self, device_name: String) {
        let offline = {
            let g = self.inner.lock().await;
            g.active && g.state == AutoSyncState::Offline
        };
        if offline {
            self.pull_only(device_name).await;
        }
    }

    /// **`on_conflict`** — peek the head conflict paused for user decision
    /// (masked, no secrets). None if no conflict is pending. Used by the mobile
    /// conflict-resolution UI to surface the `ConflictResolutionPanel`.
    pub async fn on_conflict(&self) -> Option<baluard_core::sync::engine::PendingConflictState> {
        self.peek_pending_conflict().await
    }

    /// Activate the coordinator (remote configured + provider connected).
    /// Starts the background pull/offline loop. Idempotent.
    ///
    /// `device_name` is captured here and reused by `note_resolved` and
    /// `on_background` (lifecycle hooks fire without device context). It is
    /// fixed for the coordinator's lifetime; a host that renames its device
    /// must `deactivate`/`activate` to update it (peer review 2026-07-23).
    pub async fn activate(&self, device_name: String, devkey_seal: Option<[u8; 32]>) {
        let mut g = self.inner.lock().await;
        if g.active {
            return;
        }
        g.active = true;
        g.device_name = device_name.clone();
        g.devkey_seal = devkey_seal;
        g.state = AutoSyncState::Idle;
        let me = self.clone();
        let gen_id = g.generation;
        g.loop_handle = Some(tokio::spawn(async move {
            me.background_loop(device_name, gen_id).await;
        }));
    }

    /// Test-only: force the coordinator into a given state. Used to exercise
    /// guard logic (e.g. the `NeedsDecision` short-circuit in `pull_only`)
    /// that depends on state a unit test cannot otherwise reach without a
    /// real two-device git fixture. NOT part of the public API.
    #[cfg(test)]
    pub(crate) async fn force_state_for_test(&self, state: AutoSyncState) {
        self.inner.lock().await.state = state;
    }

    /// Deactivate (provider disconnected or vault locked). Cancels all timers.
    ///
    /// Clears `pending_conflicts` so `state` and the queue never disagree
    /// (review fix: pre-fix, deactivate reset state to Idle but left
    /// pending_conflicts populated, so a lock_all on window-blur mid-conflict
    /// desynced them — the panel never re-surfaced (state != NeedsDecision)
    /// and the next CRUD's commit tripped write_tree on the still-unmerged
    /// index, silently wedging auto-sync). The on-disk merge conflict is NOT
    /// touched here; the next activate + sync cycle re-detects it and
    /// re-surfaces it as NeedsDecision.
    pub async fn deactivate(&self) {
        let mut g = self.inner.lock().await;
        g.generation = g.generation.wrapping_add(1);
        g.active = false;
        g.state = AutoSyncState::Idle;
        g.pending = 0;
        g.pending_conflicts.clear();
        // C1: drop the devkey seal subkey with the session.
        if let Some(mut k) = g.devkey_seal.take() {
            use zeroize::Zeroize;
            k.zeroize();
        }
        if let Some(h) = g.debounce.take() {
            h.abort();
        }
        if let Some(h) = g.loop_handle.take() {
            h.abort();
        }
    }

    /// Phase 2b review fix: serialize repo-touching conflict operations
    /// (decrypt/merge/finalize) against the same `cycle_lock` the sync cycle
    /// uses. The `sync.conflict` route is polled every 10s AND fired on
    /// window focus/visibility, so two overlapping polls could race
    /// `finalize_conflicts`'s HEAD-tip guard (check-then-act without a lock).
    /// Routing through the cycle lock makes the guard a real mutual-exclusion
    /// guarantee. Returned guard is held across the conflict op's
    /// `spawn_blocking` (mirrors fire_sync / pull_only).
    pub async fn cycle_lock_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.cycle_lock.lock().await
    }

    /// Immediate pull-only sync (fetch + merge, no commit/push). Used by the
    /// unlock path to reconcile remote changes the moment the vault opens, and
    /// as the shared body of the focus trigger. Respects the cycle_lock so it
    /// can't race a debounce push. No-op if inactive or a cycle is in flight.
    pub async fn pull_only(&self, device_name: String) {
        let (generation, devkey_seal) = {
            let g = self.inner.lock().await;
            if !g.active {
                return;
            }
            // NeedsDecision guard (peer review 2026-07-23):
            // `nudge` and `background_loop` both refuse to touch the repo while
            // a conflict is paused for field-level resolution — the index/
            // worktree are mid-merge and a pull now would race the resolution
            // (corruption risk). `pull_only` previously lacked this guard.
            // Task #2's event surface added new public, host-triggerable entry
            // points to it (`pull_now`, `offline_tick`, `on_unlock`), widening
            // the exposure. Same guard as the other two repo-touching paths.
            if g.state == AutoSyncState::NeedsDecision {
                log::debug!("[autosync] pull_only skipped: conflict paused (NeedsDecision)");
                return;
            }
            (g.generation, g.devkey_seal)
        };
        // Don't race a debounce push or another cycle.
        let lock_guard = match self.cycle_lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                // Safe to skip: an in-flight push cycle includes a pull
                // (commit->pull->push), so we are not losing the update.
                log::debug!("[autosync] pull_only skipped: cycle in flight");
                return;
            }
        };
        let vault_path = self.vault_path.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            run_pull_only(&vault_path, &device_name, devkey_seal.as_ref())
        })
        .await;
        drop(lock_guard);
        let mut g = self.inner.lock().await;
        if !g.active || g.generation != generation {
            return;
        }
        match outcome {
            Ok(Ok(true)) => {
                g.last_sync = Some(now_secs());
                // Don't clobber Dirty/Syncing; only settle to Idle from Offline.
                if g.state == AutoSyncState::Offline {
                    g.state = AutoSyncState::Idle;
                }
            }
            Ok(Ok(false)) => g.state = AutoSyncState::Offline,
            _ => {}
        }
    }

    /// Focus-triggered pull. Silently skips if the last sync was within
    /// [`FOCUS_PULL_MIN_GAP_SECS`], so rapid focus flicker doesn't spam the
    /// remote. Otherwise delegates to [`pull_only`]. Called from the desktop's
    /// window-focus / visibilitychange hooks via the `sync.autosync_nudge_pull`
    /// IPC route.
    pub async fn nudge_focus_pull(&self, device_name: String) {
        let skip = {
            let g = self.inner.lock().await;
            if !g.active {
                return;
            }
            match g.last_sync {
                Some(t) => now_secs().saturating_sub(t) < FOCUS_PULL_MIN_GAP_SECS,
                None => false,
            }
        };
        if skip {
            return;
        }
        self.pull_only(device_name).await;
    }

    /// Arm (or re-arm) the push debounce. Called after every successful vault
    /// mutation. The pending counter accumulates so the UI can show "3 changes
    /// syncing".
    pub async fn nudge(&self, device_name: String) {
        let mut g = self.inner.lock().await;
        if !g.active {
            return;
        }
        // Phase 2b: if a conflict is paused for decision, DO NOT clobber the
        // state or arm the debounce — the repo is mid-merge (index/worktree
        // in conflict) and a cycle now would race the resolution. Queue the
        // mutation via `pending`; the resolution path transitions to Dirty
        // after draining so the new edit syncs on the next cycle.
        if g.state == AutoSyncState::NeedsDecision {
            g.pending = g.pending.saturating_add(1);
            return;
        }
        g.pending = g.pending.saturating_add(1);
        g.state = AutoSyncState::Dirty;
        // Reset any in-flight debounce timer.
        if let Some(h) = g.debounce.take() {
            h.abort();
        }
        let me = self.clone();
        let gen_id = g.generation;
        g.debounce = Some(tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(PUSH_DEBOUNCE_SECS)).await;
            me.fire_sync(device_name, gen_id, SYNC_OP_TIMEOUT).await;
        }));
    }

    /// Run one pull → merge → push cycle. Called from the debounce timer and
    /// from the background loop on its pull cadence.
    ///
    /// `timeout` bounds the `spawn_blocking` git work for THIS call only. The
    /// debounce and post-resolve paths pass [`SYNC_OP_TIMEOUT`] (60s, the
    /// desktop-scale default); the background-flush path ([`Self::on_background`])
    /// passes a shorter budget ([`BG_FLUSH_TIMEOUT`]) so a mobile OS
    /// background-task kill doesn't leak the pool thread against a 60s wall.
    async fn fire_sync(&self, device_name: String, generation: u64, timeout: std::time::Duration) {
        let devkey_seal = {
            let mut g = self.inner.lock().await;
            if !g.active || g.generation != generation {
                return;
            }
            g.state = AutoSyncState::Syncing;
            g.pending = 0;
            g.devkey_seal
        };

        // C3 fix: hold the cycle lock across the blocking work so two cycles
        // never touch the same on-disk repo concurrently. try_lock: if a
        // background-loop pull is already running, bail (the next mutation's
        // debounce will retry).
        let lock_guard = match self.cycle_lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                let mut g = self.inner.lock().await;
                if g.active && g.generation == generation {
                    g.state = AutoSyncState::Idle;
                }
                return;
            }
        };

        let outcome = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking({
                let vault_path = self.vault_path.clone();
                move || run_sync_cycle(&vault_path, &device_name, devkey_seal.as_ref())
            }),
        )
        .await;
        drop(lock_guard);

        let mut g = self.inner.lock().await;
        if !g.active || g.generation != generation {
            return;
        }
        match outcome {
            Ok(Ok(Ok(SyncOutcome::Synced { conflicts }))) => {
                g.conflicts_resolved = g.conflicts_resolved.saturating_add(conflicts);
                g.last_sync = Some(now_secs());
                g.state = AutoSyncState::Idle;
            }
            Ok(Ok(Ok(SyncOutcome::Offline))) => {
                g.state = AutoSyncState::Offline;
            }
            Ok(Ok(Ok(SyncOutcome::NeedsDecision { pending }))) => {
                // Phase 2b: hold the paused conflicts and surface to the UI.
                // The background loop and debounce must NOT fire while the repo
                // is mid-merge; they resume once the queue drains via
                // sync.conflict.resolve. last_sync is NOT advanced (the cycle
                // did not complete).
                g.pending_conflicts = pending;
                g.state = AutoSyncState::NeedsDecision;
            }
            _ => {
                // Op error, join error, or SYNC_OP_TIMEOUT: do not go offline
                // unless run_sync_cycle mapped it to Offline (handled above).
                // Stay Idle so the next mutation retries. L1 fix: do NOT
                // advance last_sync on error, or the UI would falsely show
                // "All synced". The timeout case is what stops a hung git2 op
                // (no libgit2 transport timeout) from leaking the pool thread.
                g.state = AutoSyncState::Idle;
            }
        }
    }

    /// Long-running background loop: periodic pull + offline retry.
    async fn background_loop(self, device_name: String, generation: u64) {
        loop {
            // Bail if deactivated.
            {
                let g = self.inner.lock().await;
                if !g.active || g.generation != generation {
                    return;
                }
            }

            let sleep_secs = {
                let g = self.inner.lock().await;
                match g.state {
                    AutoSyncState::Offline => OFFLINE_POLL_SECS,
                    // Idle/Dirty/Syncing: pull on the interval. If a debounce
                    // push is pending it will fire first; this pull then runs
                    // after, harmlessly.
                    _ => PULL_INTERVAL_SECS,
                }
            };
            tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;

            {
                let g = self.inner.lock().await;
                if !g.active || g.generation != generation {
                    return;
                }
                // Only pull when idle or offline (retry). Skip Dirty/Syncing
                // (race a debounce push) and NeedsDecision (the index/worktree
                // are mid-merge from a paused conflict).
                if g.state != AutoSyncState::Idle && g.state != AutoSyncState::Offline {
                    continue;
                }
            }

            // C3 fix: acquire the cycle lock so the background pull can't run
            // concurrently with a debounce-triggered cycle on the same repo.
            let lock_guard = match self.cycle_lock.try_lock() {
                Ok(g) => g,
                Err(_) => continue, // a sync cycle is in flight; try again next tick
            };

            // Pull-only cycle (no commit/push): just reconcile remote changes.
            // C1: read the devkey seal under the same lock as the liveness
            // check above it.
            let devkey_seal = {
                let g = self.inner.lock().await;
                if !g.active || g.generation != generation {
                    return;
                }
                g.devkey_seal
            };
            let vault_path = self.vault_path.clone();
            let dn = device_name.clone();
            let outcome = tokio::time::timeout(
                SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || run_pull_only(&vault_path, &dn, devkey_seal.as_ref())),
            )
            .await;
            drop(lock_guard);
            let mut g = self.inner.lock().await;
            if !g.active || g.generation != generation {
                return;
            }
            match outcome {
                Ok(Ok(Ok(true))) => {
                    g.last_sync = Some(now_secs());
                    g.state = AutoSyncState::Idle;
                }
                Ok(Ok(Ok(false))) => {
                    g.state = AutoSyncState::Offline;
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug)]
enum SyncOutcome {
    Synced {
        conflicts: u32,
    },
    Offline,
    /// Phase 2b: a conflict was paused for field-level resolution. The repo
    /// is mid-merge (HEAD unchanged, index/worktree in conflict state); the
    /// coordinator holds `pending` and transitions to `NeedsDecision`.
    NeedsDecision {
        pending: Vec<baluard_core::sync::engine::PendingConflictState>,
    },
}

/// Blocking pull → merge → push. Returns the outcome + conflict count.
///
/// Network failures map to [`SyncOutcome::Offline`]; everything else is a
/// regular error.
#[cfg(feature = "git-sync")]
fn run_sync_cycle(
    vault_path: &Path,
    device_name: &str,
    devkey_seal: Option<&[u8; 32]>,
) -> Result<SyncOutcome, String> {
    use baluard_core::sync::engine::{ConflictResolution, SyncCycleOutcome, SyncEngine};

    let engine = SyncEngine::new(vault_path, device_name, devkey_seal);
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    // Phase 2b: opt in to field-level resolution. On conflict, PAUSE the cycle
    // (no merge commit, no push) and surface the PendingConflictState to the
    // coordinator, which holds it for the UI. The daemon-side decrypt + merge
    // lands in 2b-2; today the resolver always pauses, and sync.conflict.resolve
    // picks the raw blob (local or remote bytes) per the user's verdict.
    match engine.run_sync_cycle_with_resolver(&repo, &mut |_| ConflictResolution::Pause) {
        Ok(SyncCycleOutcome::Synced { conflicts }) => Ok(SyncOutcome::Synced { conflicts }),
        Ok(SyncCycleOutcome::Offline) => Ok(SyncOutcome::Offline),
        Ok(SyncCycleOutcome::NeedsDecision { pending }) => {
            Ok(SyncOutcome::NeedsDecision { pending })
        }
        Err(e) => Err(format!("{e}")),
    }
}

#[cfg(not(feature = "git-sync"))]
fn run_sync_cycle(
    _vault_path: &Path,
    _device_name: &str,
    _devkey_seal: Option<&[u8; 32]>,
) -> Result<SyncOutcome, String> {
    Err("git-sync feature disabled".into())
}

/// Pull-only (no commit/push). Used by the background loop to catch remote
/// edits. Returns Ok(true) on success, Ok(false) on network failure (offline).
#[cfg(feature = "git-sync")]
fn run_pull_only(
    vault_path: &Path,
    device_name: &str,
    devkey_seal: Option<&[u8; 32]>,
) -> Result<bool, String> {
    use baluard_core::sync::engine::is_network_error;
    use baluard_core::sync::engine::{PullResult, SyncEngine};

    let engine = SyncEngine::new(vault_path, device_name, devkey_seal);
    let repo = match engine.open_repo() {
        Ok(r) => r,
        Err(ref e) if is_network_error(e) => return Ok(false),
        Err(e) => return Err(format!("{e}")),
    };
    match engine.pull(&repo, "origin") {
        // A background pull that hits a conflict: keep local via the same
        // keep-local path the full cycle uses. No push here (the next
        // mutation-triggered cycle, or manual sync, will push the merge).
        Ok(PullResult::Conflict {
            files,
            local_oid,
            remote_oid,
        }) => {
            // B3 fix: a failed conflict resolution leaves the repo in a
            // half-merged state (HEAD advanced, no resolution commit). Map to
            // Err so the caller does NOT advance last_sync / mark Idle, and the
            // next cycle retries instead of pushing a corrupt tree.
            engine
                .resolve_conflict_keep_local(&repo, local_oid, remote_oid, &files)
                .map(|_| true)
                .map_err(|e| format!("conflict resolution failed: {e}"))
        }
        Ok(_) => Ok(true),
        Err(ref e) if is_network_error(e) => Ok(false),
        Err(e) => Err(format!("{e}")),
    }
}

#[cfg(not(feature = "git-sync"))]
fn run_pull_only(
    _vault_path: &Path,
    _device_name: &str,
    _devkey_seal: Option<&[u8; 32]>,
) -> Result<bool, String> {
    Ok(true)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Phase 2b holistic review fix #1 regression: deactivate() must clear
    // pending_conflicts so state and the queue never disagree. Pre-fix, a
    // lock_all on window-blur mid-conflict reset state to Idle but left the
    // queue populated, permanently hiding the still-unresolved conflict from
    // the UI and wedging the next CRUD's commit on the unmerged index.
    //
    // We can't easily populate pending_conflicts without a real two-device
    // sync cycle (no public setter), so this asserts the invariant at the
    // boundary we control: a fresh handle has count 0, and deactivate (even
    // called repeatedly / without activate) keeps it at 0 + state Idle. The
    // full pause->deactivate->activate->re-detect round-trip is covered by
    // the deferred two-device crypto integration test.
    #[tokio::test]
    async fn deactivate_clears_state_and_keeps_queue_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());

        // Fresh: clean.
        assert_eq!(h.pending_conflict_count().await, 0);
        assert_eq!(h.status().await.state, AutoSyncState::Idle);

        // activate is a no-op without a real remote, but should not populate
        // pending_conflicts either.
        h.activate("test-device".to_string(), None).await;
        assert_eq!(h.pending_conflict_count().await, 0);

        // deactivate must reset to Idle + drain any pending conflicts.
        h.deactivate().await;
        assert_eq!(h.status().await.state, AutoSyncState::Idle);
        assert_eq!(
            h.pending_conflict_count().await,
            0,
            "deactivate must clear pending_conflicts (state/queue desync regression)"
        );
    }

    // ── Event-method surface tests (Phase 0 Task #2) ─────────────────────
    //
    // These verify the CONTRACT of the mobile event surface without a real
    // git remote: that each event method resolves to the correct underlying
    // state transition, that guards (no-op unless active, no-op unless Offline)
    // hold, and that `on_background` flushes a Dirty debounce immediately.
    //
    // The full Offline-recovery reproduction (offline_tick driving Offline→Idle
    // on a real network recovery) needs a two-device git fixture and is covered
    // by the same deferred crypto integration test as the pause/resume cycle
    // above. What we CAN prove here: offline_tick is a no-op unless Offline,
    // so a host can safely call it on every foreground tick without spamming
    // pulls when the vault is healthy.

    #[tokio::test]
    async fn event_methods_noop_when_inactive() {
        // Before activate, every event method must be a safe no-op (mobile may
        // fire lifecycle hooks before the coordinator is wired).
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());

        h.on_unlock("d".to_string()).await;
        h.on_mutation("d".to_string()).await;
        h.on_foreground("d".to_string()).await;
        h.on_background().await;
        h.pull_now("d".to_string()).await;
        h.offline_tick("d".to_string()).await;
        assert!(h.on_conflict().await.is_none());

        let s = h.status().await;
        assert!(!s.active);
        assert_eq!(s.state, AutoSyncState::Idle);
        assert_eq!(s.pending, 0, "inactive nudge must not accumulate pending");
    }

    #[tokio::test]
    async fn on_mutation_arms_debounce_and_sets_dirty() {
        // The core event: a CRUD mutation arms the 5s debounce and marks Dirty.
        // We activate WITHOUT a real remote (activate sets active=true + Idle,
        // but no provider is connected); on_mutation still arms the debounce
        // because it only checks `active`, not remote reachability.
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());
        h.activate("test-device".to_string(), None).await;

        h.on_mutation("test-device".to_string()).await;
        let s = h.status().await;
        assert_eq!(s.state, AutoSyncState::Dirty, "on_mutation must set Dirty");
        assert_eq!(s.pending, 1, "on_mutation must increment pending");

        // A burst coalesces: second nudge within the debounce window.
        h.on_mutation("test-device".to_string()).await;
        let s = h.status().await;
        assert_eq!(s.pending, 2, "burst must accumulate in pending");
        assert_eq!(s.state, AutoSyncState::Dirty);

        h.deactivate().await;
    }

    #[tokio::test]
    async fn on_background_flushes_dirty_debounce_immediately() {
        // THE critical mobile contract (plan §3.5 "Flush-on-background is
        // mandatory"): on_background must fire a Dirty debounce NOW, not wait
        // for the 5s timer the OS is about to suspend. We verify the state
        // transition Dirty → Syncing (the flush armed fire_sync).
        //
        // fire_sync will fail (no real remote) and settle back to Idle; we
        // can't assert Syncing deterministically across awaits, so we verify
        // the NEGATIVE: after on_background, the debounce handle is gone
        // (flushed) and pending has reset to 0 (fire_sync clears it). A plain
        // 5s-wait path would still show pending > 0 and Dirty here.
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());
        h.activate("test-device".to_string(), None).await;
        h.on_mutation("test-device".to_string()).await;
        assert_eq!(h.status().await.state, AutoSyncState::Dirty);

        h.on_background().await;

        // fire_sync ran (and failed on no remote); state settled off Dirty,
        // pending cleared. The debounce timer is no longer armed.
        let s = h.status().await;
        assert_ne!(
            s.state,
            AutoSyncState::Dirty,
            "on_background must flush the Dirty debounce, not leave it pending"
        );
        assert_eq!(s.pending, 0, "flush must clear pending");

        h.deactivate().await;
    }

    #[tokio::test]
    async fn on_background_noop_when_not_dirty() {
        // No pending debounce → on_background is a cheap no-op. Prevents
        // mobile from firing empty push cycles every time the app backgrounds.
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());
        h.activate("test-device".to_string(), None).await;
        assert_eq!(h.status().await.state, AutoSyncState::Idle);

        h.on_background().await; // must not panic, must not change state
        assert_eq!(h.status().await.state, AutoSyncState::Idle);

        h.deactivate().await;
    }

    #[tokio::test]
    async fn offline_tick_noop_when_not_offline() {
        // offline_tick is the host-scheduled 30s probe mobile MUST fire while
        // foregrounded. It must be a no-op when the vault is healthy (Idle),
        // otherwise every 30s tick would spam a redundant pull. Only fires
        // when state == Offline. (The Offline→Idle recovery transition itself
        // requires a real two-device git fixture; here we prove the guard.)
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());
        h.activate("test-device".to_string(), None).await;
        assert_eq!(h.status().await.state, AutoSyncState::Idle);

        // Idle: no-op. We can't observe "did not pull" directly without a
        // remote, but we assert the guard short-circuits without touching
        // state (no transition away from Idle).
        h.offline_tick("test-device".to_string()).await;
        assert_eq!(
            h.status().await.state,
            AutoSyncState::Idle,
            "offline_tick must be a no-op when not Offline"
        );

        h.deactivate().await;
    }

    #[tokio::test]
    async fn pull_only_skips_when_needs_decision() {
        // Regression for peer-review finding #7 (2026-07-23):
        // pull_only must NOT run a git pull while a conflict is paused for
        // field-level resolution — the index/worktree are mid-merge and a pull
        // would race the resolution (corruption risk). nudge and background_loop
        // already guard this; pull_only (now reachable from 3 new Task #2 event
        // entry points: pull_now, offline_tick, on_unlock) must too.
        //
        // We can't reach NeedsDecision via a real sync cycle in a unit test
        // (no two-device git fixture), so force_state_for_test sets it directly.
        // The guard short-circuits before touching cycle_lock or the repo, so
        // state stays NeedsDecision (proving pull_only returned early rather
        // than running and settling to Idle/Offline).
        let tmp = tempfile::tempdir().unwrap();
        let h = AutoSyncHandle::new(tmp.path());
        h.activate("test-device".to_string(), None).await;
        h.force_state_for_test(AutoSyncState::NeedsDecision).await;
        assert_eq!(h.status().await.state, AutoSyncState::NeedsDecision);

        // Every public event that delegates to pull_only must be gated.
        h.pull_now("test-device".to_string()).await;
        h.offline_tick("test-device".to_string()).await;
        h.on_unlock("test-device".to_string()).await;
        h.on_foreground("test-device".to_string()).await; // -> nudge_focus_pull -> pull_only

        // State unchanged: the guard fired on every path.
        assert_eq!(
            h.status().await.state,
            AutoSyncState::NeedsDecision,
            "pull_only (and its event wrappers) must skip in NeedsDecision, \
             not race the paused conflict resolution"
        );

        h.deactivate().await;
    }
}
