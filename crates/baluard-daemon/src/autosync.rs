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
                me.fire_sync(device_name, gen_id).await;
            }));
        }
    }

    /// Activate the coordinator (remote configured + provider connected).
    /// Starts the background pull/offline loop. Idempotent.
    pub async fn activate(&self, device_name: String) {
        let mut g = self.inner.lock().await;
        if g.active {
            return;
        }
        g.active = true;
        g.device_name = device_name.clone();
        g.state = AutoSyncState::Idle;
        let me = self.clone();
        let gen_id = g.generation;
        g.loop_handle = Some(tokio::spawn(async move {
            me.background_loop(device_name, gen_id).await;
        }));
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
        let generation = {
            let g = self.inner.lock().await;
            if !g.active {
                return;
            }
            g.generation
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
        let outcome =
            tokio::task::spawn_blocking(move || run_pull_only(&vault_path, &device_name)).await;
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
            me.fire_sync(device_name, gen_id).await;
        }));
    }

    /// Run one pull → merge → push cycle. Called from the debounce timer and
    /// from the background loop on its pull cadence.
    async fn fire_sync(&self, device_name: String, generation: u64) {
        {
            let mut g = self.inner.lock().await;
            if !g.active || g.generation != generation {
                return;
            }
            g.state = AutoSyncState::Syncing;
            g.pending = 0;
        }

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
            crate::handler::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking({
                let vault_path = self.vault_path.clone();
                move || run_sync_cycle(&vault_path, &device_name)
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
            let vault_path = self.vault_path.clone();
            let dn = device_name.clone();
            let outcome = tokio::time::timeout(
                crate::handler::SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || run_pull_only(&vault_path, &dn)),
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
fn run_sync_cycle(vault_path: &Path, device_name: &str) -> Result<SyncOutcome, String> {
    use baluard_core::sync::engine::{ConflictResolution, SyncCycleOutcome, SyncEngine};

    let engine = SyncEngine::new(vault_path, device_name);
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
fn run_sync_cycle(_vault_path: &Path, _device_name: &str) -> Result<SyncOutcome, String> {
    Err("git-sync feature disabled".into())
}

/// Pull-only (no commit/push). Used by the background loop to catch remote
/// edits. Returns Ok(true) on success, Ok(false) on network failure (offline).
#[cfg(feature = "git-sync")]
fn run_pull_only(vault_path: &Path, device_name: &str) -> Result<bool, String> {
    use baluard_core::sync::engine::is_network_error;
    use baluard_core::sync::engine::{PullResult, SyncEngine};

    let engine = SyncEngine::new(vault_path, device_name);
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
fn run_pull_only(_vault_path: &Path, _device_name: &str) -> Result<bool, String> {
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
        h.activate("test-device".to_string()).await;
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
}
