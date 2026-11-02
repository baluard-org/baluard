# ADR 0006. Desktop Auto-Synchronization

> Status: Accepted (2026-06-26). The conflict policy below is the Phase 1 policy, superseded by ADR 0004. The pull cadence was refined by ADR 0026.

## Context

Bitwarden uses immediate push after each save, server-mediated last-write-wins conflict handling (HTTP 409), read-only mobile offline behavior, and a five-minute full sync. Applying that model to a shared Git remote would create a commit and round trip for each edit in a burst, and it would lose data on conflict because last-write-wins cannot merge fields. A Git remote has no inbound push channel, so unlike Bitwarden's SignalR inbound path the clients must poll as a fallback.

## Decision

The daemon coordinates synchronization with these policies:

- After each CRUD mutation, the `COVER_MUTATION_ACTIONS` hook in `handler.rs` schedules a push after a five-second debounce. A burst of edits therefore produces one commit and round trip.
- The daemon pulls immediately on vault unlock and on a desktop focus nudge through `sync.autosync_nudge_pull`. A ten-minute guard collapses repeated focus events. Each push cycle commits local edits, pulls, resolves conflicts, then pushes, so concurrent remote edits land right after a local mutation.
- While idle and online, the daemon pulls every 30 minutes as a quiet fallback. This interval avoids a predictable frequent heartbeat (T14 timing-fingerprint); event-triggered pulls provide the primary responsiveness.
- Network failures classified from `git2::Error::class()` as Net, Http, Ssh, or Ssl become `SyncError::Network`. The coordinator enters `Offline` and probes again after 30 seconds. Local edits remain queued until reconnection. The classification is explicit because libgit2 reports every failure as a Git error string: without it the `Offline` state never triggers.
- `SyncEngine::run_sync_cycle` commits local changes before pulling, then resolves conflicts and pushes. The initial conflict policy keeps local changes through `resolve_conflict_keep_local`, creates a two-parent merge commit, and surfaces a non-blocking banner. Field-level merging through `conflict::merge_ciphers` was not yet connected to the cycle in this decision; ADR 0004 records the Phase 2 policy that merges non-overlapping fields and requests a verdict only for same-field conflicts.
- A Tokio `cycle_lock` ensures that only one synchronization cycle accesses the repository at a time. Other cycles exit cleanly. Every blocking libgit2 call is bounded by a 60-second timeout, because libgit2 has no transport timeout and a hung negotiation with a dead remote would otherwise leak a blocking thread until the pool starves.
- `VaultState::unlock` activates synchronization immediately; locking deactivates it. The daemon has no decrypted data cache, so a pull does not require reloading the vault handle.

**Git invariants the cycle depends on.**

- The pull must force-checkout (`checkout_head` with a forced `CheckoutBuilder`). The default `checkout_head(None)` is a dry run: HEAD advances while the worktree keeps stale files, and the next commit then pushes the stale tree and silently reverts the other device's changes.
- The order is commit, then pull, then push. Committing first keeps the worktree clean, so the pull's force-checkout cannot discard uncommitted edits.
- Local-only engine files (`sync-head.json`, `sync-state.json`, `.baluard/`) stay gitignored. They are rewritten outside the commit cycle, and if they were tracked the worktree would be permanently dirty and the sync status would stay on "Changes pending".

The desktop polls `sync.autosync_status` every 10 seconds through `AutoSyncContext` and displays status and conflict information in the sidebar. Communication uses request-response calls, without a Tauri event channel.

The coordinator lives in `baluard-runtime`, not in the daemon binary, so it is the single implementation for every host. The desktop daemon hosts it behind the socket, and the mobile client hosts the same runtime in-process (ADR 0010, ADR 0089) without duplicating coordinator logic.

## Consequences

Debouncing reduces commits and round trips during bursts of edits. Event-triggered pulls provide timely updates, while the 30-minute interval is a fallback. Offline edits remain local until connectivity returns. The initial conflict policy preserved local data but did not merge non-overlapping fields automatically; ADR 0004 closed that gap. Synchronization is tied to the running daemon, so it stops when the desktop application quits (ADR 0009).

## References

- `COVER_MUTATION_ACTIONS` in `handler.rs`
- `SyncEngine::run_sync_cycle`
- `conflict::merge_ciphers`
- `AutoSyncContext`, `AutoSyncIndicator`, and `ConflictBanner`
- `crates/baluard-runtime/src/autosync.rs`
- ADR 0004, ADR 0026
