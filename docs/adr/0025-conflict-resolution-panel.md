# ADR 0025. Conflict Resolution Panel

> Status: Accepted (2026-07-02)

## Context

The auto-sync path silently kept the local version on any file-level conflict. This can lose non-overlapping field edits from the remote device (finding F1: same item, non-overlapping fields, high severity), and a non-technical user has no way to see that it happened. `merge_ciphers` exists and is tested in `sync/conflict.rs`, but it was not wired into the sync cycle.

The panel is the user surface for the destructive cases that conflict resolution Phase 1 surfaces. It could be built first because it consumes a structured `PendingConflict` queue, which for the mock case is derivable in the frontend from the `sync.autosync_status` payload. This was recorded as D22. The original decision built the UI first and deferred the backend wiring, which still fell back to `resolve_conflict_keep_local`. The backend has since been wired (Phase 2).

## Decision

**UI**

- The panel is a top-floating, modal-like panel with a subtle slide-down animation, in `desktop/src/components/ConflictResolutionPanel.jsx`. It uses FocusTrap for accessibility.
- `ConflictResolutionContext.jsx` holds a queue of `PendingConflict` entries.
- Three options are offered, ordered simplest first: keep local, keep remote, keep both as separate entries. Granularity is per entry.
- Per-field picking is intentionally excluded, because it would require shipping secret values to the UI.
- The panel may show the entry name, the cipher type, and the list of conflicting field labels with a `sensitive` flag. The secret value never crosses IPC.

**Backend (Phase 2)**

- The cycle runs `merge_ciphers` per conflicting cipher through `run_sync_cycle_with_resolver(..., Pause)`.
- `Merged` writes the merged cipher and finalizes.
- `Conflict` pauses the cycle (`SyncCycleOutcome::NeedsDecision`), surfaces the conflict through the `sync.conflict` route, and resumes on `sync.conflict.resolve`.
- keep_local and keep_remote select the raw blob with no re-encryption. keep_both clones the entry under a new UUID, mirroring `add_cipher`.
- A cross-epoch decrypt failure surfaces a `cross_epoch` flag.

## Consequences

The stuck-queue escape is still open. The panel is non-dismissable and keeps the conflict in the queue when the resolver fails, which is retry-friendly. A permanently failing `sync.conflict.resolve` IPC call would lock the user out. This is tracked as `TODO(stuck-queue)` in `decide()`. The resolution options (max-retry fallback, manual escape hatch, hard-blocking product decision) are deferred. The daemon route exists and works today, so the risk is a degraded-network edge case and not a default path.

## References

- See ADR 0004 for the full mechanic.
- `docs/adr/0093-conflict-resolution-panel.md` for the contract
