# ADR 0004. Conflict Auto-Resolution and Index Healing

> Status: Accepted (2026-07-02)

## Context

Git synchronization can produce conflicting cipher versions. Non-overlapping edits should merge without user input, while conflicting security-sensitive edits require an explicit verdict. Resolution must preserve local data and keep the encrypted cipher index consistent. Earlier text described the resolver as silently force-pushing or renaming the local version and accepting the remote commit. That was inaccurate and unsafe. The policy preserves local edits and creates merge commits, and it never force-pushes.

## Decision

**Field-level three-way merge.** The daemon uses `sync/conflict.rs::merge_ciphers`. On a pull conflict it decrypts the base, local, and remote versions with `VaultHandle::decrypt_cipher_bytes` and merges non-overlapping changes automatically. Username, password, and TOTP form an atomic semantic group: if any member conflicts, the whole group is flagged for user resolution, so a username from one device is never paired with a password from another. URI lists are unioned. Custom fields are merged per name against the base, so a field deleted on one side and unchanged on the other is deleted, a field deleted on one side and edited on the other is a conflict that preserves local, and a field added on one side is taken. Every entry kind merges field by field, passkeys merge by credential id, and password history merges by timestamp under its ten-entry cap.

**Auto-merge path.** For `MergeResult::Merged`, the daemon re-encrypts the result under the merging device's `current_epoch`, assigns `max(local_seq, remote_seq) + 1`, then calls `SyncEngine::finalize_conflicts` to write a two-parent merge commit and push it. No UI prompt is shown.

**User-verdict path.** For `MergeResult::Conflict`, the daemon pauses and exposes a masked conflict through `sync.conflict`. The masked form carries the entry name, type, and per-field label with a coarse sensitive flag, never a value, and the plaintext `ConflictInfo` is intentionally not serializable and is zeroized on drop. The floating `ConflictResolutionPanel` (ADR 0025, ADR 0093) collects the verdict through `sync.conflict.resolve`. The user may keep local or keep remote, which writes the chosen raw blob from its commit without re-encryption, or keep both, which clones the cipher with a new UUID under the current epoch at sequence 1, following `add_cipher` semantics.

**Cross-epoch safety.** If an envelope uses an epoch that the held `SpaceGroupKey` cannot reach (a remote from before a rotation whose old Root Key is destroyed, or a local copy behind a rotation), `try_derive_item_key` returns `None` instead of panicking and the conflict is marked `cross_epoch`. Only keep-local and keep-remote with the raw blob are permitted, and keep-both is refused because the unreadable side cannot be cloned.

**Engine integration.** `run_sync_cycle_with_resolver` takes `ConflictResolution::{KeepLocal, Pause}` and can return `SyncCycleOutcome::NeedsDecision` carrying a `PendingConflictState`. The daemon auto-sync coordinator opts into `Pause`. The `run_sync_cycle` wrapper keeps the earlier behavior for callers without a resolver: keep local through `SyncEngine::resolve_conflict_keep_local`, which writes a two-parent merge commit so the next push fast-forwards. The resolver handles one cipher conflict at a time; `PendingConflictState` holds a list for forward compatibility, but a single pull yields at most one conflict.

**Invariants the resolution path must hold.**

- `pull_inner` leaves the sync state machine in `Merging`, not `Idle`, when it returns a conflict. The final `Merging` to `Idle` transition after resolution is what completes the cycle. Pre-transitioning to `Idle` made the closing `Idle` to `Idle` transition invalid on every real conflict.
- `finalize_conflicts` is guarded on HEAD so a verdict cannot be applied twice.
- `finalize_conflicts` returns `SyncError::Network` when the merge commit landed but the push failed. The caller must still mark the conflict resolved, otherwise it wedges against the advanced HEAD.
- Every verdict path calls `rebuild_cipher_index()` after finalization. These paths write through `SyncEngine` and bypass the `VaultHandle::add/update/delete` hooks that rebuild `meta/index.enc`, so without the rebuild a keep-both clone, which has a new cipher id, would be missing from listings.
- The daemon-side pending conflict is drained when sync deactivates on lock. The desktop conflict queue is cleared on lock and on vault switch, and a poll for one vault re-checks the active slug after its awaits so it cannot enqueue a conflict into another vault's view.

## Consequences

Non-overlapping changes merge without user input, and conflicting changes are presented for a verdict without exposing secret values to the UI. Cross-epoch conflicts have fewer safe resolution options. Index rebuilding is required after all verdicts because sync writes do not use the normal vault mutation hooks. Multi-file conflicts are not merged; a conflict is resolved one cipher at a time.

## References

- `sync/conflict.rs::merge_ciphers`
- `VaultHandle::decrypt_cipher_bytes`
- `SyncEngine::finalize_conflicts`
- `SyncEngine::resolve_conflict_keep_local`
- `crates/baluard-runtime/src/state.rs` (masked conflict, verdict handlers)
- ADR 0006, ADR 0025, ADR 0093
