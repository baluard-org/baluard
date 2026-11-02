# ADR 0093. Conflict Resolution Panel

> Status: Accepted (2026-07-02). Phase 2 is implemented: engine integration (`run_sync_cycle_with_resolver`, `ConflictResolution`, `NeedsDecision`, `finalize_conflicts`), daemon decrypt and merge (`conflict_decrypt_and_merge`), `keep_both` (`conflict_resolve_keep_both`), and the desktop IPC wiring (`conflictFlow.js`, `AutoSyncContext` poll, panel resolver). Open: the stuck-queue escape and a full two-vault crypto integration test.

This record is the full design contract for the panel. ADR 0004 records the underlying auto-resolution and index-healing policy, and ADR 0025 is the short record of the panel. Neither is repeated here.

## Context

Git synchronization can produce a conflict when the same cipher path is changed on multiple devices. Ciphers are stored flat at `ciphers/<cipher_id>.enc`, so a git-level conflict fires only when the same cipher is touched on two devices. Two different ciphers edited concurrently use different paths and fast-forward cleanly.

Before Phase 2 the sync engine kept the local copy for every conflict it could not reconcile. This silently discarded remote edits, including changes to the same field and structural changes to the cipher kind. The panel is the human-in-the-loop backstop for the cases the automatic path used to resolve destructively and silently. It is a top-floating, modal-like panel (subtle slide-down animation) shown only when the automatic path cannot safely consolidate an entry edited on two devices, and it must let a non-technical user choose between the local version, the remote version, or both.

Some edits can be merged without user input. The merge algorithm must preserve related security fields as atomic groups, and must not expose secret values to the desktop interface merely to support user decisions.

### Failure modes the design addresses

Before Phase 2 all of these silently kept local. F1 now merges automatically. F2, F3, and F4 surface the panel.

| Mode | Scenario | Severity | Outcome now |
|------|----------|----------|-------------|
| F1 | Same entry, non-overlapping fields (desktop edits the password, mobile edits the notes) | Was silent field loss | `merge_ciphers` merges both edits. No panel. |
| F2 | Same entry, same field, divergent values (two different new passwords) | High | `merge_3way_field` records a `FieldConflict`. The user decides which side wins. |
| F3 | Entry kind changed on one side (Login converted to SecureNote or another kind) | Medium | `merge_ciphers` flags a cross-type conflict on `type`. Destructive and hard to recover, so the user decides. |
| F4 | Semantic-group divergence | Medium | `SEMANTIC_GROUPS` in `conflict.rs` treats username, password, and TOTP URI as one atomic unit. If any one conflicts, all three are flagged. |

Non-failures that never open the panel: different entries edited concurrently (clean fast-forward); a one-sided edit (`merge_3way_field` applies the changed side); network failure (`SyncCycleOutcome::Offline`, the retry path); a rejected non-fast-forward push (reruns the cycle).

## Decision

### Engine and daemon flow

The sync engine uses `run_sync_cycle_with_resolver` with a pause resolver for automatic synchronization. The coordinator calls it with a `ConflictResolution::Pause` closure. On a pull conflict the cycle returns `SyncCycleOutcome::NeedsDecision { pending }`. The coordinator stores the `PendingConflictState` on its inner state and enters `AutoSyncState::NeedsDecision`. The `run_sync_cycle` wrapper without a resolver still delegates with `KeepLocal`.

The `sync.conflict` route drives `VaultState::conflict_decrypt_and_merge`. It decrypts base, local, and remote cipher data through `VaultHandle::decrypt_cipher_bytes`, which derives the item key per envelope from the held `SpaceGroupKey`, and calls `conflict::merge_ciphers`:

- `MergeResult::Merged`: re-encrypt under the merging device's current epoch with sequence number `max(local_seq, remote_seq) + 1`, then `finalize_conflicts` writes a two-parent merge commit and pushes. No panel.
- `MergeResult::Conflict`: surface a masked conflict for the user verdict.
- Cross-epoch: a side is at an epoch this device cannot decrypt. Decryption fails closed (it uses `SpaceGroupKey::try_derive_item_key`, which returns `None` on an epoch mismatch, not the panicking derivation). The response carries a `cross_epoch` flag. Only `keep_local` and `keep_remote` remain safe verdicts, because they select a raw blob without decrypting. `keep_both` is refused, since a side that cannot be read cannot be cloned. The panel hides the keep-both option when `crossEpoch` is set.

The merge algorithm is a three-way field merge. One-sided changes and non-overlapping edits merge automatically. Username, password, and TOTP URI form an atomic semantic group, and divergence in any member raises a conflict for the whole group. A change of cipher kind is a structural conflict.

### Panel behavior and decision granularity

The desktop presents the panel only when automatic merging returns a conflict. It queues every pending conflict from a sync cycle (one or more entries may diverge in a single sync). The user chooses one verdict per entry:

1. `keep_local`: this device's version wins. This matches the old silent behavior but is now explicit and user-chosen, and is the default-safe option because it reflects what the device in the user's hand just did.
2. `keep_remote`: the other device's version wins and the local change is discarded.
3. `keep_both`: duplicate the entry so neither version is lost. This is the non-destructive escape hatch for "I am not sure, both matter". It costs a duplicate to reconcile later but never destroys data.

Per-field selection is excluded. It would require shipping secret values to the UI (rejected below) and is too complex for the non-technical target user.

Never auto-decide destructively. A conflict TTL with an automatic keep-local fallback was considered and rejected. The panel is non-dismissable until a verdict is chosen.

### Security: what the panel may show

`FieldConflict` deliberately does not derive `Serialize` or `Deserialize` and holds plaintext local and remote values, including passwords, TOTP URIs, card numbers, and private keys. The panel follows the codebase-wide invariant that TOTP seeds and private keys never cross IPC. The daemon returns masked conflict metadata only:

- The entry name (plaintext metadata).
- The cipher type, for the icon and plain-language label.
- The list of conflicting field labels, each with a `sensitive` flag. Non-sensitive fields (name, username, notes, URIs) may show the divergent values. Sensitive fields (password, TOTP, card number and code, private key) are masked only ("Password was changed on both devices"); the value never crosses IPC.
- Optional friendly device names for plain language.

Users decide by side, not by reading the secret. No plaintext secret is serialized, transmitted, or rendered. The daemon builds the masked metadata on demand and never persists decrypted conflict data.

### Frontend data contract

The context holds a queue of entries with this shape:

```ts
type PendingConflict = {
  cipherId: string;          // opaque id for routing, never displayed
  name: string;              // entry display name (plaintext metadata)
  cipherType: CipherType;    // "login" | "card" | ... (icon + label)
  typeChanged: boolean;      // F3: one side changed the entry kind
  fields: Array<{
    key: string;             // "password" | "notes" | ...
    label: string;           // localized, human-readable field name
    sensitive: boolean;      // true => mask, never show value
  }>;
  localDevice: string | null;  // friendly device name
  remoteDevice: string | null; // friendly device name
};

type ConflictVerdict = "keep_local" | "keep_remote" | "keep_both";
```

`typeChanged: true` overrides the per-field list. The whole entry shape differs, so the panel explains it at the entry level ("changed from a login to a note") and does not imply per-field selection. The cross-epoch case adds a `crossEpoch` flag on the queue entry, derived from the daemon's `cross_epoch` field.

### Verdict application

For `keep_local` and `keep_remote`, the engine selects the chosen side's existing blob by object ID. The envelope is already valid and its AAD is consistent, so the blob is neither decrypted nor re-encrypted. For `keep_both` (`conflict_resolve_keep_both`), the local blob stays untouched at the original cipher path, and the remote content is decrypted and written at `ciphers/<new_id>.enc` under a fresh UUID, the current epoch, and sequence number 1, mirroring `add_cipher`. Both land in one merge commit.

After any verdict the engine finalizes the merge and rebuilds the cipher index (`rebuild_cipher_index()`), because direct sync writes go through `SyncEngine` and bypass the `VaultHandle` add, update, and delete hooks that normally rebuild `meta/index.enc`. Without the rebuild a `keep_both` clone with a new cipher ID would be invisible in the vault list. `finalize_conflicts` is HEAD-guarded against double resolution. If the merge commit lands but the push fails, it returns a network error, and the caller must still call `note_resolved` or the conflict wedges against the advanced HEAD.

### Coordinator lifecycle

While paused, the background loop and debounce do not fire. `nudge` increments the pending-mutation counter and returns early when the state is `NeedsDecision`, so mutations queue instead of freezing the debounce window. The coordinator holds `PendingConflictState` in memory only. Resolution calls `note_resolved`. The coordinator returns to the dirty state only after the queue is empty, so the merge commit and the queued mutations synchronize on the next cycle. Network failures remain offline-retry conditions and do not open the panel. `pull_inner` must leave the state machine in `Merging` (not `Idle`) on a conflict, because the final `Merging` to `Idle` transition in resolution is what completes the cycle.

The queue is not persisted. The daemon-side `pending_conflicts` drains on `deactivate()` (vault lock). The frontend `ConflictResolutionContext` queue clears on lock (the vault subtree unmounts, destroying the signals) and clears explicitly on vault switch (the `activeSlug` effect in `AutoSyncContext` calls `conflicts.clear()`, because the keep-unlocked model keeps the provider mounted across switches). `refresh()` captures the slug before its awaits and re-checks it afterward, so a stale poll for vault A cannot enqueue A's conflict into vault B's view.

The desktop polls `sync.conflict` every 10 seconds (`POLL_MS`) while autosync reports `NeedsDecision`.

## Consequences

Non-overlapping edits no longer lose data silently, and the user makes explicit choices only for ambiguous or structural conflicts. Sensitive values remain within the daemon and vault cryptographic boundary.

`keep_both` preserves both versions but creates a duplicate that the user may need to reconcile later. `keep_local` and `keep_remote` intentionally discard the other side's version after an explicit choice. The cross-epoch case limits the user to those two destructive verdicts.

The panel remains non-dismissable until a verdict is selected.

### Open items

- Stuck-queue escape, still open. The panel's `decide()` keeps the conflict in the queue when the resolver throws (retry-friendly), and shows a failure toast. If `sync.conflict.resolve` permanently fails (daemon down, item key unrecoverable), the head never leaves the queue and the user is locked behind a modal whose actions all fail. Candidate resolutions: (a) a maximum-retry counter that falls back to a safe non-destructive state such as "skip for now, re-merge on next sync" after N consecutive failures; (b) a manual escape hatch (close and re-queue through persistent state, or a link to logs); (c) an explicit product decision to keep the modal hard-blocking. It is tracked as `TODO(stuck-queue)` in `ConflictResolutionPanel.jsx`. That comment still says the route is not wired yet. The route is wired, so the comment is stale.
- Full two-vault integration test. Unit tests cover the engine integration (`run_sync_cycle_with_resolver_pause_and_finalize`, `run_sync_cycle_backward_compat_uses_keep_local`) and the cross-epoch guard (`try_derive_item_key_returns_none_on_epoch_mismatch`). The complete decrypt, merge, re-encrypt, and finalize round trip across two real vaults with key rotation is not yet covered.

## References

- ADR 0004, conflict auto-resolution and index healing: `docs/adr/0004-conflict-auto-resolution-index-healing.md`.
- ADR 0025, the short record of the panel: `docs/adr/0025-conflict-resolution-panel.md`.
- ADR 0006, desktop auto-sync: `docs/adr/0006-desktop-auto-sync.md`.
- `crates/baluard-core/src/sync/engine.rs`
- `crates/baluard-core/src/sync/conflict.rs`
- `crates/baluard-runtime/src/state.rs`
- `crates/baluard-runtime/src/autosync.rs`
- `desktop/src/components/ConflictResolutionPanel.jsx`
- `desktop/src/lib/conflictFlow.js`
