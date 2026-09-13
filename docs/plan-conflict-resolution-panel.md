# Conflict Resolution Panel: failure modes + design contract

Status: **Phase 2 implemented (2026-07-02).** Backend wired: engine integration (`run_sync_cycle_with_resolver`, `ConflictResolution`, `NeedsDecision`, `finalize_conflicts`), daemon decrypt + `merge_ciphers` (`conflict_decrypt_and_merge`), `keep_both` (`conflict_resolve_keep_both`), frontend real IPC (`conflictFlow.js`, AutoSyncContext poll, panel resolver). Open: stuck-queue escape (see below).
Related: `crates/baluard-core/src/sync/engine.rs`, `crates/baluard-core/src/sync/conflict.rs`, `crates/baluard-daemon/src/state.rs`, `crates/baluard-daemon/src/autosync.rs`, `desktop/src/components/ConflictResolutionPanel.jsx`, `desktop/src/lib/conflictFlow.js`.

## Goal

A top-floating, modal-like panel (subtle slide-down animation) shown **only** when
the automatic sync path cannot safely consolidate an item edited on two devices.
It lets a non-technical user pick between keeping their local version, the remote
version, or keeping both as separate entries. This is the human-in-the-loop
backstop for the destructive cases the auto path used to resolve silently.

## Scope (current)

Phase 2 added the engine integration + daemon decrypt/merge + verdicts + frontend
wiring on top of the original UI-only panel. The cycle now runs `merge_ciphers`
on pull conflicts; auto-mergeable cases (F1) resolve with no prompt; same-field
conflicts (F2/F4) and type-change conflicts (F3) surface this panel. The
remaining open item is the **stuck-queue escape** (the panel is non-dismissable;
a permanently-failing `sync.conflict.resolve` IPC would lock the user out).

## How conflicts are now handled (Phase 2)

The authoritative cycle is `SyncEngine::run_sync_cycle_with_resolver`
(`sync/engine.rs`), which the daemon's auto-sync coordinator calls with a
`ConflictResolution::Pause` closure. On a pull conflict:

```rust
match engine.run_sync_cycle_with_resolver(&repo, &mut |_| ConflictResolution::Pause) {
    Ok(SyncCycleOutcome::NeedsDecision { pending }) => { /* coordinator holds it */ }
    ...
}
```

The coordinator (`autosync.rs`) stores the `PendingConflictState` and enters
`AutoSyncState::NeedsDecision` (the background loop and debounce do NOT fire
while paused; `nudge` queues mutations for after the drain).

The `sync.conflict` route then drives `VaultState::conflict_decrypt_and_merge`,
which decrypts base/local/remote via `VaultHandle::decrypt_cipher_bytes` (item
key derived per-envelope from the held `SpaceGroupKey`; cross-epoch decrypt
failure fails closed) and runs `conflict::merge_ciphers`:

- **`MergeResult::Merged`** → re-encrypt under the merging device's
  `current_epoch` + `max(local_seq, remote_seq)+1` and `finalize_conflicts`
  (writes a 2-parent merge commit + pushes). **No panel.**
- **`MergeResult::Conflict`** → surface a masked `MaskedConflict` (name, type,
  field labels + sensitive flag; NO plaintext values) for the user verdict.
- **Cross-epoch** (a side is at an epoch this device can't decrypt) → surface
  a `cross_epoch` flag; only keep_local/keep_remote (raw blob, no decrypt)
  remain safe verdicts. `keep_both` is refused (can't clone a side we can't read).

`sync.conflict.resolve` applies the verdict:
- **keep_local / keep_remote** → raw blob selection from the chosen side's OID
  (the envelope is already valid + AAD-consistent; no re-encrypt).
- **keep_both** → `conflict_resolve_keep_both`: local stays at the original path
  (untouched blob) + a fresh cipher under a new uuid at `ciphers/<new_id>.enc`
  with the remote content re-encrypted under the new id + current epoch + seq 1
  (mirrors `add_cipher`). Both land in one merge commit.

All three paths call `rebuild_cipher_index()` after `finalize_conflicts`, since
they write cipher files directly via `SyncEngine` (bypassing the
`VaultHandle::add/update/delete` hooks that normally rebuild `meta/index.enc`).

Storage layout matters: each cipher lives at `ciphers/<cipher_id>.enc` (flat), so a
git-level conflict only fires when **the same cipher** is touched on two
devices. Two different ciphers edited concurrently never conflict (different
paths, fast-forward cleanly).

### The failure modes the panel exists for (F2/F3/F4)

(Pre-Phase-2, ALL of these silently kept local. Now F1 auto-merges; F2/F3/F4
surface the panel.)

### F1. Same item, non-overlapping fields: NOW auto-merged (was silent field loss)

Desktop edits the **password**, mobile edits the **notes** of the same entry.
`merge_ciphers` merges cleanly (different fields). **No panel fires.** Both
edits land in the merged cipher.

### F2. Same item, same field, divergent values: true conflict (HIGH severity)

Desktop changes the GitHub password to `A`. Mobile changes the same password to
`B`. `merge_3way_field` (`conflict.rs:204`) records a `FieldConflict` (both
sides changed, differ). Today: keep local (`A`), discard `B` silently. The user
should decide which password wins.

### F3. Entry type changed on one side: structural conflict (MEDIUM severity)

Desktop keeps "GitHub" as a Login. Mobile converts it to a SecureNote (or a
different cipher kind). `merge_ciphers` flags a cross-type conflict on `type`.
Today: keep local kind, discard the remote shape. Destructive and hard to
recover.

### F4. Semantic-group divergence (atomic unit) (MEDIUM severity)

`merge_ciphers` groups security-sensitive fields as atomic units
(`SEMANTIC_GROUPS` in `conflict.rs`): username + password + TOTP move together.
If any one conflicts, all three are flagged. Today none of this runs; keep-local
discards the remote group wholesale.

### Non-failures (no panel)

- Different items edited concurrently → no file conflict → clean fast-forward.
- One-sided edit → `merge_3way_field` applies the changed side → no conflict.
- Network failure → `SyncCycleOutcome::Offline`, retry path, no data decision.
- Push rejected (non-fast-forward) → re-runs the cycle, no user decision.

## When the panel fires (implemented trigger)

Implemented in `run_sync_cycle_with_resolver` + `conflict_decrypt_and_merge`:

1. On `PullResult::Conflict`, the cycle pauses (returns
   `SyncCycleOutcome::NeedsDecision { pending }`); the coordinator holds the
   `PendingConflictState` and enters `NeedsDecision`.
2. The `sync.conflict` route runs `merge_ciphers` on the decrypted base/local/remote.
3. `MergeResult::Merged` → re-encrypt + `finalize_conflicts` (no panel).
4. `MergeResult::Conflict` → surface the masked `MaskedConflict` via the route;
   AutoSyncContext's 10s poll feeds it to the panel queue.
5. `sync.conflict.resolve` applies the user's verdict + drains the queue
   (`note_resolved` → Dirty if empty, so queued mutations + the merge sync).

The panel consumes a queue of pending conflicts (one or more entries may have
diverged in a single sync).

## Security: what the panel may show

`FieldConflict` (`conflict.rs:67`) deliberately does **not** derive
`Serialize`/`Deserialize` and holds plaintext local/remote values, including
passwords, TOTP URIs, card numbers, private keys. Mirroring the codebase-wide
invariant ("TOTP seed NEVER crosses IPC", "private key never crosses IPC"), the
panel shows:

- The entry **name** (metadata, plaintext, safe).
- The **cipher type** (for the icon + plain-language label).
- The list of **conflicting field labels** with a `sensitive` flag.
  - Non-sensitive (name, username, notes, URIs): may show the divergent values.
  - Sensitive (password, TOTP, card number/code, private key): **masked only**
    ("Password was changed on both devices"). The actual value never crosses IPC.

Users decide by **side**, not by reading the secret. No plaintext secret is
serialized, transmitted, or rendered.

## Decision granularity

Per entry. Three options, ordered simplest-first:

1. **Keep this device's version**: local wins (matches current keep-local
   behavior, but now explicit and user-chosen). Default-safe because it is what
   the device the user is holding just did.
2. **Keep the other device's version**: remote wins; local change is discarded.
3. **Keep both as separate entries**: duplicate the entry so neither version is
   lost. The non-destructive escape hatch for the "I'm not sure / both matter"
   case. Costs a duplicate to reconcile later, but never destroys data.

Per-field picking is intentionally excluded: it requires shipping secret values
to the UI (rejected above) and is too complex for the non-technical target user.

## Frontend data contract (consumed by ConflictResolutionPanel)

The context signal holds a queue of:

```ts
type PendingConflict = {
  cipherId: string;          // opaque id, never displayed
  name: string;              // entry display name (plaintext metadata)
  cipherType: CipherType;    // "login" | "card" | ... (icon + label)
  typeChanged: boolean;      // F3: one side changed the entry kind
  fields: Array<{
    key: string;             // "password" | "notes" | ...
    label: string;           // i18n'd, human-readable field name
    sensitive: boolean;      // true => mask, never show value
  }>;
  localDevice: string | null;  // friendly device name, for plain language
  remoteDevice: string | null; // friendly device name
};

type ConflictVerdict =
  | "keep_local"
  | "keep_remote"
  | "keep_both";
```

`typeChanged: true` overrides the per-field list: the whole entry shape differs,
so the panel explains it at the entry level ("changed from a login to a note").

## Open questions

- ~~Where is `ConflictInfo` held while paused?~~ **Answered:** the engine-side
  `PendingConflictState` lives on the autosync coordinator's `Inner`; the
  decrypted `MaskedConflict` is built on demand in `conflict_decrypt_and_merge`
  (never persisted).
- ~~Does a paused block freeze the debounce window, or queue mutations?~~
  **Answered (queue):** `nudge` increments `pending` and returns early when
  state is `NeedsDecision`; `note_resolved` transitions to `Dirty` when the
  queue empties so the merge commit + queued mutations sync on the next cycle.
- ~~Conflict TTL / auto-keep-local?~~ **Answered:** never auto-decide
  destructively; the panel is non-dismissable until a verdict is chosen.
- **Frontend queue lifecycle (Phase 4, answered):** the daemon-side
  `pending_conflicts` drains on `deactivate()` (lock). The frontend
  `ConflictResolutionContext` queue: cleared automatically on lock (the vault
  subtree unmounts via `<Show>`, destroying the queue signals) AND cleared
  explicitly on vault switch (`AutoSyncContext`'s `activeSlug` effect calls
  `conflicts.clear()`, because the keep-unlocked model keeps the provider
  mounted across switches). `refresh()` also captures the slug before its
  awaits and re-checks after, so a stale poll for vault A can't re-enqueue
  A's conflict into vault B's view after the clear.
- **Stuck-queue escape (resolve-failure path), STILL OPEN.** The panel's
  `decide()` keeps the conflict in the queue when the resolver throws
  (retry-friendly), and the panel is non-dismissable. If the real
  `sync.conflict.resolve` IPC permanently fails (daemon down, item key
  unrecoverable), the head never leaves the queue and the user is locked behind
  a modal whose actions all fail. Tracked as `TODO(stuck-queue)` in
  `ConflictResolutionPanel.jsx::decide`. Resolution options for a future pass:
  (a) max-retry fallback to a safe non-destructive state, (b) a manual escape
  hatch (close + re-queue via persistent state, or a link to logs), (c) an
  explicit product decision to keep the modal hard-blocking.
- **Full two-device crypto integration test.** The engine integration has unit tests
  (`run_sync_cycle_with_resolver_pause_and_finalize`,
  `run_sync_cycle_backward_compat_uses_keep_local`) and the cross-epoch guard
  has a unit test (`try_derive_item_key_returns_none_on_epoch_mismatch`). The
  full decrypt→merge→re-encrypt→finalize round-trip across two real vaults with
  rotation is deferred to a dedicated integration test pass.
- **Stuck-queue escape (resolve-failure path).** The panel's `decide()` keeps
  the conflict in the queue when the resolver throws (retry-friendly), and the
  panel is non-dismissable. If the real `sync.conflict.resolve` IPC
  permanently fails (daemon down, item key unrecoverable), the head never
  leaves the queue and the user is locked behind a modal whose actions all
  fail. Acceptable today because the route isn't wired yet (dev-only mock
  triggers). When wiring lands, add one of: (a) a max-retry counter that falls
  back to a safe non-destructive state (e.g. "skip for now, re-merge on next
  sync") after N consecutive failures, (b) a manual escape hatch (close +
  re-queue via persistent state, or a link to logs), or (c) an explicit product
  decision to keep the modal hard-blocking. Tracked as `TODO(stuck-queue)` in
  `ConflictResolutionPanel.jsx::decide`.
