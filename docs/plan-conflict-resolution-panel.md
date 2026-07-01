# Conflict Resolution Panel — failure modes + design contract

Status: **Design / UI built. Backend wiring deferred (see Scope).**
Related: `crates/baluard-core/src/sync/engine.rs`, `crates/baluard-core/src/sync/conflict.rs`, `desktop/src/components/ConflictResolutionPanel.jsx`.

## Goal

A top-floating, modal-like panel (subtle slide-down animation) shown **only** when
the automatic sync path cannot safely consolidate an item edited on two devices.
It lets a non-technical user pick between keeping their local version, the remote
version, or keeping both as separate entries. This is the human-in-the-loop
backstop for the destructive cases the auto path currently resolves silently.

## Scope (explicit)

We do **not** change the sync engine's state machine in this pass. This document
defines (a) how the current infra fails, (b) exactly when the panel should fire,
and (c) the data contract the UI consumes. The UI panel itself is built now and
driven by a mockable frontend signal; the daemon route that feeds it is a
follow-up.

## How the current infrastructure can fail (destructive paths)

The authoritative cycle is `SyncEngine::run_sync_cycle` (`sync/engine.rs:1053`):

```
commit local  →  pull  →  resolve conflicts  →  push
```

The pull step returns `PullResult::Conflict { files, local_oid, remote_oid }`
when git reports a **file-level** conflict: the same path was modified on both
sides. In production the resolution is unconditional:

```rust
self.resolve_conflict_keep_local(repo, local_oid, remote_oid, &files)?;
conflicts = 1;
```

`resolve_conflict_keep_local` (`engine.rs:1026`) takes the **local bytes
wholesale** for every conflicting file and ignores the remote content. It then
builds a 2-parent merge commit so the next push fast-forwards. The frontend only
ever learns the integer `conflicts_resolved` via `sync.autosync_status`.

Storage layout matters: each cipher lives at `entries/<cipher_id>/...`, so a
git-level conflict only fires when **the same cipher** is touched on two
devices. Two different ciphers edited concurrently never conflict (different
paths, fast-forward cleanly).

The field-level 3-way merge `merge_ciphers` (`sync/conflict.rs:89`) **exists and
is tested, but is never called** in the production cycle. It can auto-merge
non-overlapping fields and detect true conflicts (`MergeResult::Conflict`). It is
dormant.

From this, the destructive failure modes where the panel should eventually fire:

### F1. Same item, non-overlapping fields — silent field loss (HIGH severity)

Desktop edits the **password** of "GitHub". Mobile, before pulling, edits the
**notes** of the same "GitHub" entry.

- Git path conflict on `entries/<id>/...`.
- `resolve_conflict_keep_local` keeps the local file. The remote notes edit is
  **discarded entirely**.
- `merge_ciphers` would have merged these cleanly (different fields, no
  conflict). But it is not wired in, so the loss is silent.
- The user sees only: "This item was also edited on another device. We kept the
  most recent version." — a claim that is **not** what happened (we kept local,
  not "most recent").

This is the primary case the user wants surfaced. Even after `merge_ciphers` is
wired, this case auto-resolves and the panel is NOT needed. The panel is needed
for F2/F3.

### F2. Same item, same field, divergent values — true conflict (HIGH severity)

Desktop changes the GitHub password to `A`. Mobile changes the same password to
`B`. `merge_3way_field` (`conflict.rs:204`) records a `FieldConflict` (both
sides changed, differ). Today: keep local (`A`), discard `B` silently. The user
should decide which password wins.

### F3. Entry type changed on one side — structural conflict (MEDIUM severity)

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

## When the panel fires (trigger contract)

The panel is shown when, and only when, the sync engine hits a conflict it
cannot auto-merge and decides to defer to the user instead of silently keeping
local. Concretely, the future backend wiring (not in this pass):

1. In `run_sync_cycle`, on `PullResult::Conflict`, run `merge_ciphers` per
   conflicting cipher instead of unconditionally `resolve_conflict_keep_local`.
2. If `MergeResult::Merged` → write the merged cipher, continue (no panel).
3. If `MergeResult::Conflict` → **pause** the cycle, hold the `ConflictInfo`
   in memory on `VaultState`, return a new `SyncCycleOutcome::NeedsDecision`,
   and surface the conflict (masked, see below) via a `sync.conflict` route.
4. On `sync.conflict.resolve`, resume the cycle with the user's verdict.

The panel consumes a queue of pending conflicts (one or more entries may have
diverged in a single sync).

## Security: what the panel may show

`FieldConflict` (`conflict.rs:67`) deliberately does **not** derive
`Serialize`/`Deserialize` and holds plaintext local/remote values — including
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

1. **Keep this device's version** — local wins (matches current keep-local
   behavior, but now explicit and user-chosen). Default-safe because it is what
   the device the user is holding just did.
2. **Keep the other device's version** — remote wins; local change is discarded.
3. **Keep both as separate entries** — duplicate the entry so neither version is
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

## Open questions (for the backend wiring pass)

- Where is `ConflictInfo` held while paused? `VaultState` is the natural home;
  it must be zeroized on drop / lock (the struct already implements `Drop`).
- Does a paused block freeze the auto-sync coordinator's debounce window, or
  queue new mutations behind the decision? Recommendation: queue (do not lose
  the user's newer edits) and re-merge after the verdict.
- Conflict TTL: if the user ignores the panel for hours, do we auto-keep-local
  after a warning? Recommendation: never auto-decide destructively; the panel is
  non-dismissable until a verdict is chosen (it is modal by design).
