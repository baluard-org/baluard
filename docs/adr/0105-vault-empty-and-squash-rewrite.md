# ADR 0105: `baluard vault empty` and the squash history rewrite

Date: 2026-11-10
Status: accepted
Design: docs/designs/vault-empty.md (readiness report: vault-empty.egm-report.md; peer review folded in)

## Context

Emptying a vault required a hand-rolled loop over `list`/`delete`/`trash purge`, and no mechanism existed to scrub entry blobs from git history. The only fresh-start path deleted the vault and re-enrolled every device.

## Decision

`baluard vault empty [--rewrite-history] [--phrase] [--yes]`, personal vaults only (refused when `space_meta::shape_flipped`).

**Phrase gate.** The 24 recovery words are proven by HPKE-unwrapping `meta/recovery.json` (`recovery-keywrap`) plus `verify_rk_canary`; the recovery kit escrow is the fallback. Wrong words, a stale post-rotation escrow, and a missing escrow produce distinct errors. Phrase attempts are the only ones that burn the route's rate limiter; post-wipe failures (push, timeout) never lock `vault.unlock`.

**Wipe.** `VaultHandle::empty_entries`: enumerate, then soft-delete all live+archived entries (batch: index rebuild deferred), purge the entire trash with no mtime cutoff (`purge_trash_impl(None)`; a future-dated file cannot survive), drop each purged checkpoint, wipe folders and the tag store, rebuild the index, and fail if anything survived. Semantic `meta/` state survives; caches update normally.

**Rewrite.** `rewrite_history_squash` MINTS targets without moving refs: one signed orphan carrying the emptied tree, plus one empty-tree gossip orphan. `push_rewritten` pushes them by OBJECT ID (`+<sha>:refs/heads/...`); local main, gossip, HEAD and tracking refs move only after the push lands. A rejected push therefore leaves the device on its old, still-pullable lineage — retry is a plain re-run, no wedge. Local prune (`git reflog expire --expire=now --all && git gc --prune=now`) runs inside the autosync cycle lock after a landed push; in direct mode the CLI prunes itself.

**Gossip reset is mandatory for erasure.** Announcement commits parent the announced heads; without the reset, `refs/heads/baluard-gossip` anchors every pre-rewrite blob forever on the remote, in fresh clones, and against local gc. Enforcement needs no reset: announcements bind the vault tag (root-commit oid), so pre-rewrite announcements fail verification under the new root and stay inert by the deny-only rule.

**Pull guard.** `SyncError::HistoryRewritten` refuses any pull whose remote tip roots on a different commit than local (recorded to the refusal log like every refusal). Without it, an old device would merge discarded history back. `migrate_remote` preserves the root and passes; the guard cannot exempt the rewriting device because it compares root oids — with push-by-sha it never triggers for that device, since refs move only after a landed push.

**Integrity checkpoint drops.** `integrity_delta_ok` now admits dropping a checkpoint only when no `<id>.enc` object survives under `ciphers/` or `trash/` in the committed tree (peer walk) or the worktree accounting for deletions this staging pass SKIPS and restores (`stage_admitted` is decide-then-apply for exactly this). Dropping a checkpoint while the object survives is still laundering and is reverted.

## Consequences

- Other devices must detach and re-clone after a rewrite; the pull guard turns that contract into an enforced refusal with a clear message. Enrollment survives (`meta/devices.json` rides the emptied tree).
- The rewrite is irreversible once pushed. The phrase gate, the personal-vault gate, and printed consequences are the mitigations; a failed push is now harmless (nothing moved locally).
- Known limitations, accepted: two-step rollback laundering (delete and drop in one commit, then re-add an older blob) is blocked only by roster membership — a tombstone seq floor is future work; revocation entries whose target commits died with the rewrite are inert forever; `sync revoke` from an un-pulled old device cannot land post-rewrite (non-ff) and that entry is lost on re-clone; remote hosts may retain unreachable objects until their own gc — absolute erasure can use `sync remote` to a fresh repo.
- The phrase flows over daemon IPC like the enroll route does, zeroized on every exit; a `vault.add` landing between the wipe and the squash is captured by the rewrite (documented, acceptable).
