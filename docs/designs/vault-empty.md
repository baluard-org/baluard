# Design: `baluard vault empty`

Status: implemented. Readiness report: vault-empty.egm-report.md (blockers and majors folded in). peer review 2026-11-10 folded in: push-by-sha before ref moves, decide-then-apply staging with a restore-aware checkpoint-drop rule, prune inside the cycle lock, rate-limit burn scoped to phrase rejections, no-cutoff trash purge with an emptiness assertion, refusal log entry for the HistoryRewritten guard. ADR: docs/adr/0105-vault-empty-and-squash-rewrite.md.
Owner: Esteban
Scope: CLI only (desktop/mobile parity deferred)

## Problem

Emptying a vault today needs a hand-rolled loop over `list`/`delete`/`trash purge`, and there is no way to scrub old entry blobs from git history. Users who want a fresh start are forced to delete the vault and re-enroll every device, losing settings, folders, and sync setup.

## Goal

One CLI command that permanently removes all entries (live, archived, trashed, plus folders and tags) from the active vault, gated by the 24-word recovery phrase, with an opt-in history rewrite that leaves the repository carrying no entry blobs reachable from any fetched ref. Settings, devices, collections, members, and all other semantic `meta/` state survive. Personal vaults only for the first cut.

## Non-goals

Desktop and mobile UI. Shared (Space/family) vault support. Rotating the root key (users who want crypto-level erasure of pre-rewrite history snapshots can still run `rotate-root` afterwards; that command already exists).

## UX

```
$ baluard vault empty
Vault: baluard-personal
Removes: 42 entries (38 live, 2 archived, 2 in trash), 4 folders, 6 tags
Keeps: settings, devices, collections, members, sync setup
Recovery phrase (24 words): ********
Emptying vault... done. 42 entries removed.
```

Confirmation = the vault's own 24 recovery words. Phrase resolution order matches `enroll-with-phrase`: `--phrase` flag > `BALUARD_RECOVERY_PHRASE` env (argv warning) > masked prompt. A wrong phrase aborts with zero changes. `--yes` is scripting sugar only; it does not bypass the phrase.

`--rewrite-history` appends to the flow: squash all of main into a single new root commit carrying the emptied tree, reset the gossip branch, force-push both, prune local old objects, and print per-device re-clone instructions.

## Gates

1. Personal shape: refuse when `space_meta::shape_flipped(&path)` is true (`meta/space-shape.json` mode `team`). This is the canonical detector with precedent in the personal phrase-rotation path. Do NOT key off `meta/members/` — every post-S1a personal vault carries member rows (owner row at creation).
2. Recovery phrase must unwrap this vault's root key. Shape check (`RecoveryPhrase::from_phrase`, 24 words) is not enough; the HPKE unwrap against `meta/recovery.json` is the proof. Distinct error cases: unwrap failure = wrong words; unwrap success but `meta/rk-canary.enc` failure = stale escrow (post `rotate-root` on a legacy escrow) with a dedicated message telling the user to re-enroll with the phrase to refresh the escrow.
3. Vault must be unlocked (daemon session or `BALUARD_PASSWORD`/prompt in direct mode). Deletion moves and the index rebuild need the open handle.
4. Daemon route rate-limits phrase attempts with `claim_attempt` (failure counts, success commits), mirroring `vault.enroll_with_phrase`. Phrase is zeroized on every exit path.

## Core changes (baluard-core)

### `verify_recovery_phrase(vault_path, phrase) -> Result<(), BaluardError>`

Parse, derive seed, X25519 secret from `seed[0..32]`, `hpke_wrap::unwrap_key` against `meta/recovery.json` with the `recovery-keywrap` context, then `verify_rk_canary` on the recovered key against `meta/rk-canary.enc` (fail-closed read; precedent: handle.rs rk-canary paths). Personal escrow absent → try the recovery kit escrow: `recover_root_from_kit(vault_path, vault_id, phrase)` with vault_id resolved via the existing `vault_id_for_path` helper. Both escrows absent → explicit error. Canary failure after successful unwrap → dedicated stale-escrow error, not the wrong-phrase error.

### `VaultHandle::empty_entries() -> Result<EmptyReport, BaluardError>`

`EmptyReport { entries: usize, folders: usize, tags: usize }`.

Prerequisite fix: `delete_cipher`'s flat-cipher role gate refuses on legacy (pre-S1a) personal vaults because `member_role_for_device` returns `None` without `meta/members/`. Extend the flat arm with the same legacy-founder fallback `assert_collection_write` already uses (`is_admin || meta/members/ absent`) — a latent bug fix this feature needs, matching existing precedent.

Order matters: enumerate first, mutate second, so a failure mid-loop cannot leave a half-counted vault.

1. Guards: `writes_allowed`, personal-shape check (gate 1).
2. Count and soft-delete live+archived (`list_cipher_ids` → batch delete). Batch = internal delete path with the per-delete `rebuild_index` suppressed (precedent: `add_cipher_batch`); one rebuild at the end.
3. `purge_old_trash(0)` — permanent removal, attachment dir cleanup (`entries/<id>/`). Extend `purge_old_trash` to drop the integrity checkpoint per purged id (mirroring `delete_cipher`'s trash branch): without it, entries already in trash before the command leave stale checkpoints and `detect_rollback` prints permanent rollback warnings on every open. Test: empty a vault with pre-existing trash, reopen, zero rollback warnings.
4. Folders: save the empty folder set through the existing per-fact folder store (its save path prunes orphan files).
5. Tags: clear the tag index through its existing store.
6. Final `rebuild_index`.

Semantic `meta/` state is never touched: settings, devices, collections, members, KDF, canaries, avatar, activity ride along. Caches do update as usual (`meta/index.enc`, `meta/integrity.json`) — that is expected, not a violation.

### Sync engine: `rewrite_history_squash(repo) -> Result<Oid, BaluardError>`

1. `commit_all` so the emptied worktree is one clean snapshot.
2. Build the tree from the current index; create ONE orphan commit (no parents) signed with this device's key via the existing `create_signed_commit` (roster genesis rule admits a signed orphan with `meta/devices.json` in-tree — verified).
3. Force-update `refs/heads/<default>` to the orphan and `set_head`.
4. Reset the gossip branch. Announcement commits carry the announced main head as a second parent, so the remote's `baluard-gossip` tip anchors every pre-rewrite head and keeps old blobs reachable forever (defeats remote gc, fresh clones, and local gc alike). Create a gossip orphan commit with an empty tree (no `heads/` announcements; plain commit like `announce_head` writes), force-update the local gossip ref (`refs/notes/baluard-gossip`), and delete the legacy `baluard-gossip` heads branch left by pre-relocation versions.
5. Force-push both refs in one push: `+refs/heads/<default>:refs/heads/<default>` and `+refs/notes/baluard-gossip:refs/notes/baluard-gossip`, reusing the existing credential callbacks. Post-rewrite `announce_head` seeds from the fetched gossip tip and pushes non-force — it now sees the clean orphan tip on both sides, so normal operation resumes.

Gossip enforcement: announcements bind `vault_tag` = root-commit oid, so pre-rewrite announcements fail `verify()` under the new root oid and are inert by the deny-only rule (assessed acceptable in S1b-3). Resetting the branch is for erasure, not enforcement. A test pins both facts.

### Push-failure recovery (documented, procedural)

The `HistoryRewritten` guard (below) compares root oids and cannot exempt the rewriting device: if the force-push fails, local root != remote root and every autosync cycle refuses. Recovery is procedural and printed by the CLI: re-run `baluard vault empty --rewrite-history` (idempotent — an already-emptied vault reports zero entries, squash + gossip reset re-run, push retried), or fall back to `sync remote` pointing at a fresh repo. A failed push also means re-cloning another device would resurface old entries; the erasure must be redone after the push lands.

### Pull guard: `SyncError::HistoryRewritten`

In `pull_inner`, after fetch and next to the `check_head_gossip` call, BEFORE the up-to-date early return: if remote tip's root-commit oid != local root-commit oid (`root_commit_oid_from` exists), refuse. Without this, an old device pulling after a rewrite would merge the discarded history back, resurrecting deleted entries; it also refuses foreign force-pushes of a different lineage. `pull()` already resets the state machine on any error, so no extra unwinding. `record_refusal` is capped and dedupes consecutive entries, so old devices looping on the refusal stay bounded. Compat verified: `migrate_remote` pushes full history (root preserved → passes), `apply_revocations` is unaffected (absent target commits are skipped; the manifest blob itself is unchanged by the squash and the fresh-clone walk verifies against the root roster — pinned by test).

## Runtime + daemon

`VaultState::vault_empty(payload)`: take the autosync `cycle_lock` (precedent: `finalize_conflicts`) across the whole flow — phrase verify → `empty_entries` → commit → squash/force-push or plain push. The empty flow deletes dozens of files, exactly what nudges the autosync debounce; without the lock a cycle can interleave and resurrect entries or wedge mid-divergence. Daemon route `vault.empty`, payload `{ "phrase": ..., "rewrite_history": bool }`, JSON like the enroll route; phrase zeroized on every exit; attempts rate-limited. Added to `route_coverage` tests.

## CLI

`baluard vault empty [--rewrite-history] [--phrase] [--yes]` — a new singular `vault` group operating on the ACTIVE vault, distinct from the existing `vaults` registry command (add/list/switch). Per user decision; the reviewer suggested extending `VaultAction` instead (`baluard vaults empty`), kept here as the naming precedent if the singular group ever feels redundant.

Direct mode mirrors the daemon path with local primitives and takes the same serialization (single-threaded in direct mode, but hold the discipline anyway). After a rewrite the CLI runs `git reflog expire --expire=now --all && git gc --prune=now` inside the vault dir via system git, best-effort, AFTER the cycle lock is held and the push landed (libgit2/system-git coexistence is unexercised elsewhere; only touch the repo while no cycle can run). Prints the commands if system git is missing.

Post-rewrite output includes per-device instructions: every other device must detach/re-clone (desktop: remove + re-add the vault from the provider; mobile: remove + re-add). Enrollment survives because `meta/devices.json` rides the emptied tree.

## Caveats stated to the user

Remote hosts may retain unreachable objects until their own gc; with the gossip branch reset the old lineage is unreachable, but for absolute erasure the user can create a fresh remote repo and re-point sync (`sync remote` + `sync push`); a test pins that migrate-after-rewrite keeps sync working. Revocation entries whose target commits died with the rewrite are inert forever (apply skips absent commits); `sync revoke` from an old un-pulled device after a rewrite cannot land (non-ff reject on the old line) and that entry is lost on re-clone. Local gc in the command covers the machine it runs on.

## Test plan (test-first)

Core: phrase verify accepts only the vault's phrase (right/wrong/12-word/no-escrow/stale-escrow-after-rotate). `empty_entries` wipes entries+trash+attachments+folders+tags, keeps settings/devices/collections; legacy no-members vault empties fine; pre-existing-trash purge leaves zero rollback warnings on reopen; batch path rebuilds the index correctly (list reflects empty).

Engine: squash produces a single-commit main with the identical tree; gossip branch reset leaves a fresh clone with no entry blobs reachable from ANY fetched ref (assert across all refs, not just main); fresh clone of the rewritten remote clones and pulls clean (clone-side history verification + gossip inertness pinned); an old-line clone's pull refuses with `HistoryRewritten`; migrate-to-fresh-remote after a rewrite keeps a peer syncing; revocation manifest walk passes on the squashed line.

Daemon: route coverage; wrong phrase aborts and burns an attempt; locked vault refuses. CLI e2e (`tests/empty.rs`) against the local git-server fixture: env-phrase scripting path empties a seeded vault; wrong phrase leaves the vault untouched; `--rewrite-history` yields a one-commit remote without entry blobs on any ref and prints re-clone instructions.

## Risks

- Rewrite is irreversible once pushed; the phrase gate plus personal-only gate plus printed consequences are the mitigations.
- Old-clone pulls now refuse by design; the error text must be self-explanatory (first-run UX for anyone who rewrote without reading instructions).
- Push failure wedges the rewriting device until the documented retry runs; the CLI must print the recovery on failure, not just the error.
- Host gc lag means "clean" is strongest locally; the caveat is printed, not hidden.
