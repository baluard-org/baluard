# Implementation Readiness Review — `baluard vault empty`

Reviewer: Implementation Readiness Goldfish (fresh context, REVIEW mode)
Target: `docs/designs/vault-empty.md`
Method: design read against `baluard-core` / `baluard-runtime` / `baluard-daemon` / `baluard-cli` sources; every load-bearing claim traced to code.

## Verdict

**NOT READY FOR IMPLEMENTATION.** 2 Blockers, 5 Majors, 7 Nits.

The design's cryptographic core is correct and matches the codebase exactly (verified below), and the gossip-inertness argument holds. But Gate 1 as written refuses every newly created personal vault, the `baluard-gossip` branch keeps the entire discarded history reachable (defeating the headline erasure goal on both remote and local gc), and the push-failure path permanently wedges the rewriting device under the new pull guard. These must be resolved in the design before code is written.

---

## Blockers

### B1 — Gate 1's personal-vault detection is wrong for the current codebase

- **Severity**: Blocker
- **Affected Scope**: "Gates" §1, `empty_entries` step 1, test plan, UX gate text
- **Finding & Guidance**: The design says: "Personal vaults only: refuse when `meta/members/` exists (team/space shape), same detection `purge_old_trash` uses." Both halves are wrong against current code:
  1. Since S1a, **every newly created vault writes `meta/members/`** — `VaultCreator::execute` writes the Owner member row plus the founding-device binding "with the registry BEFORE the initial commit" (`crates/baluard-core/src/vault/creation.rs` ~474–500). A personal vault created today has `meta/members/`. The proposed gate would refuse **every new personal vault**, i.e. the command's primary audience.
  2. `purge_old_trash` does not use `meta/members` as a *refusal* signal (`crates/baluard-core/src/vault/handle.rs:9241`): the directory's presence switches the op to a **role gate** (Owner/Admin may purge); it is not a team-only refusal. The design mischaracterizes its own cited precedent.
- **Required fix**: Detect personal shape with `!crate::vault::space_meta::shape_flipped(&path)` (`space_meta.rs:134` — the `meta/space-shape.json` `mode == "team"` marker). This is the codebase's canonical detector and has direct precedent in the personal-phrase-rotation path (`handle.rs` ~6075: "A flipped (team) Space recovers with its Space Recovery Kit…"). Update the test plan: fixtures are member-carrying personal vaults; add a flipped-Space refusal test.

### B2 — The `baluard-gossip` branch keeps the entire discarded history alive; erasure goal and local gc claim both fail

- **Severity**: Blocker
- **Affected Scope**: "Core changes → Sync engine: `rewrite_history_squash`", "`--rewrite-history` flow", local gc step, Caveats, test-plan assertion "one-commit remote without entry blobs"
- **Finding & Guidance**: The squash force-updates only `refs/heads/<default>`. The gossip side branch defeats the rewrite:
  1. Announcement commits **carry the announced main head as a second parent** so "the announced history stays REACHABLE from the gossip branch" (`sync/gossip.rs` header; `announce_head` parents at `engine.rs` ~1886–1920). The remote's `refs/heads/baluard-gossip` therefore anchors every pre-rewrite main head, and remote-side gc will **never** prune the old entry blobs. The Caveats section's "remote hosts keep unreachable objects until their own gc" is false as stated: they are *reachable*, permanently, until the gossip branch is also rewritten.
  2. Pull and clone fetch the wildcard refspec `refs/heads/*:refs/remotes/{remote}/*` (`pull_inner` `engine.rs` ~2264; `clone_remote`), so **every fresh clone receives the full discarded history and its entry blobs** via `refs/remotes/origin/baluard-gossip`. The test-plan assertion "a one-commit remote without entry blobs" fails the moment the test inspects anything but `main` — and the design's stated goal ("carrying no entry blobs in any commit") is not met even on a successful run.
  3. Locally, `git reflog expire --expire=now --all && git gc --prune=now` cannot prune objects still reachable from `refs/heads/baluard-gossip` and `refs/remotes/origin/baluard-gossip`. The "strongest locally" claim in Caveats is also false.
  4. Even if the rewrite force-pushed gossip to an orphan once, the rewritten device's **next** `announce_head` seeds from the fetched gossip tip and pushes **non-force** (`engine.rs` ~1936–1944) — after a local-only cleanup the remote-tracking ref still points at the old tip, re-attaching the entire old lineage to the new gossip tip on the first post-rewrite sync.
- **Required fix**: `rewrite_history_squash` must explicitly handle `refs/heads/baluard-gossip`: force-push it to a fresh orphan (or delete it on the remote), update/delete the local branch and `refs/remotes/<remote>/baluard-gossip` (or refetch after the remote reset) **before** the gc step, and include the gossip refspec in the force-push refspecs. The test plan must assert absence of entry blobs across **all** fetched refs of a fresh clone, not just `main`.

---

## Majors

### M1 — Force-push failure after the squash permanently wedges the rewriting device, with no specified recovery

- **Severity**: Major
- **Affected Scope**: `rewrite_history_squash` step 3 ("Push failure aborts the rewrite locally… reports the divergence honestly"), new `SyncError::HistoryRewritten` guard
- **Finding & Guidance**: If the force-push fails, local main sits on the new orphan root and remote main on the old root. Every subsequent autosync cycle (`run_sync_cycle_with_resolver`, `engine.rs:3467`: commit → pull → push, push skipped on pull error) hits the proposed guard — remote root ≠ local root — refuses, and never pushes. The device that legitimately rewrote is **indistinguishable from a foreign-force-push victim** under the guard as specified. "Reports the divergence honestly" is not a recovery procedure; the user is stuck with a vault that can neither pull nor push.
- **Required fix**: Specify the escape hatch in the design: e.g. a `--retry-push`/re-run of `vault empty --rewrite-history` that re-attempts only the force-push (the emptied tree is already committed), plus documented fallback (`sync remote` to a fresh repo + push, or re-clone + re-empty — noting re-clone resurfaces the old entries because the push failed, so the erasure must be redone). Also state that the guard compares root oids and therefore cannot exempt the rewriting device; the recovery must be procedural.

### M2 — `empty_entries` step 2 inherits `delete_cipher`'s role gate, which refuses on legacy (pre-S1a) personal vaults

- **Severity**: Major
- **Affected Scope**: `VaultHandle::empty_entries` step 2 ("`list_cipher_ids` → `delete_cipher`")
- **Finding & Guidance**: `delete_cipher`'s flat-cipher arm refuses unless `member_role_for_device` resolves Owner/Admin (`handle.rs` ~8925–8930, arm at ~8966). On a vault **without** `meta/members/` (any pre-S1a personal vault — exactly the old vaults a user most wants to empty), that resolves `None` → refusal ("this operation requires a managing device"). The codebase already solves this in two places the design should cite or reuse: `assert_collection_write`'s legacy fallback `is_admin || !meta/members.is_dir()` (`handle.rs:9031`) and `device_maps_to_admin` ("Legacy founder: no member directory at all — the founding device is the admin by construction", `handle.rs:3364`). `delete_cipher` itself lacks the fallback (arguably an existing latent bug); `empty_entries` must not silently inherit it.
- **Required fix**: Either route step 2 through an internal delete that uses the `device_maps_to_admin`-style rule, or state that `delete_cipher`'s flat-arm gate is fixed as part of this change. Add a legacy-vault (no `meta/members/`) test to the test plan.

### M3 — Step 3's claim "purge_old_trash(0) … integrity entry removal" is factually wrong; stale checkpoints trigger permanent rollback warnings

- **Severity**: Major
- **Affected Scope**: `empty_entries` step 3
- **Finding & Guidance**: `purge_old_trash` (`handle.rs:9234–9304`) removes trash files and `entries/<id>/` attachment dirs but **never calls `remove_integrity`** — only `delete_cipher` does (`handle.rs:8971`, `9006`). Entries that were already in trash before the command (the UX explicitly counts "2 in trash") leave stale checkpoints in `meta/integrity.json`. `IntegrityManifest::detect_rollback` reports any checkpoint whose object is absent from `ciphers/` as a rollback (`integrity.rs:136–160`), and `VaultHandle::open` prints a "WARNING: rollback detected" block per stale entry on **every open, forever** (`handle.rs:347–380`).
- **Required fix**: Specify explicit integrity-checkpoint removal for every purged trash id (mirroring `delete_cipher`'s trash branch), either inside `empty_entries` or by extending `purge_old_trash`. Add a test: after emptying a vault with pre-existing trash, `detect_rollback` is empty on next open.

### M4 — `vault_empty` must serialize against the autosync cycle; the design is silent

- **Severity**: Major
- **Affected Scope**: "Runtime + daemon → `VaultState::vault_empty(payload)`"
- **Finding & Guidance**: The desktop runtime runs a debounced + cadence autosync (`fire_sync`, `autosync.rs:619`) guarded by a process-wide `cycle_lock` (`autosync.rs:469`). The empty flow deletes dozens of files — which is precisely what nudges the debounce — and the squash/force-push window is a divergence window. Without the lock, a cycle can interleave: (a) mid-`empty_entries`, a pull merges the remote's old-line commits and **resurrects deleted entries** into the worktree (count mismatch, half-emptied vault); (b) between squash and force-push, a cycle's pull hits the diverged roots and wedges the cycle (see M1). The codebase precedent the design must adopt: `finalize_conflicts` holds `autosync.cycle_lock_guard()` across its spawn_blocking git work (`runtime/state.rs` ~7584).
- **Required fix**: Add to the runtime section: `vault_empty` (and the CLI direct-mode path) takes the cycle lock across phrase verify → `empty_entries` → squash → force-push.

### M5 — HistoryRewritten guard: correct in principle, but placement and the clone path need pinning

- **Severity**: Major (downgradeable to documented-Nit if addressed in text)
- **Affected Scope**: "Pull guard: `SyncError::HistoryRewritten`"
- **Finding & Guidance**: The root-oid comparison is sound and cheap: `root_commit_oid_from` (`engine.rs:2086`) exists and is today used only by gossip (1850, 1993), so no other consumer anchors to the root oid. Verified interactions:
  - `migrate_remote` (`engine.rs:1153`) pushes **full local history** to the new remote — root oid preserved → guard passes. ✓ (The design should still pin a test for "migrate to a fresh remote after a rewrite keeps sync working", since the Caveats recommend exactly that flow for absolute erasure.)
  - `clone_remote` verifies full history (`verify_fetched_history`, `engine.rs:4426` — "Root commits: own tree" handles the signed orphan with `meta/devices.json` in-tree per `roster_for_commit`'s genesis rule) and runs `check_head_gossip` (`engine.rs:3868–3875`) — succeeds via the inertness argument. Pin the clone path in a test, not only "pulls successfully" post-clone (a fresh clone's first `pull` is the trivial `AlreadyUpToDate` arm; the meaningful assertions are clone-side verification + gossip inertness).
  - Placement: the guard belongs next to `check_head_gossip` — after fetch, **before** the `local_oid == remote_oid` early return. The `pull()` wrapper already resets the state machine on any error (`engine.rs:2213–2235`), so the refusal cannot strand `SyncState` — say so explicitly so the implementer doesn't add redundant unwinding.
  - Old devices will refuse on every cycle; `record_refusal` is capped at 200 lines with consecutive-dedupe (`engine.rs` ~2969), so the refusal log stays bounded. Fine — state it.

---

## Nits

### N1 — CLI command shape doesn't exist as written

- **Severity**: Nit
- **Affected Scope**: "CLI" section, UX header
- **Finding & Guidance**: The design says `Commands::Vault { action: VaultAction }` and shows `$ baluard vault empty`; the codebase has `Commands::Vaults { action: VaultAction }` (plural, `main.rs:437/471`) with variants like `Add/List/Switch/…`. Specify: extend the existing `VaultAction` with `Empty { --rewrite-history, --phrase, --yes }` (invoked as `baluard vaults empty`), or justify a new top-level command. An implementer should not have to choose.

### N2 — `verify_recovery_phrase` signature under-specified for the kit fallback

- **Severity**: Nit
- **Affected Scope**: "Core changes → `verify_recovery_phrase(vault_path, phrase)`"
- **Finding & Guidance**: The kit fallback calls `recover_root_from_kit(vault_path, vault_id, phrase)` — it needs a `vault_id` the signature doesn't carry. Name the resolver: `VaultHandle::vault_id_for_path` (used by kit recovery, `handle.rs` ~1162). Also name the canary file (`meta/rk-canary.enc`) and its fail-closed read (precedent: `handle.rs:1171–1178`). The personal-escrow recipe itself is **verified correct**: `RecoveryPhrase::from_phrase` enforces 24-word/32-byte entropy and rejects 12-word (`recovery.rs:43–58`); `derive_key()[..32]` → X25519 → `hpke_wrap::unwrap_key(..., "recovery-keywrap")` vs `meta/recovery.json` matches `recover_from_phrase` (`device_manager.rs:1355–1445`) and the phrase-rotation mint path (`handle.rs:6096–6120`); `verify_rk_canary` closes the loop.

### N3 — Stale escrow after `rotate-root` on legacy recovery.json produces a misleading refusal

- **Severity**: Nit
- **Affected Scope**: Gate 2, test plan
- **Finding & Guidance**: `rewrap_recovery_key` silently skips when `meta/recovery.json` lacks `recovery_x25519_pubkey` (legacy escrow), warning that "Recovery phrase will NOT work after this rotation" (`handle.rs:10909–10933`). For such vaults the phrase *unwraps* (old root) but fails the canary — Gate 2 refuses, correctly, but with a "wrong phrase"-shaped error. Specify a distinct error message ("recovery escrow is stale after a root-key rotation; re-enroll with the phrase to refresh it") and add the right-phrase-after-rotate-root test.

### N4 — "meta/ is never touched" is literally false

- **Severity**: Nit
- **Affected Scope**: `empty_entries` closing paragraph
- **Finding & Guidance**: The flow rewrites `meta/integrity.json` (`remove_integrity` per delete; `integrity.rs:18`) and `meta/index.enc` (`rebuild_index`). The semantic claim (settings/devices/collections/members/KDF/canaries/avatar survive) is right; reword to "no *semantic* meta changes; caches (index, integrity) update as usual" so an implementer doesn't contort the flow to avoid meta writes.

### N5 — O(N²) rebuilds in step 2

- **Severity**: Nit
- **Affected Scope**: `empty_entries` step 2 / step 6
- **Finding & Guidance**: `delete_cipher` calls `rebuild_index` (full vault rescan) per entry. The codebase already solved this shape: `add_cipher_batch` skips the per-add rebuild for exactly this reason (`handle.rs`, `add_cipher_batch` doc). Specify batch semantics (per-id delete with rebuild suppressed, single `rebuild_index` at step 6) or accept and document the cost.

### N6 — Revocation manifest: entries orphaned by the rewrite; unpulled revocations silently dropped

- **Severity**: Nit
- **Affected Scope**: Caveats / Risks (revocations not mentioned), test plan
- **Finding & Guidance**: Verified no wedge: `apply_revocations` skips entries whose target commit is absent (`find_commit` → `continue`, `engine.rs` ~3127), and the append-only history walk is content-addressed — the manifest blob is unchanged by the squash, so the tracker short-circuits, and on a fresh clone the single-commit walk verifies all entries against the root roster (`verify_manifest_transition`, `engine.rs` ~2810). Two consequences deserve a sentence in Caveats: (a) pre-rewrite entries point at commits that no longer exist fleet-wide (inert forever); (b) `sync revoke` on an old device appends on the old line, the push is non-ff-rejected, and the entry is lost on re-clone. Add a test that the manifest walk passes on a squashed line.

### N7 — `git reflog expire/gc` via system git while the daemon lives

- **Severity**: Nit
- **Affected Scope**: "CLI" gc step
- **Finding & Guidance**: Running system `git gc` inside the vault repo is fine only if the autosync cycle cannot run concurrently — covered by M4's cycle lock; make the gc step explicitly run under it (or after the daemon has quiesced), and note libgit2/system-git coexistence is otherwise unexercised in the codebase.

---

## Verified correct (no action needed)

- **Recovery unwrap recipe**: parse → BIP-39 seed → `X25519` from `seed[0..32]` → HPKE unwrap vs `meta/recovery.json` with context `recovery-keywrap` → `verify_rk_canary`. Matches `recover_from_phrase` (`device_manager.rs`), the mint/rewrap paths (`handle.rs:6107`, `10947`), and `creation.rs:112/446`. Fail-closed on missing escrow matches existing behavior. Phrase resolution order (flag > `BALUARD_RECOVERY_PHRASE` with argv warning > masked prompt) matches `handle_enroll_with_phrase` (`commands/mod.rs:3296`).
- **Rate limiting**: `claim_attempt` + `commit_success`/`commit_failure` + zeroize-on-every-exit mirrors `handle_enroll_with_phrase` (`handler.rs:3902–3950`).
- **Gossip inertness**: `check_head_gossip` derives `vault_tag` from the fetched target's first-parent root (`engine.rs:1993`) and treats any announcement whose signature fails under it as inert (deny-only loop, `engine.rs:2010–2027`). Pre-rewrite announcements fail `verify()` under the new root oid → skipped. Holds for pull and clone. A pinning test is warranted and planned.
- **Guard compatibility**: `migrate_remote` preserves the root (full-history push); revoke/`apply_revocations` unaffected (N6); `roster_for_commit` genesis rule admits the signed orphan root; `create_signed_commit` accepts empty parents (orphan feasible) and correctly refuses an *unsigned* orphan on an enrolled tree (`commit_line_is_enrolled` sees `meta/devices.json` in the new tree).
- **`empty_entries` data sources**: `list_cipher_ids` covers live+archived (archived is an in-place flag, `handle.rs:9587`); `list_trash_ids` exists; `save_folders(&[])` prunes per-fact orphans and drops legacy files (`handle.rs:7494–7547`); tag clearing via `save_tags_enc(&TagIndex::default())` shape exists; `purge_old_trash(0)` purges immediately (mtime carries deletion time; pinned by `trash_soft_delete_restore_purge`).
- **Daemon/CLI plumbing**: `payload: &str` VaultState methods are an established pattern; route-coverage test list exists (`handler.rs:370+`); e2e git-server fixture exists (`tests/e2e/main.rs:1107`, `e2e/git-server/http-git-server.py`); `sync remote`/`sync push` and `rotate-root` exist as the Caveats claim.

## Ready-when

Resolve B1 (shape detection via `shape_flipped`), B2 (gossip branch reset in the rewrite + gc ordering + all-refs test), M1 (post-push-failure recovery path), M2 (legacy-vault delete gate), M3 (integrity cleanup for purged trash), M4 (cycle-lock serialization), and fold M5/N1–N7 into the text. After that, the design is actionable end-to-end: every remaining step names existing primitives with correct signatures.
