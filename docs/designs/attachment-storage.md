# Design: attachment storage and sync

Status: designed, not implemented. Bundle picked from a six-axis option space; peer review folded in (2026-11-13, two blockers and five risks applied, zero-trust verified against the tree). ADR pending at implementation time.

Owner: Esteban
Scope: core, runtime, daemon, CLI, desktop, mobile

## Problem

Attachments are capped at 1.9 MB and ride the main branch as worktree files. Two consequences: the 2 MiB XL bucket wastes up to 8.4x for content just above the L tier (a plain 5 MiB XL bump would waste 21x), and every clone and pull carries every blob version ever committed, forever. Deletion is logical only; main history is the only cleanup vehicle and it is the `vault empty --rewrite-history` sledgehammer.

## Goal

Keep the attachment cap at 2 MiB (scope decision below), keep size-hiding padding as is, move encrypted blobs off main onto a dedicated git ref so main stays lean, and define deletion and compaction honestly across GitHub, GitLab, Codeberg, and custom remotes. No breaking changes: existing vaults and existing attachments stay valid; security posture is preserved or improved.

## Scope decision (2026-11-13)

The cap STAYS at 2 MiB (XL bucket unchanged, `MAX_ATTACHMENT_SIZE` stays 1_900_000). Esteban's call: "leave this at 2MB max, until someone bothers." Consequences: Axis B (bucket ladder), Axis E (IPC transport raises), and Axis F (new tier variants) are ALL MOOT — no tier changes, no frame/response/read-cap raises, no envelope changes. The remaining feature is the line itself: ref, manifest, reconcile, compaction, surfaces. Deletion-space reclamation (Axis D) is the design's center of gravity.

## Ground truth this design rests on

All read from the tree, 2026-11-13.

- `Tier` (crates/baluard-core/src/types.rs ~23-95): Xs 5K, S 30K, M 100K, L 250K, Xl 2 MiB. A 4-byte LE length prefix rides inside the bucket (`padding.rs`). `fit()` accounts for the prefix.
- Attachment blobs are worktree files at `entries/<cipher>/attachments/<id>.enc`, staged onto main by `commit_all`'s `add_all("*")` (engine.rs ~408-490). `MAX_ATTACHMENT_SIZE = 1_900_000` (attachment.rs).
- AAD binds (vault, cipher, attachment, tier, epoch, seq); decrypt recomputes the AAD from the envelope header (attachment.rs ~116-129). The binding protects against cross-identity swaps, not same-identity forgery: header epoch and seq are attacker-chosen when the forger holds the item key.
- Attachment IPC is base64 JSON inside protobuf frames. Daemon frame cap 4 MiB, desktop `MAX_RESPONSE_SIZE` 5 MiB (desktop/src-tauri/src/lib.rs:41), runtime read cap 4 MiB (state.rs ~9067). 5 MiB plaintext is about 7.0 MB base64: caps must move together.
- Deletion is logical: `attach_delete` drops file and metadata, the next commit stages the removal, the blob stays reachable in main history.
- `refs/notes/baluard-gossip` is shipped and live-verified on GitHub, GitLab, and Codeberg (gossip.rs:48). Custom namespaces (`refs/baluard/...`) have unverified forge acceptance. Forge gc: GitHub and GitLab keep unreachable objects until their own gc; Forgejo has `doctor`; custom remotes gc on demand. `refs/pull/*` and `refs/merge-requests/*` are created by forges for PR/MR flows only, which Baluard never opens: not a factor.
- Client caps hardcode 1_900_000: desktop/src/components/AddEditCipherForm.jsx:18, mobile EditCipherViewModel.kt:189, CLI through `MAX_ATTACHMENT_SIZE`.
- Threat model: T1 (provider sees file counts per padded size class; the tier rides the plaintext envelope header and the provider sees the raw padded byte size regardless), T7 (no plaintext temp files, zeroize after use). docs/security/threat-model.md.
- Key rotation re-encrypts attachment blobs in place (handle.rs ~3057-3104), multiplying blob versions per rotation.
- `stage_admitted` resets the index to HEAD and re-stages only admitted paths; non-admitted dirty paths are physically reverted, and non-admitted untracked files are deleted in the decisions pass (engine.rs ~615-842). Any new local blob layout must be skipped in `stage_admitted` before that pass or devices delete their own new blobs.

## The option space (axes as evaluated)

### Axis A: where blobs live in git

- **A1 stay on main.** Zero sync work; roster admission, signed chains, rollback detection all inherited. Main stays heavy; clone weight grows without bound; only cleanup is the sledgehammer rewrite.
- **A2 side ref, append-only line.** `refs/notes/baluard-attachments`, linear signed commits, non-force pushes. Forge acceptance proven by the gossip ref on the same namespace. Custom namespaces rejected: unverified on all three forges.
- **A3 side ref, rolling snapshot.** Force-updated tip every change. Bounded weight immediately, but routine force pushes and push-race reconciles contradict the boring-sync goal.
- **A4 side ref, append-only plus explicit compaction.** A2 for daily operation, a manual force-compact for hygiene. Picked.
- **A5 separate attachments repo per vault.** Rejected: doubles credentials and setup for non-technical users, the same reason a separate gossip repo was rejected.
- **A6 pointers on main plus external blob store (LFS-style).** Rejected: new vendor infrastructure, standing directive against.
- **Custom namespace `refs/baluard/attachments`.** Rejected pending forge verification that A2 gets for free.

### Axis B: bucket ladder to 5 MiB (MOOT — cap stays 2 MiB, see scope decision)

The privacy lever is bucket width, not bucket count: the provider already observes the exact padded byte size and the tier code in the header, so narrower buckets narrow what a file's class reveals, and more classes make that narrowing explicit. Storage economy pulls the same direction as granularity; T1 pulls toward width.

- **B1 single 5 MiB XL.** Up to 21x waste above 250K. Most private per file, most wasteful.
- **B2 doubling ladder: L 250K (shared), then 512 KiB, 1 MiB, 2 MiB, 5 MiB.** Worst hop 2.5x (2M to 5M). Picked. Optional refinement if waste proves painful in practice: a 3.5 MiB bucket drops that hop to 1.67x at the cost of one more class. Powers-of-two to 4 MiB then 5 MiB caps waste at 2x on the last hops.
- **B3 fine ladder.** Storage-optimal, T1-hostile. Rejected.

Cap: `MAX_ATTACHMENT_SIZE = 5_242_876` (the 5 MiB bucket minus the 4-byte prefix). No envelope slack needed: the envelope wraps the padded payload. Plaintext of exactly 5 MiB minus prefix fits.

### Axis C: when the ref travels

- **C1 eager fetch on every pull and after clone.** Parity with today, offline-complete, simple.
- **C2 lazy fetch on download demand.** Lean pulls, visible offline-first regression, per-blob fetch complexity.
- **C3 conditional eager (picked): fetch the ref only when main metadata references ids missing locally.** Offline-complete like C1; pulls touching no attachments skip the ref entirely. Hardened per peer review with a push-order invariant, an unpublished-ids retry set, pending-state UI instead of hard errors, and a per-id fetch backoff (see deltas).

### Axis D: deletion and compaction (the design's center of gravity)

Deletion is logical in every variant: the blob leaves the tip tree, offline devices adopt the removal on their next pull (the pathspec checkout machinery handles deletions), and metadata on main is the existence authority. Deletion itself is byte-free: a content-addressed blob is never copied, so removing it writes only a tiny manifest/metadata edit. What deletion can NEVER do, in any git-based layout, is shrink history — history is append-only and every historical commit that carried the blob keeps it reachable. Space reclamation is therefore a separate, explicit operation:

- **D1 logical only.** Line history grows like main did, just off main.
- **D2 logical plus manual compaction (picked):** a user-triggered action force-pushes a fresh genesis re-parented on the vault root, pruning the tree to the referenced set. Peer refinement: a passive "reclaimable bytes" figure and a settings nudge when superseded bytes exceed max(50 MiB, 2x live set); auto-compaction only after a completed key rotation and only with self-heal in place.

Compaction mechanics, tightened:

- **Live-set rule (airtight):** the fresh genesis keeps exactly the blob ids present in the line that are referenced by (the union of all manifest commits in the line) OR (main HEAD's cipher metadata). Anything else is junk and is dropped. If main references blob ids absent from the line (another device's uploads in flight — the unpublished set), compaction ABORTS with a retry-later condition rather than risk a breach; the publishing device's own re-push path covers it moments later.
- **Race with an offline deleter self-heals:** a device that tombstoned offline pushes its manifest merge after the compactor force-pushed; the reconcile rule adopts the tombstone, and at worst one already-deleted blob rides in the fresh genesis as junk until the next compaction. Bounded, never a correctness problem: the manifest is the authority, not the line's contents.
- **Local reclaim is immediate:** after the force-push lands, the client moves its line ref to the fresh genesis, expires the line reflog, and gc-prunes. That is the same dance `vault empty --rewrite-history` already performs locally; only the provider side lags.
- **Provider-side reclaim is delayed and outside our control:** the force-push makes old blobs unreachable; GitHub and GitLab gc on their own schedule, Forgejo via admin `doctor`. Until then the old ciphertext stays SHA-addressable on the forge (API access by oid), and forks would pin it. Exposure stays ciphertext-only: blobs are client-side encrypted under item keys, so a leaked old blob is useless without the vault. Compaction's honest promise is: clients stop carrying and fetching the bytes immediately; the provider forgets them eventually; true erasure is the `vault empty --rewrite-history` story.
- **Single-flight and force safety:** one compaction at a time (claim guard, the icon-backfill pattern), fetch-verify of the advertised line oid before the force push (old-oid CAS does not exist in the push API; server-side non-fast-forward rejection is the backstop, proven by the spike).
- **Alternatives rejected:** per-attachment refs (delete the ref = instant forge-unreachable, no compaction) explode ref counts by thousands per vault and choke fetch enumeration; routine `main` history rewrites for blob hygiene are the nuclear path and would shred main's audit-chain value; hence the line plus compaction is the only mechanism that reclaims bytes without touching main.

Multi-device force-rewrite safety (2-3+ devices):

- **Nothing referenced is ever dropped, regardless of who is offline.** The compactor's live set is computed ONLY from forge-side state — the freshly fetched line manifest union the freshly fetched main HEAD — never from any device's local view. The per-device push order (line before main) means any id referenced by forge main is already in the forge line, so a stale local view anywhere cannot widen or shrink what compaction keeps.
- **In-flight uploads re-attach from their owner.** A device pushing its line commit against a just-compacted remote gets the non-fast-forward rejection and reconciles: fetch the fresh genesis, replay its manifest edits, and re-add its blob tree entries — the bytes are content-addressed and the uploader still holds them locally (it wrote them seconds ago). Rejection-reconcile is the standard flow, not an error path; N offline devices replay in arbitrary order and converge because manifest merges are a union and blob entries dedup by hash.
- **The old line can never be resurrected.** Force-pushing the line is allowed ONLY in the compaction path, and compaction only ever pushes a genesis it computed in the same operation — never a fetched tip, never local history. Every other writer is non-force, and the server-enforced non-fast-forward rejection (spike-proven) is the backstop. A device stuck months behind cannot re-anchor purged blobs: its pushes are rejected, its manifest edits rebase onto the current genesis, and its old line commits become local junk its own gc sweeps.
- **Concurrent compactors are churn, not loss.** The referenced set is a deterministic function of the same forge inputs, so two devices racing compaction produce equivalent genesis trees; last writer wins, the loser's genesis becomes junk. Single-flight per device, fetch-verify of the advertised oid before force, and a final re-fetch-and-recompute if line or main moved during the build narrow the window to near zero.
- **Worst case in every race is junk or a transient pending state, never missing data.** A blob dropped just before its tombstone lands is redundant until the next compaction; a main-referenced id momentarily absent from the line is the unpublished set, covered by the owner's re-push and the download pending state. main's metadata is the authority for what exists; the line is storage that converges.
- **D3 automatic compaction on a threshold.** Rejected for now: a surprise force-push during sync is machinery behavior the UX pillar avoids.
- **D4 compaction rides `vault empty --rewrite-history` only.** Keep as the nuclear path; the rewrite must also reset the attachments ref (force to fresh genesis or delete), or pre-rewrite blobs stay anchored.

Honest caveat, all variants and every forge: compaction bounds future clone and fetch weight immediately. It does not erase bytes at the provider on any schedule we control. GitHub and GitLab gc on their own schedule, Forgejo via admin `doctor`, custom remotes on demand. True provider-side erasure stays the documented `vault empty --rewrite-history` plus provider-gc-lag story.

### Axis E: IPC transport for 5 MiB payloads (MOOT — no raises; today's caps already fit a 2 MiB envelope)

- **E1 raise the caps together (picked):** daemon frame cap 8 MiB, desktop response cap 8 MiB, runtime read cap 6 MiB (on-disk file is the 5 MiB bucket plus envelope). Peer correction from the drafted 16 MiB: the frame cap is a per-connection allocation ceiling for any token-holding local client; smaller is better, and 8 MiB covers 7.0 MB base64 plus JSON overhead.
- **E2 chunked routes.** Rejected: protocol work for a cap nobody has hit; revisit past ~16 MiB.
- **E3 per-route caps.** Rejected: two limit systems is the kind of special case that becomes a security bug.

Implementation notes riding E1: `attach_upload` currently base64-decodes while holding the vault write lock, and the base64 payload strings are not zeroized (only the decoded plaintext is). Decode before taking the lock and zeroize the base64 buffers; T7 exposure otherwise grows with the cap.

### Axis F: representing the new tiers (MOOT — no new tiers)

- **F1 extend `Tier` with attachment-only variants (picked).** New code strings in the same enum, header field unchanged, AAD construction unchanged, `fit()` for the cipher path stays classic-five, a new `fit_attachment` gates the new variants to attachments. Old clients transiently fail the header deserialization of a new-bucket blob: one attachment download errors cleanly, never corruption. Short window under lockstep releases.
- **F2 parallel enum plus a new header field.** Same old-client failure, more code, two tier systems. Rejected.
- **F3 envelope version 3 for attachments.** Most code, a version fork inside one format. Rejected.

## The bundle, as amended by peer review

A4 + C3-hardened + D2, with the cap unchanged (Axes B/E/F moot per the scope decision).

### Ref layout

```
refs/notes/baluard-attachments          remote line (forge-visible namespace, proven by gossip)
refs/remotes/<remote>/baluard-attachments   local tracking view (local-only, no forge semantics)
```

Line commit shape:

- Tree: flat content-addressed paths `<sha256-of-ciphertext>.enc`.
- Genesis commit parents onto the vault root commit so root-classification (`root_commit_oid_from`, the gossip machinery) binds the line to this vault and foreign lines are recognizable.
- Every line commit signed with the device key. Signatures are hygiene (junk and bloat control), NOT the security boundary: integrity comes from the ciphertext hash pinned in writer-gated metadata.
- Line commits carry the vault id in the commit message for humans; classification never trusts the message.

### Integrity model (the amendment that matters)

The drafted "blobs are inert under forgery" claim was wrong: AAD binds identity with attacker-chosen epoch and seq when the forger holds the item key, and read access to an entry implies holding its key. Fix, mandatory:

- `AttachmentMeta` gains `blob_sha256` (hex of the ciphertext bytes), additive with a serde default so older ciphers decode.
- Metadata lives in the cipher JSON on main, which stays admission-gated: only writers can pin a hash.
- Download verifies the hash before decrypt. Replay of an old epoch, forged content, and cross-path swaps all fail.
- Line paths are content-addressed, so same-path replacement and squatting cannot happen.
- A blob at a path with no referencing metadata is inert junk: undecryptable without the key, unreferenced, pruned by compaction.

### Sync behavior

Ordering invariant: **main never references a blob the remote line lacks.** Push the line first, then main (today `push_inner` pushes main then gossip; the attachments push slots before main).

Write path (upload): encrypt, write worktree file (unchanged C17 secret-file write), hash, add to metadata (main), append blob commit to the line, push line, push main. A failed line push after a successful metadata write is retried through a persistent local "unpublished blob ids" set that every sync re-attempts and only a confirmed push clears. The uploader never re-learns a line failure from the network because C3 does not fetch when metadata ids look present locally.

Pull path: fetch main as today. After merge, prune-adopt the line: fetch the ref only when metadata references ids missing locally (C3 gate), merge the remote tip into the local line view (union of tip trees, all signers accepted), then prune the merged tree to the id set main references. Pruning is what makes logical deletion stick: union merges alone resurrect blobs for devices that have not seen the delete.

Reconcile and wedge rules:

- Non-force push rejected (concurrent writer or junk on the tip): fetch the remote tip, union-merge trees accepting ALL signers (hash pinning makes foreign entries inert), push again. The merge fast-forwards over junk. Deny-only refusal is the wrong model here: gossip can refuse a pull, but the line supplies content clients consume, so its failure mode is a wedge and the cure is to merge past it.
- Foreign-rooted or foreign-vault line tips: classify by root commit and ignore/force-replace, reusing the gossip rewrite machinery.
- Line rollback or wipe by an attacker: self-heal. Any device holding blobs that main references but the remote line lacks re-publishes them after its next sync. Without self-heal, a wipe plus a fresh-clone cycle loses attachments permanently.
- Deleted-blob adoption: a device whose metadata no longer references an id drops it from the worktree and the line view at the next prune pass.

Fetch mechanics: explicit `FetchOptions` for the notes ref (the `refs/heads/*` wildcard does not cover `refs/notes/*`), separate fetch call from the main fetch so an absent line ref cannot fail the main fetch, fresh credential callbacks per fetch (the shared-callback attempt-budget lesson from the gossip arc), clone sites fetch with the clone's own credential config.

### Prune and compaction

- Passive prune on every line write and merge: tree pruned to main-referenced ids.
- Manual compaction (CLI + settings action): build a fresh genesis from the referenced set (re-parented on the vault root), force-push with the previously advertised oid as an expected-value check, then prune local unreachable objects opportunistically (`gc` is heavy; opportunistic only).
- Compaction warning in UI text: bounds future clone weight; does not erase provider bytes until its gc; does not touch legacy blobs still on main from before the cutover.
- `vault empty --rewrite-history` (ADR 0105) extended: also force-reset or delete `refs/notes/baluard-attachments` so pre-rewrite blobs stop anchoring.
- Passive reclaimable figure (superseded bytes) surfaced in settings with the nudge threshold max(50 MiB, 2x live set); no timer-based auto-compaction.

### Offline behavior

- Worktree files remain the local source of truth for reads; upload/download/delete code paths keep their file-based semantics, symlink and read-cap guards, and C17 owner-only writes.
- After any metadata-bearing pull, the C3 gate fetches the line once for all missing ids: the vault returns to offline-completeness.
- Download with a missing blob and no network: mapped "attachment pending, retry when online" state, not a hard error; per-id fetch backoff keyed to the line tip oid prevents a forever-missing id from triggering a fetch every pull.
- First clone: main only. First metadata pull triggers the one line fetch. Mobile networks need a generous fetch timeout and pending-state UI for attachment blobs.
- A device without a collection's key fetches blobs it cannot decrypt: acceptable, same as main today.

### Padding tiers and compatibility (MOOT — tiers unchanged by the scope decision; this section stays only as the recorded evaluation)

Would-have-been ladder: L 250K (shared with entries), then 512 KiB, 1 MiB, 2 MiB, 5 MiB, with `MAX_ATTACHMENT_SIZE` at 5_242_876. Rejected with the 2 MiB decision: existing attachments keep classic tiers and valid decrypt paths forever, no new-client/old-client window, no migration commit, no `.gitignore`. The cutover mechanics that SURVIVE the decision: readers check the worktree path first, then the line; legacy blobs stay grandfathered on main; new clients skip `entries/*/attachments/**` in `stage_admitted` with a prefix rule placed BEFORE the decisions pass (engine.rs ~825), and new blobs are written only to the line; `AttachmentMeta.blob_sha256` additive with serde default, absent for legacy attachments.

## Deltas from the first draft (peer review, zero-trust verified)

1. BLOCKER fixed: ciphertext hash pin in metadata plus content-addressed paths, replacing signature-based admission as the integrity boundary. The drafted claim that AAD alone makes forgeries inert was false for key-holding members.
2. BLOCKER fixed: no migration commit, no `.gitignore` exclusion. The drafted cutover would have silenced old-client uploads (they honor the ignore via `add_all`) and deleted blob files on old clients via the removal checkout, while shrinking nothing.
3. Self-heal republish added (line wipe was undetectable: gossip announces main heads only).
4. Merge-over-junk reconcile specified (the line wedges; it does not refuse).
5. Prune-to-metadata on every write and merge (union merges resurrect deletions otherwise).
6. Push order line-before-main plus the unpublished-ids retry set, pending UI state, and fetch backoff (C3's blind spot: the uploader cannot see its own failed line push).
7. Caps 8 MiB frame/response and 6 MiB read instead of 16 MiB.
8. Cap arithmetic corrected to bucket minus prefix; envelope slack was double-counted.
9. Compaction refinements: passive reclaimable nudge, expected-oid force push, auto only after key rotation.

## Implementation plan

Phase 1, core crypto: `AttachmentMeta.blob_sha256` with serde default, hash computed at upload; envelope/AAD untouched (no tier work — cap decision). The base64-not-zeroized exposure in `attach_upload` becomes a STANDALONE hardening (previously rode the transport phase): decode outside the vault write lock, zeroize base64 buffers.

Phase 2, core sync (new `sync/attachments.rs`):
- Ref constants, line commit builder (signed, content-addressed, genesis parented on vault root), explicit ref fetch with per-call credential callbacks in `fetch_locked`, `pull_inner`, and both clone sites.
- Union-merge consume, prune-to-metadata, push with reject-reconcile, expected-oid force push for compaction.
- `stage_admitted` prefix skip for `entries/*/attachments/**`.
- Wire tests: content hash pin rejects forged blob; prune removes deleted ids; junk-tip merge converges; foreign-rooted tip force-replaced; line push failure retries via the unpublished set; self-heal republish after a simulated wipe.

Phase 3, runtime wiring:
- Upload path appends to the line and records the unpublished id until confirmed push.
- Post-pull C3 gate and line merge; download falls back worktree-then-line with pending state on miss.
- Compaction action plumbing (daemon route plus CLI flag), reclaimable-bytes computation.
- Sync push order changed to line, main, gossip.

Phase 4, clients:
- Pending/partial attachment UI state; compaction action in settings; reclaimable-bytes display.
- Error mapping: new ERROR_PATTERNS rows for line failures mapped to user language (pending, compact, provider-gc caveat).

Phase 5, docs and tests:
- ADR for the attachments ref design; threat-model T1 (bucket classes, unchanged ladder) and T7 (caps, base64 zeroization) updates; key-concepts attachment section.
- e2e git-server fixture gains the attachments ref scenario (clone, upload offline then sync, delete and prune, compact) PLUS the multi-device compaction race: device B holds an unpublished upload while device A compacts; assert B's blob survives the reconcile and lands on the fresh genesis.
- Live forge test: DONE for GitHub (see assessment results; probe size 5 MiB is generous headroom over the 2 MiB cap).

## Assessment results (empirical, 2026-11-13)

A throwaway git2 0.20.2 probe (same crate as the workspace) ran a six-probe suite locally and live against a private GitHub probe repo (created and deleted after the run; spikes live in /tmp/attach-assess, ephemeral).

| Probe | Local | GitHub live | Verdict for the design |
|---|---|---|---|
| P1 explicit notes-ref fetch round-trip | PASS | PASS | The transport works end to end |
| P2 5,242,876-byte blob push + fetch, byte-identical | PASS | PASS | The exact proposed cap travels; no per-push size wall hit on GitHub |
| P3a non-force push of a non-descendant | PASS | PASS | Rejected with NotFastForward: the wedge semantics the reconcile rule assumes are server-enforced |
| P3b force-update of the notes ref | PASS | PASS | Compaction's vehicle works on the forge |
| P4 shallow fetch depth=1 of the notes ref | expected FAIL (local transport has no shallow) | PASS | Depth works over the network; see the shallow caveat below |
| P5 `atomic` git push option | expected FAIL (local transport has no push-options) | PASS | libgit2 exposes `remote_push_options` and GitHub honors it |

Two capability questions answered from the git2 0.20.2 registry source before coding: `FetchOptions::depth(i32)` exists, and `PushOptions::remote_push_options(&[&str])` exists. Old-oid compare-and-swap on force push is NOT exposed by the push API: force pushes keep the fetch-verify-before-force pattern (standing rule), with the advertised oid check left to server-side non-fast-forward rejection.

Design deltas the results produce (SUPERSEDED in part — see the second review section):

1. ~~**Atomic combined push becomes the primary path.**~~ SUPERSEDED by the second review's atomic test: libgit2 rejects any mixed multi-ref push containing a non-fast-forwardable member CLIENT-SIDE (empirical: control and atomic legs both rejected wholesale, nothing landed), so a combined push is already all-or-nothing for the reject case without push options. The atomic option is dropped; line-before-main ordering plus the unpublished-ids set stays THE path, and the residual torn window (mid-push disconnect after the pack lands, or a per-ref server-side race) is what it covers.
2. **Shallow fetch is for readers only.** Depth=1 fetching works, but the vault repo itself must never become shallow: a shallow repo cannot push its own line (incomplete history), and the vault repo is the line's writer. So the vault keeps full line fetches (client weight still bounded by compaction), while depth=1 is the tool for two future paths: restoring a wiped line cheaply (self-heal reads the remote tip without dragging history) and a lazy read-only blob service if one is ever needed. A shallow-fetch design note must record that libgit2's local transport rejects shallow entirely, so e2e fixtures against local bare repos cannot exercise it.
3. **The spike re-proved the ambient pushInsteadOf hazard:** the first live run pushed to SSH and died auth-side because the box's global gitconfig rewrites https github pushes; the fix was a repo-local `remote.origin.pushurl` pin, exactly the shipped identity-pin pattern. Any new probe or tool repo on this box needs the pin.

Remaining open (needs credentials or live access): GitLab and Codeberg runs of the same suite (notes-ref acceptance is already strongly evidenced by the shipped gossip ref on both forges, but 5 MiB push size, force-update, depth fetch, and the atomic option are unverified there), read-only-role key holding, trash/purge interaction with the new ref, and the AGENTS.md STATUS-versus-standards inconsistency.

## Second peer review round (Claude, 2026-11-13): findings, zero-trust verification, dispositions

Claude's verdict: change-first, four blockers. All four verified against the tree; two confirmed as stated, one confirmed with a different cure than the reviewer proposed, one settled empirically against the reviewer's source read.

**B1 — the `atomic` probe proves nothing (VERIFIED, disposition: drop the option).** P5 only proved the option string was not rejected. The reviewer's source claim ("atomic is a protocol capability libgit2 lacks") is wrong at the wire level — libgit2 1.9.7 genuinely sends push options as pkt-lines and advertises push-options (smart_protocol.c:842-857); git's atomicity is server-side, keyed on the literal `atomic` push option. But the decisive experiment ends the question anyway: a mixed push (one FF ref + one non-FF ref) is rejected CLIENT-SIDE by libgit2 wholesale — "cannot push non-fastforwardable reference" — before any packet is sent, with or without the option; nothing landed in either leg. Through libgit2 the combined push is already all-or-nothing for the reject case. DISPOSITION: drop the atomic option entirely; line-before-main + unpublished-ids stays the only reconcile path; the torn window is mid-disconnect-after-unpack and per-ref server races, both covered by the existing retry set.

**B2 — prune and live-set need keys some devices lack (VERIFIED as stated).** Attachment ids live inside ENCRYPTED cipher JSON (state.rs:8916-8926 region); a device without a collection's key cannot read the referencing metadata, so its prune would drop other collections' blobs from the shared line. Also verified: trashed and archived ciphers keep their blobs under `entries/<id>/` and PURGE removes the whole dir (handle.rs ~9040, ~9326, ~9351) — the doc's U2 premise (files move under trash/) was WRONG; trash is a metadata state, not a file move. DISPOSITIONS: (a) prune only removes ids the device can ATTRIBUTE — an id is pruned only when its owning cipher is decryptable locally and no longer references it; unattributable ids are never pruned by that device (junk from unreadable ciphers is bounded and compaction cleans it); (b) compaction refuses when any cipher in main HEAD is undecryptable locally (it cannot compute the full live set) — an admin/owner action on shared vaults, as key rotation already is; (c) the live set includes trashed AND archived ciphers.

**B3 — key rotation breaks the hash pin (VERIFIED as stated).** Rotation re-encrypts materialized blobs IN PLACE at the same `{id}.enc` path under the new item key (handle.rs ~3057-3106), so ciphertext bytes change while `blob_sha256` stays stale — every later download fails verification. Also confirmed: the `exists() -> continue` skips strand blobs not materialized locally (pre-existing gap: they keep old-key ciphertext; the line design does not fix it — flagged to Esteban as a separate defect). DISPOSITIONS: rotation is a hash-pin update event — after re-encrypting a blob, recompute `blob_sha256`, update the metadata (rides the rotation commit), and republish the blob to the line under the NEW content-addressed path (the old path becomes junk until compaction); the idempotency probe (blob already decrypts under the new key) also recomputes the pin. Conflict comparison (sync/conflict.rs:691) compares filename/size/encrypted_size today — the pin joins the compared field set so a rotated-versus-not-rotated divergence surfaces as a field conflict instead of silently keeping a stale pin. (Correction to an earlier note in this section: the conflict.rs citation is real; an initial zero-trust check looked in vault/ and wrongly called it fabricated.)

**B4 — blanket prefix skip breaks legacy blob deletions (VERIFIED as stated, reviewer's cure adopted).** pass 1 of `stage_admitted` treats each entry's deletion/written shape separately and SKIPPED DELETIONS ARE RESTORED FROM HEAD (engine.rs ~762) — a blanket `entries/*/attachments/**` skip would zombie every legacy attachment deletion (path stays dirty, pull restores it). DISPOSITION: the prefix skip applies ONLY to WT_NEW entries (the new-blob writes that must stay off main); tracked-path modifications and deletions of legacy blobs continue through normal admission. NEW integration point found while verifying: the PULL dirty guard (`dirty_paths_split`) refuses pulls when untracked files exist as local content — new blob files sitting untracked in the worktree would refuse EVERY pull — so the attachments prefix needs the same exclusion in the pull-side guard, not just in staging.

Risks verified and dispositioned:

- R1 self-heal under C3 (VERIFIED concern): C3 fetches only when metadata references ids missing locally, so a compaction drop of a concurrently-uploaded blob has no fetch trigger on a device holding it locally. DISPOSITION: every sync compares the advertised line tip to the local tracking tip; a moved tip forces a line fetch and re-evaluation (the gossip re-anchor lesson applied).
- R2 force-push backstop wording (VERIFIED wrong as written): server-side non-fast-forward rejection protects NON-force pushes only; a force push has no CAS and the verify-then-force window exists. DISPOSITION: immediately before force, re-read the advertised line oid via a fresh connect + ls (the `connect_auth` + `list()` pattern, engine.rs ~1866-1892), and document the residual TOCTOU honestly.
- R3 root-classification fail-open (VERIFIED): classification errors fall through to force-replace, fine for advisory gossip but destructive for the line. DISPOSITION: foreign/foreign-rooted line tips are IGNORED (never adopted, never force-replaced); only compaction force-pushes, and only a genesis it just built.
- R4 no admission gating on the line (VERIFIED as inherent): any writer can append junk; the hash pin makes it inert, compaction bounds it. Accepted with a junk-growth note in the compaction nudge figure.
- R5 manifest wording (VERIFIED, U4 confirmed): the line has no manifest structure. Live-set rule restated: the fresh genesis keeps the freshly fetched tip tree (passive prune already keeps tip ⊆ main-referenced) plus any main-referenced ids; abort when main references ids absent from the line.

## Open items

- GitLab and Codeberg runs of the assessment suite (needs PATs or user-approved token use; the GitHub probe pushed a 5 MiB blob, generous headroom over the kept 2 MiB cap — the remaining question is force-update acceptance on those two forges; the atomic option was dropped with B1).
- Trash/purge interaction: RESOLVED by B2 verification — trash is a metadata state (files never move under trash/), purge removes the whole `entries/<cipher_id>/` dir (three sites in handle.rs), so the live set must include trashed and archived ciphers and compaction needs readable metadata for ALL ciphers in main HEAD. Integrity-manifest treatment of the new ref stays open.
- Whether read-only/viewer roles hold item keys (B2 sharpened this: key-less devices never prune unattributable ids and never compact; the hash pin makes foreign blobs inert regardless).
- PRE-EXISTING defect surfaced by B3, outside this design's scope: key rotation's `exists() -> continue` skip strands blobs not materialized locally (handle.rs ~3062, ~10538) — they keep old-key ciphertext and become undecryptable after rotation. The line design does not fix or worsen this; flag for a dedicated rotation wave.
- Repository consistency sweep: the repo STATUS section says no breaking changes while CODING STANDARDS still says pre-1.0 compatibility is not a goal; the standards line is stale after the STATUS rewrite.
