# ADR 0106: Attachment blobs off `main` on a signed side channel

Date: 2026-11-13
Status: accepted
Design: docs/designs/attachment-storage.md (two peer-review rounds folded in; libgit2 and forge capabilities settled empirically)

## Context

Attachment blobs shipped inside `entries/<cipher>/attachments/` on `main`: every clone carried every file, deleting an entry never shrank the repository, and branch history accumulated every prior version of every blob forever. The git-native storage contract also made `main` the only carrier, so a fresh clone paid for files it had never opened.

## Decision

Attachment blobs move to `refs/notes/baluard-attachments`: a signed, append-only, content-addressed line that `main` no longer carries.

**Content addressing.** Each line entry is named `<sha256(blob_sha256-hex)>.enc` — the pin of the stored ciphertext, computed at upload (`AttachmentMeta.blob_sha256`, empty on legacy metadata meaning grandfathered-on-main). The pin joins the cipher metadata that rides main, joins conflict comparison as a field, and joins key rotation (rotation is a hash-pin update event; the bytes-level rewrap site leaves pins stale, a recorded limitation). Any device can verify fetched bytes against the pin inside the fetch, so a hostile remote cannot substitute foreign blobs, and junk names ride the line inert.

**Sync.** `push_inner` publishes every untracked worktree blob (pure `WT_NEW`, never index-tracked legacy files) to the line before the main push, best-effort — a failed line push must never block the main push. Downloads fall back to worktree-then-line, materializing fetched bytes locally for next time; a ref-absent line entry surfaces as "not finished syncing" rather than an error. The multi-device race (a line blob referenced by a main commit that has not landed everywhere) self-heals: the device holding the file republishes it from its untracked worktree copy on its next sync.

**Deletion and compaction.** Deleting an entry removes the worktree file and the metadata reference; the line keeps the bytes until the owner runs compaction (`vault.attach_compact`, exposed as a Settings action on desktop and mobile). Compaction force-replaces the line with a fresh signed genesis parented on the vault root, carrying only the pins the vault still references (live, trashed, and archived). The keep set must cover every main-HEAD reference, so compaction refuses when any entry is unreadable on this device — an owner/admin action on shared vaults — and aborts when a referenced pin is missing from the line, never partially reclaiming. Compaction is the only pruner: sync-time line writes never prune, because pruning to main references would race other devices' in-flight uploads.

**What was rejected.** A separate repo per vault (heavyweight), external blob stores (violates the local-first infrastructure stance), raising the 2 MiB XL cap with a finer bucket ladder (deferred — the 5 MiB framing was dropped from scope; the tier machinery is unchanged), and the git atomic push option (rejected empirically: libgit2 rejects any mixed multi-ref push containing a non-fastforwardable member client-side, wholesale, before any byte reaches the wire — so the line-before-main ordering plus the self-healing republish is the reconcile path, not server-side atomicity).

## Consequences

- Fresh clones no longer carry blobs in the git tree; they fetch on demand and cache locally. `main` stays text-scale forever, keeping branch history lean.
- A line rollback or wipe by a hostile remote is not gossip-detectable (gossip watches main heads only); the mitigations are the content pins (foreign bytes refuse) and the self-heal republish. The line has no admission gating by design — junk is inert and compaction bounds it.
- Forge-side garbage collection bounds real erasure: compaction removes the line's references, but a provider may retain unreachable objects. Deletion of vault data remains subject to the Data-lifecycle caveat recorded in the threat model.
- Legacy vaults read as grandfathered: attachments on `main` keep working, and `stage_admitted` skips untracked blob writes while tracked-path deletions keep flowing through normal admission, so no migration commit exists to strand mixed-version fleets.
