# ADR 0063. The Stage Is the Policy (P5 explicit staged path sets)

> Status: Accepted (2026-09-28)

## Context

Staging all paths with `add_all("*")` allowed a device to create a local commit containing paths its policy rejects. Peers then refused the commit, leaving the branch blocked by an unpushable commit.

Commit-time admission must match peer verification while using the correct tree for each authorization fact. Reading all facts from the worktree could allow local metadata edits to self-promote a device. Reading all facts from HEAD would reject a legitimate commit that creates a collection and its first cipher together.

## Decision

`commit_all` stages only changed paths admitted by the signer's policy, using the same per-path logic as peer verification. Structural predicates for member-record deltas, the integrity manifest, and registry own-bumps are pure byte-level functions shared by both sides. Apply `authorize_scoped` with the collection scope. Peers continue to verify every delta.

Resolve role and member from the HEAD tree using the member snapshot, never the worktree. Read collection directories, the signer's writable grants (Manage implies write), and the flip marker from worktree metadata because these describe the prospective commit tree. Resolve managed authority from HEAD so a manager cannot grant itself authority in the same commit. The scope file itself stages only through the Admin table row, so a local forged grant cannot be admitted into history.

For merge commits, preserve the index created by `repo.merge`; filtering it would drop unconflicted remote entries. Peer P8a residue checks govern merge-commit admission. Revert skipped tracked paths to committed content and remove skipped untracked paths. With no HEAD, admit all paths for the founder's initial commit; peers grandfather the root commit.

## Consequences

Policy-clean paths are staged by construction, and peer verification remains defense in depth. A tombstoned signer stages nothing. Non-UTF-8 paths cannot be authorized and remain dirty. Each skipped path emits an `eprintln` warning without aborting the operation.

## References

- Original record D60.
- Member collection access and scoped authorization: ADR 0044.
