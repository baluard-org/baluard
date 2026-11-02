# ADR 0037. Grant Expiry-that-Rotates (S3-3)

> Status: Accepted (2026-09-23)

## Context

`CollectionGrant.expires_at` existed but was not enforced. Expiry has to cut a departing grantee off from content minted later, without making commit verification depend on a clock. An expired-between-authoring-and-verify grant would otherwise refuse commits on every peer and wedge the vault (the first-denied-commit rule). The work is slice S3-3 and was recorded as D34. An external review round (second rotation on this codebase) accepted 5 findings and declined 1.

## Decision

**Enforcement.** `CollectionGrant.expires_at` is now enforced by the admin client. The sweep drops grants whose `expires_at` has passed and rotates the affected collections' content keys in the same atomic save: one write per collection with the grant drop, a fresh CK, and the re-sealed name. A departing grantee's derived item keys then stop matching anything minted later.

**Execution surfaces.** The sweep runs at unlock (the runtime post-pull tail) and on demand through the `collections.sweep` route. The route is token-gated, in `COVER_MUTATION_ACTIONS`, and in the desktop allowlist.

**Notices.** Pending and expired grants surface to members on the notices screen, in en, es, and pt: `grant_expiring` (within 7 days) and `grant_expired` (expired but still present because the sweep has not landed yet). The expired notice reads "will be removed on the next sync", with no unlock prompt, because non-admins cannot act on one.

**Enforcement placement (settled).** Commit verification stays clock-free. Expiry enforcement is admin-side, and peers converge on pull. The local write gate (`assign_cipher_to_collection`) does check expiry, because a locally expired grant must not mint new moves. `expires_at = 0` is the IPC convention for "no expiry" and never expires. The sweep gate also keeps the legacy-vault admin-equivalence bypass, matching the other collection mutators.

**Sweep ordering (review blocker).** The sweep originally ran inside core unlock before the unlock pull. The pull's force-checkout would have discarded the uncommitted sweep files, and they would never have been committed or pushed, because unlock is not a cover mutation. The sweep moved to the runtime post-pull tail: pull first, then sweep (admin-gated), then an autosync nudge so the rotation commits and pushes on the normal cycle. Vaults without a remote sweep inline after the handle guard drops. The review also caught a self-deadlock the fix introduced, where the inline no-remote sweep ran while unlock still held the handle guard. The guard now drops before the unlock tail.

## Consequences

Expired-but-unenforced grants keep authorizing at the git layer until the admin's sweep lands. They surface as `grant_expired`. A grantee can replant content with pre-expiry knowledge until rotation converges. This is the plan's accepted eventual-revocation boundary.

There are no per-member wraps yet (P1 Space parts), so CK rotation is future-proofing for the Team shape. The sweep is triggered only by unlock or by the route, with no background timer. Clock-clamp note 11 holds: the sweep clock is the admin's local clock only for its own writes.

No review finding was declined.

## References

- `docs/adr/0085-sharing.md`, grant-expiry and rotation decisions
