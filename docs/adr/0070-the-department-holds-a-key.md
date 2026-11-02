# ADR 0070. The Department Holds a Key

> Status: Accepted (2026-09-29)

## Context

Granting a collection to a department should avoid per-member key wrapping and make member departure inexpensive. A removed member may retain copied content keys; this is the accepted eventual-revocation boundary.

## Decision

A group is stored at `meta/groups/<id>.json`. Its member list is plaintext, its display name is sealed under a random Group Key (GK), and the GK is sealed under an SGK-derived wrapping key. A collection grant to a group stores the collection key (CK) under the GK in `<g>/<c>.ckwrap`; each member holds the GK wrapped to their identity key in `<g>/<m>.gkwrap`. The key chain is gkwrap → GK → ckwrap → CK. Removing a member rotates only the group's GK and reseals its ckwraps; collection CKs and direct grantees are unchanged.

Use typed `GrantTarget` values for members and groups. One effective-access predicate covers direct grants and group expansion, selects maximum access, and ignores expired grants. Sync scope walks, staging filters, member listings, collection write gates, and JIT ask coverage checks use this predicate. Group grants and membership changes are admin-only because group ckwraps reside in the Admin sync row. Reset and removal delete the member's gkwrap and rotate each affected group's GK while the current SGK is held. Deleting a group prunes its grant rows from all collections. `resolve_ck` falls back through the group chain when a member has no direct wrap.

JIT asks and role templates remain member-targeted. Groups cannot request access or receive template grants.

## Consequences

Removing a member from a group does not re-key each collection or affect direct grantees. A removed member's remembered CK can still decrypt future writes to granted collections. Self-service group departure and mobile support are deferred.

## References

- `meta/groups/`
- S1a-6 offboarding completeness rule
