# ADR 0040. Delegated Manage (S3-5)

> Status: Accepted (2026-09-24)

## Context

Admins should be able to hand the administration of a single collection to another member without granting admin rights. The authority chain must not let a member grant themselves that power inside the commit being verified. The work is slice S3-5 and was recorded as D37. An external review round accepted 6 findings and declined 1.

## Decision

**Access level.** `CollectionAccess::Manage` is a third access level on collections. A member holding a live manage grant administers that one collection (grants, revokes, rename) without admin rights. Collection create and delete stay admin-only, because deletion kills the grant list. Manage is mintable to Editor and above only. Viewer plus manage is refused at `upsert_grant` and `validate_template`, the same wedge class as Viewer plus write. Manage implies write for cipher moves in the managed collection, and both the scope builder and the local move gate accept it.

**Authority chain is parent-tree scoped.** The sync policy's `meta/collections/**` Admin row gains a scoped relaxation. A signer whose manage grants appear in the parent tree's def files may write `meta/collections/<id>.json` and `meta/collections/<id>/**`, and the Editor role floor still applies. Authority reads from the parent and never from the commit's own tree, so a member cannot self-grant manage in the commit being verified. The local `assert_can_manage_collection` gate mirrors the rule: admin or legacy bypass, otherwise a live non-expired manage grant on the exact target. Every locally minted commit therefore stays locally authorizable and can never wedge a peer's pull.

**Accepted review findings**

- Blocker: the scope builder trusted a def file's inner `id` without binding it to the filename. A manager of collection A could rebrand their def to collection B and inherit B's scope in the next commit's parent walk. Both tree walks now pin stem to id, as `load_dir_map` and `list_collections` do.
- Def deletion was delegable. The policy now takes an `is_deletion` flag. Def removal stays admin-only, and wrap removal stays within manage.
- A demoted Viewer with a stale manage or write grant passed the local gates and wedged sync. Both local gates now refuse Viewers up front. Role changes never strip grants.
- The merge conflict-strip loop authorized with the unscoped policy. It now uses the same parent-tree scope.
- A pre-existing wave-12 wedge surfaced. A plain grantee rotating their identity rewrites their own `meta/collections/<c>/<member>.wrap`, which the Admin row refused on every peer. It is fixed with an own-wrap structural rule at any role, like the members and devices self-rule.
- Shapes are exact. A def is 3 segments ending in `.json`, and a wrap is 4 segments ending in `.wrap`. Nothing hides under loose subpaths.

## Consequences

Verification stays clock-free. An expired-but-unrotated manage grant keeps sync authority until the S3-3 sweep lands, which is the accepted eventual-revocation boundary, while the local gate checks expiry. Delegated managers cannot create or delete collections or touch members. UI for managers rides the §4.8 sharing-surfaces wave.

Declined: having the local gate avoid decrypting all collection names through `list_collections`. The 256-collection cap bounds the work, and a damaged name fails closed.
