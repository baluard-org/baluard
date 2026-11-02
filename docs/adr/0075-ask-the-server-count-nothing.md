# ADR 0075. Ask the Server, Count Nothing

> Status: Accepted (2026-09-30)

## Context

Desktop inferred admin status by counting collection rows. This fails when an admin has no collections. Mobile already queried the daemon for this state.

## Decision

Expose read-only, token-gated `vault.is_admin_device`, which reports `holds_root()`, and use it on desktop and mobile. Treat the result as key state rather than a live role lookup: a locked vault reports false, and a device whose role is demoted server-side continues to report admin while its keys remain in the session. Surfaces use the marker for ergonomics only; the daemon revalidates each mutation.

Reset vault-scoped context signals on vault switch. `resetNavigation` clears collections and the admin marker with other navigation state. Use the same marker for `CipherDetail`'s admin-only move-to-flat option. On the flipped-vault quorum rotation path, threshold-two rotation requires a second admin; the ask travels through Git and executes on the confirmer's clone. Both admins converge through the rekey wrap, and the SMK remains unchanged, preserving member wraps.

## Consequences

The route exposes one boolean and is not part of mutation lists; it remains default-deny and token-gated. The marker may be stale until lock, so it cannot authorize a mutation. Switching to an empty collection set renders the empty state rather than stale rows.

## References

- `vault.is_admin_device`
- `resetNavigation`
- `CipherDetail`
