# ADR 0035. Collections Core (S3-1)

> Status: Accepted (2026-09-22)

## Context

Sharing at organization granularity needs a data and key layer for collections. The work is slice S3-1 and was recorded as D32. An external review round produced 7 findings, all accepted: grants were write-only through IPC (list carried only a count), decrypted CK vectors were not zeroized, `format` was unvalidated, a filename and id mismatch could wedge rotation, editor-refusal coverage existed only for create, a doc comment was stale, and the rewrap path skipped the size cap. Refutations confirmed the gate coverage on all mutating ops, the epoch-bound wrap derivation, AAD transplant rejection, rotation wiring in both paths, and grant validation.

## Decision

**Data layer.** `meta/collections/<id>.json` carries plaintext grants (`{member_id, access: read|write, expires_at?}`) and the collection's display name sealed under a random per-collection content key (CK). The plan rule is that plaintext is UUIDs, names, and trust. A non-grantee sees an opaque id and grantees see real names.

**Key layer.** The CK is wrapped under a key HKDF-derived from the Space Group Key and bound to its epoch (plan: "collection key, random; wrapped under SGK"). This is why rotation re-seals. Both `rotate_root_key` and `revoke_device_and_rekey` decrypt every collection's CK with the outgoing SGK before the swap and re-seal it after the swap, following the outbox-registry pattern.

**API.** Six admin-gated handle methods, runtime wrappers, and daemon routes: `collections.create`, `list`, `rename`, `delete`, `grant`, and `revoke`. The five mutating routes are in `COVER_MUTATION_ACTIONS` and the desktop allowlist is updated. `collections_list` returns grant rows (member, access, expiry), so an admin can see who has what before revoking.

**Trust model.** The admin gate (`assert_can_manage_members`) covers all five mutating operations. List is open to any unlocked member and is read-only. The sync policy table already requires Admin for `meta/collections/**`, so commit verification backs the route gate. Grants validate that the target is a live member, with no `removed` or `reset` tombstone. Malformed files skip inertly in the directory walker, and the filename stem must match the embedded id so a misnamed file cannot wedge rotation.

## Consequences

Entries stay at personal paths. Collection-scoped cipher paths and the policy-table binding are the P5 remainder (the enforcement slice). Per-member identity wraps (`meta/collections/<c>/<m>.wrap`) and Team-shape key separation (non-admins never hold the Root Key) arrive with the P1 Space parts. Expiry enforcement (expiry that rotates, plus notices surfacing), role templates, delegated manage, JIT request-access, and `space.adopt` are separate S3 slices. There is no UI yet, because it belongs to the §4.8 sharing-surfaces wave.

## References

- `docs/adr/0085-sharing.md` §4.2 and §4.6 (S3 row) and the S3 tracking row
