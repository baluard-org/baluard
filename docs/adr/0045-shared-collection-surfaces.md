# ADR 0045. Shared-Collection Surfaces (§4.8-4)

> Status: Accepted (2026-09-25)

## Context

Desktop and daemon collection surfaces need one role-aware listing contract. Collection access and cipher membership must be derived from trusted vault state rather than client claims.

The inbox contract also crosses the client and daemon boundary. A mismatched payload or an ignored expiry can turn an intended temporary request into permanent access or cause approval actions to fail.

## Decision

Use one collection listing route. Administrators receive all collections, the grant table, and an `access:"admin"` marker. Members receive only collections they can open, with names decrypted through their grant wraps. The server derives the marker from `holds_root`.

Derive `CipherMeta.collection_id` from the cipher's on-disk location using one directory-map pass. Do not accept collection membership from client input. Entry creation accepts a collection id and writes the entry into that collection in one operation, avoiding an intermediate flat entry that a Read-grantee could move.

Treat the inbox payload as a client-daemon contract: `requester_member_id` is required for approve and deny, and expiry must be parsed and enforced. Verify payload shape at both ends of the contract.

The SolidJS 2.0.0-rc.1 build requires the existing `onSettled` convention because its default entry no longer exports `onMount`; both importers use that convention, and the Vite build smoke check covers the toolchain constraint.

## Consequences

Clients cannot claim administrator status or assign a cipher to a collection in which it is not stored. Entry creation does not expose a create-then-move interval.

Move-to-collection UI, trash collection mapping, and catalog opt-out belong to the §4.8-5 polish work. Organization settings, readiness, and the provider checklist remain outside this record.

## References

- Original record D42.
- Collection polish: ADR 0046.
