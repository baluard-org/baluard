# ADR 0046. Collection Polish (§4.8-5)

> Status: Accepted (2026-09-25)

## Context

Collection moves change the cipher's encryption domain. The interface must reflect the operations the daemon permits without becoming an authorization boundary.

Trash and catalog surfaces also need to preserve collection origin and give administrators an explicit way to disable publication.

## Decision

The entry detail offers only reachable destinations. Administrators can select any collection or return an entry to personal storage. Members can select collections for which they have a live write or manage grant. A read-only source is displayed as a label rather than a selectable destination. If the daemon refuses a move, the control returns to the persisted value. The daemon remains the validator; UI filtering is for usability only.

Trash rows carry their origin collection, derived from the on-disk layout. List flat entries before collection subdirectories so listing order agrees with the restore resolver regardless of directory order.

An empty catalog publish disables the administrator catalog.

## Consequences

Users are not offered moves that the daemon will refuse, while the daemon remains authoritative for every operation. Trash restoration uses the preserved collection origin.

Collection-aware extension routes and mobile administrator surfaces remain in the S3 work. Organization settings, readiness, and the provider checklist remain deferred.

## References

- Original record D43.
- Shared collection surfaces: ADR 0045.
