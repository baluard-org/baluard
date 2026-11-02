# ADR 0054. The Admin Marker Must Survive the Empty Set (§4.8-9 mobile collection CRUD)

> Status: Accepted (2026-09-26)

## Context

Mobile People and Collections settings entries used the presence of an `access:"admin"` collection row as their administrator marker. A vault with no collections returns no rows, so an administrator could not reach these entries or create the first collection.

## Decision

Derive the entry-point marker from `holds_root`, the capability that `collections_list` uses to distinguish managing devices. Do not infer a capability by counting the artifacts it produces.

Bridge methods accept typed arguments. The app passes strings and a record list; the Rust bridge constructs JSON. Kotlin does not escape identifiers.

## Consequences

Administrators can reach People and Collections settings when the collection set is empty. Catalog publication sends all current collections, without per-item curation on mobile. Deleting a collection keeps its entries but removes its grants; the confirmation dialog states this. The Settings gate controls reachability, and the daemon validates each call.

## References

- Original record D51.
- Mobile administrator surfaces: ADR 0049.
