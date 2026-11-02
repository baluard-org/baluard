# ADR 0065. Who Can See What, On Demand

> Status: Accepted (2026-09-29)

## Context

Space administrators need an audit view of members, collections, grants, pending asks, join requests, access requests, and owner-side outbox mirrors. Removed or reset members' grant rows remain after tombstoning until expiry because revocation does not rotate collection keys. Data already read cannot be recalled.

## Decision

Compute an access review on demand on the admin device from disk state. Persist no report data and provide JSON export. Include member roles, trust, tombstones, decrypted collection names, grants with access and expiry, pending quorum asks, the join queue, access requests, and owner-side outbox mirrors. Retain rows for removed and reset members and include their collections in a rotation list. Exclude raw keys, wraps, and identity seeds.

Each sub-reader enforces its own access gate even when the aggregate report's top-level gate admits a legacy founder without a member directory. The JIT ask inbox resolves the acting device's member ID and refuses on those legacy vaults. Each report row label supplies all interpolation values it renders. Role-gated review cards follow the People section's `yourRole` visibility and remain hidden from non-admins.

## Consequences

The report identifies collections a departing member could read while active and recommends password rotation as mitigation. Contact-key grants and outbox links are local to other devices and excluded; only owner-side mirrors appear. Before the flip, members held the Root Key and could read every flat cipher. After the flip, the report can state that boundary. A removed member may retain a content key and decrypt future writes to a granted collection; this eventual-revocation residual is mitigated by the rotation list. The bridge method is available to mobile later; the analysis UI is desktop-first.

## References

- S4-4 access review
- S4-8 exposure summary
- `PeopleTab`
