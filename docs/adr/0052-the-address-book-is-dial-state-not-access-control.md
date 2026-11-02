# ADR 0052. The Address Book Is Dial State, Not Access Control (S2 contact flavors)

> Status: Accepted (2026-09-26)

## Context

The address book stores contact identity and verification state. Importing a signed card proves only that the card is signed; HPKE base mode authenticates no identity. Level 1 contacts can receive shared items because packages and reveals wrap no live keys.

The verification code protects the out-of-band identity comparison. A 32-bit unilateral hash lets an active man-in-the-middle search offline for a colliding key.

## Decision

Treat the address book as dial state, not access control. Use a 64-bit verification code as the minimum for human comparison, sized against offline attack by the best-resourced attacker.

Provide contact removal and display the card code in the appropriate UI. Exposed address-book operations must have the required create, read, update, and delete surfaces so neither side of sharing ends at an unusable operation.

## Consequences

Trust remains binary: Channel or Verified, as defined in §4.1. Removing a contact changes only local dial state and does not revoke items already received. Contact cards travel out of band and have no expiry; re-issuing after identity rotation is the reconciliation path. Outbox publish and revoke UI remains unowned.

## References

- Original record D49.
- Item-sharing surfaces: ADR 0051.
