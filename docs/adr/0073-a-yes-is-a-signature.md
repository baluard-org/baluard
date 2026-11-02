# ADR 0073. A Yes Is a Signature

> Status: Accepted (2026-09-30)

## Context

Quorum approvals were bare member IDs in plaintext records. Any admin with repository access could add another ID and satisfy the gate without the member's approval.

## Decision

Each approval carries the approver's member-identity Ed25519 signature over the ask kind, parameter digest, vault ID, and ask timestamp. Count an approval only when its signature verifies against the identity key published in the member row. Dedupe repeated valid entries by member. Count only live Owner or Admin rows; ignore Viewer approvals and keys from evicted admins. Bind signatures to the vault and timestamp to prevent replay across Spaces and fresh asks.

Consume asks older than seven days so a confirmation after the window raises a fresh ask. Apply the live quorum threshold in both directions: tampering cannot make an ask pass below the threshold or become impossible to approve above it. Remove every matching approval record by discovered path, including renamed or concurrent duplicates. Invalidly signed records parse but approve nothing; subsequent access rewrites them from valid entries. Old plain-UUID records parse-fail inert under the pre-1.0 format change.

## Consequences

Approval records remain on the `meta/**` Admin sync row, so asks are visible to admins. The keyless sync walker cannot read the encrypted threshold; the gate enforces signatures locally, and the quorum knob remains local-only under §6.5. Identity rotation invalidates that member's old signatures, requiring fresh approval.

## References

- `meta/approvals`
- §6.5 quorum setting
