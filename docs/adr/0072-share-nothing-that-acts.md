# ADR 0072. Share Nothing That Acts

> Status: Accepted (2026-09-30)

## Context

Sharing must not transfer live credentials. The sharing review also identified a deadlock in voluntary ownership transfer when the quorum threshold is raised: the Owner initiates consent but cannot provide the required second approval.

## Decision

Strip FIDO2 credentials from both outbox exports and one-shot package exports and imports. Import stripping is defense in depth against hostile hand-built payloads. Reveal operations already omit passkeys through field projection.

For voluntary ownership transfer, allow an admin other than the Owner to confirm the Owner's pending ask. Confirmation cannot initiate an ask. Run deterministic refusals, including self-transfer, invalid or tombstoned targets, and wrong actor, before the quorum gate. Apply the same target checks in the confirmer path. Bind the ask digest to both the recorded Owner and the successor. A new ask supersedes earlier asks of the same kind from its initiator, restarting approvals when the target changes. Desktop SpaceTab and mobile SettingsScreen provide the matching approval action.

Other pending-ask kinds, including removal and rotation, continue to complete when an admin repeats the operation rather than through a separate approval action.

## Consequences

An ask cannot execute after the recorded Owner changes, and a changed target invalidates prior approvals. The owner must restart consent for a replacement ask. Handwritten `meta/approvals` records for gated operations remain a client-side enforcement residual: an admin can construct such records until peer-side record verification is implemented. Findings about the recovery kit and pre-flip grants remain as documented in ADR 0064 and the flipped-key design.

## References

- ADR 0064
- ADR 0009 allowlist
- `SpaceTab`
- `SettingsScreen`
