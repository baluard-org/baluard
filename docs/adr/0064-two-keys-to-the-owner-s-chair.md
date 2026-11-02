# ADR 0064. Two Keys to the Owner's Chair

> Status: Accepted (2026-09-28)

## Context

The power pack closes the owner-recovery gap and hardens the quorum setting under `adr-power-pack.md` §13. Ownership continuity requires paths for an owner who is permanently absent and an owner who later returns. Lowering the admin-operation quorum must not let the current admins remove the protection without approval.

## Decision

Provide two owner-recovery operations. `ownership_claim(new_owner_id)` is an admin-only operation with its own quorum ask for the case where the owner is permanently absent. It executes through `commit_ownership_swap`, a pure mutator that promotes the successor before demoting the prior Owner and maintains exactly one Owner. Voluntary `transfer_ownership` uses the same mutator and retains pair-Space Editor demotion. `member_reset` accepts an Owner target for admin callers; the successor row inherits the Owner role, allowing the returning owner to rejoin as themself. `create_invite` permits an Owner-role invite only when bound to a successor; binding an existing row does not create an invite.

Lowering `quorum_admin_ops` invokes the quorum gate using the current value, which remains on disk until the operation passes. A genuine reduction therefore requires a co-approver; an increase remains immediate. No separate quorum-lock setting is used.

The co-approver confirms the same pending ask. Claim parameters include the claimant ID and are stored in the pending record so another admin can confirm the operation; interfaces use those parameters, falling back to `initiated_by` only for records without them. Self-reset checks and target preflights run before the quorum gate. Self-reset fails directly, and nonexistent or tombstoned claimants cannot consume approval. The Owner row has no Remove action; Reset remains available on desktop and mobile. The desktop People surface is admitted by the ADR 0009 allowlist for its members, requests, notices, and activity calls. Claim ceremonies propagate the confirming device's swap commit and verify role convergence after the peer pulls it; role changes do not rotate keys or require re-unlock.

## Consequences

At quorum threshold two or higher, owner recovery stalls if only one admin remains. The pending ask appears in Space settings; users must maintain two admins before raising the threshold. A demoted owner's devices retain their existing key knowledge. Theft-shaped displacement therefore requires `member_remove`, including the provider seat strike and key rotation. An owner-device notice and cancellation window are deferred beyond v1.

## References

- `adr-power-pack.md` §13
- ADR 0009 allowlist
