# ADR 0062. Two Admins, Two Signatures (S4-1 quorum and creation authority)

> Status: Accepted (2026-09-27)

## Context

Sensitive administrator operations need an optional multi-administrator approval requirement. Collection creation may also need to be delegated to editors. The sync walker remains keyless, so enforcement belongs in local runtime operations while approval records travel through the existing metadata sync policy.

## Decision

Add `quorum_admin_ops`, defaulting to 1 (disabled); an administrator may set it from 2 through 5. Removals, resets, transfers, root rotation, device revocation, and sync-address moves require distinct administrator approvals. Store plaintext approval asks at `meta/approvals/<digest>-<initiator>.json` under the `meta/**` Admin sync row. The first administrator's call writes the ask and refuses. Further administrators approve the same operation kind and parameter digest. The confirming call consumes the record and executes on that administrator's device. The initiator-specific filename prevents two local, uncommitted asks from colliding during pull.

Add `collection_create_authority` to allow editors to create collections when enabled. Enforce both settings locally; keep the sync walker keyless.

Compare approvals against the maximum of the live threshold and the threshold copied into the record. Consume approval in the strike-ordering precheck and mark the matching operation kind and digest as satisfied on the handle. Internal revalidation skips the gate only for that matching mark; direct core callers still pass through the gate. Operations that rotate internally, including removal's offboarding rotation, call the ungated worker after the outer operation has passed the gate. On quorum refusal, runtime wrappers perform a best-effort signed sync cycle so the ask is available for confirmation.

Settings reads used by the gate are encrypted. A handle with a stale root after a pulled rotation fails closed until it re-unlocks.

## Consequences

Approval is consumed even if a later operation fails, including a seat-strike failure. Retrying requires new co-approval because state may have changed. The pending-asks card is desktop-first; the mobile bridge method exists without a card.

Groups, broader dual-control generalization, access review, the full timeline, advisory policies, and the mobile multi-Space host remain S4 work.

## References

- Original record D59.
- Space settings defaults: ADR 0055.
