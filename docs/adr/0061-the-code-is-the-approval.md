# ADR 0061. The Code Is the Approval (§6.5 join_approval)

> Status: Accepted (2026-09-27)

## Context

The `join_approval` setting controls whether an administrator reviews each introduction or possession of a valid invite code is sufficient approval. The one-time code is consumed at introduction, so approval checks must use the administrator-side invite copy.

## Decision

Support two modes. `manual` is the default and retains administrator review. In `code` mode, the administrator device's post-pull and unlock-tail sweep walks the repository-backed queue and automatically approves introductions whose one-time-code secret check passes. The sweep uses the same admin-gated executor as grant-expiry processing and calls the same `approve_queued_join` path as manual approval, retaining its pair-Space cap, flip-readiness, role-floor, and template-snapshot gates.

A failed secret check approves nothing. The row remains queued for administrator review and is not automatically denied. The queue row carries proof, not the credential; the check uses the administrator-side invite copy. If the invite role cannot be resolved, the sweep grants no seat. The vault id is captured while holding the lock before the sweep proceeds.

## Consequences

In code mode, a leaked invite code grants membership. Manual approval therefore remains the default. The setting applies at approval time only; rows staged under manual mode remain queued until an administrator decides.

`quorum_admin_ops` remains deferred pending confirmation of the §10 Q1 default.

## References

- Original record D58.
- Space settings defaults: ADR 0055.
