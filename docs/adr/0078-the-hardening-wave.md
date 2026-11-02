# ADR 0078. The Hardening Wave

> Status: Accepted (2026-10-01)

## Context

An independent review of the sharing surfaces found inconsistencies across key rotation, device binding, commit verification, approval replay, offboarding, and flipped-vault rotation. Source triage accepted eight findings and declined three as designed, documented, or already handled.

## Decision

When a grant-expiry sweep rotates a collection key, re-encrypt entries, trash, and attachments, and use a gitignored crash marker so the definition flip and re-encryption converge. Reject duplicate device bindings in the sync walk and both local resolvers; tombstoned subtrees remain inert so reset re-enrollment is legal. Apply surface-diff review to all clients, including join routes.

Make peer commit verification evaluate grants against the commit tree, with `now = 0`; expiry remains a local enforcement concern. Prevent consumed quorum approvals from replaying by recording tombstones keyed by kind, digest, and nonce. Add a random nonce to every ask and bind it into the signed message. During removal rotation, skip and name corrupt entries instead of aborting after the tombstone; re-seal member-visible metadata during SMK rotation and heal at the next admin unlock under a marker.

For flipped vaults, record `flipped_epoch` in the marker and show a persistent rotation reminder until an epoch bump proves rotation ran. Add `space.rotate_root`, gated by admin role and quorum, and check role authorization at every threshold, including one. Keep show-once ceremony phrases in process memory by ceremony kind so blur-lock unmount does not destroy the display state.

Do not add one-click Approve buttons for operations completed by repeating the operation, rate limits to password-gated routes, or extra orphan-device checks where card validation already precedes enrollment.

## Consequences

Expiry no longer changes the commit verification result as time passes. Corrupt entries do not block removal rotation, but are named and skipped. A flip now produces an explicit rotation reminder. The first implementation review used one scripted two-site patch despite the no-scripted-edits rule; this was self-detected and recorded as a process violation.

## References

- S3-3 grant-expiry sweep
- S3-7c item keys
- P5 staged-path policy
- `space.rotate_root`
