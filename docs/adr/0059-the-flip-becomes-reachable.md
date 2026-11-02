# ADR 0059. The Flip Becomes Reachable (Team-mode surfaces)

> Status: Accepted (2026-09-27)

## Context

The S3-7b team-shape flip had core and daemon support but no user-facing entry point. Administrators need to understand readiness before invoking this one-way upgrade.

The status and preparation payloads contain similarly named fields with different shapes: `SpaceStatus.missing_wrap_pubkey` is a count, while `PrepareReport` contains an id array.

## Decision

Expose status, prepare, and the one-way upgrade on the desktop Space tab and mobile administrator Space card. Provide three thin UniFFI methods over the shared runtime wrappers and require typed `team` confirmation on both platforms.

Use a prepare-then-flip flow. Preparation reports the number of members who need to open Baluard and sign in once. Keep the upgrade unavailable until the missing count is zero; the daemon rechecks readiness in all cases. Keep the payload shapes explicit in repository parsing. Treat a failed prepare, including a null result, as failure rather than success.

## Consequences

Administrators can invoke the privacy upgrade from desktop or mobile after readiness is established. The desktop tab remains visible to members by convention, but a refused status request renders a muted placeholder and inactive controls. The core remains the authorization boundary regardless of client presentation.

`join_approval` and `quorum_admin_ops` remain deferred.

## References

- Original record D56.
- Team-shape flip: ADR 0043.
