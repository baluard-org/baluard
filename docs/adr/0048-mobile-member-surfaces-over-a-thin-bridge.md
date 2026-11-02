# ADR 0048. Mobile Member Surfaces over a Thin Bridge (§4.8-6)

> Status: Accepted (2026-09-26)

## Context

Mobile member sharing and join surfaces must use the same validation and payload contracts as desktop. Reimplementing parsing or validation in Kotlin would allow platform behavior to diverge.

The member join flow also interacts with repository synchronization. A pull from an unsynchronized engine can race the sync cycle unless it occurs in the safe join-poll state.

## Decision

The mobile bridge delegates sharing and join operations to the runtime wrappers used by desktop daemon routes. Payload parsing and validation remain authoritative in those wrappers.

The join flow checks status first. It performs a best-effort pull only while locked and introduced but not yet approved, the state in which repository access cannot race the active sync cycle lock.

Render the ask-for-access control even when the member has no collections. Gate whether the operation succeeds, not whether its entry point is visible. Hand-built JSON must escape control characters for inputs that allow multiline text; the daemon also refuses newline-containing values.

## Consequences

The mobile and desktop surfaces share one parser and runtime validation path. The joiner's master password crosses the FFI as a String and remains in composable state for the ceremony duration; Rust zeroizes it before the introduction write, matching the desktop trust model.

Invite, approve, deny, flip, and grant administration remain desktop surfaces. iOS remains at its existing parity.

## References

- Original record D45.
