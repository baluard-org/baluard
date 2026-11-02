# ADR 0050. Fail-Loud Offboarding on a Small Screen (§4.8-8)

> Status: Accepted (2026-09-26)

## Context

Mobile offboarding includes destructive reset, removal, and transfer actions. The interface must report failures clearly, including failures that arrive after a core operation has already changed state.

## Decision

Typed confirmation uses the member's name. Require a non-empty member name and a trimmed input match. On strike failure, keep the dialog open and leave the override switch unchecked. Parse the offboarding report fail-loud: malformed responses produce a visible error, not an empty success. This is required because reset may already have occurred when the response arrives, and the reset code is needed by the successor.

Disable dialog dismissal while the strike network call is in flight so its failure report remains visible.

## Consequences

An empty member name cannot make typed confirmation succeed without input. Failed offboarding remains visible to the operator, including when a request is still in flight.

Flip and prepare remain off mobile until desktop has a corresponding flip surface. Transfer confirmation carries no extra secret; the dialog states that demotion is irreversible except by the new owner. The mobile UI removes one member at a time although the core API supports batch removal.

## References

- Original record D47.
