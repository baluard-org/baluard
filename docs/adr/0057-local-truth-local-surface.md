# ADR 0057. Local Truth, Local Surface (mobile notices and activity)

> Status: Accepted (2026-09-27)

## Context

The core emits share events in chronological order, oldest first, following the audit-log convention. The bridge documentation described the reverse order, and the mobile screen placed the oldest event first under a "Recent activity" heading.

An activity screen that reports an empty result before a request completes presents unverified state as fact. Mobile status surfaces also should not make optional forge round-trips for transport seat checks.

## Decision

Keep the core event order canonical. Reverse the list only in the repository parser for the mobile presentation, and document the core order at each layer. Any layer that changes canonical wire ordering documents its own transformation.

Render the activity screen blank until loading completes. Keep transport seat checks off mobile by using `refresh_transport=false`.

## Consequences

Notices require an unlocked vault and each member device reads its own notices. Reset-pending names and grant counts come from the member directory already distributed to clones. Event and refusal logs remain per-device local files and do not sync. Date-only event stamps continue to use the shared formatter; ordering provides finer sequence information.

## References

- Original record D54.
