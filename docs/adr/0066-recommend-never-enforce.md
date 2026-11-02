# ADR 0066. Recommend, Never Enforce

> Status: Accepted (2026-09-29)

## Context

Space owners need to communicate recommended organization settings without making stale or missing recommendations affect security or prevent member operations. The existing S3-6 catalog pattern stores shared metadata under the `meta/**` Admin row.

## Decision

Publish recommendations in plaintext, git-tracked `meta/policies.json`. File existence represents a published setting; an empty publish removes the file and opts out. Validate values fail-closed against the shipped §6.5 knob table, including single-valued `restore_policy`, and accept every value the settings table can emit. No decision gate reads this file; enforcement uses the shipped knobs.

Members read recommendations without keys. Desktop and mobile surfaces display a localized "recommended" hint beside matching settings; mobile displays only recommendations that differ from current values. Render chip labels rather than raw wire values. `policies.set` is included in daemon `COVER_MUTATION_ACTIONS`, the token-gate pin list, the desktop allowlist, and `daemon.js` `MUTATION_ACTIONS`.

## Consequences

Recommendations are plaintext because they are not secrets. A member's local write to the Admin row is refused by peers; staging filters this pre-P5 wedge shape as recorded in ADR 0063. Publishing is desktop-first. Mobile supports reading hints, while a mobile publishing surface is deferred. There is no per-member acknowledgment or compliance report.

## References

- S3-6 catalog pattern
- §6.5 knob table
- ADR 0063
