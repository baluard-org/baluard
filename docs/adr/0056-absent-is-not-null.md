# ADR 0056. Absent Is Not Null (the §6.5 settings surface)

> Status: Accepted (2026-09-27)

## Context

The §6.5 settings routes gained desktop and mobile interfaces. The runtime parser treats a present key with JSON `null` as a mistyped value. However, `serde_json::json!` serializes `Option::None` as `null`, causing mobile partial updates to fail when unchanged settings were represented as `None`.

Optimistic settings controls can also become inconsistent if a second update is dropped while the first is in flight.

## Decision

The bridge emits only fields present in a partial update. An absent field means "leave unchanged"; `null` has no meaning and is not sent.

Reject mutation while an update is busy and disable the control during that period. On mobile, set the busy flag synchronously before `scope.launch`. In exception handling, rethrow `CancellationException` before catching other exceptions.

## Consequences

Mobile settings updates no longer send null values for unchanged knobs. Rapid repeated input cannot update the displayed toggle without a corresponding daemon request.

The remaining §6.5 knobs (`join_approval`, `quorum_admin_ops`, `trash_policy`, and `restore_policy`) remain unimplemented pending design and §10 confirmations. The desktop tab renders for members, with the daemon refusing unauthorized operations in plain language. The mobile card is gated by `is_admin_device`.

## References

- Original record D53.
- Settings defaults: ADR 0055.
