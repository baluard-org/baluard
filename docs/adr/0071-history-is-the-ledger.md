# ADR 0071. History Is the Ledger

> Status: Accepted (2026-09-30)

## Context

A Space-wide activity feed is useful, but a shared event file would create mutable shared history and record reads. Git commits already provide signed, roster-attributed, policy-checked history.

## Decision

Derive the feed on demand from verified Git history; write no shared event file. Synthesize membership, grant, group, key, and Space-shape changes. Keep S1b's per-device log local. Omit individual cipher changes and access-view events. Skip changes from unverifiable commits and continue the history walk.

Order entries topologically from HEAD toward the root, newest first. Display Git timestamps but do not sort by them. Never include raw keys, sealed names, or cipher contents; identify collections and groups by short IDs. Represent an access change, such as Read to Write for one target, as both a revocation and a grant. Include modified deltas for Space facts, including republished policies, rewrapped recovery kits, and later remote moves.

## Consequences

The feed records shared changes without recording reads or entry-level cipher churn. It is admin-gated, with founder-equivalent vaults admitted. The walk is limited to 500 commits and clamps the requested limit. A member without a row is named by the device-ID prefix; the genesis commit credits "the space's creator."

## References

- S1b per-device activity log
- S4-4 access review
- `derive_timeline` in `sync/engine.rs`
