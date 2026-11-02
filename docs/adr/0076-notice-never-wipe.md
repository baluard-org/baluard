# ADR 0076. Notice, Never Wipe

> Status: Accepted (2026-09-30)

## Context

Removing a member strikes their provider seat, so their device may lose the channel that would report removal. Repeated sync failures are indistinguishable from network failure, leaving a stale vault on the device. Automatic deletion is unsafe because a local device cannot enforce revocation and ambiguous errors can indicate a deleted repository or provider outage.

## Decision

Detect likely and confirmed removal and ask the user whether to detach the vault from the app, preserving its files. Do not auto-wipe. Classify remote access-denied errors conservatively inside sync failures using HTTP status text and authentication wording. Do not match bare digits or "not found"; exclude local filesystem permission errors. The autosync coordinator counts consecutive refused pulls; three indicate probable removal. Clear the count after any success, full sync cycle, or fresh session. Independently check the device's member row on disk without keys; a landed tombstone confirms removal.

The banner offers only reversible detach. Keep deletion CLI-only and show the command without running it. The daemon revalidates all actions. Check access-denied before network errors because provider strikes are classified as network errors. Reset banner state on vault switch and lock. When a device has bindings to both a tombstoned row and a live successor, prefer the live row rather than relying on directory iteration order.

## Consequences

The feature supports honest removed users; it is not enforcement. Offline devices remain unreachable and removed devices retain their local bytes. A probable-removal banner says "may have been removed" because expired tokens and MFA prompts can resemble a refusal. Lock-first banner ordering deactivates autosync before detach. A pre-existing host-close autosync-loop leak remains tracked: host close does not deactivate the coordinator.

## References

- `SyncError::Network`
- autosync coordinator
- `resetNavigation`
