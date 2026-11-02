# ADR 0026. Event-Driven Sync Pull

> Status: Accepted (2026-06)

## Context

A predictable 3-minute heartbeat pull is a measurable timing fingerprint (T14) and spends git round-trips while the desktop is idle. The events that actually need a fresh vault (unlock, window focus returning, a local CRUD round-trip) can drive pulls directly. This refines ADR 0006 and was recorded as D23.

## Decision

The periodic 3-minute heartbeat pull is replaced by event-driven triggers and a 30-minute idle fallback.

- The daemon pulls immediately on vault unlock. `VaultState::unlock` calls `pull_only` after `activate`.
- The desktop fires `sync.autosync_nudge_pull` on Tauri `WindowEvent::Focused(true)`. The daemon applies a 10-minute `FOCUS_PULL_MIN_GAP_SECS` guard, so flicker collapses to one pull per 10 minutes.
- The push cycle itself commits, pulls, and pushes. Concurrent remote edits land right after a local mutation, so no separate event is needed.
- A 30-minute idle fallback (`PULL_INTERVAL_SECS`) catches the rare case of a vault left open on two machines. It is deliberately quiet, with no predictable periodic heartbeat.
- A `cycle_lock` tokio Mutex (C3 fix) guarantees only one sync cycle touches the on-disk repo at a time. Losing cycles bail cleanly.
- Activation happens in `VaultState::unlock`, immediately and not lazily. It is deactivated on lock.
- There is no daemon-side decrypted cache. `get_cipher` and `list_folders` read from disk on every call, so after a pull the handle serves fresh data without a reload. `root_key` and the SGK stay valid.

**Frontend.** The desktop polls `sync.autosync_status` every 10 seconds (`AutoSyncContext`). A status pill in the sidebar header (`AutoSyncIndicator`) and a non-blocking conflict banner (`ConflictBanner`) show the state. There is no Tauri event channel, only request and response.

## Consequences

The fixed timing fingerprint is removed and idle desktops no longer pull on a schedule.

The 30-minute fallback is still required. Under the keep-unlocked model (ADR 0022) with N unlocked vaults, an event-driven-only design can miss the case where device A made an edit while device B sat idle and none of B's events fired. The timer is the quiet backstop, not the primary sync path.
