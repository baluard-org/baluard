//! Baluard runtime: vault-session orchestration shared by every host.
//!
//! Extracted from `baluard-daemon` (Phase 0, `docs/plan-mobile-apps.md`) so the
//! desktop daemon AND a mobile app can each host it **in-process**. The daemon
//! hosts it as a long-lived background process (Unix-socket IPC); mobile hosts
//! it as a foreground process (UniFFI bindings, no daemon — see plan §3.2).
//!
//! What lives here:
//! - [`host::VaultHost`] — multi-vault map + active pointer (Phase 6 invariant).
//! - [`state::VaultState`] — per-vault handle, session token, cover timer,
//!   auto-lock, autosync handle, PIN escrow.
//! - [`autosync::AutoSyncHandle`] — debounced push, periodic pull, offline
//!   retry, conflict queue. Exposes a `background_loop` (daemon) and an
//!   event-method surface (mobile, Task #2).
//! - [`pin::PinEscrow`] — session PIN quick-unlock (in-memory KEK, 5-strike nuke).
//! - [`bridge::BridgeRegistry`] — browser-extension pairing state (desktop-only
//!   feature; mobile links but does not call).
//! - [`crypto`] — constant-time comparison.
//! - [`rate_limit`] — per-vault brute-force backoff for sensitive ops.
//!
//! What does NOT live here: the Unix-socket listener, protobuf routing, and
//! desktop keychain glue — those stay in `baluard-daemon`.

pub mod autosync;
pub mod bridge;
pub mod crypto;
pub mod host;
pub mod pin;
pub mod providers;
pub mod rate_limit;
pub mod state;

pub use autosync::{AutoSyncHandle, AutoSyncState, AutoSyncStatus};
pub use bridge::SharedBridgeRegistry;
pub use host::{SharedVaultHost, SnapshotError, VaultHost, VaultPresence};
pub use pin::PinEscrow;
pub use providers::ProviderManager;
pub use state::{SharedVaultState, VaultState};
