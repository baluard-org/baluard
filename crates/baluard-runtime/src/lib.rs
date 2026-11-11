//! Baluard runtime: vault-session orchestration shared by every host.
//!
//! Extracted from `baluard-daemon` (Phase 0, `docs/adr/0089-mobile-apps.md`) so the
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

pub mod agents;
pub mod autosync;
pub mod bridge;
pub mod crypto;
pub mod founding;
pub mod host;
pub mod legacy;
pub mod pin;
pub mod providers;
pub mod rate_limit;

/// Serializes tests that sandbox process-global env vars (`BALUARD_DATA_DIR`
/// and friends). Env mutation is process-global, so every test that redirects
/// a path env var must hold this lock for its whole body — two such tests
/// running in parallel would otherwise write into each other's temp dirs.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Hold for the entire test body while any path env var is redirected.
    pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}
pub mod state;

pub use agents::{
    AGENT_ALLOWED_ACTIONS, DEFAULT_TTL_SECS, PeerBinding, PendingOutcome, PendingQueue,
    PendingRequest, pid_in_process_tree,
};
pub use autosync::{AutoSyncHandle, AutoSyncState, AutoSyncStatus};
pub use bridge::SharedBridgeRegistry;
pub use host::{SharedVaultHost, SnapshotError, VaultHost, VaultPresence};
pub use pin::PinEscrow;
pub use providers::ProviderManager;
pub mod icon_backfill;
pub use state::{SharedVaultState, VaultState};
