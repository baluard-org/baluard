//! Git operations: pull, push, shallow clone management.
//!
//! D11: Shallow by default, auto-unshallow on conflict.
//! D13: Auto-poll 30-60s via git ref comparison.

/// Maximum number of commits to fetch during auto-unshallow (D11).
pub const UNSHALLOW_BUDGET: usize = 500;

/// Default foreground polling interval in seconds (D13).
pub const POLL_INTERVAL_FOREGROUND_SECS: u64 = 30;

/// Maximum background polling interval in seconds (D13).
pub const POLL_INTERVAL_BACKGROUND_MAX_SECS: u64 = 300;

/// Result of a sync operation.
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    pub pulled_commits: usize,
    pub pushed_commits: usize,
    pub conflicts: Vec<uuid::Uuid>,
}

// Note: Full git2 operations will be implemented when wiring the vault handle
// to actual filesystem repos. This module provides the types and constants.
