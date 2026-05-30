//! Sync state machine (D12).
//!
//! States: idle → pulling → merging → encrypting → committing → pushing → push_verify → idle
//! Each transition is idempotent with persisted operation IDs.

use serde::{Deserialize, Serialize};

/// Sync operation states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    Idle,
    Pulling,
    Merging,
    Encrypting,
    Committing,
    Pushing,
    PushVerify,
}

impl SyncState {
    /// Valid transitions from current state.
    pub fn next(&self) -> &[SyncState] {
        match self {
            SyncState::Idle => &[SyncState::Pulling],
            SyncState::Pulling => &[SyncState::Merging, SyncState::Idle],
            SyncState::Merging => &[SyncState::Encrypting, SyncState::Idle],
            SyncState::Encrypting => &[SyncState::Committing, SyncState::Idle],
            SyncState::Committing => &[SyncState::Pushing, SyncState::Idle],
            SyncState::Pushing => &[SyncState::PushVerify, SyncState::Merging],
            SyncState::PushVerify => &[SyncState::Idle, SyncState::Merging],
        }
    }

    /// Check if transition to `target` is valid.
    pub fn can_transition_to(&self, target: SyncState) -> bool {
        self.next().contains(&target)
    }
}

/// Sync state machine with crash-safe checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateMachine {
    pub current: SyncState,
    /// Monotonic operation ID for idempotency.
    pub operation_id: u64,
    /// Cipher IDs currently being processed (for resume after crash).
    pub pending_ciphers: Vec<uuid::Uuid>,
    /// Timestamp when pending_ciphers was last modified.
    /// Used to detect stale pending state (conflict resolution timeout).
    pub pending_since: Option<u64>,
}

/// Maximum time in seconds before pending ciphers are considered stale.
/// After this, escalate to forced resolution or eviction.
const PENDING_TIMEOUT_SECS: u64 = 3600; // 1 hour

impl SyncStateMachine {
    pub fn new() -> Self {
        Self {
            current: SyncState::Idle,
            operation_id: 0,
            pending_ciphers: Vec::new(),
            pending_since: None,
        }
    }

    /// Attempt a state transition. Returns Err if invalid.
    pub fn transition(&mut self, target: SyncState) -> Result<(), String> {
        if self.current.can_transition_to(target) {
            self.current = target;
            if target == SyncState::Idle {
                self.operation_id += 1;
                self.pending_ciphers.clear();
            }
            Ok(())
        } else {
            Err(format!(
                "invalid transition: {:?} → {:?}",
                self.current, target
            ))
        }
    }

    /// Check if pending ciphers have been stuck too long.
    /// Returns the list of stale cipher IDs if timeout exceeded.
    pub fn check_pending_timeout(&self) -> Option<&[uuid::Uuid]> {
        let since = self.pending_since?;
        let now = now_secs();
        if now.saturating_sub(since) > PENDING_TIMEOUT_SECS && !self.pending_ciphers.is_empty() {
            Some(&self.pending_ciphers)
        } else {
            None
        }
    }

    /// Force-clear stale pending ciphers (eviction policy).
    /// Recovery path: bypasses state machine validation to prevent stuck states.
    pub fn evict_stale_pending(&mut self) {
        self.pending_ciphers.clear();
        self.pending_since = None;
        // Force-reset to Idle, bypassing transition validation.
        // This is a recovery operation — the normal transition graph doesn't
        // cover all states, so we go direct.
        self.current = SyncState::Idle;
        self.operation_id += 1;
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for SyncStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sync_cycle() {
        let mut sm = SyncStateMachine::new();
        assert_eq!(sm.current, SyncState::Idle);

        sm.transition(SyncState::Pulling).unwrap();
        sm.transition(SyncState::Merging).unwrap();
        sm.transition(SyncState::Encrypting).unwrap();
        sm.transition(SyncState::Committing).unwrap();
        sm.transition(SyncState::Pushing).unwrap();
        sm.transition(SyncState::PushVerify).unwrap();
        sm.transition(SyncState::Idle).unwrap();

        assert_eq!(sm.operation_id, 1);
    }

    #[test]
    fn invalid_transition_rejected() {
        let mut sm = SyncStateMachine::new();
        assert!(sm.transition(SyncState::Pushing).is_err()); // Idle → Pushing: invalid
    }

    #[test]
    fn push_reject_returns_to_merging() {
        let mut sm = SyncStateMachine::new();
        sm.transition(SyncState::Pulling).unwrap();
        sm.transition(SyncState::Merging).unwrap();
        sm.transition(SyncState::Encrypting).unwrap();
        sm.transition(SyncState::Committing).unwrap();
        sm.transition(SyncState::Pushing).unwrap();
        // Push rejected: back to merging
        sm.transition(SyncState::Merging).unwrap();
    }

    #[test]
    fn push_verify_mismatch_returns_to_merging() {
        let mut sm = SyncStateMachine::new();
        sm.transition(SyncState::Pulling).unwrap();
        sm.transition(SyncState::Merging).unwrap();
        sm.transition(SyncState::Encrypting).unwrap();
        sm.transition(SyncState::Committing).unwrap();
        sm.transition(SyncState::Pushing).unwrap();
        sm.transition(SyncState::PushVerify).unwrap();
        sm.transition(SyncState::Merging).unwrap();
    }
}
