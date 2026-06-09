//! Epoch state machine for Root Key lifecycle.
//!
//! Doc 06 Section 2: CREATED → ACTIVE → ROTATING → RETIRED → DESTROYED.
//! Only one epoch can be ACTIVE or ROTATING at any time.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Epoch state machine for Root Key lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochState {
    /// New epoch initiated, not yet pushed.
    Created,
    /// Active epoch, all new writes use this.
    Active,
    /// New epoch active, old epoch still readable (Phase 1).
    Rotating,
    /// Old epoch deprecated, old keys purged.
    Retired,
    /// Old epoch key material destroyed.
    Destroyed,
}

/// Epoch metadata tracked per Root Key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    /// Monotonic epoch number.
    pub epoch: u64,
    /// Current state.
    pub state: EpochState,
    /// Timestamp (unix seconds) when this epoch was created.
    pub created_at: u64,
    /// Timestamp (unix seconds) when this epoch was retired (if applicable).
    pub retired_at: Option<u64>,
    /// Devices that have acknowledged this epoch.
    pub acknowledged_devices: Vec<Uuid>,
    /// Timestamp (unix seconds) when rotation started (ROTATING state entered).
    /// Used for timeout-based coordinator election.
    #[serde(default)]
    pub rotation_started_at: Option<u64>,
}

impl EpochInfo {
    /// Create a new epoch info at CREATED state.
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            state: EpochState::Created,
            created_at: now_secs(),
            retired_at: None,
            acknowledged_devices: Vec::new(),
            rotation_started_at: None,
        }
    }

    /// Transition to ACTIVE. Only valid from CREATED.
    pub fn activate(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Created => {
                self.state = EpochState::Active;
                Ok(())
            }
            _ => Err(format!("cannot activate from {:?}", self.state)),
        }
    }

    /// Transition to ROTATING. Only valid from ACTIVE.
    /// Records timestamp for timeout-based coordinator election.
    pub fn begin_rotation(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Active => {
                self.state = EpochState::Rotating;
                self.rotation_started_at = Some(now_secs());
                Ok(())
            }
            _ => Err(format!("cannot begin rotation from {:?}", self.state)),
        }
    }

    /// Transition to RETIRED. Only valid from ROTATING.
    pub fn retire(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Rotating => {
                self.state = EpochState::Retired;
                self.retired_at = Some(now_secs());
                Ok(())
            }
            _ => Err(format!("cannot retire from {:?}", self.state)),
        }
    }

    /// Transition to DESTROYED. Only valid from RETIRED.
    pub fn destroy(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Retired => {
                self.state = EpochState::Destroyed;
                Ok(())
            }
            _ => Err(format!("cannot destroy from {:?}", self.state)),
        }
    }

    /// Abort a stalled rotation. Only valid from ROTATING.
    /// Resets to ACTIVE state, clears rotation timestamp and acks.
    pub fn abort_rotation(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Rotating => {
                self.state = EpochState::Active;
                self.rotation_started_at = None;
                self.acknowledged_devices.clear();
                Ok(())
            }
            _ => Err(format!("cannot abort rotation from {:?}", self.state)),
        }
    }

    /// How long has the current rotation been running (seconds).
    /// Returns None if not in ROTATING state or no start timestamp.
    pub fn rotation_elapsed_secs(&self) -> Option<u64> {
        if self.state != EpochState::Rotating {
            return None;
        }
        self.rotation_started_at
            .map(|started| now_secs().saturating_sub(started))
    }

    /// Record a device's acknowledgment of this epoch.
    pub fn acknowledge(&mut self, device_id: Uuid) {
        if !self.acknowledged_devices.contains(&device_id) {
            self.acknowledged_devices.push(device_id);
        }
    }

    /// Check if quorum is met: ceil(N/2) of N enrolled devices.
    pub fn quorum_met(&self, enrolled_count: usize) -> bool {
        let required = if enrolled_count == 0 {
            0
        } else {
            enrolled_count.div_ceil(2)
        };
        self.acknowledged_devices.len() >= required
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_valid() {
        let mut e = EpochInfo::new(0);
        assert_eq!(e.state, EpochState::Created);
        e.activate().unwrap();
        assert_eq!(e.state, EpochState::Active);
        e.begin_rotation().unwrap();
        assert_eq!(e.state, EpochState::Rotating);
        e.retire().unwrap();
        assert_eq!(e.state, EpochState::Retired);
        e.destroy().unwrap();
        assert_eq!(e.state, EpochState::Destroyed);
    }

    #[test]
    fn invalid_transition_rejected() {
        let mut e = EpochInfo::new(0);
        assert!(e.retire().is_err()); // CREATED → RETIRED: invalid
        e.activate().unwrap();
        assert!(e.destroy().is_err()); // ACTIVE → DESTROYED: invalid
    }

    #[test]
    fn quorum_n3_needs_2() {
        let mut e = EpochInfo::new(0);
        e.acknowledge(Uuid::new_v4());
        assert!(!e.quorum_met(3)); // 1 of 3, need 2
        e.acknowledge(Uuid::new_v4());
        assert!(e.quorum_met(3)); // 2 of 3, met
    }

    #[test]
    fn quorum_n2_needs_1() {
        let mut e = EpochInfo::new(0);
        assert!(!e.quorum_met(2)); // 0 of 2, need 1
        e.acknowledge(Uuid::new_v4());
        assert!(e.quorum_met(2)); // 1 of 2, met
    }

    #[test]
    fn rotation_started_at_recorded() {
        let mut e = EpochInfo::new(0);
        e.activate().unwrap();
        assert!(e.rotation_started_at.is_none());
        e.begin_rotation().unwrap();
        assert!(e.rotation_started_at.is_some());
        assert!(e.rotation_elapsed_secs().unwrap() < 5); // just started
    }

    #[test]
    fn abort_rotation_resets_to_active() {
        let mut e = EpochInfo::new(0);
        e.activate().unwrap();
        e.begin_rotation().unwrap();
        assert_eq!(e.state, EpochState::Rotating);

        e.abort_rotation().unwrap();
        assert_eq!(e.state, EpochState::Active);
        assert!(e.rotation_started_at.is_none());
        assert!(e.acknowledged_devices.is_empty());
    }

    #[test]
    fn abort_from_non_rotating_fails() {
        let mut e = EpochInfo::new(0);
        e.activate().unwrap();
        assert!(e.abort_rotation().is_err());
    }
}
