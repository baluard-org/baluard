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
    pub fn begin_rotation(&mut self) -> Result<(), String> {
        match self.state {
            EpochState::Active => {
                self.state = EpochState::Rotating;
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
}
