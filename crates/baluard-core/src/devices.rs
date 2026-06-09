//! Device enrollment, revocation, quorum management.
//!
//! D14: Per-device wrapping keys, selective rekey, emergency force evict.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DeviceError;
use crate::vault::manifest::{DeviceEntry, DevicePublicKeyEntry, DevicePublicKeys};

/// Device registry: manages enrolled devices, their keys, and quorum state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistry {
    /// Format version. Must be 1.
    pub version: u32,
    pub devices: HashMap<Uuid, DeviceEntry>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            version: 1,
            devices: HashMap::new(),
        }
    }

    /// Enroll a new device. Returns the device entry.
    ///
    /// Per D14: new devices require explicit approval from an existing enrolled device.
    /// For the first device (empty registry), enrollment is automatic.
    pub fn enroll(
        &mut self,
        name: String,
        encryption_public_key: [u8; 32],
        signing_public_key: [u8; 32],
        enrolled_by: Option<Uuid>,
    ) -> Result<DeviceEntry, DeviceError> {
        self.enroll_with_id(
            Uuid::new_v4(),
            name,
            encryption_public_key,
            signing_public_key,
            enrolled_by,
        )
    }

    /// Enroll a new device with a specific device ID.
    pub fn enroll_with_id(
        &mut self,
        device_id: Uuid,
        name: String,
        encryption_public_key: [u8; 32],
        signing_public_key: [u8; 32],
        enrolled_by: Option<Uuid>,
    ) -> Result<DeviceEntry, DeviceError> {
        if self.devices.contains_key(&device_id) {
            return Err(DeviceError::AlreadyEnrolled(device_id.to_string()));
        }
        let entry = DeviceEntry {
            device_id,
            name,
            encryption_public_key: hex::encode(encryption_public_key),
            signing_public_key: hex::encode(signing_public_key),
            enrolled_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            enrolled_by,
            last_seen_epoch: 0,
        };

        self.devices.insert(device_id, entry.clone());
        Ok(entry)
    }

    /// Revoke a device. Returns the removed device entry.
    ///
    /// Per D14: requires quorum signature. Not enforced here (caller's responsibility).
    pub fn revoke(&mut self, device_id: Uuid) -> Result<DeviceEntry, DeviceError> {
        self.devices
            .remove(&device_id)
            .ok_or_else(|| DeviceError::NotEnrolled(device_id.to_string()))
    }

    /// Emergency Force Evict (D14): single surviving device rewrites registry.
    ///
    /// The lost device will never sync again. Full rekey must be triggered after.
    pub fn force_evict(
        &mut self,
        surviving_device_id: Uuid,
    ) -> Result<Vec<DeviceEntry>, DeviceError> {
        let surviving = self
            .devices
            .get(&surviving_device_id)
            .ok_or_else(|| DeviceError::NotEnrolled(surviving_device_id.to_string()))?
            .clone();

        let evicted: Vec<DeviceEntry> = self
            .devices
            .iter()
            .filter(|(id, _)| **id != surviving_device_id)
            .map(|(_, e)| e.clone())
            .collect();

        self.devices.clear();
        self.devices.insert(surviving_device_id, surviving);

        Ok(evicted)
    }

    /// Get enrolled device count.
    pub fn count(&self) -> usize {
        self.devices.len()
    }

    /// Check if a device is enrolled.
    pub fn is_enrolled(&self, device_id: &Uuid) -> bool {
        self.devices.contains_key(device_id)
    }

    /// Get all device X25519 public keys for epoch rotation.
    pub fn encryption_public_keys(&self) -> Vec<(Uuid, [u8; 32])> {
        let mut keys = Vec::new();
        for (id, entry) in &self.devices {
            if let Ok(bytes) = hex::decode(&entry.encryption_public_key) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    keys.push((*id, arr));
                }
            }
        }
        keys
    }

    /// Build the plaintext device public keys file (meta/device-pks).
    pub fn to_public_keys(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            keys: self
                .devices
                .values()
                .map(|e| DevicePublicKeyEntry {
                    device_id: e.device_id,
                    signing_public_key: e.signing_public_key.clone(),
                    quorum_signature: String::new(), // Set by caller during commit
                })
                .collect(),
        }
    }

    /// Required quorum size for N enrolled devices.
    /// ceil(N/2) with minimum 1. Intuitive scaling: 1→1, 2→1, 3→2, 4→2, 5→3.
    pub fn quorum_required(&self) -> usize {
        let n = self.devices.len();
        if n == 0 {
            return 0;
        }
        n.div_ceil(2)
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_first_device() {
        let mut reg = DeviceRegistry::new();
        let entry = reg
            .enroll("MacBook".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();
        assert_eq!(reg.count(), 1);
        assert_eq!(entry.name, "MacBook");
    }

    #[test]
    fn enroll_multiple_devices() {
        let mut reg = DeviceRegistry::new();
        reg.enroll("Device 1".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();
        reg.enroll("Device 2".into(), [3u8; 32], [4u8; 32], None)
            .unwrap();
        reg.enroll("Device 3".into(), [5u8; 32], [6u8; 32], None)
            .unwrap();
        assert_eq!(reg.count(), 3);
    }

    #[test]
    fn revoke_device() {
        let mut reg = DeviceRegistry::new();
        let e1 = reg.enroll("D1".into(), [1u8; 32], [2u8; 32], None).unwrap();
        reg.enroll("D2".into(), [3u8; 32], [4u8; 32], None).unwrap();
        reg.revoke(e1.device_id).unwrap();
        assert_eq!(reg.count(), 1);
        assert!(!reg.is_enrolled(&e1.device_id));
    }

    #[test]
    fn revoke_nonexistent_fails() {
        let mut reg = DeviceRegistry::new();
        assert!(reg.revoke(Uuid::new_v4()).is_err());
    }

    #[test]
    fn force_evict_keeps_surviving() {
        let mut reg = DeviceRegistry::new();
        let surviving = reg
            .enroll("Survivor".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();
        reg.enroll("Lost".into(), [3u8; 32], [4u8; 32], None)
            .unwrap();
        reg.enroll("Also Lost".into(), [5u8; 32], [6u8; 32], None)
            .unwrap();

        let evicted = reg.force_evict(surviving.device_id).unwrap();
        assert_eq!(evicted.len(), 2);
        assert_eq!(reg.count(), 1);
        assert!(reg.is_enrolled(&surviving.device_id));
    }

    #[test]
    fn quorum_sizes() {
        let mut reg = DeviceRegistry::new();
        assert_eq!(reg.quorum_required(), 0); // 0 devices

        reg.enroll("D1".into(), [1u8; 32], [2u8; 32], None).unwrap();
        assert_eq!(reg.quorum_required(), 1); // 1 device: need 1

        reg.enroll("D2".into(), [3u8; 32], [4u8; 32], None).unwrap();
        assert_eq!(reg.quorum_required(), 1); // 2 devices: ceil(2/2)=1

        reg.enroll("D3".into(), [5u8; 32], [6u8; 32], None).unwrap();
        assert_eq!(reg.quorum_required(), 2); // 3 devices: need 2

        reg.enroll("D4".into(), [7u8; 32], [8u8; 32], None).unwrap();
        assert_eq!(reg.quorum_required(), 2); // 4 devices: ceil(4/2)=2
    }

    #[test]
    fn public_keys_match_devices() {
        let mut reg = DeviceRegistry::new();
        reg.enroll("D1".into(), [1u8; 32], [2u8; 32], None).unwrap();
        reg.enroll("D2".into(), [3u8; 32], [4u8; 32], None).unwrap();

        let pks = reg.to_public_keys();
        assert_eq!(pks.keys.len(), 2);
    }
}
