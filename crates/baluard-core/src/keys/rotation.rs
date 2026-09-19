//! Key rotation flows.
//!
//! Doc 06 Section 7: master password change, device revocation, org member removal.
//! D5: Versioned keys + two-phase commit.

use uuid::Uuid;

use crate::crypto::hpke_wrap;
use crate::error::BaluardError;
use crate::keys::hierarchy::RootKey;

/// Rekey transaction format (D5).
///
/// Committed to the vault repo to coordinate key rotation across devices.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekeyTransaction {
    /// Epoch being rotated from.
    pub old_epoch: u64,
    /// New epoch number.
    pub new_epoch: u64,
    /// Per-device HPKE-wrapped new Root Key.
    pub wrapped_root_keys: Vec<WrappedKeyEntry>,
    /// Device that initiated this rotation.
    pub initiating_device_id: Uuid,
    /// Unix timestamp of initiation.
    pub timestamp: u64,
    /// Quorum commit barrier signatures.
    pub commit_barrier: Vec<CommitBarrierSig>,
}

/// A per-device wrapped Root Key entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedKeyEntry {
    pub device_id: Uuid,
    /// Ephemeral X25519 public key (32 bytes).
    pub ephemeral_public: Vec<u8>,
    /// AES-256-GCM encrypted Root Key.
    pub encrypted_key: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: [u8; 16],
}

/// Quorum commit barrier signature from a device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBarrierSig {
    pub device_id: Uuid,
    pub epoch: u64,
    /// Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

/// Initiate a new vault epoch by generating a new Root Key
/// and HPKE-wrapping it for all enrolled devices.
///
/// Returns the new Root Key and a rekey transaction (not yet committed).
pub fn initiate_epoch_rotation(
    old_epoch: u64,
    enrolled_device_pubs: &[(Uuid, [u8; 32])],
    initiating_device_id: Uuid,
) -> Result<(RootKey, RekeyTransaction), BaluardError> {
    let new_root = RootKey::generate();
    let new_epoch = old_epoch + 1;

    let mut wrapped_keys = Vec::with_capacity(enrolled_device_pubs.len());

    for (device_id, pub_bytes) in enrolled_device_pubs {
        let pub_key = x25519_dalek::PublicKey::from(*pub_bytes);
        let (eph_pub, ct, tag) = hpke_wrap::wrap_key(
            new_root.as_bytes(),
            &pub_key,
            &format!("keywrap:rotation:{new_epoch}"),
        )?;
        wrapped_keys.push(WrappedKeyEntry {
            device_id: *device_id,
            ephemeral_public: eph_pub,
            encrypted_key: ct,
            tag,
        });
    }

    let tx = RekeyTransaction {
        old_epoch,
        new_epoch,
        wrapped_root_keys: wrapped_keys,
        initiating_device_id,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        commit_barrier: Vec::new(),
    };

    Ok((new_root, tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hpke_wrap::generate_x25519_keypair;

    #[test]
    fn initiate_rotation_wraps_for_all_devices() {
        let (priv1, pub1) = generate_x25519_keypair();
        let (_priv2, pub2) = generate_x25519_keypair();

        let devices = vec![
            (Uuid::new_v4(), pub1.to_bytes()),
            (Uuid::new_v4(), pub2.to_bytes()),
        ];

        let (root_key, tx) = initiate_epoch_rotation(0, &devices, devices[0].0).unwrap();

        assert_eq!(tx.old_epoch, 0);
        assert_eq!(tx.new_epoch, 1);
        assert_eq!(tx.wrapped_root_keys.len(), 2);

        // Verify device 1 can unwrap its copy
        let entry = &tx.wrapped_root_keys[0];
        let unwrapped = hpke_wrap::unwrap_key(
            &entry.ephemeral_public,
            &entry.encrypted_key,
            &entry.tag,
            &priv1,
            "keywrap:rotation:1",
        )
        .unwrap();
        assert_eq!(unwrapped, root_key.as_bytes());
    }
}
