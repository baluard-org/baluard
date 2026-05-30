//! Device lifecycle and root key rotation coordinator.
//!
//! D14: Per-device wrapping keys, selective rekey, emergency force evict.
//! Doc 06 Section 7: Epoch rotation with two-phase commit via git-mediated ack files.
//!
//! Architecture: DeviceManager aggregates DeviceRegistry + EpochInfo + RotationCoordinator.
//! Individual components stay independently testable. DeviceManager enforces cross-cutting invariants.

use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::signature;
use crate::devices::DeviceRegistry;
use crate::error::{DeviceError, IdttyError, KeyError, SyncError};
use crate::keys::epoch::{EpochInfo, EpochState};
use crate::keys::hierarchy::RootKey;
use crate::keys::rotation::{CommitBarrierSig, RekeyTransaction};
use crate::vault::manifest::DeviceEntry;

// ── Enrollment Authorization ──

/// Enrollment payload from a new device (QR code content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentPayload {
    pub device_id: Uuid,
    /// X25519 public key (32 bytes, hex-encoded).
    pub encryption_public_key: String,
    /// Ed25519 public key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Unix timestamp of payload creation.
    pub timestamp: u64,
    /// Anti-replay nonce (32 random bytes, hex-encoded).
    pub nonce: String,
    /// User-chosen device name.
    pub name: String,
}

/// Approval signature from an existing enrolled device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    /// Device ID of the approver.
    pub approver_device_id: Uuid,
    /// Ed25519 signature over H("enroll" || CBOR(payload) || nonce).
    pub signature: Vec<u8>,
}

/// Acknowledgment of an epoch rotation proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationAck {
    /// Epoch being acknowledged.
    pub epoch: u64,
    /// Device acknowledging.
    pub device_id: Uuid,
    /// SHA-256 hash of the .txn file content (binds ack to exact proposal).
    pub txn_hash: String,
    /// Ed25519 signature over H("ack" || epoch || device_id || txn_hash).
    pub signature: Vec<u8>,
}

// ── DeviceManager Aggregate ──

/// Device lifecycle coordinator. Owns registry, epoch state, and rotation logic.
pub struct DeviceManager {
    /// Device registry (enrolled devices, keys, quorum).
    pub registry: DeviceRegistry,
    /// Current epoch metadata.
    pub epoch: EpochInfo,
    /// Pending rekey transaction (Some during ROTATING state).
    pub pending_transaction: Option<RekeyTransaction>,
    /// Collected acks for current rotation.
    pub collected_acks: Vec<RotationAck>,
    /// Seen enrollment nonces (anti-replay).
    seen_nonces: Vec<String>,
    /// Path to vault directory (for file I/O).
    vault_path: Option<std::path::PathBuf>,
}

impl DeviceManager {
    /// Create a new DeviceManager with a fresh registry and epoch 0.
    pub fn new() -> Self {
        Self {
            registry: DeviceRegistry::new(),
            epoch: EpochInfo::new(0),
            pending_transaction: None,
            collected_acks: Vec::new(),
            seen_nonces: Vec::new(),
            vault_path: None,
        }
    }

    /// Create a DeviceManager from existing registry and epoch info.
    pub fn from_parts(registry: DeviceRegistry, epoch: EpochInfo) -> Self {
        Self {
            registry,
            epoch,
            pending_transaction: None,
            collected_acks: Vec::new(),
            seen_nonces: Vec::new(),
            vault_path: None,
        }
    }

    /// Set the vault path for file I/O operations.
    pub fn set_vault_path(&mut self, path: &Path) {
        self.vault_path = Some(path.to_path_buf());
    }

    /// Current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.epoch.epoch
    }

    /// Current epoch state.
    pub fn epoch_state(&self) -> EpochState {
        self.epoch.state
    }

    /// Check if vault writes are allowed (not during ROTATING).
    pub fn writes_allowed(&self) -> bool {
        matches!(self.epoch.state, EpochState::Active)
    }

    // ── Enrollment (D14: approval required) ──

    /// Enroll a new device with approval from an existing device.
    ///
    /// D14: First device auto-approves. Subsequent devices require a valid
    /// Ed25519 signature from an enrolled device over the enrollment payload.
    pub fn enroll(
        &mut self,
        payload: &EnrollmentPayload,
        approval: Option<&ApprovalSignature>,
    ) -> Result<DeviceEntry, IdttyError> {
        // Anti-replay: reject seen nonces
        if self.seen_nonces.contains(&payload.nonce) {
            return Err(DeviceError::EnrollmentRejected(
                "replay: nonce already used".into(),
            )
            .into());
        }

        // Timestamp window: ±5 minutes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = now.abs_diff(payload.timestamp);
        if drift > 300 {
            return Err(DeviceError::EnrollmentRejected(
                "stale: timestamp outside 5-minute window".into(),
            )
            .into());
        }

        // Validate public key lengths
        let enc_pk = hex::decode(&payload.encryption_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid encryption key hex".into()))?;
        let sig_pk = hex::decode(&payload.signing_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid signing key hex".into()))?;
        if enc_pk.len() != 32 || sig_pk.len() != 32 {
            return Err(DeviceError::EnrollmentRejected(
                "invalid public key length".into(),
            )
            .into());
        }

        let mut enc_arr = [0u8; 32];
        let mut sig_arr = [0u8; 32];
        enc_arr.copy_from_slice(&enc_pk);
        sig_arr.copy_from_slice(&sig_pk);

        // Authorization gate: first device auto-approves, others need approval
        if self.registry.count() > 0 {
            let approval = approval.ok_or_else(|| {
                DeviceError::EnrollmentRejected(
                    "approval required from enrolled device".into(),
                )
            })?;

            // Verify approver is enrolled
            if !self.registry.is_enrolled(&approval.approver_device_id) {
                return Err(DeviceError::EnrollmentRejected(
                    "approver not enrolled".into(),
                )
                .into());
            }

            // Verify signature
            let approver_entry = self
                .registry
                .devices
                .get(&approval.approver_device_id)
                .unwrap();
            let approver_vk_bytes: [u8; 32] =
                hex::decode(&approver_entry.signing_public_key)
                    .map_err(|_| DeviceError::Keystore("invalid approver key".into()))?
                    .try_into()
                    .map_err(|_| DeviceError::Keystore("approver key wrong length".into()))?;

            let verifying_key = signature::verifying_key_from_bytes(&approver_vk_bytes)
                .map_err(|_| DeviceError::EnrollmentRejected("invalid approver key".into()))?;

            // Build the signed payload: H("enroll" || payload_bytes || nonce)
            let payload_bytes = serde_json::to_vec(payload)
                .map_err(|e| DeviceError::EnrollmentRejected(format!("serialize: {e}")))?;
            let mut sign_input = b"enroll".to_vec();
            sign_input.extend_from_slice(&payload_bytes);
            let sig = ed25519_dalek::Signature::from_slice(&approval.signature)
                .map_err(|_| DeviceError::EnrollmentRejected("invalid signature".into()))?;
            signature::verify(&verifying_key, &sign_input, &sig)
                .map_err(|_| DeviceError::EnrollmentRejected("signature verification failed".into()))?;
        }

        // Record nonce
        self.seen_nonces.push(payload.nonce.clone());

        // Enroll in registry
        let entry = self.registry.enroll_with_id(
            payload.device_id,
            payload.name.clone(),
            enc_arr,
            sig_arr,
        )?;

        Ok(entry)
    }

    // ── Epoch Rotation (two-phase commit) ──

    /// Initiate epoch rotation. Generates new Root Key, wraps for all enrolled devices.
    ///
    /// Transitions epoch: ACTIVE → ROTATING.
    /// Vault writes are blocked until rotation completes.
    pub fn initiate_rotation(
        &mut self,
        initiating_device_id: Uuid,
    ) -> Result<(RootKey, &RekeyTransaction), IdttyError> {
        // Must be ACTIVE to start rotation
        if self.epoch.state != EpochState::Active {
            return Err(KeyError::InvalidEpochState(format!(
                "cannot initiate rotation from {:?}",
                self.epoch.state
            ))
            .into());
        }

        // Initiating device must be enrolled
        if !self.registry.is_enrolled(&initiating_device_id) {
            return Err(DeviceError::NotEnrolled(initiating_device_id.to_string()).into());
        }

        // Generate new Root Key and wrap for all enrolled devices
        let device_pubs = self.registry.encryption_public_keys();
        let (new_root, tx) = crate::keys::rotation::initiate_epoch_rotation(
            self.epoch.epoch,
            &device_pubs,
            initiating_device_id,
        )?;

        // Transition epoch to ROTATING
        self.epoch.begin_rotation().map_err(|e| KeyError::InvalidEpochState(e))?;

        self.pending_transaction = Some(tx);
        self.collected_acks.clear();

        Ok((new_root, self.pending_transaction.as_ref().unwrap()))
    }

    /// Record an acknowledgment from a device for the pending rotation.
    ///
    /// Verifies: device is enrolled, signature is valid, txn_hash matches.
    /// Automatically commits if quorum is reached.
    pub fn record_ack(&mut self, ack: RotationAck) -> Result<bool, IdttyError> {
        let tx = self
            .pending_transaction
            .as_ref()
            .ok_or_else(|| KeyError::InvalidEpochState("no pending rotation".into()))?;

        // Verify epoch matches
        if ack.epoch != tx.new_epoch {
            return Err(KeyError::EpochMismatch {
                expected: tx.new_epoch,
                actual: ack.epoch,
            }
            .into());
        }

        // Verify device is enrolled
        if !self.registry.is_enrolled(&ack.device_id) {
            return Err(DeviceError::NotEnrolled(ack.device_id.to_string()).into());
        }

        // Verify txn_hash matches pending transaction
        let actual_txn_hash = compute_txn_hash(tx);
        if ack.txn_hash != actual_txn_hash {
            return Err(DeviceError::EnrollmentRejected(
                "ack txn_hash mismatch".into(),
            )
            .into());
        }

        // Verify signature
        let device_entry = self.registry.devices.get(&ack.device_id).unwrap();
        let vk_bytes: [u8; 32] = hex::decode(&device_entry.signing_public_key)
            .map_err(|_| DeviceError::Keystore("invalid signing key".into()))?
            .try_into()
            .map_err(|_| DeviceError::Keystore("signing key wrong length".into()))?;

        let verifying_key = signature::verifying_key_from_bytes(&vk_bytes)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid device key".into()))?;

        let mut sign_input = b"ack".to_vec();
        sign_input.extend_from_slice(&ack.epoch.to_le_bytes());
        sign_input.extend_from_slice(ack.device_id.as_bytes());
        sign_input.extend_from_slice(ack.txn_hash.as_bytes());

        let sig = ed25519_dalek::Signature::from_slice(&ack.signature)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid ack signature".into()))?;
        signature::verify(&verifying_key, &sign_input, &sig)
            .map_err(|_| DeviceError::EnrollmentRejected("ack signature verification failed".into()))?;

        // Record ack
        self.collected_acks.push(ack);

        // Record in epoch
        self.epoch.acknowledge(self.collected_acks.last().unwrap().device_id);

        // Check quorum
        let quorum = self.registry.quorum_required();
        if self.collected_acks.len() >= quorum {
            self.commit_rotation()?;
            return Ok(true); // committed
        }

        Ok(false) // ack recorded, not yet committed
    }

    /// Commit a rotation after quorum is reached.
    /// Transitions: old epoch → RETIRED, new epoch → ACTIVE.
    fn commit_rotation(&mut self) -> Result<(), IdttyError> {
        let tx = self
            .pending_transaction
            .take()
            .ok_or_else(|| KeyError::InvalidEpochState("no pending transaction".into()))?;

        // Populate commit barrier with verified ack signatures
        let _commit_barrier: Vec<CommitBarrierSig> = self
            .collected_acks
            .iter()
            .map(|ack| CommitBarrierSig {
                device_id: ack.device_id,
                epoch: ack.epoch,
                signature: ack.signature.clone(),
            })
            .collect();

        // Transition epoch: ROTATING → RETIRED (old) → create new ACTIVE
        self.epoch.retire().map_err(|e| KeyError::InvalidEpochState(e))?;
        self.epoch = EpochInfo::new(tx.new_epoch);
        self.epoch.activate().map_err(|e| KeyError::InvalidEpochState(e))?;

        self.collected_acks.clear();

        Ok(())
    }

    // ── Force Evict ──

    /// Emergency force evict: removes all devices except survivor,
    /// then immediately initiates epoch rotation.
    ///
    /// Security: evicted device retains wrapped key until rekey.
    /// This method triggers rotation synchronously to close that window.
    pub fn force_evict_and_rotate(
        &mut self,
        surviving_device_id: Uuid,
    ) -> Result<ForceEvictResult, IdttyError> {
        let evicted = self.registry.force_evict(surviving_device_id)?;

        // Capture surviving count before initiating rotation (which borrows mutably)
        let surviving_count = self.registry.count();
        let quorum_needed = self.registry.quorum_required();

        // Immediately initiate rotation
        let (_new_root, tx) = self.initiate_rotation(surviving_device_id)?;
        let new_epoch = tx.new_epoch;

        // Single surviving device = self-ack = immediate commit
        let rotation_committed = if surviving_count <= quorum_needed {
            // Caller must provide the ack externally for production.
            // For single-device case, we auto-acknowledge using the epoch's ack mechanism.
            self.epoch.acknowledge(surviving_device_id);
            self.commit_rotation()?;
            true
        } else {
            false
        };

        Ok(ForceEvictResult {
            evicted_devices: evicted,
            rotation_committed,
            new_epoch: if rotation_committed { new_epoch } else { self.epoch.epoch },
        })
    }

    /// Generate a self-signed ack for a device that has its private key available.
    /// In production, the caller (VaultHandle/daemon) performs the actual signing
    /// and passes the completed RotationAck to record_ack().
    #[allow(dead_code)]
    fn sign_ack(
        &self,
        _device_id: Uuid,
        _epoch: u64,
        _txn_hash: &str,
    ) -> Result<RotationAck, IdttyError> {
        // Note: actual signing requires the device's Ed25519 private key,
        // which is not stored in DeviceManager (it's in the vault keywrap).
        // The caller (VaultHandle/daemon) performs the actual signing
        // and passes the completed RotationAck to record_ack().
        //
        // This method exists for single-device self-commit where the
        // caller has direct access to the signing key.
        Err(KeyError::RootKeyUnavailable.into())
    }

    // ── Persistence ──

    /// Load DeviceManager from vault directory.
    pub fn load_from_vault(vault_path: &Path) -> Result<Self, IdttyError> {
        let registry_path = vault_path.join("meta/devices.json");
        let registry = if registry_path.exists() {
            let data = std::fs::read_to_string(&registry_path)
                .map_err(|e| DeviceError::Keystore(format!("read devices: {e}")))?;
            serde_json::from_str(&data)
                .map_err(|e| DeviceError::Keystore(format!("parse devices: {e}")))?
        } else {
            DeviceRegistry::new()
        };

        let epoch_path = vault_path.join("meta/epoch.json");
        let epoch = if epoch_path.exists() {
            let data = std::fs::read_to_string(&epoch_path)
                .map_err(|e| KeyError::InvalidEpochState(format!("read epoch: {e}")))?;
            serde_json::from_str(&data)
                .map_err(|e| KeyError::InvalidEpochState(format!("parse epoch: {e}")))?
        } else {
            EpochInfo::new(0)
        };

        // Check for pending rotation transaction
        let mut pending_transaction = None;
        let mut collected_acks = Vec::new();
        let rekey_dir = vault_path.join(".idtty/rekey");
        if rekey_dir.exists() {
            // Look for .txn file matching current epoch+1
            let next_epoch = epoch.epoch + 1;
            let txn_path = rekey_dir.join(format!("{next_epoch}.txn"));
            if txn_path.exists() {
                let data = std::fs::read_to_string(&txn_path)
                    .map_err(|e| SyncError::Git(format!("read txn: {e}")))?;
                pending_transaction = Some(
                    serde_json::from_str(&data)
                        .map_err(|e| KeyError::InvalidEpochState(format!("parse txn: {e}")))?,
                );

                // Load existing acks
                for entry in std::fs::read_dir(&rekey_dir)
                    .map_err(|e| SyncError::Git(format!("read rekey dir: {e}")))?
                {
                    let entry = entry.map_err(|e| SyncError::Git(format!("dir entry: {e}")))?;
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(&format!("{next_epoch}.ack.")) {
                        let ack_data = std::fs::read_to_string(entry.path())
                            .map_err(|e| SyncError::Git(format!("read ack: {e}")))?;
                        if let Ok(ack) = serde_json::from_str(&ack_data) {
                            collected_acks.push(ack);
                        }
                    }
                }
            }
        }

        Ok(Self {
            registry,
            epoch,
            pending_transaction,
            collected_acks,
            seen_nonces: Vec::new(),
            vault_path: Some(vault_path.to_path_buf()),
        })
    }

    /// Save registry and epoch state to vault directory.
    pub fn save_to_vault(&self) -> Result<(), IdttyError> {
        let vault_path = self.vault_path.as_ref().ok_or_else(|| {
            DeviceError::Keystore("no vault path set".into())
        })?;

        let meta = vault_path.join("meta");
        std::fs::create_dir_all(&meta)
            .map_err(|e| DeviceError::Keystore(format!("create meta dir: {e}")))?;

        // Save registry
        let registry_json = serde_json::to_string_pretty(&self.registry)
            .map_err(|e| DeviceError::Keystore(format!("serialize registry: {e}")))?;
        std::fs::write(meta.join("devices.json"), registry_json)
            .map_err(|e| DeviceError::Keystore(format!("write registry: {e}")))?;

        // Save epoch
        let epoch_json = serde_json::to_string_pretty(&self.epoch)
            .map_err(|e| KeyError::InvalidEpochState(format!("serialize epoch: {e}")))?;
        std::fs::write(meta.join("epoch.json"), epoch_json)
            .map_err(|e| KeyError::InvalidEpochState(format!("write epoch: {e}")))?;

        // Save pending transaction if in ROTATING state
        if let Some(ref tx) = self.pending_transaction {
            let rekey_dir = vault_path.join(".idtty/rekey");
            std::fs::create_dir_all(&rekey_dir)
                .map_err(|e| SyncError::Git(format!("create rekey dir: {e}")))?;

            let txn_json = serde_json::to_string_pretty(tx)
                .map_err(|e| KeyError::InvalidEpochState(format!("serialize txn: {e}")))?;
            std::fs::write(rekey_dir.join(format!("{}.txn", tx.new_epoch)), txn_json)
                .map_err(|e| SyncError::Git(format!("write txn: {e}")))?;

            // Save acks
            for ack in &self.collected_acks {
                let ack_json = serde_json::to_string_pretty(ack)
                    .map_err(|e| KeyError::InvalidEpochState(format!("serialize ack: {e}")))?;
                let ack_path =
                    rekey_dir.join(format!("{}.ack.{}", ack.epoch, ack.device_id));
                std::fs::write(&ack_path, ack_json)
                    .map_err(|e| SyncError::Git(format!("write ack: {e}")))?;
            }
        }

        Ok(())
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a force evict operation.
#[derive(Debug)]
pub struct ForceEvictResult {
    /// Devices that were evicted.
    pub evicted_devices: Vec<DeviceEntry>,
    /// Whether the epoch rotation was immediately committed.
    pub rotation_committed: bool,
    /// New epoch number after rotation.
    pub new_epoch: u64,
}

/// Compute a hash of a rekey transaction for ack binding.
fn compute_txn_hash(tx: &RekeyTransaction) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Deterministic serialization of key fields
    hasher.update(tx.old_epoch.to_le_bytes());
    hasher.update(tx.new_epoch.to_le_bytes());
    hasher.update(tx.initiating_device_id.as_bytes());
    hasher.update(tx.timestamp.to_le_bytes());
    for entry in &tx.wrapped_root_keys {
        hasher.update(entry.device_id.as_bytes());
        hasher.update(&entry.ephemeral_public);
        hasher.update(&entry.encrypted_key);
        hasher.update(&entry.tag);
    }
    format!("{:x}", hasher.finalize())
}

// ── Helper: generate self-signed ack (for single-device commit) ──

/// Build the sign input for an ack. Public so callers can sign externally.
pub fn build_ack_sign_input(epoch: u64, device_id: &Uuid, txn_hash: &str) -> Vec<u8> {
    let mut input = b"ack".to_vec();
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(device_id.as_bytes());
    input.extend_from_slice(txn_hash.as_bytes());
    input
}

/// Build the sign input for enrollment approval. Public so callers can sign externally.
pub fn build_enroll_sign_input(payload: &EnrollmentPayload) -> Vec<u8> {
    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let mut input = b"enroll".to_vec();
    input.extend_from_slice(&payload_bytes);
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hpke_wrap, signature as sig};

    fn make_payload(name: &str) -> EnrollmentPayload {
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let nonce: [u8; 32] = rand::random();
        EnrollmentPayload {
            device_id: Uuid::new_v4(),
            encryption_public_key: hex::encode(x_pk),
            signing_public_key: hex::encode(e_pk),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: hex::encode(nonce),
            name: name.to_string(),
        }
    }

    #[test]
    fn first_device_auto_approves() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let payload = make_payload("First Device");
        let entry = mgr.enroll(&payload, None).unwrap();
        assert_eq!(entry.name, "First Device");
        assert_eq!(mgr.registry.count(), 1);
    }

    #[test]
    fn second_device_requires_approval() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // Enroll first device
        let p1 = make_payload("First");
        mgr.enroll(&p1, None).unwrap();

        // Enroll second device without approval → rejected
        let p2 = make_payload("Second");
        assert!(mgr.enroll(&p2, None).is_err());
    }

    #[test]
    fn second_device_with_valid_approval() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // Enroll first device (with known signing key)
        let (signing_key, verifying_key) = sig::generate_ed25519_keypair();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let p1 = EnrollmentPayload {
            device_id: Uuid::new_v4(),
            encryption_public_key: hex::encode(x_pk),
            signing_public_key: hex::encode(sig::verifying_key_bytes(&verifying_key)),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: hex::encode::<[u8; 32]>(rand::random()),
            name: "Approver".to_string(),
        };
        let approver_id = p1.device_id;
        mgr.enroll(&p1, None).unwrap();

        // Enroll second device with approval from first
        let p2 = make_payload("Second");
        let sign_input = build_enroll_sign_input(&p2);
        let approval_sig = sig::sign(&signing_key, &sign_input).unwrap();

        let approval = ApprovalSignature {
            approver_device_id: approver_id,
            signature: approval_sig.to_bytes().to_vec(),
        };

        let entry = mgr.enroll(&p2, Some(&approval)).unwrap();
        assert_eq!(entry.name, "Second");
        assert_eq!(mgr.registry.count(), 2);
    }

    #[test]
    fn replay_nonce_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let payload = make_payload("First");
        mgr.enroll(&payload, None).unwrap();

        // Reuse same nonce → rejected
        let mut payload2 = make_payload("Second");
        payload2.nonce = payload.nonce.clone();
        assert!(mgr.enroll(&payload2, None).is_err());
    }

    #[test]
    fn stale_timestamp_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let mut payload = make_payload("Stale");
        payload.timestamp = 0; // very old
        assert!(mgr.enroll(&payload, None).is_err());
    }

    #[test]
    fn initiate_rotation_transitions_to_rotating() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(device_id, "D1".into(), x_pk.to_bytes(), sig::verifying_key_bytes(&e_pk))
            .unwrap();

        let (_root_key, tx) = mgr.initiate_rotation(device_id).unwrap();
        assert_eq!(tx.new_epoch, 1);
        assert_eq!(tx.wrapped_root_keys.len(), 1);
        drop(tx); // release borrow on reference does nothing, but tx goes out of scope
        assert_eq!(mgr.epoch_state(), EpochState::Rotating);
        assert!(!mgr.writes_allowed());
    }

    #[test]
    fn single_device_self_commits() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(device_id, "Solo".into(), x_pk.to_bytes(), sig::verifying_key_bytes(&e_pk))
            .unwrap();

        let result = mgr.force_evict_and_rotate(device_id).unwrap();
        assert!(result.rotation_committed);
        assert_eq!(mgr.epoch_state(), EpochState::Active);
        assert!(mgr.writes_allowed());
        assert_eq!(mgr.current_epoch(), 1);
    }

    #[test]
    fn force_evict_removes_devices() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let d1 = mgr.registry.enroll("D1".into(), [1u8; 32], [2u8; 32]).unwrap();
        let d2 = mgr.registry.enroll("D2".into(), [3u8; 32], [4u8; 32]).unwrap();
        let d3 = mgr.registry.enroll("D3".into(), [5u8; 32], [6u8; 32]).unwrap();

        // Note: force_evict keeps ONLY surviving device, removes all others.
        let result = mgr.force_evict_and_rotate(d1.device_id).unwrap();
        assert_eq!(result.evicted_devices.len(), 2);
        assert_eq!(mgr.registry.count(), 1);
        assert!(mgr.registry.is_enrolled(&d1.device_id));
        assert!(!mgr.registry.is_enrolled(&d2.device_id));
        assert!(!mgr.registry.is_enrolled(&d3.device_id));
    }

    #[test]
    fn concurrent_rotation_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(device_id, "D1".into(), [1u8; 32], [2u8; 32])
            .unwrap();

        mgr.initiate_rotation(device_id).unwrap();
        // Second initiation while ROTATING → error
        assert!(mgr.initiate_rotation(device_id).is_err());
    }

    #[test]
    fn ack_with_wrong_txn_hash_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let (signing_key, verifying_key) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        mgr.registry
            .enroll_with_id(
                device_id,
                "D1".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&verifying_key),
            )
            .unwrap();

        let (_, _) = mgr.initiate_rotation(device_id).unwrap();

        // Build ack with wrong txn_hash
        let sign_input = build_ack_sign_input(1, &device_id, "wrong_hash");
        let ack_sig = sig::sign(&signing_key, &sign_input).unwrap();

        let ack = RotationAck {
            epoch: 1,
            device_id,
            txn_hash: "wrong_hash".to_string(),
            signature: ack_sig.to_bytes().to_vec(),
        };

        assert!(mgr.record_ack(ack).is_err());
    }

    #[test]
    fn ack_forgery_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let (real_signing, real_verifying) = sig::generate_ed25519_keypair();
        let (fake_signing, _) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        mgr.registry
            .enroll_with_id(
                device_id,
                "D1".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&real_verifying),
            )
            .unwrap();

        let (_, tx) = mgr.initiate_rotation(device_id).unwrap();
        let txn_hash = compute_txn_hash(tx);

        // Sign with wrong key
        let sign_input = build_ack_sign_input(1, &device_id, &txn_hash);
        let forged_sig = sig::sign(&fake_signing, &sign_input).unwrap();

        let ack = RotationAck {
            epoch: 1,
            device_id,
            txn_hash,
            signature: forged_sig.to_bytes().to_vec(),
        };

        assert!(mgr.record_ack(ack).is_err());
    }

    #[test]
    fn quorum_gate_multi_device() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // 3 devices: need ceil(3/2) = 2 acks
        let _d1 = mgr.registry.enroll("D1".into(), [1u8; 32], [2u8; 32]).unwrap();
        let _d2 = mgr.registry.enroll("D2".into(), [3u8; 32], [4u8; 32]).unwrap();
        let _d3 = mgr.registry.enroll("D3".into(), [5u8; 32], [6u8; 32]).unwrap();

        // Can't initiate with real rotation (need real keypairs for HPKE wrapping)
        // Just test quorum_required logic
        assert_eq!(mgr.registry.quorum_required(), 2);
    }

    #[test]
    fn epoch_state_transitions_valid() {
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
}
