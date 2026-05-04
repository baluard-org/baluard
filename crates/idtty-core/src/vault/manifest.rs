//! Manifest: hybrid filename-based cipher list + encrypted metadata files.
//!
//! D6: Cipher list from filenames in ciphers/. Encrypted meta files for structure.
//! Meta files: folders.enc, settings.enc, trash.enc, devices.enc, device-pks (plaintext).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::DeviceId;

/// Device registry entry (stored encrypted in meta/devices.enc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: DeviceId,
    /// Device name (user-chosen, e.g. "MacBook Pro").
    pub name: String,
    /// X25519 public key (32 bytes, hex-encoded).
    pub encryption_public_key: String,
    /// Ed25519 public key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Unix timestamp of enrollment.
    pub enrolled_at: u64,
}

/// Plaintext device public keys (stored in meta/device-pks, quorum-signed).
/// Allows commit signature verification without vault decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublicKeys {
    pub keys: Vec<DevicePublicKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublicKeyEntry {
    pub device_id: DeviceId,
    /// Ed25519 verifying key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Quorum signature over this entry (Ed25519, hex-encoded).
    pub quorum_signature: String,
}

/// Folder definition (stored encrypted in meta/folders.enc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub icon: Option<String>,
}

/// Trash entry with logical timestamp (D6: per-item tombstones, delete-wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashEntry {
    pub object_id: Uuid,
    pub object_type: TrashObjectType,
    /// Monotonic sequence number (not wall-clock).
    pub delete_seq: u64,
    /// Device that performed the delete.
    pub deleted_by: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrashObjectType {
    Cipher,
    Folder,
}

/// Vault settings (stored encrypted in meta/settings.enc, last-write-wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    pub auto_lock_minutes: Option<u32>,
    pub theme: Option<String>,
    pub default_uri_match: Option<String>,
}

/// Sequence manifest entry (per device, stored in meta/sequences/{device_id}.enc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceManifest {
    pub vault_id: Uuid,
    pub device_id: DeviceId,
    pub epoch: u64,
    pub entries: Vec<SequenceEntry>,
    pub signed_at: u64,
    /// Ed25519 signature (hex-encoded).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceEntry {
    pub object_id: Uuid,
    pub last_seq: u64,
}
