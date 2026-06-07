//! Manifest: hybrid filename-based cipher list + encrypted metadata files.
//!
//! D6: Cipher list from filenames in ciphers/. Encrypted meta files for structure.
//! Meta files: folders.json, settings.json, trash.enc, devices.enc, device-pks (plaintext).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::DeviceId;

/// Device registry entry (stored in meta/devices.json).
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
    /// Which device approved enrollment. None for first (founding) device.
    #[serde(default)]
    pub enrolled_by: Option<DeviceId>,
    /// Last epoch this device was seen in. 0 = unknown.
    #[serde(default)]
    pub last_seen_epoch: u64,
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

/// Folder definition (stored in meta/folders.json).
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
    /// URI match strategy global default. Typed enum with hard error on unknown values.
    #[serde(default, deserialize_with = "deserialize_uri_match_strategy")]
    pub default_uri_match: Option<crate::types::UriMatchStrategy>,
    /// Whether to fetch favicons from third-party sites for entries with URIs.
    /// `None` or `Some(true)` = enabled (default). `Some(false)` = disabled.
    #[serde(default)]
    pub fetch_favicons: Option<bool>,
}

fn deserialize_uri_match_strategy<'de, D>(
    deserializer: D,
) -> Result<Option<crate::types::UriMatchStrategy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            // Try typed enum first
            if let Ok(typed) = serde_json::from_value::<crate::types::UriMatchStrategy>(v.clone()) {
                return Ok(Some(typed));
            }
            // Try string with strict parsing
            if let Some(s) = v.as_str() {
                return crate::types::UriMatchStrategy::from_str_strict(s)
                    .map(Some)
                    .map_err(serde::de::Error::custom);
            }
            Err(serde::de::Error::custom("invalid URI match strategy"))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_settings_rejects_unknown_uri_match_strategy() {
        let json = r#"{"auto_lock_minutes": 10, "default_uri_match": "exakt"}"#;
        let result: Result<VaultSettings, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "expected error for unknown strategy, got: {:?}",
            result
        );
    }

    #[test]
    fn vault_settings_accepts_valid_uri_match_strategy() {
        let json = r#"{"default_uri_match": "host"}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(
            settings.default_uri_match,
            Some(crate::types::UriMatchStrategy::Host)
        );
    }

    #[test]
    fn vault_settings_null_uri_match_is_none() {
        let json = r#"{"default_uri_match": null}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert!(settings.default_uri_match.is_none());
    }
}
