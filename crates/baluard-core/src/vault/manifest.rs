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

/// Tag index cache (stored in meta/tag_index.json).
/// Derived from decrypted cipher tags. Committed to git for cross-device sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagIndex {
    pub tags: Vec<String>,
    #[serde(default)]
    pub updated_at: u64,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultSettings {
    pub auto_lock_minutes: Option<u32>,
    pub theme: Option<crate::types::ThemeMode>,
    /// Language code (e.g. "en", "es"). Persisted separately in plaintext meta/locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// URI match strategy global default. Typed enum with hard error on unknown values.
    #[serde(default, deserialize_with = "deserialize_uri_match_strategy")]
    pub default_uri_match: Option<crate::types::UriMatchStrategy>,
    /// Whether to fetch favicons from third-party sites for entries with URIs.
    /// `None` or `Some(true)` = enabled (default). `Some(false)` = disabled.
    #[serde(default)]
    pub fetch_favicons: Option<bool>,
    /// Vault slug (machine-friendly identifier, e.g. "baluard-personal").
    /// Immutable after creation. Used as filesystem folder name, registry key, and git repo name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// User display name shown in sidebar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// User subtitle/role shown under display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    /// Avatar file extension (e.g. "png", "jpg"). Avatar stored at meta/avatar.{ext}.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_ext: Option<String>,
    /// Enrollment policy controls how a new device joins this vault.
    /// - `Personal` (default for new vaults): either an enrolled-device
    ///   signature OR the recovery phrase can authorize enrollment. The
    ///   recovery phrase is the root authority and can already perform
    ///   full disaster recovery; non-destructive enrollment via phrase
    ///   is a strict subset of that authority.
    /// - `Strict` (default for existing vaults, backward compat): only an
    ///   enrolled-device signature can authorize enrollment. Recovery
    ///   phrase only works via destructive `recover_from_phrase`.
    /// Migrating from Strict to Personal is a one-way door; re-read docs
    /// before doing so.
    #[serde(default = "default_enrollment_policy")]
    pub enrollment_policy: EnrollmentPolicy,
}

/// Vault enrollment policy for new device joins.
///
/// See `VaultSettings::enrollment_policy` for the full description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EnrollmentPolicy {
    /// New vaults: phrase OR enrolled-device signature can enroll.
    #[default]
    Personal,
    /// Existing vaults: only enrolled-device signature can enroll.
    Strict,
}

fn default_enrollment_policy() -> EnrollmentPolicy {
    // Called when the field is missing from existing settings.json.
    // Backward compat: old vaults were Strict (required device approval).
    EnrollmentPolicy::Strict
}

/// Encrypted user profile fields (stored in meta/profile.enc).
/// Separated from VaultSettings to prevent identity leakage via git sync.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub subtitle: Option<String>,
    pub avatar_ext: Option<String>,
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

    #[test]
    fn theme_mode_serde_roundtrip() {
        use crate::types::ThemeMode;
        for theme in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
            let json = serde_json::to_string(&theme).unwrap();
            let back: ThemeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(theme, back);
        }
    }

    #[test]
    fn theme_mode_rejects_unknown() {
        let result: Result<crate::types::ThemeMode, _> = serde_json::from_str("\"neon\"");
        assert!(result.is_err());
    }

    #[test]
    fn theme_mode_case_insensitive_deserialize() {
        // Existing vaults may have capitalized theme strings
        for (input, expected) in [
            ("\"Light\"", crate::types::ThemeMode::Light),
            ("\"DARK\"", crate::types::ThemeMode::Dark),
            ("\"System\"", crate::types::ThemeMode::System),
            ("\"light\"", crate::types::ThemeMode::Light),
        ] {
            let result: crate::types::ThemeMode = serde_json::from_str(input).unwrap();
            assert_eq!(result, expected, "failed for input: {input}");
        }
    }

    #[test]
    fn vault_settings_theme_roundtrip() {
        let settings = VaultSettings {
            theme: Some(crate::types::ThemeMode::Dark),
            lang: Some("es".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: VaultSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.theme, Some(crate::types::ThemeMode::Dark));
        assert_eq!(back.lang.as_deref(), Some("es"));
    }

    #[test]
    fn vault_settings_lang_skipped_when_none() {
        let settings = VaultSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        assert!(!json.contains("lang"));
    }
}
