//! Emergency access: public key wrapping + time-gated release.
//!
//! D18: Pre-wrapped Root Key in meta/emergency.json, advisory time gate.

use crate::crypto::hpke_wrap;
use crate::error::{IdttyError, VaultError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmergencyStatus {
    Inactive,
    Requested { request_time: u64 },
    Approved,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyConfig {
    pub trusted_contact_email: String,
    pub trusted_contact_pubkey: Vec<u8>, // X25519 public key
    pub delay_seconds: u64,
    pub wrapped_root_key: crate::orgs::WrappedKeyBundle, // HPKE wrapped Root Key
    pub status: EmergencyStatus,
}

/// Load the emergency config JSON from disk. Returns None if not exists.
pub fn load_emergency_config(vault_path: &Path) -> Result<Option<EmergencyConfig>, IdttyError> {
    let path = vault_path.join("meta/emergency.json");
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading emergency config: {e}")))?;
    let config: EmergencyConfig = serde_json::from_str(&data)
        .map_err(|e| VaultError::Corrupt(format!("emergency config parsing: {e}")))?;
    Ok(Some(config))
}

/// Save the emergency config JSON to disk (atomic write tmp + rename).
pub fn save_emergency_config(
    vault_path: &Path,
    config: &EmergencyConfig,
) -> Result<(), IdttyError> {
    let path = vault_path.join("meta/emergency.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| VaultError::Metadata(format!("emergency config serialization: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Setup emergency access for a trusted contact.
pub fn setup_emergency_access(
    vault_path: &Path,
    email: &str,
    contact_pubkey_bytes: &[u8],
    delay_seconds: u64,
    root_key: &[u8; 64],
) -> Result<(), IdttyError> {
    if contact_pubkey_bytes.len() != 32 {
        return Err(VaultError::Metadata("invalid X25519 public key length".into()).into());
    }

    let mut pub_key_bytes = [0u8; 32];
    pub_key_bytes.copy_from_slice(contact_pubkey_bytes);
    let pub_key = PublicKey::from(pub_key_bytes);

    let (eph_pub, ct, tag) = hpke_wrap::wrap_key(root_key, &pub_key)?;

    let wrapped_root_key = crate::orgs::WrappedKeyBundle {
        ephemeral_pub: hex::encode(eph_pub),
        ciphertext: hex::encode(ct),
        tag: hex::encode(tag),
    };

    let config = EmergencyConfig {
        trusted_contact_email: email.to_string(),
        trusted_contact_pubkey: contact_pubkey_bytes.to_vec(),
        delay_seconds,
        wrapped_root_key,
        status: EmergencyStatus::Inactive,
    };

    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Initiate the emergency recovery request. Called by the trusted contact.
pub fn initiate_emergency_request(vault_path: &Path) -> Result<(), IdttyError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    if matches!(config.status, EmergencyStatus::Revoked) {
        return Err(VaultError::Metadata(
            "Access Denied: emergency access has been permanently revoked by the owner".into(),
        )
        .into());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    config.status = EmergencyStatus::Requested { request_time: now };
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Approve the emergency request early. Called by the vault owner.
pub fn approve_emergency_request(vault_path: &Path) -> Result<(), IdttyError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    config.status = EmergencyStatus::Approved;
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Reject or revoke the emergency request/setup. Called by the vault owner.
pub fn reject_or_revoke_emergency(vault_path: &Path) -> Result<(), IdttyError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    config.status = EmergencyStatus::Revoked;
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Attempt to recover the root key as the trusted contact.
/// Must be either Approved or in Requested state with delay_seconds elapsed.
pub fn recover_emergency_root_key(
    vault_path: &Path,
    contact_privkey: &StaticSecret,
) -> Result<[u8; 64], IdttyError> {
    let config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let authorized = match config.status {
        EmergencyStatus::Approved => true,
        EmergencyStatus::Requested { request_time } => now >= request_time + config.delay_seconds,
        _ => false,
    };

    if !authorized {
        return Err(VaultError::Metadata(
            "Access Denied: wait time has not elapsed or not requested".into(),
        )
        .into());
    }

    let eph_pub = hex::decode(&config.wrapped_root_key.ephemeral_pub)
        .map_err(|e| VaultError::Corrupt(format!("invalid hex: {e}")))?;
    let ct = hex::decode(&config.wrapped_root_key.ciphertext)
        .map_err(|e| VaultError::Corrupt(format!("invalid hex: {e}")))?;
    let tag_bytes = hex::decode(&config.wrapped_root_key.tag)
        .map_err(|e| VaultError::Corrupt(format!("invalid hex: {e}")))?;

    if tag_bytes.len() != 16 {
        return Err(VaultError::Corrupt("invalid tag length".into()).into());
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    let decrypted = hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, contact_privkey)?;

    if decrypted.len() != 64 {
        return Err(VaultError::Corrupt("decrypted key is invalid length".into()).into());
    }

    let mut root_key = [0u8; 64];
    root_key.copy_from_slice(&decrypted);

    Ok(root_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_emergency_access_lifecycle() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();

        let root_key = [7u8; 64];
        let (contact_priv, contact_pub) = hpke_wrap::generate_x25519_keypair();

        // 1. Setup emergency access
        setup_emergency_access(
            vault_path,
            "emergency@contact.com",
            contact_pub.as_bytes(),
            10, // 10 seconds delay
            &root_key,
        )
        .unwrap();

        let config = load_emergency_config(vault_path).unwrap().unwrap();
        assert_eq!(config.status, EmergencyStatus::Inactive);
        assert_eq!(config.delay_seconds, 10);

        // 2. Recovery fails if requested but not elapsed
        initiate_emergency_request(vault_path).unwrap();
        let res = recover_emergency_root_key(vault_path, &contact_priv);
        assert!(res.is_err());

        // 3. Early approval works immediately
        approve_emergency_request(vault_path).unwrap();
        let recovered = recover_emergency_root_key(vault_path, &contact_priv).unwrap();
        assert_eq!(recovered, root_key);

        // 4. Revocation closes access
        reject_or_revoke_emergency(vault_path).unwrap();
        let res = recover_emergency_root_key(vault_path, &contact_priv);
        assert!(res.is_err());

        // 5. Re-initiation fails once Revoked
        let res = initiate_emergency_request(vault_path);
        assert!(res.is_err());
    }
}
