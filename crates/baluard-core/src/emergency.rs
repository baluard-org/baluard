//! Emergency access: public key wrapping + owner-approved release.
//!
//! D18: Pre-wrapped Root Key in meta/emergency.json, owner-signed approval.
//!
//! C3 fix: Only explicit owner approval (Ed25519-signed) unlocks recovery.
//! The verifying key is pinned to the device registry (not self-stored),
//! preventing the grantee from forging signatures. The client-side time
//! gate is advisory-only and does NOT grant recovery. The wrapped Root Key
//! is stored with 0600 permissions and should be excluded from git sync.

use crate::crypto::hpke_wrap;
use crate::crypto::signature;
use crate::error::{BaluardError, VaultError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmergencyStatus {
    Inactive,
    /// Advisory: signals intent to recover. Does NOT grant access.
    Requested {
        request_time: u64,
    },
    Approved,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyConfig {
    pub trusted_contact_email: String,
    pub trusted_contact_pubkey: Vec<u8>, // X25519 public key
    pub delay_seconds: u64,
    pub wrapped_root_key: crate::orgs::WrappedKeyBundle, // HPKE-wrapped Root Key for the contact
    pub status: EmergencyStatus,
    /// Vault ID this config belongs to (prevents cross-vault replay).
    pub vault_id: Option<String>,
    /// Ed25519 signature from the owner's device key over the status transition.
    /// Covers: status || vault_id. Prevents grantee tampering with the approval.
    /// Verified against the PINNED key from the device registry, not from this file.
    pub owner_signature: Option<String>,
}

/// Load the emergency config JSON from disk. Returns None if not exists.
pub fn load_emergency_config(vault_path: &Path) -> Result<Option<EmergencyConfig>, BaluardError> {
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
/// Sets 0600 permissions to prevent same-group/other read access.
pub fn save_emergency_config(
    vault_path: &Path,
    config: &EmergencyConfig,
) -> Result<(), BaluardError> {
    let path = vault_path.join("meta/emergency.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| VaultError::Metadata(format!("emergency config serialization: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    // C3 fix: harden permissions after rename
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Setup emergency access for a trusted contact.
/// Signs the initial config with the owner's device key to prevent tampering.
pub fn setup_emergency_access(
    vault_path: &Path,
    email: &str,
    contact_pubkey_bytes: &[u8],
    delay_seconds: u64,
    root_key: &[u8; 64],
    vault_id: &str,
    owner_signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), BaluardError> {
    if contact_pubkey_bytes.len() != 32 {
        return Err(VaultError::Metadata("invalid X25519 public key length".into()).into());
    }

    let mut pub_key_bytes = [0u8; 32];
    pub_key_bytes.copy_from_slice(contact_pubkey_bytes);
    let pub_key = PublicKey::from(pub_key_bytes);

    let wrapped_root_key = crate::orgs::wrap_to_bundle(root_key, &pub_key, "emergency-escrow")?;

    let mut config = EmergencyConfig {
        trusted_contact_email: email.to_string(),
        trusted_contact_pubkey: contact_pubkey_bytes.to_vec(),
        delay_seconds,
        wrapped_root_key,
        status: EmergencyStatus::Inactive,
        vault_id: Some(vault_id.to_string()),
        owner_signature: None,
    };

    // Sign the initial status
    sign_status(&mut config, owner_signing_key, vault_id)?;

    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Initiate the emergency recovery request. Called by the trusted contact.
/// This is advisory-only: it does NOT grant recovery access.
/// The owner must explicitly approve via `approve_emergency_request`.
pub fn initiate_emergency_request(vault_path: &Path) -> Result<(), BaluardError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    if matches!(config.status, EmergencyStatus::Revoked) {
        return Err(VaultError::Metadata(
            "Access Denied: emergency access has been permanently revoked by the owner".into(),
        )
        .into());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    config.status = EmergencyStatus::Requested { request_time: now };
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Approve the emergency request. Called by the vault owner.
/// Signs the approval with the owner's device key, making it tamper-proof.
pub fn approve_emergency_request(
    vault_path: &Path,
    owner_signing_key: &ed25519_dalek::SigningKey,
    vault_id: &str,
) -> Result<(), BaluardError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    config.status = EmergencyStatus::Approved;
    sign_status(&mut config, owner_signing_key, vault_id)?;
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Reject or revoke the emergency request/setup. Called by the vault owner.
/// Signs the revocation with the owner's device key.
pub fn reject_or_revoke_emergency(
    vault_path: &Path,
    owner_signing_key: &ed25519_dalek::SigningKey,
    vault_id: &str,
) -> Result<(), BaluardError> {
    let mut config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    config.status = EmergencyStatus::Revoked;
    sign_status(&mut config, owner_signing_key, vault_id)?;
    save_emergency_config(vault_path, &config)?;
    Ok(())
}

/// Attempt to recover the root key as the trusted contact.
///
/// Only `Approved` status is accepted, and the signature is verified against
/// the **pinned** owner verifying key from the device registry (not from the
/// config file itself). This prevents the grantee from forging approvals by
/// substituting their own key.
///
/// `owner_verifying_key` must be loaded from the device registry by the caller.
pub fn recover_emergency_root_key(
    vault_path: &Path,
    contact_privkey: &StaticSecret,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<[u8; 64], BaluardError> {
    let config = load_emergency_config(vault_path)?
        .ok_or_else(|| VaultError::Metadata("emergency access not configured".into()))?;

    // Only explicit owner approval is accepted.
    // The Requested time-gate path is advisory-only and does NOT grant recovery.
    match &config.status {
        EmergencyStatus::Approved => {
            // Verify signature against the PINNED key from the device registry.
            // This prevents the grantee from re-signing with their own key.
            verify_status_signature(&config, owner_verifying_key)?;
        }
        _ => {
            return Err(VaultError::Metadata(
                "Access Denied: emergency access not approved by the owner".into(),
            )
            .into());
        }
    };

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

    let decrypted =
        hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, contact_privkey, "emergency-escrow")?;

    if decrypted.len() != 64 {
        return Err(VaultError::Corrupt("decrypted key is invalid length".into()).into());
    }

    let mut root_key = [0u8; 64];
    root_key.copy_from_slice(&decrypted);

    Ok(root_key)
}

/// Build the signable payload from config status + vault_id.
/// Covers: status_json || vault_id, preventing tampering with either.
fn status_payload(config: &EmergencyConfig) -> Vec<u8> {
    let status_json = serde_json::to_string(&config.status).unwrap_or_default();
    let vault_id = config.vault_id.as_deref().unwrap_or("");
    let mut payload = Vec::with_capacity(status_json.len() + vault_id.len());
    payload.extend_from_slice(status_json.as_bytes());
    payload.extend_from_slice(vault_id.as_bytes());
    payload
}

/// Sign the current status with the owner's Ed25519 device key.
/// The signature covers `status || vault_id` only — NOT the
/// `wrapped_root_key` (that is bound by HPKE to the contact pubkey).
/// `pub(crate)`: also used by the rotation rewrap, which must re-sign after
/// swapping the wrapped key so the pinned-key verification stays valid.
pub(crate) fn sign_status(
    config: &mut EmergencyConfig,
    owner_signing_key: &ed25519_dalek::SigningKey,
    vault_id: &str,
) -> Result<(), BaluardError> {
    config.vault_id = Some(vault_id.to_string());
    let payload = status_payload(config);
    let sig = signature::sign(owner_signing_key, &payload)
        .map_err(|e| VaultError::Metadata(format!("emergency signature: {e}")))?;
    config.owner_signature = Some(hex::encode(sig.to_bytes()));
    Ok(())
}

/// Verify the owner's signature on the config status against the PINNED
/// verifying key from the device registry. The key is NOT read from the
/// config file, preventing the grantee from substituting their own key.
fn verify_status_signature(
    config: &EmergencyConfig,
    pinned_vk: &ed25519_dalek::VerifyingKey,
) -> Result<(), BaluardError> {
    let sig_hex = config
        .owner_signature
        .as_deref()
        .ok_or_else(|| VaultError::Corrupt("emergency config missing owner signature".into()))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| VaultError::Corrupt(format!("emergency signature hex: {e}")))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| VaultError::Corrupt("invalid emergency signature".into()))?;

    let payload = status_payload(config);
    signature::verify(pinned_vk, &payload, &sig).map_err(|_| {
        VaultError::Corrupt("emergency config: invalid owner signature (tampered?)".into())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::generate_ed25519_keypair;
    use tempfile::tempdir;

    fn owner_vk(signing: &ed25519_dalek::SigningKey) -> ed25519_dalek::VerifyingKey {
        signing.verifying_key()
    }

    #[test]
    fn test_emergency_access_lifecycle() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();
        let vault_id = "test-vault-001";

        let root_key = [7u8; 64];
        let (contact_priv, contact_pub) = hpke_wrap::generate_x25519_keypair();
        let (owner_signing, _) = generate_ed25519_keypair();

        // 1. Setup emergency access
        setup_emergency_access(
            vault_path,
            "emergency@contact.com",
            contact_pub.as_bytes(),
            10,
            &root_key,
            vault_id,
            &owner_signing,
        )
        .unwrap();

        let config = load_emergency_config(vault_path).unwrap().unwrap();
        assert_eq!(config.status, EmergencyStatus::Inactive);
        assert!(config.owner_signature.is_some());

        // 2. Request does NOT grant recovery (advisory-only)
        initiate_emergency_request(vault_path).unwrap();
        let res = recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing));
        assert!(res.is_err());

        // 3. Owner-signed approval grants recovery
        approve_emergency_request(vault_path, &owner_signing, vault_id).unwrap();
        let recovered =
            recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing))
                .unwrap();
        assert_eq!(recovered, root_key);

        // 4. Revocation closes access
        reject_or_revoke_emergency(vault_path, &owner_signing, vault_id).unwrap();
        let res = recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing));
        assert!(res.is_err());

        // 5. Re-initiation fails once Revoked
        let res = initiate_emergency_request(vault_path);
        assert!(res.is_err());
    }

    #[test]
    fn test_tampered_approval_no_signature() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();
        let vault_id = "test-vault-002";

        let root_key = [42u8; 64];
        let (contact_priv, contact_pub) = hpke_wrap::generate_x25519_keypair();
        let (owner_signing, _) = generate_ed25519_keypair();

        setup_emergency_access(
            vault_path,
            "evil@contact.com",
            contact_pub.as_bytes(),
            600,
            &root_key,
            vault_id,
            &owner_signing,
        )
        .unwrap();

        // Grantee writes Approved with no signature
        let mut config = load_emergency_config(vault_path).unwrap().unwrap();
        config.status = EmergencyStatus::Approved;
        config.owner_signature = None;
        let json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(vault_path.join("meta/emergency.json"), json).unwrap();

        let res = recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing));
        assert!(res.is_err(), "Must reject unsigned approval");
    }

    #[test]
    fn test_bypass_a_grantee_re_signs_with_own_key() {
        // Peer review Bypass A: grantee generates own keypair, self-signs Approved.
        // Must fail because verifying key is pinned to device registry (owner's key).
        let dir = tempdir().unwrap();
        let vault_path = dir.path();
        let vault_id = "test-vault-bypass-a";

        let root_key = [55u8; 64];
        let (contact_priv, contact_pub) = hpke_wrap::generate_x25519_keypair();
        let (owner_signing, _) = generate_ed25519_keypair();

        setup_emergency_access(
            vault_path,
            "evil@contact.com",
            contact_pub.as_bytes(),
            600,
            &root_key,
            vault_id,
            &owner_signing,
        )
        .unwrap();

        // Grantee generates their own Ed25519 keypair and self-signs
        let (grantee_signing, _) = generate_ed25519_keypair();
        let mut config = load_emergency_config(vault_path).unwrap().unwrap();
        config.status = EmergencyStatus::Approved;
        // Sign with the grantee's key (NOT the owner's)
        let payload = status_payload(&config);
        let sig = signature::sign(&grantee_signing, &payload).unwrap();
        config.owner_signature = Some(hex::encode(sig.to_bytes()));
        let json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(vault_path.join("meta/emergency.json"), json).unwrap();

        // Recovery must fail: signature doesn't match the PINNED owner key
        let res = recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing));
        assert!(
            res.is_err(),
            "Bypass A: Must reject grantee's self-signed approval (key not pinned)"
        );
    }

    #[test]
    fn test_bypass_b_requested_zero_time_instant_recovery() {
        // Peer review Bypass B: grantee sets Requested { request_time: 0 } for instant recovery.
        // Must fail because Requested path no longer grants recovery.
        let dir = tempdir().unwrap();
        let vault_path = dir.path();
        let vault_id = "test-vault-bypass-b";

        let root_key = [99u8; 64];
        let (contact_priv, contact_pub) = hpke_wrap::generate_x25519_keypair();
        let (owner_signing, _) = generate_ed25519_keypair();

        setup_emergency_access(
            vault_path,
            "evil@contact.com",
            contact_pub.as_bytes(),
            0, // zero delay
            &root_key,
            vault_id,
            &owner_signing,
        )
        .unwrap();

        // Grantee writes Requested { request_time: 0 } — instant time gate bypass
        let mut config = load_emergency_config(vault_path).unwrap().unwrap();
        config.status = EmergencyStatus::Requested { request_time: 0 };
        let json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(vault_path.join("meta/emergency.json"), json).unwrap();

        // Recovery must fail: Requested does NOT grant recovery
        let res = recover_emergency_root_key(vault_path, &contact_priv, &owner_vk(&owner_signing));
        assert!(
            res.is_err(),
            "Bypass B: Must reject Requested status (only Approved grants recovery)"
        );
    }
}
