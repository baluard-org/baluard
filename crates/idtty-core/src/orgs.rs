//! Org key distribution and member management.
//!
//! D17: X25519 + HPKE authenticated key wrapping.
//! D19: Auto-rekey all shared items on member removal.

use crate::crypto::hpke_wrap;
use crate::error::{IdttyError, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;
use x25519_dalek::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub email: String,
    pub device_id: Uuid,
    pub x25519_public_key: Vec<u8>, // HPKE recipient public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyBundle {
    pub ephemeral_pub: String, // hex
    pub ciphertext: String,    // hex
    pub tag: String,           // hex
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessList {
    pub members: Vec<OrgMember>,
    /// Group Keys wrapped per member: device_id -> hex-encoded HPKE ciphertexts
    pub wrapped_group_keys: HashMap<Uuid, WrappedKeyBundle>,
}

/// Load the access list JSON from disk. Returns default if not exists.
pub fn load_access_list(vault_path: &Path) -> Result<AccessList, IdttyError> {
    let path = vault_path.join("meta/access_list.json");
    if !path.exists() {
        return Ok(AccessList::default());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading access list: {e}")))?;
    let list: AccessList = serde_json::from_str(&data)
        .map_err(|e| VaultError::Corrupt(format!("access list parsing: {e}")))?;
    Ok(list)
}

/// Save the access list JSON to disk.
pub fn save_access_list(vault_path: &Path, list: &AccessList) -> Result<(), IdttyError> {
    let path = vault_path.join("meta/access_list.json");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let json = serde_json::to_string_pretty(list)
        .map_err(|e| VaultError::Metadata(format!("access list serialization: {e}")))?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Add a member and wrap the current Space Group Key for their device.
pub fn add_member(
    vault_path: &Path,
    email: &str,
    device_id: Uuid,
    x25519_pub_bytes: &[u8],
    group_key: &[u8; 32],
) -> Result<(), IdttyError> {
    let mut list = load_access_list(vault_path)?;

    // Remove if duplicate device_id exists
    list.members.retain(|m| m.device_id != device_id);

    let member = OrgMember {
        email: email.to_string(),
        device_id,
        x25519_public_key: x25519_pub_bytes.to_vec(),
    };

    // HPKE wrap the group key
    let mut pub_key_bytes = [0u8; 32];
    if x25519_pub_bytes.len() != 32 {
        return Err(VaultError::Metadata("invalid X25519 public key length".into()).into());
    }
    pub_key_bytes.copy_from_slice(x25519_pub_bytes);
    let pub_key = PublicKey::from(pub_key_bytes);

    let (eph_pub, ct, tag) = hpke_wrap::wrap_key(group_key, &pub_key)?;

    let bundle = WrappedKeyBundle {
        ephemeral_pub: hex::encode(eph_pub),
        ciphertext: hex::encode(ct),
        tag: hex::encode(tag),
    };

    list.members.push(member);
    list.wrapped_group_keys.insert(device_id, bundle);

    save_access_list(vault_path, &list)?;
    Ok(())
}

/// Remove a member and trigger a Group Key rotation (returns new group key).
pub fn remove_member(vault_path: &Path, device_id: Uuid) -> Result<[u8; 32], IdttyError> {
    let mut list = load_access_list(vault_path)?;

    list.members.retain(|m| m.device_id != device_id);
    list.wrapped_group_keys.remove(&device_id);

    // Generate a new rotated Space Group Key
    use rand::RngCore;
    let mut new_group_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_group_key);

    // Re-wrap the new Group Key for all remaining members
    let mut new_wrapped_group_keys = HashMap::new();
    for member in &list.members {
        let mut pub_key_bytes = [0u8; 32];
        if member.x25519_public_key.len() != 32 {
            continue;
        }
        pub_key_bytes.copy_from_slice(&member.x25519_public_key);
        let pub_key = PublicKey::from(pub_key_bytes);

        if let Ok((eph_pub, ct, tag)) = hpke_wrap::wrap_key(&new_group_key, &pub_key) {
            let bundle = WrappedKeyBundle {
                ephemeral_pub: hex::encode(eph_pub),
                ciphertext: hex::encode(ct),
                tag: hex::encode(tag),
            };
            new_wrapped_group_keys.insert(member.device_id, bundle);
        }
    }
    list.wrapped_group_keys = new_wrapped_group_keys;

    save_access_list(vault_path, &list)?;

    Ok(new_group_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_org_key_sharing_and_revocation() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();

        let group_key = [42u8; 32];
        let (_, device_pub) = hpke_wrap::generate_x25519_keypair();
        let device_id = Uuid::new_v4();

        // 1. Add member
        add_member(
            vault_path,
            "test@user.com",
            device_id,
            device_pub.as_bytes(),
            &group_key,
        )
        .unwrap();

        // Verify member exists in access list
        let list = load_access_list(vault_path).unwrap();
        assert_eq!(list.members.len(), 1);
        assert_eq!(list.members[0].email, "test@user.com");
        assert!(list.wrapped_group_keys.contains_key(&device_id));

        // 2. Rotate keys on member removal
        let new_key = remove_member(vault_path, device_id).unwrap();
        assert_ne!(new_key, group_key);

        // Verify member is removed
        let list_after = load_access_list(vault_path).unwrap();
        assert_eq!(list_after.members.len(), 0);
        assert!(!list_after.wrapped_group_keys.contains_key(&device_id));
    }
}
