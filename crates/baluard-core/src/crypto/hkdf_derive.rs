//! HKDF-SHA256 key derivation from KEK.
//!
//! D16: KEK → HKDF → Session Key + Sync-Only Key.
//! Critical rule: Argon2id for password derivation. HKDF only from already-stretched KEK.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

const SESSION_INFO: &[u8] = b"baluard-session-v1";
const SYNC_INFO: &[u8] = b"baluard-sync-v1";
/// Domain separation for the device-privkey seal subkey (C1).
/// Derives from the KEK so the seal opens exactly when master-password
/// material is present (creation, unlock, PIN-escrowed KEK).
const DEVKEY_SEAL_INFO: &[u8] = b"baluard-devkey-v1";
const SEQUENCE_INFO: &[u8] = b"baluard-sequence-v1";
const INDEX_INFO: &[u8] = b"baluard-index-v1";
const FOLDERS_INFO: &[u8] = b"baluard-folders-v1";
const TAGS_INFO: &[u8] = b"baluard-tags-v1";
const PROFILE_INFO: &[u8] = b"baluard-profile-v1";
const SETTINGS_INFO: &[u8] = b"baluard-settings-v1";
const ACTIVITY_INFO: &[u8] = b"baluard-activity-v1";
const GENERATOR_HISTORY_INFO: &[u8] = b"baluard-generator-history-v1";
const CONTACTS_INFO: &[u8] = b"baluard-contacts-v1";
const EVENTS_INFO: &[u8] = b"baluard-share-events-v1";

/// Derive a 32-byte Session Key from KEK.
///
/// Session Key encrypts the local vault cache (SQLite).
/// Purged from OS keystore on vault lock.
pub fn derive_session_key(kek: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    derive_key(kek, SESSION_INFO)
}

/// Derive a 32-byte Sync-Only Key from KEK.
///
/// Sync Key allows R/W encrypted blobs but CANNOT decrypt ciphers or access Root Key.
/// Retained through lock for desktop system tray background sync.
pub fn derive_sync_key(kek: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    derive_key(kek, SYNC_INFO)
}

/// Derive a 32-byte device-privkey seal key from KEK (C1).
///
/// Seals `meta/device-privkey.json` for keystore-less vaults. The KEK
/// itself is never retained post-unlock; the unlocked handle keeps only
/// this subkey.
pub fn derive_devkey_seal_key(kek: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    derive_key(kek, DEVKEY_SEAL_INFO)
}

/// Derive a 32-byte Sequence Key from Root Key.
///
/// Sequence Key encrypts per-device sequence manifests.
pub fn derive_sequence_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    // For 64-byte Root Key, use first 32 bytes as HKDF input
    // (HKDF-SHA256 accepts any length IKM)
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(SEQUENCE_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Index Key from Root Key.
pub fn derive_index_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(INDEX_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Folders Key from Root Key.
/// Used to encrypt/decrypt `meta/folders.enc`.
pub fn derive_folders_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(FOLDERS_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Tags Key from Root Key.
/// Used to encrypt/decrypt `meta/tags.enc`.
pub fn derive_tags_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(TAGS_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Profile Key from Root Key.
/// Used to encrypt/decrypt `meta/profile.enc` (user identity fields).
pub fn derive_profile_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(PROFILE_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Settings Key from Root Key.
///
/// Settings Key encrypts meta/settings.enc (vault_timeout, default_uri_match,
/// fetch_favicons, slug, enrollment_policy — the post-unlock settings that
/// leak vault identity/policy if plaintext on the remote).
pub fn derive_settings_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(SETTINGS_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Device Activity Key from Root Key.
///
/// Activity Key encrypts meta/activity.enc (device last-push metadata).
pub fn derive_activity_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(ACTIVITY_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Contacts Key from Root Key.
///
/// Contacts Key encrypts the local address book (meta/contacts.enc).
/// S1a-3 artifact: covered by rotation like the other RootKey-derived
/// metadata keys.
pub fn derive_contacts_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(CONTACTS_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Share Events Key from Root Key.
///
/// Events Key encrypts the sharing activity log (meta/share-events.enc).
/// S1b-1 artifact: covered by rotation like the other RootKey-derived
/// metadata keys.
pub fn derive_events_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(EVENTS_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Derive a 32-byte Generator History Key from Root Key.
/// Used to encrypt/decrypt `meta/generator-history.enc`.
pub fn derive_generator_history_key(root_key: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut key = [0u8; 32];
    hkdf.expand(GENERATOR_HISTORY_INFO, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

fn derive_key(kek: &[u8; 32], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, kek);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_deterministic() {
        let kek = [42u8; 32];
        let k1 = derive_session_key(&kek).unwrap();
        let k2 = derive_session_key(&kek).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn sync_key_deterministic() {
        let kek = [42u8; 32];
        let k1 = derive_sync_key(&kek).unwrap();
        let k2 = derive_sync_key(&kek).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn session_and_sync_differ() {
        let kek = [42u8; 32];
        let session = derive_session_key(&kek).unwrap();
        let sync = derive_sync_key(&kek).unwrap();
        assert_ne!(session, sync);
    }

    #[test]
    fn different_kek_different_keys() {
        let kek1 = [1u8; 32];
        let kek2 = [2u8; 32];
        assert_ne!(
            derive_session_key(&kek1).unwrap(),
            derive_session_key(&kek2).unwrap()
        );
        assert_ne!(
            derive_sync_key(&kek1).unwrap(),
            derive_sync_key(&kek2).unwrap()
        );
    }

    #[test]
    fn folders_key_deterministic() {
        let rk = [42u8; 64];
        assert_eq!(
            derive_folders_key(&rk).unwrap(),
            derive_folders_key(&rk).unwrap()
        );
    }

    #[test]
    fn tags_key_deterministic() {
        let rk = [42u8; 64];
        assert_eq!(derive_tags_key(&rk).unwrap(), derive_tags_key(&rk).unwrap());
    }

    #[test]
    fn index_folders_tags_all_differ() {
        let rk = [42u8; 64];
        let idx = derive_index_key(&rk).unwrap();
        let fld = derive_folders_key(&rk).unwrap();
        let tag = derive_tags_key(&rk).unwrap();
        assert_ne!(idx, fld);
        assert_ne!(idx, tag);
        assert_ne!(fld, tag);
    }

    #[test]
    fn generator_history_key_deterministic_and_unique() {
        let rk = [42u8; 64];
        let k1 = derive_generator_history_key(&rk).unwrap();
        let k2 = derive_generator_history_key(&rk).unwrap();
        assert_eq!(k1, k2);
        // Must differ from all other derived keys
        assert_ne!(k1, derive_profile_key(&rk).unwrap());
        assert_ne!(k1, derive_index_key(&rk).unwrap());
        assert_ne!(k1, derive_folders_key(&rk).unwrap());
        assert_ne!(k1, derive_tags_key(&rk).unwrap());
        assert_ne!(k1, derive_activity_key(&rk).unwrap());
    }

    #[test]
    fn profile_key_deterministic_and_unique() {
        let rk = [42u8; 64];
        let p1 = derive_profile_key(&rk).unwrap();
        let p2 = derive_profile_key(&rk).unwrap();
        assert_eq!(p1, p2);
        assert_ne!(p1, derive_index_key(&rk).unwrap());
        assert_ne!(p1, derive_folders_key(&rk).unwrap());
        assert_ne!(p1, derive_tags_key(&rk).unwrap());
    }
}
