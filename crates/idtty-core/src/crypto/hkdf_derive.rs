//! HKDF-SHA256 key derivation from KEK.
//!
//! D16: KEK → HKDF → Session Key + Sync-Only Key.
//! Critical rule: Argon2id for password derivation. HKDF only from already-stretched KEK.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

const SESSION_INFO: &[u8] = b"idtty-session-v1";
const SYNC_INFO: &[u8] = b"idtty-sync-v1";
const SEQUENCE_INFO: &[u8] = b"idtty-sequence-v1";

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
}
