//! Canary creation and verification helpers.
//!
//! Shared by vault creation, key rotation, and password change.
//! Eliminates copy-paste of HKDF derivation + AEAD envelope construction.

use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::BaluardError;
use crate::keys::hierarchy::RootKey;
use crate::types::EnvelopeHeader;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};

// ── RK Canary ──

/// Domain-separated HKDF info string for Root Key canary key derivation.
const RK_CANARY_INFO: &[u8] = b"baluard-rk-canary-v1";
/// Expected plaintext inside the RK canary envelope.
const RK_CANARY_PT: &[u8] = b"baluard-rk-ok";
/// AAD used for the RK canary envelope.
const RK_CANARY_AAD: &[u8] = b"baluard-rk-canary-v1";

/// Derive a canary-specific key from a Root Key via HKDF-SHA256.
pub fn derive_rk_canary_key(root_key: &RootKey) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(RK_CANARY_INFO, &mut key)
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

/// Create an encrypted RK canary envelope.
///
/// Returns the serialized envelope bytes ready to write to `meta/rk-canary.enc`.
/// The caller is responsible for zeroizing the returned key if needed.
pub fn create_rk_canary(
    root_key: &RootKey,
    vault_id: Uuid,
    epoch: u64,
) -> Result<Vec<u8>, BaluardError> {
    let mut canary_key = derive_rk_canary_key(root_key);

    let nonce = crate::crypto::aead::build_nonce(0, vault_id);
    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch: epoch,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let envelope =
        crate::crypto::aead::encrypt(&canary_key, RK_CANARY_PT, RK_CANARY_AAD, &nonce, header)?;
    canary_key.zeroize();

    crate::vault::envelope::serialize(&envelope).map_err(Into::into)
}

/// Verify a Root Key against an RK canary envelope.
///
/// Decrypts the envelope and checks the plaintext matches `RK_CANARY_PT`.
pub fn verify_rk_canary(root_key: &RootKey, canary_bytes: &[u8]) -> Result<(), BaluardError> {
    let mut canary_key = derive_rk_canary_key(root_key);
    let envelope = crate::vault::envelope::deserialize(canary_bytes)?;
    let pt = crate::crypto::aead::decrypt(&canary_key, &envelope).inspect_err(|_| {
        canary_key.zeroize();
    });
    canary_key.zeroize();
    let pt =
        pt.map_err(|_| crate::error::VaultError::Corrupt("root key verification failed".into()))?;
    if pt != RK_CANARY_PT {
        return Err(crate::error::VaultError::Corrupt(
            "root key verification failed (plaintext mismatch)".into(),
        )
        .into());
    }
    Ok(())
}

// ── KEK Canary ──

/// Expected plaintext inside the KEK canary envelope.
const KEK_CANARY_PT: &[u8] = b"baluard-kek-ok";
/// AAD used for the KEK canary envelope.
const KEK_CANARY_AAD: &[u8] = b"baluard-kek-canary-v1";

/// Create an encrypted KEK canary envelope.
///
/// Encrypts the canary plaintext with the session key derived from KEK.
/// Returns serialized envelope bytes for `meta/kek-canary.enc`.
pub fn create_kek_canary(session_key: &[u8; 32], vault_id: Uuid) -> Result<Vec<u8>, BaluardError> {
    let nonce = crate::crypto::aead::build_nonce(0, vault_id);
    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let envelope =
        crate::crypto::aead::encrypt(session_key, KEK_CANARY_PT, KEK_CANARY_AAD, &nonce, header)?;
    crate::vault::envelope::serialize(&envelope).map_err(Into::into)
}

/// Verify a KEK/session key against a KEK canary envelope.
///
/// Returns `Ok(())` if decryption succeeds and plaintext matches.
pub fn verify_kek_canary(session_key: &[u8; 32], canary_bytes: &[u8]) -> Result<(), BaluardError> {
    let envelope = crate::vault::envelope::deserialize(canary_bytes)?;
    let pt = crate::crypto::aead::decrypt(session_key, &envelope)
        .map_err(|_| crate::error::VaultError::PasswordMismatch)?;
    if pt != KEK_CANARY_PT {
        return Err(crate::error::VaultError::PasswordMismatch.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::hierarchy::RootKey;

    #[test]
    fn rk_canary_roundtrip() {
        let rk = RootKey::generate();
        let vault_id = Uuid::new_v4();
        let bytes = create_rk_canary(&rk, vault_id, 1).unwrap();
        assert!(verify_rk_canary(&rk, &bytes).is_ok());
    }

    #[test]
    fn rk_canary_wrong_key_fails() {
        let rk = RootKey::generate();
        let wrong = RootKey::generate();
        let vault_id = Uuid::new_v4();
        let bytes = create_rk_canary(&rk, vault_id, 1).unwrap();
        assert!(verify_rk_canary(&wrong, &bytes).is_err());
    }

    #[test]
    fn kek_canary_roundtrip() {
        let vault_id = Uuid::new_v4();
        let key = [42u8; 32];
        let bytes = create_kek_canary(&key, vault_id).unwrap();
        assert!(verify_kek_canary(&key, &bytes).is_ok());
    }

    #[test]
    fn kek_canary_wrong_key_fails() {
        let vault_id = Uuid::new_v4();
        let key = [42u8; 32];
        let wrong = [99u8; 32];
        let bytes = create_kek_canary(&key, vault_id).unwrap();
        assert!(verify_kek_canary(&wrong, &bytes).is_err());
    }
}
