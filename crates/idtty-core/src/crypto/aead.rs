//! AEAD encryption: AES-256-GCM envelope construction.
//!
//! D3: versioned envelope with AAD binding.
//! AAD = SHA256(vault_id || object_type || object_id || tier || alg_id || key_epoch || update_seq)

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::error::CryptoError;
use crate::types::{CipherEnvelope, EnvelopeHeader, ObjectType, Tier};
use uuid::Uuid;

/// Construct the AAD hash from context-binding fields.
///
/// Binds ciphertext to: vault, object identity, size tier, algorithm, epoch, version.
/// Prevents cut-and-paste and rollback attacks.
///
/// Each field is length-prefixed (u64 LE) to prevent collision attacks
/// where different (object_type, object_id) pairs produce identical byte strings.
pub fn build_aad(
    vault_id: Uuid,
    object_type: ObjectType,
    object_id: Uuid,
    tier: Option<Tier>,
    alg_id: u16,
    key_epoch: u64,
    update_seq: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Domain separation prefix
    hasher.update(b"idtty-aad-v2");
    // Length-prefixed fields to prevent collision
    let vault_bytes = vault_id.as_bytes();
    hasher.update((vault_bytes.len() as u64).to_le_bytes());
    hasher.update(vault_bytes);
    let ot_bytes = object_type.as_str().as_bytes();
    hasher.update((ot_bytes.len() as u64).to_le_bytes());
    hasher.update(ot_bytes);
    let oid_bytes = object_id.as_bytes();
    hasher.update((oid_bytes.len() as u64).to_le_bytes());
    hasher.update(oid_bytes);
    let tier_str = tier.map(|t| t.code()).unwrap_or("none");
    let tier_bytes = tier_str.as_bytes();
    hasher.update((tier_bytes.len() as u64).to_le_bytes());
    hasher.update(tier_bytes);
    hasher.update((2u64).to_le_bytes()); // alg_id is u16 = 2 bytes
    hasher.update(alg_id.to_le_bytes());
    hasher.update((8u64).to_le_bytes());
    hasher.update(key_epoch.to_le_bytes());
    hasher.update((8u64).to_le_bytes());
    hasher.update(update_seq.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Build a 12-byte nonce from a per-object counter and object shard ID.
///
/// nonce = nonce_counter (8 bytes LE) || object_shard_id (4 bytes)
pub fn build_nonce(nonce_counter: u64, object_id: Uuid) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());
    // First 4 bytes of UUID as shard ID for namespace separation
    nonce[8..].copy_from_slice(&object_id.as_bytes()[..4]);
    nonce
}

/// Encrypt plaintext with AES-256-GCM, producing a full cipher envelope.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    nonce: &[u8; 12],
    header: EnvelopeHeader,
) -> Result<CipherEnvelope, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);
    let ciphertext_bytes = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::EncryptFailed(e.to_string()))?;

    // aes-gcm appends the 16-byte tag to the ciphertext
    if ciphertext_bytes.len() < 16 {
        return Err(CryptoError::EncryptFailed("ciphertext too short".into()));
    }
    let ct_len = ciphertext_bytes.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext_bytes[ct_len..]);

    Ok(CipherEnvelope {
        header,
        nonce: *nonce.as_ref(),
        aad: aad.to_vec(),
        ciphertext: ciphertext_bytes[..ct_len].to_vec(),
        tag,
    })
}

/// Decrypt a cipher envelope with AES-256-GCM.
pub fn decrypt(key: &[u8; 32], envelope: &CipherEnvelope) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptFailed(e.to_string()))?;

    // Reconstruct ciphertext + tag for aes-gcm
    let mut ct_with_tag = Vec::with_capacity(envelope.ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(&envelope.ciphertext);
    ct_with_tag.extend_from_slice(&envelope.tag);

    let nonce = Nonce::from_slice(&envelope.nonce);
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ct_with_tag,
                aad: &envelope.aad,
            },
        )
        .map_err(|_| CryptoError::AuthTagMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ALG_AES_256_GCM, IDTTY_VERSION};
    use uuid::Uuid;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let vault_id = Uuid::new_v4();
        let object_id = Uuid::new_v4();
        let plaintext = b"hello idtty vault content";

        let aad = build_aad(
            vault_id,
            ObjectType::Cipher,
            object_id,
            Some(Tier::Xs),
            ALG_AES_256_GCM,
            1,
            1,
        );
        let nonce = build_nonce(0, object_id);
        let header = EnvelopeHeader {
            version: IDTTY_VERSION,
            alg_id: ALG_AES_256_GCM,
            key_epoch: 1,
            nonce_counter: 0,
            update_seq: 1,
            tier: Some(Tier::Xs),
        };

        let envelope = encrypt(&key, plaintext, &aad, &nonce, header).unwrap();
        let decrypted = decrypt(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let vault_id = Uuid::new_v4();
        let object_id = Uuid::new_v4();

        let aad = build_aad(
            vault_id,
            ObjectType::Cipher,
            object_id,
            Some(Tier::S),
            ALG_AES_256_GCM,
            1,
            1,
        );
        let nonce = build_nonce(0, object_id);
        let header = EnvelopeHeader {
            version: IDTTY_VERSION,
            alg_id: ALG_AES_256_GCM,
            key_epoch: 1,
            nonce_counter: 0,
            update_seq: 1,
            tier: Some(Tier::S),
        };

        let envelope = encrypt(&key, b"secret", &aad, &nonce, header).unwrap();
        assert!(decrypt(&wrong_key, &envelope).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [42u8; 32];
        let vault_id = Uuid::new_v4();
        let object_id = Uuid::new_v4();

        let aad = build_aad(
            vault_id,
            ObjectType::Cipher,
            object_id,
            Some(Tier::Xs),
            ALG_AES_256_GCM,
            1,
            1,
        );
        let wrong_aad = build_aad(
            vault_id,
            ObjectType::Cipher,
            object_id,
            Some(Tier::L),
            ALG_AES_256_GCM,
            1,
            1,
        );
        let nonce = build_nonce(0, object_id);
        let header = EnvelopeHeader {
            version: IDTTY_VERSION,
            alg_id: ALG_AES_256_GCM,
            key_epoch: 1,
            nonce_counter: 0,
            update_seq: 1,
            tier: Some(Tier::Xs),
        };

        let mut envelope = encrypt(&key, b"secret", &aad, &nonce, header).unwrap();
        envelope.aad = wrong_aad; // tamper with AAD
        assert!(decrypt(&key, &envelope).is_err());
    }
}
