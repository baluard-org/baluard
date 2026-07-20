//! Encrypted lookup index (index.enc) for high-performance O(1) searches.
//!
//! D2: Padded index.enc lookup table.
//! D4: Auto-healing on sync conflict.

use crate::crypto::aead;
use crate::error::{BaluardError, VaultError};
use crate::types::{CipherMeta, EnvelopeHeader, ObjectType, Tier};
use crate::vault::envelope;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexTable {
    pub ciphers: Vec<CipherMeta>,
}

/// Encrypt the index lookup table into a padded envelope.
pub fn encrypt_index(
    vault_id: Uuid,
    ciphers: &[CipherMeta],
    index_key: &[u8; 32],
    key_epoch: u64,
) -> Result<Vec<u8>, BaluardError> {
    let table = IndexTable {
        ciphers: ciphers.to_vec(),
    };
    let json = serde_json::to_vec(&table)
        .map_err(|e| VaultError::Metadata(format!("index serialization: {e}")))?;

    let tier = Tier::fit(json.len())
        .ok_or_else(|| VaultError::InvalidTier(format!("index too large: {} bytes", json.len())))?;

    let padded = super::padding::pad(&json, tier)?;

    let aad = aead::build_aad(
        vault_id,
        ObjectType::Meta,
        Uuid::nil(),
        Some(tier),
        ALG_AES_256_GCM,
        key_epoch,
        1,
    );

    let nonce = aead::build_random_nonce();
    // Header stores only a u64 `nonce_counter`; derive it from the first
    // 8 bytes of the 96-bit random nonce so the field stays populated
    // (metadata-only — decrypt reads the full 12-byte nonce from the
    // envelope, not this field). A-1 fix: previously build_nonce(counter,
    // Uuid::nil()) zeroed the shard tail, leaving only 64 random bits under
    // a fixed key on the highest-write-frequency object.
    let nonce_counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());

    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
        nonce_counter,
        update_seq: 1,
        tier: Some(tier),
    };

    let enc_envelope = aead::encrypt(index_key, &padded, &aad, &nonce, header)?;
    let envelope_bytes = envelope::serialize(&enc_envelope)?;

    Ok(envelope_bytes)
}

/// Decrypt the index lookup table from its envelope.
pub fn decrypt_index(
    vault_id: Uuid,
    envelope_bytes: &[u8],
    index_key: &[u8; 32],
) -> Result<Vec<CipherMeta>, BaluardError> {
    let enc_envelope = envelope::deserialize(envelope_bytes)?;

    let expected_aad = aead::build_aad(
        vault_id,
        ObjectType::Meta,
        Uuid::nil(),
        enc_envelope.header.tier,
        enc_envelope.header.alg_id,
        enc_envelope.header.key_epoch,
        enc_envelope.header.update_seq,
    );

    if enc_envelope.aad != expected_aad {
        return Err(VaultError::Corrupt(
            "index identity mismatch (AAD verification failed)".into(),
        )
        .into());
    }

    let decrypted = aead::decrypt(index_key, &enc_envelope)?;

    let unpadded = super::padding::unpad(&decrypted)?;
    let table: IndexTable = serde_json::from_slice(&unpadded)
        .map_err(|e| VaultError::Corrupt(format!("index deserialization: {e}")))?;

    Ok(table.ciphers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CipherType;

    fn sample_metas() -> Vec<CipherMeta> {
        (0..5)
            .map(|i| CipherMeta {
                id: Uuid::new_v4(),
                name: format!("cipher-{i}"),
                folder_id: None,
                cipher_type: CipherType::Login,
                favorite: i % 2 == 0,
                reprompt: false,
                username: Some(format!("user{i}@example.com")),
                tier: Tier::S,
                key_epoch: 1,
                update_seq: 1,
                updated_at: 1_700_000_000,
                archived: false,
                tags: vec![],
            })
            .collect()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let metas = sample_metas();
        let encrypted = encrypt_index(vault_id, &metas, &index_key, 1).expect("encrypt");
        assert!(!encrypted.is_empty());
        let decrypted = decrypt_index(vault_id, &encrypted, &index_key).expect("decrypt");
        assert_eq!(decrypted.len(), metas.len());
        for (got, want) in decrypted.iter().zip(metas.iter()) {
            assert_eq!(got.id, want.id);
            assert_eq!(got.name, want.name);
            assert_eq!(got.favorite, want.favorite);
        }
    }

    #[test]
    fn decrypt_with_wrong_vault_id_fails() {
        let vault_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let encrypted = encrypt_index(vault_id, &sample_metas(), &index_key, 1).unwrap();
        // AAD mismatch must be detected — wrong vault_id means the AAD
        // builder produces different bytes and decrypt rejects.
        let err = decrypt_index(other_id, &encrypted, &index_key).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("aad")
                || err.to_string().to_lowercase().contains("identity"),
            "expected AAD/identity error: {err}"
        );
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let other_key = [0x99u8; 32];
        let encrypted = encrypt_index(vault_id, &sample_metas(), &index_key, 1).unwrap();
        // Wrong key: AAD matches but AEAD tag check fails.
        let err = decrypt_index(vault_id, &encrypted, &other_key).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("auth")
                || err.to_string().to_lowercase().contains("decrypt")
        );
    }

    #[test]
    fn empty_cipher_list_round_trips() {
        let vault_id = Uuid::new_v4();
        let index_key = [0x42u8; 32];
        let encrypted = encrypt_index(vault_id, &[], &index_key, 1).unwrap();
        let decrypted = decrypt_index(vault_id, &encrypted, &index_key).unwrap();
        assert!(decrypted.is_empty());
    }
}
