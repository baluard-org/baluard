//! Encrypted lookup index (index.enc) for high-performance O(1) searches.
//!
//! D2: Padded index.enc lookup table.
//! D4: Auto-healing on sync conflict.

use crate::crypto::aead;
use crate::error::{IdttyError, VaultError};
use crate::types::{CipherMeta, EnvelopeHeader, ObjectType, Tier};
use crate::vault::envelope;
use crate::{ALG_AES_256_GCM, IDTTY_VERSION};
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
) -> Result<Vec<u8>, IdttyError> {
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

    let nonce = aead::build_nonce(0, Uuid::nil());

    let header = EnvelopeHeader {
        version: IDTTY_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
        nonce_counter: 0,
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
) -> Result<Vec<CipherMeta>, IdttyError> {
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
