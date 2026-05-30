//! Cipher file operations: create, read, update, delete.
//!
//! D6: Filenames = truth for ciphers ({uuid}.enc).
//! D7: Folder assignment inside each cipher file.
//! D8: Tiered uniform padding.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead;
use crate::error::{IdttyError, VaultError};
use crate::keys::hierarchy::ItemKey;
use crate::types::{Cipher, CipherEnvelopeData, CipherId, CipherInput, EnvelopeHeader, ObjectType, Tier};
use crate::vault::envelope;
use crate::vault::padding;
use crate::{ALG_AES_256_GCM, IDTTY_VERSION};

/// Encrypted cipher file data: envelope + metadata for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherFile {
    /// The cipher UUID (= filename without .enc).
    pub id: CipherId,
    /// The serialized AEAD envelope.
    pub envelope_bytes: Vec<u8>,
}

/// Encrypt a cipher input into a padded, encrypted envelope.
///
/// Steps:
/// 1. Serialize cipher data to JSON
/// 2. Select tier based on content size
/// 3. Apply tiered padding
/// 4. Encrypt with Item Key using AES-256-GCM + AAD
pub fn encrypt_cipher(
    vault_id: Uuid,
    cipher_id: CipherId,
    input: &CipherInput,
    item_key: &ItemKey,
    key_epoch: u64,
    update_seq: u64,
    nonce_counter: u64,
) -> Result<CipherFile, IdttyError> {
    // Serialize cipher data
    let cipher_data = CipherData::from_input(input);
    let json = serde_json::to_vec(&cipher_data)
        .map_err(|e| VaultError::Metadata(format!("cipher serialization: {e}")))?;

    // Tier selection
    let tier = Tier::fit(json.len()).ok_or_else(|| {
        VaultError::InvalidTier(format!(
            "content too large for any tier: {} bytes",
            json.len()
        ))
    })?;

    // Pad
    let padded = padding::pad(&json, tier)?;

    // Build AAD
    let aad = aead::build_aad(
        vault_id,
        ObjectType::Cipher,
        cipher_id,
        Some(tier),
        ALG_AES_256_GCM,
        key_epoch,
        update_seq,
    );

    // Build nonce
    let nonce = aead::build_nonce(nonce_counter, cipher_id);

    // Build header
    let header = EnvelopeHeader {
        version: IDTTY_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
        nonce_counter,
        update_seq,
        tier: Some(tier),
    };

    // Encrypt
    let enc_envelope = aead::encrypt(item_key.as_bytes(), &padded, &aad, &nonce, header)?;

    // Serialize envelope to binary
    let envelope_bytes = envelope::serialize(&enc_envelope)?;

    Ok(CipherFile {
        id: cipher_id,
        envelope_bytes,
    })
}

/// Decrypt a cipher file envelope back into a Cipher struct.
///
/// Verifies that the AAD bound into the envelope matches the caller's expected
/// identity (vault_id + cipher_id + tier + epoch + seq) BEFORE decryption.
/// This blocks swap/rename attacks (CVE-2020-28086 class).
pub fn decrypt_cipher(
    vault_id: Uuid,
    cipher_id: CipherId,
    file: &CipherFile,
    item_key: &ItemKey,
) -> Result<Cipher, IdttyError> {
    // Deserialize envelope
    let enc_envelope = envelope::deserialize(&file.envelope_bytes)?;

    // R7-1: Verify AAD identity binding before decryption.
    // Recompute expected AAD from caller params and compare to stored AAD.
    // Fail fast: no decryption oracle on mismatch.
    let expected_aad = aead::build_aad(
        vault_id,
        ObjectType::Cipher,
        cipher_id,
        enc_envelope.header.tier,
        enc_envelope.header.alg_id,
        enc_envelope.header.key_epoch,
        enc_envelope.header.update_seq,
    );
    if enc_envelope.aad != expected_aad {
        return Err(IdttyError::Vault(VaultError::Corrupt(
            "cipher identity mismatch: AAD does not match expected vault/cipher binding".into(),
        )));
    }

    // Decrypt
    let padded = aead::decrypt(item_key.as_bytes(), &enc_envelope)?;

    // Unpad
    let json = padding::unpad(&padded)?;

    // Deserialize cipher data (handles old flat format via migrate())
    let raw_data: CipherEnvelopeData = serde_json::from_slice(&json)
        .map_err(|e| VaultError::Corrupt(format!("cipher deserialization: {e}")))?;
    let data: CipherData = raw_data.into();

    Ok(Cipher {
        id: cipher_id,
        name: data.name,
        folder_id: data.folder_id,
        kind: data.kind,
        notes: data.notes,
        custom_fields: data.custom_fields,
        key_epoch: enc_envelope.header.key_epoch,
        update_seq: enc_envelope.header.update_seq,
        tier: enc_envelope
            .header
            .tier
            .ok_or_else(|| VaultError::Corrupt("cipher envelope missing tier".into()))?,
        created_at: data.created_at,
        updated_at: data.updated_at,
    })
}

/// Internal cipher data for JSON serialization (within the encrypted envelope).
///
/// Uses `CipherEnvelopeData` which handles backward-compatible deserialization
/// and migration from old flat-format ciphers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CipherData {
    pub name: String,
    pub folder_id: Option<Uuid>,
    pub kind: crate::types::CipherKind,
    pub notes: Option<String>,
    /// Write-only: populated on encrypt for backward compat. Read path uses kind.Login.totp_uri.
    #[serde(default)]
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<crate::types::CustomField>,
    // Write-only legacy fields: populated on encrypt for backward compat.
    // Read path uses kind.Login.username/password/uris instead.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl CipherData {
    fn from_input(input: &CipherInput) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Extract login-specific flat fields for backward compat serialization
        let (username, password, uris, totp_uri) = match &input.kind {
            crate::types::CipherKind::Login(data) => (
                data.username.clone(),
                data.password.clone(),
                data.uris.clone(),
                data.totp_uri.clone(),
            ),
            _ => (None, None, Vec::new(), None),
        };

        Self {
            name: input.name.clone(),
            folder_id: input.folder_id,
            kind: input.kind.clone(),
            notes: input.notes.clone(),
            totp_uri: totp_uri.clone(),
            custom_fields: input.custom_fields.clone(),
            username,
            password,
            uris,
            created_at: now,
            updated_at: now,
        }
    }
}

impl From<CipherEnvelopeData> for CipherData {
    fn from(env: CipherEnvelopeData) -> Self {
        let migrated = env.migrate();
        Self {
            name: migrated.name,
            folder_id: migrated.folder_id,
            kind: migrated.kind,
            notes: migrated.notes,
            totp_uri: migrated.totp_uri,
            custom_fields: migrated.custom_fields,
            username: migrated.username,
            password: migrated.password,
            uris: migrated.uris,
            created_at: migrated.created_at,
            updated_at: migrated.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CipherInput;

    #[test]
    fn encrypt_decrypt_cipher_roundtrip() {
        let vault_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let item_key = ItemKey::generate();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@example.com".into()),
                password: Some("s3cret!".into()),
                uris: vec!["https://github.com".into()],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            notes: None,
            custom_fields: vec![],
        };

        let file = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1, 0).unwrap();

        // Verify envelope is properly formed
        assert_eq!(file.id, cipher_id);

        let cipher = decrypt_cipher(vault_id, cipher_id, &file, &item_key).unwrap();
        assert_eq!(cipher.name, "GitHub");
        match &cipher.kind {
            crate::types::CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris, vec!["https://github.com"]);
            }
            _ => panic!("expected Login kind"),
        }
        assert_eq!(cipher.key_epoch, 1);
        assert_eq!(cipher.update_seq, 1);
    }

    #[test]
    fn wrong_item_key_fails() {
        let vault_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let item_key = ItemKey::generate();
        let wrong_key = ItemKey::generate();

        let input = CipherInput {
            name: "test".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("secret".into()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            notes: None,
            custom_fields: vec![],
        };

        let file = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1, 0).unwrap();
        assert!(decrypt_cipher(vault_id, cipher_id, &file, &wrong_key).is_err());
    }

    /// R7-1: Verify swap/renamed entry attack is blocked.
    /// Encrypt for cipher_id A, then try to decrypt pretending it's cipher_id B.
    /// Must fail with identity mismatch, not return wrong plaintext.
    #[test]
    fn swap_attack_blocked_by_aad_verification() {
        let vault_id = Uuid::new_v4();
        let cipher_id_a = Uuid::new_v4();
        let cipher_id_b = Uuid::new_v4();
        let item_key = ItemKey::generate();

        let input = CipherInput {
            name: "secret-entry".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("password-for-A".into()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            notes: None,
            custom_fields: vec![],
        };

        // Encrypt for cipher A
        let file_a = encrypt_cipher(vault_id, cipher_id_a, &input, &item_key, 1, 1, 0).unwrap();

        // Build a fake CipherFile that looks like B but contains A's envelope
        let swapped_file = CipherFile {
            id: cipher_id_b,
            envelope_bytes: file_a.envelope_bytes.clone(),
        };

        // Try to decrypt as B: must fail with identity mismatch
        let err = decrypt_cipher(vault_id, cipher_id_b, &swapped_file, &item_key);
        assert!(err.is_err());
        let err_str = format!("{err:?}");
        assert!(
            err_str.contains("identity mismatch"),
            "expected identity mismatch error, got: {err_str}"
        );
    }
}
