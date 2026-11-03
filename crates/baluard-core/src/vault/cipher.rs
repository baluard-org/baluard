//! Cipher file operations: create, read, update, delete.
//!
//! D6: Filenames = truth for ciphers ({uuid}.enc).
//! D7: Folder assignment inside each cipher file.
//! D8: Tiered uniform padding.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead;
use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::ItemKey;
use crate::types::{
    Cipher, CipherEnvelopeData, CipherId, CipherInput, EnvelopeHeader, ObjectType, Tier,
};
use crate::vault::envelope;
use crate::vault::padding;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};
use zeroize::Zeroizing;

/// Encrypted cipher file data: envelope + metadata for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherFile {
    /// The cipher UUID (= filename without .enc).
    pub id: CipherId,
    /// The serialized AEAD envelope.
    pub envelope_bytes: Vec<u8>,
}

/// Signing keys: derived metadata is daemon-recomputed on save and the
/// certificate wins (D81). The user-typed subject/issuer are only a
/// fallback for keys stored without a parseable certificate.
pub(crate) fn finalize_signing_key_metadata(kind: &mut crate::types::CipherKind) {
    let crate::types::CipherKind::SigningKey(data) = kind else {
        return;
    };
    if data.certificates.is_empty() {
        return;
    }
    // The leaf must itself parse; deriving "subject" from an intermediate
    // because the leaf is unreadable would mislabel the entry. When the
    // first entry fails, the user-typed fields stand (documented fallback).
    let Some(leaf_der) = crate::crypto::cert::pem_certificate_der(&data.certificates[0]) else {
        return;
    };
    let Some(leaf) = crate::crypto::cert::parse_certificate_der(&leaf_der) else {
        return;
    };
    let chain = crate::crypto::cert::parse_certificate_chain(&data.certificates);
    data.expires_at = crate::crypto::cert::earliest_expiry(&chain);
    data.fingerprint = Some(leaf.fingerprint_sha256.clone());
    data.subject = Some(leaf.subject.clone());
    data.issuer = Some(leaf.issuer.clone());
}

/// Encrypt a cipher input into a padded, encrypted envelope.
///
/// Steps:
/// 1. Serialize cipher data to JSON
/// 2. Select tier based on content size
/// 3. Apply tiered padding
/// 4. Encrypt with Item Key using AES-256-GCM + AAD + random nonce
///
/// Each encryption uses a fresh random 96-bit nonce to prevent nonce reuse
/// across concurrent multi-device edits (C1 fix).
pub fn encrypt_cipher(
    vault_id: Uuid,
    cipher_id: CipherId,
    input: &CipherInput,
    item_key: &ItemKey,
    key_epoch: u64,
    update_seq: u64,
) -> Result<CipherFile, BaluardError> {
    // Serialize cipher data
    let cipher_data = CipherEnvelopeData::from_input(input);
    let json: Zeroizing<Vec<u8>> = Zeroizing::new(
        serde_json::to_vec(&cipher_data)
            .map_err(|e| VaultError::Metadata(format!("cipher serialization: {e}")))?,
    );

    // Tier selection
    let tier = Tier::fit(json.len()).ok_or_else(|| {
        VaultError::InvalidTier(format!(
            "content too large for any tier: {} bytes",
            json.len()
        ))
    })?;

    // Pad
    let padded: Zeroizing<Vec<u8>> = Zeroizing::new(padding::pad(&json, tier)?);

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

    // Build random nonce (C1 fix: prevents nonce reuse across devices)
    let nonce = aead::build_random_nonce();

    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
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
) -> Result<Cipher, BaluardError> {
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
        return Err(BaluardError::Vault(VaultError::Corrupt(
            "cipher identity mismatch: AAD does not match expected vault/cipher binding".into(),
        )));
    }

    // Decrypt
    let mut padded = aead::decrypt(item_key.as_bytes(), &enc_envelope)?;

    // Unpad
    let mut json = padding::unpad(&padded)?;

    // Deserialize cipher data (handles old flat format via migrate())
    let raw_data_result = serde_json::from_slice::<CipherEnvelopeData>(&json);

    // H2 fix: zeroize plaintext intermediates even on error paths.
    // padded and json hold full cleartext; zeroize before any early return.
    use zeroize::Zeroize;
    json.zeroize();
    padded.zeroize();

    let raw_data: CipherEnvelopeData =
        raw_data_result.map_err(|e| VaultError::Corrupt(format!("cipher deserialization: {e}")))?;

    let data = raw_data.migrate();

    Ok(Cipher {
        id: cipher_id,
        name: data.name,
        folder_id: data.folder_id,
        kind: data.kind,
        favorite: data.favorite,
        reprompt: data.reprompt,
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
        password_history: data.password_history,
        attachments: data.attachments,
        archived: data.archived,
        tags: data.tags,
    })
}

/// Seal already-serialized cipher JSON without a typed parse. Rotation
/// rewraps entries whose kind a newer client wrote, so the bytes must move
/// to the new item key even when this build cannot model the kind.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_cipher_raw(
    vault_id: Uuid,
    cipher_id: CipherId,
    plaintext: &[u8],
    item_key: &ItemKey,
    key_epoch: u64,
    update_seq: u64,
    tier: Option<Tier>,
) -> Result<CipherFile, BaluardError> {
    // A rewrap preserves the source tier: a newer client may have chosen a
    // larger bucket deliberately, and downsizing changes the padding
    // leakage profile the original writer picked.
    let tier = tier.or_else(|| Tier::fit(plaintext.len())).ok_or_else(|| {
        VaultError::InvalidTier(format!(
            "content too large for any tier: {} bytes",
            plaintext.len()
        ))
    })?;

    let padded: Zeroizing<Vec<u8>> = Zeroizing::new(padding::pad(plaintext, tier)?);

    let aad = aead::build_aad(
        vault_id,
        ObjectType::Cipher,
        cipher_id,
        Some(tier),
        ALG_AES_256_GCM,
        key_epoch,
        update_seq,
    );

    let nonce = aead::build_random_nonce();

    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch,
        update_seq,
        tier: Some(tier),
    };

    let enc_envelope = aead::encrypt(item_key.as_bytes(), &padded, &aad, &nonce, header)?;

    Ok(CipherFile {
        id: cipher_id,
        envelope_bytes: envelope::serialize(&enc_envelope)?,
    })
}

/// Decrypt an envelope back to raw cipher JSON (pre-parse). Used by
/// rotation's opaque rewrap, where the typed kind must not gate the rekey;
/// the AAD identity binding still verifies before decryption.
pub fn decrypt_cipher_raw(
    vault_id: Uuid,
    cipher_id: CipherId,
    file: &CipherFile,
    item_key: &ItemKey,
) -> Result<Zeroizing<Vec<u8>>, BaluardError> {
    let enc_envelope = envelope::deserialize(&file.envelope_bytes)?;

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
        return Err(BaluardError::Vault(VaultError::Corrupt(
            "cipher identity mismatch: AAD does not match expected vault/cipher binding".into(),
        )));
    }

    // H2 parity with the typed twin: the padded plaintext holds full
    // cleartext, so it zeroizes on drop even when unpad fails.
    let padded = Zeroizing::new(aead::decrypt(item_key.as_bytes(), &enc_envelope)?);
    let json = padding::unpad(&padded)?;

    Ok(Zeroizing::new(json))
}

/// Read the schema version out of a decrypted cipher JSON without a typed
/// parse. Absent means 1 (the first schema had no field). A present but
/// non-integer value is corruption; an integer beyond u32 is a newer
/// schema by construction.
pub fn stored_item_schema(json: &[u8]) -> Result<u32, BaluardError> {
    let v: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| VaultError::Corrupt(format!("cipher deserialization: {e}")))?;
    match v.get("schema") {
        None => Ok(1),
        Some(s) => match s.as_u64() {
            Some(n) => u32::try_from(n)
                .map_err(|_| BaluardError::Vault(VaultError::ItemSchemaTooNew(u32::MAX))),
            None => Err(VaultError::Corrupt("cipher schema field is not an integer".into()).into()),
        },
    }
}

/// Refuse a typed re-encrypt of an item whose stored schema this build
/// cannot fully model: decrypt-edit-encrypt would silently strip the
/// newer build's fields. Callers that hold the raw bytes instead (rotation
/// rewrap) may keep moving them.
pub fn ensure_schema_writable_raw(
    vault_id: Uuid,
    cipher_id: CipherId,
    file: &CipherFile,
    item_key: &ItemKey,
) -> Result<(), BaluardError> {
    let json = decrypt_cipher_raw(vault_id, cipher_id, file, item_key)?;
    let schema = stored_item_schema(&json)?;
    if schema > crate::types::ITEM_SCHEMA_VERSION {
        return Err(BaluardError::Vault(VaultError::ItemSchemaTooNew(schema)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CipherInput;

    #[test]
    fn raw_seal_roundtrip_preserves_bytes() {
        let vault_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let item_key = ItemKey::generate();
        let json = br#"{"kind":{"type":"signingKey"}}"#.to_vec();

        let file = encrypt_cipher_raw(vault_id, cipher_id, &json, &item_key, 3, 7, None).unwrap();
        let back = decrypt_cipher_raw(vault_id, cipher_id, &file, &item_key).unwrap();
        assert_eq!(&*back, &json);
        // An explicit tier survives the round trip: a rewrap must not
        // downscale the padding bucket the original writer picked.
        let file = encrypt_cipher_raw(vault_id, cipher_id, &json, &item_key, 3, 7, Some(Tier::Xl))
            .unwrap();
        let envelope = envelope::deserialize(&file.envelope_bytes).unwrap();
        assert_eq!(envelope.header.tier, Some(Tier::Xl));
        assert!(decrypt_cipher_raw(vault_id, cipher_id, &file, &item_key).is_ok());

        // The AAD binds vault and cipher identity: another id must refuse.
        assert!(decrypt_cipher_raw(vault_id, Uuid::new_v4(), &file, &item_key).is_err());
    }

    #[test]
    fn stored_item_schema_strictness() {
        assert_eq!(stored_item_schema(br#"{"name":"n"}"#).unwrap(), 1);
        assert_eq!(stored_item_schema(br#"{"schema":1}"#).unwrap(), 1);
        assert_eq!(stored_item_schema(br#"{"schema":3}"#).unwrap(), 3);
        // A string or float schema is corruption, not a pass-through.
        assert!(stored_item_schema(br#"{"schema":"2"}"#).is_err());
        assert!(stored_item_schema(br#"{"schema":2.5}"#).is_err());
        // Integer beyond u32 cannot wrap down to a small schema.
        let err = stored_item_schema(br#"{"schema":4294967297}"#).unwrap_err();
        assert!(matches!(
            err,
            BaluardError::Vault(VaultError::ItemSchemaTooNew(u32::MAX))
        ));
    }

    #[test]
    fn encrypt_stamps_current_schema() {
        let vault_id = Uuid::new_v4();
        let cipher_id = CipherId::new_v4();
        let input = CipherInput {
            name: "n".into(),
            kind: crate::types::CipherKind::Login(Default::default()),
            folder_id: None,
            collection_id: None,
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
            archived: false,
            tags: vec![],
        };
        let item_key = ItemKey::generate();
        let file = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1).unwrap();
        let json = decrypt_cipher_raw(vault_id, cipher_id, &file, &item_key).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            v["schema"].as_u64(),
            Some(crate::types::ITEM_SCHEMA_VERSION as u64),
            "every write must stamp the item schema version"
        );
    }

    #[test]
    fn decrypt_displays_newer_schema_item() {
        let vault_id = Uuid::new_v4();
        let cipher_id = CipherId::new_v4();
        let item_key = ItemKey::generate();
        let json = format!(
            r#"{{"name":"n","created_at":1,"updated_at":1,"schema":{}}}"#,
            crate::types::ITEM_SCHEMA_VERSION + 1
        );
        let file = encrypt_cipher_raw(vault_id, cipher_id, json.as_bytes(), &item_key, 1, 1, None)
            .unwrap();
        // Read-only display keeps working for known fields.
        let cipher = decrypt_cipher(vault_id, cipher_id, &file, &item_key).unwrap();
        assert_eq!(cipher.name, "n");
    }

    #[test]
    fn encrypt_decrypt_cipher_roundtrip() {
        let vault_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let item_key = ItemKey::generate();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@example.com".into()),
                password: Some("s3cret!".into()),
                uris: vec![crate::types::LoginUri::new("https://github.com".into())],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
            archived: false,
            tags: vec![],
        };

        let file = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1).unwrap();

        // Verify envelope is properly formed
        assert_eq!(file.id, cipher_id);

        let cipher = decrypt_cipher(vault_id, cipher_id, &file, &item_key).unwrap();
        assert_eq!(cipher.name, "GitHub");
        match &cipher.kind {
            crate::types::CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris.len(), 1);
                assert_eq!(data.uris[0].uri, "https://github.com");
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
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("secret".into()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                fido2_credentials: None,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
            archived: false,
            tags: vec![],
        };

        let file = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1).unwrap();
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
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("password-for-A".into()),
                uris: vec![],
                totp_uri: None,
                fido2_credentials: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
            archived: false,
            tags: vec![],
        };

        // Encrypt for cipher A
        let file_a = encrypt_cipher(vault_id, cipher_id_a, &input, &item_key, 1, 1).unwrap();

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

    /// C1 regression: two encryptions with identical inputs MUST produce
    /// different nonces (prevents AES-GCM nonce reuse across devices).
    #[test]
    fn random_nonce_prevents_reuse() {
        let vault_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let item_key = ItemKey::generate();

        let input = CipherInput {
            name: "test".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("secret".into()),
                uris: vec![],
                fido2_credentials: None,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
            archived: false,
            tags: vec![],
        };

        // Same vault, cipher, key, epoch, update_seq — what multi-device edit would produce
        let file1 = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1).unwrap();
        let file2 = encrypt_cipher(vault_id, cipher_id, &input, &item_key, 1, 1).unwrap();

        // Nonces must differ (this is the exact property C1 turns on)
        let env1 = envelope::deserialize(&file1.envelope_bytes).unwrap();
        let env2 = envelope::deserialize(&file2.envelope_bytes).unwrap();
        assert_ne!(
            env1.nonce, env2.nonce,
            "C1 regression: two encryptions produced the same nonce!"
        );

        // Both must still decrypt correctly
        let dec1 = decrypt_cipher(vault_id, cipher_id, &file1, &item_key).unwrap();
        let dec2 = decrypt_cipher(vault_id, cipher_id, &file2, &item_key).unwrap();
        assert_eq!(dec1.name, "test");
        assert_eq!(dec2.name, "test");
    }
}
