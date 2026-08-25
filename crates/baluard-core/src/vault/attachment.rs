//! Attachment encryption/decryption.
//!
//! Attachments are encrypted with AES-256-GCM using the cipher's item key,
//! padded into the standard tier buckets and AAD-bound to their identity
//! (audit C4: previously unpadded + unbound, leaking exact plaintext sizes
//! to the git provider and allowing same-cipher attachment swaps).
//! Stored on disk at `<vault>/entries/<cipher_id>/attachments/<attach_id>.enc`.
//! Metadata is tracked inside the cipher's JSON.
//!
//! Binary format: the standard AEAD envelope (see `vault::envelope`),
//! with header.tier carrying the padding tier.

use crate::error::VaultError;
use crate::types::{EnvelopeHeader, Tier};
use crate::vault::padding;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};
use uuid::Uuid;

use crate::crypto::aead;

/// Attachment metadata stored inside the cipher.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentMeta {
    /// Unique attachment ID.
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// Original file size in bytes.
    pub size: u64,
    /// Encrypted file size in bytes (after AEAD).
    pub encrypted_size: u64,
    /// MIME type (best-effort detection).
    pub mime_type: String,
    /// Creation timestamp (epoch seconds).
    pub created_at: u64,
}

/// Encrypt attachment content for storage (audit C4).
///
/// Pads into the standard tier buckets (size-hiding) and binds the AEAD
/// association data to (vault, cipher, attachment, tier, epoch, seq) so a
/// blob cannot be swapped with another attachment's file. `key_epoch` and
/// `update_seq` come from the owning cipher at upload time.
pub fn encrypt_attachment(
    vault_id: Uuid,
    cipher_id: Uuid,
    attachment_id: Uuid,
    item_key: &[u8; 32],
    plaintext: &[u8],
    key_epoch: u64,
    update_seq: u64,
) -> Result<Vec<u8>, VaultError> {
    let tier = Tier::fit(plaintext.len()).ok_or_else(|| {
        VaultError::InvalidTier(format!(
            "attachment too large for any tier: {} bytes",
            plaintext.len()
        ))
    })?;
    let padded = padding::pad(plaintext, tier)?;

    let aad = aead::build_attachment_aad(
        vault_id,
        cipher_id,
        attachment_id,
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
        nonce_counter: 0,
        update_seq,
        tier: Some(tier),
    };

    let enc_envelope = aead::encrypt(item_key, &padded, &aad, &nonce, header)
        .map_err(|e| VaultError::Crypto(format!("attachment encrypt: {e}")))?;
    crate::vault::envelope::serialize(&enc_envelope)
        .map_err(|e| VaultError::Crypto(format!("envelope serialize: {e}")))
}

/// Decrypt attachment content from storage (audit C4).
///
/// Verifies the AAD identity binding (vault + cipher + attachment + tier +
/// epoch + seq) BEFORE decryption, mirroring `decrypt_cipher`'s R7-1 swap
/// protection. Fails closed on any mismatch.
pub fn decrypt_attachment(
    vault_id: Uuid,
    cipher_id: Uuid,
    attachment_id: Uuid,
    item_key: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, VaultError> {
    use zeroize::Zeroize;

    let enc_envelope = crate::vault::envelope::deserialize(blob)
        .map_err(|e| VaultError::Crypto(format!("attachment envelope: {e}")))?;

    // R7-1 pattern: recompute the expected AAD from caller identity and
    // compare before decrypting. No decryption oracle on mismatch.
    let expected_aad = aead::build_attachment_aad(
        vault_id,
        cipher_id,
        attachment_id,
        enc_envelope.header.tier,
        enc_envelope.header.alg_id,
        enc_envelope.header.key_epoch,
        enc_envelope.header.update_seq,
    );
    if enc_envelope.aad != expected_aad {
        return Err(VaultError::Crypto(
            "attachment identity mismatch: AAD does not match expected vault/cipher/attachment binding".into(),
        ));
    }

    let mut padded = aead::decrypt(item_key, &enc_envelope)
        .map_err(|e| VaultError::Crypto(format!("attachment decrypt: {e}")))?;
    let plaintext = padding::unpad(&padded);
    padded.zeroize(); // plaintext-length prefix + zeros
    plaintext
}

/// Detect MIME type from file extension.
pub fn detect_mime(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".pdf") {
        "application/pdf".into()
    } else if lower.ends_with(".png") {
        "image/png".into()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".into()
    } else if lower.ends_with(".gif") {
        "image/gif".into()
    } else if lower.ends_with(".txt") {
        "text/plain".into()
    } else if lower.ends_with(".csv") {
        "text/csv".into()
    } else if lower.ends_with(".json") {
        "application/json".into()
    } else if lower.ends_with(".xml") {
        "application/xml".into()
    } else if lower.ends_with(".zip") {
        "application/zip".into()
    } else if lower.ends_with(".key") || lower.ends_with(".pem") {
        "application/x-pem-file".into()
    } else if lower.ends_with(".doc") {
        "application/msword".into()
    } else if lower.ends_with(".docx") {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into()
    } else {
        "application/octet-stream".into()
    }
}

/// Maximum attachment file size (audit C4). Kept below the XL tier's
/// padded size so the encrypted envelope (padded content + tag + header)
/// stays under 2 MB on disk and inside the envelope budget.
pub const MAX_ATTACHMENT_SIZE: usize = 1_900_000; // 1.9 MB

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Uuid, Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn round_trip() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key = [42u8; 32];
        let plaintext = b"Hello, attachment world!";

        let encrypted =
            encrypt_attachment(vault_id, cipher_id, attach_id, &key, plaintext, 1, 1).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());
        assert!(encrypted.len() > plaintext.len()); // padding + envelope + tag

        let decrypted =
            decrypt_attachment(vault_id, cipher_id, attach_id, &key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key1 = [42u8; 32];
        let key2 = [99u8; 32];
        let plaintext = b"secret data";

        let encrypted =
            encrypt_attachment(vault_id, cipher_id, attach_id, &key1, plaintext, 1, 1).unwrap();
        assert!(decrypt_attachment(vault_id, cipher_id, attach_id, &key2, &encrypted).is_err());
    }

    /// C4: swapping two same-cipher attachment files on disk must fail both
    /// decrypts (AAD binds vault/cipher/attachment identity).
    #[test]
    fn swap_between_attachments_blocked_by_aad() {
        let (vault_id, cipher_id, _) = ids();
        let (_, _, attach_a) = ids();
        let (_, _, attach_b) = ids();
        let key = [7u8; 32];

        let blob_a =
            encrypt_attachment(vault_id, cipher_id, attach_a, &key, b"contents-of-A", 1, 1)
                .unwrap();
        let blob_b =
            encrypt_attachment(vault_id, cipher_id, attach_b, &key, b"contents-of-B", 1, 1)
                .unwrap();

        // Swap the files on disk: A's blob at B's identity and vice versa.
        assert!(decrypt_attachment(vault_id, cipher_id, attach_b, &key, &blob_a).is_err());
        assert!(decrypt_attachment(vault_id, cipher_id, attach_a, &key, &blob_b).is_err());

        // The originals still decrypt.
        assert_eq!(
            decrypt_attachment(vault_id, cipher_id, attach_a, &key, &blob_a).unwrap(),
            b"contents-of-A"
        );
    }

    /// C4: a blob moved to another cipher or vault fails closed too.
    #[test]
    fn cross_cipher_and_cross_vault_blocked() {
        let (vault_id, cipher_id, attach_id) = ids();
        let (other_vault, other_cipher, _) = ids();
        let key = [7u8; 32];

        let blob =
            encrypt_attachment(vault_id, cipher_id, attach_id, &key, b"payload", 1, 1).unwrap();

        assert!(
            decrypt_attachment(vault_id, other_cipher, attach_id, &key, &blob).is_err(),
            "blob replayed under another cipher must fail"
        );
        assert!(
            decrypt_attachment(other_vault, cipher_id, attach_id, &key, &blob).is_err(),
            "blob replayed under another vault must fail"
        );
    }

    /// C4: encrypted size depends only on the tier, not the plaintext
    /// length (size metadata must not leak to the git provider).
    #[test]
    fn encrypted_size_is_tier_uniform() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key = [7u8; 32];

        let small = encrypt_attachment(vault_id, cipher_id, attach_id, &key, b"x", 1, 1).unwrap();
        let bigger = encrypt_attachment(
            vault_id,
            cipher_id,
            attach_id,
            &key,
            &[0xAB; 4 * 1024],
            1,
            1,
        )
        .unwrap();

        // Both fit the XS tier: identical on-disk size.
        assert_eq!(small.len(), bigger.len());
        assert!(
            small.len() > Tier::Xs.padded_size(),
            "must at least carry the padded payload"
        );
    }

    #[test]
    fn detect_mime_types() {
        assert_eq!(detect_mime("photo.png"), "image/png");
        assert_eq!(detect_mime("doc.PDF"), "application/pdf");
        assert_eq!(detect_mime("data.json"), "application/json");
        assert_eq!(detect_mime("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn large_attachment_round_trip() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key = [7u8; 32];
        let plaintext = vec![0xABu8; 1024 * 100]; // 100KB -> M tier

        let encrypted =
            encrypt_attachment(vault_id, cipher_id, attach_id, &key, &plaintext, 1, 1).unwrap();
        let decrypted =
            decrypt_attachment(vault_id, cipher_id, attach_id, &key, &encrypted).unwrap();
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_attachment() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key = [1u8; 32];
        let plaintext = b"";

        let encrypted =
            encrypt_attachment(vault_id, cipher_id, attach_id, &key, plaintext, 1, 1).unwrap();
        let decrypted =
            decrypt_attachment(vault_id, cipher_id, attach_id, &key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn corrupt_blob_fails() {
        let (vault_id, cipher_id, attach_id) = ids();
        let key = [1u8; 32];
        assert!(decrypt_attachment(vault_id, cipher_id, attach_id, &key, &[0u8; 20]).is_err());
        assert!(decrypt_attachment(vault_id, cipher_id, attach_id, &key, &[0u8; 5]).is_err());
    }
}
