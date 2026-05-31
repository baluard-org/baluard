//! Attachment encryption/decryption.
//!
//! Attachments are encrypted with AES-256-GCM using the cipher's item key.
//! Stored on disk at `<vault>/<cipher_id>/attachments/<attach_id>.enc`.
//! Metadata is tracked inside the cipher's JSON.
//!
//! Binary format: [12-byte nonce | ciphertext | 16-byte tag]

use crate::error::VaultError;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

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

/// Encrypt attachment content for storage.
/// Returns: [12-byte nonce | ciphertext+tag]
pub fn encrypt_attachment(item_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(item_key)
        .map_err(|e| VaultError::Crypto(format!("key init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(format!("encrypt: {e}")))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt attachment content from storage.
/// Input: [12-byte nonce | ciphertext+tag]
pub fn decrypt_attachment(item_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    if blob.len() < 12 + 16 {
        return Err(VaultError::Crypto("attachment blob too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(item_key)
        .map_err(|e| VaultError::Crypto(format!("key init: {e}")))?;

    let nonce = Nonce::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Crypto("attachment decrypt failed (wrong key or corrupt)".into()))
}

/// Detect MIME type from file extension.
pub fn detect_mime(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".pdf") { "application/pdf".into() }
    else if lower.ends_with(".png") { "image/png".into() }
    else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") { "image/jpeg".into() }
    else if lower.ends_with(".gif") { "image/gif".into() }
    else if lower.ends_with(".txt") { "text/plain".into() }
    else if lower.ends_with(".csv") { "text/csv".into() }
    else if lower.ends_with(".json") { "application/json".into() }
    else if lower.ends_with(".xml") { "application/xml".into() }
    else if lower.ends_with(".zip") { "application/zip".into() }
    else if lower.ends_with(".key") || lower.ends_with(".pem") { "application/x-pem-file".into() }
    else if lower.ends_with(".doc") { "application/msword".into() }
    else if lower.ends_with(".docx") { "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into() }
    else { "application/octet-stream".into() }
}

/// Maximum attachment file size: 2 MB.
pub const MAX_ATTACHMENT_SIZE: usize = 2 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [42u8; 32];
        let plaintext = b"Hello, attachment world!";

        let encrypted = encrypt_attachment(&key, plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());
        assert!(encrypted.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = decrypt_attachment(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [99u8; 32];
        let plaintext = b"secret data";

        let encrypted = encrypt_attachment(&key1, plaintext).unwrap();
        assert!(decrypt_attachment(&key2, &encrypted).is_err());
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
        let key = [7u8; 32];
        let plaintext = vec![0xABu8; 1024 * 100]; // 100KB

        let encrypted = encrypt_attachment(&key, &plaintext).unwrap();
        let decrypted = decrypt_attachment(&key, &encrypted).unwrap();
        assert_eq!(decrypted.len(), plaintext.len());
    }

    #[test]
    fn empty_attachment() {
        let key = [1u8; 32];
        let plaintext = b"";

        let encrypted = encrypt_attachment(&key, plaintext).unwrap();
        let decrypted = decrypt_attachment(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn corrupt_blob_fails() {
        let key = [1u8; 32];
        assert!(decrypt_attachment(&key, &[0u8; 20]).is_err());
        assert!(decrypt_attachment(&key, &[0u8; 5]).is_err());
    }
}
