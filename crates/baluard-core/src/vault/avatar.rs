//! Avatar encryption (M1 fix).
//!
//! Avatars were previously stored as plaintext files at `meta/avatar.{ext}`
//! and synced to git in cleartext (PII leak). They are now AES-256-GCM
//! encrypted with a key derived from the Space Group Key (domain-separated
//! from item keys). The encrypted blob is stored at `meta/avatar.enc`
//! regardless of source extension.
//!
//! Envelope format: `[12-byte nonce | ciphertext | 16-byte tag]` (same as
//! attachments). The plaintext extension is stored alongside in the encrypted
//! `profile.enc`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::VaultError;

/// Encrypted avatar blob size limit (350 KB plaintext, ~352 KB encrypted).
pub const MAX_AVATAR_PLAINTEXT: usize = 350 * 1024;

/// Encrypt avatar content for storage.
/// Returns: `[12-byte nonce | ciphertext+tag]`.
pub fn encrypt_avatar(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    if plaintext.len() > MAX_AVATAR_PLAINTEXT {
        return Err(VaultError::Crypto(format!(
            "avatar too large: {} bytes (max {})",
            plaintext.len(),
            MAX_AVATAR_PLAINTEXT
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("avatar key init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(format!("avatar encrypt: {e}")))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    // Zeroize the local nonce after copying into the output buffer.
    nonce_bytes.zeroize();
    Ok(out)
}

/// Decrypt avatar content from storage.
/// Input: `[12-byte nonce | ciphertext+tag]`.
pub fn decrypt_avatar(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    if blob.len() < 12 + 16 {
        return Err(VaultError::Crypto("avatar blob too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("avatar key init: {e}")))?;

    let nonce = Nonce::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Crypto("avatar decrypt failed (wrong key or corrupt)".into()))
}

use rand::rngs::OsRng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"fake-png-bytes-here";
        let blob = encrypt_avatar(&key, plaintext).unwrap();
        let decrypted = decrypt_avatar(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let blob = encrypt_avatar(&key1, b"secret").unwrap();
        assert!(decrypt_avatar(&key2, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = [3u8; 32];
        assert!(decrypt_avatar(&key, &[0u8; 10]).is_err());
    }

    #[test]
    fn oversize_rejected() {
        let key = [4u8; 32];
        let big = vec![0u8; MAX_AVATAR_PLAINTEXT + 1];
        assert!(encrypt_avatar(&key, &big).is_err());
    }
}
