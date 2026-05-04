//! HPKE-based key wrapping (X25519 + HPKE, RFC 9180).
//!
//! D3: Root Key wrapped per-device via HPKE with X25519.
//! D17: Org Key wrapped per-member via HPKE.
//! D18: Emergency access keys wrapped via HPKE.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

/// Generate a new X25519 keypair for device wrapping.
pub fn generate_x25519_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Wrap (encrypt) a key using HPKE with the recipient's X25519 public key.
///
/// Simplified HPKE seal: X25519 ECIES with authenticated encryption.
/// For production, use a full HPKE library (RFC 9180).
///
/// Returns: (ephemeral_public_key, encrypted_key, auth_tag)
pub fn wrap_key(
    plaintext_key: &[u8],
    recipient_pub: &PublicKey,
) -> Result<(Vec<u8>, Vec<u8>, [u8; 16]), CryptoError> {
    // Generate ephemeral X25519 keypair
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);

    // DH shared secret
    let shared = eph_secret.diffie_hellman(recipient_pub);

    // Derive wrapping key from shared secret using HKDF
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(eph_public.as_bytes()),
        shared.as_bytes(),
    );

    let mut wrap_key = [0u8; 32];
    hkdf.expand(b"idtty-hpke-wrap-v1", &mut wrap_key)
        .map_err(|e| CryptoError::HpkeFailed(format!("HKDF expand: {e}")))?;

    // AES-256-GCM encrypt the plaintext key
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher = Aes256Gcm::new_from_slice(&wrap_key)
        .map_err(|e| CryptoError::HpkeFailed(e.to_string()))?;

    // Use first 12 bytes of shared secret as nonce (safe: unique per ephemeral key)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&shared.as_bytes()[..12]);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext_key,
                aad: b"idtty-keywrap",
            },
        )
        .map_err(|e| CryptoError::EncryptFailed(e.to_string()))?;

    // Split ciphertext and tag
    let ct_len = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ct_len..]);

    Ok((eph_public.as_bytes().to_vec(), ciphertext[..ct_len].to_vec(), tag))
}

/// Unwrap (decrypt) a key using HPKE with the recipient's X25519 private key.
pub fn unwrap_key(
    ephemeral_pub_bytes: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    recipient_priv: &StaticSecret,
) -> Result<Vec<u8>, CryptoError> {
    if ephemeral_pub_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: ephemeral_pub_bytes.len(),
        });
    }

    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(ephemeral_pub_bytes);
    let eph_pub = PublicKey::from(eph_pub_bytes);

    // DH shared secret
    let shared = recipient_priv.diffie_hellman(&eph_pub);

    // Derive wrapping key
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(eph_pub_bytes.as_slice()),
        shared.as_bytes(),
    );

    let mut wrap_key = [0u8; 32];
    hkdf.expand(b"idtty-hpke-wrap-v1", &mut wrap_key)
        .map_err(|e| CryptoError::HpkeFailed(format!("HKDF expand: {e}")))?;

    // Reconstruct ciphertext + tag
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    // AES-256-GCM decrypt
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher = Aes256Gcm::new_from_slice(&wrap_key)
        .map_err(|e| CryptoError::HpkeFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&shared.as_bytes()[..12]);

    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: &ct_with_tag,
                aad: b"idtty-keywrap",
            },
        )
        .map_err(|_| CryptoError::UnwrapFailed("HPKE unwrap failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (priv_key, pub_key) = generate_x25519_keypair();
        let secret_data = b"root-key-32-bytes-of-randomness!!"; // 32 bytes

        let (eph_pub, ct, tag) = wrap_key(secret_data, &pub_key).unwrap();
        let unwrapped = unwrap_key(&eph_pub, &ct, &tag, &priv_key).unwrap();

        assert_eq!(unwrapped, secret_data);
    }

    #[test]
    fn wrong_private_key_fails() {
        let (_, pub_key) = generate_x25519_keypair();
        let (wrong_priv, _) = generate_x25519_keypair();

        let (eph_pub, ct, tag) = wrap_key(b"secret-key-material", &pub_key).unwrap();
        assert!(unwrap_key(&eph_pub, &ct, &tag, &wrong_priv).is_err());
    }
}
