//! Ed25519 signature operations.
//!
//! D22: All commits signed with device's Ed25519 signing key.
//! D14: Quorum signatures for device enrollment/revocation.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::CryptoError;

/// Generate a new Ed25519 signing keypair.
pub fn generate_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with Ed25519.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
    Ok(signing_key.sign(message))
}

/// Verify an Ed25519 signature.
pub fn verify(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

/// Serialize a verifying key to bytes (32 bytes).
pub fn verifying_key_bytes(key: &VerifyingKey) -> [u8; 32] {
    key.to_bytes()
}

/// Deserialize a verifying key from bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, CryptoError> {
    VerifyingKey::from_bytes(bytes)
        .map_err(|e| CryptoError::SignFailed(format!("invalid verifying key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (signing, verifying) = generate_ed25519_keypair();
        let message = b"vault update";

        let sig = sign(&signing, message).unwrap();
        assert!(verify(&verifying, message, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let (signing, verifying) = generate_ed25519_keypair();
        let sig = sign(&signing, b"message-1").unwrap();
        assert!(verify(&verifying, b"message-2", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (signing, _) = generate_ed25519_keypair();
        let (_, other_verifying) = generate_ed25519_keypair();
        let sig = sign(&signing, b"message").unwrap();
        assert!(verify(&other_verifying, b"message", &sig).is_err());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let (_, verifying) = generate_ed25519_keypair();
        let bytes = verifying_key_bytes(&verifying);
        let restored = verifying_key_from_bytes(&bytes).unwrap();
        assert_eq!(
            verifying_key_bytes(&verifying),
            verifying_key_bytes(&restored)
        );
    }
}
