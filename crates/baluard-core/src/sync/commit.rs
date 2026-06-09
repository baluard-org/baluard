//! Signed commit construction and verification.
//!
//! D9: Static "vault update" commit messages.
//! D22: All commits signed with device Ed25519 signing key.

use crate::crypto::signature;
use crate::error::SyncError;

/// Static commit message per D9.
pub const COMMIT_MESSAGE: &str = "vault update";

/// Create a signed commit payload for verification.
///
/// The commit signature covers: tree hash + parent hash + message + timestamp.
/// This is a simplified version for the in-memory model.
/// The actual git commit signing happens via git2 callbacks.
pub fn create_commit_signature_payload(
    tree_hash: &[u8],
    parent_hash: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + 8 + 16);
    payload.extend_from_slice(b"baluard-commit-v1");
    payload.extend_from_slice(tree_hash);
    payload.extend_from_slice(parent_hash);
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload
}

/// Verify that a commit signature is valid for a given device's verifying key.
pub fn verify_commit_signature(
    verifying_key_bytes: &[u8; 32],
    payload: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SyncError> {
    let verifying_key = signature::verifying_key_from_bytes(verifying_key_bytes)
        .map_err(|_e| SyncError::InvalidCommitSignature)?;

    let sig = ed25519_dalek::Signature::from_slice(signature_bytes)
        .map_err(|_| SyncError::InvalidCommitSignature)?;

    signature::verify(&verifying_key, payload, &sig).map_err(|_| SyncError::InvalidCommitSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::generate_ed25519_keypair;

    #[test]
    fn sign_and_verify_commit() {
        let (signing, verifying) = generate_ed25519_keypair();
        let payload = create_commit_signature_payload(&[1u8; 20], &[2u8; 20], 12345);
        let sig = signature::sign(&signing, &payload).unwrap();

        let sig_bytes = sig.to_bytes();
        verify_commit_signature(&verifying.to_bytes(), &payload, &sig_bytes).unwrap();
    }

    #[test]
    fn tampered_payload_fails() {
        let (signing, verifying) = generate_ed25519_keypair();
        let payload = create_commit_signature_payload(&[1u8; 20], &[2u8; 20], 12345);
        let sig = signature::sign(&signing, &payload).unwrap();

        let tampered = create_commit_signature_payload(&[9u8; 20], &[2u8; 20], 12345);
        assert!(
            verify_commit_signature(&verifying.to_bytes(), &tampered, &sig.to_bytes()).is_err()
        );
    }
}
