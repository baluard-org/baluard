//! Signed commit construction and verification.
//!
//! D9: Static "vault update" commit messages.
//! D22: All commits signed with device Ed25519 signing key.

use crate::crypto::signature;
use crate::error::SyncError;

/// Static commit message per D9.
pub const COMMIT_MESSAGE: &str = "vault update";

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
        let payload = b"tree 1b2e5d2 parent a3f9c11 committer x";
        let sig = signature::sign(&signing, payload).unwrap();

        let sig_bytes = sig.to_bytes();
        verify_commit_signature(&verifying.to_bytes(), payload, &sig_bytes).unwrap();
    }

    #[test]
    fn tampered_payload_fails() {
        let (signing, verifying) = generate_ed25519_keypair();
        let payload = b"tree 1b2e5d2 parent a3f9c11 committer x";
        let sig = signature::sign(&signing, payload).unwrap();

        let tampered = b"tree 9e1f7a3 parent a3f9c11 committer x";
        assert!(verify_commit_signature(&verifying.to_bytes(), tampered, &sig.to_bytes()).is_err());
    }
}
