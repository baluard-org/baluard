//! Wrapped-key envelope shared by the emergency escrow.
//!
//! History: this module once carried org key distribution and member
//! management (OrgMember, AccessList, add_member, remove_member) aimed at
//! the sharing plan. Sharing shipped through vault/space_meta.rs and
//! vault/members.rs instead, so only the three-field HPKE envelope survived
//! as a dependency: EmergencyConfig.wrapped_root_key stores the
//! Root Key wrapped for the trusted contact, and both rotation paths
//! rebuild it.

use crate::crypto::hpke_wrap;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyBundle {
    pub ephemeral_pub: String, // hex
    pub ciphertext: String,    // hex
    pub tag: String,           // hex
}

/// Wrap `key` to `recipient` and hex-encode the HPKE result into a bundle.
///
/// The context string domain-separates uses (emergency escrow vs others).
/// Key length stays generic (`&[u8]`) to match `hpke_wrap::wrap_key`: the
/// escrow wraps the 64-byte Root Key, not a 32-byte content key.
pub fn wrap_to_bundle(
    key: &[u8],
    recipient: &PublicKey,
    context: &str,
) -> Result<WrappedKeyBundle, crate::error::BaluardError> {
    let (eph_pub, ct, tag) = hpke_wrap::wrap_key(key, recipient, context)?;
    Ok(WrappedKeyBundle {
        ephemeral_pub: hex::encode(eph_pub),
        ciphertext: hex::encode(ct),
        tag: hex::encode(tag),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_to_bundle_matches_direct_hpke_fields() {
        let (_secret, device_pub) = hpke_wrap::generate_x25519_keypair();
        let key = [42u8; 64];

        let bundle = wrap_to_bundle(&key, &device_pub, "test-context").unwrap();

        // Fresh randomness per call, so pin shape only: 32-byte ephemeral
        // key, ciphertext that excludes the tag (it is split out), 16-byte tag.
        assert_eq!(hex::decode(&bundle.ephemeral_pub).unwrap().len(), 32);
        assert_eq!(hex::decode(&bundle.tag).unwrap().len(), 16);
        assert_eq!(hex::decode(&bundle.ciphertext).unwrap().len(), key.len());
    }
}
