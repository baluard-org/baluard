//! HPKE-based key wrapping (DHKEM(X25519, HKDF-SHA256), AES-256-GCM).
//!
//! D3: Root Key wrapped per-device via HPKE with X25519.
//! D17: Org Key wrapped per-member via HPKE.
//! D18: Emergency access keys wrapped via HPKE.
//!
//! Implemented with the `hpke` crate (RFC 9180) single-shot API in Base mode
//! (no PSK, no sender auth). This retires the prior homegrown ECIES:
//!   - proper DHKEM key encap (kem_context binds BOTH ephemeral + recipient pubkeys)
//!   - HKDF-derived AEAD key + nonce (not raw DH bytes)
//!   - contributory check is part of DHKEM (rejects low-order points)
//!   - AAD flows through the HPKE context (callers still pass the wire AAD)
//!
//! Wire shape is unchanged: callers persist `{ ephemeral_public, encrypted_key, tag }`.
//! HPKE's single-shot seal returns ciphertext-with-tag-appended; we split it at
//! the boundary so existing on-disk `WrappedKeyEntry` files keep their 3-field
//! shape. The split is cosmetic: tag is always the last 16 bytes of the HPKE
//! ciphertext per RFC 9180 §6.1 (AES-256-GCM tag length = 16).

use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

/// AES-256-GCM tag length in bytes (RFC 9180 §6.1).
const GCM_TAG_LEN: usize = 16;

/// Result of HPKE key wrapping: (ephemeral_public_key, encrypted_key, auth_tag).
pub type WrapResult = Result<(Vec<u8>, Vec<u8>, [u8; 16]), CryptoError>;

/// Generate a new X25519 keypair for device wrapping.
pub fn generate_x25519_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Wrap (encrypt) a key using HPKE with the recipient's X25519 public key.
///
/// Uses DHKEM(X25519, HKDF-SHA256) + AES-256-GCM in Base mode (RFC 9180).
/// `context` binds the wrap to its purpose and bindings (e.g.
/// `"keywrap:{vault_id}:{device_id}"`) — a wrap produced under one context
/// cannot be unwrapped under another (P7: wrap context binding).
/// Returns: (ephemeral_public_key, encrypted_key, auth_tag).
pub fn wrap_key(plaintext_key: &[u8], recipient_pub: &PublicKey, context: &str) -> WrapResult {
    let recip_pub_hpke =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(recipient_pub.as_bytes())
            .map_err(|e| CryptoError::HpkeFailed(format!("recipient pubkey import: {e}")))?;

    let aad = format!("baluard-keywrap/{context}");
    let mut rng = OsRng;
    let (encapped, ciphertext_with_tag) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &recip_pub_hpke,
            b"baluard-hpke-wrap-v2",
            plaintext_key,
            aad.as_bytes(),
            &mut rng,
        )
        .map_err(|e| CryptoError::HpkeFailed(format!("seal: {e}")))?;

    // Split ciphertext || tag (hpke returns them appended) into the on-disk
    // 3-field shape. Tag is always the final 16 bytes.
    if ciphertext_with_tag.len() < GCM_TAG_LEN {
        return Err(CryptoError::HpkeFailed(format!(
            "ciphertext too short: {} bytes",
            ciphertext_with_tag.len()
        )));
    }
    let ct_len = ciphertext_with_tag.len() - GCM_TAG_LEN;
    let mut tag = [0u8; GCM_TAG_LEN];
    tag.copy_from_slice(&ciphertext_with_tag[ct_len..]);

    // EncappedKey serializes to exactly the 32-byte ephemeral X25519 public key.
    let eph_pub_bytes = encapped.to_bytes().to_vec();

    Ok((eph_pub_bytes, ciphertext_with_tag[..ct_len].to_vec(), tag))
}

/// Unwrap (decrypt) a key using HPKE with the recipient's X25519 private key.
/// `context` must match the context used at seal time — a mismatch fails the
/// GCM tag check (P7: wrap context binding prevents transplants).
pub fn unwrap_key(
    ephemeral_pub_bytes: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    recipient_priv: &StaticSecret,
    context: &str,
) -> Result<Vec<u8>, CryptoError> {
    if ephemeral_pub_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: ephemeral_pub_bytes.len(),
        });
    }

    // Reconstruct the HPKE EncappedKey from the serialized ephemeral pubkey.
    let encapped =
        <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(ephemeral_pub_bytes)
            .map_err(|e| CryptoError::HpkeFailed(format!("encapped import: {e}")))?;

    // Import the recipient's x25519_dalek private key into hpke's wrapper type.
    let recip_priv_hpke =
        <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(&recipient_priv.to_bytes())
            .map_err(|e| CryptoError::HpkeFailed(format!("recipient privkey import: {e}")))?;

    // Re-assemble ciphertext || tag (hpke expects them appended).
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + GCM_TAG_LEN);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let aad = format!("baluard-keywrap/{context}");
    let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &recip_priv_hpke,
        &encapped,
        b"baluard-hpke-wrap-v2",
        &ct_with_tag,
        aad.as_bytes(),
    )
    .map_err(|e| CryptoError::UnwrapFailed(format!("HPKE open: {e}")))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (priv_key, pub_key) = generate_x25519_keypair();
        let secret_data = b"root-key-32-bytes-of-randomness!!"; // 32 bytes

        let (eph_pub, ct, tag) =
            wrap_key(secret_data, &pub_key, "keywrap:test:vault:device").unwrap();
        let unwrapped =
            unwrap_key(&eph_pub, &ct, &tag, &priv_key, "keywrap:test:vault:device").unwrap();

        assert_eq!(unwrapped, secret_data);
    }

    #[test]
    fn wrong_private_key_fails() {
        let (_, pub_key) = generate_x25519_keypair();
        let (wrong_priv, _) = generate_x25519_keypair();

        let (eph_pub, ct, tag) = wrap_key(
            b"secret-key-material",
            &pub_key,
            "keywrap:test:vault:device",
        )
        .unwrap();
        assert!(
            unwrap_key(
                &eph_pub,
                &ct,
                &tag,
                &wrong_priv,
                "keywrap:test:vault:device"
            )
            .is_err()
        );
    }

    #[test]
    fn ephemeral_public_is_32_bytes() {
        // Wire-shape guard: the encapped key must serialize to exactly the
        // 32-byte X25519 public key, matching the on-disk format.
        let (_, pub_key) = generate_x25519_keypair();
        let (eph_pub, _ct, _tag) = wrap_key(b"any", &pub_key, "test").unwrap();
        assert_eq!(eph_pub.len(), 32);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        // A-3/A-4 guards: HPKE authenticates the whole ciphertext + AAD; a
        // single-bit flip in ct must fail the tag check, not unwrap to garbage.
        let (priv_key, pub_key) = generate_x25519_keypair();
        let secret = b"thirty-two-byte-root-key-xxxxxxx";
        let (eph_pub, mut ct, tag) = wrap_key(secret, &pub_key, "test:tamper").unwrap();
        ct[0] ^= 0xff;
        assert!(unwrap_key(&eph_pub, &ct, &tag, &priv_key, "test:tamper").is_err());
    }

    /// P7: a wrap produced under one context must fail to unwrap under a
    /// different context — this is the transplant-rejection guarantee.
    #[test]
    fn context_mismatch_fails() {
        let (priv_key, pub_key) = generate_x25519_keypair();
        let secret = b"root-key-material";
        let (eph_pub, ct, tag) = wrap_key(secret, &pub_key, "keywrap:vault-a:device-1").unwrap();

        // Same key, different context: must fail.
        assert!(unwrap_key(&eph_pub, &ct, &tag, &priv_key, "keywrap:vault-a:device-2").is_err());

        // Different purpose, same bindings: must also fail.
        assert!(
            unwrap_key(
                &eph_pub,
                &ct,
                &tag,
                &priv_key,
                "identity-escrow:vault-a:device-1"
            )
            .is_err()
        );

        // Same context: must succeed.
        assert!(unwrap_key(&eph_pub, &ct, &tag, &priv_key, "keywrap:vault-a:device-1").is_ok());
    }
}
