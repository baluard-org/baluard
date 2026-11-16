//! Vault SSH key material helpers behind the agent: parse the stored
//! private-key text, derive the wire-encoded public blob and
//! SHA-256 fingerprint, and produce wire-encoded signatures.
//!
//! Serves ed25519 and ECDSA P-256 (the types the daemon generates, ADR 0014)
//! plus imported RSA, including legacy PKCS#1 and PKCS#8 PEM containers.
//! RSA signing follows the sign-request flags: rsa-sha2-256 / rsa-sha2-512,
//! falling back to legacy ssh-rsa (SHA-1) when a client requests neither —
//! the only path old servers that predate RFC 8332 will accept.

use ssh_key::private::PrivateKey;
use ssh_key::{Algorithm, HashAlg};

/// One served key, ready for the agent protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyMaterial {
    /// Wire-encoded public key blob (string alg + params), identities-answer form.
    pub blob: Vec<u8>,
    /// `SHA256:<base64>` as stored by keygen and shown in the desktop.
    pub fingerprint: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Stored text is not a readable unencrypted private key.
    Unreadable,
    /// Encrypted private keys cannot be served without a passphrase flow.
    Encrypted,
    /// DSA and the other algorithms outside the served set.
    UnsupportedAlgorithm,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Unreadable => write!(f, "ssh key text is unreadable"),
            KeyError::Encrypted => write!(f, "encrypted ssh keys are not served by the agent"),
            KeyError::UnsupportedAlgorithm => {
                write!(f, "ssh key algorithm is not served by the agent")
            }
        }
    }
}

/// Parse stored private-key text into a serving-ready key.
/// Accepts OpenSSH containers plus legacy PKCS#1 and PKCS#8 PEM wrappers.
/// Returns the wire blob and fingerprint; the parsed private key itself
/// is kept by the caller for signing and zeroized on drop.
pub fn load_material(private_text: &str) -> Result<(PrivateKey, SshKeyMaterial), KeyError> {
    let private = parse_private(private_text)?;
    if private.is_encrypted() {
        return Err(KeyError::Encrypted);
    }
    let algorithm = private.algorithm();
    if !matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256
            }
            | Algorithm::Rsa { .. }
    ) {
        return Err(KeyError::UnsupportedAlgorithm);
    }
    let public = private.public_key();
    let blob = public.to_bytes().map_err(|_| KeyError::Unreadable)?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    Ok((private, SshKeyMaterial { blob, fingerprint }))
}

/// OpenSSH container first (the daemon's own format); PEM wrappers follow
/// because keys generated before OpenSSH 7.8 (2018) carry PKCS#1 armor and
/// many tools still export PKCS#8.
fn parse_private(text: &str) -> Result<PrivateKey, KeyError> {
    if let Ok(k) = PrivateKey::from_openssh(text) {
        return Ok(k);
    }
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let trimmed = text.trim();
    if trimmed.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        let key = rsa::RsaPrivateKey::from_pkcs1_pem(trimmed).map_err(|_| KeyError::Unreadable)?;
        return rsa_to_private(key);
    }
    if trimmed.starts_with("-----BEGIN PRIVATE KEY-----") {
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(trimmed).map_err(|_| KeyError::Unreadable)?;
        return rsa_to_private(key);
    }
    Err(KeyError::Unreadable)
}

fn rsa_to_private(key: rsa::RsaPrivateKey) -> Result<PrivateKey, KeyError> {
    let keypair = ssh_key::private::RsaKeypair::try_from(key).map_err(|_| KeyError::Unreadable)?;
    PrivateKey::new(ssh_key::private::KeypairData::Rsa(keypair), String::new())
        .map_err(|_| KeyError::Unreadable)
}

#[cfg(test)]
pub(crate) fn test_rsa_raw(bits: usize) -> rsa::RsaPrivateKey {
    struct RngAdapter;
    impl ssh_key::rand_core::TryRng for RngAdapter {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            use rand::RngCore;
            Ok(rand::rngs::OsRng.next_u32())
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            use rand::RngCore;
            Ok(rand::rngs::OsRng.next_u64())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(dst);
            Ok(())
        }
    }
    impl ssh_key::rand_core::TryCryptoRng for RngAdapter {}

    rsa::RsaPrivateKey::new(&mut RngAdapter, bits).expect("rsa generation")
}

#[cfg(test)]
pub(crate) fn test_rsa_openssh_private(bits: usize) -> PrivateKey {
    let key = test_rsa_raw(bits);
    let keypair = ssh_key::private::RsaKeypair::try_from(key).expect("keypair conversion");
    PrivateKey::new(ssh_key::private::KeypairData::Rsa(keypair), String::new())
        .expect("rsa private key construction")
}

/// Sign-request flags for the RSA SHA-2 variants (RFC 8332). When a client
/// sets neither bit it is asking for legacy `ssh-rsa` SHA-1 signatures —
/// the only thing servers predating RFC 8332 will verify.
const FLAG_RSA_SHA2_256: u32 = 2;
const FLAG_RSA_SHA2_512: u32 = 4;

/// Sign `data` and encode the signature in agent wire form
/// (string alg + string sig blob), exactly what `14` responses carry.
/// `flags` selects the RSA hash; ed25519 and ECDSA ignore it.
pub fn sign_wire(private: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, KeyError> {
    use signature::{SignatureEncoding, Signer};
    let signature = match private.key_data() {
        ssh_key::private::KeypairData::Rsa(keypair) => {
            let hash = if flags & FLAG_RSA_SHA2_512 != 0 {
                Some(HashAlg::Sha512)
            } else if flags & FLAG_RSA_SHA2_256 != 0 {
                Some(HashAlg::Sha256)
            } else {
                None
            };
            use signature::Signer as _;
            (keypair, hash)
                .try_sign(data)
                .map_err(|_| KeyError::Unreadable)?
        }
        _ => private.try_sign(data).map_err(|_| KeyError::Unreadable)?,
    };
    Ok(signature.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use ssh_key::LineEnding;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    /// Fixed test seed — synthetic, never a real key.
    const SEED: [u8; 32] = [7u8; 32];

    fn ed25519_private() -> PrivateKey {
        let kp = Ed25519Keypair::from_seed(&SEED);
        PrivateKey::new(KeypairData::Ed25519(kp), String::new()).expect("ed25519 key construction")
    }

    fn openssh_text(private: &PrivateKey) -> String {
        private.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    // Adapter bridging rand 0.8 OsRng to ssh_key's rand_core 0.10 traits,
    // same shape as the generator in runtime state.rs.
    struct Adapter;
    impl ssh_key::rand_core::TryRng for Adapter {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(rand::rngs::OsRng.next_u32())
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(rand::rngs::OsRng.next_u64())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            rand::rngs::OsRng.fill_bytes(dst);
            Ok(())
        }
    }
    impl ssh_key::rand_core::TryCryptoRng for Adapter {}

    fn p256_random() -> PrivateKey {
        PrivateKey::random(
            &mut Adapter,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .expect("p256 key generation")
    }

    // --- load_material -----------------------------------------------------

    #[test]
    fn ed25519_material_round_trips_blob_and_fingerprint() {
        let private = ed25519_private();
        let (parsed, material) = load_material(&openssh_text(&private)).unwrap();
        assert!(material.fingerprint.starts_with("SHA256:"));
        // Blob re-parses as a public key and re-encodes byte-identical.
        let key = ssh_key::PublicKey::from_bytes(&material.blob).unwrap();
        assert_eq!(key.algorithm(), ssh_key::Algorithm::Ed25519);
        assert_eq!(key.to_bytes().unwrap(), material.blob);
        // The parsed private key signs (smoke, not verification).
        assert!(sign_wire(&parsed, b"hello", 0).is_ok());
    }

    #[test]
    fn ed25519_blob_names_the_ssh_ed25519_algorithm() {
        let private = ed25519_private();
        let (_, material) = load_material(&openssh_text(&private)).unwrap();
        // First ssh string inside the blob is the algorithm name.
        let alg_len = u32::from_be_bytes(material.blob[..4].try_into().unwrap()) as usize;
        assert_eq!(&material.blob[4..4 + alg_len], b"ssh-ed25519");
    }

    #[test]
    fn p256_material_loads_and_signs() {
        let private = p256_random();
        let (parsed, material) = load_material(&openssh_text(&private)).unwrap();
        assert!(material.fingerprint.starts_with("SHA256:"));
        assert!(sign_wire(&parsed, b"payload", 0).is_ok());
    }

    #[test]
    fn garbage_text_is_unreadable() {
        assert_eq!(load_material("not a key"), Err(KeyError::Unreadable));
        assert_eq!(load_material(""), Err(KeyError::Unreadable));
    }

    #[test]
    fn encrypted_keys_are_refused() {
        let private = ed25519_private();
        let encrypted = private
            .encrypt(&mut Adapter, "test-passphrase-for-the-gate")
            .unwrap();
        let text = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();
        assert_eq!(load_material(&text), Err(KeyError::Encrypted));
    }

    // --- sign_wire ---------------------------------------------------------

    #[test]
    fn ed25519_signature_verifies_against_the_public_key() {
        let private = ed25519_private();
        let msg = b"baluard agent challenge";
        let wire = sign_wire(&private, msg, 0).unwrap();
        // Decode: string alg, string sig(64).
        let alg_len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(&wire[4..4 + alg_len], b"ssh-ed25519");
        let mut at = 4 + alg_len;
        let sig_len = u32::from_be_bytes(wire[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        assert_eq!(sig_len, 64);
        assert_eq!(wire.len(), at + 64);
        let sig: [u8; 64] = wire[at..].try_into().unwrap();
        let kp = match private.key_data() {
            KeypairData::Ed25519(kp) => kp,
            _ => unreachable!("test builds ed25519 only"),
        };
        use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&kp.public.0).unwrap();
        vk.verify(msg, &DalekSig::from_bytes(&sig)).unwrap();
    }

    #[test]
    fn p256_signature_carries_nistp256_alg_and_r_s_pair() {
        let private = p256_random();
        let wire = sign_wire(&private, b"payload", 0).unwrap();
        let alg_len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(&wire[4..4 + alg_len], b"ecdsa-sha2-nistp256");
        let mut at = 4 + alg_len;
        let sig_len = u32::from_be_bytes(wire[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        assert_eq!(wire.len(), at + sig_len);
        // RFC 5656: ECDSA sig blob is mpint r, mpint s. An mpint pads a
        // high first byte with 0x00, so either half may reach 33 bytes.
        let blob = &wire[at..];
        let read_mpint = |off: usize| -> (usize, &[u8]) {
            let n = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
            assert!((1..=33).contains(&n), "mpint len {n}");
            (off + 4 + n, &blob[off + 4..off + 4 + n])
        };
        let (after_r, r) = read_mpint(0);
        let (after_s, s) = read_mpint(after_r);
        assert_eq!(after_s, blob.len(), "trailing bytes in sig blob");
        // Stripped of the mpint pad, each half is a full-width P-256
        // scalar. Minimal mpint encoding strips a scalar-high 0x00 byte,
        // so a signature whose r or s lands under 2^248 carries 31 wire
        // bytes: the honest bound is 31..=32 with a minimal encoding.
        let scalar_len = |m: &[u8]| -> usize {
            if m.first() == Some(&0) {
                m.len() - 1
            } else {
                m.len()
            }
        };
        let r_len = scalar_len(r);
        let s_len = scalar_len(s);
        assert!((31..=32).contains(&r_len), "r scalar len {r_len}");
        assert!((31..=32).contains(&s_len), "s scalar len {s_len}");
        // Minimal encoding: no stripped-able zero pad may remain.
        if r.len() <= 32 {
            assert_ne!(r.first(), Some(&0), "r mpint not minimal");
        }
        if s.len() <= 32 {
            assert_ne!(s.first(), Some(&0), "s mpint not minimal");
        }
    }

    // --- RSA serving (fixtures come from the crate-level test support) -----

    use test_rsa_openssh_private as rsa_openssh_private;

    fn alg_name(blob: &[u8]) -> String {
        let alg_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        String::from_utf8(blob[4..4 + alg_len].to_vec()).unwrap()
    }

    fn wire_sig_alg(wire: &[u8]) -> String {
        let alg_len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        String::from_utf8(wire[4..4 + alg_len].to_vec()).unwrap()
    }

    #[test]
    fn rsa_material_round_trips_blob_fingerprint_and_signs() {
        let private = rsa_openssh_private(2048);
        let text = openssh_text(&private);
        let (parsed, material) = load_material(&text).unwrap();
        assert!(material.fingerprint.starts_with("SHA256:"));
        assert_eq!(alg_name(&material.blob), "ssh-rsa");
        let key = ssh_key::PublicKey::from_bytes(&material.blob).unwrap();
        assert_eq!(key.to_bytes().unwrap(), material.blob);
        assert!(sign_wire(&parsed, b"hello", 4).is_ok());
    }

    #[test]
    fn legacy_sized_rsa_keys_are_served() {
        let private = rsa_openssh_private(1024);
        let (_, material) = load_material(&openssh_text(&private)).unwrap();
        assert_eq!(alg_name(&material.blob), "ssh-rsa");
        assert!(material.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn rsa_pkcs1_pem_containers_are_served() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let raw = test_rsa_raw(2048);
        let pem = raw
            .to_pkcs1_pem(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        let (_, material) = load_material(&pem).unwrap();
        assert_eq!(alg_name(&material.blob), "ssh-rsa");
        assert!(sign_wire(&load_material(&pem).unwrap().0, b"x", 4).is_ok());
    }

    #[test]
    fn rsa_pkcs8_pem_containers_are_served() {
        use rsa::pkcs8::EncodePrivateKey;
        let raw = test_rsa_raw(2048);
        let pem = raw
            .to_pkcs8_pem(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let (_, material) = load_material(&pem).unwrap();
        assert_eq!(alg_name(&material.blob), "ssh-rsa");
    }

    #[test]
    fn rsa_sign_flags_select_the_signature_algorithm() {
        let private = rsa_openssh_private(2048);
        let none = sign_wire(&private, b"m", 0).unwrap();
        let sha256 = sign_wire(&private, b"m", FLAG_RSA_SHA2_256).unwrap();
        let sha512 = sign_wire(&private, b"m", FLAG_RSA_SHA2_512).unwrap();
        assert_eq!(wire_sig_alg(&none), "ssh-rsa");
        assert_eq!(wire_sig_alg(&sha256), "rsa-sha2-256");
        assert_eq!(wire_sig_alg(&sha512), "rsa-sha2-512");
        // Both flag bits set: the higher hash wins, matching OpenSSH.
        let both = sign_wire(&private, b"m", FLAG_RSA_SHA2_256 | FLAG_RSA_SHA2_512).unwrap();
        assert_eq!(wire_sig_alg(&both), "rsa-sha2-512");
    }

    #[test]
    fn rsa_signatures_verify_against_the_public_key() {
        let private = rsa_openssh_private(2048);
        let public = private.public_key();
        for flags in [0, FLAG_RSA_SHA2_256, FLAG_RSA_SHA2_512] {
            let wire = sign_wire(&private, b"challenge", flags).unwrap();
            let sig = ssh_key::Signature::try_from(&wire[..]).unwrap();
            use signature::Verifier;
            public.key_data().verify(b"challenge", &sig).unwrap();
        }
    }

    #[test]
    fn pkcs1_v15_signing_is_deterministic() {
        let private = rsa_openssh_private(2048);
        let a = sign_wire(&private, b"same", FLAG_RSA_SHA2_256).unwrap();
        let b = sign_wire(&private, b"same", FLAG_RSA_SHA2_256).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ed25519_signing_is_deterministic_for_a_fixed_seed() {
        let private = ed25519_private();
        let a = sign_wire(&private, b"same input", 0).unwrap();
        let b = sign_wire(&private, b"same input", 0).unwrap();
        assert_eq!(a, b);
    }
}
