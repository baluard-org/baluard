//! Vault SSH key material helpers behind the agent: parse the stored
//! OpenSSH private-key text, derive the wire-encoded public blob and
//! SHA-256 fingerprint, and produce wire-encoded signatures.
//!
//! Only ed25519 and ECDSA P-256 are supported — the same types the daemon
//! generates (ADR 0014). RSA stays out with the L7 RUSTSEC-2023-0071 fix.

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
    /// Stored text is not a readable unencrypted OpenSSH private key.
    Unreadable,
    /// Encrypted private keys cannot be served without a passphrase flow.
    Encrypted,
    /// RSA or another algorithm outside the served set.
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

/// Parse stored OpenSSH private-key text into a serving-ready key.
/// Returns the wire blob and fingerprint; the parsed private key itself
/// is kept by the caller for signing and zeroized on drop.
pub fn load_material(openssh_text: &str) -> Result<(PrivateKey, SshKeyMaterial), KeyError> {
    let private = PrivateKey::from_openssh(openssh_text).map_err(|_| KeyError::Unreadable)?;
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
    ) {
        return Err(KeyError::UnsupportedAlgorithm);
    }
    let public = private.public_key();
    let blob = public.to_bytes().map_err(|_| KeyError::Unreadable)?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    Ok((private, SshKeyMaterial { blob, fingerprint }))
}

/// Sign `data` and encode the signature in agent wire form
/// (string alg + string sig blob), exactly what `14` responses carry.
pub fn sign_wire(private: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, KeyError> {
    use signature::{SignatureEncoding, Signer};
    let signature = private.try_sign(data).map_err(|_| KeyError::Unreadable)?;
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
        assert!(sign_wire(&parsed, b"hello").is_ok());
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
        assert!(sign_wire(&parsed, b"payload").is_ok());
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
        let wire = sign_wire(&private, msg).unwrap();
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
        let wire = sign_wire(&private, b"payload").unwrap();
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

    #[test]
    fn ed25519_signing_is_deterministic_for_a_fixed_seed() {
        let private = ed25519_private();
        let a = sign_wire(&private, b"same input").unwrap();
        let b = sign_wire(&private, b"same input").unwrap();
        assert_eq!(a, b);
    }
}
