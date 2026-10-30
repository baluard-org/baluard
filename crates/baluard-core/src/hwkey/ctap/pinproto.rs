//! pinUvAuth shared-secret establishment (CTAP2 spec §6.5.6/§6.5.7).
//!
//! PIN-less hmac-secret still needs this: the salt is encrypted under the
//! shared secret, so `authenticatorClientPIN` getKeyAgreement is mandatory.
//! Derivations mirror ctap-hid-fido2 (the interop-proven desktop adapter):
//! protocol 1 = SHA-256 of the raw ECDH output with AES-256-CBC/zero-IV;
//! protocol 2 = HKDF-SHA-256 with split HMAC/AES keys and a random IV.

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type CbcEnc = cbc::Encryptor<Aes256>;

fn derive_protocol_two(ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).expect("any key size");
    extract.update(ikm);
    let prk = Zeroizing::new(extract.finalize().into_bytes());
    let mut out = Zeroizing::new(vec![0u8; 64]);
    for (info, offset) in [
        (b"CTAP2 HMAC key".as_slice(), 0),
        (b"CTAP2 AES key".as_slice(), 32),
    ] {
        let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk).expect("any key size");
        expand.update(info);
        expand.update(&[1]);
        out[offset..offset + 32].copy_from_slice(&expand.finalize().into_bytes());
    }
    out
}

fn sha256_secret(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let digest = Zeroizing::new(Sha256::digest(input));
    Zeroizing::new(digest.to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    One,
    Two,
}

/// Key material: no `Clone`, and `Debug` never prints the secret.
pub struct SharedSecret {
    pub protocol: Protocol,
    /// COSE key of the client's ephemeral P-256 public key: {1:2, 3:-25, -1:1,
    /// -2:x, -3:y}. Sent as the getKeyAgreement response payload back to the
    /// token in the next clientPIN call.
    pub client_cose: Vec<u8>,
    /// Protocol 1: 32 bytes. Protocol 2: HMAC key (32) || AES key (32).
    pub secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

/// Builds the COSE P-256 key encoding CTAP2 expects for key agreement.
fn cose_p256(public: &p256::PublicKey) -> Vec<u8> {
    let point = public.to_encoded_point(false);
    let (x, y) = (&point.as_bytes()[1..33], &point.as_bytes()[33..65]);
    super::cbor::Value::Map(vec![
        (
            super::cbor::Value::Unsigned(1),
            super::cbor::Value::Unsigned(2),
        ),
        (
            super::cbor::Value::Unsigned(3),
            super::cbor::Value::Negative(-25),
        ),
        (
            super::cbor::Value::Negative(-1),
            super::cbor::Value::Unsigned(1),
        ),
        (
            super::cbor::Value::Negative(-2),
            super::cbor::Value::ByteString(x.to_vec()),
        ),
        (
            super::cbor::Value::Negative(-3),
            super::cbor::Value::ByteString(y.to_vec()),
        ),
    ])
    .encode()
}

/// AES-256-CBC with no padding. hmac-secret plaintexts (32/64-byte salts) are
/// always block-aligned, so padding never applies. The output is wiped on
/// drop because decryption yields the hmac-secret output.
fn aes_cbc(
    key: &[u8],
    iv: &[u8; 16],
    data: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if data.len() % 16 != 0 {
        return Err("plaintext not block-aligned".into());
    }
    let mut out = Zeroizing::new(vec![0u8; data.len()]);
    if encrypt {
        CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
            .map_err(|_| "aligned cbc".to_string())?;
    } else {
        cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
            .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
            .map_err(|_| "aligned cbc".to_string())?;
    }
    Ok(out)
}

impl SharedSecret {
    /// Token-side constructor (the software authenticator model): same
    /// derivations as [`SharedSecret::new`] from the already-computed ECDH
    /// output Z.
    #[cfg(test)]
    pub fn from_shared_z(protocol: Protocol, z: &[u8]) -> Result<Self, String> {
        let secret = match protocol {
            Protocol::One => sha256_secret(z),
            Protocol::Two => derive_protocol_two(z),
        };
        Ok(Self {
            protocol,
            client_cose: Vec::new(),
            secret,
        })
    }

    /// Establishes the shared secret against the token's key-agreement public
    /// key (uncompressed 65-byte 0x04||x||y or the raw 64-byte x||y form).
    pub fn new(protocol: Protocol, token_public: &[u8]) -> Result<Self, String> {
        let sec1: Vec<u8> = match token_public.len() {
            65 => token_public.to_vec(),
            64 => {
                let mut v = Vec::with_capacity(65);
                v.push(0x04);
                v.extend_from_slice(token_public);
                v
            }
            n => return Err(format!("unexpected key-agreement key length {n}")),
        };
        let peer = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())?;
        let client = EphemeralSecret::random(&mut rand_core::OsRng);
        let shared = Zeroizing::new(client.diffie_hellman(&peer).raw_secret_bytes().to_vec());
        let client_public = client.public_key();
        let client_cose = cose_p256(&client_public);
        let secret = match protocol {
            Protocol::One => sha256_secret(shared.as_slice()),
            Protocol::Two => derive_protocol_two(shared.as_slice()),
        };
        Ok(Self {
            protocol,
            client_cose,
            secret,
        })
    }

    /// authenticate(key, message), the hmac-secret saltAuth value (CTAP 2.1
    /// §6.5.6): protocol 1 keeps LEFT(HMAC-SHA-256, 16); protocol 2 keeps the
    /// full 32-byte HMAC.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.hmac_key()).expect("any key size");
        mac.update(message);
        let tag = mac.finalize().into_bytes();
        match self.protocol {
            Protocol::One => tag[..16].to_vec(),
            Protocol::Two => tag.to_vec(),
        }
    }

    /// The HMAC key: the whole secret for protocol 1, its first half for
    /// protocol 2.
    fn hmac_key(&self) -> &[u8] {
        if self.secret.len() == 64 {
            &self.secret[..32]
        } else {
            &self.secret
        }
    }

    /// encrypt(key, demPlaintext): protocol 1 uses a zero IV; protocol 2
    /// prepends a fresh random IV to the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        match self.protocol {
            Protocol::One => {
                aes_cbc(&self.secret, &[0u8; 16], plaintext, true).map(|out| out.to_vec())
            }
            Protocol::Two => {
                let mut iv = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
                let mut out = Vec::with_capacity(16 + plaintext.len());
                out.extend_from_slice(&iv);
                out.extend_from_slice(&aes_cbc(&self.secret[32..], &iv, plaintext, true)?);
                Ok(out)
            }
        }
    }

    /// decrypt(key, demCiphertext): the inverse of [`SharedSecret::encrypt`].
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        match self.protocol {
            Protocol::One => {
                if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
                    return Err("ciphertext not block-aligned".into());
                }
                aes_cbc(&self.secret, &[0u8; 16], ciphertext, false)
            }
            Protocol::Two => {
                if ciphertext.len() < 16 + 16 || (ciphertext.len() - 16) % 16 != 0 {
                    return Err("ciphertext not iv+block-aligned".into());
                }
                let (iv, ct) = ciphertext.split_at(16);
                let iv: [u8; 16] = iv.try_into().expect("16-byte iv");
                aes_cbc(&self.secret[32..], &iv, ct, false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38A F.2.5 CBC-AES256.Encrypt (first block).
    const NIST_KEY: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];
    const NIST_IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const NIST_PT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const NIST_CT: [u8; 16] = [
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb,
        0xd6,
    ];

    #[test]
    fn unaligned_cbc_input_is_an_error_not_a_release_panic() {
        let err = aes_cbc(&[0u8; 32], &[0u8; 16], &[0u8; 15], true).unwrap_err();
        assert!(err.contains("aligned"));
    }

    #[test]
    fn aes_cbc_matches_nist_vector() {
        assert_eq!(
            aes_cbc(&NIST_KEY, &NIST_IV, &NIST_PT, true)
                .unwrap()
                .as_slice(),
            NIST_CT
        );
        assert_eq!(
            aes_cbc(&NIST_KEY, &NIST_IV, &NIST_CT, false)
                .unwrap()
                .as_slice(),
            NIST_PT
        );
    }

    fn token_key() -> Vec<u8> {
        EphemeralSecret::random(&mut rand_core::OsRng)
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn both_protocols_roundtrip_hmac_secret_salt_shapes() {
        for protocol in [Protocol::One, Protocol::Two] {
            let ss = SharedSecret::new(protocol, &token_key()).unwrap();
            for salt_len in [32usize, 64] {
                let salt: Vec<u8> = (0..salt_len).map(|i| (i * 7 + 3) as u8).collect();
                let sealed = ss.encrypt(&salt).unwrap();
                assert_eq!(
                    sealed.len(),
                    if protocol == Protocol::Two {
                        salt_len + 16
                    } else {
                        salt_len
                    }
                );
                assert_eq!(ss.decrypt(&sealed).unwrap().as_slice(), salt.as_slice());
            }
        }
    }

    #[test]
    fn protocol_shapes_differ_as_specified() {
        // Protocol 1 must be zero-IV (same plaintext+key -> same ciphertext,
        // which a random-IV scheme would never produce).
        let ss1 = SharedSecret::new(Protocol::One, &token_key()).unwrap();
        let salt = [9u8; 32];
        assert_eq!(ss1.encrypt(&salt), ss1.encrypt(&salt));

        // Protocol 2 must be random-IV (identical inputs -> distinct outputs).
        let ss2 = SharedSecret::new(Protocol::Two, &token_key()).unwrap();
        let (a, b) = (ss2.encrypt(&salt).unwrap(), ss2.encrypt(&salt).unwrap());
        assert_ne!(a, b);
        assert_eq!(ss2.decrypt(&a).unwrap().as_slice(), salt);
        assert_eq!(ss2.decrypt(&b).unwrap().as_slice(), salt);

        // Secret sizes per protocol.
        assert_eq!(ss1.secret.len(), 32);
        assert_eq!(ss2.secret.len(), 64);
    }

    // Known answers computed outside this crate (Python hmac/hashlib, HKDF
    // per RFC 5869) for Z = 00 01 .. 1f and message = 48 x 0xa5.
    fn kat_z() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn protocol_two_salt_auth_is_the_full_32_byte_hmac() {
        let ss = SharedSecret::from_shared_z(Protocol::Two, &kat_z()).unwrap();
        assert_eq!(
            hex::encode(&ss.secret[..32]),
            "a689b3b92a6ebab91192408da9c4f05c674a2bc5f938d613077716c719a8df39"
        );
        assert_eq!(
            hex::encode(&ss.secret[32..]),
            "0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b58d44"
        );
        let tag = ss.authenticate(&[0xa5u8; 48]);
        assert_eq!(tag.len(), 32);
        assert_eq!(
            hex::encode(tag),
            "810b1140ddfc633eaa85ec5f6e73e7571434a622e437545f8f562d95e0dc8661"
        );
    }

    #[test]
    fn protocol_one_salt_auth_is_the_left_16_bytes() {
        let ss = SharedSecret::from_shared_z(Protocol::One, &kat_z()).unwrap();
        assert_eq!(
            hex::encode(&*ss.secret),
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        );
        assert_eq!(
            hex::encode(ss.authenticate(&[0xa5u8; 48])),
            "3a8f6a4e720cdc2dd4daa9d78a78f19c"
        );
    }

    #[test]
    fn debug_output_never_carries_key_material() {
        let ss = SharedSecret::from_shared_z(Protocol::Two, &kat_z()).unwrap();
        let shown = format!("{ss:?}");
        assert!(!shown.contains("a689b3b9"));
        assert!(!shown.contains("secret"));
    }

    #[test]
    fn rejects_short_keys() {
        assert!(SharedSecret::new(Protocol::One, &[0u8; 63]).is_err());
    }
}
