//! AEAD envelope binary serialization.
//!
//! D3: {version: u8, alg_id: u16, key_epoch: u64, nonce: [u8;12], aad_len: u16, aad, ciphertext, tag: [u8;16]}
//!
//! All fields are little-endian. Header fields are plaintext for key selection
//! before decryption (no circular dependency).

use crate::error::VaultError;
use crate::types::{CipherEnvelope, EnvelopeHeader};

// Binary envelope layout:
//   [0]       version: u8
//   [1..3]    alg_id: u16 LE
//   [3..11]   key_epoch: u64 LE
//   [11..19]  nonce_counter: u64 LE
//   [19..27]  update_seq: u64 LE
//   [27]      tier: u8 (0=none, 1=xs, 2=s, 3=m, 4=l, 5=xl)
//   [27..39]  nonce: [u8; 12]
//   [39..41]  aad_len: u16 LE
//   [41..41+aad_len]  aad
//   [41+aad_len..41+aad_len+tag_len]  tag: [u8; 16]
//   [rest]    ciphertext

// Header: version(1) + alg_id(2) + key_epoch(8) + nonce_counter(8)
// + update_seq(8) + tier(1) = 28 bytes.
const HEADER_SIZE: usize = 28;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const AAD_LEN_SIZE: usize = 2;

/// Serialize an envelope to binary format.
pub fn serialize(envelope: &CipherEnvelope) -> Result<Vec<u8>, VaultError> {
    let tier_byte = envelope
        .header
        .tier
        .map(|t| match t {
            crate::types::Tier::Xs => 1u8,
            crate::types::Tier::S => 2,
            crate::types::Tier::M => 3,
            crate::types::Tier::L => 4,
            crate::types::Tier::Xl => 5,
        })
        .unwrap_or(0);

    if envelope.aad.len() > u16::MAX as usize {
        return Err(VaultError::Corrupt(
            "envelope AAD exceeds the wire format's 64 KiB bound".into(),
        ));
    }
    let aad_len = envelope.aad.len() as u16;
    let total_size = HEADER_SIZE
        + NONCE_SIZE
        + AAD_LEN_SIZE
        + envelope.aad.len()
        + TAG_SIZE
        + envelope.ciphertext.len();

    let mut buf = Vec::with_capacity(total_size);

    // Header
    buf.push(envelope.header.version);
    buf.extend_from_slice(&envelope.header.alg_id.to_le_bytes());
    buf.extend_from_slice(&envelope.header.key_epoch.to_le_bytes());
    buf.extend_from_slice(&envelope.header.nonce_counter.to_le_bytes());
    buf.extend_from_slice(&envelope.header.update_seq.to_le_bytes());
    buf.push(tier_byte);

    // Nonce
    buf.extend_from_slice(&envelope.nonce);

    // AAD
    buf.extend_from_slice(&aad_len.to_le_bytes());
    buf.extend_from_slice(&envelope.aad);

    // Tag
    buf.extend_from_slice(&envelope.tag);

    // Ciphertext
    buf.extend_from_slice(&envelope.ciphertext);

    Ok(buf)
}

/// Deserialize binary data into an envelope.
pub fn deserialize(data: &[u8]) -> Result<CipherEnvelope, VaultError> {
    if data.len() < HEADER_SIZE + NONCE_SIZE + AAD_LEN_SIZE + TAG_SIZE {
        return Err(VaultError::Corrupt("envelope too short".into()));
    }

    let mut pos = 0;

    // Header
    let version = data[pos];
    pos += 1;
    if version != crate::BALUARD_VERSION {
        return Err(VaultError::InvalidEnvelopeVersion(version));
    }

    let alg_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    if alg_id != crate::ALG_AES_256_GCM {
        return Err(VaultError::Corrupt(format!(
            "unsupported envelope algorithm: {alg_id}"
        )));
    }
    let key_epoch = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let nonce_counter = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let update_seq = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;

    let tier_byte = data[pos];
    pos += 1;
    let tier = match tier_byte {
        0 => None,
        1 => Some(crate::types::Tier::Xs),
        2 => Some(crate::types::Tier::S),
        3 => Some(crate::types::Tier::M),
        4 => Some(crate::types::Tier::L),
        5 => Some(crate::types::Tier::Xl),
        _ => {
            return Err(VaultError::InvalidTier(format!(
                "invalid tier byte: {tier_byte}"
            )));
        }
    };

    // Nonce
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[pos..pos + NONCE_SIZE]);
    pos += NONCE_SIZE;

    // AAD
    let aad_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if data.len() < pos + aad_len + TAG_SIZE {
        return Err(VaultError::Corrupt("envelope truncated at AAD".into()));
    }
    let aad = data[pos..pos + aad_len].to_vec();
    pos += aad_len;

    // Tag
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&data[pos..pos + TAG_SIZE]);
    pos += TAG_SIZE;

    // Ciphertext (rest of buffer)
    let ciphertext = data[pos..].to_vec();

    Ok(CipherEnvelope {
        header: EnvelopeHeader {
            version,
            alg_id,
            key_epoch,
            nonce_counter,
            update_seq,
            tier,
        },
        nonce,
        aad,
        ciphertext,
        tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EnvelopeHeader, Tier};
    use crate::{ALG_AES_256_GCM, BALUARD_VERSION};

    fn test_envelope() -> CipherEnvelope {
        CipherEnvelope {
            header: EnvelopeHeader {
                version: BALUARD_VERSION,
                alg_id: ALG_AES_256_GCM,
                key_epoch: 1,
                nonce_counter: 0,
                update_seq: 5,
                tier: Some(Tier::Xs),
            },
            nonce: [42u8; 12],
            aad: vec![1, 2, 3, 4],
            ciphertext: vec![0xAB; 100],
            tag: [0xCD; 16],
        }
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let envelope = test_envelope();
        let bytes = serialize(&envelope).unwrap();
        let restored = deserialize(&bytes).unwrap();

        assert_eq!(envelope.header.version, restored.header.version);
        assert_eq!(envelope.header.alg_id, restored.header.alg_id);
        assert_eq!(envelope.header.key_epoch, restored.header.key_epoch);
        assert_eq!(envelope.header.nonce_counter, restored.header.nonce_counter);
        assert_eq!(envelope.header.update_seq, restored.header.update_seq);
        assert_eq!(envelope.header.tier, restored.header.tier);
        assert_eq!(envelope.nonce, restored.nonce);
        assert_eq!(envelope.aad, restored.aad);
        assert_eq!(envelope.ciphertext, restored.ciphertext);
        assert_eq!(envelope.tag, restored.tag);
    }

    #[test]
    fn no_tier_roundtrip() {
        let mut envelope = test_envelope();
        envelope.header.tier = None;
        let bytes = serialize(&envelope).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.header.tier, None);
    }

    #[test]
    fn truncated_data_fails() {
        let envelope = test_envelope();
        let bytes = serialize(&envelope).unwrap();
        assert!(deserialize(&bytes[..10]).is_err());
    }

    #[test]
    fn bad_version_fails() {
        let mut envelope = test_envelope();
        envelope.header.version = 99;
        let bytes = serialize(&envelope).unwrap();
        assert!(deserialize(&bytes).is_err());
    }
}
