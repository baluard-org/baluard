//! AEAD envelope binary serialization.
//!
//! D3: {version: u8, alg_id: u16, key_epoch: u64, update_seq: u64, tier: u8, nonce: [u8;12], aad_len: u16, aad, tag: [u8;16], ciphertext}
//! All fields little-endian. Header fields are plaintext for key selection
//! before decryption (no circular dependency).

use crate::error::VaultError;
use crate::types::{CipherEnvelope, EnvelopeHeader};

// Binary envelope layout:
//   [0]      version: u8
//   [1..3]   alg_id: u16 LE
//   [3..11]  key_epoch: u64 LE
//   [11..19] update_seq: u64 LE
//   [19]     tier: u8 (0=none, 1=xs, 2=s, 3=m, 4=l, 5=xl)
//   [20..32] nonce: [u8; 12]
//   [32..34] aad_len: u16 LE
//   [34..34+aad_len]  aad
//   [34+aad_len..34+aad_len+16]  tag: [u8; 16]
//   [rest]   ciphertext

// Header: version(1) + alg_id(2) + key_epoch(8) + update_seq(8) + tier(1)
// = 20 bytes.
const HEADER_SIZE: usize = 20;

/// Version policy for every persisted envelope: flag day, current version
/// only. This single fn is the decision point for the next bump — at that
/// point decide deliberately whether outstanding secret blobs (reveals,
/// share packages, synced collection wraps: no rewrap path) may keep
/// reading under the old version, and widen this check if so.
fn accepts_version(v: u8) -> bool {
    v == crate::BALUARD_VERSION
}
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
    if !accepts_version(version) {
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
    fn layout_pin_header_20_bytes_fixed_offsets() {
        // Frozen wire format: a deliberate version bump must update this
        // literal consciously, not ride the constant.
        assert_eq!(BALUARD_VERSION, 2);
        let envelope = test_envelope();
        let bytes = serialize(&envelope).unwrap();
        // 20 header + 12 nonce + 2 aad_len + 4 aad + 16 tag + 100 ciphertext
        assert_eq!(bytes.len(), 154);
        assert_eq!(bytes[0], BALUARD_VERSION);
        assert_eq!(&bytes[1..3], &ALG_AES_256_GCM.to_le_bytes());
        assert_eq!(&bytes[3..11], &1u64.to_le_bytes(), "key_epoch");
        assert_eq!(&bytes[11..19], &5u64.to_le_bytes(), "update_seq");
        assert_eq!(bytes[19], 1, "tier: Xs");
        assert_eq!(&bytes[20..32], &[42u8; 12], "nonce");
        assert_eq!(&bytes[32..34], &4u16.to_le_bytes(), "aad_len");
        assert_eq!(&bytes[34..38], &[1, 2, 3, 4], "aad");
        assert_eq!(&bytes[38..54], &[0xCD; 16], "tag before ciphertext");
        assert_eq!(&bytes[54..], &vec![0xAB; 100], "ciphertext is the rest");
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
