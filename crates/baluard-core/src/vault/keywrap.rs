//! Keywrap file parsing helpers.
//!
//! Shared between vault handle (unlock, rotation) and creation ceremony (Join mode).

use crate::error::VaultError;

/// Parsed keywrap data: HPKE ephemeral public key, ciphertext, and auth tag.
pub struct KeywrapData {
    pub ephemeral_public: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub tag: [u8; 16],
}

/// Parse a keywrap JSON file into structured data.
///
/// Expected format:
/// ```json
/// {
///   "ephemeral_public": "<hex>",
///   "encrypted_key": "<hex>",
///   "tag": "<hex>"
/// }
/// ```
pub fn parse_keywrap_json(json_str: &str) -> Result<KeywrapData, VaultError> {
    let keywrap: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| VaultError::Corrupt(format!("keywrap json: {e}")))?;

    let eph_pub = hex::decode(keywrap["ephemeral_public"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("ephemeral_public hex: {e}")))?;
    if eph_pub.len() != 32 {
        return Err(VaultError::Corrupt(format!(
            "ephemeral_public: expected 32 bytes, got {}",
            eph_pub.len()
        )));
    }

    let ct = hex::decode(keywrap["encrypted_key"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("encrypted_key hex: {e}")))?;
    if ct.len() < 32 {
        return Err(VaultError::Corrupt(format!(
            "encrypted_key: too short ({} bytes)",
            ct.len()
        )));
    }

    let tag_hex = keywrap["tag"].as_str().unwrap_or("");
    let tag_bytes =
        hex::decode(tag_hex).map_err(|e| VaultError::Corrupt(format!("tag hex: {e}")))?;
    if tag_bytes.len() != 16 {
        return Err(VaultError::Corrupt("invalid tag length".into()));
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    Ok(KeywrapData {
        ephemeral_public: eph_pub,
        encrypted_key: ct,
        tag,
    })
}
