//! Keywrap file parsing helpers.
//!
//! Shared between vault handle (unlock, rotation) and creation ceremony (Join mode).

use crate::error::VaultError;

/// Parsed keywrap data: HPKE ephemeral public key, ciphertext, and auth tag.
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid keywrap JSON blob with deterministic hex fields.
    fn sample_json() -> String {
        serde_json::json!({
            "ephemeral_public": hex::encode([0xAAu8; 32]),
            "encrypted_key": hex::encode([0xBBu8; 64]),
            "tag": hex::encode([0xCCu8; 16]),
        })
        .to_string()
    }

    #[test]
    fn parse_valid_keywrap() {
        let data = parse_keywrap_json(&sample_json()).expect("valid");
        assert_eq!(data.ephemeral_public, vec![0xAA; 32]);
        assert_eq!(data.encrypted_key.len(), 64);
        assert_eq!(data.tag, [0xCC; 16]);
    }

    #[test]
    fn parse_rejects_short_ephemeral_public() {
        let json = serde_json::json!({
            "ephemeral_public": hex::encode([0xAA; 16]), // too short
            "encrypted_key": hex::encode([0xBB; 64]),
            "tag": hex::encode([0xCC; 16]),
        })
        .to_string();
        let err = parse_keywrap_json(&json).unwrap_err();
        assert!(
            err.to_string().contains("ephemeral_public"),
            "expected ephemeral_public error: {err}"
        );
    }

    #[test]
    fn parse_rejects_short_encrypted_key() {
        let json = serde_json::json!({
            "ephemeral_public": hex::encode([0xAA; 32]),
            "encrypted_key": hex::encode([0xBB; 8]), // too short (<32)
            "tag": hex::encode([0xCC; 16]),
        })
        .to_string();
        let err = parse_keywrap_json(&json).unwrap_err();
        assert!(
            err.to_string().contains("encrypted_key"),
            "expected encrypted_key error: {err}"
        );
    }

    #[test]
    fn parse_rejects_bad_tag_length() {
        let json = serde_json::json!({
            "ephemeral_public": hex::encode([0xAA; 32]),
            "encrypted_key": hex::encode([0xBB; 64]),
            "tag": hex::encode([0xCC; 8]), // too short
        })
        .to_string();
        let err = parse_keywrap_json(&json).unwrap_err();
        assert!(err.to_string().contains("tag"), "expected tag error: {err}");
    }

    #[test]
    fn parse_rejects_invalid_hex() {
        let json = serde_json::json!({
            "ephemeral_public": "not-valid-hex",
            "encrypted_key": hex::encode([0xBB; 64]),
            "tag": hex::encode([0xCC; 16]),
        })
        .to_string();
        let err = parse_keywrap_json(&json).unwrap_err();
        assert!(err.to_string().contains("hex"), "expected hex error: {err}");
    }

    #[test]
    fn parse_rejects_malformed_json() {
        let err = parse_keywrap_json("{not json").unwrap_err();
        assert!(
            err.to_string().contains("keywrap json"),
            "expected json error: {err}"
        );
    }
}
