//! Tiered uniform padding.
//!
//! D8: XS:5KB, S:30KB, M:100KB, L:250KB, XL:2MB.

use crate::error::VaultError;
use crate::types::Tier;

/// Apply uniform padding to reach the tier's target size.
///
/// Content is padded with zeros to the tier's padded size.
/// Returns the padded content.
pub fn pad(content: &[u8], tier: Tier) -> Result<Vec<u8>, VaultError> {
    let target = tier.padded_size();
    if content.len() > target {
        return Err(VaultError::Padding(format!(
            "content {} bytes exceeds tier {} capacity {} bytes",
            content.len(),
            tier.code(),
            target
        )));
    }

    let mut padded = Vec::with_capacity(target);
    // Store actual length as first 4 bytes (LE)
    padded.extend_from_slice(&(content.len() as u32).to_le_bytes());
    padded.extend_from_slice(content);
    padded.resize(target, 0u8);
    Ok(padded)
}

/// Remove padding, extracting the original content.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, VaultError> {
    if padded.len() < 4 {
        return Err(VaultError::Padding("padded data too short".into()));
    }

    let len = u32::from_le_bytes(padded[..4].try_into().unwrap()) as usize;
    if len > padded.len() - 4 {
        return Err(VaultError::Padding(format!(
            "declared length {} exceeds available data {}",
            len,
            padded.len() - 4
        )));
    }

    Ok(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let content = b"my secret password";
        let padded = pad(content, Tier::Xs).unwrap();
        assert_eq!(padded.len(), Tier::Xs.padded_size());
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded, content);
    }

    #[test]
    fn pad_preserves_all_bytes() {
        let content = vec![0xAB; 4000];
        let padded = pad(&content, Tier::Xs).unwrap();
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded, content);
    }

    #[test]
    fn content_too_large_fails() {
        let content = vec![0u8; 10 * 1024]; // 10KB > XS tier
        assert!(pad(&content, Tier::Xs).is_err());
    }

    #[test]
    fn tier_fit() {
        use crate::types::Tier;
        assert_eq!(Tier::fit(100), Some(Tier::Xs));
        // Exactly fits = content + 4-byte length prefix == padded size.
        assert_eq!(
            Tier::fit(Tier::Xs.padded_size() - Tier::LENGTH_PREFIX),
            Some(Tier::Xs)
        );
        // One byte over (either content or prefix overflows) spills to S.
        assert_eq!(
            Tier::fit(Tier::Xs.padded_size() - Tier::LENGTH_PREFIX + 1),
            Some(Tier::S)
        );
        assert_eq!(Tier::fit(5 * 1024), Some(Tier::S)); // legacy exact-fit now spills
        assert_eq!(Tier::fit(3 * 1024 * 1024), None); // exceeds XL
    }

    #[test]
    fn pad_content_exactly_tier_minus_prefix_round_trips() {
        // C4 boundary: content of padded_size - 4 must pad + unpad cleanly
        // (the old fit() let content == padded_size truncate silently).
        let n = Tier::Xs.padded_size() - Tier::LENGTH_PREFIX;
        let content = vec![0xCDu8; n];
        let padded = pad(&content, Tier::Xs).unwrap();
        assert_eq!(padded.len(), Tier::Xs.padded_size());
        assert_eq!(unpad(&padded).unwrap(), content);
    }
}
