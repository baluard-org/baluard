//! BIP-39 recovery key: 24-word mnemonic wrapping Root Key.
//!
//! D3 (revised): Master-password-independent vault recovery path.

use bip39::Mnemonic;

use crate::error::CryptoError;

/// A 24-word BIP-39 recovery phrase.
pub struct RecoveryPhrase {
    mnemonic: Mnemonic,
}

impl RecoveryPhrase {
    /// Generate a new random 24-word recovery phrase.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = [0u8; 32]; // 256 bits = 24 words
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| CryptoError::Bip39(e.to_string()))?;
        Ok(Self { mnemonic })
    }

    /// Parse a recovery phrase from a space-separated word string.
    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::parse_normalized(phrase)
            .map_err(|e| CryptoError::Bip39(e.to_string()))?;
        Ok(Self { mnemonic })
    }

    /// Get the 24-word phrase as a string.
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Derive the 512-bit recovery key from the mnemonic.
    pub fn derive_key(&self) -> [u8; 64] {
        // BIP-39 seed with empty passphrase
        let seed = self.mnemonic.to_seed("");
        let mut key = [0u8; 64];
        key.copy_from_slice(&seed[..64]);
        key
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        // The bip39::Mnemonic stores entropy internally.
        // We cannot directly zeroize it (opaque type), but the
        // derived key [u8; 64] is stack-allocated and zeroed by the caller.
        // For defense-in-depth, clear any cached state.
        // Note: Mnemonic's internal String will be dropped normally.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_recovery_phrase() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let binding = phrase.phrase();
        let words: Vec<&str> = binding.split(' ').collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn roundtrip_phrase() {
        let original = RecoveryPhrase::generate().unwrap();
        let phrase_str = original.phrase();
        let restored = RecoveryPhrase::from_phrase(&phrase_str).unwrap();
        assert_eq!(original.derive_key(), restored.derive_key());
    }

    #[test]
    fn invalid_phrase_fails() {
        assert!(RecoveryPhrase::from_phrase("not a valid phrase").is_err());
    }
}
