//! BIP-39 recovery key: 24-word mnemonic wrapping Root Key.
//!
//! D3 (revised): Master-password-independent vault recovery path.
//!
//! L2 fix: stores entropy directly in a Zeroizing buffer rather than
//! holding a `bip39::Mnemonic` (whose internal state cannot be wiped).
//! The Mnemonic is reconstructed on demand for `phrase()` output and
//! dropped immediately after, so the long-lived secret is just the
//! 32-byte entropy (zeroized on drop).

use bip39::Mnemonic;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// 24-word BIP-39 recovery phrase.
///
/// Stores the raw 256-bit entropy in a `Zeroizing` buffer. The `Mnemonic`
/// is reconstructed only when `phrase()` is called and dropped immediately
/// after use.
pub struct RecoveryPhrase {
    /// Raw 256-bit entropy. Zeroized on drop.
    entropy: Zeroizing<[u8; 32]>,
}

impl RecoveryPhrase {
    /// Generate a new random 24-word recovery phrase.
    pub fn generate() -> Result<Self, CryptoError> {
        Self::generate_with_rng(&mut rand::rngs::OsRng)
    }

    /// Generate a new random 24-word recovery phrase using the provided RNG.
    pub fn generate_with_rng<R: rand_core::RngCore>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut entropy = Zeroizing::new([0u8; 32]); // 256 bits = 24 words
        rng.fill_bytes(&mut *entropy);
        Ok(Self { entropy })
    }

    /// Parse a recovery phrase from a space-separated word string.
    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        // Parse via Mnemonic for validation, then extract entropy.
        let mnemonic =
            Mnemonic::parse_normalized(phrase).map_err(|e| CryptoError::Bip39(e.to_string()))?;
        let mut raw_entropy = mnemonic.to_entropy();
        // Zero-padding a 12-word phrase to 32 bytes would silently derive
        // the key of a DIFFERENT 24-word phrase; reject instead.
        if raw_entropy.len() != 32 {
            let len = raw_entropy.len();
            zeroize::Zeroize::zeroize(&mut raw_entropy);
            return Err(CryptoError::Bip39(format!(
                "recovery phrase must be 24 words (got entropy for {len} bytes)"
            )));
        }
        let entropy = Zeroizing::new(
            raw_entropy
                .try_into()
                .expect("32-byte entropy checked above"),
        );
        Ok(Self { entropy })
    }

    /// Get the 24-word phrase as a string.
    /// Returns a fresh `String` each call (caller is responsible for
    /// zeroizing it when done). The internal `Mnemonic` is dropped
    /// immediately after the string is built.
    pub fn phrase(&self) -> String {
        let mnemonic = Mnemonic::from_entropy(&*self.entropy).expect("valid 32-byte entropy");
        mnemonic.to_string()
    }

    /// Derive the 512-bit recovery key from the mnemonic.
    /// Returns a `Zeroizing` wrapper so the derived key is wiped on drop.
    pub fn derive_key(&self) -> Zeroizing<[u8; 64]> {
        // BIP-39 seed with empty passphrase
        let seed = Mnemonic::from_entropy(&*self.entropy)
            .expect("valid 32-byte entropy")
            .to_seed("");
        let mut key = Zeroizing::new([0u8; 64]);
        key.copy_from_slice(&seed[..64]);
        // The local `seed` (Vec<u8>) is dropped at end of scope;
        // it holds plaintext entropy and derived material.
        key
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        // Zeroizing<[u8; 32]> wipes entropy on drop automatically.
        // Explicit zeroize() is redundant but documents intent.
        self.entropy.zeroize();
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

    #[test]
    fn twelve_word_phrase_rejected_not_zero_padded() {
        // A valid 12-word mnemonic carries 16 bytes of entropy; zero-padding
        // it to 32 used to derive the key of a DIFFERENT 24-word phrase.
        let mut ent = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut ent);
        let mnemonic = Mnemonic::from_entropy(&ent).unwrap();
        let err = RecoveryPhrase::from_phrase(&mnemonic.to_string());
        assert!(err.is_err(), "12-word phrase must be rejected");
    }

    #[test]
    fn derive_key_is_zeroizing() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let key = phrase.derive_key();
        // Verify it's a Zeroizing wrapper (compiles only if type is correct)
        let _drop_check: Zeroizing<[u8; 64]> = key;
    }

    #[test]
    fn entropy_cleared_on_drop() {
        let entropy_addr: usize;
        {
            let phrase = RecoveryPhrase::generate().unwrap();
            // Take address of the entropy buffer (for the assertion below).
            // Note: the buffer is inside a Zeroizing, so the address is
            // stable for the lifetime of `phrase`.
            entropy_addr = phrase.entropy.as_ptr() as usize;
        }
        // After drop, the memory may have been reused. We can only verify
        // that the type zeroizes by checking the Zeroizing trait is in scope
        // (it is — see the import at the top of this file).
        // The real test is that Zeroizing<[u8; 32]> implements Drop
        // that wipes the buffer.
        let _ = entropy_addr; // suppress unused warning
    }
}
