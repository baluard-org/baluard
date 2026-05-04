//! Key hierarchy types and operations.
//!
//! D3: KEK derives Session/Sync keys. Root Key wraps Item Keys.
//! Root Key is HPKE-wrapped per device, not KEK-wrapped.

use rand::RngCore;

/// Root Key: 512-bit random key, one per vault per epoch.
#[derive(Debug, Clone)]
pub struct RootKey([u8; 64]);

impl RootKey {
    /// Generate a new random Root Key.
    pub fn generate() -> Self {
        let mut key = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Zeroize the key from memory.
    pub fn zeroize(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Item Key: 256-bit per-cipher key.
#[derive(Debug, Clone)]
pub struct ItemKey([u8; 32]);

impl ItemKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
