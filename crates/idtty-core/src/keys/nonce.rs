//! Nonce management.
//!
//! Doc 06 Section 8: per-object counter strategy.
//! nonce = nonce_counter (8 bytes LE) || object_shard_id (4 bytes)
//!
//! Safety: Each cipher gets its own NonceCounter starting at 0. Counter reuse
//! across ciphers is safe because: (1) each cipher uses a unique ItemKey derived
//! from HKDF(RootKey, epoch || cipher_id), and (2) the nonce includes the object
//! shard ID (first 4 bytes of cipher UUID) for namespace separation.
//! Nonce reuse within the same cipher+key is prevented by the monotonic counter.

/// Per-object nonce counter state.
#[derive(Debug, Clone)]
pub struct NonceCounter {
    pub counter: u64,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Increment and return the new counter value.
    pub fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// Reset counter (only valid on key/epoch change).
    pub fn reset(&mut self) {
        self.counter = 0;
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}
