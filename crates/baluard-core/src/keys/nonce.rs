//! Nonce management.
//!
//! Doc 06 Section 8: per-object counter strategy (LEGACY).
//!
//! **C1 fix:** New cipher writes use `aead::build_random_nonce()` (96-bit random)
//! instead of the deterministic counter+shard scheme below. Random nonces prevent
//! AES-GCM nonce reuse when multiple devices edit the same cipher concurrently.
//!
//! The `NonceCounter` type is retained for backward compat with existing envelopes
//! and for internal bookkeeping. The actual AES-GCM nonce is stored in the envelope's
//! `nonce` field and is now always random.
//!
//! Old envelopes with counter-based nonces continue to decrypt correctly because
//! the decrypt path reads the stored nonce bytes directly from the envelope.

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
    pub fn advance(&mut self) -> u64 {
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
