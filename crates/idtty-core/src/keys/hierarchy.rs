//! Key hierarchy types and operations.
//!
//! D3: KEK derives Session/Sync keys. Root Key wraps Item Keys.
//! Root Key is HPKE-wrapped per device, not KEK-wrapped.
//!
//! R7-3: Key material is heap-allocated (Box) for stable address across moves,
//! mlock'd to prevent paging to swap. Clone manually calls from_bytes
//! to mlock the new copy. Best-effort: failures are silent.

use rand::RngCore;

/// Attempt to mlock a memory region. Best-effort: silent on failure.
#[cfg(unix)]
fn mlock_key(ptr: *const u8, len: usize) {
    let _ = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
}

/// Attempt to munlock a memory region. Best-effort.
#[cfg(unix)]
fn munlock_key(ptr: *const u8, len: usize) {
    let _ = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
}

#[cfg(not(unix))]
fn mlock_key(_ptr: *const u8, _len: usize) {}

#[cfg(not(unix))]
fn munlock_key(_ptr: *const u8, _len: usize) {}

/// Root Key: 512-bit random key, one per vault per epoch.
/// Heap-allocated so mlock address stays valid across moves.
pub struct RootKey(Box<[u8; 64]>);

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey([REDACTED; 64])")
    }
}

impl RootKey {
    /// Generate a new random Root Key. mlock'd to prevent swap.
    pub fn generate() -> Self {
        let mut key = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self::from_bytes(key)
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let s = Self(Box::new(bytes));
        mlock_key(s.0.as_ptr(), s.0.len());
        s
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

impl Clone for RootKey {
    /// Clone mlocks the new copy via from_bytes.
    fn clone(&self) -> Self {
        Self::from_bytes(*self.0)
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        munlock_key(self.0.as_ptr(), self.0.len());
        self.zeroize();
    }
}

/// Item Key: 256-bit per-cipher key.
/// Heap-allocated so mlock address stays valid across moves.
pub struct ItemKey(Box<[u8; 32]>);

impl std::fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemKey([REDACTED; 32])")
    }
}

impl ItemKey {
    /// Generate a new random Item Key. mlock'd to prevent swap.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self::from_bytes(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let s = Self(Box::new(bytes));
        mlock_key(s.0.as_ptr(), s.0.len());
        s
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for ItemKey {
    /// Clone mlocks the new copy via from_bytes.
    fn clone(&self) -> Self {
        Self::from_bytes(*self.0)
    }
}

impl Drop for ItemKey {
    fn drop(&mut self) {
        munlock_key(self.0.as_ptr(), self.0.len());
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}
