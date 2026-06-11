//! Key hierarchy types and operations.
//!
//! D3: KEK derives Session/Sync keys. Root Key → Space Group Key → Item Keys.
//! Root Key is HPKE-wrapped per device, not KEK-wrapped.
//!
//! DESIGN-3: Space Group Key sits between RootKey and ItemKey.
//! Single-user: derived deterministically from RootKey via HKDF.
//! Multi-user/org: random 256-bit key, HPKE-wrapped per member in access_list.json.
//!
//! R7-3: Key material is heap-allocated (Box) for stable address across moves,
//! mlock'd to prevent paging to swap. Clone manually calls from_bytes
//! to mlock the new copy. Best-effort: failures are silent.
//!
//! SECURITY: All zeroization uses `zeroize::Zeroize` (volatile writes) to prevent
//! compiler elimination of dead stores. Manual loops (`for b in iter_mut()`)
//! are NOT safe in release builds.

use rand::RngCore;
use zeroize::Zeroize;

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
}

impl Zeroize for RootKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
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

impl Zeroize for ItemKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
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
        self.zeroize();
    }
}

/// Space Group Key: 256-bit per-space key.
///
/// DESIGN-3: Intermediate layer between RootKey and ItemKey.
/// - Single-user: derived deterministically via `HKDF(RootKey, "baluard-sgk-v1" || epoch)`.
/// - Multi-user/org: random 256-bit key, HPKE-wrapped per member in `access_list.json`.
///
/// Carries its bound epoch to prevent misuse (passing wrong epoch to derive_item_key).
/// Heap-allocated so mlock address stays valid across moves.
pub struct SpaceGroupKey {
    key: Box<[u8; 32]>,
    /// Epoch this SGK was derived for. Used to validate derive_item_key calls.
    epoch: u64,
}

impl std::fmt::Debug for SpaceGroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpaceGroupKey([REDACTED; 32])")
    }
}

impl SpaceGroupKey {
    /// Generate a new random Space Group Key. mlock'd to prevent swap.
    /// For multi-user/org scenarios where the SGK is not derived from RootKey.
    pub fn generate(epoch: u64) -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let s = Self {
            key: Box::new(key),
            epoch,
        };
        mlock_key(s.key.as_ptr(), s.key.len());
        s
    }

    /// Derive a Space Group Key deterministically from the Root Key.
    /// Used for single-user vaults where no sharing is needed.
    pub fn derive_from_root_key(root_key: &RootKey, epoch: u64) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // "baluard-sgk-v1" (12 bytes) + epoch (8 bytes) = 20 bytes
        let mut info = Vec::with_capacity(20);
        info.extend_from_slice(b"baluard-sgk-v1");
        info.extend_from_slice(&epoch.to_le_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .expect("32 bytes is valid output length for HKDF-SHA256");

        let s = Self {
            key: Box::new(key),
            epoch,
        };
        mlock_key(s.key.as_ptr(), s.key.len());
        s
    }

    pub fn from_bytes(bytes: [u8; 32], epoch: u64) -> Self {
        let s = Self {
            key: Box::new(bytes),
            epoch,
        };
        mlock_key(s.key.as_ptr(), s.key.len());
        s
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// The epoch this SGK was derived for.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Derive an Item Key from this Space Group Key.
    /// Epoch must match the SGK's bound epoch (panics on mismatch in debug builds).
    pub fn derive_item_key(&self, cipher_id: uuid::Uuid, epoch: u64) -> ItemKey {
        debug_assert_eq!(
            epoch, self.epoch,
            "SpaceGroupKey epoch mismatch: SGK bound to epoch {} but derive_item_key called with epoch {}",
            self.epoch, epoch
        );

        use hkdf::Hkdf;
        use sha2::Sha256;

        // "baluard-item-v1" (13 bytes) + epoch (8 bytes) + UUID (16 bytes) = 37 bytes
        let mut info = Vec::with_capacity(37);
        info.extend_from_slice(b"baluard-item-v1");
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(cipher_id.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, self.key.as_slice());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .expect("32 bytes is valid output length for HKDF-SHA256");

        ItemKey::from_bytes(key)
    }

    /// M1 fix: Derive a dedicated key for encrypting the user avatar.
    /// Domain-separated from item keys so a leak of one cannot decrypt the other.
    /// Epoch-bound so avatar is re-wrapped on root key rotation.
    pub fn derive_avatar_key(&self, epoch: u64) -> [u8; 32] {
        debug_assert_eq!(
            epoch, self.epoch,
            "SpaceGroupKey epoch mismatch: SGK bound to epoch {} but derive_avatar_key called with epoch {}",
            self.epoch, epoch
        );

        use hkdf::Hkdf;
        use sha2::Sha256;

        // "baluard-avatar-v1" (17 bytes) + epoch (8 bytes) = 25 bytes
        let mut info = Vec::with_capacity(25);
        info.extend_from_slice(b"baluard-avatar-v1");
        info.extend_from_slice(&epoch.to_le_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, self.key.as_slice());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .expect("32 bytes is valid output length for HKDF-SHA256");

        key
    }
}

impl Zeroize for SpaceGroupKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Clone for SpaceGroupKey {
    fn clone(&self) -> Self {
        let s = Self {
            key: Box::new(*self.key),
            epoch: self.epoch,
        };
        mlock_key(s.key.as_ptr(), s.key.len());
        s
    }
}

impl Drop for SpaceGroupKey {
    fn drop(&mut self) {
        munlock_key(self.key.as_ptr(), self.key.len());
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgk_derive_from_root_key_deterministic() {
        let rk = RootKey::generate();
        let sgk1 = SpaceGroupKey::derive_from_root_key(&rk, 1);
        let sgk2 = SpaceGroupKey::derive_from_root_key(&rk, 1);
        assert_eq!(sgk1.as_bytes(), sgk2.as_bytes());
    }

    #[test]
    fn sgk_epoch_isolation() {
        let rk = RootKey::generate();
        let sgk1 = SpaceGroupKey::derive_from_root_key(&rk, 1);
        let sgk2 = SpaceGroupKey::derive_from_root_key(&rk, 2);
        assert_ne!(sgk1.as_bytes(), sgk2.as_bytes());
    }

    #[test]
    fn sgk_root_key_isolation() {
        let rk1 = RootKey::generate();
        let rk2 = RootKey::generate();
        let sgk1 = SpaceGroupKey::derive_from_root_key(&rk1, 1);
        let sgk2 = SpaceGroupKey::derive_from_root_key(&rk2, 1);
        assert_ne!(sgk1.as_bytes(), sgk2.as_bytes());
    }

    #[test]
    fn sgk_derive_item_key_deterministic() {
        let rk = RootKey::generate();
        let sgk = SpaceGroupKey::derive_from_root_key(&rk, 1);
        let id = uuid::Uuid::new_v4();
        let ik1 = sgk.derive_item_key(id, 1);
        let ik2 = sgk.derive_item_key(id, 1);
        assert_eq!(ik1.as_bytes(), ik2.as_bytes());
    }

    #[test]
    fn sgk_item_key_per_cipher_unique() {
        let rk = RootKey::generate();
        let sgk = SpaceGroupKey::derive_from_root_key(&rk, 1);
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let ik1 = sgk.derive_item_key(id1, 1);
        let ik2 = sgk.derive_item_key(id2, 1);
        assert_ne!(ik1.as_bytes(), ik2.as_bytes());
    }

    #[test]
    fn sgk_generate_random() {
        let sgk1 = SpaceGroupKey::generate(1);
        let sgk2 = SpaceGroupKey::generate(1);
        assert_ne!(sgk1.as_bytes(), sgk2.as_bytes());
    }

    #[test]
    fn sgk_full_chain_root_to_item() {
        let rk = RootKey::generate();
        let id = uuid::Uuid::new_v4();
        let epoch = 1u64;

        let sgk = SpaceGroupKey::derive_from_root_key(&rk, epoch);
        let ik = sgk.derive_item_key(id, epoch);
        assert_eq!(ik.as_bytes().len(), 32);

        // Same inputs -> same key (deterministic)
        let sgk2 = SpaceGroupKey::derive_from_root_key(&rk, epoch);
        let ik2 = sgk2.derive_item_key(id, epoch);
        assert_eq!(ik.as_bytes(), ik2.as_bytes());
    }

    #[test]
    fn sgk_carries_epoch() {
        let rk = RootKey::generate();
        let sgk = SpaceGroupKey::derive_from_root_key(&rk, 42);
        assert_eq!(sgk.epoch(), 42);
    }
}
