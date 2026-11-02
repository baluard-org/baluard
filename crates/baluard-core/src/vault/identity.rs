//! P1a: per-human identity keypair — stored data, never HKDF-derived.
//!
//! The identity is the crown jewel of the sharing model (0085-sharing.md
//! §4.1): Spaces trust THIS keypair, not any vault. Its sealing key is
//! therefore deliberately independent of the master-password KEK:
//!
//! - **Keystore mode** (default when an OS keystore is available): a random
//!   32-byte wrapping key is stored in the OS keystore and the identity is
//!   sealed under it. Disk theft yields the sealed blob but not the key.
//! - **Passphrase fallback** (keystore-less systems: headless Linux, WSL,
//!   CI): the wrapping key is Argon2id-derived from the master password
//!   with a DEDICATED salt (never the vault KEK). This is a WARNED
//!   downgrade — the wrapping key is offline-derivable by anyone with the
//!   master password.
//!
//! The mode decision is made at creation and recorded in
//! `meta/identity-meta.json`; there is no silent switch between modes.
//!
//! Recovery: the identity is also HPKE-wrapped to the recovery-phrase
//! pubkey (`meta/identity-escrow.json`), so phrase recovery restores it.

use ed25519_dalek::SigningKey;
use x25519_dalek::StaticSecret;

use crate::error::{BaluardError, VaultError};
use crate::secret_file;

/// The per-human identity: Ed25519 for signing (contact cards, status
/// payloads), X25519 for HPKE key wraps. Both derive from one 32-byte seed,
/// so serialization and escrow only ever handle the seed.
pub struct IdentityKeys {
    signing: SigningKey,
    wrapping: StaticSecret,
}

impl IdentityKeys {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Result<Self, BaluardError> {
        use rand::RngCore;
        use zeroize::Zeroize;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let keys = Self::from_seed(&seed);
        seed.zeroize();
        Ok(keys)
    }

    /// Rebuild from a 32-byte seed. The X25519 wrapping secret is derived
    /// from the Ed25519 seed via SHA-512 + RFC 7748 clamping (the standard
    /// Ed25519→X25519 conversion; deterministic, no second secret to
    /// store).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha512};
        use zeroize::Zeroize;
        let signing = SigningKey::from_bytes(seed);
        let mut hash = Sha512::digest(seed);
        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&hash[..32]);
        hash.zeroize();
        x25519_bytes[0] &= 248;
        x25519_bytes[31] &= 127;
        x25519_bytes[31] |= 64;
        let wrapping = StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();
        Self { signing, wrapping }
    }

    pub fn from_seed_bytes(bytes: &[u8]) -> Result<Self, BaluardError> {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VaultError::Corrupt("identity seed wrong length".into()))?;
        Ok(Self::from_seed(&seed))
    }

    /// The 32-byte seed (the only secret state — everything else derives
    /// from it).
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn wrapping_secret(&self) -> &StaticSecret {
        &self.wrapping
    }

    pub fn wrapping_pub_bytes(&self) -> [u8; 32] {
        *x25519_dalek::PublicKey::from(&self.wrapping).as_bytes()
    }
}

/// Seal the identity under `wrap_key` (the keystore-held random key or the
/// warned passphrase-derived fallback — never the vault KEK). The sealed
/// payload is the raw 32-byte seed; everything else derives from it.
pub fn seal_identity(wrap_key: &[u8; 32], keys: &IdentityKeys) -> Result<Vec<u8>, BaluardError> {
    secret_file::seal_secret_blob(wrap_key, &keys.seed(), "identity-v1")
}

/// Open a sealed identity. Fails closed on wrong key or corrupt envelope.
pub fn open_identity(wrap_key: &[u8; 32], sealed: &[u8]) -> Result<IdentityKeys, BaluardError> {
    use zeroize::Zeroize;
    let mut seed = secret_file::open_secret_blob(wrap_key, sealed, "identity-v1")?;
    let keys = IdentityKeys::from_seed_bytes(&seed);
    seed.zeroize();
    keys
}

/// How the identity sealing key is stored. Recorded in
/// `meta/identity-meta.json` at creation; never silently switched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentitySealMode {
    /// Random wrapping key stored in the OS keystore.
    Keystore,
    /// Argon2id(master password, dedicated salt) — WARNED downgrade for
    /// keystore-less systems only.
    Passphrase,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn seal_open_roundtrip_and_wrong_key_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let wrap_key = [0x42u8; 32];

        let sealed = seal_identity(&wrap_key, &keys).unwrap();
        let opened = open_identity(&wrap_key, &sealed).unwrap();
        assert_eq!(
            opened.signing_key().verifying_key().as_bytes(),
            keys.signing_key().verifying_key().as_bytes()
        );

        let wrong = [0x99u8; 32];
        assert!(open_identity(&wrong, &sealed).is_err());
    }

    #[test]
    fn roundtrip_signing_and_distinct() {
        let a = IdentityKeys::generate().unwrap();
        let b = IdentityKeys::generate().unwrap();
        assert_ne!(a.wrapping_pub_bytes(), b.wrapping_pub_bytes());

        let msg = b"identity test";
        let sig = a.signing_key().sign(msg);
        assert!(a.signing_key().verify_strict(msg, &sig).is_ok());
    }
}
