//! Baluard core library.
//!
//! Git-native password manager. Crypto, vault format, sync, key lifecycle.
//! See docs/01-architecture-decisions.md for full design rationale.

pub mod biometric;
pub mod crypto;
pub mod device_manager;
pub mod devices;
pub mod emergency;
pub mod health;
pub mod import;
pub mod integrity;
pub mod keys;
pub mod orgs;
pub mod paths;
pub mod providers;
pub mod recovery;
pub mod sync;
pub mod vault;

pub mod error;
pub mod types;

pub use error::BaluardError;

/// Library version, embedded in vault format headers.
pub const BALUARD_VERSION: u8 = 1;

/// Current AEAD algorithm identifier: AES-256-GCM.
pub const ALG_AES_256_GCM: u16 = 0x0001;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn mobile_version() -> u32 {
    BALUARD_VERSION as u32
}

#[uniffi::export]
pub fn mobile_generate_mnemonic() -> Result<String, String> {
    match crate::recovery::RecoveryPhrase::generate() {
        Ok(phrase) => Ok(phrase.phrase()),
        Err(e) => Err(e.to_string()),
    }
}

#[uniffi::export]
pub fn mobile_derive_key(password: String, salt: String) -> Result<Vec<u8>, String> {
    let salt_bytes = salt.as_bytes();
    let mut salt_32 = vec![0u8; 32];
    if salt_bytes.len() == 32 {
        salt_32.copy_from_slice(salt_bytes);
    } else {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(salt_bytes);
        salt_32.copy_from_slice(&hasher.finalize());
    }

    let params = crate::types::KdfParams {
        profile: crate::types::KdfProfile::MobileLow,
        memory_kib: crate::types::KdfProfile::MobileLow.memory_kib(),
        time_cost: crate::types::KdfProfile::MobileLow.time_cost(),
        parallelism: crate::types::KdfProfile::MobileLow.parallelism(),
        salt: salt_32,
    };

    match crate::crypto::kdf::derive_kek(&password, &params) {
        Ok(key) => Ok(key.to_vec()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniffi_wrappers() {
        assert_eq!(mobile_version(), 1);
        let phrase = mobile_generate_mnemonic().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        let key = mobile_derive_key("password123".to_string(), "salt123".to_string()).unwrap();
        assert_eq!(key.len(), 32);
    }
}
