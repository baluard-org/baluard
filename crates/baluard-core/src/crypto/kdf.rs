//! Argon2id KDF derivation.
//!
//! D1: Argon2id only. D2: Bounded profile classes.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::error::CryptoError;
use crate::types::{KdfParams, KdfProfile};

/// Derive a 32-byte KEK (Key Encryption Key) from master password.
///
/// D3: KEK is never stored. Exists in memory only for the duration of an unlock operation.
/// Used exclusively as HKDF input for Session Key and Sync-Only Key.
pub fn derive_kek(password: &str, params: &KdfParams) -> Result<[u8; 32], CryptoError> {
    validate_params(params)?;

    if params.salt.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: params.salt.len(),
        });
    }

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.time_cost,
            params.parallelism,
            Some(32),
        )
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?,
    );

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &params.salt, &mut kek)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;

    Ok(kek)
}

/// Hard bounds on stored KDF params. Stored params are attacker-controlled
/// when the git remote is hostile: an unbounded memory_kib aborts the process
/// on allocation the moment the victim types their password. Generous over
/// every shipped profile so legit vaults always derive; hostile params fail
/// closed (mirrors the guest-reveal clamp in vault/reveals.rs).
const KDF_MIN_MEMORY_KIB: u32 = 19 * 1024;
const KDF_MAX_MEMORY_KIB: u32 = 512 * 1024;
const KDF_MAX_TIME_COST: u32 = 10;
const KDF_MAX_PARALLELISM: u32 = 8;

fn validate_params(params: &KdfParams) -> Result<(), CryptoError> {
    if params.memory_kib < KDF_MIN_MEMORY_KIB {
        return Err(CryptoError::KdfParamsInvalid(format!(
            "memory_kib {} below floor {KDF_MIN_MEMORY_KIB}",
            params.memory_kib
        )));
    }
    if params.memory_kib > KDF_MAX_MEMORY_KIB {
        return Err(CryptoError::KdfParamsInvalid(format!(
            "memory_kib {} above ceiling {KDF_MAX_MEMORY_KIB}",
            params.memory_kib
        )));
    }
    if params.time_cost < 1 || params.time_cost > KDF_MAX_TIME_COST {
        return Err(CryptoError::KdfParamsInvalid(format!(
            "time_cost {} outside 1..={KDF_MAX_TIME_COST}",
            params.time_cost
        )));
    }
    if params.parallelism < 1 || params.parallelism > KDF_MAX_PARALLELISM {
        return Err(CryptoError::KdfParamsInvalid(format!(
            "parallelism {} outside 1..={KDF_MAX_PARALLELISM}",
            params.parallelism
        )));
    }
    Ok(())
}

/// Generate a new random 256-bit salt for vault creation.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Create KDF params with a fresh salt for a given profile.
pub fn create_params(profile: KdfProfile) -> KdfParams {
    let salt = generate_salt();
    KdfParams {
        memory_kib: profile.memory_kib(),
        time_cost: profile.time_cost(),
        parallelism: profile.parallelism(),
        profile,
        salt: salt.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_kek_roundtrip() {
        let params = create_params(KdfProfile::MobileLow);
        let kek1 = derive_kek("correct-horse-battery-staple", &params).unwrap();
        let kek2 = derive_kek("correct-horse-battery-staple", &params).unwrap();
        assert_eq!(kek1, kek2, "same password + params must produce same KEK");
    }

    #[test]
    fn different_password_different_kek() {
        let params = create_params(KdfProfile::MobileLow);
        let kek1 = derive_kek("password-1", &params).unwrap();
        let kek2 = derive_kek("password-2", &params).unwrap();
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn different_salt_different_kek() {
        let p1 = create_params(KdfProfile::MobileLow);
        let p2 = create_params(KdfProfile::MobileLow);
        let kek1 = derive_kek("same-password", &p1).unwrap();
        let kek2 = derive_kek("same-password", &p2).unwrap();
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn rejects_invalid_salt() {
        let params = KdfParams {
            profile: KdfProfile::MobileLow,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            salt: vec![0u8; 16], // too short
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn rejects_memory_below_floor() {
        let params = KdfParams {
            profile: KdfProfile::MobileLow,
            memory_kib: 1024,
            time_cost: 2,
            parallelism: 1,
            salt: vec![0u8; 32],
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn rejects_memory_above_ceiling() {
        let params = KdfParams {
            profile: KdfProfile::DesktopHigh,
            memory_kib: 600 * 1024,
            time_cost: 4,
            parallelism: 4,
            salt: vec![0u8; 32],
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn rejects_extreme_time_cost() {
        let params = KdfParams {
            profile: KdfProfile::MobileLow,
            memory_kib: 19 * 1024,
            time_cost: 99,
            parallelism: 1,
            salt: vec![0u8; 32],
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn rejects_extreme_parallelism() {
        let params = KdfParams {
            profile: KdfProfile::MobileLow,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 99,
            salt: vec![0u8; 32],
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn accepts_floor_boundary_params() {
        let params = KdfParams {
            profile: KdfProfile::MobileLow,
            memory_kib: 19 * 1024,
            time_cost: 1,
            parallelism: 1,
            salt: vec![7u8; 32],
        };
        assert!(derive_kek("test", &params).is_ok());
    }

    #[test]
    fn validate_params_ceiling_boundaries() {
        let mut params = KdfParams {
            profile: KdfProfile::DesktopHigh,
            memory_kib: 512 * 1024,
            time_cost: 10,
            parallelism: 8,
            salt: vec![0u8; 32],
        };
        assert!(validate_params(&params).is_ok());
        params.memory_kib += 1;
        assert!(validate_params(&params).is_err());
        params.memory_kib = 512 * 1024;
        params.time_cost = 11;
        assert!(validate_params(&params).is_err());
        params.time_cost = 10;
        params.parallelism = 9;
        assert!(validate_params(&params).is_err());
    }
}
