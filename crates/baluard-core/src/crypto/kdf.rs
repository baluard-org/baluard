//! Argon2id KDF derivation.
//!
//! D1: Argon2id only. D2: Bounded profile classes.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::error::CryptoError;
use crate::types::{KdfKind, KdfParams, KdfProfile};

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

    // Derivation lives inside the match: a new KdfKind variant fails
    // compilation until it has a real implementation, not an empty arm.
    match params.kdf {
        crate::types::KdfKind::Argon2id => {
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
    }
}

/// Parse stored KDF params (kdf-params.json, member-unlock rows, reveal
/// packages) with one shared fail-closed policy: a `kdf` field naming an
/// algorithm this build does not ship is a "newer app" error, not a
/// corrupt-vault or wrong-password error, and never a silent skip.
pub fn parse_kdf_params(json: &str) -> Result<KdfParams, crate::error::BaluardError> {
    use crate::error::{BaluardError, VaultError};
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| BaluardError::Vault(VaultError::Corrupt(format!("kdf params: {e}"))))?;
    if let Some(kind) = v.get("kdf") {
        if kind.as_str() != Some("argon2id") {
            return Err(BaluardError::Vault(VaultError::KdfKindUnknown(
                kind.as_str().unwrap_or("invalid").to_string(),
            )));
        }
    }
    serde_json::from_value(v)
        .map_err(|e| BaluardError::Vault(VaultError::Corrupt(format!("kdf params: {e}"))))
}

/// Hard bounds on stored KDF params. Stored params are attacker-controlled
/// when the git remote is hostile: an unbounded memory_kib aborts the process
/// on allocation the moment the victim types their password. Generous over
/// every shipped profile so legit vaults always derive; hostile params fail
/// closed (mirrors the guest-reveal clamp in vault/reveals.rs). The memory
/// ceiling doubles as the mobile crash guard: an overcommitted allocation
/// dies uncatchable on first touch (ADR 0099).
const KDF_MIN_MEMORY_KIB: u32 = 19 * 1024;
const KDF_MAX_MEMORY_KIB: u32 = 256 * 1024;
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
        kdf: KdfKind::Argon2id,
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
    fn kdf_params_reject_unknown_kind() {
        // A vault header written for an algorithm this build does not know
        // must fail at parse, not derive garbage with the wrong algorithm.
        let json = r#"{"memory_kib":32768,"time_cost":6,"parallelism":4,"salt":"a1b2c3d4","kdf":"scrypt"}"#;
        assert!(serde_json::from_str::<crate::types::KdfParams>(json).is_err());
        // Non-string and wrong-case values are errors too, not coercion.
        let num = r#"{"memory_kib":32768,"time_cost":6,"parallelism":4,"salt":"a1b2c3d4","kdf":2}"#;
        assert!(serde_json::from_str::<crate::types::KdfParams>(num).is_err());
        let cased = r#"{"memory_kib":32768,"time_cost":6,"parallelism":4,"salt":"a1b2c3d4","kdf":"Argon2id"}"#;
        assert!(serde_json::from_str::<crate::types::KdfParams>(cased).is_err());
    }

    #[test]
    fn parse_kdf_params_defaults_absent_and_names_foreign_kind() {
        // Pre-field files parse as argon2id.
        let legacy = r#"{"memory_kib":19456,"time_cost":2,"parallelism":1,"salt":"a1b2c3d4"}"#;
        let params = parse_kdf_params(legacy).unwrap();
        assert_eq!(params.kdf, KdfKind::Argon2id);
        // A foreign kind surfaces as the update-app error, not corrupt.
        let foreign = r#"{"memory_kib":32768,"time_cost":6,"parallelism":4,"salt":"a1b2c3d4","kdf":"scrypt"}"#;
        let err = parse_kdf_params(foreign).unwrap_err();
        assert!(matches!(
            err,
            crate::error::BaluardError::Vault(crate::error::VaultError::KdfKindUnknown(k)) if k == "scrypt"
        ));
    }

    #[test]
    fn kdf_params_stamps_and_roundtrips_kind() {
        let params = create_params(KdfProfile::DesktopStd);
        assert_eq!(params.kdf, crate::types::KdfKind::Argon2id);
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("\"kdf\":\"argon2id\""));
        let back: crate::types::KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kdf, crate::types::KdfKind::Argon2id);
    }

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
            kdf: KdfKind::Argon2id,
            profile: KdfProfile::MobileLow,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            salt: vec![0u8; 16], // too short
        };
        assert!(derive_kek("test", &params).is_err());
    }

    #[test]
    fn mobile_low_profile_shape() {
        // Bitwarden-default shape, chosen over single-lane for unlock latency.
        let params = create_params(KdfProfile::MobileLow);
        assert_eq!(params.memory_kib, 32 * 1024);
        assert_eq!(params.time_cost, 6);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn rejects_memory_below_floor() {
        let params = KdfParams {
            kdf: KdfKind::Argon2id,
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
            kdf: KdfKind::Argon2id,
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
            kdf: KdfKind::Argon2id,
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
            kdf: KdfKind::Argon2id,
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
            kdf: KdfKind::Argon2id,
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
            kdf: KdfKind::Argon2id,
            profile: KdfProfile::DesktopHigh,
            memory_kib: 256 * 1024,
            time_cost: 10,
            parallelism: 8,
            salt: vec![0u8; 32],
        };
        assert!(validate_params(&params).is_ok());
        params.memory_kib += 1;
        assert!(validate_params(&params).is_err());
        params.memory_kib = 256 * 1024;
        params.time_cost = 11;
        assert!(validate_params(&params).is_err());
        params.time_cost = 10;
        params.parallelism = 9;
        assert!(validate_params(&params).is_err());
    }
}
