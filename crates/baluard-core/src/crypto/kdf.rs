//! Argon2id KDF derivation.
//!
//! D1: Argon2id only. D2: Bounded profile classes with auto-calibration within bands.

use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::error::CryptoError;
use crate::types::{KdfParams, KdfProfile};

/// Derive a 32-byte KEK (Key Encryption Key) from master password.
///
/// D3: KEK is never stored. Exists in memory only for the duration of an unlock operation.
/// Used exclusively as HKDF input for Session Key and Sync-Only Key.
pub fn derive_kek(password: &str, params: &KdfParams) -> Result<[u8; 32], CryptoError> {
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

/// Auto-calibrate Argon2id parameters within a profile's bounds.
///
/// Runs iterative calibration to hit the latency target range.
/// Memory is ramped first (bigger gains), then time_cost is adjusted.
/// Returns a fully populated `KdfParams` including a fresh random salt.
/// Falls back to profile defaults if calibration cannot converge.
pub fn auto_calibrate(profile: KdfProfile) -> KdfParams {
    let salt = generate_salt();
    let (target_lo, target_hi) = profile.latency_range_ms();
    let target_lo = target_lo as u64;
    let target_hi = target_hi as u64;
    let base_mem = profile.memory_kib();
    let base_tc = profile.time_cost();
    let par = profile.parallelism();

    // Benchmark password — not used for real derivation, just calibration timing.
    let bench_pw = "baluard-calibration-benchmark-password";

    let mut mem = base_mem;
    let mut tc = base_tc;

    // Baseline measurement. Fall back to defaults if params are invalid.
    let Some(baseline_ms) = time_derive(bench_pw, &salt, mem, tc, par) else {
        return create_params(profile);
    };

    // Already in range?
    if baseline_ms >= target_lo && baseline_ms <= target_hi {
        return KdfParams {
            profile,
            memory_kib: mem,
            time_cost: tc,
            parallelism: par,
            salt: salt.to_vec(),
        };
    }

    if baseline_ms < target_lo {
        // Too fast: ramp memory (doubling up to 4x), then time_cost (+1 up to 3x).
        let mem_cap = base_mem * 4;
        let tc_cap = base_tc * 3;

        for _ in 0..8 {
            // Adjust first, then measure.
            if mem < mem_cap {
                mem = (mem * 2).min(mem_cap);
            } else if tc < tc_cap {
                tc += 1;
            } else {
                break; // Hit caps.
            }
            let Some(ms) = time_derive(bench_pw, &salt, mem, tc, par) else {
                break; // Invalid params, use current values.
            };
            if ms >= target_lo {
                break; // In range or overshoot (stronger KDF is acceptable).
            }
        }
    } else {
        // Too slow: reduce time_cost first, then memory.
        // M3 fix: clamp mem to absolute OWASP floor (19 MiB) regardless of profile.
        // Prevents calibration from dropping below the security floor for
        // MobileLow (19 MiB base) or any future lower-memory profile.
        const MIN_MEM_KIB: u32 = 19 * 1024;
        let mem_floor = (base_mem / 2).max(MIN_MEM_KIB);
        let mut best_mem = mem;
        let mut best_tc = tc;

        for _ in 0..6 {
            // Reduce first, then measure.
            if tc > 1 {
                tc -= 1;
            } else if mem > mem_floor {
                mem = (mem / 2).max(mem_floor);
            } else {
                break; // Hit floor.
            }
            let Some(ms) = time_derive(bench_pw, &salt, mem, tc, par) else {
                break;
            };
            if ms >= target_lo && ms <= target_hi {
                best_mem = mem;
                best_tc = tc;
                break; // In range.
            }
            if ms >= target_lo {
                best_mem = mem;
                best_tc = tc;
            }
        }
        mem = best_mem;
        tc = best_tc;
    }

    KdfParams {
        profile,
        memory_kib: mem,
        time_cost: tc,
        parallelism: par,
        salt: salt.to_vec(),
    }
}

/// Measure Argon2id derivation latency as the minimum of 3 samples.
/// Uses min (not average) to eliminate OS scheduler preemption outliers.
/// Returns None if params are invalid (e.g. memory too low for parallelism).
fn time_derive(
    pw: &str,
    salt: &[u8; 32],
    mem_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Option<u64> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(mem_kib, time_cost, parallelism, Some(32)).ok()?,
    );
    let mut best_ms = u64::MAX;
    for _ in 0..3 {
        let mut out = [0u8; 32];
        let start = Instant::now();
        argon2
            .hash_password_into(pw.as_bytes(), salt, &mut out)
            .ok()?;
        let ms = start.elapsed().as_millis() as u64;
        best_ms = best_ms.min(ms);
    }
    Some(best_ms)
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
    fn auto_calibrate_produces_valid_params() {
        let params = auto_calibrate(KdfProfile::MobileLow);
        assert_eq!(params.salt.len(), 32);
        assert!(params.memory_kib >= 19 * 1024 / 2, "memory above floor");
        assert!(params.time_cost >= 1, "time_cost at least 1");
        assert_eq!(params.parallelism, 1);
    }

    #[test]
    fn auto_calibrate_unique_salt_per_call() {
        let params = auto_calibrate(KdfProfile::DesktopStd);
        assert!(params.memory_kib > 0);
        assert!(params.time_cost >= 1);
        let params2 = auto_calibrate(KdfProfile::DesktopStd);
        assert_ne!(params.salt, params2.salt);
    }
}
