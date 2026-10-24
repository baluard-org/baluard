//! Session-bound PIN Quick Unlock escrow.
//!
//! Stores a vault's KEK in **process memory only** so that, after the first
//! master-password unlock, the user can re-unlock the vault with a 6-digit
//! PIN for the remainder of the daemon session. This is the software-only
//! Quick Unlock path (Linux, and Windows machines without Windows Hello);
//! macOS uses Touch-ID-gated keychain storage instead.
//!
//! Security model (mirrors Bitwarden's ephemeral PIN):
//! - **Nothing PIN-derivable touches disk.** The KEK and the PIN verifier
//!   live only in this struct, which is zeroized on drop.
//! - **The KEK is Argon2id-derived** (not the master password); retaining it
//!   lets PIN unlock skip the expensive KDF while still re-verifying the
//!   keywrap + canaries via `VaultHandle::unlock_with_kek`.
//! - **Online-only brute-force protection.** Because nothing is on disk,
//!   the only attack surface is in-process guessing; the per-vault failure
//!   counter caps that at `MAX_PIN_FAILURES` before the escrow is nuked and
//!   the master password becomes mandatory again. There is no offline path.
//! - **Session-bound.** The escrow dies on daemon restart, vault close, or
//!   explicit disable. It survives soft-lock / auto-lock (it is a separate
//!   field from the handle), so the PIN keeps working after the vault
//!   auto-locks — matching the UX of macOS Quick Unlock within a session.
//!
//! The PIN verifier is an Argon2id hash of the PIN with a per-escrow random
//! salt. Argon2id is defense-in-depth here: the real protection is the
//! in-process attempt cap, because the keyspace (10^6) is tiny. But hashing
//! avoids keeping the raw PIN in memory and resists a RAM-dump adversary
//! that does not also have the ability to replay guesses through the daemon.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// Maximum wrong-PIN attempts before the escrow is destroyed and the master
/// password becomes required again. Bitwarden-equivalent policy (their
/// `MAX_INVALID_PIN_ENTRY_ATTEMPTS = 5`). At 10^6 the keyspace cannot be
/// brute-forced through this cap, and destroying the escrow removes the
/// target entirely — the attacker must then defeat Argon2id on the master
/// password, which they cannot do offline via this path.
pub const MAX_PIN_FAILURES: u32 = 5;

/// Sentinel returned by `PinEscrow::verify_or_record_failure` when the
/// failure cap is reached. The caller MUST destroy the escrow (`*guard = None`)
/// when it sees this, then surface the terminal message to the user. Using a
/// sentinel (rather than a richer return type) keeps the happy path a plain
/// `Result<KEK, _>` and avoids allocating on the common wrong-PIN path.
pub const PIN_NUKED_SENTINEL: &str = "__PIN_NUKED__";

/// Argon2id parameters for the PIN verifier. These are intentionally lighter
/// than the master-password KDF (the PIN is only 6 digits; the protection is
/// the attempt cap, not the KDF cost). Memory-hardness still makes a RAM-dump
/// precompute impractical.
const PIN_ARGON2_MEM_KIB: u32 = 19 * 1024; // 19 MB
const PIN_ARGON2_TIME_COST: u32 = 2;
const PIN_ARGON2_PARALLELISM: u32 = 1;
const PIN_HASH_LEN: usize = 32;
const PIN_SALT_LEN: usize = 16;

/// In-memory escrow enabling PIN re-unlock for one vault, one session.
///
/// Held behind a `Mutex` on `VaultState`. All fields are zeroized on drop.
pub struct PinEscrow {
    /// Argon2id verifier over the user's PIN. Compared in constant time.
    pin_hash: zeroize::Zeroizing<[u8; PIN_HASH_LEN]>,
    /// Per-escrow random salt (so two enable events with the same PIN differ).
    pin_salt: [u8; PIN_SALT_LEN],
    /// The vault's KEK (Argon2id-derived from the master password). Retained
    /// so PIN unlock skips the master KDF. Zeroized on drop.
    kek: zeroize::Zeroizing<[u8; 32]>,
}

impl Drop for PinEscrow {
    fn drop(&mut self) {
        self.pin_hash.zeroize();
        self.pin_salt.zeroize();
        self.kek.zeroize();
    }
}

impl PinEscrow {
    /// Create a new escrow from a verified master password + the user's PIN.
    /// `kek` is the Argon2id-derived KEK for this vault. The PIN is hashed
    /// with a fresh random salt; neither the raw PIN nor the master password
    /// is retained.
    pub fn new(kek: [u8; 32], pin: &str) -> Result<Self, String> {
        validate_pin(pin)?;
        let mut pin_salt = [0u8; PIN_SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut pin_salt);
        let pin_hash = hash_pin(pin, &pin_salt)?;
        Ok(Self {
            pin_hash: zeroize::Zeroizing::new(pin_hash),
            pin_salt,
            kek: zeroize::Zeroizing::new(kek),
        })
    }

    /// Verify a PIN against the stored verifier in constant time, and on
    /// success return a copy of the retained KEK for `unlock_with_kek`.
    /// The returned KEK is `Zeroizing`; the caller drops it after unlock.
    pub fn verify(&self, pin: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        let candidate = hash_pin(pin, &self.pin_salt)?;
        // Constant-time compare.
        if !crate::crypto::constant_time_eq(&candidate, self.pin_hash.as_ref()) {
            return Err("Incorrect PIN".to_string());
        }
        Ok(zeroize::Zeroizing::new(*self.kek))
    }

    /// Verify a PIN and, atomically, record the outcome (increment the
    /// caller-provided counter, signal nuke-when-capped). This MUST run
    /// while the caller holds the escrow mutex, so that verify+record is
    /// one critical section: no concurrent `pin_unlock` can slip a real
    /// Argon2id-verified guess in between the verify and the cap check.
    /// Returns the KEK on success (caller clears the counter separately).
    /// On a wrong PIN, returns a user-facing message; the sentinel
    /// `PIN_NUKED_SENTINEL` means the cap was reached and the caller MUST
    /// destroy the escrow (`*guard = None`) before returning.
    pub fn verify_or_record_failure(
        &self,
        pin: &str,
        failures: &std::sync::atomic::AtomicU32,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        match self.verify(pin) {
            Ok(kek) => Ok(kek),
            Err(_) => {
                // Bump the counter under the SAME lock we were called in.
                let n = failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n >= MAX_PIN_FAILURES {
                    Err(PIN_NUKED_SENTINEL.to_string())
                } else {
                    let left = MAX_PIN_FAILURES - n;
                    Err(format!(
                        "Incorrect PIN. {} attempt{} left before PIN is disabled.",
                        left,
                        if left == 1 { "" } else { "s" }
                    ))
                }
            }
        }
    }
}

/// Validate the PIN is exactly 6 ASCII digits.
pub fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be exactly 6 digits".to_string());
    }
    Ok(())
}

/// Argon2id-hash a PIN with the given salt. Output is zeroized by the caller.
fn hash_pin(pin: &str, salt: &[u8]) -> Result<[u8; PIN_HASH_LEN], String> {
    let params = Params::new(
        PIN_ARGON2_MEM_KIB,
        PIN_ARGON2_TIME_COST,
        PIN_ARGON2_PARALLELISM,
        Some(PIN_HASH_LEN),
    )
    .map_err(|e| format!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; PIN_HASH_LEN];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2 pin hash: {e}"))?;
    Ok(out)
}

/// Constant-time equality. Lengths are equal here (both PIN_HASH_LEN).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pin_accepted() {
        assert!(validate_pin("123456").is_ok());
        assert!(validate_pin("000000").is_ok());
        assert!(validate_pin("999999").is_ok());
    }

    #[test]
    fn invalid_pin_rejected() {
        assert!(validate_pin("12345").is_err(), "too short");
        assert!(validate_pin("1234567").is_err(), "too long");
        assert!(validate_pin("abcdef").is_err(), "non-numeric");
        assert!(validate_pin("12345a").is_err(), "partial-numeric");
        assert!(validate_pin("").is_err(), "empty");
        assert!(validate_pin("12 456").is_err(), "contains space");
    }

    #[test]
    fn verify_correct_pin_returns_kek() {
        let kek = [0xABu8; 32];
        let escrow = PinEscrow::new(kek, "482910").unwrap();
        let got = escrow.verify("482910").unwrap();
        assert_eq!(got.as_ref(), &kek);
    }

    #[test]
    fn verify_wrong_pin_fails() {
        let escrow = PinEscrow::new([0xCDu8; 32], "111111").unwrap();
        assert!(escrow.verify("111112").is_err());
    }

    #[test]
    fn same_pin_different_salt_yields_different_hash() {
        // Two escrows with the same PIN must have independent salts/hashes
        // (fresh OsRng per escrow) so an old escrow leak does not help.
        let a = PinEscrow::new([0u8; 32], "000000").unwrap();
        let b = PinEscrow::new([0u8; 32], "000000").unwrap();
        // Both verify the same PIN, but their internal salts differ.
        assert!(a.verify("000000").is_ok());
        assert_ne!(a.pin_salt, b.pin_salt);
    }
}
