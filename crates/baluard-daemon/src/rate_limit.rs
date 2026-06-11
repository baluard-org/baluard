//! M4 fix: Per-vault rate limiting for sensitive operations.
//!
//! Tracks failed attempts with exponential backoff and lockout. Applied to
//! unlock, recovery, emergency access approval, and biometric unlock paths.
//!
//! Design:
//! - In-memory only (resets on daemon restart). Acceptable: Argon2id KDF
//!   cost is the primary brute-force defense; rate limiting prevents
//!   fast-fail cycling that would otherwise let a same-UID attacker grind
//!   the KDF at line speed.
//! - Exponential backoff: min(2^attempts, 60) seconds between attempts.
//! - Lockout after 10 failed attempts: refuses further attempts for 1 hour.
//! - Counter resets on successful authentication.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum failed attempts before lockout.
const MAX_ATTEMPTS_BEFORE_LOCKOUT: u32 = 10;
/// Lockout duration after MAX_ATTEMPTS_BEFORE_LOCKOUT.
const LOCKOUT_DURATION: Duration = Duration::from_secs(60 * 60);
/// Maximum backoff between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Per-vault rate limit state.
#[derive(Debug)]
struct VaultRateLimit {
    /// Number of consecutive failed attempts.
    failed_attempts: u32,
    /// When the last failed attempt occurred (for backoff).
    last_attempt: Instant,
    /// When lockout expires, if currently locked.
    locked_until: Option<Instant>,
}

impl Default for VaultRateLimit {
    fn default() -> Self {
        Self {
            failed_attempts: 0,
            last_attempt: Instant::now(),
            locked_until: None,
        }
    }
}

/// Outcome of checking rate limit before an attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum RateCheck {
    /// Proceed with the attempt.
    Allowed,
    /// Wait this long before the next attempt (exponential backoff).
    Backoff(Duration),
    /// Locked out — must wait until this Instant before retrying.
    LockedOut(Duration),
}

/// Rate limiter for sensitive vault operations. One instance per daemon,
/// keyed by vault path (so multi-vault setups are isolated).
pub struct RateLimiter {
    state: Mutex<HashMap<String, VaultRateLimit>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether an attempt is allowed. Returns the required wait if not.
    /// Does NOT consume an attempt — call `record_failure` after the attempt
    /// fails, or `record_success` if it succeeds.
    pub fn check(&self, vault_key: &str) -> RateCheck {
        let state = self.state.lock().expect("rate limiter poisoned");
        let entry = state.get(vault_key);

        let Some(entry) = entry else {
            return RateCheck::Allowed;
        };

        // Lockout check
        if let Some(until) = entry.locked_until {
            let now = Instant::now();
            if now < until {
                return RateCheck::LockedOut(until - now);
            }
        }

        // Backoff check: time since last failed attempt
        if entry.failed_attempts > 0 {
            let backoff = backoff_for_attempt(entry.failed_attempts);
            let elapsed = entry.last_attempt.elapsed();
            if elapsed < backoff {
                return RateCheck::Backoff(backoff - elapsed);
            }
        }

        RateCheck::Allowed
    }

    /// Record a failed attempt.
    pub fn record_failure(&self, vault_key: &str) {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        let entry = state.entry(vault_key.to_string()).or_default();
        entry.failed_attempts = entry.failed_attempts.saturating_add(1);
        entry.last_attempt = Instant::now();
        if entry.failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT {
            entry.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
        }
    }

    /// Record a successful attempt (resets the counter).
    pub fn record_success(&self, vault_key: &str) {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        if let Some(entry) = state.get_mut(vault_key) {
            entry.failed_attempts = 0;
            entry.locked_until = None;
        }
    }

    /// Current attempt count (for diagnostics/testing).
    pub fn attempt_count(&self, vault_key: &str) -> u32 {
        let state = self.state.lock().expect("rate limiter poisoned");
        state.get(vault_key).map(|e| e.failed_attempts).unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Exponential backoff: 2^attempt seconds, capped at MAX_BACKOFF.
fn backoff_for_attempt(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let secs = 1u64.checked_shl(attempt.min(6)).unwrap_or(MAX_BACKOFF.as_secs());
    Duration::from_secs(secs.min(MAX_BACKOFF.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn first_attempt_allowed() {
        let rl = RateLimiter::new();
        assert_eq!(rl.check("vault1"), RateCheck::Allowed);
    }

    #[test]
    fn failure_then_backoff() {
        let rl = RateLimiter::new();
        rl.record_failure("vault1");
        // After 1 failure, backoff = 2s
        match rl.check("vault1") {
            RateCheck::Backoff(d) => assert!(d <= Duration::from_secs(2)),
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[test]
    fn success_resets_counter() {
        let rl = RateLimiter::new();
        rl.record_failure("vault1");
        rl.record_failure("vault1");
        assert_eq!(rl.attempt_count("vault1"), 2);
        rl.record_success("vault1");
        assert_eq!(rl.attempt_count("vault1"), 0);
        assert_eq!(rl.check("vault1"), RateCheck::Allowed);
    }

    #[test]
    fn lockout_after_max_attempts() {
        let rl = RateLimiter::new();
        for _ in 0..MAX_ATTEMPTS_BEFORE_LOCKOUT {
            rl.record_failure("vault1");
        }
        match rl.check("vault1") {
            RateCheck::LockedOut(d) => {
                // Should be approximately 1 hour (allow some slack)
                assert!(d >= Duration::from_secs(3500));
            }
            other => panic!("expected lockout, got {other:?}"),
        }
    }

    #[test]
    fn vaults_isolated() {
        let rl = RateLimiter::new();
        rl.record_failure("vault1");
        rl.record_failure("vault1");
        // vault2 unaffected
        assert_eq!(rl.check("vault2"), RateCheck::Allowed);
    }

    #[test]
    fn backoff_capped_at_max() {
        assert_eq!(backoff_for_attempt(0), Duration::ZERO);
        assert_eq!(backoff_for_attempt(1), Duration::from_secs(2));
        assert_eq!(backoff_for_attempt(2), Duration::from_secs(4));
        assert_eq!(backoff_for_attempt(3), Duration::from_secs(8));
        assert_eq!(backoff_for_attempt(6), Duration::from_secs(60));
        assert_eq!(backoff_for_attempt(20), Duration::from_secs(60));
    }

    #[test]
    fn backoff_expires() {
        let rl = RateLimiter::new();
        rl.record_failure("vault1");
        sleep(Duration::from_millis(2100));
        assert_eq!(rl.check("vault1"), RateCheck::Allowed);
    }
}
