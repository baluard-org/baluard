//! Rate limiting for sensitive authentication operations (audit C10/C22/C23).
//!
//! Tracks failed attempts with exponential backoff and lockout, keyed by
//! vault path. Wired routes: `vault.unlock`, `vault.biometric_unlock`,
//! `vault.pin_unlock`, `vault.reprompt_verify`, `vault.enroll_with_phrase`.
//! `reprompt_verify` deliberately shares the vault's unlock key: grinding
//! the reprompt Argon2id oracle locks out `vault.unlock` too.
//!
//! Design:
//! - Process-global singleton (see [`global`]); counters are keyed by vault
//!   path, so closing and reopening a vault does NOT reset them. In-memory
//!   only: a daemon restart resets state (accepted; audit C7). Argon2id KDF
//!   cost remains the primary brute-force defense; rate limiting prevents
//!   fast-fail cycling that would otherwise let a same-UID attacker grind
//!   the KDF at line speed.
//! - Exponential backoff: min(2^attempts, 60) seconds between attempts.
//! - Lockout after 10 failed attempts: refuses further attempts for 1 hour.
//! - Counter resets on successful authentication.
//!
//! Permit API: `claim_attempt` checks backoff/lockout and returns an
//! `AttemptPermit` whose `commit_success`/`commit_failure` record the
//! outcome (and `Drop` without commit records nothing). This gives handlers
//! a structured way to record outcomes; it is NOT a concurrency gate —
//! concurrent attempts are each allowed and serialized by the caller (e.g.
//! the PIN escrow mutex holds verify+record as one critical section).
//! The authoritative brute-force counters are: Argon2id (cost), the on-disk
//! attempt file for master-password unlock, and the PIN escrow's own
//! 5-strike counter for PIN unlock.

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

/// Outcome of claiming an attempt slot.
#[derive(Debug)]
pub enum ClaimResult<'a> {
    /// Slot reserved; caller must commit success/failure or drop the permit.
    Allowed(AttemptPermit<'a>),
    /// In backoff; caller should wait this long before retrying.
    Backoff(Duration),
    /// Locked out; caller must wait until this duration elapses.
    LockedOut(Duration),
}

/// A reserved attempt slot. Dropping without a commit records a failure
/// (fail closed); call `commit_failure`/`commit_success` explicitly.
#[derive(Debug)]
pub struct AttemptPermit<'a> {
    limiter: &'a RateLimiter,
    vault_key: String,
    committed: bool,
}

impl<'a> AttemptPermit<'a> {
    /// Commit the attempt as a failure (increments failed_attempts, may lock).
    pub fn commit_failure(mut self) {
        self.limiter.record_failure(&self.vault_key);
        self.committed = true;
    }

    /// Commit the attempt as a success (clears counters, releases slot).
    pub fn commit_success(mut self) {
        self.limiter.record_success(&self.vault_key);
        self.committed = true;
    }
}

impl Drop for AttemptPermit<'_> {
    fn drop(&mut self) {
        // Fail closed: an attempt that neither committed success nor
        // failure (early return, ?-propagation, panic unwind) still
        // consumed an Argon2id-grade verification slot and must count —
        // otherwise a caller bug silently mints free oracle attempts.
        if !self.committed {
            self.limiter.record_failure(&self.vault_key);
        }
    }
}

/// Rate limiter for sensitive vault operations. One instance per daemon,
/// keyed by vault path (so multi-vault setups are isolated).
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<HashMap<String, VaultRateLimit>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check backoff/lockout and return a permit the caller commits with
    /// `commit_success` / `commit_failure`. This is NOT a concurrency gate:
    /// concurrent attempts are each allowed (the authoritative brute-force
    /// defense is Argon2id + the per-path counters, not mutual exclusion
    /// here). Handlers that need strict serialization (e.g. PIN verify+
    /// record) hold their own mutex across the critical section.
    pub fn claim_attempt(&self, vault_key: &str) -> ClaimResult<'_> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state.entry(vault_key.to_string()).or_default();

        // Lockout check
        if let Some(until) = entry.locked_until {
            if Instant::now() < until {
                return ClaimResult::LockedOut(until - Instant::now());
            }
        }

        // Backoff check
        if entry.failed_attempts > 0 {
            let backoff = backoff_for_attempt(entry.failed_attempts);
            let elapsed = entry.last_attempt.elapsed();
            if elapsed < backoff {
                return ClaimResult::Backoff(backoff - elapsed);
            }
        }

        ClaimResult::Allowed(AttemptPermit {
            limiter: self,
            vault_key: vault_key.to_string(),
            committed: false,
        })
    }

    /// Record a failed attempt (called by AttemptPermit::commit_failure).
    pub fn record_failure(&self, vault_key: &str) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state.entry(vault_key.to_string()).or_default();
        entry.failed_attempts = entry.failed_attempts.saturating_add(1);
        entry.last_attempt = Instant::now();
        if entry.failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT {
            entry.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
        }
    }

    /// Record a successful attempt (called by AttemptPermit::commit_success).
    pub fn record_success(&self, vault_key: &str) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.get_mut(vault_key) {
            entry.failed_attempts = 0;
            entry.locked_until = None;
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global limiter. One per daemon, independent of any `VaultState`
/// lifetime, so closing and reopening a vault does not reset counters
/// (audit C10).
static GLOBAL: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();

/// Access the daemon-process-global rate limiter. Handlers use this
/// instead of a per-vault field; the vault path remains the map key, so
/// multi-vault isolation is preserved while counters survive vault close.
pub fn global() -> &'static RateLimiter {
    GLOBAL.get_or_init(RateLimiter::new)
}

/// Exponential backoff: 2^attempt seconds, capped at MAX_BACKOFF.
fn backoff_for_attempt(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let secs = 1u64
        .checked_shl(attempt.min(6))
        .unwrap_or(MAX_BACKOFF.as_secs());
    Duration::from_secs(secs.min(MAX_BACKOFF.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    /// Helper: record a failure directly (bypasses the permit pattern for
    /// test setup speed). The permit pattern is exercised by the production
    /// code path; tests just need to set up failure state.
    fn fail(rl: &RateLimiter, key: &str) {
        rl.record_failure(key);
    }

    #[test]
    fn first_attempt_allowed() {
        let rl = RateLimiter::new();
        let _p = match rl.claim_attempt("vault1") {
            ClaimResult::Allowed(p) => p,
            other => panic!("expected allowed, got {other:?}"),
        };
    }

    #[test]
    fn failure_then_backoff() {
        let rl = RateLimiter::new();
        fail(&rl, "vault1");
        // After 1 failure, backoff = 2s
        match rl.claim_attempt("vault1") {
            ClaimResult::Backoff(d) => assert!(d <= Duration::from_secs(2)),
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[test]
    fn success_resets_counter() {
        let rl = RateLimiter::new();
        fail(&rl, "vault1");
        fail(&rl, "vault1");
        // Now in backoff (4s for 2nd failure). Wait for it to expire.
        sleep(Duration::from_millis(4200));
        let p = match rl.claim_attempt("vault1") {
            ClaimResult::Allowed(p) => p,
            other => panic!("expected allowed, got {other:?}"),
        };
        p.commit_success();
        // Next attempt should be allowed (counter reset)
        let _p = match rl.claim_attempt("vault1") {
            ClaimResult::Allowed(p) => p,
            other => panic!("expected allowed after success, got {other:?}"),
        };
    }

    #[test]
    fn lockout_after_max_attempts() {
        let rl = RateLimiter::new();
        for _ in 0..MAX_ATTEMPTS_BEFORE_LOCKOUT {
            sleep(Duration::from_millis(2100)); // wait out backoff
            fail(&rl, "vault1");
        }
        match rl.claim_attempt("vault1") {
            ClaimResult::LockedOut(d) => {
                // Should be approximately 1 hour (allow some slack)
                assert!(d >= Duration::from_secs(3500));
            }
            other => panic!("expected lockout, got {other:?}"),
        }
    }

    #[test]
    fn vaults_isolated() {
        let rl = RateLimiter::new();
        fail(&rl, "vault1");
        fail(&rl, "vault1");
        // vault2 unaffected
        let _p = match rl.claim_attempt("vault2") {
            ClaimResult::Allowed(p) => p,
            other => panic!("expected allowed for vault2, got {other:?}"),
        };
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
        fail(&rl, "vault1");
        sleep(Duration::from_millis(2100));
        let _p = match rl.claim_attempt("vault1") {
            ClaimResult::Allowed(p) => p,
            other => panic!("expected allowed, got {other:?}"),
        };
    }

    #[test]
    fn global_is_single_instance() {
        assert!(std::ptr::eq(global(), global()));
    }

    /// C10: counters survive vault close/reopen — they live on the global
    /// limiter keyed by vault path, not on the VaultState.
    #[test]
    fn global_counters_survive_state_lifetimes() {
        let key = "/tmp/baluard-c10-test-vault";
        for _ in 0..MAX_ATTEMPTS_BEFORE_LOCKOUT {
            global().record_failure(key);
        }
        // A "reopened" vault (fresh lookup on the same path) must still be
        // locked out.
        match global().claim_attempt(key) {
            ClaimResult::LockedOut(_) => {}
            other => panic!("expected lockout on global limiter, got {other:?}"),
        }
    }
}
