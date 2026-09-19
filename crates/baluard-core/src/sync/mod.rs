//! Git sync engine: pull, push, conflict resolution, signed commits.
//!
//! D10: Field-level merge (structured plaintext diff before re-encryption).
//! D11: Shallow clone default, auto-unshallow on conflict.
//! D12: Transactional state machine + fsck fallback.
//! D13: Auto-poll 30-60s.
//! D22: Signed commits + rollback detection.

pub mod commit;
pub mod conflict;
pub mod credentials;
pub mod known_hosts;
pub mod operations;
pub mod revocation;
pub mod state_machine;
#[cfg(feature = "git-sync")]
pub mod tls;

#[cfg(feature = "git-sync")]
pub mod engine;
