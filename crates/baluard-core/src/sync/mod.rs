//! Git sync engine: pull, push, conflict resolution, signed commits.
//!
//! D10: Field-level merge (structured plaintext diff before re-encryption).
//! D12: Transactional state machine + fsck fallback.
//! D22: Signed commits + rollback detection.
//! Clones are always full: commit signing verification walks the entire
//! first-parent history, so a shallow clone could not verify signatures.

pub mod commit;
pub mod conflict;
pub mod credentials;
pub mod gossip;
pub mod known_hosts;
pub mod policy;
pub mod revocation;
pub mod state_machine;
#[cfg(feature = "git-sync")]
pub mod tls;

#[cfg(feature = "git-sync")]
pub mod engine;
