//! Git sync engine: pull, push, conflict resolution, signed commits.
//!
//! D10: Field-level merge (structured plaintext diff before re-encryption).
//! D12: Transactional state machine + fsck fallback.
//! D22: Signed commits + rollback detection.
//! Clones are always full: commit signing verification walks the entire
//! first-parent history, so a shallow clone could not verify signatures.

pub mod attachments;
pub mod commit;
pub mod conflict;
pub mod credentials;
pub mod gossip;
pub mod known_hosts;
pub mod msgbus;
pub mod policy;
pub mod revocation;
pub mod state_machine;
pub mod timeline;
#[cfg(feature = "git-sync")]
pub mod tls;

#[cfg(feature = "git-sync")]
pub mod engine;
#[cfg(feature = "git-sync")]
pub mod folder;
#[cfg(feature = "p2p")]
pub mod p2p;

use rand::RngCore;

/// Unique tmp path for an atomic replace: fixed tmp names collide when
/// the CLI and the daemon sync the same vault concurrently (the
/// known_hosts writer uses this random-suffix pattern). The extension is
/// REPLACED (foo.json -> foo.tmp.<hex>), not appended.
pub(crate) fn unique_tmp_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut suffix = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    path.with_extension(format!(
        "tmp.{}",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
