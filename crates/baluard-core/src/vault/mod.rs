//! Vault format: cipher files, metadata, tiered padding, creation ceremony.
//!
//! D6-D8: Hybrid manifest, tiered padding, file structure.
//! Doc 06 Section 10: Vault creation ceremony.

pub mod access_requests;
pub mod approvals;
pub mod attachment;
pub mod avatar;
pub mod canary;
pub mod cipher;
pub mod collections;
pub mod contacts;
pub mod creation;
pub mod device_privkey;
pub mod envelope;
pub mod events;
pub mod handle;
pub mod identity;
pub mod index;
pub mod keywrap;
pub mod manifest;
pub mod members;
pub mod outbox;
pub mod packages;
pub mod padding;
pub mod registry;
pub mod reveals;
pub mod slug;
pub mod space;
pub mod space_meta;
pub mod templates;

pub use handle::VaultHandle;

use std::path::Path;

/// Atomic write with owner-only permissions. Delegates to the shared secret-file
/// primitive so vault data, provider tokens, exports, and attachments share one
/// hardened write path (audit C14/C17/C24/C25).
pub fn write_vault_file(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    crate::secret_file::write_secret_file(path, data)
}
