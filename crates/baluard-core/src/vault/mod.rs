//! Vault format: cipher files, metadata, tiered padding, creation ceremony.
//!
//! D6-D8: Hybrid manifest, tiered padding, file structure.
//! Doc 06 Section 10: Vault creation ceremony.

pub mod attachment;
pub mod cipher;
pub mod creation;
pub mod envelope;
pub mod handle;
pub mod index;
pub mod manifest;
pub mod padding;

pub use handle::VaultHandle;

use std::path::Path;

/// Atomic write with 0600 permissions.
/// Writes to a `.tmp` file, sets owner-only permissions, then renames to final path.
/// Prevents partial writes and ensures consistent file permissions across the vault.
pub(crate) fn write_vault_file(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
