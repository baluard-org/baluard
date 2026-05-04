//! Vault format: cipher files, metadata, tiered padding, creation ceremony.
//!
//! D6-D8: Hybrid manifest, tiered padding, file structure.
//! Doc 06 Section 10: Vault creation ceremony.

pub mod cipher;
pub mod envelope;
pub mod manifest;
pub mod padding;
pub mod creation;
pub mod handle;

pub use handle::VaultHandle;
