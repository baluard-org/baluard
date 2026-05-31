//! IDtty core library.
//!
//! Git-native password manager. Crypto, vault format, sync, key lifecycle.
//! See docs/01-architecture-decisions.md for full design rationale.

pub mod biometric;
pub mod crypto;
pub mod device_manager;
pub mod devices;
pub mod emergency;
pub mod health;
pub mod import;
pub mod integrity;
pub mod keys;
pub mod orgs;
pub mod providers;
pub mod recovery;
pub mod sync;
pub mod vault;

pub mod error;
pub mod types;

pub use error::IdttyError;

/// Library version, embedded in vault format headers.
pub const IDTTY_VERSION: u8 = 1;

/// Current AEAD algorithm identifier: AES-256-GCM.
pub const ALG_AES_256_GCM: u16 = 0x0001;
