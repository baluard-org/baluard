//! Baluard core library.
//!
//! Git-native password manager. Crypto, vault format, sync, key lifecycle.
//! See docs/01-architecture-decisions.md for full design rationale.

pub mod biometric;
pub mod bridge;
pub mod crypto;
pub mod device_manager;
pub mod devices;
pub mod emergency;
pub mod generator;
pub mod health;
pub mod import;
pub mod integrity;
pub mod keys;
pub mod orgs;
pub mod paths;
pub mod providers;
pub mod recovery;
pub mod sync;
pub mod vault;

pub mod error;
pub mod types;

pub use error::BaluardError;

/// Library version, embedded in vault format headers.
pub const BALUARD_VERSION: u8 = 1;

/// Current AEAD algorithm identifier: AES-256-GCM.
pub const ALG_AES_256_GCM: u16 = 0x0001;

// NOTE: the mobile UniFFI FFI surface lives in `crates/baluard-uniffi/`, NOT here.
// An earlier spike placed `mobile_version` / `mobile_generate_mnemonic` /
// `mobile_derive_key` directly in core (pre-rebrand `idtty` legacy); that was
// removed 2026-07-23 per plan §3.3 (single FFI boundary, keep core idiomatic
// Rust). The baluard-uniffi crate wraps core + runtime for mobile.
