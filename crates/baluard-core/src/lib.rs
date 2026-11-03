//! Baluard core library.
//!
//! Git-native password manager. Crypto, vault format, sync, key lifecycle.
//! See docs/adr/ for full design rationale.

pub mod biometric;
pub mod bridge;
pub mod crypto;
pub mod device_manager;
pub mod devices;
pub mod generator;
pub mod health;
pub mod hwkey;
pub mod import;
pub mod integrity;
pub mod keys;
pub mod legacy;
pub mod orgs;
pub mod paths;
pub mod providers;
pub mod recovery;
pub mod recovery_sheet;
pub mod secret_file;
pub mod sync;
pub mod sysdeps;
pub mod vault;

pub mod error;
pub mod types;

pub use error::BaluardError;

/// Library version, embedded in vault format headers.
pub const BALUARD_VERSION: u8 = 2;

/// True when OS-keyring access must be skipped: in-process unit tests
/// (`cfg(test)`) and any process carrying `BALUARD_DISABLE_KEYRING=1`
/// (integration tests that spawn the real daemon binary). On macOS an
/// unsigned test binary touching the user keychain triggers interactive
/// authorization prompts, which stalls tests until a human approves and
/// pollutes the user's keychain with test items. Keyring-backed paths fail
/// closed to their file/keystore fallbacks instead.
pub fn keyring_disabled() -> bool {
    cfg!(test) || std::env::var_os("BALUARD_DISABLE_KEYRING").is_some()
}

/// Current AEAD algorithm identifier: AES-256-GCM.
pub const ALG_AES_256_GCM: u16 = 0x0001;

// NOTE: the mobile UniFFI FFI surface lives in `crates/baluard-uniffi/`, NOT here.
// An earlier spike placed `mobile_version` / `mobile_generate_mnemonic` /
// `mobile_derive_key` directly in core; that was removed 2026-07-23 per plan
// §3.3 (single FFI boundary, keep core idiomatic Rust). The baluard-uniffi
// crate wraps core + runtime for mobile.
