//! Key hierarchy: unified key management for vault operations.
//!
//! Doc 06: 10 key types, 5-state epoch machine, transition protocol.
//! D3: KEK → Session/Sync keys. Root Key (HPKE-wrapped) → Item Keys.

pub mod epoch;
pub mod hierarchy;
pub mod nonce;
pub mod rotation;

pub use epoch::{EpochInfo, EpochState};
pub use hierarchy::{RootKey, ItemKey};
