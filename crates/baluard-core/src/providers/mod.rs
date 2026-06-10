//! Git provider abstraction: auth, token management, repo operations.
//!
//! Phase 2: ForgeProvider trait + GitHub provider (device flow + PAT).
//! Tokens stored in OS keyring. Non-sensitive state in providers.json.

pub mod github;
pub mod token;
pub mod types;

pub use types::{DeviceFlowSession, DeviceFlowStatus, ForgeProvider, Provider, ProviderInfo};
