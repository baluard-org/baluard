//! Git provider abstraction: auth, token management, repo operations.
//!
//! Phase 2: ForgeProvider trait + GitHub provider (device flow + PAT).
//! Tokens stored in OS keyring. Non-sensitive state in providers.json.

pub mod codeberg;
pub mod github;
pub mod gitlab;
pub mod token;
pub mod types;

pub use types::{
    DeviceFlowSession, DeviceFlowStatus, ForgeProvider, OAuthStart, Provider, ProviderConfig,
    ProviderInfo, ProviderToken, code_challenge_s256, generate_code_verifier, generate_state,
};
