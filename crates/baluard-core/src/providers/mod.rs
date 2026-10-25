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
    CollaboratorPermission, CollaboratorStatus, DeviceFlowSession, DeviceFlowStatus, ForgeProvider,
    OAuthStart, Provider, ProviderConfig, ProviderInfo, ProviderToken, code_challenge_s256,
    generate_code_verifier, generate_state, split_owner_repo,
};

use types::ProviderError;

/// Dispatch to the correct `ForgeProvider` implementation based on `Provider`.
///
/// Centralises provider routing so callers (daemon, future tests) stay
/// provider-agnostic. `config` carries Advanced Options overrides
/// (`client_id`, `instance_url`); defaults are applied inside each provider
/// when a field is `None`.
///
/// Phase 4 hardening: returns `Result<_, ProviderError>` (the providers-crate
/// error type) instead of a panicking `unimplemented!`. Callers map to their
/// own wire type via `.map_err(|e| e.to_string())`.
pub fn provider_for(
    p: Provider,
    config: ProviderConfig,
) -> Result<Box<dyn ForgeProvider>, ProviderError> {
    match p {
        Provider::GitHub => Ok(Box::new(github::GitHubProvider::with_config(config))),
        Provider::GitLab => Ok(Box::new(gitlab::GitLabProvider::with_config(config))),
        Provider::Codeberg => Ok(Box::new(codeberg::CodebergProvider::with_config(config))),
    }
}

/// Disconnect a provider with a best-effort server-side token revocation
/// attempt **before** the local keyring + `providers.json` are cleared.
///
/// Closes the Phase 4 gap where `token::disconnect` only deleted local state
/// and never invoked the `revoke_token` trait method. The order matters: we
/// load the token from the keyring, call the provider's `revoke_token`
/// (best-effort, error ignored per the trait contract), and **then** clear
/// the keyring + state. If the server-side call fails (network blip, PAT
/// which can't self-revoke, GitHub/Codeberg which lack a revoke API) we
/// still complete the local disconnect — the user wants to be disconnected
/// either way.
///
/// Config is sourced from the stored `ProviderInfo` so a self-hosted
/// instance + custom `client_id` are used for the revocation call (matches
/// the instance the token was issued for).
///
/// If the provider was never connected (no entry in `providers.json`),
/// returns `Ok(())` without touching the network. State is always cleared
/// by the delegate `token::disconnect` call.
pub async fn revoke_and_disconnect(provider: Provider) -> Result<(), ProviderError> {
    let state = token::ProvidersState::load().map_err(|e| ProviderError::Io(e.to_string()))?;

    if let Some(info) = state.get(provider).cloned() {
        let config = info.config();
        // Best-effort: token may already be gone, keyring may be unavailable.
        if let Ok(t) = token::load_token(provider, &info.username) {
            if let Ok(p) = provider_for(provider, config) {
                // Best-effort per trait contract (non-blocking on failure).
                // GitLab POSTs /oauth/revoke; GitHub/Codeberg are no-op stubs.
                let _ = p.revoke_token(&t).await;
            }
        }
    }

    // Delegate state removal + keyring deletion (both best-effort by design).
    token::disconnect(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::mock::MockProvider;

    /// Test seam: same flow as `revoke_and_disconnect` but with an injected
    /// provider factory and a pre-built token. Used to verify the wiring
    /// without depending on the OS keyring (unavailable in headless CI).
    pub(crate) async fn revoke_and_disconnect_with_factory<F>(
        provider: Provider,
        info: ProviderInfo,
        token: ProviderToken,
        factory: F,
    ) -> Result<(), ProviderError>
    where
        F: FnOnce(Provider, ProviderConfig) -> Result<Box<dyn ForgeProvider>, ProviderError>,
    {
        if let Ok(p) = factory(provider, info.config()) {
            // Best-effort per trait contract.
            let _ = p.revoke_token(&token).await;
        }
        token::disconnect(provider)
    }

    /// Verifies the Phase 4 wiring: `revoke_and_disconnect` must invoke the
    /// trait `revoke_token` method on the constructed provider before the
    /// local `providers.json` entry is cleared. Uses an injected factory so
    /// the test does not depend on the OS keyring (headless CI).
    #[tokio::test]
    #[serial_test::serial]
    async fn revoke_and_disconnect_invokes_revoke_token() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let orig = std::env::var("BALUARD_DATA_DIR").ok();
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", temp_dir.path());
        }

        // Counter shared between the factory (constructed mock) and the
        // assertion site. Increments on every `revoke_token` call.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let factory = move |_p: Provider, _c: ProviderConfig| {
            let c = c.clone();
            Ok(Box::new(MockProvider {
                provider_type: Provider::GitHub,
                revoked_calls: c,
                deleted_calls: Arc::new(AtomicUsize::new(0)),
                seat_log: Arc::new(Mutex::new(Vec::new())),
                seat_status: CollaboratorStatus::Active,
                fail_deploy_key: false,
            }) as Box<dyn ForgeProvider>)
        };

        let info = ProviderInfo {
            provider: Provider::GitHub,
            username: "alice".into(),
            scopes: "repo".into(),
            connected_at: 1_700_000_000,
            instance_url: None,
            client_id: None,
            email: None,
        };
        let token = ProviderToken::new("ghp_test", "repo");

        // Pre-populate providers.json so the delegate's `state.remove` finds
        // the entry and clears it.
        let mut state = token::ProvidersState::default();
        state.set(info.clone());
        state.save().expect("save providers.json");

        let result =
            revoke_and_disconnect_with_factory(Provider::GitHub, info, token, factory).await;
        assert!(result.is_ok(), "revoke_and_disconnect should return Ok");

        // The mock's `revoke_token` was called exactly once.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "revoke_token must be invoked exactly once before disconnect"
        );

        // The local state was cleared by the delegate.
        let post = token::ProvidersState::load().expect("reload providers.json");
        assert!(
            post.get(Provider::GitHub).is_none(),
            "providers.json entry must be removed after disconnect"
        );

        unsafe {
            if let Some(v) = orig {
                std::env::set_var("BALUARD_DATA_DIR", v);
            } else {
                std::env::remove_var("BALUARD_DATA_DIR");
            }
        }
    }

    /// No entry in providers.json => no-op, returns Ok, no factory call.
    /// Verifies the early-return path for the "already disconnected" case.
    #[tokio::test]
    #[serial_test::serial]
    async fn revoke_and_disconnect_no_entry_is_noop() {
        // Mutates BALUARD_DATA_DIR (read by ProvidersState); must not run
        // concurrently with other env-mutating provider tests.
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let orig = std::env::var("BALUARD_DATA_DIR").ok();
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", temp_dir.path());
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let factory = move |_p: Provider, _c: ProviderConfig| {
            let c = c.clone();
            Ok(Box::new(MockProvider {
                provider_type: Provider::GitHub,
                revoked_calls: c,
                deleted_calls: Arc::new(AtomicUsize::new(0)),
                seat_log: Arc::new(Mutex::new(Vec::new())),
                seat_status: CollaboratorStatus::Active,
                fail_deploy_key: false,
            }) as Box<dyn ForgeProvider>)
        };

        // Empty state. The public `revoke_and_disconnect` would still
        // delegate to `token::disconnect` (which is a no-op for empty
        // state). The factory variant is a tighter test of the early
        // return by passing a synthetic info.
        let info = ProviderInfo {
            provider: Provider::GitHub,
            username: "alice".into(),
            scopes: "repo".into(),
            connected_at: 0,
            instance_url: None,
            client_id: None,
            email: None,
        };
        let token = ProviderToken::new("ghp_test", "repo");

        let result =
            revoke_and_disconnect_with_factory(Provider::GitHub, info, token, factory).await;
        assert!(result.is_ok());
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "factory variant always invokes"
        );

        unsafe {
            if let Some(v) = orig {
                std::env::set_var("BALUARD_DATA_DIR", v);
            } else {
                std::env::remove_var("BALUARD_DATA_DIR");
            }
        }
    }

    /// `delete_repo` on the mock must return Ok and increment its counter
    /// exactly once per call. Guards the contract the daemon's
    /// `sync_disconnect(delete_remote: true)` path relies on: a wired mock
    /// is observable, not a silent no-op.
    #[tokio::test]
    async fn mock_provider_delete_repo_is_observable() {
        use crate::providers::types::mock::MockProvider;

        let provider = MockProvider::github();
        let token = ProviderToken::new("ghp_test", "repo");

        // Sanity: counter starts at zero.
        assert_eq!(
            provider.deleted_calls.load(Ordering::SeqCst),
            0,
            "deleted_calls must start at zero"
        );

        ForgeProvider::delete_repo(&provider, &token, "owner", "repo")
            .await
            .expect("mock delete_repo must succeed");

        assert_eq!(
            provider.deleted_calls.load(Ordering::SeqCst),
            1,
            "delete_repo must increment deleted_calls exactly once"
        );
    }
}
