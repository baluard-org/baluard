//! Credential callbacks for SSH and HTTPS authentication.
//!
//! SSH: delegates to ssh-agent (no key material stored in process).
//! HTTPS: reads provider token from keyring (primary), then env var,
//!         then meta/git-credentials.json in the vault directory.

use std::path::Path;

#[cfg(feature = "git-sync")]
use git2::{Cred, CredentialType, RemoteCallbacks};

use crate::providers::types::Provider;
use secrecy::ExposeSecret;

/// Credential source configuration.
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// HTTPS personal access token.
    /// Priority: keyring (provider) > env var > vault config file.
    pub https_token: Option<String>,
}

impl CredentialConfig {
    /// Load credentials from provider keyring, env var, or vault config file.
    /// Provider keyring is checked first (the auth flow stores tokens there).
    pub fn load(vault_path: &Path) -> Self {
        let https_token = Self::load_from_keyring()
            .or_else(|| std::env::var("BALUARD_GIT_TOKEN").ok())
            .or_else(|| Self::load_from_file(vault_path));
        Self { https_token }
    }

    /// Load from any connected provider's keyring entry.
    /// Iterates providers.json to find a connected provider, then reads its token.
    fn load_from_keyring() -> Option<String> {
        let state = crate::providers::token::ProvidersState::load().ok()?;
        // Try all connected providers, return first token found
        for provider in Provider::all() {
            if let Some(info) = state.get(*provider) {
                if let Ok(token) = crate::providers::token::load_token(*provider, &info.username) {
                    return Some(token.access_token().expose_secret().to_string());
                }
            }
        }
        None
    }

    /// Load from vault config file fallback.
    fn load_from_file(vault_path: &Path) -> Option<String> {
        let config_path = vault_path.join("meta/git-credentials.json");
        if config_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&config_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                    return v["token"].as_str().map(|s| s.to_string());
                }
            }
        }
        None
    }
}

/// Build RemoteCallbacks with credential handling for both SSH and HTTPS.
#[cfg(feature = "git-sync")]
pub fn build_callbacks(config: &CredentialConfig) -> RemoteCallbacks<'_> {
    let https_token = config.https_token.clone();
    let mut callbacks = RemoteCallbacks::new();

    callbacks.credentials(move |_url, username_from_url, allowed_types| {
        // SSH: try ssh-agent first when SSH key types are allowed
        if allowed_types.contains(CredentialType::SSH_KEY) {
            let user = username_from_url.unwrap_or("git");
            if let Ok(cred) = Cred::ssh_key_from_agent(user) {
                return Ok(cred);
            }
        }

        // HTTPS: use personal access token
        if allowed_types.contains(CredentialType::USER_PASS_PLAINTEXT) {
            if let Some(ref token) = https_token {
                let user = username_from_url.unwrap_or("git");
                return Cred::userpass_plaintext(user, token);
            }
        }

        // Default: let git2 try its built-in credential helpers
        if allowed_types.contains(CredentialType::DEFAULT) {
            return Cred::default();
        }

        Err(git2::Error::from_str("no credential source available"))
    });

    callbacks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_without_env_or_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = CredentialConfig::load(dir.path());
        // Without env var or config file, token is None
        assert!(config.https_token.is_none());
    }

    #[test]
    fn load_from_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let meta = dir.path().join("meta");
        std::fs::create_dir_all(&meta).unwrap();
        let config_path = meta.join("git-credentials.json");
        std::fs::write(&config_path, r#"{"token":"ghp_test123"}"#).unwrap();

        let config = CredentialConfig::load(dir.path());
        // If BALUARD_GIT_TOKEN env is set, it wins; otherwise file wins
        if std::env::var("BALUARD_GIT_TOKEN").is_ok() {
            assert!(config.https_token.is_some());
        } else {
            assert_eq!(config.https_token.as_deref(), Some("ghp_test123"));
        }
    }
}
