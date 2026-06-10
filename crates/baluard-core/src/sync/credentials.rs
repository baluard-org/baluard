//! Credential callbacks for SSH and HTTPS authentication.
//!
//! SSH: delegates to ssh-agent (no key material stored in process).
//! HTTPS: reads provider token from keyring (primary), env var,
//!         then meta/git-credentials.json in the vault directory.
//!
//! H5 fix: Token is kept as SecretString. All git2 errors are scrubbed
//! before being wrapped into SyncError to prevent credential disclosure
//! in logs and IPC error surfaces.

use std::path::Path;

#[cfg(feature = "git-sync")]
use git2::{Cred, CredentialType, RemoteCallbacks};

use crate::providers::types::Provider;
use secrecy::{ExposeSecret, SecretString};

/// Common PAT prefixes to scrub from error messages.
const PAT_PREFIXES: &[&str] = &["ghp_", "gho_", "github_pat_", "glpat-", "glpt-"];

/// Scrub potential credentials from a git2 error message.
/// Removes URL userinfo (user:token@host) and common PAT prefixes.
pub fn scrub_git_error(msg: &str) -> String {
    let mut cleaned = msg.to_string();

    // Scrub URL userinfo: ://anything@ -> ://***@
    // Simple scan-based approach (no regex dependency)
    if let Some(start) = cleaned.find("://") {
        let scheme_end = start + 3;
        if let Some(at_pos) = cleaned[scheme_end..].find('@') {
            let at_abs = scheme_end + at_pos;
            cleaned.replace_range(scheme_end..at_abs, "***");
        }
    }

    // Scrub PAT patterns
    for prefix in PAT_PREFIXES {
        while let Some(pos) = cleaned.find(prefix) {
            let end = cleaned[pos..]
                .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == ')')
                .map(|i| pos + i)
                .unwrap_or(cleaned.len());
            cleaned.replace_range(pos..end, "***");
        }
    }

    cleaned
}

/// Credential source configuration.
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// HTTPS personal access token (kept as SecretString).
    /// Priority: keyring (provider) > env var > vault config file.
    https_token: Option<SecretString>,
}

impl CredentialConfig {
    /// Load credentials from provider keyring, env var, or vault config file.
    pub fn load(vault_path: &Path) -> Self {
        Self::load_with_hint(vault_path, None)
    }

    /// Load credentials with an optional provider hint.
    pub fn load_with_hint(vault_path: &Path, hint: Option<Provider>) -> Self {
        let https_token = hint
            .and_then(Self::load_from_keyring_for)
            .or_else(Self::load_from_keyring)
            .or_else(|| {
                std::env::var("BALUARD_GIT_TOKEN").ok().map(|s| SecretString::new(s.into_boxed_str()))
            })
            .or_else(|| Self::load_from_file(vault_path));
        Self { https_token }
    }

    /// Expose the token for git2 credential callbacks (internal use only).
    /// The returned String is short-lived within the callback closure.
    #[cfg(feature = "git-sync")]
    pub(crate) fn expose_token(&self) -> Option<String> {
        self.https_token.as_ref().map(|t| t.expose_secret().to_string())
    }

    fn load_from_keyring_for(provider: Provider) -> Option<SecretString> {
        let state = crate::providers::token::ProvidersState::load().ok()?;
        let info = state.get(provider)?;
        let token = crate::providers::token::load_token(provider, &info.username).ok()?;
        Some(SecretString::new(token.access_token().expose_secret().to_string().into_boxed_str()))
    }

    fn load_from_keyring() -> Option<SecretString> {
        let state = crate::providers::token::ProvidersState::load().ok()?;
        for provider in Provider::all() {
            if let Some(info) = state.get(*provider) {
                if let Ok(token) = crate::providers::token::load_token(*provider, &info.username) {
                    return Some(SecretString::new(
                        token.access_token().expose_secret().to_string().into_boxed_str(),
                    ));
                }
            }
        }
        None
    }

    fn load_from_file(vault_path: &Path) -> Option<SecretString> {
        let config_path = vault_path.join("meta/git-credentials.json");
        if config_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&config_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                    return v["token"].as_str().map(|s| SecretString::new(s.to_string().into_boxed_str()));
                }
            }
        }
        None
    }
}

/// Build RemoteCallbacks with credential handling for both SSH and HTTPS.
#[cfg(feature = "git-sync")]
pub fn build_callbacks(config: &CredentialConfig) -> RemoteCallbacks<'_> {
    let https_token = config.expose_token();
    let mut callbacks = RemoteCallbacks::new();

    callbacks.credentials(move |_url, username_from_url, allowed_types| {
        if allowed_types.contains(CredentialType::SSH_KEY) {
            let user = username_from_url.unwrap_or("git");
            if let Ok(cred) = Cred::ssh_key_from_agent(user) {
                return Ok(cred);
            }
        }

        if allowed_types.contains(CredentialType::USER_PASS_PLAINTEXT) {
            if let Some(ref token) = https_token {
                let user = username_from_url.unwrap_or("git");
                return Cred::userpass_plaintext(user, token);
            }
        }

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
        if std::env::var("BALUARD_GIT_TOKEN").is_ok() {
            assert!(config.https_token.is_some());
        } else {
            assert!(config.https_token.is_some());
            assert_eq!(config.expose_token().as_deref(), Some("ghp_test123"));
        }
    }

    #[test]
    fn scrub_removes_url_userinfo() {
        let msg = "transport error: https://git:ghp_abc123def@github.com/user/repo.git";
        let cleaned = scrub_git_error(msg);
        assert!(!cleaned.contains("ghp_abc123def"), "PAT not scrubbed: {cleaned}");
        assert!(cleaned.contains("***@github.com"), "URL structure lost: {cleaned}");
    }

    #[test]
    fn scrub_removes_pat_prefixes() {
        let msg = "authentication failed: token ghp_ABCDEF123456";
        let cleaned = scrub_git_error(msg);
        assert!(!cleaned.contains("ghp_"), "PAT prefix not scrubbed: {cleaned}");

        let msg2 = "error: glpat-XXXXXXXXXXXX";
        let cleaned2 = scrub_git_error(msg2);
        assert!(!cleaned2.contains("glpat-"), "GitLab PAT not scrubbed: {cleaned2}");
    }

    #[test]
    fn scrub_preserves_safe_errors() {
        let msg = "failed to set local git user.name: config error";
        assert_eq!(scrub_git_error(msg), msg);
    }
}
