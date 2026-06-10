//! Token storage: OS keyring for secrets, providers.json for metadata.
//!
//! Keyring entry: `baluard-<provider>-<username>`
//! providers.json: `<data_dir>/providers.json` (non-sensitive state)

use std::collections::HashMap;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::types::{Provider, ProviderInfo, ProviderToken};
use crate::paths::data_dir;

/// Non-sensitive provider state file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvidersState {
    /// Schema version for forward compatibility.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Map of "provider" -> ProviderInfo.
    #[serde(flatten)]
    pub providers: HashMap<String, ProviderInfo>,
}

fn default_version() -> u32 {
    1
}

impl Default for ProvidersState {
    fn default() -> Self {
        Self {
            version: 1,
            providers: HashMap::new(),
        }
    }
}

impl ProvidersState {
    /// Path to providers.json.
    pub fn path() -> PathBuf {
        data_dir().join("providers.json")
    }

    /// Load from disk. Returns empty if file doesn't exist.
    pub fn load() -> Result<Self, std::io::Error> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let state: ProvidersState = serde_json::from_str(&data)?;
        Ok(state)
    }

    /// Save to disk atomically with 0600 permissions.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Get info for a provider.
    pub fn get(&self, provider: Provider) -> Option<&ProviderInfo> {
        self.providers.get(&provider.to_string())
    }

    /// Upsert provider info.
    pub fn set(&mut self, info: ProviderInfo) {
        self.providers.insert(info.provider.to_string(), info);
    }

    /// Remove provider info.
    pub fn remove(&mut self, provider: Provider) -> Option<ProviderInfo> {
        self.providers.remove(&provider.to_string())
    }
}

/// Keyring key format: `baluard-<provider>-<username>`
fn keyring_key(provider: Provider, username: &str) -> String {
    format!("baluard-{}-{}", provider, username)
}

/// Wrap keyring errors with headless environment hint.
fn keyring_error(e: &keyring::Error) -> super::types::ProviderError {
    super::types::ProviderError::Keyring(format!(
        "{e}. Keyring unavailable in headless/CI environments. \
         Use `baluard --direct provider connect-pat` with a PAT instead."
    ))
}

/// Store a provider token in the OS keyring.
///
/// Returns `ProviderError::Keyring` with a hint about headless environments
/// if the OS keyring is unavailable.
pub fn store_token(
    provider: Provider,
    username: &str,
    token: &ProviderToken,
) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    let secret = token.to_secret().map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
    let entry = keyring::Entry::new("baluard", &key)
        .map_err(|e| keyring_error(&e))?;
    entry
        .set_password(secret.expose_secret())
        .map_err(|e| keyring_error(&e))?;
    Ok(())
}

/// Retrieve a provider token from the OS keyring.
pub fn load_token(
    provider: Provider,
    username: &str,
) -> Result<ProviderToken, super::types::ProviderError> {
    let key = keyring_key(provider, username);
    let entry = keyring::Entry::new("baluard", &key)
        .map_err(|e| keyring_error(&e))?;
    let secret_str = entry
        .get_password()
        .map_err(|e| keyring_error(&e))?;
    let secret = SecretString::new(secret_str.into());
    ProviderToken::from_secret(&secret)
        .map_err(|e| super::types::ProviderError::Keyring(e.to_string()))
}

/// Delete a provider token from the OS keyring.
pub fn delete_token(
    provider: Provider,
    username: &str,
) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    let entry = keyring::Entry::new("baluard", &key)
        .map_err(|e| keyring_error(&e))?;
    entry
        .delete_credential()
        .map_err(|e| keyring_error(&e))?;
    Ok(())
}

/// Full provider disconnect: delete keyring token + remove from providers.json.
pub fn disconnect(provider: Provider) -> Result<(), super::types::ProviderError> {
    let mut state = ProvidersState::load()
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;

    if let Some(info) = state.remove(provider) {
        // Best-effort keyring deletion
        let _ = delete_token(provider, &info.username);
    }

    state
        .save()
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_state_round_trip() {
        let dir = std::env::temp_dir().join("baluard-test-providers-state");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Override data_dir for test
        let path = dir.join("providers.json");
        let mut state = ProvidersState::default();
        state.set(ProviderInfo {
            provider: Provider::GitHub,
            username: "testuser".into(),
            scopes: "repo".into(),
            connected_at: 1700000000,
        });

        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&path, &json).unwrap();

        let loaded: ProvidersState =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.providers.len(), 1);
        assert_eq!(loaded.get(Provider::GitHub).unwrap().username, "testuser");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyring_key_format() {
        assert_eq!(
            keyring_key(Provider::GitHub, "alice"),
            "baluard-github-alice"
        );
        assert_eq!(
            keyring_key(Provider::GitLab, "bob"),
            "baluard-gitlab-bob"
        );
    }

    #[test]
    fn token_serialization_round_trip() {
        use secrecy::ExposeSecret;
        let token = ProviderToken::new("ghp_test123", "repo");
        let secret = token.to_secret().unwrap();
        let restored = ProviderToken::from_secret(&secret).unwrap();
        assert_eq!(restored.access_token().expose_secret(), "ghp_test123");
        assert_eq!(restored.scopes, "repo");
        assert!(restored.refresh_token.is_none());
        assert!(restored.expires_at.is_none());
    }

    #[test]
    fn token_expiry_check() {
        let mut token = ProviderToken::new("test", "repo");
        assert!(!token.is_expired()); // no expiry = never expired

        token.expires_at = Some(100); // way in the past
        assert!(token.is_expired());
    }
}
