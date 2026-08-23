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

/// Path for file-based token fallback when OS keyring is unavailable.
fn token_file_path(key: &str) -> PathBuf {
    data_dir().join("tokens").join(format!("{key}.json"))
}

/// True when this build has a real, persistent OS keyring backend.
///
/// `keyring` 3.x only ships stores for macOS/iOS (apple-native), Windows
/// (windows-native) and Linux/BSD (secret-service / keyutils). On every other
/// target (**Android included**) `keyring::default` resolves to
/// `keyring::mock`, whose `set_password` returns `Ok(())` and writes into an
/// in-memory cell owned by that one `Entry`. The value is dropped with the
/// `Entry`, so a mock write is a silent black hole: the store reports success
/// and the next read returns `NoEntry`. Gate on the target instead of trusting
/// the `Ok`, so unsupported platforms go straight to the app-private file.
/// Mirrors the target list in `keyring::lib.rs` that resolves to a real store
/// (the workspace enables apple-native + windows-native + linux-native-sync-
/// persistent, so target_os alone decides).
const fn keyring_is_persistent() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
    ))
}

/// Write `secret` to the app-private token file with owner-only permissions from the
/// first byte (no world-readable window; audit C25).
fn store_token_file(key: &str, secret: &str) -> Result<(), super::types::ProviderError> {
    let path = token_file_path(key);
    crate::secret_file::write_secret_file(&path, secret.as_bytes())
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))
}

/// Store a provider token in the OS keyring, falling back to a 0600 file if keyring is unavailable.
pub fn store_token(
    provider: Provider,
    username: &str,
    token: &ProviderToken,
) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    let secret = token
        .to_secret()
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;

    // No real keyring on this target (Android, …): the mock store would answer
    // Ok and drop the token, so go straight to the app-private file.
    if !keyring_is_persistent() {
        return store_token_file(&key, secret.expose_secret());
    }

    let keyring_result = keyring::Entry::new("baluard", &key)
        .map_err(|e| keyring_error(&e))
        .and_then(|entry| {
            entry
                .set_password(secret.expose_secret())
                .map_err(|e| keyring_error(&e))
        });

    if keyring_result.is_err() {
        // Keyring present but unusable (headless session, locked collection):
        // fall back to the app-private token file with 0600 permissions.
        return store_token_file(&key, secret.expose_secret());
    }
    // Keyring took it; drop any stale fallback copy so the two can't diverge.
    let _ = std::fs::remove_file(token_file_path(&key));
    Ok(())
}

/// Retrieve a provider token from the OS keyring or fallback file.
pub fn load_token(
    provider: Provider,
    username: &str,
) -> Result<ProviderToken, super::types::ProviderError> {
    let key = keyring_key(provider, username);

    // Try OS keyring first (skipped where it is a no-op mock store).
    if keyring_is_persistent() {
        if let Ok(entry) = keyring::Entry::new("baluard", &key) {
            if let Ok(secret_str) = entry.get_password() {
                let secret = SecretString::new(secret_str.into());
                if let Ok(tok) = ProviderToken::from_secret(&secret) {
                    return Ok(tok);
                }
            }
        }
    }

    // Fallback: load from token file
    let path = token_file_path(&key);
    if path.exists() {
        let secret_str = std::fs::read_to_string(&path)
            .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
        let secret = SecretString::new(secret_str.trim().to_string().into());
        return ProviderToken::from_secret(&secret)
            .map_err(|e| super::types::ProviderError::Keyring(e.to_string()));
    }

    Err(super::types::ProviderError::Keyring(format!(
        "Token for provider {provider} (user {username}) not found in keyring or fallback store"
    )))
}

/// Delete a provider token from the OS keyring and fallback file.
pub fn delete_token(provider: Provider, username: &str) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    if let Ok(entry) = keyring::Entry::new("baluard", &key) {
        let _ = entry.delete_credential();
    }
    let path = token_file_path(&key);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// Full provider disconnect: delete keyring token + remove from providers.json.
pub fn disconnect(provider: Provider) -> Result<(), super::types::ProviderError> {
    let mut state =
        ProvidersState::load().map_err(|e| super::types::ProviderError::Io(e.to_string()))?;

    if let Some(info) = state.remove(provider) {
        // Best-effort keyring / file deletion
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
            instance_url: None,
            client_id: None,
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
        assert_eq!(keyring_key(Provider::GitLab, "bob"), "baluard-gitlab-bob");
    }

    #[test]
    fn token_serialization_round_trip() {
        use secrecy::ExposeSecret;
        let token = ProviderToken::new("ghp_test123", "repo");
        let secret = token.to_secret().unwrap();
        let restored = ProviderToken::from_secret(&secret).unwrap();
        assert_eq!(restored.access_token().expose_secret(), "ghp_test123");
        assert_eq!(restored.scopes, "repo");
        assert!(restored.refresh_token().is_none());
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
