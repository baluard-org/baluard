//! Shared types for git provider integration.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Supported git hosting providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    GitHub,
    GitLab,
    Codeberg,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GitHub => write!(f, "github"),
            Self::GitLab => write!(f, "gitlab"),
            Self::Codeberg => write!(f, "codeberg"),
        }
    }
}

impl Provider {
    /// All supported providers.
    pub fn all() -> &'static [Provider] {
        &[Provider::GitHub, Provider::GitLab, Provider::Codeberg]
    }

    /// Auth method label for this provider.
    pub fn auth_method(&self) -> &'static str {
        match self {
            Self::GitHub => "device-flow",
            Self::GitLab | Self::Codeberg => "pat",
        }
    }

    /// Default scopes for this provider.
    pub fn default_scopes(&self) -> &'static str {
        match self {
            Self::GitHub => "repo",
            Self::GitLab => "read_repository write_repository",
            Self::Codeberg => "repository",
        }
    }

    /// Token generation URL for PAT providers.
    pub fn token_url(&self) -> Option<&'static str> {
        match self {
            Self::GitHub => Some("https://github.com/settings/tokens/new"),
            Self::GitLab => Some("https://gitlab.com/-/user_settings/personal_access_tokens"),
            Self::Codeberg => Some("https://codeberg.org/user/settings/applications"),
        }
    }
}

/// Device flow session (step 1 response, step 2 input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFlowSession {
    /// Provider this session belongs to.
    pub provider: Provider,
    /// User code displayed to user (e.g., "ABCD-1234").
    pub user_code: String,
    /// URL the user visits to enter the code.
    pub verification_uri: String,
    /// Device code used for polling (never shown to user).
    pub device_code: String,
    /// Polling interval in seconds.
    pub interval_secs: u64,
    /// Unix timestamp when this session expires.
    pub expires_at: u64,
}

/// Device flow polling status (step 2 response).
#[derive(Debug, Clone)]
pub enum DeviceFlowStatus {
    /// User hasn't entered the code yet. Keep polling.
    Pending,
    /// Auth successful. Token ready.
    Success(ProviderToken),
    /// User denied or code expired. Start over.
    Expired,
    /// Server asked to slow down. Caller must update session.interval_secs
    /// to the value in this variant (RFC 8628 §3.5: add 5 seconds, then
    /// continue polling at the new interval).
    SlowDown { interval_secs: u64 },
}

/// Provider token with zeroize-on-drop semantics.
///
/// `access_token` is stored as `SecretString` to prevent accidental logging.
/// Use `access_token()` to retrieve it (requires `ExposeSecret` in scope).
pub struct ProviderToken {
    /// Access token (primary credential). Never logged or printed.
    access_token: SecretString,
    /// Refresh token (GitLab uses this, GitHub doesn't).
    pub refresh_token: Option<String>,
    /// Unix timestamp when token expires (None = never).
    pub expires_at: Option<u64>,
    /// Scopes granted.
    pub scopes: String,
}

// Manual Debug to avoid printing secrets.
impl std::fmt::Debug for ProviderToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderToken")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Clone for ProviderToken {
    fn clone(&self) -> Self {
        Self {
            access_token: SecretString::new(self.access_token.expose_secret().to_string().into()),
            refresh_token: self.refresh_token.clone(),
            expires_at: self.expires_at,
            scopes: self.scopes.clone(),
        }
    }
}

impl Zeroize for ProviderToken {
    fn zeroize(&mut self) {
        // SecretString handles its own zeroize, but zeroize the other fields
        self.refresh_token.zeroize();
        self.expires_at.zeroize();
        self.scopes.zeroize();
    }
}

impl Drop for ProviderToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Custom serde: serialize access_token as plain string, deserialize into SecretString.
impl Serialize for ProviderToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ProviderToken", 4)?;
        s.serialize_field("access_token", self.access_token.expose_secret())?;
        s.serialize_field("refresh_token", &self.refresh_token)?;
        s.serialize_field("expires_at", &self.expires_at)?;
        s.serialize_field("scopes", &self.scopes)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ProviderToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            access_token: String,
            refresh_token: Option<String>,
            expires_at: Option<u64>,
            scopes: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            access_token: SecretString::new(h.access_token.into()),
            refresh_token: h.refresh_token,
            expires_at: h.expires_at,
            scopes: h.scopes,
        })
    }
}

impl ProviderToken {
    /// Create a new non-expiring token (GitHub PAT style).
    pub fn new(access_token: impl Into<String>, scopes: impl Into<String>) -> Self {
        Self {
            access_token: SecretString::new(access_token.into().into()),
            refresh_token: None,
            expires_at: None,
            scopes: scopes.into(),
        }
    }

    /// Create a token with expiry and refresh (GitLab OAuth style).
    pub fn with_refresh(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_at: u64,
        scopes: impl Into<String>,
    ) -> Self {
        Self {
            access_token: SecretString::new(access_token.into().into()),
            refresh_token: Some(refresh_token.into()),
            expires_at: Some(expires_at),
            scopes: scopes.into(),
        }
    }

    /// Access the underlying token string. Requires `ExposeSecret` in scope.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Check if token is expired or about to expire (5 min buffer).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now + 300 >= exp
            }
            None => false,
        }
    }

    /// Serialize for keyring storage. Returns all fields as JSON.
    pub fn to_secret(&self) -> Result<SecretString, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(SecretString::new(json.into()))
    }

    /// Deserialize from keyring secret string.
    pub fn from_secret(secret: &SecretString) -> Result<Self, serde_json::Error> {
        serde_json::from_str(secret.expose_secret())
    }
}

/// Non-sensitive provider state (stored in providers.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider identifier.
    pub provider: Provider,
    /// Authenticated username.
    pub username: String,
    /// Scopes granted.
    pub scopes: String,
    /// Unix timestamp of connection.
    pub connected_at: u64,
}

/// A vault repo detected on a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRepo {
    /// Repository name.
    pub name: String,
    /// Full name (owner/repo).
    pub full_name: String,
    /// HTTPS clone URL.
    pub clone_url: String,
    /// Whether the repo is private.
    pub private: bool,
    /// Vault slug from .baluard marker, if detected.
    pub vault_slug: Option<String>,
    /// Vault ID from .baluard marker, if detected.
    pub vault_id: Option<String>,
}

/// Error type for provider operations.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("token expired")]
    TokenExpired,

    #[error("token validation failed: {0}")]
    TokenValidation(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("device flow expired")]
    DeviceFlowExpired,

    #[error("provider not connected")]
    NotConnected,

    #[error("repo not found: {0}")]
    RepoNotFound(String),

    #[error("repo is public (safety abort): {0}")]
    RepoPublic(String),

    #[error("{0}")]
    Other(String),
}

/// The ForgeProvider trait: async interface for all git hosting providers.
///
/// Two-phase device flow: `device_flow_start` returns session info,
/// `device_flow_poll` checks status until success/expired.
/// PAT auth: `authenticate_pat` validates and stores token.
#[async_trait::async_trait]
pub trait ForgeProvider: Send + Sync {
    /// Which provider this implementation handles.
    fn provider(&self) -> Provider;

    /// Start a device flow session. Returns session info for user.
    async fn device_flow_start(&self) -> Result<DeviceFlowSession, ProviderError>;

    /// Poll device flow status. Call repeatedly until Success or Expired.
    async fn device_flow_poll(
        &self,
        session: &DeviceFlowSession,
    ) -> Result<DeviceFlowStatus, ProviderError>;

    /// Authenticate with a personal access token. Validates against API.
    async fn authenticate_pat(
        &self,
        token: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError>;

    /// Validate a stored token is still valid by calling /user endpoint.
    async fn validate_token(&self, token: &ProviderToken) -> Result<ProviderInfo, ProviderError>;

    /// Get authenticated user's username.
    async fn get_authenticated_user(&self, token: &ProviderToken) -> Result<String, ProviderError>;

    /// List user's repositories (paginated).
    async fn list_repos(
        &self,
        token: &ProviderToken,
        page: u8,
        per_page: u8,
    ) -> Result<Vec<VaultRepo>, ProviderError>;

    /// Detect vault repos (containing .baluard marker).
    async fn detect_vault_repos(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError>;

    /// Create a private repository. Returns error if result is public.
    async fn create_private_repo(
        &self,
        token: &ProviderToken,
        name: &str,
    ) -> Result<VaultRepo, ProviderError>;

    /// Attempt to revoke a token at the provider. Non-blocking on failure.
    async fn revoke_token(&self, token: &ProviderToken) -> Result<(), ProviderError>;

    /// Refresh an expiring token. No-op for providers with non-expiring tokens (GitHub).
    /// Returns Ok(None) if no refresh was needed, Ok(Some(new_token)) if refreshed.
    async fn refresh_token(
        &self,
        token: &ProviderToken,
    ) -> Result<Option<ProviderToken>, ProviderError>;
}

#[cfg(test)]
pub mod mock {
    use super::*;

    /// Mock provider for unit tests. All operations succeed with dummy data.
    pub struct MockProvider {
        pub provider_type: Provider,
    }

    impl MockProvider {
        pub fn github() -> Self {
            Self {
                provider_type: Provider::GitHub,
            }
        }
    }

    #[async_trait::async_trait]
    impl ForgeProvider for MockProvider {
        fn provider(&self) -> Provider {
            self.provider_type
        }

        async fn device_flow_start(&self) -> Result<DeviceFlowSession, ProviderError> {
            Ok(DeviceFlowSession {
                provider: self.provider_type,
                user_code: "MOCK-CODE".into(),
                verification_uri: "https://github.com/login/device".into(),
                device_code: "mock-device-code".into(),
                interval_secs: 1,
                expires_at: u64::MAX,
            })
        }

        async fn device_flow_poll(
            &self,
            _session: &DeviceFlowSession,
        ) -> Result<DeviceFlowStatus, ProviderError> {
            Ok(DeviceFlowStatus::Success(ProviderToken::new(
                "mock-token",
                "repo",
            )))
        }

        async fn authenticate_pat(
            &self,
            _token: &str,
        ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Ok((
                ProviderToken::new("mock-token", "repo"),
                ProviderInfo {
                    provider: self.provider_type,
                    username: "mock-user".into(),
                    scopes: "repo".into(),
                    connected_at: now,
                },
            ))
        }

        async fn validate_token(
            &self,
            _token: &ProviderToken,
        ) -> Result<ProviderInfo, ProviderError> {
            Ok(ProviderInfo {
                provider: self.provider_type,
                username: "mock-user".into(),
                scopes: "repo".into(),
                connected_at: 0,
            })
        }

        async fn get_authenticated_user(
            &self,
            _token: &ProviderToken,
        ) -> Result<String, ProviderError> {
            Ok("mock-user".into())
        }

        async fn list_repos(
            &self,
            _token: &ProviderToken,
            _page: u8,
            _per_page: u8,
        ) -> Result<Vec<VaultRepo>, ProviderError> {
            Ok(vec![])
        }

        async fn detect_vault_repos(
            &self,
            _token: &ProviderToken,
        ) -> Result<Vec<VaultRepo>, ProviderError> {
            Ok(vec![])
        }

        async fn create_private_repo(
            &self,
            _token: &ProviderToken,
            name: &str,
        ) -> Result<VaultRepo, ProviderError> {
            Ok(VaultRepo {
                name: name.into(),
                full_name: format!("mock-user/{name}"),
                clone_url: format!("https://github.com/mock-user/{name}.git"),
                private: true,
                vault_slug: None,
                vault_id: None,
            })
        }

        async fn revoke_token(&self, _token: &ProviderToken) -> Result<(), ProviderError> {
            Ok(())
        }

        async fn refresh_token(
            &self,
            _token: &ProviderToken,
        ) -> Result<Option<ProviderToken>, ProviderError> {
            Ok(None)
        }
    }
}
