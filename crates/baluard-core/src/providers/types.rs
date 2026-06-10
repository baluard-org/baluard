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
}

impl PartialEq for DeviceFlowStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Pending, Self::Pending) => true,
            (Self::Expired, Self::Expired) => true,
            (Self::Success(a), Self::Success(b)) => a.access_token == b.access_token,
            _ => false,
        }
    }
}

impl Eq for DeviceFlowStatus {}

/// Provider token with zeroize-on-drop semantics.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ProviderToken {
    /// Access token (primary credential).
    pub access_token: String,
    /// Refresh token (GitLab uses this, GitHub doesn't).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix timestamp when token expires (None = never).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Scopes granted.
    pub scopes: String,
}

impl ProviderToken {
    /// Create a new non-expiring token (GitHub PAT style).
    pub fn new(access_token: impl Into<String>, scopes: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
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
            access_token: access_token.into(),
            refresh_token: Some(refresh_token.into()),
            expires_at: Some(expires_at),
            scopes: scopes.into(),
        }
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

    /// Convert to SecretString for keyring storage.
    pub fn to_secret(&self) -> SecretString {
        // Serialize full token for keyring storage (includes refresh + expiry)
        let json = serde_json::to_string(self).unwrap_or_default();
        SecretString::new(json.into())
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
    async fn get_authenticated_user(
        &self,
        token: &ProviderToken,
    ) -> Result<String, ProviderError>;

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
}
