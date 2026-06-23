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
            Self::GitHub | Self::GitLab => "device-flow",
            Self::Codeberg => "web-oauth",
        }
    }

    /// Default scopes for this provider.
    pub fn default_scopes(&self) -> &'static str {
        match self {
            Self::GitHub => "repo",
            // GitLab POST /projects requires the `api` scope (read_repository /
            // write_repository are insufficient for repo creation). `api` is
            // broad but unavoidable for a managed-sync client; user consents
            // at OAuth/PAT time.
            Self::GitLab => "api",
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

    /// Default public instance base URL (no trailing slash).
    pub fn default_instance_url(&self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::GitLab => "https://gitlab.com",
            Self::Codeberg => "https://codeberg.org",
        }
    }

    /// Default OAuth client_id (placeholder for GitLab/Codeberg until project
    /// apps are registered; GitHub is the real public client_id).
    pub fn default_client_id(&self) -> &'static str {
        match self {
            Self::GitHub => super::github::GITHUB_CLIENT_ID,
            Self::GitLab => "REPLACE_WITH_GITLAB_CLIENT_ID",
            Self::Codeberg => "REPLACE_WITH_CODEBERG_CLIENT_ID",
        }
    }
}

/// Provider connection config. `None` fields mean "use the provider's public
/// default". Overrides come from the Advanced Options UI and are persisted in
/// `ProviderInfo` so later operations reuse the same instance + client_id
/// (e.g. GitLab token refresh needs the original client_id).
///
/// One active instance per provider is supported in v1: switching instances
/// means disconnect + reconnect (new token overwrites the keyring entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderConfig {
    /// OAuth client_id override. `None` = `Provider::default_client_id()`.
    pub client_id: Option<String>,
    /// Instance base URL override (self-hosted GitLab/Forgejo). `None` =
    /// `Provider::default_instance_url()`.
    pub instance_url: Option<String>,
}

impl ProviderConfig {
    /// All defaults (public instance + project OAuth app).
    pub fn defaults() -> Self {
        Self::default()
    }

    /// Effective client_id: override or provider default.
    pub fn effective_client_id(&self, provider: Provider) -> String {
        self.client_id
            .clone()
            .unwrap_or_else(|| provider.default_client_id().to_string())
    }

    /// Effective instance base URL (no trailing slash): override or default.
    pub fn effective_instance_url(&self, provider: Provider) -> String {
        let url = self
            .instance_url
            .clone()
            .unwrap_or_else(|| provider.default_instance_url().to_string());
        url.trim_end_matches('/').to_string()
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
    /// Refresh token (GitLab/Codeberg OAuth). Also a credential: stored as
    /// SecretString so it cannot be cloned/format!-ed without ExposeSecret.
    /// Zeroized on drop via SecretString's own Drop.
    refresh_token: Option<SecretString>,
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
            refresh_token: self
                .refresh_token
                .as_ref()
                .map(|r| SecretString::new(r.expose_secret().to_string().into())),
            expires_at: self.expires_at,
            scopes: self.scopes.clone(),
        }
    }
}

impl Zeroize for ProviderToken {
    fn zeroize(&mut self) {
        // access_token + refresh_token are SecretString (own zeroize on drop).
        // Zeroize the remaining plaintext fields.
        self.expires_at.zeroize();
        self.scopes.zeroize();
    }
}

impl Drop for ProviderToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Custom serde: serialize secrets as plain strings (wrapped atomically in
// a SecretString for keyring storage via to_secret), deserialize into SecretString.
impl Serialize for ProviderToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ProviderToken", 4)?;
        s.serialize_field("access_token", self.access_token.expose_secret())?;
        s.serialize_field(
            "refresh_token",
            &self.refresh_token.as_ref().map(|r| r.expose_secret()),
        )?;
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
            refresh_token: h.refresh_token.map(|r| SecretString::new(r.into())),
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

    /// Create a token with expiry and refresh (GitLab/Codeberg OAuth style).
    pub fn with_refresh(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_at: u64,
        scopes: impl Into<String>,
    ) -> Self {
        Self {
            access_token: SecretString::new(access_token.into().into()),
            refresh_token: Some(SecretString::new(refresh_token.into().into())),
            expires_at: Some(expires_at),
            scopes: scopes.into(),
        }
    }

    /// Access the underlying access token. Requires `ExposeSecret` in scope.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Access the refresh token, if present. Requires `ExposeSecret` in scope.
    pub fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
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
    /// Instance base URL override (self-hosted). `None` = public default.
    /// Backward-compat: absent in old providers.json => public default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_url: Option<String>,
    /// OAuth client_id override. `None` = project default app.
    /// Backward-compat: absent in old providers.json => project default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl ProviderInfo {
    /// Build a `ProviderConfig` from the persisted overrides.
    pub fn config(&self) -> ProviderConfig {
        ProviderConfig {
            client_id: self.client_id.clone(),
            instance_url: self.instance_url.clone(),
        }
    }

    /// Effective instance base URL (no trailing slash).
    pub fn effective_instance_url(&self) -> String {
        self.config().effective_instance_url(self.provider)
    }

    /// Hostname of the connected instance (for display / keyring keying).
    pub fn instance_host(&self) -> String {
        self.effective_instance_url()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string()
    }
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

/// PKCE code_verifier: random 43-128 chars from the unreserved set
/// (RFC 7636 §4.1). Length randomized within the allowed range for entropy.
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let len: usize = rng.gen_range(43..=128);
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// PKCE S256 code_challenge: BASE64URL_NO_PAD(SHA256(verifier)).
pub fn code_challenge_s256(verifier: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Random CSRF state for OAuth (32 bytes hex-encoded).
pub fn generate_state() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// Current Unix timestamp in seconds. Shared helper used by providers
/// (avoids duplicating the SystemTime boilerplate per provider).
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Minimal percent-encoder for path/query segments. Encodes everything except
/// unreserved chars (RFC 3986). Shared helper used by providers.
pub(crate) fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Web-OAuth (authorization-code + PKCE) start response.
/// The code_verifier stays in daemon memory (never crosses IPC to the browser).
pub struct OAuthStart {
    /// Full authorization URL to open in the user's browser.
    pub auth_url: String,
    /// PKCE code_verifier (daemon retains, browser never sees it).
    pub code_verifier: String,
    /// CSRF state parameter (also returned by the provider redirect).
    pub state: String,
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

    /// Start a web-OAuth (auth-code + PKCE) flow. Returns auth_url + PKCE
    /// state for the daemon to retain. Default: unsupported (device-flow
    /// providers don't need this).
    async fn oauth_start(&self, _redirect_uri: &str) -> Result<OAuthStart, ProviderError> {
        Err(ProviderError::Other(
            "web-OAuth not supported by this provider".into(),
        ))
    }

    /// Exchange an authorization code for tokens (completes web-OAuth).
    /// Default: unsupported.
    async fn oauth_exchange(
        &self,
        _code: &str,
        _code_verifier: &str,
        _redirect_uri: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        Err(ProviderError::Other(
            "web-OAuth not supported by this provider".into(),
        ))
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock provider for unit tests. All operations succeed with dummy data.
    /// `revoked_calls` counts how many times `revoke_token` was invoked —
    /// tests can share an `Arc<AtomicUsize>` between the factory and the
    /// assertion site to verify the trait method is called by the wiring.
    pub struct MockProvider {
        pub provider_type: Provider,
        pub revoked_calls: Arc<AtomicUsize>,
    }

    impl MockProvider {
        pub fn github() -> Self {
            Self {
                provider_type: Provider::GitHub,
                revoked_calls: Arc::new(AtomicUsize::new(0)),
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
                    instance_url: None,
                    client_id: None,
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
                instance_url: None,
                client_id: None,
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
            self.revoked_calls.fetch_add(1, Ordering::SeqCst);
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
