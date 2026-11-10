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

/// GitHub OAuth app client secret. Deliberately embedded: a desktop app
/// cannot keep a secret (the same trade as the gh CLI), and the token it
/// guards is the app identity, not user data. Rotate via the GitHub app
/// settings; `BALUARD_GITHUB_CLIENT_SECRET` overrides for development.
const GITHUB_CLIENT_SECRET: Option<&str> = Some("73a95d04c148979e451c672f5e6abba3d2904c0e");

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

    /// Whether the provider implements the web application flow (loopback
    /// redirect + PKCE). GitHub ships it for mobile/desktop browsers; Codeberg
    /// is web-only; GitLab is device-flow only today.
    pub fn supports_web_oauth(&self) -> bool {
        matches!(self, Self::GitHub | Self::Codeberg)
    }

    /// Embedded default client_secret for web-flow token exchange.
    /// GitHub's OAuth app requires a secret at exchange time (there is no
    /// PKCE-only mode); native-app secrets are not truly confidential and
    /// shipping them is the norm for GitHub apps (the gh CLI does the same).
    /// The app registration's secret is embedded for GitHub; the env var
    /// `BALUARD_GITHUB_CLIENT_SECRET` overrides it per invocation.
    pub fn default_client_secret(&self) -> Option<&'static str> {
        match self {
            Self::GitHub => GITHUB_CLIENT_SECRET,
            Self::GitLab | Self::Codeberg => None,
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

    /// Resolved OAuth client_id with this priority chain:
    /// 1. `BALUARD_GITHUB_CLIENT_ID` / `BALUARD_GITLAB_CLIENT_ID` /
    ///    `BALUARD_CODEBERG_CLIENT_ID` env var (loaded from process env,
    ///    which `dotenvy` populates from `.env` at startup). Empty string
    ///    is treated as unset.
    /// 2. The value baked at compile time from the same variable via
    ///    `option_env!`: release builds run with the env sourced, so the
    ///    real project app ID ships inside the binary. Builds without it
    ///    (fresh clones, CI) keep the placeholder.
    ///
    /// Client IDs are public identifiers, safe to embed. The
    /// BALUARD_*_CLIENT_SECRET vars are NOT consumed this way: GitLab
    /// (device flow) and Codeberg (PKCE) are public clients that must not
    /// send a secret.
    ///
    /// Returns `String` (not `&'static str`) because env-var reads are
    /// owned. Callers that need the embedded default without env influence
    /// (e.g. tests) can compare against the consts directly.
    pub fn default_client_id(&self) -> String {
        let env_var = match self {
            Self::GitHub => "BALUARD_GITHUB_CLIENT_ID",
            Self::GitLab => "BALUARD_GITLAB_CLIENT_ID",
            Self::Codeberg => "BALUARD_CODEBERG_CLIENT_ID",
        };
        std::env::var(env_var)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| match self {
                Self::GitHub => super::github::GITHUB_CLIENT_ID.to_string(),
                Self::GitLab => option_env!("BALUARD_GITLAB_CLIENT_ID")
                    .filter(|s| !s.is_empty())
                    .unwrap_or(GITLAB_CLIENT_ID_PLACEHOLDER)
                    .to_string(),
                Self::Codeberg => option_env!("BALUARD_CODEBERG_CLIENT_ID")
                    .filter(|s| !s.is_empty())
                    .unwrap_or(CODEBERG_CLIENT_ID_PLACEHOLDER)
                    .to_string(),
            })
    }
}

/// Sentinels that keep builds without the provider env functional: OAuth
/// starts with these ID would 404 at the forge, so flows refuse them via
/// `ensure_client_id_configured`.
pub const GITLAB_CLIENT_ID_PLACEHOLDER: &str = "REPLACE_WITH_GITLAB_CLIENT_ID";
pub const CODEBERG_CLIENT_ID_PLACEHOLDER: &str = "REPLACE_WITH_CODEBERG_CLIENT_ID";

/// Refuse OAuth starts whose client_id is blank or an unconfigured sentinel.
/// Real project IDs are baked at compile time (`option_env!` in
/// `Provider::default_client_id`); reaching a placeholder here means a
/// plain build without `BALUARD_GITLAB_CLIENT_ID` / `BALUARD_CODEBERG_CLIENT_ID`.
pub fn ensure_client_id_configured(client_id: &str) -> Result<(), ProviderError> {
    let id = client_id.trim();
    if id.is_empty() || id == GITLAB_CLIENT_ID_PLACEHOLDER || id == CODEBERG_CLIENT_ID_PLACEHOLDER {
        return Err(ProviderError::Other(
            "Sign-in is not configured for this provider. Connect with an access token instead."
                .into(),
        ));
    }
    Ok(())
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
    /// OAuth client_secret override for web-flow token exchange. `None` =
    /// env `BALUARD_<PROVIDER>_CLIENT_SECRET`, then the embedded default
    /// (GitHub needs a secret at exchange time; Forgejo public clients do not).
    pub client_secret: Option<String>,
    /// Instance base URL override (self-hosted GitLab/Forgejo). `None` =
    /// `Provider::default_instance_url()`.
    pub instance_url: Option<String>,
}

impl ProviderConfig {
    /// All defaults (public instance + project OAuth app).
    pub fn defaults() -> Self {
        Self::default()
    }

    /// Effective client_id: explicit override (`client_id` field), then
    /// the env-var-aware default. The env-var chain lives inside
    /// `Provider::default_client_id`.
    pub fn effective_client_id(&self, provider: Provider) -> String {
        self.client_id
            .clone()
            .unwrap_or_else(|| provider.default_client_id())
    }

    /// Effective instance base URL (no trailing slash): override or default.
    /// An override is sanitized before use: the scheme is forced to https
    /// (plain http needs the debug escape hatch) and userinfo, query and
    /// fragment components are dropped, so a mistyped instance can never
    /// carry the token in cleartext or to a URL-embedded account.
    pub fn effective_instance_url(&self, provider: Provider) -> String {
        let default = provider.default_instance_url().to_string();
        let url = match self.instance_url.as_deref() {
            None => return default.trim_end_matches('/').to_string(),
            Some(u) => u.trim().trim_end_matches('/'),
        };
        if url.is_empty() {
            return default.trim_end_matches('/').to_string();
        }
        let insecure = std::env::var("BALUARD_ALLOW_INSECURE_INSTANCE").is_ok();
        // Strip userinfo, query and fragment: keep scheme://host[:port]/path.
        let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        let authority_path = after_scheme.split(['?', '#']).next().unwrap_or("");
        // The authority ends at the first '/'; the host is what follows
        // the LAST '@' (userinfo cannot contain '/').
        let host_part = authority_path.split('/').next().unwrap_or("");
        let authority = host_part.rsplit('@').next().unwrap_or("");
        if authority.is_empty() {
            return default.trim_end_matches('/').to_string();
        }
        // Loopback servers (dev mock APIs, local forges) may stay http:
        // the traffic never leaves the machine. Anything else is forced
        // to https unless the debug escape hatch is set.
        let host_lower = authority.to_ascii_lowercase();
        let loopback = host_lower.starts_with("localhost")
            || host_lower.starts_with("127.0.0.1")
            || host_lower.starts_with("[::1]");
        let scheme = if (insecure || loopback) && !host_lower.starts_with("https://") {
            "http://"
        } else {
            "https://"
        };
        format!("{scheme}{authority}")
    }

    /// Effective client_secret for web-flow token exchange: explicit
    /// override, then the `BALUARD_<PROVIDER>_CLIENT_SECRET` env var, then
    /// the embedded default. `None` when the provider needs no secret
    /// (Forgejo public clients). Missing secret fails at exchange time with
    /// a plain-language error.
    pub fn effective_client_secret(&self, provider: Provider) -> Option<String> {
        if let Some(s) = self.client_secret.clone() {
            return Some(s);
        }
        let env_var = match provider {
            Provider::GitHub => "BALUARD_GITHUB_CLIENT_SECRET",
            Provider::GitLab => "BALUARD_GITLAB_CLIENT_SECRET",
            Provider::Codeberg => "BALUARD_CODEBERG_CLIENT_SECRET",
        };
        if let Ok(s) = std::env::var(env_var) {
            if !s.trim().is_empty() {
                return Some(s);
            }
        }
        provider.default_client_secret().map(str::to_string)
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
    /// The connected account's email as the provider reports it
    /// (GitLab/Codeberg return it under our existing scopes; GitHub
    /// hides it without the `user:email` scope, so `None` there).
    /// Local-device data only — it never syncs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OAuth client_id override. `None` = project default app.
    /// Backward-compat: absent in old providers.json => project default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl ProviderInfo {
    /// Build a `ProviderConfig` from the persisted overrides. Deliberately
    /// without a client_secret: secrets ride the env var or the embedded
    /// default, never the plaintext providers.json.
    pub fn config(&self) -> ProviderConfig {
        ProviderConfig {
            client_id: self.client_id.clone(),
            instance_url: self.instance_url.clone(),
            client_secret: None,
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

/// A repo deploy key as the forge reports it. Legacy contact kits arm
/// read-only keys only: the contact can clone, never push.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeployKey {
    /// Provider-assigned numeric id.
    pub id: u64,
    /// Key title as set at creation.
    pub title: String,
    /// OpenSSH public key material.
    pub key: String,
    /// Whether the key may push (Baluard always arms read-only keys).
    pub read_only: bool,
}

/// Transport seat level for a repo collaborator (P8c least-privilege
/// staging): pending joiners and viewers ride READ-only access (they must
/// clone to introduce), editors and above are granted WRITE at approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollaboratorPermission {
    /// Read-only seat (clone/pull only). Pending joiners + viewers.
    ReadOnly,
    /// Write seat (push). Editors and above, granted at approval.
    Write,
}

impl fmt::Display for CollaboratorPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read-only"),
            Self::Write => write!(f, "write"),
        }
    }
}

/// Forge-side seat state for one collaborator on one repository.
/// GitHub is the only provider with a real pending-acceptance state;
/// GitLab and Codeberg grant immediately (acceptance is a no-op).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollaboratorStatus {
    /// Seat granted and accepted (or provider grants immediately).
    Active,
    /// Invitation pending (GitHub; expires after 7 days server-side —
    /// an expired invite reports `None` and the caller re-invites).
    Invited,
    /// No seat of any kind.
    None,
}

impl fmt::Display for CollaboratorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Invited => write!(f, "invited"),
            Self::None => write!(f, "none"),
        }
    }
}

/// Error type for provider operations.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("token expired")]
    TokenExpired,

    #[error("temporary provider outage: {0}")]
    /// Retryable: 429/5xx/network. Must not clear stored credentials.
    Transient(String),

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

/// P8c: extract `(owner, repo)` from a clone URL for the collaborator
/// APIs. Handles `https://host/owner/repo(.git)`, `ssh://`, and
/// `git@host:owner/repo(.git)` forms. GitHub and Forgejo require exactly
/// two path segments; GitLab accepts nested subgroup paths (everything
/// but the last segment is the owner path). Returns None when the URL
/// does not match the provider's expected shape — callers treat that as
/// "no transport seat possible".
pub fn split_owner_repo(provider: Provider, url: &str) -> Option<(String, String)> {
    let s = url.trim();
    let s = s.strip_suffix('/').unwrap_or(s);
    let s = s.strip_suffix(".git").unwrap_or(s);
    let path = if let Some(pos) = s.find("://") {
        let rest = &s[pos + 3..];
        let start = rest.find('/')?;
        &rest[start + 1..]
    } else {
        let at = s.rfind('@')?;
        let colon = s[at..].find(':')?;
        &s[at + colon + 1..]
    };
    let path = path.trim_start_matches('/').trim_end_matches('/');
    if path.is_empty() {
        return None;
    }
    let mut segments: Vec<&str> = path.split('/').collect();
    let repo = segments.pop()?;
    if repo.is_empty() {
        return None;
    }
    match provider {
        // GitHub and Forgejo repos are strictly owner/repo.
        Provider::GitHub | Provider::Codeberg => {
            if segments.len() != 1 {
                return None;
            }
            let owner = segments[0];
            if owner.is_empty() {
                return None;
            }
            Some((owner.to_string(), repo.to_string()))
        }
        // GitLab supports nested subgroups: the full path minus the last
        // segment is the project owner path.
        Provider::GitLab => {
            if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
                return None;
            }
            Some((segments.join("/"), repo.to_string()))
        }
    }
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

    /// Delete a repository by owner and name.
    async fn delete_repo(
        &self,
        token: &ProviderToken,
        owner: &str,
        name: &str,
    ) -> Result<(), ProviderError>;

    /// Grant (or upgrade) a collaborator seat on a repo. P8c staging:
    /// pending joiners ride `ReadOnly`, approved editors ride `Write`.
    /// Returns the seat state AFTER the call (GitHub reports `Invited`
    /// for a fresh invitation, `Active` when the seat exists already).
    async fn add_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
        permission: CollaboratorPermission,
    ) -> Result<CollaboratorStatus, ProviderError>;

    /// Query the seat state for one username on one repo. Used by the
    /// join-approval pre-flight and the offboarding pre-flight.
    async fn collaborator_status(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
    ) -> Result<CollaboratorStatus, ProviderError>;

    /// Strike a collaborator seat. Idempotent: removing a username with
    /// no seat succeeds (removal pre-flight must not wedge on retries).
    async fn remove_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
    ) -> Result<(), ProviderError>;

    /// Arm a read-only deploy key on a repo. Legacy contact kits carry
    /// the matching private half, so the contact can clone without a
    /// forge account of their own. Returns the provider-assigned key id.
    async fn add_deploy_key(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> Result<u64, ProviderError>;

    /// List a repo's deploy keys. Used to find a stale Baluard key on
    /// re-arm before minting a replacement.
    async fn list_deploy_keys(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<DeployKey>, ProviderError>;

    /// Remove a deploy key by provider id. Idempotent: removing an
    /// absent key succeeds so disarm retries never wedge.
    async fn remove_deploy_key(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        key_id: u64,
    ) -> Result<(), ProviderError>;

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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Mock provider for unit tests. All operations succeed with dummy data.
    /// `revoked_calls` counts how many times `revoke_token` was invoked and
    /// `deleted_calls` counts how many times `delete_repo` was invoked, tests
    /// can share an `Arc<AtomicUsize>` between the factory and the assertion
    /// site to verify the trait method is called by the wiring. `seat_log`
    /// records collaborator ops as `"add:o/r:user:read-only"`-style strings;
    /// `seat_status` is the canned `collaborator_status`/`add_collaborator`
    /// answer.
    pub struct MockProvider {
        pub provider_type: Provider,
        pub revoked_calls: Arc<AtomicUsize>,
        pub deleted_calls: Arc<AtomicUsize>,
        pub seat_log: Arc<Mutex<Vec<String>>>,
        pub seat_status: CollaboratorStatus,
        /// When true, add_deploy_key fails like a PAT lacking the scope.
        pub fail_deploy_key: bool,
    }

    impl MockProvider {
        pub fn github() -> Self {
            Self {
                provider_type: Provider::GitHub,
                revoked_calls: Arc::new(AtomicUsize::new(0)),
                deleted_calls: Arc::new(AtomicUsize::new(0)),
                seat_log: Arc::new(Mutex::new(Vec::new())),
                seat_status: CollaboratorStatus::Active,
                fail_deploy_key: false,
            }
        }

        fn record(&self, line: String) {
            self.seat_log.lock().unwrap().push(line);
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
                    email: None,
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
                email: None,
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

        async fn delete_repo(
            &self,
            _token: &ProviderToken,
            _owner: &str,
            _name: &str,
        ) -> Result<(), ProviderError> {
            self.deleted_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn add_collaborator(
            &self,
            _token: &ProviderToken,
            owner: &str,
            repo: &str,
            username: &str,
            permission: CollaboratorPermission,
        ) -> Result<CollaboratorStatus, ProviderError> {
            self.record(format!("add:{owner}/{repo}:{username}:{permission}"));
            Ok(self.seat_status)
        }

        async fn collaborator_status(
            &self,
            _token: &ProviderToken,
            owner: &str,
            repo: &str,
            username: &str,
        ) -> Result<CollaboratorStatus, ProviderError> {
            self.record(format!("status:{owner}/{repo}:{username}"));
            Ok(self.seat_status)
        }

        async fn remove_collaborator(
            &self,
            _token: &ProviderToken,
            owner: &str,
            repo: &str,
            username: &str,
        ) -> Result<(), ProviderError> {
            self.record(format!("remove:{owner}/{repo}:{username}"));
            Ok(())
        }

        async fn add_deploy_key(
            &self,
            _token: &ProviderToken,
            owner: &str,
            repo: &str,
            _title: &str,
            _public_key: &str,
        ) -> Result<u64, ProviderError> {
            if self.fail_deploy_key {
                return Err(ProviderError::Api(
                    "403: the token lacks the deploy key scope".into(),
                ));
            }
            self.record(format!("addkey:{owner}/{repo}"));
            Ok(4242)
        }

        async fn list_deploy_keys(
            &self,
            _token: &ProviderToken,
            _owner: &str,
            _repo: &str,
        ) -> Result<Vec<DeployKey>, ProviderError> {
            Ok(Vec::new())
        }

        async fn remove_deploy_key(
            &self,
            _token: &ProviderToken,
            owner: &str,
            repo: &str,
            _key_id: u64,
        ) -> Result<(), ProviderError> {
            self.record(format!("delkey:{owner}/{repo}"));
            Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that mutate the `BALUARD_*_CLIENT_ID` env vars.
    /// `cargo test` runs unit tests in parallel; concurrent `set_var` on
    /// the same key is a data race (Rust 1.85 marks `set_var` `unsafe`).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Save a snapshot of the three client_id env vars and return a closure
    /// that restores them. Used with `ENV_LOCK` to keep tests independent.
    fn snapshot_client_id_env() -> impl Drop {
        struct Restore {
            github: Option<String>,
            gitlab: Option<String>,
            codeberg: Option<String>,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                restore("BALUARD_GITHUB_CLIENT_ID", self.github.take());
                restore("BALUARD_GITLAB_CLIENT_ID", self.gitlab.take());
                restore("BALUARD_CODEBERG_CLIENT_ID", self.codeberg.take());
            }
        }
        fn restore(key: &str, val: Option<String>) {
            match val {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        Restore {
            github: std::env::var("BALUARD_GITHUB_CLIENT_ID").ok(),
            gitlab: std::env::var("BALUARD_GITLAB_CLIENT_ID").ok(),
            codeberg: std::env::var("BALUARD_CODEBERG_CLIENT_ID").ok(),
        }
    }

    #[test]
    fn client_id_guard_accepts_real_and_rejects_blank_or_placeholder() {
        assert!(ensure_client_id_configured("real-client-id").is_ok());
        assert!(ensure_client_id_configured(GITLAB_CLIENT_ID_PLACEHOLDER).is_err());
        assert!(ensure_client_id_configured(CODEBERG_CLIENT_ID_PLACEHOLDER).is_err());
        // .env ships blank assignments; a build shell that exports them
        // must not produce an empty client_id that bypasses the guard.
        assert!(ensure_client_id_configured("").is_err());
        assert!(ensure_client_id_configured("   ").is_err());
    }

    #[test]
    fn env_override_takes_precedence_over_embedded() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore = snapshot_client_id_env();

        unsafe { std::env::set_var("BALUARD_GITHUB_CLIENT_ID", "test-github-override") };
        assert_eq!(Provider::GitHub.default_client_id(), "test-github-override");

        unsafe { std::env::set_var("BALUARD_GITLAB_CLIENT_ID", "test-gitlab-override") };
        assert_eq!(Provider::GitLab.default_client_id(), "test-gitlab-override");

        unsafe { std::env::set_var("BALUARD_CODEBERG_CLIENT_ID", "test-codeberg-override") };
        assert_eq!(
            Provider::Codeberg.default_client_id(),
            "test-codeberg-override"
        );
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore = snapshot_client_id_env();

        // Empty string must not shadow the embedded default. A blank
        // value in `.env` is a user typo we should not honor.
        unsafe { std::env::set_var("BALUARD_GITHUB_CLIENT_ID", "") };
        assert_eq!(
            Provider::GitHub.default_client_id(),
            crate::providers::github::GITHUB_CLIENT_ID
        );
    }

    #[test]
    fn unset_env_falls_back_to_embedded() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore = snapshot_client_id_env();

        unsafe { std::env::remove_var("BALUARD_GITHUB_CLIENT_ID") };
        assert_eq!(
            Provider::GitHub.default_client_id(),
            crate::providers::github::GITHUB_CLIENT_ID
        );

        // GitLab/Codeberg fall back to the compile-time `option_env!` bake:
        // on a machine that builds with the env sourced this is the real
        // project app ID, elsewhere the placeholder. The test mirrors the
        // same expression, so it holds in both build environments.
        unsafe { std::env::remove_var("BALUARD_GITLAB_CLIENT_ID") };
        assert_eq!(
            Provider::GitLab.default_client_id(),
            option_env!("BALUARD_GITLAB_CLIENT_ID").unwrap_or(GITLAB_CLIENT_ID_PLACEHOLDER)
        );

        unsafe { std::env::remove_var("BALUARD_CODEBERG_CLIENT_ID") };
        assert_eq!(
            Provider::Codeberg.default_client_id(),
            option_env!("BALUARD_CODEBERG_CLIENT_ID").unwrap_or(CODEBERG_CLIENT_ID_PLACEHOLDER)
        );
    }

    #[test]
    fn effective_client_id_prefers_explicit_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore = snapshot_client_id_env();

        unsafe { std::env::set_var("BALUARD_GITHUB_CLIENT_ID", "from-env") };
        let config = ProviderConfig {
            client_id: Some("from-config".into()),
            instance_url: None,
            client_secret: None,
        };
        // Explicit `ProviderConfig.client_id` wins over env var (Advanced
        // Options override is the user's most deliberate choice).
        assert_eq!(config.effective_client_id(Provider::GitHub), "from-config");

        // No explicit override -> env var.
        let config = ProviderConfig::defaults();
        assert_eq!(config.effective_client_id(Provider::GitHub), "from-env");
    }

    #[test]
    fn split_owner_repo_handles_provider_shapes() {
        // GitHub: https + .git, exactly owner/repo.
        assert_eq!(
            split_owner_repo(Provider::GitHub, "https://github.com/o/r.git"),
            Some(("o".into(), "r".into()))
        );
        // Codeberg: git@ scp form.
        assert_eq!(
            split_owner_repo(Provider::Codeberg, "git@codeberg.org:o/r.git"),
            Some(("o".into(), "r".into()))
        );
        // ssh:// URL with a userinfo + port.
        assert_eq!(
            split_owner_repo(Provider::GitHub, "ssh://git@github.com:22/o/r.git"),
            Some(("o".into(), "r".into()))
        );
        // Trailing slash tolerated.
        assert_eq!(
            split_owner_repo(Provider::GitHub, "https://github.com/o/r/"),
            Some(("o".into(), "r".into()))
        );
        // GitLab nested subgroups: everything but the last segment is the
        // owner path.
        assert_eq!(
            split_owner_repo(Provider::GitLab, "https://gitlab.com/g/sub/r"),
            Some(("g/sub".into(), "r".into()))
        );
        // GitHub with subgroups is not a valid repo URL.
        assert_eq!(
            split_owner_repo(Provider::GitHub, "https://github.com/g/sub/r"),
            None
        );
        // Not a repo URL.
        assert_eq!(
            split_owner_repo(Provider::GitHub, "https://github.com"),
            None
        );
    }
}

/// Shared test double for the forge REST APIs: a real local HTTP server so
/// the collaborator ops run their actual reqwest request paths. Each test
/// scripts FIFO responses with `push`; every request is recorded as
/// `(method, path, body)` for assertions.
#[cfg(test)]
pub(crate) mod http_mock {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    pub struct MockApi {
        pub base_url: String,
        requests: Arc<Mutex<Vec<(String, String, String)>>>,
        responses: Arc<Mutex<VecDeque<(u16, String)>>>,
    }

    impl MockApi {
        /// Bind 127.0.0.1:0 and serve until process exit (tests are
        /// short-lived; the accept thread is detached).
        pub fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock api");
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
            let responses = Arc::new(Mutex::new(VecDeque::<(u16, String)>::new()));
            let (reqs, resps) = (requests.clone(), responses.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let (reqs, resps) = (reqs.clone(), resps.clone());
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 8192];
                        let mut raw = Vec::new();
                        // Read until the client is done writing this
                        // request (Connection: close semantics).
                        while let Ok(n) = stream.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            raw.extend_from_slice(&buf[..n]);
                            // Header terminator seen: request complete
                            // unless Content-Length exceeds what we have.
                            if let Some(pos) = find(&raw, b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&raw[..pos]).to_lowercase();
                                let len: usize = head
                                    .lines()
                                    .find_map(|l| {
                                        l.strip_prefix("content-length:")
                                            .map(|v| v.trim().parse().unwrap_or(0))
                                    })
                                    .unwrap_or(0);
                                if raw.len() >= pos + 4 + len {
                                    break;
                                }
                            }
                        }
                        let text = String::from_utf8_lossy(&raw);
                        let mut lines = text.lines();
                        let request_line = lines.next().unwrap_or_default().to_string();
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or_default().to_string();
                        let path = parts.next().unwrap_or_default().to_string();
                        let body = text
                            .split("\r\n\r\n")
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        reqs.lock().unwrap().push((method, path, body));
                        let (status, body) = resps
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or((500, "mock: no scripted response".into()));
                        let reason = match status {
                            200 => "OK",
                            201 => "Created",
                            204 => "No Content",
                            404 => "Not Found",
                            409 => "Conflict",
                            _ => "Error",
                        };
                        let payload = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(payload.as_bytes());
                    });
                }
            });
            Self {
                base_url: format!("http://127.0.0.1:{port}"),
                requests,
                responses,
            }
        }

        /// Script the next response.
        pub fn push(&self, status: u16, body: &str) {
            self.responses
                .lock()
                .unwrap()
                .push_back((status, body.to_string()));
        }

        /// Snapshot of recorded requests.
        pub fn requests(&self) -> Vec<(String, String, String)> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}

/// Trait-boundary guard for forge path segments (owner, repo,
/// username): a peer-influenced value must not change which endpoint a
/// request hits when interpolated into a URL path.
/// Like assert_safe_segment but allows '/' separators (GitLab subgroup
/// owners such as `group/sub`): each segment must pass on its own.
pub fn assert_safe_path(value: &str, what: &str) -> Result<(), ProviderError> {
    for part in value.split('/') {
        assert_safe_segment(part, what)?;
    }
    Ok(())
}

pub fn assert_safe_segment(value: &str, what: &str) -> Result<(), ProviderError> {
    let ok = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(ProviderError::Api(format!(
            "the {what} name contains characters the forge does not allow"
        )))
    }
}
