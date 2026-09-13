//! GitHub provider: device flow + PAT auth via octocrab.
//!
//! Device flow uses GitHub's OAuth app credentials (public client_id, no secret).
//! PAT: validates against /user endpoint before storing.
//! Repo creation uses raw POST /user/repos (octocrab doesn't expose it directly).

use async_trait::async_trait;
use octocrab::Octocrab;
use octocrab::models::Repository;
use secrecy::ExposeSecret;

use super::types::{
    DeviceFlowSession, DeviceFlowStatus, ForgeProvider, Provider, ProviderError, ProviderInfo,
    ProviderToken, VaultRepo,
};

/// Format an octocrab error with the real GitHub API message.
///
/// `octocrab::Error::GitHub`'s default `Display` renders only the variant
/// name ("GitHub"), dropping `GitHubError.message` and `status_code`. That
/// turns every API failure into a useless "API error: GitHub" string. This
/// surfaces the actual server message and HTTP status.
/// Render an error with its full cause chain as one UI-friendly line.
///
/// octocrab derives `Display` with snafu; variants without an explicit
/// `#[snafu(display(...))]` render as the bare variant name ("Other",
/// "UriParse"), dropping the wrapped cause. Walking `Error::source()`
/// restores the real failure: "Other: failed to load certificates" instead
/// of a useless "Other". Repeated causes (snafu variants that embed their
/// source in `display`) are skipped, and the trailing "Found at " snafu
/// backtrace marker is stripped (the backtrace feature renders empty).
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(err) = src {
        let cause = err.to_string();
        if !msg.contains(&cause) {
            msg.push_str(": ");
            msg.push_str(&cause);
        }
        src = err.source();
    }
    // snafu display templates end with "\nFound at <backtrace>"; the
    // backtrace feature is off, so the tail is empty. Anchoring on the
    // newline keeps legitimate mid-message text like "no commit Found at
    // ref main" intact.
    if let Some(idx) = msg.rfind("\nFound at") {
        msg.truncate(idx);
    }
    msg.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Format an octocrab error with the real GitHub API message.
///
/// `octocrab::Error::GitHub`'s default `Display` renders only the variant
/// name ("GitHub"), dropping `GitHubError.message` and `status_code`. That
/// turns every API failure into a useless "API error: GitHub" string. This
/// surfaces the actual server message and HTTP status, and every other
/// variant through its full source chain.
fn api_error(e: octocrab::Error) -> ProviderError {
    match e {
        octocrab::Error::GitHub { source, .. } => {
            ProviderError::Api(format!("{} (HTTP {})", source.message, source.status_code))
        }
        other => ProviderError::Api(error_chain(&other)),
    }
}

/// GitHub OAuth app client ID (public, no secret needed for device flow).
pub(crate) const GITHUB_CLIENT_ID: &str = "Ov23liTCidT2TQDLP4No";

/// GitHub device flow endpoints.
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

pub struct GitHubProvider {
    http: reqwest::Client,
    config: super::types::ProviderConfig,
}

impl GitHubProvider {
    /// New with the public default instance + project OAuth app.
    pub fn new() -> Self {
        Self::with_config(super::types::ProviderConfig::defaults())
    }

    /// New with overrides (Advanced Options: client_id, instance_url).
    pub fn with_config(config: super::types::ProviderConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("Baluard/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http, config }
    }

    /// Effective client_id for this instance.
    fn client_id(&self) -> String {
        self.config.effective_client_id(Provider::GitHub)
    }

    /// Build an octocrab client from a token.
    fn client_from_token(&self, token: &ProviderToken) -> Result<Octocrab, ProviderError> {
        Octocrab::builder()
            .personal_token(token.access_token().expose_secret().to_string())
            .build()
            .map_err(api_error)
    }

    /// Convert octocrab Repository to VaultRepo.
    /// Convert octocrab Repository to VaultRepo. Returns None when the
    /// payload lacks a clone_url (minimal search-embedded repositories);
    /// an empty clone_url would only surface later as an obscure scheme
    /// error at clone time.
    fn repo_to_vault(&self, r: &Repository) -> Option<VaultRepo> {
        let clone_url = r
            .clone_url
            .as_ref()
            .map(|u| u.to_string())
            .unwrap_or_default();
        if clone_url.is_empty() {
            return None;
        }
        Some(VaultRepo {
            name: r.name.clone(),
            full_name: r.full_name.clone().unwrap_or_default(),
            clone_url,
            private: r.private.unwrap_or(false),
            vault_slug: None,
            vault_id: None,
        })
    }
}

impl Default for GitHubProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ForgeProvider for GitHubProvider {
    fn provider(&self) -> Provider {
        Provider::GitHub
    }

    async fn device_flow_start(&self) -> Result<DeviceFlowSession, ProviderError> {
        let client = &self.http;
        let client_id = self.client_id();
        let resp = client
            .post(DEVICE_CODE_URL)
            .header("Accept", "application/json")
            .form(&[("client_id", client_id.as_str()), ("scope", "repo")])
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // 404 on /login/device/code is GitHub's signal that the OAuth
            // App has not enabled the Device Authorization flow toggle
            // (opt-in per https://github.blog/changelog/2022-03-16-enable-
            // oauth-device-authentication-flow-for-apps/). Surface that
            // distinct cause so the user / maintainer knows to flip the
            // toggle rather than chasing a generic network/credential bug.
            if status == 404 {
                return Err(ProviderError::Api(
                    "GitHub returned 404 for /login/device/code. The OAuth \
                     App registered with this client_id has not enabled \
                     the Device Authorization flow (opt-in per app since \
                     March 2022). Enable it in the app's settings: \
                     https://github.com/settings/developers → click the \
                     app → 'Device flow' → Enable. See \
                     docs/git-provider-apps-and-tokens.md §3.2."
                        .into(),
                ));
            }
            return Err(ProviderError::Api(format!(
                "device flow start failed: {status}: {body}"
            )));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(DeviceFlowSession {
            provider: Provider::GitHub,
            user_code: data["user_code"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing user_code".into()))?
                .to_string(),
            // verification_uri_complete pre-fills the code (GitHub sends it for
            // the device flow); fall back to the bare page otherwise.
            verification_uri: data["verification_uri_complete"]
                .as_str()
                .or_else(|| data["verification_uri"].as_str())
                .ok_or_else(|| ProviderError::Api("missing verification_uri".into()))?
                .to_string(),
            device_code: data["device_code"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing device_code".into()))?
                .to_string(),
            interval_secs: data["interval"].as_u64().unwrap_or(5),
            expires_at: now + data["expires_in"].as_u64().unwrap_or(900),
        })
    }

    async fn device_flow_poll(
        &self,
        session: &DeviceFlowSession,
    ) -> Result<DeviceFlowStatus, ProviderError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now >= session.expires_at {
            return Ok(DeviceFlowStatus::Expired);
        }

        let client = &self.http;
        let client_id = self.client_id();
        let resp = match client
            .post(ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id.as_str()),
                ("device_code", &session.device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(_e) => {
                if now >= session.expires_at {
                    return Ok(DeviceFlowStatus::Expired);
                }
                return Ok(DeviceFlowStatus::Pending);
            }
        };

        // Check HTTP status before parsing JSON body. 429 (rate limit) and 5xx
        // (server error) are NOT device flow responses. 400 IS one: RFC 8628
        // §3.5 sends authorization_pending / slow_down / expired_token /
        // access_denied with HTTP 400, so its body must be parsed like a 200.
        // Rejecting 400 outright turns every normal pending tick into a hard
        // error and hides the terminal states behind an opaque "HTTP 400".
        let status = resp.status();
        if status.as_u16() == 429 {
            // Rate limited. Treat as slow_down with +5s (RFC 8628 §3.5).
            return Ok(DeviceFlowStatus::SlowDown {
                interval_secs: session.interval_secs + 5,
            });
        }
        if !status.is_success() && status.as_u16() != 400 {
            return Err(ProviderError::Api(format!(
                "device flow poll HTTP {status}"
            )));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        match data["error"].as_str() {
            Some("authorization_pending") => Ok(DeviceFlowStatus::Pending),
            // M11 fix: SlowDown now carries the new interval (RFC 8628 §3.5).
            Some("slow_down") => Ok(DeviceFlowStatus::SlowDown {
                interval_secs: session.interval_secs + 5,
            }),
            Some("expired_token") | Some("access_denied") => Ok(DeviceFlowStatus::Expired),
            Some(e) => Err(ProviderError::AuthFailed(e.to_string())),
            None => {
                let access_token = data["access_token"]
                    .as_str()
                    .ok_or_else(|| ProviderError::Api("missing access_token".into()))?
                    .to_string();
                let scopes = data["scope"].as_str().unwrap_or("repo").to_string();
                Ok(DeviceFlowStatus::Success(ProviderToken::new(
                    access_token,
                    scopes,
                )))
            }
        }
    }

    async fn authenticate_pat(
        &self,
        pat: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        let token = ProviderToken::new(pat, "repo");
        let info = self.validate_token(&token).await?;
        Ok((token, info))
    }

    async fn validate_token(&self, token: &ProviderToken) -> Result<ProviderInfo, ProviderError> {
        let client = self.client_from_token(token)?;
        let user = client
            .current()
            .user()
            .await
            .map_err(|e| ProviderError::TokenValidation(error_chain(&e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ProviderInfo {
            provider: Provider::GitHub,
            username: user.login,
            scopes: token.scopes.clone(),
            connected_at: now,
            instance_url: self.config.instance_url.clone(),
            client_id: self.config.client_id.clone(),
        })
    }

    async fn get_authenticated_user(&self, token: &ProviderToken) -> Result<String, ProviderError> {
        let info = self.validate_token(token).await?;
        Ok(info.username)
    }

    async fn list_repos(
        &self,
        token: &ProviderToken,
        page: u8,
        per_page: u8,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        let client = self.client_from_token(token)?;
        let page_result = client
            .current()
            .list_repos_for_authenticated_user()
            .type_("owner")
            .per_page(per_page)
            .page(page)
            .send()
            .await
            .map_err(api_error)?;

        Ok(page_result
            .into_iter()
            .filter_map(|r| self.repo_to_vault(&r))
            .collect())
    }

    async fn detect_vault_repos(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        let client = self.client_from_token(token)?;
        let user = client.current().user().await.map_err(api_error)?;

        let query = format!("filename:.baluard user:{}", user.login);
        let results: octocrab::Page<octocrab::models::Code> = client
            .search()
            .code(&query)
            .send()
            .await
            .map_err(api_error)?;

        // The code-search item embeds a MINIMAL repository object that omits
        // clone_url, so mapping it directly yields empty clone URLs that
        // fail at clone with "unsupported URL scheme: ". Fetch each hit's
        // full repo record instead.
        let mut repos = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for item in results {
            let Some(full_name) = item.repository.full_name else {
                continue;
            };
            // Code search can return multiple hits per repo; fetch each
            // repo record once.
            if !seen.insert(full_name.clone()) {
                continue;
            }
            let Some((owner, name)) = full_name.split_once('/') else {
                continue;
            };
            // One dead hit (renamed/deleted repo, or a transient API miss)
            // must not hide every other vault from the picker.
            let Ok(repo) = client.repos(owner, name).get().await else {
                continue;
            };
            if let Some(r) = self.repo_to_vault(&repo) {
                repos.push(r);
            }
        }
        Ok(repos)
    }
    async fn create_private_repo(
        &self,
        token: &ProviderToken,
        name: &str,
    ) -> Result<VaultRepo, ProviderError> {
        let client = self.client_from_token(token)?;

        #[derive(serde::Serialize)]
        struct CreateRepoBody {
            name: String,
            private: bool,
            auto_init: bool,
        }

        let repo: Repository = client
            .post(
                "/user/repos",
                Some(&CreateRepoBody {
                    name: name.to_string(),
                    private: true,
                    auto_init: false,
                }),
            )
            .await
            .map_err(api_error)?;

        // Safety: verify repo is private after creation
        if !repo.private.unwrap_or(false) {
            // Delete public repo immediately
            if let Some(owner) = &repo.owner {
                let route = format!("/repos/{}/{}", owner.login, repo.name);
                let _ = client.delete::<(), _, ()>(route, None as Option<&()>).await;
            }
            return Err(ProviderError::RepoPublic(format!(
                "repo '{name}' was created public (safety abort)"
            )));
        }

        self.repo_to_vault(&repo)
            .ok_or_else(|| ProviderError::Api("missing repo fields".into()))
    }

    async fn delete_repo(
        &self,
        token: &ProviderToken,
        owner: &str,
        name: &str,
    ) -> Result<(), ProviderError> {
        let client = self.client_from_token(token)?;
        let route = format!("/repos/{owner}/{name}");
        client
            .delete::<(), _, ()>(route, None as Option<&()>)
            .await
            .map_err(api_error)
    }

    async fn revoke_token(&self, _token: &ProviderToken) -> Result<(), ProviderError> {
        // GitHub OAuth tokens can't be revoked via API (only deleted from settings).
        // PATs also require manual deletion. No-op.
        Ok(())
    }

    async fn refresh_token(
        &self,
        _token: &ProviderToken,
    ) -> Result<Option<ProviderToken>, ProviderError> {
        // GitHub tokens (PAT + OAuth) don't expire. No refresh needed.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity() {
        let gh = GitHubProvider::new();
        assert_eq!(gh.provider(), Provider::GitHub);
    }

    #[test]
    fn provider_auth_method() {
        assert_eq!(Provider::GitHub.auth_method(), "device-flow");
        assert_eq!(Provider::GitLab.auth_method(), "device-flow");
        assert_eq!(Provider::Codeberg.auth_method(), "web-oauth");
    }

    #[test]
    fn provider_default_scopes() {
        assert_eq!(Provider::GitHub.default_scopes(), "repo");
    }

    #[test]
    fn provider_token_url() {
        assert!(Provider::GitHub.token_url().is_some());
    }

    #[test]
    fn provider_display() {
        assert_eq!(Provider::GitHub.to_string(), "github");
    }

    #[test]
    fn provider_all() {
        assert_eq!(Provider::all().len(), 3);
    }

    #[derive(Debug)]
    struct Root;
    impl std::fmt::Display for Root {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Other")
        }
    }
    impl std::error::Error for Root {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&Leaf)
        }
    }

    #[derive(Debug)]
    struct Leaf;
    impl std::fmt::Display for Leaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "failed to load native certificates")
        }
    }
    impl std::error::Error for Leaf {}

    #[test]
    fn error_chain_includes_causes() {
        // Mirrors the snafu shape that produced the useless "API error:
        // Other" on Android: bare variant name Display + a source carrying
        // the real cause.
        assert_eq!(error_chain(&Root), "Other: failed to load native certificates");
    }

    #[test]
    fn error_chain_keeps_inline_found_at() {
        #[derive(Debug)]
        struct Plain;
        impl std::fmt::Display for Plain {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "no commit Found at ref main")
            }
        }
        impl std::error::Error for Plain {}
        // Agy review: mid-message "Found at" must survive; only the snafu
        // newline-anchored backtrace marker is stripped.
        assert_eq!(error_chain(&Plain), "no commit Found at ref main");
    }

    // Regression for the Android onboarding failure "unsupported URL
    // scheme: .": code-search hits embed a minimal repository object
    // WITHOUT clone_url. repo_to_vault must reject it (returning None)
    // instead of producing an empty clone URL downstream.
    #[test]
    fn repo_to_vault_rejects_missing_clone_url() {
        let gh = GitHubProvider::new();
        let json = r#"{
            "id": 1296269,
            "name": "baluard-personal",
            "full_name": "EstebanForge/baluard-personal",
            "private": true,
            "url": "https://api.github.com/repos/EstebanForge/baluard-personal"
        }"#;
        let repo: octocrab::models::Repository = serde_json::from_str(json).unwrap();
        assert!(gh.repo_to_vault(&repo).is_none());
    }

    #[test]
    fn repo_to_vault_maps_full_repo_record() {
        let gh = GitHubProvider::new();
        let json = r#"{
            "id": 1296269,
            "name": "baluard-personal",
            "full_name": "EstebanForge/baluard-personal",
            "private": true,
            "url": "https://api.github.com/repos/EstebanForge/baluard-personal",
            "clone_url": "https://github.com/EstebanForge/baluard-personal.git"
        }"#;
        let repo: octocrab::models::Repository = serde_json::from_str(json).unwrap();
        let vault = gh.repo_to_vault(&repo).expect("full record must map");
        assert_eq!(vault.name, "baluard-personal");
        assert_eq!(vault.full_name, "EstebanForge/baluard-personal");
        assert_eq!(vault.clone_url, "https://github.com/EstebanForge/baluard-personal.git");
        assert!(vault.private);
        assert_eq!(vault.vault_slug, None);
    }

    #[test]
    fn repo_to_vault_null_clone_url_rejected() {
        let gh = GitHubProvider::new();
        let json = r#"{ "id": 1, "name": "x", "url": "https://api.github.com/repos/o/x", "clone_url": null }"#;
        let repo: octocrab::models::Repository = serde_json::from_str(json).unwrap();
        assert!(gh.repo_to_vault(&repo).is_none());
    }
}
