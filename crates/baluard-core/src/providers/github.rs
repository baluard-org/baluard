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
fn api_error(e: octocrab::Error) -> ProviderError {
    match e {
        octocrab::Error::GitHub { source, .. } => {
            ProviderError::Api(format!("{} (HTTP {})", source.message, source.status_code))
        }
        other => ProviderError::Api(other.to_string()),
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
    fn repo_to_vault(&self, r: &Repository) -> Option<VaultRepo> {
        Some(VaultRepo {
            name: r.name.clone(),
            full_name: r.full_name.clone().unwrap_or_default(),
            clone_url: r
                .clone_url
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_default(),
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

        // M11 fix: check HTTP status before parsing JSON body.
        // GitHub returns 400 with an error JSON for authorization_pending /
        // slow_down / expired_token, but 429 (rate limit) or 5xx (server
        // error) should NOT be parsed as a normal device flow response.
        let status = resp.status();
        if !status.is_success() {
            // 429: rate limited. Treat as slow_down with +5s (RFC 8628 §3.5).
            if status.as_u16() == 429 {
                return Ok(DeviceFlowStatus::SlowDown {
                    interval_secs: session.interval_secs + 5,
                });
            }
            // Other non-2xx: surface as error.
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
            .map_err(|e| ProviderError::TokenValidation(e.to_string()))?;

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

        Ok(results
            .into_iter()
            .filter_map(|item| self.repo_to_vault(&item.repository))
            .collect())
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
}
