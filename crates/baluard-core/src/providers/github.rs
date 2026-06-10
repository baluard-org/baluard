//! GitHub provider: device flow + PAT auth via octocrab.
//!
//! Device flow uses GitHub's OAuth app credentials (public client_id, no secret).
//! PAT: validates against /user endpoint before storing.
//! Repo creation uses raw POST /user/repos (octocrab doesn't expose it directly).

use async_trait::async_trait;
use octocrab::models::Repository;
use octocrab::Octocrab;
use secrecy::ExposeSecret;

use super::types::{
    DeviceFlowSession, DeviceFlowStatus, ForgeProvider, Provider, ProviderError, ProviderInfo,
    ProviderToken, VaultRepo,
};

/// GitHub OAuth app client ID (public, no secret needed for device flow).
const GITHUB_CLIENT_ID: &str = "Ov23liuGmBAmBRWm3Ni";

/// GitHub device flow endpoints.
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

pub struct GitHubProvider {
    http: reqwest::Client,
}

impl GitHubProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// Build an octocrab client from a token.
    fn client_from_token(&self, token: &ProviderToken) -> Result<Octocrab, ProviderError> {
        Octocrab::builder()
            .personal_token(token.access_token().expose_secret().to_string())
            .build()
            .map_err(|e| ProviderError::Api(e.to_string()))
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
        let resp = client
            .post(DEVICE_CODE_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", GITHUB_CLIENT_ID),
                ("scope", "repo"),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
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
            verification_uri: data["verification_uri"]
                .as_str()
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
        let resp = client
            .post(ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", GITHUB_CLIENT_ID),
                ("device_code", &session.device_code),
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        match data["error"].as_str() {
            Some("authorization_pending") => {
                Ok(DeviceFlowStatus::Pending)
            }
            Some("slow_down") => Ok(DeviceFlowStatus::SlowDown),
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
        })
    }

    async fn get_authenticated_user(
        &self,
        token: &ProviderToken,
    ) -> Result<String, ProviderError> {
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
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        Ok(page_result.into_iter().filter_map(|r| self.repo_to_vault(&r)).collect())
    }

    async fn detect_vault_repos(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        let client = self.client_from_token(token)?;
        let user = client
            .current()
            .user()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        let query = format!("filename:.baluard user:{}", user.login);
        let results: octocrab::Page<octocrab::models::Code> = client
            .search()
            .code(&query)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

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
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        // Safety: verify repo is private after creation
        if !repo.private.unwrap_or(false) {
            // Delete public repo immediately
            if let Some(owner) = &repo.owner {
                let route = format!("/repos/{}/{}", owner.login, repo.name);
                let _ = client
                    .delete::<(), _, ()>(route, None as Option<&()>)
                    .await;
            }
            return Err(ProviderError::RepoPublic(format!(
                "repo '{name}' was created public (safety abort)"
            )));
        }

        self.repo_to_vault(&repo)
            .ok_or_else(|| ProviderError::Api("missing repo fields".into()))
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
        assert_eq!(Provider::GitLab.auth_method(), "pat");
        assert_eq!(Provider::Codeberg.auth_method(), "pat");
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
