//! Codeberg (Forgejo) provider: web-OAuth (auth-code + PKCE) + PAT.
//!
//! Forgejo does NOT support device flow (RFC 8628). The only automatic flow is
//! authorization-code + PKCE, which requires a localhost callback listener.
//! PAT is the more secure fallback: Forgejo PATs are scoped (`write:repository`)
//! while OAuth2 tokens have NO scopes (full account access).
//!
//! API: Forgejo REST v1. Auth: PAT as `Authorization: token <pat>`, OAuth as
//! `Authorization: Bearer <token>`. Git HTTPS: token as password.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrecy::ExposeSecret;

use super::types::{
    CollaboratorPermission, CollaboratorStatus, ForgeProvider, OAuthStart, Provider,
    ProviderConfig, ProviderError, ProviderInfo, ProviderToken, VaultRepo, code_challenge_s256,
    generate_code_verifier, generate_state, now_secs, urlencoding_encode,
};

pub struct CodebergProvider {
    http: reqwest::Client,
    config: ProviderConfig,
}

impl CodebergProvider {
    pub fn new() -> Self {
        Self::with_config(ProviderConfig::defaults())
    }

    pub fn with_config(config: ProviderConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("Baluard/{}", env!("CARGO_PKG_VERSION")))
            // P8c-2 review: reqwest defaults to NO timeout — a hung forge
            // connection would wedge the caller (sync, seat strikes) forever.
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http, config }
    }

    fn client_id(&self) -> String {
        self.config.effective_client_id(Provider::Codeberg)
    }

    fn base(&self) -> String {
        self.config.effective_instance_url(Provider::Codeberg)
    }

    fn api_base(&self) -> String {
        format!("{}/api/v1", self.base())
    }

    /// Authenticated request: Forgejo accepts both `token <pat>` and
    /// `Bearer <oauth>`. We use `token` uniformly (works for both).
    fn authed(
        &self,
        method: reqwest::Method,
        url: &str,
        token: &ProviderToken,
    ) -> reqwest::RequestBuilder {
        self.http.request(method, url).header(
            "Authorization",
            format!("token {}", token.access_token().expose_secret()),
        )
    }

    /// Convert a Forgejo repo JSON object into a VaultRepo.
    fn repo_to_vault(r: &serde_json::Value) -> Option<VaultRepo> {
        Some(VaultRepo {
            name: r["name"].as_str()?.to_string(),
            full_name: r["full_name"].as_str()?.to_string(),
            clone_url: r["clone_url"].as_str()?.to_string(),
            private: r.get("private").and_then(|v| v.as_bool()).unwrap_or(true),
            vault_slug: None,
            vault_id: None,
        })
    }

    /// Fetch + parse `.baluard` for one repo. Returns slug/id if present.
    async fn read_marker(
        &self,
        token: &ProviderToken,
        full_name: &str,
    ) -> Option<(Option<String>, Option<String>)> {
        let url = format!(
            "{api}/repos/{repo}/contents/.baluard",
            api = self.api_base(),
            repo = full_name,
        );
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let b64 = v["content"].as_str()?;
        // Forgejo returns base64 content; may have newlines, strip them.
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let raw = BASE64.decode(&cleaned).ok()?;
        let marker: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        Some((
            marker["slug"].as_str().map(str::to_string),
            marker["vault_id"].as_str().map(str::to_string),
        ))
    }
}

impl Default for CodebergProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ForgeProvider for CodebergProvider {
    fn provider(&self) -> Provider {
        Provider::Codeberg
    }

    // Device flow not supported by Forgejo — these return errors.
    async fn device_flow_start(&self) -> Result<super::types::DeviceFlowSession, ProviderError> {
        Err(ProviderError::Other(
            "Codeberg does not support device flow. Use web-OAuth or PAT.".into(),
        ))
    }

    async fn device_flow_poll(
        &self,
        _session: &super::types::DeviceFlowSession,
    ) -> Result<super::types::DeviceFlowStatus, ProviderError> {
        Err(ProviderError::Other(
            "Codeberg does not support device flow.".into(),
        ))
    }

    async fn oauth_start(&self, redirect_uri: &str) -> Result<OAuthStart, ProviderError> {
        let verifier = generate_code_verifier();
        let challenge = code_challenge_s256(&verifier);
        let state = generate_state();
        let client_id = self.client_id();

        let params = [
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge.as_str()),
            ("state", state.as_str()),
        ];
        // Forgejo ignores the `scope` param (no OAuth2 scope support); the
        // token grants full account access regardless. Do not send a scope.

        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let auth_url = format!("{}/login/oauth/authorize?{}", self.base(), query);

        Ok(OAuthStart {
            auth_url,
            code_verifier: verifier,
            state,
        })
    }

    async fn oauth_exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        let client_id = self.client_id();
        let resp = self
            .http
            .post(format!("{}/login/oauth/access_token", self.base()))
            .header("Accept", "application/json")
            .json(&serde_json::json!({
                "client_id": client_id,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::AuthFailed(format!(
                "oauth_exchange HTTP {status}: {body}"
            )));
        }

        let d: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        if let Some(err) = d["error"].as_str() {
            return Err(ProviderError::AuthFailed(err.to_string()));
        }

        let access = d["access_token"]
            .as_str()
            .ok_or_else(|| ProviderError::Api("missing access_token".into()))?
            .to_string();
        let scopes = d["scope"].as_str().unwrap_or("").to_string();
        let now = now_secs();
        let expires_in = d["expires_in"].as_u64().unwrap_or(3600);

        // Forgejo returns refresh_token for OAuth2.
        let token = if let Some(rt) = d["refresh_token"].as_str() {
            ProviderToken::with_refresh(access, rt, now + expires_in, scopes)
        } else {
            let mut t = ProviderToken::new(access, scopes);
            t.expires_at = Some(now + expires_in);
            t
        };

        let info = self.validate_token(&token).await?;
        Ok((token, info))
    }

    async fn authenticate_pat(
        &self,
        pat: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        let token = ProviderToken::new(pat, "");
        let info = self.validate_token(&token).await?;
        Ok((token, info))
    }

    async fn validate_token(&self, token: &ProviderToken) -> Result<ProviderInfo, ProviderError> {
        let resp = self
            .authed(
                reqwest::Method::GET,
                &format!("{}/user", self.api_base()),
                token,
            )
            .send()
            .await
            .map_err(|e| ProviderError::TokenValidation(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ProviderError::TokenExpired);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::TokenValidation(format!("{s}: {body}")));
        }

        let u: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::TokenValidation(e.to_string()))?;
        Ok(ProviderInfo {
            provider: Provider::Codeberg,
            username: u["login"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing username".into()))?
                .to_string(),
            scopes: token.scopes.clone(),
            connected_at: now_secs(),
            instance_url: self.config.instance_url.clone(),
            client_id: self.config.client_id.clone(),
        })
    }

    async fn get_authenticated_user(&self, token: &ProviderToken) -> Result<String, ProviderError> {
        self.validate_token(token).await.map(|i| i.username)
    }

    async fn list_repos(
        &self,
        token: &ProviderToken,
        page: u8,
        per_page: u8,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        let url = format!(
            "{api}/repos/list?limit={pp}&page={pg}",
            api = self.api_base(),
            pp = per_page,
            pg = page,
        );
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(ProviderError::Api(format!("list_repos HTTP {s}")));
        }
        let arr: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        Ok(arr.iter().filter_map(Self::repo_to_vault).collect())
    }

    async fn detect_vault_repos(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        // Forgejo: paginate /user/repos (type=owner - accessible org/collab
        // repos must NOT surface in the picker), probe .baluard per repo. Fetches
        // within a page run concurrently (JoinSet) to avoid rate-limit thrash
        // on large accounts.
        let mut found = Vec::new();
        let mut page: u8 = 1;
        loop {
            let url = format!(
                "{api}/user/repos?limit=50&page={pg}&type=owner",
                api = self.api_base(),
                pg = page,
            );
            let resp = self
                .authed(reqwest::Method::GET, &url, token)
                .send()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            if !resp.status().is_success() {
                let s = resp.status();
                return Err(ProviderError::Api(format!("detect_vault_repos HTTP {s}")));
            }
            let arr: Vec<serde_json::Value> = resp
                .json()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            if arr.is_empty() {
                break;
            }
            // Probe .baluard concurrently for this page's repos.
            let page_repos: Vec<(serde_json::Value, Option<(Option<String>, Option<String>)>)> = {
                let mut tasks = tokio::task::JoinSet::new();
                for r in arr {
                    let this = std::sync::Arc::new(Self::with_config(self.config.clone()));
                    let token_clone = token.clone();
                    let full_name = r["full_name"].as_str().map(str::to_string);
                    if let Some(full_name) = full_name {
                        tasks.spawn(async move {
                            (r, this.read_marker(&token_clone, &full_name).await)
                        });
                    }
                }
                let mut results = Vec::new();
                while let Some(res) = tasks.join_next().await {
                    if let Ok((r, marker)) = res {
                        results.push((r, marker));
                    }
                }
                results
            };
            for (r, marker) in page_repos {
                if let Some((slug, vault_id)) = marker {
                    let mut repo = match Self::repo_to_vault(&r) {
                        Some(r) => r,
                        None => continue,
                    };
                    repo.vault_slug = slug;
                    repo.vault_id = vault_id;
                    found.push(repo);
                }
            }
            page = page.saturating_add(1);
            if page > 20 {
                break; // safety cap: 1000 repos
            }
        }
        Ok(found)
    }

    async fn create_private_repo(
        &self,
        token: &ProviderToken,
        name: &str,
    ) -> Result<VaultRepo, ProviderError> {
        let resp = self
            .authed(
                reqwest::Method::POST,
                &format!("{}/user/repos", self.api_base()),
                token,
            )
            .json(&serde_json::json!({
                "name": name,
                "private": true,
                "auto_init": false,
            }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Api(format!(
                "create repo HTTP {status}: {body}"
            )));
        }
        let r: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        // Safety: verify private before returning.
        if r["private"].as_bool() != Some(true) {
            if let Some(full) = r["full_name"].as_str() {
                let _ = self
                    .authed(
                        reqwest::Method::DELETE,
                        &format!("{}/repos/{}", self.api_base(), full),
                        token,
                    )
                    .send()
                    .await;
            }
            return Err(ProviderError::RepoPublic(format!(
                "repo '{name}' was created non-private (safety abort)"
            )));
        }

        Self::repo_to_vault(&r).ok_or_else(|| ProviderError::Api("missing repo fields".into()))
    }

    async fn delete_repo(
        &self,
        token: &ProviderToken,
        owner: &str,
        name: &str,
    ) -> Result<(), ProviderError> {
        let url = format!("{}/repos/{owner}/{name}", self.api_base());
        let resp = self
            .authed(reqwest::Method::DELETE, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Api(format!(
                "delete repo HTTP {status}: {body}"
            )));
        }
        Ok(())
    }

    async fn add_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
        permission: CollaboratorPermission,
    ) -> Result<CollaboratorStatus, ProviderError> {
        // Forgejo grants immediately — acceptance is a no-op, so the seat
        // is Active the moment the PUT lands. Scope gaps (a scopeless
        // token is full account access) are surfaced at connect time.
        let forgejo_permission = match permission {
            CollaboratorPermission::ReadOnly => "read",
            CollaboratorPermission::Write => "write",
        };
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}",
            self.api_base()
        );
        let resp = self
            .authed(reqwest::Method::PUT, &url, token)
            .json(&serde_json::json!({ "permission": forgejo_permission }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            204 => Ok(CollaboratorStatus::Active),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!(
                    "add collaborator HTTP {s}: {body}"
                )))
            }
        }
    }

    async fn collaborator_status(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
    ) -> Result<CollaboratorStatus, ProviderError> {
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}",
            self.api_base()
        );
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            204 => Ok(CollaboratorStatus::Active),
            404 => Ok(CollaboratorStatus::None),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!("collaborator HTTP {s}: {body}")))
            }
        }
    }

    async fn remove_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
    ) -> Result<(), ProviderError> {
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}",
            self.api_base()
        );
        let resp = self
            .authed(reqwest::Method::DELETE, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            // Idempotent strike: a missing seat is already what we want.
            204 | 404 => Ok(()),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!(
                    "remove collaborator HTTP {s}: {body}"
                )))
            }
        }
    }

    async fn revoke_token(&self, _token: &ProviderToken) -> Result<(), ProviderError> {
        // Forgejo OAuth tokens can be revoked by the user deleting the app
        // authorization in settings. No API self-revoke for OAuth.
        // PATs: user deletes in settings.
        Ok(())
    }

    async fn refresh_token(
        &self,
        token: &ProviderToken,
    ) -> Result<Option<ProviderToken>, ProviderError> {
        let Some(rt) = token.refresh_token() else {
            return Ok(None);
        };
        let rt_plain = rt.expose_secret();
        let client_id = self.client_id();
        let resp = self
            .http
            .post(format!("{}/login/oauth/access_token", self.base()))
            .header("Accept", "application/json")
            .json(&serde_json::json!({
                "client_id": client_id,
                "refresh_token": rt_plain,
                "grant_type": "refresh_token",
            }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("refresh failed: {e}")))?;

        if !resp.status().is_success() {
            let s = resp.status();
            return Err(ProviderError::AuthFailed(format!("refresh HTTP {s}")));
        }
        let d: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let access = d["access_token"]
            .as_str()
            .ok_or_else(|| ProviderError::Api("refresh missing access_token".into()))?
            .to_string();
        let expires_in = d["expires_in"].as_u64().unwrap_or(3600);
        let scopes = d["scope"].as_str().unwrap_or(&token.scopes).to_string();
        let new_rt = d["refresh_token"]
            .as_str()
            .map(str::to_string)
            .or_else(|| Some(rt_plain.to_string()));
        Ok(Some(ProviderToken::with_refresh(
            access,
            new_rt.unwrap_or_default(),
            now_secs() + expires_in,
            scopes,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::types::ProviderConfig;
    use crate::providers::types::http_mock::MockApi;

    fn cb_at(base: &str) -> CodebergProvider {
        CodebergProvider::with_config(ProviderConfig {
            client_id: None,
            instance_url: Some(base.into()),
        })
    }

    #[tokio::test]
    async fn collaborator_ops_immediate_grant() {
        let api = MockApi::start();
        let cb = cb_at(&api.base_url);
        let tok = ProviderToken::new("tok", "");

        // Forgejo grants immediately: PUT 204 -> Active; read/write map
        // to Forgejo's permission strings.
        api.push(204, "");
        let st = cb
            .add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::ReadOnly)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        let (method, path, body) = &api.requests()[0];
        assert_eq!(method, "PUT");
        assert_eq!(path, "/api/v1/repos/o/r/collaborators/alice");
        assert!(body.contains("\"read\""), "body: {body}");

        api.push(204, "");
        let st = cb
            .add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::Write)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        let (_, _, body) = &api.requests()[1];
        assert!(body.contains("\"write\""), "body: {body}");

        // Status: 204 present / 404 absent.
        api.push(204, "");
        let st = cb
            .collaborator_status(&tok, "o", "r", "alice")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        api.push(404, "");
        let st = cb
            .collaborator_status(&tok, "o", "r", "ghost")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::None);

        // Removal is idempotent (204 + 404 both succeed).
        api.push(204, "");
        cb.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
        api.push(404, "");
        cb.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
        let (method, path, _) = &api.requests()[4];
        assert_eq!(method, "DELETE");
        assert_eq!(path, "/api/v1/repos/o/r/collaborators/alice");
    }

    #[test]
    fn provider_identity() {
        let cb = CodebergProvider::new();
        assert_eq!(cb.provider(), Provider::Codeberg);
    }

    #[test]
    fn default_base_is_codeberg_org() {
        let cb = CodebergProvider::new();
        assert_eq!(cb.base(), "https://codeberg.org");
        assert_eq!(cb.api_base(), "https://codeberg.org/api/v1");
    }

    #[test]
    fn custom_instance_overrides_base() {
        let cb = CodebergProvider::with_config(ProviderConfig {
            instance_url: Some("https://forgejo.example.com/".into()),
            client_id: None,
        });
        assert_eq!(cb.base(), "https://forgejo.example.com");
    }

    #[test]
    fn default_client_id_is_placeholder() {
        assert_eq!(
            Provider::Codeberg.default_client_id(),
            "REPLACE_WITH_CODEBERG_CLIENT_ID"
        );
    }

    #[test]
    fn auth_method_is_web_oauth() {
        // Codeberg/Forgejo has no device flow; primary path is web-OAuth (PKCE).
        assert_eq!(Provider::Codeberg.auth_method(), "web-oauth");
    }

    #[test]
    fn pkce_verifier_length() {
        let v = generate_code_verifier();
        assert!(v.len() >= 43 && v.len() <= 128);
    }

    #[test]
    fn pkce_challenge_is_url_safe_no_pad() {
        let v = generate_code_verifier();
        let c = code_challenge_s256(&v);
        assert!(!c.contains('='));
        assert!(!c.contains('+'));
        assert!(!c.contains('/'));
    }

    #[test]
    fn repo_to_vault_maps_fields() {
        let r = serde_json::json!({
            "name": "my-vault",
            "full_name": "alice/my-vault",
            "clone_url": "https://codeberg.org/alice/my-vault.git",
            "private": true,
        });
        let v = CodebergProvider::repo_to_vault(&r).unwrap();
        assert_eq!(v.name, "my-vault");
        assert_eq!(v.full_name, "alice/my-vault");
        assert!(v.private);
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // RFC 7636 Appendix B test vector: verifier -> S256 challenge.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_verifier_length_in_spec_range() {
        // L2: length is randomized within RFC 7636 §4.1 (43-128).
        for _ in 0..100 {
            let v = generate_code_verifier();
            assert!(
                v.len() >= 43 && v.len() <= 128,
                "verifier len {} out of range",
                v.len()
            );
            // Only unreserved chars.
            assert!(
                v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
            );
        }
    }
}
