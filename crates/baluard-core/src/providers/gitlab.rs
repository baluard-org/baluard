//! GitLab provider: device flow + PAT auth via raw reqwest.
//!
//! Device flow (RFC 8628) is supported on GitLab >= 17.1 (GA 17.9). OAuth
//! access tokens expire in 7200s (2h); a refresh_token is returned and used
//! to obtain fresh access tokens without re-auth. PATs are separate
//! (long-lived, optional expiry, no refresh).
//!
//! PATs are detected by the `glpat-` prefix and sent as `PRIVATE-TOKEN`;
//! OAuth tokens are sent as `Authorization: Bearer`.
//!
//! Repo creation requires the `api` scope (POST /projects rejects narrower
//! scopes). This is documented at connect time so the user consents.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrecy::ExposeSecret;

use super::types::{
    CollaboratorPermission, CollaboratorStatus, DeviceFlowSession, DeviceFlowStatus, ForgeProvider,
    Provider, ProviderConfig, ProviderError, ProviderInfo, ProviderToken, VaultRepo, now_secs,
    urlencoding_encode,
};

/// OAuth scopes requested at device-flow / PAT time. `api` is required for
/// `POST /projects`; it is broad but there is no narrower create-repo scope.
const GITLAB_SCOPES: &str = "api";

/// PAT prefix (GitLab personal access tokens).
const PAT_PREFIX: &str = "glpat-";

pub struct GitLabProvider {
    http: reqwest::Client,
    config: ProviderConfig,
}

impl GitLabProvider {
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
        self.config.effective_client_id(Provider::GitLab)
    }

    fn base(&self) -> String {
        self.config.effective_instance_url(Provider::GitLab)
    }

    fn api_base(&self) -> String {
        format!("{}/api/v4", self.base())
    }

    /// True if the token looks like a GitLab PAT (PRIVATE-TOKEN auth).
    fn is_pat(token: &ProviderToken) -> bool {
        token.access_token().expose_secret().starts_with(PAT_PREFIX)
    }

    /// Build an authenticated request: PAT -> `PRIVATE-TOKEN`, OAuth -> Bearer.
    fn authed(
        &self,
        method: reqwest::Method,
        url: &str,
        token: &ProviderToken,
    ) -> reqwest::RequestBuilder {
        let req = self.http.request(method, url);
        if Self::is_pat(token) {
            req.header("PRIVATE-TOKEN", token.access_token().expose_secret())
        } else {
            req.header(
                "Authorization",
                format!("Bearer {}", token.access_token().expose_secret()),
            )
        }
    }

    /// Convert a GitLab project JSON object into a VaultRepo (no marker info).
    fn project_to_repo(p: &serde_json::Value) -> Option<VaultRepo> {
        Some(VaultRepo {
            name: p["path"].as_str()?.to_string(),
            full_name: p["path_with_namespace"].as_str()?.to_string(),
            clone_url: p["http_url_to_repo"].as_str()?.to_string(),
            private: p["visibility"].as_str() == Some("private"),
            vault_slug: None,
            vault_id: None,
        })
    }

    /// Fetch + parse the `.baluard` marker for one project. Returns slug/id if
    /// present and well-formed; None if missing or malformed.
    async fn read_marker(
        &self,
        token: &ProviderToken,
        project_id: i64,
        default_branch: &str,
    ) -> Option<(Option<String>, Option<String>)> {
        let url = format!(
            "{api}/projects/{id}/repository/files/{path}?ref={branch}",
            api = self.api_base(),
            id = project_id,
            // `.baluard` is URL-encoded per GitLab files API (leading dot -> %2E).
            path = "%2Ebaluard",
            branch = urlencoding_encode(default_branch),
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
        let raw = BASE64.decode(b64).ok()?;
        let marker: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        Some((
            marker["slug"].as_str().map(str::to_string),
            marker["vault_id"].as_str().map(str::to_string),
        ))
    }
}

impl Default for GitLabProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GitLabProvider {
    /// Resolve a GitLab username to its numeric id — the members API takes
    /// user_id only, never the username.
    async fn resolve_user_id(
        &self,
        token: &ProviderToken,
        username: &str,
    ) -> Result<u64, ProviderError> {
        let url = format!(
            "{}/users?username={}",
            self.api_base(),
            urlencoding_encode(username)
        );
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Api(format!("user lookup HTTP {s}: {body}")));
        }
        let users: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let wanted = username.to_lowercase();
        users
            .as_array()
            .and_then(|list| {
                list.iter().find_map(|u| {
                    let login = u["username"].as_str().map(|l| l.to_lowercase());
                    if login.as_deref() == Some(wanted.as_str()) {
                        u["id"].as_u64()
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| ProviderError::Api(format!("user {username} not found on GitLab")))
    }
}

#[async_trait]
impl ForgeProvider for GitLabProvider {
    fn provider(&self) -> Provider {
        Provider::GitLab
    }

    async fn device_flow_start(&self) -> Result<DeviceFlowSession, ProviderError> {
        let client_id = self.client_id();
        let resp = self
            .http
            .post(format!("{}/oauth/authorize_device", self.base()))
            .form(&[("client_id", client_id.as_str()), ("scope", GITLAB_SCOPES)])
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

        let d: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let now = now_secs();

        // verification_uri_complete is the friendliest URL (code pre-filled).
        let verification_uri = d["verification_uri_complete"]
            .as_str()
            .or_else(|| d["verification_uri"].as_str())
            .ok_or_else(|| ProviderError::Api("missing verification_uri".into()))?
            .to_string();

        Ok(DeviceFlowSession {
            provider: Provider::GitLab,
            user_code: d["user_code"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing user_code".into()))?
                .to_string(),
            verification_uri,
            device_code: d["device_code"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing device_code".into()))?
                .to_string(),
            interval_secs: d["interval"].as_u64().unwrap_or(5),
            expires_at: now + d["expires_in"].as_u64().unwrap_or(300),
        })
    }

    async fn device_flow_poll(
        &self,
        session: &DeviceFlowSession,
    ) -> Result<DeviceFlowStatus, ProviderError> {
        if now_secs() >= session.expires_at {
            return Ok(DeviceFlowStatus::Expired);
        }

        let client_id = self.client_id();
        let resp = match self
            .http
            .post(format!("{}/oauth/token", self.base()))
            .form(&[
                ("client_id", client_id.as_str()),
                ("device_code", session.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(_e) => {
                if now_secs() >= session.expires_at {
                    return Ok(DeviceFlowStatus::Expired);
                }
                return Ok(DeviceFlowStatus::Pending);
            }
        };

        let status = resp.status();
        if status.as_u16() == 429 {
            // GitLab returns 429 with {"error":"slow_down","interval":N} for
            // rate limiting. Honor the server-provided interval when present;
            // otherwise apply the RFC 8628 §3.5 +5s backoff.
            let new_interval = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|d| d["interval"].as_u64())
                .unwrap_or(session.interval_secs + 5);
            return Ok(DeviceFlowStatus::SlowDown {
                interval_secs: new_interval,
            });
        }
        // 400 IS a device flow response: RFC 8628 §3.5 sends
        // authorization_pending / slow_down / expired_token / access_denied
        // with HTTP 400, so its body must be parsed like a 200. Rejecting it
        // outright turns every pending tick into a hard error and hides the
        // terminal states behind an opaque "HTTP 400".
        if !status.is_success() && status.as_u16() != 400 {
            return Err(ProviderError::Api(format!(
                "device flow poll HTTP {status}"
            )));
        }

        let d: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match d["error"].as_str() {
            Some("authorization_pending") => Ok(DeviceFlowStatus::Pending),
            Some("slow_down") => Ok(DeviceFlowStatus::SlowDown {
                interval_secs: session.interval_secs + 5,
            }),
            Some("expired_token") | Some("access_denied") => Ok(DeviceFlowStatus::Expired),
            Some(e) => Err(ProviderError::AuthFailed(e.to_string())),
            None => {
                let access = d["access_token"]
                    .as_str()
                    .ok_or_else(|| ProviderError::Api("missing access_token".into()))?
                    .to_string();
                let scopes = d["scope"].as_str().unwrap_or(GITLAB_SCOPES).to_string();
                // OAuth tokens expire in 7200s; refresh_token present for renewal.
                let expires_in = d["expires_in"].as_u64().unwrap_or(7200);
                let now = now_secs();
                if let Some(rt) = d["refresh_token"].as_str() {
                    Ok(DeviceFlowStatus::Success(ProviderToken::with_refresh(
                        access,
                        rt,
                        now + expires_in,
                        scopes,
                    )))
                } else {
                    // Edge case: some configs omit refresh_token. Expiring token
                    // with no refresh -> user re-auths when it lapses.
                    let mut t = ProviderToken::new(access, scopes);
                    t.expires_at = Some(now + expires_in);
                    Ok(DeviceFlowStatus::Success(t))
                }
            }
        }
    }

    async fn authenticate_pat(
        &self,
        pat: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        let token = ProviderToken::new(pat, "api");
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
            provider: Provider::GitLab,
            username: u["username"]
                .as_str()
                .ok_or_else(|| ProviderError::Api("missing username".into()))?
                .to_string(),
            // The `api` scope already covers the account email — no new
            // consent needed (GitHub would need `user:email`, so it
            // stays None there).
            email: u["email"].as_str().map(|s| s.to_string()),
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
            "{api}/projects?membership=true&simple=true&per_page={pp}&page={pg}",
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
        Ok(arr.iter().filter_map(Self::project_to_repo).collect())
    }

    async fn detect_vault_repos(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        // List+fetch: GitLab code search requires Elasticsearch (not always on
        // gitlab.com for all users), so we paginate member projects
        // (membership spans owned + invited seats - a joiner needs this to
        // see the shared repo) and probe `.baluard` per repo. Known boundary:
        // the 10-page probe cap can drop repos for users with very large
        // membership lists.
        let mut found = Vec::new();
        let mut page: u8 = 1;
        loop {
            let url = format!(
                "{api}/projects?membership=true&simple=true&per_page=100&page={pg}",
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
            for p in &arr {
                let id = match p["id"].as_i64() {
                    Some(i) => i,
                    None => continue,
                };
                let branch = p["default_branch"].as_str().unwrap_or("main");
                if let Some((slug, vault_id)) = self.read_marker(token, id, branch).await {
                    let mut repo = match Self::project_to_repo(p) {
                        Some(r) => r,
                        None => continue,
                    };
                    repo.vault_slug = slug;
                    repo.vault_id = vault_id;
                    found.push(repo);
                }
            }
            page = page.saturating_add(1);
            if page > 10 {
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
                &format!("{}/projects", self.api_base()),
                token,
            )
            .json(&serde_json::json!({
                "name": name,
                "visibility": "private",
                "initialize_with_readme": false,
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
        let p: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;

        // Safety: verify private before returning. Public vault repo leaks
        // encrypted blobs + padded-bucket metadata.
        if p["visibility"].as_str() != Some("private") {
            if let Some(id) = p["id"].as_i64() {
                let _ = self
                    .authed(
                        reqwest::Method::DELETE,
                        &format!("{}/projects/{}", self.api_base(), id),
                        token,
                    )
                    .send()
                    .await;
            }
            return Err(ProviderError::RepoPublic(format!(
                "repo '{name}' was created non-private (safety abort)"
            )));
        }

        Self::project_to_repo(&p).ok_or_else(|| ProviderError::Api("missing repo fields".into()))
    }

    async fn delete_repo(
        &self,
        token: &ProviderToken,
        owner: &str,
        name: &str,
    ) -> Result<(), ProviderError> {
        let path_or_id = format!("{owner}/{name}");
        let url_encoded = urlencoding_encode(&path_or_id);
        let url = format!("{}/projects/{}", self.api_base(), url_encoded);
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
        // GitLab grants immediately (no pending-acceptance state at CE
        // level). Reporter(20) = read-only seat, Developer(30) = write.
        let access_level = match permission {
            CollaboratorPermission::ReadOnly => 20,
            CollaboratorPermission::Write => 30,
        };
        let user_id = self.resolve_user_id(token, username).await?;
        let path = format!("{owner}/{repo}");
        let url = format!(
            "{}/projects/{}/members",
            self.api_base(),
            urlencoding_encode(&path)
        );
        let resp = self
            .authed(reqwest::Method::POST, &url, token)
            .json(&serde_json::json!({
                "user_id": user_id,
                "access_level": access_level
            }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            201 => Ok(CollaboratorStatus::Active),
            // 409 Conflict = already a member; the seat exists.
            409 => Ok(CollaboratorStatus::Active),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!("add member HTTP {s}: {body}")))
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
        let user_id = self.resolve_user_id(token, username).await?;
        let path = format!("{owner}/{repo}");
        let url = format!(
            "{}/projects/{}/members/{}",
            self.api_base(),
            urlencoding_encode(&path),
            user_id
        );
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            200 => Ok(CollaboratorStatus::Active),
            404 => Ok(CollaboratorStatus::None),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!("member HTTP {s}: {body}")))
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
        let user_id = self.resolve_user_id(token, username).await?;
        let path = format!("{owner}/{repo}");
        let url = format!(
            "{}/projects/{}/members/{}",
            self.api_base(),
            urlencoding_encode(&path),
            user_id
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
                    "remove member HTTP {s}: {body}"
                )))
            }
        }
    }

    async fn revoke_token(&self, token: &ProviderToken) -> Result<(), ProviderError> {
        // Best-effort. OAuth public clients revoke via /oauth/revoke with
        // client_id + token. PATs cannot self-revoke; user deletes in settings.
        if Self::is_pat(token) {
            return Ok(());
        }
        let client_id = self.client_id();
        let _ = self
            .http
            .post(format!("{}/oauth/revoke", self.base()))
            .form(&[
                ("client_id", client_id.as_str()),
                ("token", token.access_token().expose_secret()),
            ])
            .send()
            .await;
        Ok(())
    }

    async fn refresh_token(
        &self,
        token: &ProviderToken,
    ) -> Result<Option<ProviderToken>, ProviderError> {
        // PATs do not refresh.
        let Some(rt) = token.refresh_token() else {
            return Ok(None);
        };
        let rt_plain = rt.expose_secret();
        let client_id = self.client_id();
        let resp = self
            .http
            .post(format!("{}/oauth/token", self.base()))
            .form(&[
                ("client_id", client_id.as_str()),
                ("refresh_token", rt_plain),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("refresh failed: {e}")))?;

        if !resp.status().is_success() {
            let s = resp.status();
            // Refresh invalidates the prior pair; failure = must re-auth.
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
        let new_rt = d["refresh_token"]
            .as_str()
            .ok_or_else(|| ProviderError::Api("refresh missing refresh_token".into()))?
            .to_string();
        let expires_in = d["expires_in"].as_u64().unwrap_or(7200);
        let scopes = d["scope"].as_str().unwrap_or(&token.scopes).to_string();
        Ok(Some(ProviderToken::with_refresh(
            access,
            new_rt,
            now_secs() + expires_in,
            scopes,
        )))
    }
}

// now_secs + urlencoding_encode are shared from super::types.

#[cfg(test)]
mod tests {
    use super::super::types::urlencoding_encode;
    use super::*;
    use crate::providers::types::ProviderConfig;
    use crate::providers::types::http_mock::MockApi;

    fn gl_at(base: &str) -> GitLabProvider {
        GitLabProvider::with_config(ProviderConfig {
            client_id: None,
            instance_url: Some(base.into()),
            client_secret: None,
        })
    }

    #[tokio::test]
    async fn add_collaborator_resolves_user_id_and_maps_levels() {
        let api = MockApi::start();
        let gl = gl_at(&api.base_url);
        let tok = ProviderToken::new("tok", "api");

        // Read-only: username -> id lookup, then Reporter(20).
        api.push(200, r#"[{"id": 42, "username": "alice"}]"#);
        api.push(201, r#"{"access_level": 20}"#);
        let st = gl
            .add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::ReadOnly)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        let (method, path, body) = &api.requests()[1];
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/v4/projects/o%2Fr/members");
        assert!(body.contains("\"user_id\":42"), "body: {body}");
        assert!(body.contains("\"access_level\":20"), "body: {body}");

        // Write: Developer(30).
        api.push(200, r#"[{"id": 42, "username": "alice"}]"#);
        api.push(201, "{}");
        gl.add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::Write)
            .await
            .unwrap();
        let (_, _, body) = &api.requests()[3];
        assert!(body.contains("\"access_level\":30"), "body: {body}");

        // Already a member (409) counts as Active — the seat exists.
        api.push(200, r#"[{"id": 42, "username": "alice"}]"#);
        api.push(409, "{}");
        let st = gl
            .add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::Write)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
    }

    #[tokio::test]
    async fn collaborator_status_and_unknown_user() {
        let api = MockApi::start();
        let gl = gl_at(&api.base_url);
        let tok = ProviderToken::new("tok", "api");

        // Member present -> Active.
        api.push(200, r#"[{"id": 7, "username": "bob"}]"#);
        api.push(200, r#"{"access_level": 30}"#);
        let st = gl.collaborator_status(&tok, "o", "r", "bob").await.unwrap();
        assert_eq!(st, CollaboratorStatus::Active);

        // Not a member -> None.
        api.push(200, r#"[{"id": 7, "username": "bob"}]"#);
        api.push(404, "");
        let st = gl.collaborator_status(&tok, "o", "r", "bob").await.unwrap();
        assert_eq!(st, CollaboratorStatus::None);

        // Unknown forge user fails closed — no silent seat assumption.
        api.push(200, "[]");
        let err = gl
            .collaborator_status(&tok, "o", "r", "ghost")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "err: {err}");
    }

    #[tokio::test]
    async fn remove_collaborator_idempotent() {
        let api = MockApi::start();
        let gl = gl_at(&api.base_url);
        let tok = ProviderToken::new("tok", "api");

        // 204 removes; 404 (seat already gone) is also success — the
        // offboarding pre-flight must not wedge on retries.
        api.push(200, r#"[{"id": 42, "username": "alice"}]"#);
        api.push(204, "");
        gl.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
        let (method, path, _) = &api.requests()[1];
        assert_eq!(method, "DELETE");
        assert_eq!(path, "/api/v4/projects/o%2Fr/members/42");

        api.push(200, r#"[{"id": 42, "username": "alice"}]"#);
        api.push(404, "");
        gl.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
    }

    #[test]
    fn provider_identity() {
        let gl = GitLabProvider::new();
        assert_eq!(gl.provider(), Provider::GitLab);
    }

    #[test]
    fn default_base_is_gitlab_com() {
        let gl = GitLabProvider::new();
        assert_eq!(gl.base(), "https://gitlab.com");
        assert_eq!(gl.api_base(), "https://gitlab.com/api/v4");
    }

    #[test]
    fn custom_instance_overrides_base() {
        let gl = GitLabProvider::with_config(ProviderConfig {
            instance_url: Some("https://gitlab.example.com/".into()),
            client_secret: None,
            client_id: None,
        });
        // trailing slash trimmed
        assert_eq!(gl.base(), "https://gitlab.example.com");
    }

    #[test]
    fn pat_detection() {
        let pat = ProviderToken::new("glpat-XXXXXXXXXXXX", "api");
        assert!(GitLabProvider::is_pat(&pat));
        let oauth = ProviderToken::new("some-oauth-token", "api");
        assert!(!GitLabProvider::is_pat(&oauth));
    }

    #[test]
    fn default_client_id_is_placeholder() {
        // Until the project GitLab OAuth app is registered, this is a sentinel.
        assert_eq!(
            Provider::GitLab.default_client_id(),
            "REPLACE_WITH_GITLAB_CLIENT_ID"
        );
    }

    #[test]
    fn urlencoding_encodes_branch_segments() {
        // Slashes in branch names must be encoded for the ref query param.
        assert_eq!(urlencoding_encode("main"), "main");
        assert_eq!(urlencoding_encode("feat/x"), "feat%2Fx");
    }

    #[test]
    fn project_to_repo_maps_fields() {
        let p = serde_json::json!({
            "path": "my-vault",
            "path_with_namespace": "alice/my-vault",
            "http_url_to_repo": "https://gitlab.com/alice/my-vault.git",
            "visibility": "private",
        });
        let r = GitLabProvider::project_to_repo(&p).unwrap();
        assert_eq!(r.name, "my-vault");
        assert_eq!(r.full_name, "alice/my-vault");
        assert!(r.private);
        assert!(r.clone_url.ends_with(".git"));
    }
}
