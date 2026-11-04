//! GitHub provider: device flow + PAT auth via octocrab.
//!
//! Device flow uses GitHub's OAuth app credentials (public client_id, no secret).
//! PAT: validates against /user endpoint before storing.
//! Repo creation uses raw POST /user/repos (octocrab doesn't expose it directly).

use async_trait::async_trait;
use base64::Engine as _;
use octocrab::Octocrab;
use octocrab::models::Repository;
use secrecy::ExposeSecret;

use super::types::{
    CollaboratorPermission, CollaboratorStatus, DeviceFlowSession, DeviceFlowStatus, ForgeProvider,
    OAuthStart, Provider, ProviderError, ProviderInfo, ProviderToken, VaultRepo,
    code_challenge_s256, generate_code_verifier, generate_state, urlencoding_encode,
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

/// HTTP statuses providers use to signal a repo-name conflict.
fn conflict_code(code: u16) -> bool {
    matches!(code, 409 | 422)
}

fn is_conflict(e: &octocrab::Error) -> bool {
    matches!(
        e,
        octocrab::Error::GitHub { source, .. } if conflict_code(source.status_code.as_u16())
    )
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
            // P8c-2 review: reqwest defaults to NO timeout — a hung forge
            // connection would wedge the caller (sync, seat strikes) forever.
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
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
        let mut builder =
            Octocrab::builder().personal_token(token.access_token().expose_secret().to_string());
        // GHES mounts REST under /api/v3; without this the enterprise PAT
        // would be sent to api.github.com instead of the instance.
        let base = self.config.effective_instance_url(Provider::GitHub);
        if base != Provider::GitHub.default_instance_url() {
            builder = builder
                .base_uri(format!("{base}/api/v3"))
                .map_err(api_error)?;
        }
        builder.build().map_err(api_error)
    }

    /// REST API base for raw reqwest calls (collaborator ops). The public
    /// instance talks to api.github.com; an explicit override is a
    /// self-hosted GitHub Enterprise Server and mounts REST under /api/v3.
    fn api_base(&self) -> String {
        let base = self.config.effective_instance_url(Provider::GitHub);
        if base == Provider::GitHub.default_instance_url() {
            "https://api.github.com".into()
        } else {
            format!("{base}/api/v3")
        }
    }

    /// Authenticated raw request for the collaborator ops.
    fn authed(
        &self,
        method: reqwest::Method,
        url: &str,
        token: &ProviderToken,
    ) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(
                "Authorization",
                format!("Bearer {}", token.access_token().expose_secret()),
            )
            .header("Accept", "application/vnd.github+json")
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

impl GitHubProvider {
    /// Tier 1: paginate the authenticated user's owned + collaborator
    /// repos and probe .baluard concurrently within each page (an invited
    /// joiner holds a read-only seat and must see the shared repo).
    async fn list_and_probe_owned(
        &self,
        token: &ProviderToken,
    ) -> Result<Vec<VaultRepo>, ProviderError> {
        let client = self.client_from_token(token)?;
        let mut found: Vec<VaultRepo> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut page: u8 = 1;
        loop {
            let page_repos: Vec<octocrab::models::Repository> = client
                .current()
                .list_repos_for_authenticated_user()
                // Collaborators too: an invited joiner holds a ReadOnly
                // seat on the shared repo and must see it to clone it.
                .affiliation("owner,collaborator")
                .per_page(100)
                .page(page)
                .send()
                .await
                .map_err(api_error)?
                .items;
            if page_repos.is_empty() {
                break;
            }
            let this = std::sync::Arc::new(Self::with_config(self.config.clone()));
            // Bound the fan-out: 100 simultaneous content requests trips
            // GitHub's secondary rate limits, and a limited probe looks
            // identical to "no marker".
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
            let mut tasks = tokio::task::JoinSet::new();
            for repo in page_repos {
                let client = client.clone();
                let this = this.clone();
                let sem = sem.clone();
                tasks.spawn(async move {
                    let _permit = sem.acquire_owned().await;
                    this.probe_marker(&client, &repo).await
                });
            }
            while let Some(res) = tasks.join_next().await {
                if let Ok(Some(r)) = res {
                    if seen.insert(r.full_name.clone()) {
                        found.push(r);
                    }
                }
            }
            page += 1;
            if page > 20 {
                break; // safety cap: 1000 repos
            }
        }
        Ok(found)
    }

    /// Fetch + parse .baluard for one repo. Returns the VaultRepo (built
    /// from the repo record) with slug/id filled in, or None when the marker
    /// is absent or unreadable.
    async fn probe_marker(
        &self,
        client: &octocrab::Octocrab,
        repo: &octocrab::models::Repository,
    ) -> Option<VaultRepo> {
        let full_name = repo.full_name.as_deref()?;
        let (owner, name) = full_name.split_once('/')?;
        let content = client
            .repos(owner, name)
            .get_content()
            .path(".baluard")
            .send()
            .await
            .ok()?;
        let encoded = content
            .items
            .into_iter()
            .find(|i| i.name == ".baluard")
            .and_then(|i| i.content)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.replace('\n', ""))
            .ok()?;
        let marker: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
        // Any parseable JSON is not a marker: an unrelated .baluard file
        // must not surface a slug-less vault in the picker.
        let (Some(slug), Some(vid)) = (
            marker["slug"].as_str().map(str::to_string),
            marker["vault_id"].as_str().map(str::to_string),
        ) else {
            return None;
        };
        let mut r = self.repo_to_vault(repo)?;
        r.vault_slug = Some(slug);
        r.vault_id = Some(vid);
        Some(r)
    }

    /// Tier 2: code search (filename:.baluard user:login). Supplementary
    /// only - the search index lags for fresh repos and may skip private
    /// repos, so tier 1 is the source of record.
    async fn search_marker_repos(
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
}

#[async_trait]
impl ForgeProvider for GitHubProvider {
    fn provider(&self) -> Provider {
        Provider::GitHub
    }

    /// Web application flow start (loopback redirect + PKCE). GitHub
    /// ignores RFC 8628 verification_uri_complete entirely, so the device
    /// flow can never pre-fill the code; the web flow is the mobile/desktop
    /// path where the browser redirects straight back with the code.
    async fn oauth_start(&self, redirect_uri: &str) -> Result<OAuthStart, ProviderError> {
        let verifier = generate_code_verifier();
        let challenge = code_challenge_s256(&verifier);
        let state = generate_state();
        let client_id = self.client_id();

        let params = [
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "repo"),
            ("state", state.as_str()),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge.as_str()),
        ];
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(OAuthStart {
            auth_url: format!("https://github.com/login/oauth/authorize?{}", query),
            code_verifier: verifier,
            state,
        })
    }

    /// Web flow token exchange. GitHub has no PKCE-only mode: the secret is
    /// required here even for native clients (the gh CLI ships its secret in
    /// public source for the same reason).
    async fn oauth_exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<(ProviderToken, ProviderInfo), ProviderError> {
        let secret = self
            .config
            .effective_client_secret(Provider::GitHub)
            .ok_or_else(|| {
                ProviderError::AuthFailed(
                    "GitHub web sign-in needs the app client secret; set BALUARD_GITHUB_CLIENT_SECRET"
                        .into(),
                )
            })?;
        let client_id = self.client_id();
        let resp = self
            .http
            .post(ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ])
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
            let desc = d["error_description"].as_str().unwrap_or("");
            return Err(ProviderError::AuthFailed(format!(
                "{}{}",
                err,
                if desc.is_empty() {
                    String::new()
                } else {
                    format!(": {}", desc)
                }
            )));
        }
        let access = d["access_token"]
            .as_str()
            .ok_or_else(|| ProviderError::Api("missing access_token".into()))?
            .to_string();
        let token = ProviderToken::new(access, d["scope"].as_str().unwrap_or("repo"));
        let info = self.validate_token(&token).await?;
        Ok((token, info))
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
                     docs/dev/git-provider-apps-and-tokens.md §3.2."
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
            // /user omits email without the `user:email` scope, which we
            // deliberately do not request (re-consent + noreply reality);
            // GitHub users type their email instead.
            email: None,
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
            // affiliation covers collaborator seats (see detect path); it
            // replaces type_ — GitHub treats the two as alternatives.
            .affiliation("owner,collaborator")
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
        // Tier 1 (primary): paginate owned + collaborator repos and probe
        // .baluard per repo.
        // Complete and immune to code-search indexing lag (N4: the search API
        // can miss private repos entirely and only indexes default branches).
        let mut found = self.list_and_probe_owned(token).await?;

        // Tier 2 (supplementary): code search catches vaults outside the
        // owned list (e.g. org-owned repos the user administers). Deduped.
        let extra = self.search_marker_repos(token).await?;
        for r in extra {
            if !found.iter().any(|f| f.full_name == r.full_name) {
                found.push(r);
            }
        }
        Ok(found)
    }

    async fn create_private_repo(
        &self,
        token: &ProviderToken,
        name: &str,
    ) -> Result<VaultRepo, ProviderError> {
        super::types::assert_safe_segment(name, "repository")?;
        let client = self.client_from_token(token)?;

        #[derive(serde::Serialize)]
        struct CreateRepoBody {
            name: String,
            private: bool,
            auto_init: bool,
        }

        let repo: Repository = match client
            .post(
                "/user/repos",
                Some(&CreateRepoBody {
                    name: name.to_string(),
                    private: true,
                    auto_init: false,
                }),
            )
            .await
        {
            Ok(repo) => repo,
            Err(e) => {
                // GitHub reports a name collision as 422 whose top-level
                // message is only "Repository creation failed." — the
                // "already exists" detail sits in errors[] and never
                // reaches upstream string matchers. Probe the repo
                // directly and adopt it when it already exists, private,
                // and owned by the token's user; anything else
                // propagates as the original error.
                if !is_conflict(&e) {
                    return Err(api_error(e));
                }
                let user = client.current().user().await.map_err(api_error)?;
                let probe = client.repos(&user.login, name).get().await;
                let adoptable = probe.as_ref().is_ok_and(|r| {
                    r.private.unwrap_or(false)
                        && r.owner.as_ref().is_some_and(|o| o.login == user.login)
                });
                if !adoptable {
                    return Err(api_error(e));
                }
                probe.map_err(|_| api_error(e))?
            }
        };

        // Safety: verify repo is private after creation
        if !repo.private.unwrap_or(false) {
            // Delete public repo immediately. The OAuth scope usually
            // lacks delete_repo: tell the user when the cleanup could not
            // run instead of claiming gone. The refusal must fire even
            // when the owner object is missing.
            let mut cleanup =
                " It could not be deleted automatically — delete it on the site.".to_string();
            if let Some(owner) = &repo.owner {
                let route = format!("/repos/{}/{}", owner.login, repo.name);
                if client
                    .delete::<(), _, ()>(route, None as Option<&()>)
                    .await
                    .is_ok()
                {
                    cleanup = String::new();
                }
            }
            return Err(ProviderError::RepoPublic(format!(
                "repo '{name}' was created public (safety abort).{cleanup}"
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
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(name, "repository")?;
        let client = self.client_from_token(token)?;
        let route = format!("/repos/{owner}/{name}");
        client
            .delete::<(), _, ()>(route, None as Option<&()>)
            .await
            .map_err(api_error)
    }

    async fn add_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
        permission: CollaboratorPermission,
    ) -> Result<CollaboratorStatus, ProviderError> {
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        super::types::assert_safe_segment(username, "member")?;
        // GitHub invitation flow: PUT creates a pending invitation (201)
        // or updates an existing collaborator's permission (204). `pull`
        // = read-only seat, `push` = write seat (P8c staging).
        let gh_permission = match permission {
            CollaboratorPermission::ReadOnly => "pull",
            CollaboratorPermission::Write => "push",
        };
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}",
            self.api_base()
        );
        let resp = self
            .authed(reqwest::Method::PUT, &url, token)
            .json(&serde_json::json!({ "permission": gh_permission }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            201 => Ok(CollaboratorStatus::Invited),
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
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        super::types::assert_safe_segment(username, "member")?;
        let api = self.api_base();
        // Effective-permission check: the endpoint reports the user's real
        // access INCLUDING org/team-inherited roles. `none` (or 404 for an
        // unknown user) means no effective seat — fall through to the
        // invitation scan. Any other failure propagates: the pre-flight
        // callers must never read a server error as "no seat".
        let url = format!("{api}/repos/{owner}/{repo}/collaborators/{username}/permission");
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            200 => {
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ProviderError::Api(e.to_string()))?;
                match body["permission"].as_str() {
                    Some("none") => {} // no effective seat; try invitations
                    Some(_) => return Ok(CollaboratorStatus::Active),
                    None => {
                        return Err(ProviderError::Api(
                            "collaborator permission: response missing permission field".into(),
                        ));
                    }
                }
            }
            404 => {} // unknown user; try invitations
            s => {
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Api(format!(
                    "collaborator permission HTTP {s}: {body}"
                )));
            }
        }
        // Pending invitation scan, paginated (the default page size is 30
        // and a large invite backlog must not hide the invitee). GitHub
        // invites expire server-side after 7 days; an expired one is
        // simply absent here, so the caller sees None and re-invites.
        let mut page = 1u8;
        loop {
            let url = format!("{api}/repos/{owner}/{repo}/invitations?per_page=100&page={page}");
            let resp = self
                .authed(reqwest::Method::GET, &url, token)
                .send()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            if resp.status().as_u16() != 200 {
                let s = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Api(format!(
                    "list invitations HTTP {s}: {body}"
                )));
            }
            let invites: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            let list = invites.as_array().cloned().unwrap_or_default();
            let wanted = username.to_lowercase();
            for invite in &list {
                let login = invite["invitee"]["login"]
                    .as_str()
                    .map(|l| l.to_lowercase());
                if login.as_deref() == Some(wanted.as_str()) {
                    return Ok(CollaboratorStatus::Invited);
                }
            }
            if list.len() < 100 || page >= 10 {
                break;
            }
            page += 1;
        }
        Ok(CollaboratorStatus::None)
    }

    async fn remove_collaborator(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        username: &str,
    ) -> Result<(), ProviderError> {
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        super::types::assert_safe_segment(username, "member")?;
        let api = self.api_base();
        // Strike the live seat first; 404 = no direct seat. Boundary:
        // DELETE removes DIRECT seats only — access inherited from a
        // GitHub org/team survives it. The offboarding pre-flight calls
        // collaborator_status AFTER this strike; a lingering Active
        // report is the screen-6 signal to remove the org seat by hand.
        let url = format!("{api}/repos/{owner}/{repo}/collaborators/{username}");
        let resp = self
            .authed(reqwest::Method::DELETE, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let status = resp.status().as_u16();
        if status == 204 {
            return Ok(());
        }
        if status != 404 {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Api(format!(
                "remove collaborator HTTP {status}: {body}"
            )));
        }
        // Fallback: cancel a pending invitation instead (removal pre-flight
        // must clear BOTH seat kinds; absent invitation = already gone).
        // Errors propagate — a swallowed lookup here would leave a live
        // invite behind while the caller believes the seat is gone.
        let wanted = username.to_lowercase();
        let mut page = 1u8;
        loop {
            let url = format!("{api}/repos/{owner}/{repo}/invitations?per_page=100&page={page}");
            let resp = self
                .authed(reqwest::Method::GET, &url, token)
                .send()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            if resp.status().as_u16() != 200 {
                let s = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Api(format!(
                    "list invitations HTTP {s}: {body}"
                )));
            }
            let invites: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ProviderError::Api(e.to_string()))?;
            let list = invites.as_array().cloned().unwrap_or_default();
            let invite_id = list.iter().find_map(|i| {
                let login = i["invitee"]["login"].as_str().map(|l| l.to_lowercase());
                if login.as_deref() == Some(wanted.as_str()) {
                    i["id"].as_u64()
                } else {
                    None
                }
            });
            if let Some(invite_id) = invite_id {
                let url = format!("{api}/repos/{owner}/{repo}/invitations/{invite_id}");
                let resp = self
                    .authed(reqwest::Method::DELETE, &url, token)
                    .send()
                    .await
                    .map_err(|e| ProviderError::Api(e.to_string()))?;
                if resp.status().as_u16() != 204 {
                    let s = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(ProviderError::Api(format!(
                        "cancel invitation HTTP {s}: {body}"
                    )));
                }
                return Ok(());
            }
            if list.len() < 100 || page >= 10 {
                return Ok(());
            }
            page += 1;
        }
    }

    async fn add_deploy_key(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> Result<u64, ProviderError> {
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        let url = format!("{}/repos/{owner}/{repo}/keys", self.api_base());
        let resp = self
            .authed(reqwest::Method::POST, &url, token)
            .json(&serde_json::json!({
                "title": title,
                "key": public_key,
                "read_only": true
            }))
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let status = resp.status();
        let body = resp.json::<serde_json::Value>().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ProviderError::Api(format!(
                "add deploy key HTTP {status}: {body}"
            )));
        }
        body.get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ProviderError::Api(format!("add deploy key: no id in {body}")))
    }

    async fn list_deploy_keys(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<super::types::DeployKey>, ProviderError> {
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        let url = format!("{}/repos/{owner}/{repo}/keys", self.api_base());
        let resp = self
            .authed(reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        let status = resp.status();
        let body = resp.json::<serde_json::Value>().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ProviderError::Api(format!(
                "list deploy keys HTTP {status}: {body}"
            )));
        }
        parse_deploy_keys(&body)
    }

    async fn remove_deploy_key(
        &self,
        token: &ProviderToken,
        owner: &str,
        repo: &str,
        key_id: u64,
    ) -> Result<(), ProviderError> {
        super::types::assert_safe_segment(owner, "owner")?;
        super::types::assert_safe_segment(repo, "repository")?;
        let url = format!("{}/repos/{owner}/{repo}/keys/{key_id}", self.api_base());
        let resp = self
            .authed(reqwest::Method::DELETE, &url, token)
            .send()
            .await
            .map_err(|e| ProviderError::Api(e.to_string()))?;
        match resp.status().as_u16() {
            204 => Ok(()),
            // Idempotent: the key was already gone.
            404 => Ok(()),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProviderError::Api(format!(
                    "remove deploy key HTTP {s}: {body}"
                )))
            }
        }
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

/// Parse a forge deploy-key array. GitHub /api/v3 returns the fields
/// directly; kept forgiving on absent `read_only` (older GHES) treating
/// absent as read-only because Baluard never arms writable keys.
fn parse_deploy_keys(
    body: &serde_json::Value,
) -> Result<Vec<super::types::DeployKey>, ProviderError> {
    let arr = body
        .as_array()
        .ok_or_else(|| ProviderError::Api("list deploy keys: not an array".into()))?;
    Ok(arr
        .iter()
        .map(|k| super::types::DeployKey {
            id: k.get("id").and_then(|v| v.as_u64()).unwrap_or(0),
            title: k
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            key: k
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            read_only: k.get("read_only").and_then(|v| v.as_bool()).unwrap_or(true),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn repo_name_conflicts_are_409_and_422() {
        assert!(super::conflict_code(422));
        assert!(super::conflict_code(409));
        assert!(!super::conflict_code(404));
        assert!(!super::conflict_code(403));
        assert!(!super::conflict_code(401));
    }

    use super::*;
    use crate::providers::types::ProviderConfig;
    use crate::providers::types::http_mock::MockApi;

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
        assert_eq!(
            error_chain(&Root),
            "Other: failed to load native certificates"
        );
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
        // Review note: mid-message "Found at" must survive; only the snafu
        // newline-anchored backtrace marker is stripped.
        assert_eq!(error_chain(&Plain), "no commit Found at ref main");
    }

    #[test]
    fn error_chain_strips_snafu_backtrace_marker() {
        #[derive(Debug)]
        struct SnafuErr;
        impl std::fmt::Display for SnafuErr {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "request failed\nFound at line 42 of file.rs")
            }
        }
        impl std::error::Error for SnafuErr {}
        assert_eq!(error_chain(&SnafuErr), "request failed");
    }

    #[test]
    fn error_chain_deduplicates_repeated_causes() {
        #[derive(Debug)]
        struct Child;
        impl std::fmt::Display for Child {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connection timeout")
            }
        }
        impl std::error::Error for Child {}

        #[derive(Debug)]
        struct Parent;
        impl std::fmt::Display for Parent {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "request error: connection timeout")
            }
        }
        impl std::error::Error for Parent {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&Child)
            }
        }
        assert_eq!(error_chain(&Parent), "request error: connection timeout");
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
        assert_eq!(
            vault.clone_url,
            "https://github.com/EstebanForge/baluard-personal.git"
        );
        assert!(vault.private);
        assert_eq!(vault.vault_slug, None);
        assert_eq!(vault.vault_id, None);
    }

    #[test]
    fn repo_to_vault_null_clone_url_rejected() {
        let gh = GitHubProvider::new();
        let json = r#"{ "id": 1, "name": "x", "url": "https://api.github.com/repos/o/x", "clone_url": null }"#;
        let repo: octocrab::models::Repository = serde_json::from_str(json).unwrap();
        assert!(gh.repo_to_vault(&repo).is_none());
    }

    fn gh_at(base: &str) -> GitHubProvider {
        GitHubProvider::with_config(ProviderConfig {
            client_id: None,
            instance_url: Some(base.into()),
            client_secret: None,
        })
    }

    #[tokio::test]
    async fn deploy_key_add_list_remove_roundtrip() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Add: POST body must pin read_only true, id surfaced.
        api.push(201, r#"{"id": 77}"#);
        let id = gh
            .add_deploy_key(&tok, "o", "r", "baluard-legacy-contact", "ssh-ed25519 AAA")
            .await
            .unwrap();
        assert_eq!(id, 77);
        let (method, path, body) = &api.requests()[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/v3/repos/o/r/keys");
        assert!(body.contains("\"read_only\":true"), "body: {body}");

        // List.
        api.push(
            200,
            r#"[{"id":77,"title":"baluard-legacy-contact","key":"ssh-ed25519 AAA","read_only":true}]"#,
        );
        let keys = gh.list_deploy_keys(&tok, "o", "r").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, 77);
        assert!(keys[0].read_only);

        // Remove: 204 first, then 404 stays idempotent success.
        api.push(204, "");
        gh.remove_deploy_key(&tok, "o", "r", 77).await.unwrap();
        let (method, path, _) = &api.requests()[2];
        assert_eq!(method, "DELETE");
        assert_eq!(path, "/api/v3/repos/o/r/keys/77");
        api.push(404, r#"{"message":"Not Found"}"#);
        gh.remove_deploy_key(&tok, "o", "r", 77).await.unwrap();
    }

    const MOCK_USER: &str = r#"{"login":"octocat","id":1,"node_id":"n1","avatar_url":"https://example.com/a.png","gravatar_id":"","url":"https://api.github.com/users/octocat","html_url":"https://github.com/octocat","followers_url":"https://api.github.com/users/octocat/followers","following_url":"https://api.github.com/users/octocat/following","gists_url":"https://api.github.com/users/octocat/gists","starred_url":"https://api.github.com/users/octocat/starred","subscriptions_url":"https://api.github.com/users/octocat/subscriptions","organizations_url":"https://api.github.com/users/octocat/orgs","repos_url":"https://api.github.com/users/octocat/repos","events_url":"https://api.github.com/users/octocat/events","received_events_url":"https://api.github.com/users/octocat/received_events","type":"User","site_admin":false}"#;

    #[tokio::test]
    async fn create_repo_adopts_existing_private_repo_on_name_conflict() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // GitHub's name-collision 422: the "already exists" detail sits in
        // errors[], so the top-level message upstream code matches on never
        // contains it. The create call must probe and adopt the repo.
        api.push(422, r#"{"message":"Repository creation failed.","errors":[{"resource":"Repository","code":"custom","field":"name","message":"name already exists on this account"}]}"#);
        api.push(200, MOCK_USER);
        // owner must deserialize as a full octocrab Author.
        api.push(
            200,
            &format!(
                r#"{{"id":9,"node_id":"r1","name":"baluard-vault","full_name":"octocat/baluard-vault","private":true,"owner":{MOCK_USER},"clone_url":"https://github.com/octocat/baluard-vault.git","url":"https://api.github.com/repos/octocat/baluard-vault","html_url":"https://github.com/octocat/baluard-vault"}}"#
            ),
        );

        let repo = gh.create_private_repo(&tok, "baluard-vault").await.unwrap();
        assert_eq!(repo.full_name, "octocat/baluard-vault");
        assert!(repo.private);
        assert_eq!(
            repo.clone_url,
            "https://github.com/octocat/baluard-vault.git"
        );
        let (method, path, _) = &api.requests()[1];
        assert_eq!(method, "GET");
        assert!(path.ends_with("/user"), "path: {path}");
        let (method, path, _) = &api.requests()[2];
        assert_eq!(method, "GET");
        assert!(
            path.ends_with("/repos/octocat/baluard-vault"),
            "path: {path}"
        );
    }

    #[tokio::test]
    async fn create_repo_name_conflict_without_existing_repo_propagates() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // A 422 whose probe misses (invalid name, quota) must surface the
        // original provider error, not be swallowed as "adopted".
        api.push(
            422,
            r#"{"message":"Validation Failed","errors":[{"field":"name","code":"invalid"}]}"#,
        );
        api.push(200, MOCK_USER);
        api.push(404, r#"{"message":"Not Found"}"#);

        let err = gh
            .create_private_repo(&tok, "baluard-vault")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Validation Failed"), "err: {err}");
    }

    #[tokio::test]
    async fn add_collaborator_invitation_and_existing_seat() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Fresh invitation: 201 -> Invited; read-only maps to `pull`.
        api.push(201, "{}");
        let st = gh
            .add_collaborator(&tok, "o", "r", "alice", CollaboratorPermission::ReadOnly)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Invited);
        let (method, path, body) = &api.requests()[0];
        assert_eq!(method, "PUT");
        assert_eq!(path, "/api/v3/repos/o/r/collaborators/alice");
        assert!(body.contains("\"pull\""), "body: {body}");

        // Existing seat: 204 -> Active; write maps to `push`.
        api.push(204, "");
        let st = gh
            .add_collaborator(&tok, "o", "r", "bob", CollaboratorPermission::Write)
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        let (_, _, body) = &api.requests()[1];
        assert!(body.contains("\"push\""), "body: {body}");
    }

    #[tokio::test]
    async fn collaborator_status_direct_invited_and_none() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Direct collaborator: one request, Active.
        api.push(
            200,
            r#"{"permission": "write", "user": {"login": "alice"}}"#,
        );
        let st = gh
            .collaborator_status(&tok, "o", "r", "alice")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Active);
        assert_eq!(api.requests().len(), 1);

        // No direct seat but a pending invitation -> Invited.
        api.push(200, r#"{"permission": "none"}"#);
        api.push(200, r#"[{"id": 9, "invitee": {"login": "Alice"}}]"#);
        let st = gh
            .collaborator_status(&tok, "o", "r", "alice")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Invited);

        // Neither seat nor invitation -> None (expired GitHub invites
        // surface exactly this way, so the caller re-invites).
        api.push(200, r#"{"permission": "none"}"#);
        api.push(200, "[]");
        let st = gh
            .collaborator_status(&tok, "o", "r", "carol")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::None);
    }

    #[tokio::test]
    async fn collaborator_status_fails_closed_on_errors() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Server error on the permission check propagates — the pre-flight
        // must never read a failure as "no seat".
        api.push(500, "boom");
        assert!(
            gh.collaborator_status(&tok, "o", "r", "alice")
                .await
                .is_err()
        );

        // Server error on the invitation scan propagates too.
        api.push(200, r#"{"permission": "none"}"#);
        api.push(503, "overloaded");
        assert!(
            gh.collaborator_status(&tok, "o", "r", "alice")
                .await
                .is_err()
        );

        // Malformed 200 body (missing permission field) fails closed
        // instead of reporting Active.
        api.push(200, "{}");
        let err = gh
            .collaborator_status(&tok, "o", "r", "alice")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing permission field"));
    }

    #[tokio::test]
    async fn collaborator_status_scans_invitation_pages() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Full first page (100 entries, no alice) -> the scan continues
        // to page 2 and finds her there.
        let page1: Vec<String> = (0..100)
            .map(|i| format!(r#"{{"id": {i}, "invitee": {{"login": "user{i}"}}}}"#))
            .collect();
        api.push(200, r#"{"permission": "none"}"#);
        api.push(200, &format!("[{}]", page1.join(",")));
        api.push(200, r#"[{"id": 777, "invitee": {"login": "alice"}}]"#);
        let st = gh
            .collaborator_status(&tok, "o", "r", "alice")
            .await
            .unwrap();
        assert_eq!(st, CollaboratorStatus::Invited);
        let (_, path2, _) = &api.requests()[2];
        assert_eq!(path2, "/api/v3/repos/o/r/invitations?per_page=100&page=2");
    }

    #[tokio::test]
    async fn remove_collaborator_live_seat_pending_invite_and_errors() {
        let api = MockApi::start();
        let gh = gh_at(&api.base_url);
        let tok = ProviderToken::new("tok", "repo");

        // Live seat: single DELETE, 204 -> Ok.
        api.push(204, "");
        gh.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
        let (method, path, _) = &api.requests()[0];
        assert_eq!(method, "DELETE");
        assert_eq!(path, "/api/v3/repos/o/r/collaborators/alice");

        // No live seat (404) but a pending invitation: the invite is
        // cancelled via its id. Absent invitation = already gone, Ok.
        api.push(404, "");
        api.push(200, r#"[{"id": 42, "invitee": {"login": "alice"}}]"#);
        api.push(204, "");
        gh.remove_collaborator(&tok, "o", "r", "alice")
            .await
            .unwrap();
        let (method, path, _) = &api.requests()[3];
        assert_eq!(method, "DELETE");
        assert_eq!(path, "/api/v3/repos/o/r/invitations/42");

        // A server error on the invitation lookup propagates — swallowing
        // it would leave a live invite behind while the caller believes
        // the seat is gone.
        api.push(404, "");
        api.push(500, "boom");
        assert!(
            gh.remove_collaborator(&tok, "o", "r", "alice")
                .await
                .is_err()
        );

        // Server error propagates — the pre-flight must see the failure.
        api.push(500, "boom");
        assert!(
            gh.remove_collaborator(&tok, "o", "r", "alice")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn web_oauth_start_builds_pkce_authorize_url() {
        let gh = GitHubProvider::new();
        let start = gh
            .oauth_start("http://127.0.0.1:1234/callback")
            .await
            .unwrap();
        assert!(
            start
                .auth_url
                .starts_with("https://github.com/login/oauth/authorize?")
        );
        assert!(start.auth_url.contains("client_id="));
        assert!(
            start
                .auth_url
                .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcallback")
        );
        assert!(start.auth_url.contains("response_type=code"));
        assert!(start.auth_url.contains("scope=repo"));
        assert!(start.auth_url.contains("code_challenge_method=S256"));
        assert!(start.auth_url.contains("code_challenge="));
        assert!(start.auth_url.contains("state="));
        assert!(start.code_verifier.len() >= 43);
    }

    #[test]
    fn web_oauth_secret_chain_shape() {
        // The embedded default ships (the app registration handed the secret
        // over), so the exchange no longer fails closed on GitHub; the chain
        // contract that remains is explicit-override-wins and per-provider
        // defaults.
        assert!(Provider::GitHub.default_client_secret().is_some());
        assert!(Provider::GitLab.default_client_secret().is_none());
        assert!(Provider::Codeberg.default_client_secret().is_none());
        // An explicit config override wins even when empty (set for the
        // flow's lifetime only; it never persists to providers.json).
        let cfg = ProviderConfig {
            client_id: None,
            instance_url: None,
            client_secret: Some(String::new()),
        };
        assert_eq!(
            cfg.effective_client_secret(Provider::GitHub),
            Some(String::new())
        );
    }

    #[test]
    fn github_supports_web_oauth() {
        assert!(Provider::GitHub.supports_web_oauth());
        assert!(Provider::Codeberg.supports_web_oauth());
        assert!(!Provider::GitLab.supports_web_oauth());
    }
}
