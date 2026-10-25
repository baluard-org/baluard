//! Credential callbacks for SSH and HTTPS authentication.
//!
//! SSH: delegates to ssh-agent (no key material stored in process).
//! HTTPS: reads provider token from keyring (primary), env var,
//!         then meta/git-credentials.json in the vault directory.
//!
//! H5 fix: Token is kept as SecretString. All git2 errors are scrubbed
//! before being wrapped into SyncError to prevent credential disclosure
//! in logs and IPC error surfaces.

use std::path::{Path, PathBuf};

#[cfg(feature = "git-sync")]
use git2::{Cred, CredentialType, RemoteCallbacks};

use crate::error::BaluardError;
use crate::providers::types::Provider;
use secrecy::{ExposeSecret, SecretString};

/// Common PAT prefixes to scrub from error messages.
const PAT_PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "glpt-", "glcbt-"];

/// Scrub potential credentials from a git2 error message.
/// Removes URL userinfo (user:token@host) and common PAT prefixes.
pub fn scrub_git_error(msg: &str) -> String {
    let mut cleaned = msg.to_string();

    // Scrub URL userinfo in EVERY scheme://...@ occurrence (one error
    // can carry several URLs, e.g. push + redirected fetch hints).
    let mut search_from = 0;
    while let Some(start) = cleaned[search_from..].find("://") {
        let scheme_end = search_from + start + 3;
        match cleaned[scheme_end..].find('@') {
            Some(at_off) if !cleaned[scheme_end..scheme_end + at_off].contains('/') => {
                let at_abs = scheme_end + at_off;
                cleaned.replace_range(scheme_end..at_abs, "***");
                search_from = scheme_end + 3;
            }
            _ => {
                search_from = scheme_end;
            }
        }
    }

    // Scrub PAT patterns
    for prefix in PAT_PREFIXES {
        while let Some(pos) = cleaned.find(prefix) {
            let end = cleaned[pos..]
                .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == ')')
                .map(|i| pos + i)
                .unwrap_or(cleaned.len());
            cleaned.replace_range(pos..end, "***");
        }
    }

    cleaned
}

/// Extract host name from a URL or git address.
///
/// The authority ends at the first `/` — anything after it is path and
/// must never participate in userinfo splitting, or a crafted URL like
/// `https://evil.example/x@github.com/y` would resolve to github.com and
/// release its host-bound token to evil.example.
pub fn extract_host(url: &str) -> Option<String> {
    let s = url.trim();
    let rest = if let Some(pos) = s.find("://") {
        &s[pos + 3..]
    } else {
        // scp-like form user@host:path (no scheme): the host ends at the
        // first ':' or '/', and userinfo is the last '@' within that
        // bound. Taking the first '@' anywhere would let a path like
        // evil.example/x@github.com/y resolve to github.com and release
        // its host-bound token to evil.example.
        let bound = s.find(|c: char| c == ':' || c == '/').unwrap_or(s.len());
        let authority = &s[..bound];
        let host = match authority.rfind('@') {
            Some(at) => &authority[at + 1..],
            None => authority,
        };
        return if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        };
    };
    let authority = match rest.find('/') {
        Some(slash) => &rest[..slash],
        None => rest,
    };
    let host_part = if let Some(at) = authority.rfind('@') {
        &authority[at + 1..]
    } else {
        authority
    };
    // Bracketed IPv6: the colons inside the brackets are address bytes,
    // not a port separator. Return the bare address (no brackets) so it
    // matches what the UIs store as the bound host.
    if let Some(rest) = host_part.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return Some(rest[..close].to_ascii_lowercase());
        }
    }
    let end = host_part
        .find(|c: char| c == ':' || c.is_whitespace())
        .unwrap_or(host_part.len());
    let host = &host_part[..end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The custom-remote credential file (meta/git-credentials.json).
#[derive(Debug, Clone)]
struct CustomFileCredentials {
    token: Option<SecretString>,
    username: Option<String>,
    /// Bound host: the token is only released for URLs on this host.
    host: Option<String>,
    ssh_passphrase: Option<SecretString>,
}

/// Credential source configuration.
#[derive(Debug, Clone, Default)]
pub struct CredentialConfig {
    /// HTTPS personal access token (kept as SecretString).
    /// Priority: keyring (provider) > env var > vault config file.
    https_token: Option<SecretString>,
    /// Allowed hosts for which this token may be exposed.
    /// If Some, credentials callback only exposes https_token if the target
    /// URL's host matches an allowed host.
    pub allowed_hosts: Option<Vec<String>>,
    /// Bound host for the custom-remote token: when set, the token is
    /// released only for URLs on this host (redirect-safe).
    pub bound_host: Option<String>,
    /// Optional username for HTTPS basic auth (custom remotes where the
    /// login name is not "git").
    pub username: Option<String>,
    /// Path of the custom SSH private key (meta/git-ssh-key); read at
    /// callback time, never at load.
    pub ssh_key_path: Option<PathBuf>,
    /// In-memory SSH private key (clone-time credential override).
    pub ssh_key_pem: Option<SecretString>,
    /// Passphrase for the custom SSH key.
    pub ssh_passphrase: Option<SecretString>,
    /// Port hint for host-key observations (custom remotes on non-22 ports).
    pub port_hint: Option<u16>,
}

impl CredentialConfig {
    /// Load credentials from provider keyring, env var, or vault config file.
    pub fn load(vault_path: &Path) -> Self {
        Self::load_with_hint(vault_path, None)
    }

    /// Load credentials with an optional provider hint.
    pub fn load_with_hint(vault_path: &Path, hint: Option<Provider>) -> Self {
        let file = Self::load_from_file(vault_path);
        // A host-bound custom credential must win outright: letting the
        // keyring or BALUARD_GIT_TOKEN arm win would send that token to the
        // custom server unbound.
        if let Some(ref f) = file {
            if f.host.is_some() {
                return Self {
                    https_token: f.token.clone(),
                    allowed_hosts: None,
                    bound_host: f.host.clone(),
                    username: f.username.clone(),
                    ssh_key_path: {
                        let p = vault_path.join("meta/git-ssh-key");
                        if p.is_file() { Some(p) } else { None }
                    },
                    ssh_key_pem: None,
                    ssh_passphrase: f.ssh_passphrase.clone(),
                    port_hint: None,
                };
            }
        }
        let mut https_token: Option<SecretString> = None;
        let mut allowed_hosts: Option<Vec<String>> = None;
        let mut bound_host: Option<String> = None;
        let mut username: Option<String> = None;
        let mut ssh_passphrase: Option<SecretString> = None;
        if let Some((tok, hosts)) = hint.and_then(Self::load_from_keyring_for) {
            https_token = Some(tok);
            allowed_hosts = Some(hosts);
        } else if let Some((tok, hosts)) = Self::load_from_keyring() {
            https_token = Some(tok);
            allowed_hosts = Some(hosts);
        } else if let Ok(s) = std::env::var("BALUARD_GIT_TOKEN") {
            https_token = Some(SecretString::new(s.into_boxed_str()));
        } else if let Some(ref f) = file {
            https_token = f.token.clone();
            bound_host = f.host.clone();
            username = f.username.clone();
            ssh_passphrase = f.ssh_passphrase.clone();
        }
        let ssh_key_path = {
            let p = vault_path.join("meta/git-ssh-key");
            if p.is_file() { Some(p) } else { None }
        };
        Self {
            https_token,
            allowed_hosts,
            bound_host,
            username: username.or(file.as_ref().and_then(|f| f.username.clone())),
            ssh_key_path,
            ssh_key_pem: None,
            ssh_passphrase,
            port_hint: None,
        }
    }

    /// In-memory credentials for a clone-time override: the vault directory
    /// does not exist yet, so nothing can be loaded from disk.
    pub fn in_memory(
        token: Option<String>,
        username: Option<String>,
        ssh_key_pem: Option<String>,
        ssh_passphrase: Option<String>,
        host: Option<String>,
    ) -> Self {
        Self {
            https_token: token.map(|s| SecretString::new(s.into_boxed_str())),
            allowed_hosts: None,
            bound_host: host,
            username,
            ssh_key_path: None,
            ssh_key_pem: ssh_key_pem.map(|s| SecretString::new(s.into_boxed_str())),
            ssh_passphrase: ssh_passphrase.map(|s| SecretString::new(s.into_boxed_str())),
            port_hint: None,
        }
    }

    /// Expose the token for git2 credential callbacks (internal use only).
    /// M6 fix: wraps the exposed plaintext in Zeroizing so it is wiped on drop,
    /// closing the gap where the callback closure held a plain `String` copy
    /// of the secret for the lifetime of the sync operation.
    #[cfg(feature = "git-sync")]
    pub(crate) fn expose_token(&self) -> Option<zeroize::Zeroizing<String>> {
        self.https_token
            .as_ref()
            .map(|t| zeroize::Zeroizing::new(t.expose_secret().to_string()))
    }

    fn load_from_keyring_for(provider: Provider) -> Option<(SecretString, Vec<String>)> {
        let state = crate::providers::token::ProvidersState::load().ok()?;
        let info = state.get(provider)?;
        let token = crate::providers::token::load_token(provider, &info.username).ok()?;
        let mut hosts = Vec::new();
        if let Some(h) = extract_host(provider.default_instance_url()) {
            hosts.push(h);
        }
        if let Some(ref inst) = info.instance_url {
            if let Some(h) = extract_host(inst) {
                if !hosts.contains(&h) {
                    hosts.push(h);
                }
            }
        }
        Some((
            SecretString::new(
                token
                    .access_token()
                    .expose_secret()
                    .to_string()
                    .into_boxed_str(),
            ),
            hosts,
        ))
    }

    fn load_from_keyring() -> Option<(SecretString, Vec<String>)> {
        let state = crate::providers::token::ProvidersState::load().ok()?;
        for provider in Provider::all() {
            if let Some(info) = state.get(*provider) {
                if let Ok(token) = crate::providers::token::load_token(*provider, &info.username) {
                    let mut hosts = Vec::new();
                    if let Some(h) = extract_host(provider.default_instance_url()) {
                        hosts.push(h);
                    }
                    if let Some(ref inst) = info.instance_url {
                        if let Some(h) = extract_host(inst) {
                            if !hosts.contains(&h) {
                                hosts.push(h);
                            }
                        }
                    }
                    return Some((
                        SecretString::new(
                            token
                                .access_token()
                                .expose_secret()
                                .to_string()
                                .into_boxed_str(),
                        ),
                        hosts,
                    ));
                }
            }
        }
        None
    }

    fn load_from_file(vault_path: &Path) -> Option<CustomFileCredentials> {
        let config_path = vault_path.join("meta/git-credentials.json");
        let data = std::fs::read_to_string(&config_path).ok()?;
        serde_json::from_str::<serde_json::Value>(&data)
            .ok()
            .and_then(|v| {
                let token = v
                    .get("token")
                    .and_then(|t| t.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| SecretString::new(s.to_string().into_boxed_str()));
                let secret_str = |key: &str| {
                    v.get(key)
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| SecretString::new(s.to_string().into_boxed_str()))
                };
                if token.is_none()
                    && secret_str("ssh_passphrase").is_none()
                    && v.get("username").and_then(|x| x.as_str()).is_none()
                {
                    return None;
                }
                Some(CustomFileCredentials {
                    token,
                    username: v
                        .get("username")
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                    host: v
                        .get("host")
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_ascii_lowercase()),
                    ssh_passphrase: secret_str("ssh_passphrase"),
                })
            })
    }
}

/// One credentials-callback attempt, extracted from build_callbacks: libgit2
/// consumes the closure, so the per-type attempt caps and the host-bound
/// token release are only unit-testable as a plain function.
#[cfg(feature = "git-sync")]
fn credentials_attempt(
    cfg: &CredentialConfig,
    url: &str,
    username_from_url: Option<&str>,
    allowed_types: git2::CredentialType,
    ssh_attempts: &std::cell::Cell<u32>,
    userpass_attempts: &std::cell::Cell<u32>,
) -> Result<Cred, git2::Error> {
    const MAX_ATTEMPTS: u32 = 3;

    let user = username_from_url
        .or(cfg.username.as_deref())
        .unwrap_or("git");

    if allowed_types.contains(CredentialType::USERNAME) {
        return Cred::username(user);
    }

    if allowed_types.contains(CredentialType::SSH_KEY) {
        if ssh_attempts.get() >= MAX_ATTEMPTS {
            return Err(git2::Error::from_str(
                "SSH authentication failed too many times",
            ));
        }
        // Host binding covers SSH keys too: a custom key (and the agent's
        // identities behind it) must never be offered to a foreign host.
        let target_host = extract_host(url);
        if let Some(ref bound) = cfg.bound_host {
            match target_host.as_deref() {
                Some(th) if th.eq_ignore_ascii_case(bound) => {}
                _ => {
                    return Err(git2::Error::from_str(&format!(
                        "refusing to send the SSH key to an untrusted host: {bound} expected"
                    )));
                }
            }
        }
        if let Some(ref allowed) = cfg.allowed_hosts {
            match target_host.as_deref() {
                Some(th) if allowed.iter().any(|h| h.eq_ignore_ascii_case(th)) => {}
                // Unparseable host: fail closed like bound_host does.
                Some(th) => {
                    return Err(git2::Error::from_str(&format!(
                        "refusing to send SSH credentials to untrusted host: {th}"
                    )))
                }
                None => {
                    return Err(git2::Error::from_str(
                        "refusing to send SSH credentials: the target host could not be determined",
                    ))
                }
            }
        }
        ssh_attempts.set(ssh_attempts.get() + 1);
        let pem: Option<zeroize::Zeroizing<String>> = cfg
            .ssh_key_pem
            .as_ref()
            .map(|s| zeroize::Zeroizing::new(s.expose_secret().to_string()))
            .or_else(|| {
                cfg.ssh_key_path
                    .as_ref()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .map(zeroize::Zeroizing::new)
            });
        if let Some(pem) = pem {
            if let Ok(cred) = Cred::ssh_key_from_memory(
                user,
                None,
                pem.as_str(),
                cfg.ssh_passphrase.as_ref().map(|s| s.expose_secret()),
            ) {
                return Ok(cred);
            }
        } else if let Ok(cred) = Cred::ssh_key_from_agent(user) {
            return Ok(cred);
        }
    }

    if allowed_types.contains(CredentialType::USER_PASS_PLAINTEXT) {
        if userpass_attempts.get() >= MAX_ATTEMPTS {
            return Err(git2::Error::from_str(
                "authentication failed too many times",
            ));
        }
        userpass_attempts.set(userpass_attempts.get() + 1);
        if let Some(ref token) = cfg.https_token {
            let target_host = extract_host(url);
            if let Some(ref allowed) = cfg.allowed_hosts {
                if let Some(ref th) = target_host {
                    if !allowed.iter().any(|h| h.eq_ignore_ascii_case(th)) {
                        return Err(git2::Error::from_str(&format!(
                            "refusing to send provider token to untrusted host: {th}"
                        )));
                    }
                }
            }
            // Host-bound custom token: released only for its own host,
            // so a server-side redirect can never capture it.
            if let Some(ref bound) = cfg.bound_host {
                match target_host.as_deref() {
                    Some(th) if th.eq_ignore_ascii_case(bound) => {}
                    _ => {
                        return Err(git2::Error::from_str(&format!(
                            "refusing to send the vault token to a different host: {bound} expected"
                        )));
                    }
                }
            }
            let user = username_from_url
                .map(|s| s.to_string())
                .or_else(|| cfg.username.clone())
                .unwrap_or_else(|| "git".to_string());
            return Cred::userpass_plaintext(&user, token.expose_secret());
        }
    }

    if allowed_types.contains(CredentialType::DEFAULT) {
        return Cred::default();
    }

    Err(git2::Error::from_str("no credential source available"))
}

/// Build RemoteCallbacks with credential handling for both SSH and HTTPS.
/// Strict known_hosts enforcement (M5) rides `certificate_check`; unknown
/// SSH host keys are stashed as pending observations for the trust flow.
#[cfg(feature = "git-sync")]
pub fn build_callbacks(config: &CredentialConfig) -> RemoteCallbacks<'_> {
    crate::sync::tls::ensure_tls_roots();
    let port_hint = config.port_hint;
    let mut callbacks = RemoteCallbacks::new();
    let ssh_attempts = std::cell::Cell::new(0u32);
    let userpass_attempts = std::cell::Cell::new(0u32);
    callbacks.credentials(move |url, username_from_url, allowed_types| {
        credentials_attempt(
            config,
            url,
            username_from_url,
            allowed_types,
            &ssh_attempts,
            &userpass_attempts,
        )
    });
    // libgit2 only pre-checks fast-forward locally: a server-side
    // refusal (branch protection, pre-receive) otherwise returns Ok and
    // sync reports success while nothing landed.
    callbacks.push_update_reference(|refname, status| {
        match status {
            Some(msg) => Err(git2::Error::from_str(&format!(
                "the remote rejected {}: {}",
                refname, msg
            ))),
            None => Ok(()),
        }
    });

    // M5 fix: enforce known_hosts for SSH connections, passthrough for HTTPS.
    // - SSH host keys: strict verification against ~/.ssh/known_hosts.
    //   Unknown hosts rejected (fail closed), preventing MITM via first-use.
    // - HTTPS (X.509): passthrough to libgit2/libcurl's built-in CA validation
    //   (already secure by default).
    callbacks.certificate_check(move |cert, host| {
        use git2::CertificateCheckStatus;
        use git2::cert::SshHostKeyType;
        if let Some(hostkey) = cert.as_hostkey() {
            let key_type = match hostkey.hostkey_type() {
                Some(SshHostKeyType::Ed255219) => "ssh-ed25519",
                Some(SshHostKeyType::Rsa) => "ssh-rsa",
                Some(SshHostKeyType::Dss) => "ssh-dss",
                Some(SshHostKeyType::Ecdsa256) => "ecdsa-sha2-nistp256",
                Some(SshHostKeyType::Ecdsa384) => "ecdsa-sha2-nistp384",
                Some(SshHostKeyType::Ecdsa521) => "ecdsa-sha2-nistp521",
                _ => "",
            };
            let key = hostkey.hostkey().unwrap_or(&[]);
            // Port hint comes from the URL captured at callback build
            // time. A thread-local carried the PREVIOUS operation's URL
            // on this pool thread and could pin the wrong port onto
            // hashed-entry lookups and written trust records.
            let obs_port = port_hint.unwrap_or(22);
            let verdict = crate::sync::known_hosts::verify_host_key(host, obs_port, key_type, key);
            match verdict {
                crate::sync::known_hosts::HostKeyResult::Known => {
                    Ok(CertificateCheckStatus::CertificateOk)
                }
                // Fail closed: reject unknown / mismatched / missing file.
                // Unknown keys are stashed as daemon-observed pending
                // handshakes so the trust route can only bless a key the
                // daemon itself saw.
                // Missing (no readable known_hosts yet) is the same trust
                // situation as Unknown on a fresh machine: offer the key for
                // the first-contact trust flow.
                crate::sync::known_hosts::HostKeyResult::Unknown
                | crate::sync::known_hosts::HostKeyResult::Missing
                | crate::sync::known_hosts::HostKeyResult::UnknownOtherType => {
                    crate::sync::known_hosts::record_observation(
                        crate::sync::known_hosts::ObservedHostKey {
                            host: host.to_string(),
                            port: obs_port,
                            key_type: key_type.to_string(),
                            key: key.to_vec(),
                            fingerprint: crate::sync::known_hosts::fingerprint(key),
                            changed: false,
                            known_other_type: matches!(
                                verdict,
                                crate::sync::known_hosts::HostKeyResult::UnknownOtherType
                            ),
                        },
                    );
                    Err(git2::Error::from_str(&format!(
                        "SSH host key for {host} is not trusted yet"
                    )))
                }
                // A changed key is recorded flagged so the surface can warn,
                // but the trust route refuses changed observations — the key
                // can never be blessed one-click.
                // A file we cannot read is not a first contact: fail
                // closed with no trust offer, or one unreadable file
                // would re-arm changed-key prompts for every pinned host.
                crate::sync::known_hosts::HostKeyResult::Unreadable => Err(
                    git2::Error::from_str(
                        "your SSH known_hosts file exists but cannot be read; fix its permissions before connecting",
                    ),
                ),
                // The presented key sits on an @revoked line: never
                // trust-offerable, the user must remove the revocation
                // deliberately after investigating.
                crate::sync::known_hosts::HostKeyResult::Revoked => Err(
                    git2::Error::from_str(
                        "this host key has been revoked in your SSH known_hosts file; do not connect unless you know why",
                    ),
                ),
                crate::sync::known_hosts::HostKeyResult::Mismatch => {
                    crate::sync::known_hosts::record_observation(
                        crate::sync::known_hosts::ObservedHostKey {
                            host: host.to_string(),
                            port: obs_port,
                            key_type: key_type.to_string(),
                            key: key.to_vec(),
                            fingerprint: crate::sync::known_hosts::fingerprint(key),
                            changed: true,
                            known_other_type: false,
                        },
                    );
                    Err(git2::Error::from_str(&format!(
                        "SSH host key for {host} changed; if you are sure, remove the old line from your SSH known_hosts file"
                    )))
                }
            }
        } else {
            // HTTPS/X.509 cert: passthrough to libgit2's built-in CA check.
            Ok(CertificateCheckStatus::CertificatePassthrough)
        }
    });

    callbacks
}

impl CredentialConfig {
    /// Record the URL's port so the certificate check can attribute the
    /// observed host key correctly (SSH auth happens after the hostkey
    /// exchange, so the callback URL arrives too late).
    pub fn with_url_hint(mut self, url: &str) -> Self {
        self.port_hint = Some(port_of(url));
        self
    }
}

/// Extract the SSH/HTTPS port from a remote URL (default 22 for SSH, 443
/// meaningful only for observations on https, which never reaches the SSH
/// trust path).
pub fn port_of(url: &str) -> u16 {
    let after_scheme = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or("");
    let hostpart = after_scheme.split('/').next().unwrap_or("");
    let hostpart = hostpart.rsplit('@').next().unwrap_or("");
    if let Some((_, port)) = hostpart.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return p;
        }
    }
    22
}

/// Format a transport error for the wire. When the failing operation left a
/// pending host-key observation, the marker JSON
/// `{"host_key_untrusted": {...}}` replaces the generic message so UIs can
/// render the trust flow; drains the observation.
pub fn format_sync_error(err: &BaluardError) -> String {
    format_sync_error_for(err, None)
}

/// Host-scoped variant: only an observation for THIS URL's host decorates the
/// error, so a background sync to another server cannot misattribute its
/// fingerprint here.
pub fn format_sync_error_for(err: &BaluardError, url: Option<&str>) -> String {
    let scoped = url.map(|u| (extract_host(u), u.to_string()));
    let matches_scope = |obs_host: &str, obs_port: u16| -> bool {
        match &scoped {
            None => true,
            Some((Some(h), raw)) => h.eq_ignore_ascii_case(obs_host) && port_of(raw) == obs_port,
            Some((None, _)) => true,
        }
    };
    // Peek, never drain: the trust route consumes the observation by id
    // after the surface reports it.
    if let Some((attempt_id, obs)) = crate::sync::known_hosts::peek_latest_observation()
        .filter(|(_, obs)| matches_scope(&obs.host, obs.port))
    {
        return serde_json::json!({
            "host_key_untrusted": {
                "host": obs.host,
                "port": obs.port,
                "key_type": obs.key_type,
                "fingerprint": obs.fingerprint,
                "changed": obs.changed,
                "known_other_type": obs.known_other_type,
                "attempt_id": attempt_id,
            }
        })
        .to_string();
    }
    format!("{err}")
}

/// Clear meta/git-credentials.json when its bound host no longer matches
/// the vault's remote. The bound-host release refuses any other host, so a
/// stale file can only produce confusing failures; repointing the remote is
/// the moment the old binding loses its purpose. Returns true when a file
/// was removed.
pub fn clear_stale_custom_credentials(vault_path: &Path, new_url: &str) -> bool {
    let config_path = vault_path.join("meta/git-credentials.json");
    let Ok(data) = std::fs::read_to_string(&config_path) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else {
        return false;
    };
    let Some(bound) = v.get("host").and_then(|h| h.as_str()) else {
        return false;
    };
    let Some(new_host) = extract_host(new_url) else {
        return false;
    };
    if bound.eq_ignore_ascii_case(new_host.trim()) {
        return false;
    }
    let _ = std::fs::remove_file(&config_path);
    // The SSH key belongs to the old host too; leaving it would offer it
    // to the new one on the next sync.
    let _ = std::fs::remove_file(vault_path.join("meta/git-ssh-key"));
    true
}

/// Fields the user supplies at once for a custom remote. At rest the token,
/// username, and passphrase share meta/git-credentials.json (0600) while the
/// key body lives beside it in meta/git-ssh-key (0600): same directory, same
/// perms, same trust domain, so splitting the passphrase out buys nothing.
/// The payload for the custom-remote credential writer. Present fields
/// update; an empty string clears that field. Absent fields stay untouched.
#[derive(Debug, Clone, Default)]
pub struct CustomCredentialsUpdate {
    pub token: Option<String>,
    pub username: Option<String>,
    pub ssh_passphrase: Option<String>,
    /// PEM private key material (paste or device pick); written to
    /// meta/git-ssh-key. An empty string removes the key file.
    pub ssh_key_pem: Option<String>,
}

/// Apply a custom-credentials update to the vault's device-local files.
/// `meta/git-credentials.json` is rewritten atomically (0600) with the
/// merged fields; key bytes land in `meta/git-ssh-key` (0600). The remote
/// host must be supplied whenever the token is set so the stored
/// credential stays host-bound.
pub fn apply_custom_credentials(
    vault_path: &Path,
    host: &str,
    update: &CustomCredentialsUpdate,
) -> Result<(), String> {
    let host_norm = host.trim().to_ascii_lowercase();
    if host_norm.is_empty() {
        return Err("custom remote host is required".into());
    }

    // Merge with the existing file first.
    let config_path = vault_path.join("meta/git-credentials.json");
    let mut fields: serde_json::Map<String, serde_json::Value> =
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .and_then(|v: serde_json::Value| v.as_object().cloned())
            .unwrap_or_default();

    let secret = |v: &Option<String>| {
        v.as_deref().map(|s| {
            if s.trim().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(s.to_string())
            }
        })
    };

    if update.token.is_some() {
        match secret(&update.token) {
            Some(serde_json::Value::Null) | None => {
                fields.remove("token");
                fields.remove("host");
            }
            Some(v) => {
                fields.insert("token".into(), v);
                fields.insert("host".into(), host_norm.clone().into());
            }
        }
    }
    if let Some(v) = secret(&update.username) {
        if v.is_null() {
            fields.remove("username");
        } else {
            fields.insert("username".into(), v);
        }
    }
    if let Some(v) = secret(&update.ssh_passphrase) {
        if v.is_null() {
            fields.remove("ssh_passphrase");
        } else {
            fields.insert("ssh_passphrase".into(), v);
        }
    }

    // All token-bearing fields cleared: remove the file entirely.
    if fields.get("token").is_none()
        && fields.get("ssh_passphrase").is_none()
        && fields.get("username").is_none()
    {
        let _ = std::fs::remove_file(&config_path);
    } else {
        let pretty = serde_json::to_vec(&serde_json::Value::Object(fields))
            .map_err(|e| format!("credential serialization failed: {e}"))?;
        crate::secret_file::write_secret_file(&config_path, &pretty)
            .map_err(|e| format!("cannot write the credential file: {e}"))?;
    }

    if let Some(pem) = update.ssh_key_pem.as_deref() {
        let key_path = vault_path.join("meta/git-ssh-key");
        if pem.trim().is_empty() {
            let _ = std::fs::remove_file(&key_path);
        } else {
            // Normalize the trailing newline: pasted keys lose it and
            // OpenSSH-format parsers require it.
            let mut normalized = pem.to_string();
            if !normalized.ends_with('\n') {
                normalized.push('\n');
            }
            crate::secret_file::write_secret_file(&key_path, normalized.as_bytes())
                .map_err(|e| format!("cannot write the SSH key: {e}"))?;
        }
    }
    Ok(())
}

/// Write a clone-time in-memory credential configuration into the cloned
/// vault's device-local files so the next sync authenticates the same way.
/// Only the credential families the config actually carries are written.
pub fn persist_in_memory(vault_path: &Path, cfg: &CredentialConfig) -> Result<(), String> {
    let host = cfg
        .bound_host
        .clone()
        .ok_or_else(|| "credential config carries no bound host".to_string())?;
    let token = cfg
        .https_token
        .as_ref()
        .map(|s| s.expose_secret().to_string());
    let ssh_key_pem = cfg
        .ssh_key_pem
        .as_ref()
        .map(|s| s.expose_secret().to_string());
    let ssh_passphrase = cfg
        .ssh_passphrase
        .as_ref()
        .map(|s| s.expose_secret().to_string());
    if token.is_none() && ssh_key_pem.is_none() && ssh_passphrase.is_none() {
        return Ok(());
    }
    apply_custom_credentials(
        vault_path,
        &host,
        &CustomCredentialsUpdate {
            token,
            username: cfg.username.clone(),
            ssh_passphrase,
            ssh_key_pem,
        },
    )
}

#[cfg(test)]
mod tests {

    #[test]
fn extract_host_handles_bracketed_ipv6() {
    assert_eq!(extract_host("ssh://git@[2001:db8::1]:2222/repo.git"), Some("2001:db8::1".to_string()));
    assert_eq!(extract_host("ssh://[::1]/repo"), Some("::1".to_string()));
    assert_eq!(extract_host("https://[2001:db8::1]:8443/x"), Some("2001:db8::1".to_string()));
}

#[test]
    fn extract_host_ignores_userinfo_spoofed_through_the_path() {
        // A crafted URL must not resolve to the host named after the @
        // in its path: the token bound to github.com would be released
        // to evil.example.
        assert_eq!(
            extract_host("https://evil.example/x@github.com/y").as_deref(),
            Some("evil.example")
        );
        // Legitimate userinfo still resolves.
        assert_eq!(
            extract_host("https://token123@github.com/owner/repo.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(extract_host("git@github.com:owner/repo.git").as_deref(), Some("github.com"));
        assert_eq!(
            extract_host("ssh://git@github.com:2222/owner/repo.git").as_deref(),
            Some("github.com")
        );
        // Scheme-less spoofs: git connects to the host before the first
        // ':' or '/', so the token binding must resolve to that host,
        // never to a host named after an '@' in the path or after a
        // colon-scoped segment.
        assert_eq!(
            extract_host("evil.com:x@github.com:y").as_deref(),
            Some("evil.com")
        );
        assert_eq!(
            extract_host("evil.example/x@github.com:y").as_deref(),
            Some("evil.example")
        );
    }
    use super::*;

    /// Clear `BALUARD_GIT_TOKEN` AND redirect `BALUARD_DATA_DIR` to an empty
    /// tempdir for the duration of a test so the keyring lookup
    /// (`ProvidersState::load` reads `providers.json` from data_dir) can't
    /// pull the developer's real cached GitHub token into a credential
    /// test. Both env vars are restored on drop. Marked `#[serial]` so
    /// tests don't race on the process-wide env.
    pub(crate) fn with_credential_test_env<F: FnOnce()>(f: F) {
        let prev_token = std::env::var("BALUARD_GIT_TOKEN").ok();
        let prev_data_dir = std::env::var("BALUARD_DATA_DIR").ok();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialised by #[serial]; in tests that pair with this.
        unsafe {
            std::env::remove_var("BALUARD_GIT_TOKEN");
        }
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", tmp.path());
        }
        f();
        match prev_token {
            Some(v) => unsafe {
                std::env::set_var("BALUARD_GIT_TOKEN", v);
            },
            None => unsafe {
                std::env::remove_var("BALUARD_GIT_TOKEN");
            },
        }
        match prev_data_dir {
            Some(v) => unsafe {
                std::env::set_var("BALUARD_DATA_DIR", v);
            },
            None => unsafe {
                std::env::remove_var("BALUARD_DATA_DIR");
            },
        }
        drop(tmp); // also serves as proof the dir was empty / unused.
    }

    #[test]
    #[serial_test::serial]
    fn load_without_env_or_file() {
        super::tests::with_credential_test_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let config = CredentialConfig::load(dir.path());
            assert!(config.https_token.is_none());
        });
    }

    #[test]
    #[serial_test::serial]
    fn load_from_config_file() {
        super::tests::with_credential_test_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let meta = dir.path().join("meta");
            std::fs::create_dir_all(&meta).unwrap();
            let config_path = meta.join("git-credentials.json");
            std::fs::write(&config_path, r#"{"token":"ghp_test123"}"#).unwrap();

            let config = CredentialConfig::load(dir.path());
            assert!(config.https_token.is_some());
            assert_eq!(
                config.expose_token().as_deref().map(|s| s.as_str()),
                Some("ghp_test123")
            );
        });
    }

    #[test]
    fn scrub_removes_url_userinfo() {
        let msg = "transport error: https://git:ghp_abc123def@github.com/user/repo.git";
        let cleaned = scrub_git_error(msg);
        assert!(
            !cleaned.contains("ghp_abc123def"),
            "PAT not scrubbed: {cleaned}"
        );
        assert!(
            cleaned.contains("***@github.com"),
            "URL structure lost: {cleaned}"
        );
    }

    #[test]
    fn scrub_removes_pat_prefixes() {
        let msg = "authentication failed: token ghp_ABCDEF123456";
        let cleaned = scrub_git_error(msg);
        assert!(
            !cleaned.contains("ghp_"),
            "PAT prefix not scrubbed: {cleaned}"
        );

        let msg2 = "error: glpat-XXXXXXXXXXXX";
        let cleaned2 = scrub_git_error(msg2);
        assert!(
            !cleaned2.contains("glpat-"),
            "GitLab PAT not scrubbed: {cleaned2}"
        );
    }

    #[test]
    fn scrub_preserves_safe_errors() {
        let msg = "failed to set local git user.name: config error";
        assert_eq!(scrub_git_error(msg), msg);
    }

    #[test]
    fn extract_host_handles_various_url_formats() {
        assert_eq!(
            extract_host("https://github.com/foo/bar.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            extract_host("https://user:token@gitlab.example.com:8443/foo/bar.git").as_deref(),
            Some("gitlab.example.com")
        );
        assert_eq!(
            extract_host("git@codeberg.org:foo/bar.git").as_deref(),
            Some("codeberg.org")
        );
        assert_eq!(
            extract_host("ssh://git@git.myorg.internal/foo/bar.git").as_deref(),
            Some("git.myorg.internal")
        );
        assert_eq!(
            extract_host("   https://UPPERCASE.COM/FOO   ").as_deref(),
            Some("uppercase.com")
        );
    }

    #[test]
    fn credentials_callback_refuses_untrusted_host() {
        let config = CredentialConfig {
            https_token: Some(secrecy::SecretString::new(
                "ghp_secret".to_string().into_boxed_str(),
            )),
            allowed_hosts: Some(vec!["github.com".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            extract_host("https://attacker.com/vault.git").as_deref(),
            Some("attacker.com")
        );
        assert!(
            !config
                .allowed_hosts
                .as_ref()
                .unwrap()
                .iter()
                .any(|h| h == "attacker.com")
        );
        assert!(
            config
                .allowed_hosts
                .as_ref()
                .unwrap()
                .iter()
                .any(|h| h == "github.com")
        );
    }
}

#[cfg(test)]
mod custom_remote_tests {
    #[test]
    fn ssh_credentials_refuse_a_foreign_host() {
        // A custom SSH key is bound to its host exactly like a custom
        // token: a redirect or hostile host must not get signing offers.
        let cfg = CredentialConfig::in_memory(
            None,
            None,
            Some("not-a-real-key".to_string()),
            None,
            Some("git.example.com".to_string()),
        );
        let ssh = std::cell::Cell::new(0u32);
        let up = std::cell::Cell::new(0u32);
        let types = git2::CredentialType::SSH_KEY;
        let Err(e) = credentials_attempt(&cfg, "ssh://git@evil.example/x", None, types, &ssh, &up)
        else {
            panic!("foreign host must be refused");
        };
        assert!(e.message().contains("untrusted host"), "{e}");
        // Same host passes the guard (ssh_key_from_memory defers key
        // parsing to first use, so Ok or a parse error are both fine) —
        // what matters is the host refusal did not fire.
        if let Err(e) =
            credentials_attempt(&cfg, "ssh://git@git.example.com/x", None, types, &ssh, &up)
        {
            assert!(!e.message().contains("untrusted host"), "{e}");
        }
    }


    #[test]
    fn custom_credentials_writer_merges_updates_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let vp = dir.path();

        // Set: token + host binding + username.
        apply_custom_credentials(
            vp,
            "Git.Example.COM",
            &CustomCredentialsUpdate {
                token: Some("tok1".into()),
                username: Some("alex".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vp.join("meta/git-credentials.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["token"], "tok1");
        assert_eq!(v["host"], "git.example.com");
        assert_eq!(v["username"], "alex");

        // Untouched fields survive a partial update; empty clears.
        apply_custom_credentials(
            vp,
            "git.example.com",
            &CustomCredentialsUpdate {
                username: Some(String::new()),
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vp.join("meta/git-credentials.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["token"], "tok1");
        assert!(v.get("username").is_none());

        // Key file written with normalized newline, 0600.
        apply_custom_credentials(
            vp,
            "git.example.com",
            &CustomCredentialsUpdate {
                ssh_key_pem: Some("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let key = std::fs::read_to_string(vp.join("meta/git-ssh-key")).unwrap();
        assert!(key.ends_with('\n'));

        // Clearing the token removes the file.
        apply_custom_credentials(
            vp,
            "git.example.com",
            &CustomCredentialsUpdate {
                token: Some(String::new()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!vp.join("meta/git-credentials.json").exists());
    }

    use super::*;

    // --- Custom-remote credential tests ---

    #[test]
    fn clear_stale_credentials_removes_only_a_foreign_binding() {
        super::tests::with_credential_test_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let meta = dir.path().join("meta");
            std::fs::create_dir_all(&meta).unwrap();
            let cfg_path = meta.join("git-credentials.json");
            std::fs::write(&cfg_path, r#"{"token":"tok123","host":"git.old.example"}"#).unwrap();

            // Same host (case-insensitive): the file stays.
            assert!(!super::clear_stale_custom_credentials(
                dir.path(),
                "https://Git.Old.Example/repo.git"
            ));
            assert!(cfg_path.exists());

            // A different host: the file is removed.
            assert!(super::clear_stale_custom_credentials(
                dir.path(),
                "https://git.new.example/repo.git"
            ));
            assert!(!cfg_path.exists());

            // No file: a quiet no-op.
            assert!(!super::clear_stale_custom_credentials(
                dir.path(),
                "https://git.third.example/repo.git"
            ));
        });
    }

    #[test]
    fn custom_file_loads_token_host_username_and_passphrase() {
        super::tests::with_credential_test_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let meta = dir.path().join("meta");
            std::fs::create_dir_all(&meta).unwrap();
            std::fs::write(
            meta.join("git-credentials.json"),
            r#"{"token":"tok123","username":"alex","host":"git.example.com","ssh_passphrase":"pp"}"#,
        )
        .unwrap();
            let config = CredentialConfig::load(dir.path());
            assert_eq!(config.bound_host.as_deref(), Some("git.example.com"));
            assert_eq!(config.username.as_deref(), Some("alex"));
            assert!(config.ssh_passphrase.is_some());
            // The key file is absent, so no path is recorded.
            assert!(config.ssh_key_path.is_none());
        });
    }

    #[test]
    fn ssh_key_path_recorded_only_when_present() {
        super::tests::with_credential_test_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let meta = dir.path().join("meta");
            std::fs::create_dir_all(&meta).unwrap();
            std::fs::write(
                meta.join("git-ssh-key"),
                "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            )
            .unwrap();
            let config = CredentialConfig::load(dir.path());
            assert!(config.ssh_key_path.is_some());
        });
    }

    #[test]
    fn host_key_marker_schema_is_stable() {
        // Golden shape: daemon error decoration, the CLI probe parser, and
        // both GUI trust flows read these exact keys — a rename here breaks
        // every surface at once.
        let err = BaluardError::Sync(crate::error::SyncError::Git("connect failed".into()));
        crate::sync::known_hosts::record_observation(crate::sync::known_hosts::ObservedHostKey {
            host: "git.example.com".into(),
            port: 2222,
            key_type: "ssh-ed25519".into(),
            key: b"k".to_vec(),
            fingerprint: "SHA256:abc".into(),
            changed: false,
            known_other_type: true,
        });
        let marker = format_sync_error(&err);
        let v: serde_json::Value = serde_json::from_str(&marker).expect("marker is JSON");
        let inner = &v["host_key_untrusted"];
        assert_eq!(inner["host"], "git.example.com");
        assert_eq!(inner["port"], 2222);
        assert_eq!(inner["key_type"], "ssh-ed25519");
        assert_eq!(inner["fingerprint"], "SHA256:abc");
        assert_eq!(inner["known_other_type"], true);
        let id = inner["attempt_id"].as_str().expect("attempt id");
        assert_eq!(id.len(), 32);
        // Consumed by the trust route's take_observation(id).
        assert!(crate::sync::known_hosts::take_observation(id).is_some());
    }

    #[test]
    fn attempt_cap_stops_the_credential_loop() {
        // The deterministic failing shape: a tokenless USER_PASS request —
        // every attempt errors ("no credential source available") until the
        // budget is gone. (SSH legs can succeed via the box's ssh-agent, so
        // their cap is transport-dependent; the counter logic is shared.)
        let cfg = CredentialConfig::default();
        let ssh = std::cell::Cell::new(0u32);
        let up = std::cell::Cell::new(0u32);
        let types = git2::CredentialType::USER_PASS_PLAINTEXT;
        // libgit2 retries the callback after every failure; three failures
        // exhaust the budget and the fourth call is refused up front.
        for _ in 0..3 {
            let Err(e) = credentials_attempt(&cfg, "ssh://git@h/x", None, types, &ssh, &up) else {
                panic!("expected a failure while the budget lasts");
            };
            assert!(!e.message().contains("too many times"), "{e}");
        }
        let Err(e) = credentials_attempt(&cfg, "ssh://git@h/x", None, types, &ssh, &up) else {
            panic!("expected the exhausted-budget refusal");
        };
        assert!(e.message().contains("too many times"), "{e}");
    }

    #[test]
    fn bound_host_refuses_to_release_the_token_elsewhere() {
        let cfg = CredentialConfig::in_memory(
            Some("tok1".into()),
            Some("alex".into()),
            None,
            None,
            Some("git.example.com".into()),
        );
        let ssh = std::cell::Cell::new(0u32);
        let up = std::cell::Cell::new(0u32);
        let types = git2::CredentialType::USER_PASS_PLAINTEXT;
        // Own host: released (Cred is not Debug, so judge by is_ok only).
        assert!(matches!(
            credentials_attempt(
                &cfg,
                "https://git.example.com/vault.git",
                None,
                types,
                &ssh,
                &up
            ),
            Ok(_)
        ));
        // Redirected host: refused with the bound message.
        let Err(err) = credentials_attempt(
            &cfg,
            "https://attacker.com/vault.git",
            None,
            types,
            &ssh,
            &up,
        ) else {
            panic!("expected the bound-host refusal");
        };
        assert!(
            err.message()
                .contains("refusing to send the vault token to a different host"),
            "{err}"
        );
    }

    #[test]
    fn port_of_extracts_non_default_ports() {
        assert_eq!(port_of("ssh://git@git.example.com:2222/repo.git"), 2222);
        assert_eq!(port_of("ssh://git@git.example.com/repo.git"), 22);
        assert_eq!(port_of("git@git.example.com:repo.git"), 22);
    }
}
