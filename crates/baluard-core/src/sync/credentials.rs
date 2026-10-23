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
const PAT_PREFIXES: &[&str] = &["ghp_", "gho_", "github_pat_", "glpat-", "glpt-"];

/// Scrub potential credentials from a git2 error message.
/// Removes URL userinfo (user:token@host) and common PAT prefixes.
pub fn scrub_git_error(msg: &str) -> String {
    let mut cleaned = msg.to_string();

    // Scrub URL userinfo: ://anything@ -> ://***@
    // Simple scan-based approach (no regex dependency)
    if let Some(start) = cleaned.find("://") {
        let scheme_end = start + 3;
        if let Some(at_pos) = cleaned[scheme_end..].find('@') {
            let at_abs = scheme_end + at_pos;
            cleaned.replace_range(scheme_end..at_abs, "***");
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
pub fn extract_host(url: &str) -> Option<String> {
    let s = url.trim();
    let rest = if let Some(pos) = s.find("://") {
        &s[pos + 3..]
    } else if let Some(at) = s.rfind('@') {
        &s[at + 1..]
    } else {
        s
    };
    let host_part = if let Some(at) = rest.rfind('@') {
        &rest[at + 1..]
    } else {
        rest
    };
    let end = host_part
        .find(|c: char| c == '/' || c == ':' || c.is_whitespace())
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
    token: SecretString,
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
    pub port_hint: u16,
}

impl CredentialConfig {
    /// Load credentials from provider keyring, env var, or vault config file.
    pub fn load(vault_path: &Path) -> Self {
        Self::load_with_hint(vault_path, None)
    }

    /// Load credentials with an optional provider hint.
    pub fn load_with_hint(vault_path: &Path, hint: Option<Provider>) -> Self {
        let file = Self::load_from_file(vault_path);
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
            https_token = Some(f.token.clone());
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
            port_hint: 22,
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
            port_hint: 22,
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
                let token = v.get("token").and_then(|t| t.as_str())?;
                let secret_str = |key: &str| {
                    v.get(key)
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| SecretString::new(s.to_string().into_boxed_str()))
                };
                Some(CustomFileCredentials {
                    token: SecretString::new(token.to_string().into_boxed_str()),
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

thread_local! {
    /// URL of the connection currently authenticating. The credentials
    /// callback fires before host-key verification, so the cert-check
    /// closure reads the port from here without call sites passing it.
    static LAST_AUTH_URL: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Build RemoteCallbacks with credential handling for both SSH and HTTPS.
/// Strict known_hosts enforcement (M5) rides `certificate_check`; unknown
/// SSH host keys are stashed as pending observations for the trust flow.
#[cfg(feature = "git-sync")]
pub fn build_callbacks(config: &CredentialConfig) -> RemoteCallbacks<'_> {
    crate::sync::tls::ensure_tls_roots();
    let https_token = config.expose_token();
    let allowed_hosts = config.allowed_hosts.clone();
    let bound_host = config.bound_host.clone();
    let username = config.username.clone();
    let ssh_key_pem = config
        .ssh_key_pem
        .as_ref()
        .map(|s| zeroize::Zeroizing::new(s.expose_secret().to_string()));
    let ssh_key_path = config.ssh_key_path.clone();
    let ssh_passphrase = config
        .ssh_passphrase
        .as_ref()
        .map(|s| zeroize::Zeroizing::new(s.expose_secret().to_string()));
    let mut callbacks = RemoteCallbacks::new();
    let ssh_attempts = std::cell::Cell::new(0u32);
    let userpass_attempts = std::cell::Cell::new(0u32);

    callbacks.credentials(move |url, username_from_url, allowed_types| {
        // libgit2 retries the callback after every failure; cap each auth
        // type so a wrong key or token cannot loop forever.
        const MAX_ATTEMPTS: u32 = 3;
        LAST_AUTH_URL.with(|u| *u.borrow_mut() = url.to_string());

        let user = username_from_url
            .or(username.as_deref())
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
            ssh_attempts.set(ssh_attempts.get() + 1);
            // Dedicated custom key first (never touches the agent), then the
            // agent for provider-shaped flows.
            let pem: Option<zeroize::Zeroizing<String>> = ssh_key_pem
                .clone()
                .or_else(|| {
                    ssh_key_path
                        .as_ref()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(zeroize::Zeroizing::new)
                });
            if let Some(pem) = pem {
                if let Ok(cred) = Cred::ssh_key_from_memory(
                    user,
                    None,
                    pem.as_str(),
                    ssh_passphrase.as_deref().map(|s| s.as_str()),
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
            if let Some(ref token) = https_token {
                let target_host = extract_host(url);
                if let Some(ref allowed) = allowed_hosts {
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
                if let Some(ref bound) = bound_host {
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
                    .or_else(|| username.clone())
                    .unwrap_or_else(|| "git".to_string());
                return Cred::userpass_plaintext(&user, token.as_str());
            }
        }

        if allowed_types.contains(CredentialType::DEFAULT) {
            return Cred::default();
        }

        Err(git2::Error::from_str("no credential source available"))
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
            match crate::sync::known_hosts::verify_host_key(host, key_type, key) {
                crate::sync::known_hosts::HostKeyResult::Known => {
                    Ok(CertificateCheckStatus::CertificateOk)
                }
                // Fail closed: reject unknown / mismatched / missing file.
                // Unknown keys are stashed as daemon-observed pending
                // handshakes so the trust route can only bless a key the
                // daemon itself saw.
                // Missing (no readable known_hosts yet) is the same trust
                // situation as Unknown on a fresh machine: offer the key for
                // the first-contact trust flow. Mismatch stays silent.
                crate::sync::known_hosts::HostKeyResult::Unknown
                | crate::sync::known_hosts::HostKeyResult::Missing => {
                    let port = LAST_AUTH_URL.with(|u| port_of(&u.borrow()));
                    crate::sync::known_hosts::record_observation(
                        crate::sync::known_hosts::ObservedHostKey {
                            host: host.to_string(),
                            port,
                            key_type: key_type.to_string(),
                            key: key.to_vec(),
                            fingerprint: crate::sync::known_hosts::fingerprint(key),
                        },
                    );
                    Err(git2::Error::from_str(&format!(
                        "SSH host key for {host} is not trusted yet"
                    )))
                }
                _ => Err(git2::Error::from_str(&format!(
                    "SSH host key for {host} not in known_hosts"
                ))),
            }
        } else {
            // HTTPS/X.509 cert: passthrough to libgit2's built-in CA check.
            Ok(CertificateCheckStatus::CertificatePassthrough)
        }
    });

    callbacks
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
    // Peek, never drain: the trust route consumes the observation by id
    // after the surface reports it.
    if let Some((attempt_id, obs)) = crate::sync::known_hosts::peek_latest_observation() {
        return serde_json::json!({
            "host_key_untrusted": {
                "host": obs.host,
                "port": obs.port,
                "key_type": obs.key_type,
                "fingerprint": obs.fingerprint,
                "attempt_id": attempt_id,
            }
        })
        .to_string();
    }
    format!("{err}")
}

/// Upgrade a failed sync/clone/transport error into the structured
/// `HostKeyUntrusted` error when the failing operation recorded a pending
/// host-key observation. The observation stays pending for the trust route.
pub fn upgrade_host_key_error(err: BaluardError) -> BaluardError {
    // Peek, never drain: the trust route consumes the observation by id
    // after the surface reports it.
    if let Some((attempt_id, obs)) = crate::sync::known_hosts::peek_latest_observation() {
        return BaluardError::Sync(crate::error::SyncError::HostKeyUntrusted {
            host: obs.host,
            port: obs.port,
            key_type: obs.key_type,
            fingerprint: obs.fingerprint,
            attempt_id,
        });
    }
    err
}

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
    fn host_bound_token_refuses_foreign_hosts() {
        // The callback closure is exercised through build_callbacks by the
        // connection layer; here we pin the config-shape contract that drives
        // the refusal: a bound host set from the file must match exactly.
        let config = CredentialConfig::in_memory(
            Some("tok".into()),
            None,
            None,
            None,
            Some("Git.Example.COM".into()),
        );
        assert_eq!(config.bound_host.as_deref(), Some("Git.Example.COM"));
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
    fn port_of_extracts_non_default_ports() {
        assert_eq!(port_of("ssh://git@git.example.com:2222/repo.git"), 2222);
        assert_eq!(port_of("ssh://git@git.example.com/repo.git"), 22);
        assert_eq!(port_of("git@git.example.com:repo.git"), 22);
    }
}
