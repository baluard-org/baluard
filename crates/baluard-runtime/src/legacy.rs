//! Owner-side Legacy Contact operations, bridging the daemon surface to
//! the core protocol. The remote identity and provider token come from
//! the vault's announced sync remote and the device's connected provider
//! accounts; nothing is taken from the request beyond the owner's own
//! choices (window, passphrase, letter).

use baluard_core::legacy as core_legacy;
use baluard_core::providers::token::ProvidersState;
use baluard_core::providers::types::{Provider, ProviderConfig, ProviderToken};
use baluard_core::sync::engine::read_remote_announcement;
use baluard_core::vault::handle::VaultHandle;
use baluard_core::error::VaultError;
use baluard_core::BaluardError;

use crate::providers::ensure_valid_token;

/// The resolved sync target: which connected forge this vault lives on,
/// parsed from the announced remote URL.
struct ResolvedRemote {
    identity: core_legacy::RemoteIdentity,
    provider: Provider,
    config: ProviderConfig,
    token: ProviderToken,
}

fn default_host(provider: Provider) -> &'static str {
    match provider {
        Provider::GitHub => "github.com",
        Provider::GitLab => "gitlab.com",
        Provider::Codeberg => "codeberg.org",
    }
}

/// Split a git URL into (host, owner, repo). Accepts the HTTPS and the
/// scp-like SSH forms; the URL was already shape-validated by
/// `read_remote_announcement`.
fn split_git_url(url: &str) -> Option<(String, String, String)> {
    let (host, rest) = if let Some(after) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ssh://"))
    {
        let (h, r) = after.split_once('/')?;
        // Strip userinfo if someone pasted it into the URL.
        let h = h.rsplit('@').next().unwrap_or(h);
        (h.to_string(), r.to_string())
    } else {
        // scp-like: git@host:owner/repo(.git)
        let at = url.rfind('@')?;
        let colon = url[at..].find(':')? + at;
        (url[at + 1..colon].to_string(), url[colon + 1..].to_string())
    };
    let mut segs = rest.split('/');
    let owner = segs.next()?.trim_end_matches(".git").to_string();
    let repo = segs.next()?.trim_end_matches(".git").to_string();
    if owner.is_empty() || repo.is_empty() || segs.next().is_some() {
        return None;
    }
    Some((host.to_ascii_lowercase(), owner, repo))
}

async fn resolve_remote(vault_path: &std::path::Path) -> Result<ResolvedRemote, BaluardError> {
    let origin = read_remote_announcement(vault_path).ok_or_else(|| {
        BaluardError::from(VaultError::NotFound(
            "this vault has no sync remote. Legacy Contact guards the online \
             copy of your vault, so a vault must be syncing first."
                .into(),
        ))
    })?;
    let (host, owner, repo) = split_git_url(&origin).ok_or_else(|| {
        BaluardError::from(VaultError::NotFound(format!(
            "cannot read the sync remote as an owner/repository URL: {origin}"
        )))
    })?;

    // The provider must be one this device is connected to, and the
    // remote host must be that provider's (possibly self-hosted) home.
    let state = ProvidersState::load()
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("reading provider state: {e}"))))?;
    for provider in [Provider::GitHub, Provider::GitLab, Provider::Codeberg] {
        let Some(info) = state.get(provider) else {
            continue;
        };
        let config = info.config();
        let base = config.effective_instance_url(provider);
        let base_host = split_git_url(&base)
            .map(|(h, _, _)| h)
            .unwrap_or_default();
        if host == base_host || (info.instance_url.is_none() && host == default_host(provider)) {
            let (info, token) = ensure_valid_token(provider).await?;
            let ssh_url = format!("git@{host}:{owner}/{repo}.git");
            return Ok(ResolvedRemote {
                identity: core_legacy::RemoteIdentity {
                    provider,
                    owner,
                    repo,
                    origin_url: origin,
                    ssh_url,
                },
                provider,
                config: info.config(),
                token,
            });
        }
    }
    Err(BaluardError::from(VaultError::NotFound(
        "no connected Git provider account matches this vault's remote. \
         Connect the vault's sync account first."
            .into(),
    )))
}

fn require_unlocked(handle: &VaultHandle) -> Result<(), String> {
    if !handle.is_unlocked() {
        return Err("Vault is locked. Unlock first.".into());
    }
    Ok(())
}

/// legacy.status: the owner-side poll (banner + settings screen).
pub fn status_json(
    vault_path: &std::path::Path,
    handle: &VaultHandle,
) -> Result<String, String> {
    require_unlocked(handle)?;
    let st = core_legacy::status(vault_path, handle).map_err(|e| e.to_string())?;
    serde_json::to_string(&st).map_err(|e| e.to_string())
}

/// legacy.arm: mint the kit, seal the layer, push the deploy key.
pub async fn arm_json(
    vault_path: &std::path::Path,
    handle: &VaultHandle,
    payload: &str,
) -> Result<String, String> {
    require_unlocked(handle)?;
    let p: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let window_days = p["window_days"].as_u64().unwrap_or(30).min(365);
    let passphrase = p["passphrase"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("missing passphrase")?;
    let letter = p["letter"].as_str().unwrap_or("");
    let contact_name = p["contact_name"].as_str().unwrap_or("your contact");
    let remote = resolve_remote(vault_path).await.map_err(|e| e.to_string())?;
    let forge = baluard_core::providers::provider_for(remote.provider, remote.config)
        .map_err(|e| e.to_string())?;
    let outcome = core_legacy::arm(
        vault_path,
        handle,
        &remote.identity,
        forge.as_ref(),
        &remote.token,
        window_days,
        passphrase,
        letter,
        contact_name,
    )
    .await
    .map_err(|e| e.to_string())?;
    serde_json::to_string(&outcome).map_err(|e| e.to_string())
}

/// legacy.close: deny / replace rotate the Root Key, disarm does not.
pub async fn close_json(
    vault_path: &std::path::Path,
    handle: &mut VaultHandle,
    payload: &str,
) -> Result<String, String> {
    require_unlocked(handle)?;
    let p: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let reason = match p["reason"].as_str().unwrap_or("") {
        "denied" => core_legacy::CloseReason::Denied,
        "replaced" => core_legacy::CloseReason::Replaced,
        "disarmed" => core_legacy::CloseReason::Disarmed,
        other => return Err(format!("unknown close reason: {other}")),
    };
    let remote = resolve_remote(vault_path).await.map_err(|e| e.to_string())?;
    let forge = baluard_core::providers::provider_for(remote.provider, remote.config)
        .map_err(|e| e.to_string())?;
    core_legacy::close(vault_path, handle, forge.as_ref(), &remote.token, reason)
        .await
        .map_err(|e| e.to_string())?;
    Ok(r#"{"closed": true}"#.into())
}

/// legacy.resend: byte-identical re-export of the stored kit.
pub fn resend_json(
    vault_path: &std::path::Path,
    handle: &VaultHandle,
) -> Result<String, String> {
    require_unlocked(handle)?;
    let (kit_id, armor) = core_legacy::resend(vault_path, handle).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "kit_id": kit_id, "kit_armor": armor }).to_string())
}

#[cfg(test)]
mod tests {
    use super::split_git_url;

    #[test]
    fn splits_https_scp_and_ssh_forms() {
        assert_eq!(
            split_git_url("https://github.com/owner/repo.git"),
            Some(("github.com".into(), "owner".into(), "repo".into()))
        );
        assert_eq!(
            split_git_url("git@github.com:owner/repo.git"),
            Some(("github.com".into(), "owner".into(), "repo".into()))
        );
        assert_eq!(
            split_git_url("ssh://git@gitlab.com/owner/repo"),
            Some(("gitlab.com".into(), "owner".into(), "repo".into()))
        );
        // Userinfo in an HTTPS URL must not become the owner.
        assert_eq!(
            split_git_url("https://user@github.com/owner/repo.git"),
            Some(("github.com".into(), "owner".into(), "repo".into()))
        );
        // Deep paths and bare hosts are not owner/repo URLs.
        assert_eq!(split_git_url("https://github.com/owner/repo/extra"), None);
        assert_eq!(split_git_url("https://github.com"), None);
    }
}
