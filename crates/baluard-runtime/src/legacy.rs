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
    handle: &mut VaultHandle,
    payload: &str,
) -> Result<String, String> {
    require_unlocked(handle)?;
    // Replace semantics: arming over a live kit retires it first. The
    // old deploy key is removed and the Root Key rotates, so a kit
    // already in the wild stops working even if the new arm fails.
    if let Ok(Some(st)) = core_legacy::status(vault_path, handle) {
        if matches!(
            st.phase,
            core_legacy::LegacyPhase::Quiet | core_legacy::LegacyPhase::Open
        ) {
            let remote = resolve_remote(vault_path).await.map_err(|e| e.to_string())?;
            let forge = baluard_core::providers::provider_for(remote.provider, remote.config)
                .map_err(|e| e.to_string())?;
            core_legacy::close(
                vault_path,
                handle,
                forge.as_ref(),
                &remote.token,
                core_legacy::CloseReason::Replaced,
            )
            .await
            .map_err(|e| e.to_string())?;
        }
    }
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

/// The opened contact view: an unlocked, disposable clone of the
/// owner's vault plus the silence-window facts the UI shows first.
pub struct ContactViewOpened {
    pub handle: baluard_core::vault::handle::VaultHandle,
    pub kit_id: String,
    pub owner_note: String,
    pub silence_days: u64,
    pub window_days: u64,
    pub vault_name: String,
}

/// legacy.contact_view: open the kit, clone the vault copy with the
/// kit's deploy key, verify the owner-signed record chain and the
/// silence window, unwrap the layer, and return an unlocked session.
/// Everything secret stays in this function's scope; the caller gets
/// the opened handle and the display facts only.
pub async fn open_contact_view(
    letter: &str,
    passphrase: &str,
) -> Result<ContactViewOpened, BaluardError> {
    let letter = letter.to_string();
    let passphrase = passphrase.to_string();
    tokio::task::spawn_blocking(move || {
        let body = core_legacy::open_kit(&letter, &passphrase)?;
        let ek: [u8; 32] = hex::decode(&body.ek)
            .map_err(|_| VaultError::Corrupt("kit escrow key is not valid hex".into()))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("kit escrow key is not 32 bytes".into()))?;

        // Fresh disposable clone each open: the view holds no local
        // writes by design, so re-downloading is both simplest and the
        // only way the contact ever sees current data.
        let view_root = baluard_core::paths::data_dir().join("legacy-view");
        std::fs::create_dir_all(&view_root)
            .map_err(|e| VaultError::Metadata(format!("creating view dir: {e}")))?;
        let target = view_root.join(&body.kit_id);
        if target.join("meta/kdf-params.json").exists() {
            std::fs::remove_dir_all(&target)
                .map_err(|e| VaultError::Metadata(format!("clearing old view: {e}")))?;
        }
        let host = baluard_core::sync::credentials::extract_host(&body.repo_ssh_url)
            .filter(|h| !h.is_empty())
            .ok_or_else(|| {
                VaultError::InvalidOperation(format!(
                    "cannot read the host out of the kit's vault address: {}",
                    body.repo_ssh_url
                ))
            })?;
        let mut creds = baluard_core::sync::credentials::CredentialConfig::in_memory(
            None,
            Some("git".into()),
            Some(body.deploy_private_key.clone()),
            None,
            Some(host),
        )
        .with_url_hint(&body.repo_ssh_url);
        creds.port_hint = baluard_core::sync::credentials::port_of(&body.repo_ssh_url).into();
        let progress = std::sync::Arc::new(std::sync::Mutex::new(
            baluard_core::sync::engine::CloneProgress::default(),
        ));
        baluard_core::sync::engine::SyncEngine::clone_remote_cancelable(
            &body.repo_ssh_url,
            &target,
            None,
            progress,
            None,
            Some(creds),
        )?;

        // The record chain must say Armed; a closed kit fails with the
        // owner's actual decision.
        let record = core_legacy::load_record(&target, &body.kit_id)?.ok_or_else(|| {
            VaultError::NotFound("the vault copy has no record for this kit".to_string())
        })?;
        match record.state {
            core_legacy::LegacyState::Armed => {}
            core_legacy::LegacyState::Closed => {
                let why = match record.reason {
                    Some(core_legacy::CloseReason::Denied) => {
                        "the owner refused this request"
                    }
                    Some(core_legacy::CloseReason::Replaced) => {
                        "the owner handed the kit to someone else"
                    }
                    _ => "the owner turned this kit off",
                };
                return Err(VaultError::InvalidOperation(format!(
                    "This kit no longer works: {why}."
                ))
                .into());
            }
        }

        // Silence window: the contact's own clock reads the owner's
        // signed days. Honest-scope per the plan: a modified client can
        // rewind this; the wait guards mistakes, not determination.
        let today = core_legacy::today_day();
        let phase = core_legacy::derive_phase(&record, record_last_alive_day(&target, &body.kit_id), today);
        if phase != core_legacy::LegacyPhase::Open {
            let silence = today.saturating_sub(record.created_day);
            let wait = record.window_days.saturating_sub(silence);
            return Err(VaultError::InvalidOperation(format!(
                "The waiting period is not over yet. About {wait} more day(s)."
            ))
            .into());
        }
        let silence_days = today.saturating_sub(record.created_day);

        // The kit's escrow key must match the record's fingerprint, then
        // the layer opens to the vault's Root Key.
        let check = core_legacy::ek_check(&ek, &body.kit_id)?;
        if check != record.ek_check {
            return Err(VaultError::Corrupt("this kit does not match the vault copy".into()).into());
        }
        let layer = core_legacy::load_layer(&target, &body.kit_id)?.ok_or_else(|| {
            VaultError::NotFound("the vault copy is missing its layer blob".to_string())
        })?;
        let root =
            core_legacy::open_layer(&ek, &layer, &body.vault_id, &body.kit_id, record.epoch)?;

        // Cross-vault replay guard: the clone must be the kit's vault.
        let cloned_vault_id = baluard_core::vault::handle::VaultHandle::vault_id_for_path(&target)?;
        if cloned_vault_id.to_string() != body.vault_id {
            return Err(VaultError::Corrupt("this kit belongs to a different vault".into()).into());
        }

                let root_key = baluard_core::keys::hierarchy::RootKey::from_bytes(*root);
        let handle = baluard_core::vault::handle::VaultHandle::open_with_root_key(&target, &root_key)?;
        let vault_name = handle
            .get_settings()
            .ok()
            .and_then(|s| s.display_name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "the vault".into());

        Ok(ContactViewOpened {
            handle,
            kit_id: body.kit_id,
            owner_note: letter_text(letter),
            silence_days,
            window_days: record.window_days,
            vault_name,
        })
    })
    .await
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("view task: {e}"))))?
}

/// The plaintext note above the armor's BEGIN marker.
fn letter_text(letter: String) -> String {
    match letter.find(core_legacy::ARMOR_BEGIN) {
        Some(idx) => letter[..idx].trim_end().to_string(),
        None => String::new(),
    }
}

/// The stored heartbeat's day, read best-effort from the fresh clone.
fn record_last_alive_day(target: &std::path::Path, kit_id: &str) -> Option<u64> {
    core_legacy::load_alive(target, kit_id)
        .ok()
        .flatten()
        .map(|a| a.day)
}
