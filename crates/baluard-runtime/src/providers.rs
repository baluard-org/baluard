//! Provider and device orchestration runtime layer.
//!
//! Provides process-global token refresh serialization, device flow polling,
//! PAT connection, repo discovery, cancelable clone with `.baluard` marker check,
//! and pre-unlock device enrollment for mobile and daemon hosts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Mutex as AsyncMutex;

use baluard_core::device_manager::{DeviceManager, EnrollmentPayload};
use baluard_core::error::{BaluardError, VaultError};
use baluard_core::providers::types::{CollaboratorPermission, CollaboratorStatus, VaultRepo};
use baluard_core::providers::{
    DeviceFlowSession, Provider, ProviderConfig, ProviderInfo, ProviderToken, provider_for,
    revoke_and_disconnect, token,
};
use baluard_core::sync::engine::{CloneProgress, SyncEngine};
use baluard_core::vault::handle::VaultHandle;
use zeroize::Zeroize;

/// Process-global lock map for per-provider token refresh.
pub struct ProviderManager {
    locks: Mutex<HashMap<Provider, Arc<AsyncMutex<()>>>>,
}

static PROVIDER_MANAGER: OnceLock<ProviderManager> = OnceLock::new();

pub fn global_provider_manager() -> &'static ProviderManager {
    PROVIDER_MANAGER.get_or_init(|| ProviderManager {
        locks: Mutex::new(HashMap::new()),
    })
}

impl ProviderManager {
    pub fn lock_for(&self, provider: Provider) -> Arc<AsyncMutex<()>> {
        let mut map = self.locks.lock().unwrap();
        map.entry(provider)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}

/// Sweep orphan `*.partial` clone directories in the parent directory of `target_path`.
pub fn sweep_partial_clones(target_path: &Path) {
    if let Some(parent) = target_path.parent() {
        if parent.exists() {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.ends_with(".partial") {
                                let _ = std::fs::remove_dir_all(&path);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Start an OAuth RFC8628 device flow session.
pub async fn connect_device_flow(
    provider: Provider,
    config: ProviderConfig,
) -> Result<DeviceFlowSession, BaluardError> {
    let p = provider_for(provider, config)
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
    p.device_flow_start()
        .await
        .map_err(|e| VaultError::Metadata(format!("device flow start: {e}")).into())
}

/// Authenticate using a Personal Access Token (PAT).
pub async fn connect_pat(
    provider: Provider,
    token_str: &str,
    config: ProviderConfig,
) -> Result<ProviderInfo, BaluardError> {
    let p = provider_for(provider, config)
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
    let (pat_token, info) = p
        .authenticate_pat(token_str)
        .await
        .map_err(|e| VaultError::Metadata(format!("PAT auth failed: {e}")))?;

    // Store token in keyring and update providers state
    token::store_token(provider, &info.username, &pat_token)
        .map_err(|e| VaultError::Metadata(format!("storing token: {e}")))?;

    let mut state = token::ProvidersState::load()
        .map_err(|e| VaultError::Metadata(format!("loading state: {e}")))?;
    state.set(info.clone());
    state
        .save()
        .map_err(|e| VaultError::Metadata(format!("saving state: {e}")))?;

    Ok(info)
}

/// Ensure a valid token exists for the given provider, performing refresh under a per-provider lock if needed.
pub async fn ensure_valid_token(
    provider: Provider,
) -> Result<(ProviderInfo, ProviderToken), BaluardError> {
    let lock = global_provider_manager().lock_for(provider);
    let _guard = lock.lock().await;

    let state = token::ProvidersState::load()
        .map_err(|e| VaultError::Metadata(format!("loading providers state: {e}")))?;
    let info = state.get(provider).cloned().ok_or_else(|| {
        BaluardError::from(VaultError::NotFound(format!(
            "provider {provider:?} not connected"
        )))
    })?;

    let tok = token::load_token(provider, &info.username)
        .map_err(|e| VaultError::Metadata(format!("loading token: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check if token is expired or within 60s buffer
    if let Some(exp) = tok.expires_at {
        if now + 60 >= exp {
            let p = provider_for(provider, info.config())
                .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
            let refreshed_opt = p
                .refresh_token(&tok)
                .await
                .map_err(|e| VaultError::Metadata(format!("token refresh failed: {e}")))?;

            if let Some(refreshed) = refreshed_opt {
                token::store_token(provider, &info.username, &refreshed)
                    .map_err(|e| VaultError::Metadata(format!("saving refreshed token: {e}")))?;

                return Ok((info, refreshed));
            } else {
                return Err(VaultError::Metadata(format!(
                    "provider {provider:?} token refresh returned no token"
                ))
                .into());
            }
        }
    }

    Ok((info, tok))
}

/// Detect vault repositories owned or accessible by the connected account.
pub async fn detect_vault_repos(provider: Provider) -> Result<Vec<VaultRepo>, BaluardError> {
    let (info, tok) = ensure_valid_token(provider).await?;
    let p = provider_for(provider, info.config())
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;

    p.detect_vault_repos(&tok)
        .await
        .map_err(|e| VaultError::Metadata(format!("detect repos: {e}")).into())
}

/// Where a member stands in the P8c transport-staging lifecycle.
/// The mapping is the least-privilege rule: nobody gets push until the
/// vault-side approval grants an editor-or-above role.
pub enum SeatStage {
    /// Invited but not yet approved: read-only seat (must clone to introduce).
    Pending,
    /// Approved as a viewer: read-only seat.
    Viewer,
    /// Approved at editor or above: write seat.
    Editor,
}

/// P8c staging rule: pending and viewer = read-only, editor+ = write.
pub fn seat_permission(stage: SeatStage) -> CollaboratorPermission {
    match stage {
        SeatStage::Pending | SeatStage::Viewer => CollaboratorPermission::ReadOnly,
        SeatStage::Editor => CollaboratorPermission::Write,
    }
}

/// Grant (or upgrade) a collaborator seat on the connected provider.
pub async fn add_collaborator(
    provider: Provider,
    owner: &str,
    repo: &str,
    username: &str,
    permission: CollaboratorPermission,
) -> Result<CollaboratorStatus, BaluardError> {
    let (info, tok) = ensure_valid_token(provider).await?;
    let p = provider_for(provider, info.config())
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
    p.add_collaborator(&tok, owner, repo, username, permission)
        .await
        .map_err(|e| VaultError::Metadata(format!("add collaborator: {e}")).into())
}

/// Query the seat state for one username on one repo of the connected provider.
pub async fn collaborator_status(
    provider: Provider,
    owner: &str,
    repo: &str,
    username: &str,
) -> Result<CollaboratorStatus, BaluardError> {
    let (info, tok) = ensure_valid_token(provider).await?;
    let p = provider_for(provider, info.config())
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
    p.collaborator_status(&tok, owner, repo, username)
        .await
        .map_err(|e| VaultError::Metadata(format!("collaborator status: {e}")).into())
}

/// §4.5 `ensure_access_accepted`: surface whether a member actually
/// accepted their seat, and heal an expired invitation — GitHub invites
/// die after 7 days and an expired one reads as `None`, so the healing
/// action is a re-invite with the member's approved permission. Returns
/// the current-or-refreshed status plus whether a re-invite was issued.
/// GitHub ONLY: on GitLab/Codeberg a `None` is ambiguous (never-added,
/// deliberately-struck, or revoked out-of-band — grants there are
/// immediate, there is no pending state), so auto re-adding would
/// resurrect access an admin may have removed by hand. Those providers
/// report `None` and the admin re-invites explicitly.
pub async fn ensure_access_accepted(
    provider: Provider,
    owner: &str,
    repo: &str,
    username: &str,
    permission: CollaboratorPermission,
) -> Result<(CollaboratorStatus, bool), BaluardError> {
    let status = collaborator_status(provider, owner, repo, username).await?;
    match status {
        CollaboratorStatus::Active | CollaboratorStatus::Invited => Ok((status, false)),
        CollaboratorStatus::None if provider == Provider::GitHub => {
            let s = add_collaborator(provider, owner, repo, username, permission).await?;
            Ok((s, true))
        }
        CollaboratorStatus::None => Ok((status, false)),
    }
}

/// Strike a collaborator seat (idempotent). Offboarding pre-flight calls
/// this BEFORE the vault-side rotation commit is pushed.
pub async fn remove_collaborator(
    provider: Provider,
    owner: &str,
    repo: &str,
    username: &str,
) -> Result<(), BaluardError> {
    let (info, tok) = ensure_valid_token(provider).await?;
    let p = provider_for(provider, info.config())
        .map_err(|e| VaultError::Metadata(format!("provider init: {e}")))?;
    p.remove_collaborator(&tok, owner, repo, username)
        .await
        .map_err(|e| VaultError::Metadata(format!("remove collaborator: {e}")).into())
}

/// Clone a remote repository into `local_path` with `.partial` staging and `.baluard` marker verification.
pub fn clone_and_register(
    provider: Option<Provider>,
    clone_url: &str,
    local_path: &Path,
    cancel_flag: Option<Arc<AtomicBool>>,
) -> Result<(), BaluardError> {
    sweep_partial_clones(local_path);

    let partial_path = PathBuf::from(format!("{}.partial", local_path.display()));
    if partial_path.exists() {
        let _ = std::fs::remove_dir_all(&partial_path);
    }

    let progress = Arc::new(Mutex::new(CloneProgress::default()));

    let clone_res = SyncEngine::clone_remote_cancelable(
        clone_url,
        &partial_path,
        provider,
        progress,
        cancel_flag,
    );

    if let Err(e) = clone_res {
        let _ = std::fs::remove_dir_all(&partial_path);
        return Err(e);
    }

    // Verify .baluard marker file inside cloned directory
    let marker_path = partial_path.join(".baluard");
    if !marker_path.exists() {
        let _ = std::fs::remove_dir_all(&partial_path);
        return Err(VaultError::NotFound(
            "repository does not contain a .baluard marker file".into(),
        )
        .into());
    }

    // Never clobber an existing vault directory: if the target holds a
    // .baluard marker it is a real vault and a caller bug got us here.
    if local_path.join(".baluard").exists() {
        let _ = std::fs::remove_dir_all(&partial_path);
        return Err(VaultError::Metadata(
            "clone target already contains a vault; refusing to overwrite".into(),
        )
        .into());
    }

    if local_path.exists() {
        let _ = std::fs::remove_dir_all(local_path);
    }

    std::fs::rename(&partial_path, local_path)
        .map_err(|e| VaultError::Metadata(format!("renaming partial clone: {e}")).into())
}

/// Disconnect a provider.
pub async fn disconnect(provider: Provider) -> Result<(), BaluardError> {
    revoke_and_disconnect(provider)
        .await
        .map_err(|e| VaultError::Metadata(format!("disconnect failed: {e}")).into())
}

/// Enroll a device into an existing vault pre-unlock using the 24-word recovery phrase.
pub fn enroll_device_pre_unlock(
    vault_path: &Path,
    master_password: &str,
    recovery_phrase: &str,
    device_name: &str,
) -> Result<VaultHandle, BaluardError> {
    let word_count = recovery_phrase.split_whitespace().count();
    if word_count != 24 {
        return Err(VaultError::Corrupt(format!(
            "recovery phrase must be 24 words, got {word_count}"
        ))
        .into());
    }

    let kdf_json = std::fs::read_to_string(vault_path.join("meta/kdf-params.json"))
        .map_err(|e| VaultError::Metadata(format!("reading kdf params: {e}")))?;
    let _kdf_params: baluard_core::types::KdfParams = serde_json::from_str(&kdf_json)
        .map_err(|e| VaultError::Corrupt(format!("kdf params: {e}")))?;

    // Policy is NOT read here: settings.enc is unreadable pre-unlock and
    // settings-pub.json does not carry it. Core derives the real policy
    // from settings.enc under the phrase-recovered root key (guessing
    // Personal here would bypass Strict vaults).

    let (x25519_secret, x25519_public) = baluard_core::crypto::hpke_wrap::generate_x25519_keypair();
    let (ed25519_signing, ed25519_verifying) =
        baluard_core::crypto::signature::generate_ed25519_keypair();

    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let payload = EnrollmentPayload {
        device_id: uuid::Uuid::new_v4(),
        encryption_public_key: hex::encode(x25519_public.to_bytes()),
        signing_public_key: hex::encode(baluard_core::crypto::signature::verifying_key_bytes(
            &ed25519_verifying,
        )),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        nonce: hex::encode(nonce_bytes),
        name: if device_name.is_empty() {
            "Mobile Device".to_string()
        } else {
            device_name.to_string()
        },
        vault_id: None,
        epoch: None,
        registry_version: None,
    };

    let mut dm = DeviceManager::load_from_vault(vault_path)
        .map_err(|e| VaultError::Metadata(format!("load device manager: {e}")))?;

    let result = dm
        .enroll_with_recovery_phrase(&payload, recovery_phrase, x25519_secret, ed25519_signing)
        .map_err(|e| VaultError::Metadata(format!("enroll failed: {e}")))?;

    let privkey_data = serde_json::json!({
        "device_id": result.device_id.to_string(),
        "x25519_private": hex::encode(result.x25519_secret.to_bytes()),
        "ed25519_private": hex::encode(result.ed25519_signing.to_bytes()),
    });
    let privkey_path = vault_path.join("meta/device-privkey.json");
    let privkey_tmp = privkey_path.with_extension("json.tmp");
    let mut privkey_json_str = serde_json::to_string_pretty(&privkey_data)
        .map_err(|e| VaultError::Corrupt(format!("privkey json: {e}")))?;

    std::fs::write(&privkey_tmp, privkey_json_str.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("write privkey: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&privkey_tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&privkey_tmp, &privkey_path)
        .map_err(|e| VaultError::Metadata(format!("rename privkey: {e}")))?;

    privkey_json_str.zeroize();

    let _ = baluard_core::vault::device_privkey::write_device_id(vault_path, result.device_id);

    if let Some(keystore) = baluard_core::vault::creation::get_global_keystore() {
        let privkey_bytes = serde_json::to_vec(&privkey_data).unwrap_or_default();
        let _ = keystore.store_secret(&result.device_id.to_string(), &privkey_bytes);
        let _ = keystore.store_secret(&format!("device:{}", result.device_id), &privkey_bytes);
    }

    let mut handle = VaultHandle::open(vault_path)?;
    handle.unlock(master_password)?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_provider_manager_locks() {
        let mgr = global_provider_manager();
        let lock1 = mgr.lock_for(Provider::GitHub);
        let lock2 = mgr.lock_for(Provider::GitHub);
        assert!(Arc::ptr_eq(&lock1, &lock2));

        let lock_codeberg = mgr.lock_for(Provider::Codeberg);
        assert!(!Arc::ptr_eq(&lock1, &lock_codeberg));
    }

    #[test]
    fn seat_permission_maps_p8c_staging() {
        // Least-privilege: nobody gets push until vault-side approval
        // grants an editor-or-above role.
        assert_eq!(
            seat_permission(SeatStage::Pending),
            CollaboratorPermission::ReadOnly
        );
        assert_eq!(
            seat_permission(SeatStage::Viewer),
            CollaboratorPermission::ReadOnly
        );
        assert_eq!(
            seat_permission(SeatStage::Editor),
            CollaboratorPermission::Write
        );
    }

    #[test]
    fn test_sweep_partial_clones() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("vault_repo");
        let partial_dir = temp_dir.path().join("vault_repo.partial");
        std::fs::create_dir_all(&partial_dir).unwrap();
        assert!(partial_dir.exists());

        sweep_partial_clones(&target_dir);
        assert!(!partial_dir.exists());
    }

    #[test]
    fn test_clone_and_register_rejects_missing_marker() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("vault_repo");

        // Clone non-vault local git repo (no .baluard marker)
        let source_dir = temp_dir.path().join("source_repo");
        let git_repo = git2::Repository::init(&source_dir).unwrap();

        // Create an initial commit in source_repo
        let mut index = git_repo.index().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = git_repo.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        git_repo
            .commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
            .unwrap();

        let source_url = format!("file://{}", source_dir.display());
        let result = clone_and_register(Some(Provider::GitHub), &source_url, &target_dir, None);

        assert!(result.is_err());
        assert!(!target_dir.exists());
        assert!(!target_dir.with_extension("partial").exists());
    }
}
