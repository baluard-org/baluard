//! Provider and device orchestration runtime layer.
//!
//! Provides process-global token refresh serialization, device flow polling,
//! PAT connection, repo discovery, cancelable clone with `.baluard` marker check,
//! and pre-unlock device enrollment for mobile and daemon hosts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// G16 (mobile parity): point a phone-created vault at its own private
/// Git repo — create-or-reuse the repo, wire the origin remote, commit
/// pending changes, first push, and record sync info in the device
/// registry. Mirrors the daemon's vault.setup_sync arm so a vault born
/// on the phone gains a remote without a desktop; unlike the daemon arm
/// it self-heals a pre-existing repo (create failing with an
/// already-exists shape falls back to the repo's existing clone URL).
#[cfg(feature = "git-sync")]
pub async fn setup_sync_remote(
    vault_path: &Path,
    devkey_seal: Option<[u8; 32]>,
    provider: Provider,
    repo_name: &str,
    clone_url: Option<String>,
) -> Result<String, String> {
    let (info, tok) = ensure_valid_token(provider)
        .await
        .map_err(|e| e.to_string())?;
    let prov = provider_for(provider, info.config()).map_err(|e| format!("provider init: {e}"))?;

    // Default the repo name from the .baluard marker slug, then the
    // directory name — the same ladder the daemon arm uses.
    let marker_slug = baluard_core::vault::registry::BaluardMarker::read_from_vault(vault_path)
        .ok()
        .flatten()
        .map(|m| m.slug);
    let effective_name = baluard_core::vault::slug::normalize_slug(&match repo_name.trim() {
        "" => marker_slug.clone().unwrap_or_else(|| {
            vault_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault")
                .to_string()
        }),
        n => n.to_string(),
    });

    let remote_url: String = if let Some(url) = clone_url {
        url
    } else {
        match prov.create_private_repo(&tok, &effective_name).await {
            Ok(r) => r.clone_url,
            Err(e) => {
                let msg = e.to_string();
                // Only a real name-collision signal reuses; a bare "422"
                // also covers plan-quota and invalid-name failures that
                // must surface to the user, not trigger a repo hunt.
                let looks_exists =
                    msg.contains("already exists") || msg.contains("name already exists");
                if !looks_exists {
                    return Err(format!("Failed to create repo: {msg}"));
                }
                // Repo exists from a prior partial attempt — reuse it.
                // Accounts can hold many repos; walk pages until found.
                let mut found: Option<String> = None;
                for page in 1..=10u8 {
                    let repos = prov
                        .list_repos(&tok, page, 100)
                        .await
                        .map_err(|e| format!("Repo exists but listing failed: {e}"))?;
                    if repos.is_empty() {
                        break;
                    }
                    if let Some(r) = repos.iter().find(|r| r.name == effective_name) {
                        found = Some(r.clone_url.clone());
                        break;
                    }
                }
                found.ok_or_else(|| {
                    format!("Repo '{effective_name}' exists but was not found on {provider}")
                })?
            }
        }
    };

    // Init git repo + add remote + commit + push (blocking git ops).
    let git_path = vault_path.to_path_buf();
    let provider_str = provider.to_string();
    let remote_for_block = remote_url.clone();
    let _ = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let engine = SyncEngine::new(&git_path, "baluard-mobile", devkey_seal.as_ref());
        let git_repo = match engine.open_repo() {
            Ok(r) => r,
            Err(open_err) => {
                // A .git directory means an existing vault repo: an open
                // failure there is transient (lock contention with another
                // engine) and re-initializing would silently wipe the
                // vault's history, producing a second genesis whose push
                // can never fast-forward over the first incarnation's
                // remote line. Only a vault with no .git at all may init.
                if git_path.join(".git").exists() {
                    return Err(format!(
                        "Git open failed (vault repo already initialized): {open_err}"
                    ));
                }
                engine
                    .init_repo()
                    .map_err(|e| format!("Git init failed: {e}"))?
            }
        };
        if let Ok(existing) = engine.get_remote_url(&git_repo, "origin") {
            if existing != remote_for_block {
                return Err(format!(
                    "Remote 'origin' already set to {existing}; disconnect sync first"
                ));
            }
        } else {
            engine
                .add_remote(&git_repo, "origin", &remote_for_block)
                .map_err(|e| format!("Failed to add remote: {e}"))?;
        }
        let status = engine
            .status(&git_repo)
            .map_err(|e| format!("Status check failed: {e}"))?;
        if status.is_dirty() {
            engine
                .commit_all(&git_repo, "")
                .map_err(|e| format!("Commit failed: {e}"))?;
        }
        // A just-created forge repo can serve phantom or stale refs to the
        // push's own negotiation: the pack lands (or lands on retry) while
        // the call reports non-fast-forward, and the ref view converges
        // seconds later. Retry with a delay, then trust the remote tip over
        // the error — org-journey evidence: every "failed" backup repo was
        // fully populated and converged within a minute.
        let mut push_err: Option<BaluardError> = None;
        for attempt in 0..3u8 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            match engine.push(&git_repo, "origin") {
                Ok(()) => {
                    push_err = None;
                    break;
                }
                Err(e) => {
                    if engine.remote_head_matches_local(&git_repo, "origin") {
                        eprintln!(
                            "warning: push reported {e} but the remote tip already carries our head; treating the backup as pushed"
                        );
                        push_err = None;
                        break;
                    }
                    push_err = Some(e);
                }
            }
        }
        if let Some(e) = push_err {
            return Err(format!("First push failed: {e}"));
        }
        Ok(remote_for_block)
    })
    .await
    .map_err(|e| format!("Task join: {e}"))??;

    // Record sync info in the device-local registry.
    if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
        if let Some(slug) = marker_slug {
            if let Some(entry) = reg.get_mut(&slug) {
                entry.provider = Some(provider_str.clone());
                entry.remote_url = Some(remote_url.clone());
                entry.last_synced = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
            }
            let _ = reg.save_locked();
        }
    }

    Ok(serde_json::json!({
        "status": "synced",
        "repo": remote_url,
        "provider": provider_str,
    })
    .to_string())
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
    clone_and_register_with_credentials(provider, clone_url, local_path, cancel_flag, None)
}

/// Custom-remote clone: request-time credentials ride the shared callback
/// machinery into the clone and persist into the cloned vault's
/// device-local files after the rename, so the next sync authenticates
/// the same way.
pub fn clone_and_register_with_credentials(
    provider: Option<Provider>,
    clone_url: &str,
    local_path: &Path,
    cancel_flag: Option<Arc<AtomicBool>>,
    creds: Option<baluard_core::sync::credentials::CredentialConfig>,
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
        creds.clone(),
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

    std::fs::rename(&partial_path, local_path).map_err(|e| {
        BaluardError::Vault(VaultError::Metadata(format!("renaming partial clone: {e}")))
    })?;

    if let Some(cfg) = creds.as_ref() {
        baluard_core::sync::credentials::persist_in_memory(local_path, cfg)
            .map_err(|e| VaultError::Metadata(format!("persisting credentials: {e}")))?;
    }
    Ok(())
}

/// Custom-remote setup: the repository URL is user-supplied; there is no
/// provider token and no repo creation. Credentials were already stored
/// device-side via apply_custom_credentials and the sync engine's
/// credential chain reads them at transport time. The registry entry
/// carries provider None: forge automation stays manual by design.
#[cfg(feature = "git-sync")]
pub async fn setup_sync_remote_custom(
    vault_path: &Path,
    devkey_seal: Option<[u8; 32]>,
    clone_url: String,
) -> Result<String, String> {
    let git_path = vault_path.to_path_buf();
    let seal = devkey_seal;
    let remote_url = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let engine = SyncEngine::new(&git_path, "baluard-mobile", seal.as_ref());
        let git_repo = match engine.open_repo() {
            Ok(r) => r,
            Err(open_err) => {
                if git_path.join(".git").exists() {
                    return Err(format!(
                        "Git open failed (vault repo already initialized): {open_err}"
                    ));
                }
                engine
                    .init_repo()
                    .map_err(|e| format!("Git init failed: {e}"))?
            }
        };
        if let Ok(existing) = engine.get_remote_url(&git_repo, "origin") {
            if existing != clone_url {
                return Err(format!(
                    "Remote 'origin' already set to {existing}; disconnect sync first"
                ));
            }
        } else {
            engine
                .add_remote(&git_repo, "origin", &clone_url)
                .map_err(|e| format!("Failed to add remote: {e}"))?;
        }
        let status = engine
            .status(&git_repo)
            .map_err(|e| format!("Status check failed: {e}"))?;
        if status.is_dirty() {
            engine
                .commit_all(&git_repo, "")
                .map_err(|e| format!("Commit failed: {e}"))?;
        }
        // The same raced-first-push tolerance as the provider path.
        let mut push_err: Option<BaluardError> = None;
        for attempt in 0..3u8 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            match engine.push(&git_repo, "origin") {
                Ok(()) => {
                    push_err = None;
                    break;
                }
                Err(e) => {
                    if engine.remote_head_matches_local(&git_repo, "origin") {
                        push_err = None;
                        break;
                    }
                    push_err = Some(e);
                }
            }
        }
        if let Some(e) = push_err {
            return Err(format!("First push failed: {e}"));
        }
        Ok(clone_url)
    })
    .await
    .map_err(|e| format!("Task join: {e}"))??;

    if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
        let slug = baluard_core::vault::registry::BaluardMarker::read_from_vault(vault_path)
            .ok()
            .flatten()
            .map(|m| m.slug);
        if let Some(slug) = slug {
            if let Some(entry) = reg.get_mut(&slug) {
                // Custom remotes carry no provider: seat grants and repo
                // listing are manual by design.
                entry.provider = None;
                entry.remote_url = Some(remote_url.clone());
                entry.last_synced = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
            }
            let _ = reg.save_locked();
        }
    }
    Ok(remote_url)
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
    let _kdf_params = baluard_core::crypto::kdf::parse_kdf_params(&kdf_json)?;

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

    // Prove the master password BEFORE any enrollment write: a mistyped
    // password must not mint ghost devices (roster entries, key files,
    // keystore secrets) that sync to every member. A full unlock cannot
    // run here — a fresh device has no device private key yet — so the
    // proof is the KEK canary alone; no key material is retained.
    {
        let kek = baluard_core::crypto::kdf::derive_kek(master_password, &_kdf_params)
            .map_err(|e| VaultError::Corrupt(format!("kdf: {e}")))?;
        let session_key = baluard_core::crypto::hkdf_derive::derive_session_key(&kek)
            .map_err(|e| VaultError::Corrupt(format!("kdf: {e}")))?;
        let canary = std::fs::read(vault_path.join("meta/kek-canary.enc"))
            .map_err(|e| VaultError::Metadata(format!("reading kek canary: {e}")))?;
        baluard_core::vault::canary::verify_kek_canary(&session_key, &canary)
            .map_err(|_| VaultError::InvalidOperation("master password incorrect".to_string()))?;
        let mut proof = (kek, session_key);
        use zeroize::Zeroize;
        proof.0.zeroize();
        proof.1.zeroize();
    }
    let mut dm = DeviceManager::load_from_vault(vault_path)
        .map_err(|e| VaultError::Metadata(format!("load device manager: {e}")))?;

    let result = dm
        .enroll_with_recovery_phrase(&payload, recovery_phrase, x25519_secret, ed25519_signing)
        .map_err(|e| VaultError::Metadata(format!("enroll failed: {e}")))?;

    let mut privkey_data = serde_json::json!({
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
    // The hex private keys live in heap Strings that a plain remove would
    // drop without wiping, so take and zeroize them explicitly.
    if let Some(obj) = privkey_data.as_object_mut() {
        if let Some(serde_json::Value::String(mut hex)) = obj.remove("x25519_private") {
            hex.zeroize();
        }
        if let Some(serde_json::Value::String(mut hex)) = obj.remove("ed25519_private") {
            hex.zeroize();
        }
    }

    let _ = baluard_core::vault::device_privkey::write_device_id(vault_path, result.device_id);

    if let Some(keystore) = baluard_core::vault::creation::get_global_keystore() {
        // The escrow stores only identity metadata (the key hex is
        // stripped above and never reaches the keystore); it is
        // best-effort because the privkey file is already written (it
        // reseals at the unlock below), and every failure logs instead of
        // vanishing.
        match serde_json::to_vec(&privkey_data) {
            Ok(mut privkey_bytes) => {
                if let Err(e) = keystore.store_secret(&result.device_id.to_string(), &privkey_bytes)
                {
                    log::warn!(
                        "device keystore escrow failed for {}: {e}",
                        result.device_id
                    );
                }
                if let Err(e) =
                    keystore.store_secret(&format!("device:{}", result.device_id), &privkey_bytes)
                {
                    log::warn!(
                        "device keystore escrow failed for device:{}: {e}",
                        result.device_id
                    );
                }
                zeroize::Zeroize::zeroize(&mut privkey_bytes);
            }
            Err(e) => {
                log::warn!("device keystore escrow skipped: privkey serialization failed: {e}");
            }
        }
    }

    let mut handle = VaultHandle::open(vault_path)?;
    handle.unlock(master_password)?;
    Ok(handle)
}

// ── Web-OAuth (auth-code + PKCE) callback infrastructure ──
// Shared by the daemon (desktop) and the mobile UniFFI surface. The host
// starts a localhost TCP listener, the client opens the auth URL in a
// browser, the provider redirects to
// http://127.0.0.1:<port>/callback?code=...&state=... and the host
// exchanges the code for a token.
// Used by Codeberg/Forgejo (no device flow). The daemon starts a localhost
// TCP listener, the desktop opens the auth URL in a browser, the provider
// redirects to http://127.0.0.1:<port>/callback?code=...&state=... and the
// daemon exchanges the code for a token.
//
// B1 fix: sessions are keyed by provider (not a single global Option) so a
// concurrent flow for a different provider cannot overwrite another. M4 fix:
// starting a new flow for the SAME provider aborts the prior listener task,
// freeing its port immediately instead of waiting for the 5-min timeout.

struct OAuthSession {
    result: Option<Result<String, String>>, // Ok(username) | Err(msg)
    /// Handle to the callback listener task. Aborted when the same provider
    /// starts a new flow, dropping the listener and closing its port.
    task: Option<tokio::task::JoinHandle<()>>,
}

static OAUTH_SESSIONS: std::sync::LazyLock<
    tokio::sync::Mutex<
        std::collections::HashMap<baluard_core::providers::types::Provider, OAuthSession>,
    >,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

/// Start a web-OAuth flow: bind a loopback listener, build the auth URL,
/// spawn the callback handler, return the URL for the desktop to open.
pub async fn web_oauth_start(
    provider: baluard_core::providers::types::Provider,
    config: baluard_core::providers::ProviderConfig,
) -> Result<String, String> {
    let prov = baluard_core::providers::provider_for(provider, config.clone())
        .map_err(|e| e.to_string())?;

    // Bind a random loopback port for the callback. RFC 8252 §7.3 says loopback
    // redirects allow any port, so we bind :0 (OS-assigned). Forgejo's OAuth2
    // provider is documented to honor this for public clients registered with
    // `http://127.0.0.1/` as the redirect URI.
    //
    // TODO(H1, release-gate): verify Codeberg (Forgejo) actually accepts a
    // dynamic-port redirect at runtime before shipping the automatic flow.
    // If Codeberg requires an exact registered port, register a fixed port
    // here and change the bind to `127.0.0.1:<FIXED>` to match. Test
    // end-to-end against codeberg.org. Tracked in docs/dev/git-provider-apps-
    // and-tokens.md §9.6. Until verified, Codeberg users fall back to PAT.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get listener addr: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let oauth = prov
        .oauth_start(&redirect_uri)
        .await
        .map_err(|e| format!("oauth_start failed: {e}"))?;

    // Spawn the callback listener (accepts one connection, then exits).
    let verifier = oauth.code_verifier.clone();
    let expected_state = oauth.state.clone();
    let task = tokio::spawn(async move {
        handle_oauth_callback(
            listener,
            provider,
            config,
            verifier,
            expected_state,
            redirect_uri,
        )
        .await;
    });

    // Replace any prior session for this provider: abort its listener (M4) so
    // its port is freed immediately, then record the new one.
    {
        let mut sessions = OAUTH_SESSIONS.lock().await;
        if let Some(mut old) = sessions.insert(
            provider,
            OAuthSession {
                result: None,
                task: Some(task),
            },
        ) {
            if let Some(t) = old.task.take() {
                t.abort();
            }
        }
    }

    Ok(oauth.auth_url)
}

/// Accept one HTTP request on the callback listener, extract code+state,
/// exchange for token, store result in the session.
async fn handle_oauth_callback(
    listener: tokio::net::TcpListener,
    provider: baluard_core::providers::types::Provider,
    config: baluard_core::providers::ProviderConfig,
    verifier: String,
    expected_state: String,
    redirect_uri: String,
) {
    // Accept one connection (timeout after 5 minutes).
    let (mut sock, _) =
        match tokio::time::timeout(std::time::Duration::from_secs(300), listener.accept()).await {
            Ok(Ok(conn)) => conn,
            _ => {
                set_oauth_result(provider, Err("callback timeout".into())).await;
                return;
            }
        };

    // Read the HTTP request until the header terminator (\r\n\r\n). M3: a
    // single read() is not guaranteed to return all data; loop until the
    // terminator appears or we hit the buffer cap. Each read is bounded:
    // a stalled browser preconnect must not hold the flow for 300s.
    let mut buf = vec![0u8; 8192];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            break; // header too large; proceed with what we have
        }
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sock.read(&mut buf[total..]),
        )
        .await
        {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            // Read timeout or error: abandon this connection attempt.
            _ => {
                set_oauth_result(provider, Err("callback read timed out".into())).await;
                return;
            }
        };
        total += n;
        if String::from_utf8_lossy(&buf[..total]).contains("\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&buf[..total]);

    // Extract code + state from the request line: GET /callback?code=X&state=Y
    let (code, state) = match parse_callback_query(&request) {
        Some(pair) => pair,
        None => {
            let _ = respond_html(&mut sock, "Missing code or state in callback.").await;
            // A user-side deny arrives as ?error=access_denied&error_description=...
            // (no code); surface the real reason instead of the generic line.
            let reason =
                parse_callback_error(&request).unwrap_or_else(|| "missing code/state".into());
            set_oauth_result(provider, Err(reason)).await;
            return;
        }
    };

    if state != expected_state {
        let _ = respond_html(&mut sock, "CSRF state mismatch. Authentication aborted.").await;
        set_oauth_result(provider, Err("CSRF state mismatch".into())).await;
        return;
    }

    // Exchange code for token.
    let prov = match baluard_core::providers::provider_for(provider, config) {
        Ok(p) => p,
        Err(e) => {
            let _ = respond_html(&mut sock, &format!("Provider error: {e}")).await;
            set_oauth_result(provider, Err(e.to_string())).await;
            return;
        }
    };

    match prov.oauth_exchange(&code, &verifier, &redirect_uri).await {
        Ok((token, info)) => {
            if let Err(e) =
                baluard_core::providers::token::store_token(info.provider, &info.username, &token)
            {
                let _ = respond_html(&mut sock, &format!("Keyring error: {e}")).await;
                set_oauth_result(provider, Err(format!("Keyring: {e}"))).await;
                return;
            }
            let mut state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            state_file.set(info.clone());
            if let Err(e) = state_file.save() {
                let _ = baluard_core::providers::token::delete_token(info.provider, &info.username);
                let _ = respond_html(&mut sock, &format!("State save error: {e}")).await;
                set_oauth_result(provider, Err(format!("State: {e}"))).await;
                return;
            }
            let _ = respond_html(
                &mut sock,
                "Authentication successful! You can close this tab and return to Baluard.",
            )
            .await;
            set_oauth_result(provider, Ok(info.username)).await;
        }
        Err(e) => {
            let _ = respond_html(&mut sock, &format!("Authentication failed: {e}")).await;
            set_oauth_result(provider, Err(e.to_string())).await;
        }
    }
}

/// Poll a web-OAuth session: `{"status":"pending"}`, `{"status":"success",
/// "username":...}`, or `{"status":"error","error":...}`. Shared by the
/// daemon route and the mobile UniFFI surface.
pub async fn web_oauth_status(
    provider: baluard_core::providers::types::Provider,
) -> Result<String, String> {
    let sessions = OAUTH_SESSIONS.lock().await;
    match sessions.get(&provider) {
        Some(s) => match &s.result {
            Some(Ok(username)) => Ok(serde_json::json!({
                "status": "success", "username": username
            })
            .to_string()),
            Some(Err(msg)) => Ok(serde_json::json!({
                "status": "error", "error": msg
            })
            .to_string()),
            None => Ok(serde_json::json!({"status": "pending"}).to_string()),
        },
        None => Err("No web-OAuth session in progress for this provider".into()),
    }
}

/// Escape HTML metacharacters. H2: provider API error bodies may contain
/// <, >, &, ", ' — interpolating them raw into the callback response page is
/// an XSS surface (local-only, but fail closed).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

async fn respond_html(sock: &mut tokio::net::TcpStream, msg: &str) -> std::io::Result<()> {
    let safe = html_escape(msg);
    let body = format!(
        "<html><body style='font-family:sans-serif;text-align:center;padding:40px'>\
         <h2>{safe}</h2></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    sock.write_all(response.as_bytes()).await
}

async fn set_oauth_result(
    provider: baluard_core::providers::types::Provider,
    result: Result<String, String>,
) {
    let mut sessions = OAUTH_SESSIONS.lock().await;
    if let Some(s) = sessions.get_mut(&provider) {
        s.result = Some(result);
    }
}

/// Parse code + state from a GET request line: `GET /callback?code=X&state=Y HTTP/1.1`.
fn parse_callback_query(request: &str) -> Option<(String, String)> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        match kv.next()? {
            "code" => code = kv.next().map(urldecode),
            "state" => state = kv.next().map(urldecode),
            _ => {}
        }
    }
    Some((code?, state?))
}

/// The OAuth error form of a callback: `?error=access_denied&error_description=...`.
/// Returns `error: description` when present, else `None`.
fn parse_callback_error(request: &str) -> Option<String> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    let mut err = None;
    let mut desc = None;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        match kv.next()? {
            "error" => err = kv.next().map(urldecode),
            "error_description" => desc = kv.next().map(urldecode),
            _ => {}
        }
    }
    Some(match (err?, desc) {
        (e, Some(d)) => format!("{e}: {d}"),
        (e, None) => e,
    })
}

/// Minimal URL-decoder for %XX sequences.
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract the slug field from a JSON payload. Returns `None` when the
/// payload is not JSON, has no `slug` field, or the field is empty. Used to

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
