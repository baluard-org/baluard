//! Vault state management for the daemon.
//!
//! Holds an unlocked VaultHandle in memory behind a shared lock.
//! The daemon routes gateway actions through this state.

use baluard_core::vault::handle::{CipherRead, VaultHandle};
use base64::Engine;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use zeroize::Zeroize;

/// UI-facing masked conflict. NO secret values; field labels + a sensitive
/// flag only. Mirrors `PendingConflict` in the frontend contract
/// (`docs/plan-conflict-resolution-panel.md`).
#[derive(serde::Serialize)]
struct MaskedConflict {
    name: String,
    cipher_type: String,
    fields: Vec<MaskedField>,
}

#[derive(serde::Serialize)]
struct MaskedField {
    key: String,
    label: String,
    sensitive: bool,
}

/// Build a `MaskedConflict` from the local decrypted cipher + the engine's
/// `ConflictInfo`. `ConflictInfo.conflicting_fields` carries plaintext
/// local/remote values (intentionally not Serialize); we surface ONLY the
/// field name + a coarse sensitive classification, never the value.
fn mask_conflict(
    local: &baluard_core::types::Cipher,
    info: &baluard_core::sync::conflict::ConflictInfo,
) -> MaskedConflict {
    // Coarse sensitive-field classifier. Mirrors the semantic groups in
    // conflict.rs (username/password/totp atomic) + card/ssh private material.
    const SENSITIVE_KEYS: &[&str] = &["password", "totp_uri", "code", "number", "private_key"];
    let fields = info
        .conflicting_fields
        .iter()
        .map(|f| {
            let key = f.field_name.clone();
            let sensitive = SENSITIVE_KEYS.iter().any(|s| key == *s)
                || key.contains("private")
                || key.contains("secret");
            MaskedField {
                label: key.clone(),
                key,
                sensitive,
            }
        })
        .collect();
    MaskedConflict {
        name: local.name.clone(),
        cipher_type: format!("{:?}", local.kind.cipher_type()).to_lowercase(),
        fields,
    }
}

/// Shared vault state accessible from all connection handlers.
pub struct VaultState {
    /// Path to the vault directory on disk.
    pub vault_path: PathBuf,
    /// The vault handle. None = not opened or locked.
    inner: RwLock<Option<VaultHandle>>,
    /// R7-2: Session authorization token. Generated on unlock.
    /// Any same-UID process connecting after unlock must present this token
    /// to access cipher data. Prevents the daemon from being a full-vault oracle.
    session_token: RwLock<Option<String>>,
    /// H6 fix: Timestamp when session token was created (epoch seconds).
    /// Token expires after SESSION_TOKEN_TTL_SECONDS.
    session_token_created: AtomicU64,
    /// Last activity timestamp (seconds since epoch). Updated on every IPC request.
    last_activity: AtomicU64,
    /// Cover commit scheduler handle. Cancelled on lock.
    cover_timer: RwLock<Option<tokio::task::JoinHandle<()>>>,
    /// Whether a post-mutation cover commit is already pending.
    /// Prevents spawning multiple cover tasks from rapid sequential edits.
    cover_pending: std::sync::atomic::AtomicBool,
    /// Session counter incremented on every lock. Orphaned cover tasks
    /// check this and bail if the session has changed.
    cover_session: AtomicU64,
    /// Phase 1: WebAuthn ceremony state cache (300s TTL).
    pub ceremony_cache: baluard_core::crypto::webauthn::CeremonyCache,
    /// Session-bound PIN Quick Unlock escrow. None = PIN not enabled this
    /// session. Survives soft-lock (separate from `inner`); dies on close /
    /// daemon restart. See `pin::PinEscrow` for the security model.
    pin: tokio::sync::Mutex<Option<crate::pin::PinEscrow>>,
    /// Wrong-PIN attempt counter. On reaching `pin::MAX_PIN_FAILURES` the
    /// escrow is destroyed (master password becomes mandatory again).
    pin_failures: std::sync::atomic::AtomicU32,
    /// Auto-sync coordinator. Activated on unlock when the vault has a remote
    /// + connected provider. Cheap clone (Arc inside).
    pub autosync: crate::autosync::AutoSyncHandle,
}

impl VaultState {
    /// Create a new empty state pointing at a vault directory.
    pub fn new(vault_path: PathBuf) -> Self {
        let autosync = crate::autosync::AutoSyncHandle::new(&vault_path);
        Self {
            vault_path,
            inner: RwLock::new(None),
            session_token: RwLock::new(None),
            session_token_created: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            cover_timer: RwLock::new(None),
            cover_pending: std::sync::atomic::AtomicBool::new(false),
            cover_session: AtomicU64::new(0),
            ceremony_cache: baluard_core::crypto::webauthn::CeremonyCache::new(),
            pin: tokio::sync::Mutex::new(None),
            pin_failures: std::sync::atomic::AtomicU32::new(0),
            autosync,
        }
    }

    /// Touch last activity timestamp (called on every IPC request).
    pub fn touch_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Start the periodic cover commit timer.
    /// Fires at random intervals (2-6 hours) to mask inactivity patterns.
    /// Only runs while vault is unlocked. Cancelled on lock.
    pub async fn start_cover_timer(self: &Arc<Self>) {
        self.stop_cover_timer().await;
        let state = self.clone();
        let state_for_store = self.clone();

        let handle = tokio::spawn(async move {
            loop {
                // Random interval: 2-6 hours
                let delay_secs = 7200 + (rand::random::<u64>() % 14400);
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                // Check vault is still unlocked
                let guard = state.inner.read().await;
                if let Some(handle) = guard.as_ref() {
                    if handle.is_unlocked() {
                        drop(guard);
                        #[cfg(feature = "git-sync")]
                        state.fire_cover_commit().await;
                    }
                }
            }
        });

        *state_for_store.cover_timer.write().await = Some(handle);
    }

    /// Cancel the cover commit timer.
    pub async fn stop_cover_timer(&self) {
        if let Some(handle) = self.cover_timer.write().await.take() {
            handle.abort();
        }
    }

    /// Schedule a single cover commit at a random delay (30min-4hr).
    /// Deduplicates: if a cover is already pending, this is a no-op.
    /// Orphaned tasks (from lock/re-unlock) bail via session counter.
    /// No-op in non-git-sync builds.
    pub fn schedule_cover_after_commit(self: &Arc<Self>) {
        #[cfg(not(feature = "git-sync"))]
        {
            return;
        }

        // Dedup: skip if already scheduled
        if self
            .cover_pending
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let state = self.clone();
        let session_at_spawn = self.cover_session.load(Ordering::Relaxed);
        tokio::spawn(async move {
            // Random delay: 30min - 4hr
            let delay_secs = 1800 + (rand::random::<u64>() % 12600);
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

            // Bail if session changed (vault was locked/re-unlocked)
            if state.cover_session.load(Ordering::Relaxed) != session_at_spawn {
                state.cover_pending.store(false, Ordering::Relaxed);
                return;
            }

            // Clear pending flag before firing (allows next mutation to reschedule)
            state.cover_pending.store(false, Ordering::Relaxed);

            let guard = state.inner.read().await;
            if let Some(handle) = guard.as_ref() {
                if handle.is_unlocked() {
                    drop(guard);
                    #[cfg(feature = "git-sync")]
                    state.fire_cover_commit().await;
                }
            }
        });
    }

    /// Fire a cover commit (git-sync only).
    #[cfg(feature = "git-sync")]
    async fn fire_cover_commit(&self) {
        let (device_id, devkey_seal) = {
            let guard = self.inner.read().await;
            let Some(handle) = guard.as_ref() else {
                return;
            };
            if !handle.is_unlocked() {
                return;
            }
            // C5: engine identity is the device UUID, not the display name.
            (handle.device_id.to_string(), handle.devkey_seal())
        };
        if device_id.is_empty() {
            return;
        }
        let engine = baluard_core::sync::engine::SyncEngine::new(
            &self.vault_path,
            &device_id,
            devkey_seal.as_ref(),
        );
        if let Ok(repo) = engine.open_repo() {
            let _ = engine.cover_commit(&repo);
        }
    }

    /// Get seconds since last activity.
    pub fn seconds_since_activity(&self) -> u64 {
        let last = self.last_activity.load(Ordering::Relaxed);
        if last == 0 {
            return 0;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last)
    }

    /// Decide whether this single vault should auto-lock now. Reads its own
    /// `vault_timeout` policy from settings + `last_activity`. Returns `false`
    /// for any locked or unopened vault (nothing to do).
    ///
    /// Used by the Phase 6 host walker. The actual `lock()` happens in the
    /// caller so this method is side-effect free (no cover-timer /
    /// session-token churn on a `false`).
    ///
    /// Policy mapping:
    /// - `Minutes(n)` -> idle check (elapsed >= n minutes)
    /// - `OnAppExit` -> never by idle (the vault locks when the app exits)
    /// - `Immediately` -> never here (driven by the desktop blur event, not
    ///   the walker; see `vaults.on_app_blur`)
    ///
    /// No maximum cap: the user's explicit choice is respected. The natural
    /// backstop is app exit (the daemon sidecar dies on quit, keys are
    /// in-memory only) + manual lock.
    pub async fn should_auto_lock(&self) -> bool {
        let timeout_minutes = {
            let guard = self.inner.read().await;
            let Some(handle) = guard.as_ref() else {
                return false; // no vault open
            };
            if !handle.is_unlocked() {
                return false; // already locked
            }
            handle
                .get_settings()
                .ok()
                .map(|s| s.vault_timeout)
                .unwrap_or_default()
                .idle_minutes()
        };

        let Some(timeout_minutes) = timeout_minutes else {
            return false; // OnAppExit / Immediately -> not idle-timed
        };

        let elapsed = self.seconds_since_activity();
        let timeout_secs = (timeout_minutes as u64) * 60;
        elapsed >= timeout_secs
    }

    /// Read this vault's timeout policy. Falls back to the default when the
    /// vault is closed/locked or settings can't be read. Used by the desktop
    /// blur event to decide whether this vault locks on app background.
    pub async fn timeout_policy(&self) -> baluard_core::vault::manifest::VaultTimeout {
        let guard = self.inner.read().await;
        let Some(handle) = guard.as_ref() else {
            return baluard_core::vault::manifest::VaultTimeout::default_for_new();
        };
        handle
            .get_settings()
            .map(|s| s.vault_timeout)
            .unwrap_or_default()
    }

    /// Open a vault from disk (locked state).
    pub async fn open(&self) -> Result<(), String> {
        let handle = VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Failed to open vault: {e}"))?;
        let mut guard = self.inner.write().await;
        *guard = Some(handle);
        Ok(())
    }

    /// C1: devkey seal subkey from the unlocked handle; `None` while
    /// locked. Lets the daemon's sync routes open the sealed
    /// `meta/device-privkey.json` for commit signing without exposing the
    /// handle itself.
    pub async fn devkey_seal(&self) -> Option<[u8; 32]> {
        let g = self.inner.read().await;
        g.as_ref().and_then(|h| h.devkey_seal())
    }

    /// Unlock the vault with the master password.
    ///
    /// KDF derivation (Argon2id) runs OUTSIDE the write lock to avoid
    /// blocking all reads during the expensive derivation (~300ms-1s).
    /// Opens the vault once, unlocks it, then swaps it in.
    pub async fn unlock(&self, master_password: &str) -> Result<(), String> {
        // Quick check: already unlocked?
        {
            let guard = self.inner.read().await;
            if let Some(ref handle) = *guard {
                if handle.is_unlocked() {
                    return Ok(());
                }
            }
        }

        // Open a fresh handle and derive KEK outside any lock (expensive Argon2id)
        let mut new_handle = VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Failed to open vault for unlock: {e}"))?;

        new_handle
            .unlock(master_password)
            .map_err(|e| format!("Unlock failed: {e}"))?;

        // Swap in the unlocked handle under write lock
        let mut guard = self.inner.write().await;
        // Double-check: another thread may have unlocked while we waited
        if let Some(ref handle) = *guard {
            if handle.is_unlocked() {
                // Another thread won the race. Discard our handle (keys zeroize on drop).
                return Ok(());
            }
        }
        *guard = Some(new_handle);

        // R7-2: Generate session token on unlock
        let mut token_guard = self.session_token.write().await;
        *token_guard = Some(generate_session_token());
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        drop(token_guard);

        // C5: fold plaintext device names into settings.enc + strip them from
        // the git-tracked devices.json. Runs on every unlock (idempotent;
        // re-folds names reintroduced by a legacy remote's registry). Runs
        // outside git-sync so non-syncing vaults migrate too. Best-effort:
        // a failure logs and retries on the next unlock.
        if let Some(handle) = guard.as_ref() {
            if let Err(e) = handle.migrate_device_names_into_settings() {
                log::warn!("[state] device-name migration deferred: {e}");
            }
        }

        // M2 fix: activate the auto-sync coordinator immediately on unlock if
        // the vault has a remote. Previously activation was lazy (only on the
        // first sync.autosync_status poll, ~10s after unlock), so edits in that
        // window weren't queued. Device identity comes from the handle; guard
        // the whole thing behind git-sync since the sync check needs the
        // engine.
        #[cfg(feature = "git-sync")]
        {
            // C5: engine identity is the device UUID, not the display name.
            let device_id = guard
                .as_ref()
                .map(|h| h.device_id.to_string())
                .unwrap_or_default();
            // C1: seal subkey from the just-unlocked handle (never the KEK).
            let devkey_seal = guard.as_ref().and_then(|h| h.devkey_seal());
            if !device_id.is_empty() {
                let has_remote = baluard_core::sync::engine::SyncEngine::new(
                    &self.vault_path,
                    &device_id,
                    devkey_seal.as_ref(),
                )
                .open_repo()
                .and_then(|repo| baluard_core::sync::engine::SyncEngine::has_remote(&repo))
                .unwrap_or(false);
                if has_remote {
                    self.autosync.activate(device_id.clone(), devkey_seal).await;
                    // Pull remote changes the moment the vault opens so the UI
                    // reflects other-device edits immediately (event-driven,
                    // not waiting on the 30-min idle cadence). Spawned off the
                    // unlock IPC path so unlock returns without waiting on a
                    // network fetch; pull_only's generation check no-ops if the
                    // vault is locked before the fetch completes.
                    let handle = self.autosync.clone();
                    tokio::spawn(async move {
                        handle.pull_only(device_id).await;
                    });
                }
            }
        }

        Ok(())
    }

    /// Lock the vault, zeroizing keys in memory. Clears the session token.
    pub async fn lock(&self) -> Result<(), String> {
        // Stop cover timer + auto-sync first
        self.stop_cover_timer().await;
        self.autosync.deactivate().await;
        self.cover_pending.store(false, Ordering::Relaxed);
        self.cover_session.fetch_add(1, Ordering::Relaxed);

        let mut guard = self.inner.write().await;
        if let Some(ref mut handle) = *guard {
            handle.lock();
        }
        // R7-2: Invalidate session token on lock
        let mut token_guard = self.session_token.write().await;
        *token_guard = None;
        self.session_token_created.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Change the master password. Requires vault to be unlocked.
    /// H1 fix: re-wraps KEK and disables stale biometric secret.
    pub async fn change_master_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        handle
            .change_master_password(old_password, new_password)
            .map_err(|e| format!("{e}"))
    }

    /// Check if vault is currently unlocked.
    pub async fn is_unlocked(&self) -> bool {
        let guard = self.inner.read().await;
        guard.as_ref().is_some_and(|h| h.is_unlocked())
    }

    /// This device's UUID (string form). Empty if the vault is closed.
    /// Feeds the autosync coordinator and sync engine (C5: identity is the
    /// id, never the display name).
    pub async fn device_id(&self) -> String {
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .map(|h| h.device_id.to_string())
            .unwrap_or_default()
    }

    /// This device's display name (audit C5: primary source is the encrypted
    /// settings map; the registry file is the pre-migration fallback). Empty
    /// if the vault is locked or the device isn't registered. Exposed for the
    /// mobile FFI layer so the OS lifecycle host doesn't have to thread the
    /// name through every sync event callback (plan §3.5).
    pub async fn device_name(&self) -> String {
        let guard = self.inner.read().await;
        let Some(h) = guard.as_ref() else {
            return String::new();
        };
        if let Some(name) = h.device_display_names().get(&h.device_id.to_string()) {
            return name.clone();
        }
        // Pre-migration fallback: name still in the registry file.
        h.device_manager
            .registry()
            .devices
            .get(&h.device_id)
            .map(|d| d.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_default()
    }

    /// Re-unlock the vault with a pre-derived KEK, skipping the Argon2id KDF.
    /// This is the autofill / extension quick-unlock path (plan §3.2): the
    /// caller retrieves the biometric-gated KEK from the platform keychain
    /// (StrongBox / Secure Enclave) and passes it here. The master-password
    /// KDF never runs in the memory-capped autofill process (OOM guard).
    ///
    /// Mirrors the `pin_unlock` tail: opens a fresh handle, runs the shared
    /// `unlock_with_kek` (keywrap HPKE unwrap + canaries), mints a session
    /// token. A stale/corrupted keywrap fails closed (a password changed on
    /// another device invalidates the retained KEK).
    pub async fn unlock_with_kek(&self, kek: &[u8; 32]) -> Result<(), String> {
        // unlock_with_kek runs outside the lock (no KDF, but the HPKE unwrap
        // + canary check still touch the keywrap).
        let mut new_handle = baluard_core::vault::handle::VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Failed to open vault for KEK unlock: {e}"))?;
        new_handle
            .unlock_with_kek(kek)
            .map_err(|e| format!("KEK unlock failed: {e}"))?;
        let mut guard = self.inner.write().await;
        *guard = Some(new_handle);
        drop(guard);
        let mut token_guard = self.session_token.write().await;
        *token_guard = Some(generate_session_token());
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        Ok(())
    }

    /// List all cipher IDs (works locked or unlocked).
    #[allow(dead_code)]
    pub async fn list_cipher_ids(&self) -> Result<Vec<String>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let ids = handle.list_cipher_ids().map_err(|e| format!("{e}"))?;
        Ok(ids.iter().map(|id| id.to_string()).collect())
    }

    /// List cipher metadata (requires unlocked vault).
    pub async fn list_cipher_meta(&self) -> Result<Vec<baluard_core::types::CipherMeta>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        handle.list_cipher_meta().map_err(|e| format!("{e}"))
    }

    /// Batch-fetch all decrypted ciphers, folders, trash, and archived items.
    /// Returns a single JSON blob to eliminate N+1 IPC round-trips from the frontend.
    pub async fn list_all(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        // Folders
        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;

        // Main ciphers (excludes archived)
        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::with_capacity(metas.len());
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(ref c)) => {
                    let mut json = cipher_to_json(c);
                    json["_meta"] = serde_json::json!({
                        "id": meta.id.to_string(),
                        "name": meta.name,
                        "cipher_type": meta.cipher_type,
                        "favorite": meta.favorite,
                        "username": meta.username,
                    });
                    ciphers.push(json);
                }
                _ => continue,
            }
        }

        // Trash
        let trash_ids = handle.list_trash_ids().map_err(|e| format!("{e}"))?;
        let mut trash = Vec::with_capacity(trash_ids.len());
        for id in &trash_ids {
            match handle.get_cipher(*id) {
                Ok(CipherRead::Decrypted(ref c)) => trash.push(cipher_to_json(c)),
                _ => continue,
            }
        }

        // Archived
        let archived_metas = handle.list_archived_meta().map_err(|e| format!("{e}"))?;
        let mut archived = Vec::with_capacity(archived_metas.len());
        for meta in &archived_metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(ref c)) => {
                    let mut json = cipher_to_json(c);
                    json["_meta"] = serde_json::json!({
                        "id": meta.id.to_string(),
                        "name": meta.name,
                        "cipher_type": meta.cipher_type,
                        "favorite": meta.favorite,
                        "username": meta.username,
                    });
                    archived.push(json);
                }
                _ => continue,
            }
        }

        // Rebuild tag index from decrypted cipher data
        let _ = handle.rebuild_tag_index();
        let tags = handle.list_tags().unwrap_or_default();

        let result = serde_json::json!({
            "ciphers": ciphers,
            "folders": folders,
            "trash": trash,
            "archived": archived,
            "tags": tags,
        });
        serde_json::to_string(&result).map_err(|e| format!("Serialization: {e}"))
    }

    /// Get a cipher by ID. Requires vault to be unlocked for decryption.
    pub async fn get_cipher(&self, id_str: &str, decrypt: bool) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        let result = handle.get_cipher(cipher_id).map_err(|e| format!("{e}"))?;

        match result {
            baluard_core::vault::handle::CipherRead::Decrypted(c) => {
                Ok(cipher_to_json(&c).to_string())
            }
            baluard_core::vault::handle::CipherRead::Locked(info) => {
                if decrypt {
                    Err("Vault is locked. Unlock first.".to_string())
                } else {
                    let json = serde_json::json!({
                        "id": info.id.to_string(),
                        "epoch": info.key_epoch,
                        "seq": info.update_seq,
                        "tier": format!("{:?}", info.tier),
                        "ciphertext_len": info.ciphertext_len,
                    });
                    Ok(json.to_string())
                }
            }
        }
    }

    /// Get current vault settings as JSON.
    /// Merges encrypted profile data (display_name, subtitle, avatar_ext) from profile.enc.
    pub async fn settings_get(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let mut settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        // Merge encrypted profile fields (if available).
        // Note: load_profile() may write settings.json (strips stale identity fields
        // from crash window). Safe because write_vault_file uses atomic rename, but
        // semantically a write inside a read-locked context.
        if let Ok(profile) = handle.load_profile() {
            settings.display_name = profile.display_name;
            settings.subtitle = profile.subtitle;
            settings.avatar_ext = profile.avatar_ext;
        }
        serde_json::to_string(&settings).map_err(|e| format!("settings serialization: {e}"))
    }

    /// Update vault settings from partial JSON.
    pub async fn settings_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;

        let mut settings = handle.get_settings().map_err(|e| format!("{e}"))?;

        // Vault timeout policy token (e.g. "15m", "immediately", "on_app_exit").
        if let Some(v) = partial.get("vault_timeout") {
            settings.vault_timeout = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid vault_timeout: {e}"))?;
        }
        if let Some(v) = partial.get("theme") {
            settings.theme =
                serde_json::from_value(v.clone()).map_err(|e| format!("Invalid theme: {e}"))?;
        }
        if let Some(v) = partial.get("default_uri_match") {
            let s = v.as_str().ok_or("default_uri_match must be a string")?;
            settings.default_uri_match =
                Some(baluard_core::types::UriMatchStrategy::from_str_strict(s)?);
        }
        if let Some(v) = partial.get("fetch_favicons") {
            settings.fetch_favicons = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid fetch_favicons: {e}"))?;
        }
        if let Some(v) = partial.get("display_name") {
            settings.display_name = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid display_name: {e}"))?;
        }
        if let Some(v) = partial.get("subtitle") {
            settings.subtitle =
                serde_json::from_value(v.clone()).map_err(|e| format!("Invalid subtitle: {e}"))?;
        }
        if let Some(v) = partial.get("avatar_ext") {
            settings.avatar_ext = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid avatar_ext: {e}"))?;
        }
        if let Some(v) = partial.get("lang") {
            let lang = v.as_str().ok_or("lang must be a string")?;
            settings.lang = Some(lang.to_string());
            // Also persist to plaintext meta/locale for pre-unlock access
            handle.save_locale(lang).map_err(|e| format!("{e}"))?;
        }

        // Check if payload contains identity keys (even with null values for clearing)
        let partial_obj = partial.as_object();
        let has_identity_keys = partial_obj.is_some_and(|o| {
            o.contains_key("display_name")
                || o.contains_key("subtitle")
                || o.contains_key("avatar_ext")
        });

        if has_identity_keys {
            let profile = baluard_core::vault::manifest::UserProfile {
                display_name: settings.display_name.clone(),
                subtitle: settings.subtitle.clone(),
                avatar_ext: settings.avatar_ext.clone(),
            };
            // Strip identity from settings, save both
            settings.display_name = None;
            settings.subtitle = None;
            settings.avatar_ext = None;
            handle
                .save_settings(&settings)
                .map_err(|e| format!("{e}"))?;
            handle.save_profile(&profile).map_err(|e| format!("{e}"))?;
        } else {
            handle
                .save_settings(&settings)
                .map_err(|e| format!("{e}"))?;
        }
        Ok(())
    }

    /// Get avatar image as base64. Returns empty string if no avatar set.
    /// Reads avatar_ext from encrypted profile.enc.
    /// M1 fix: avatar is AES-256-GCM encrypted at meta/avatar.enc. On first
    /// read of a legacy plaintext meta/avatar.{ext}, migrates to encrypted
    /// storage and deletes the plaintext file.
    pub async fn avatar_get(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        let ext = handle
            .load_profile()
            .ok()
            .and_then(|p| p.avatar_ext)
            .unwrap_or_default();
        if ext.is_empty() {
            return Ok(String::new());
        }

        let enc_path = handle.path.join("meta/avatar.enc");
        if enc_path.exists() {
            let blob = std::fs::read(&enc_path).map_err(|e| format!("read avatar: {e}"))?;
            let key = handle.derive_avatar_key();
            let bytes = baluard_core::vault::avatar::decrypt_avatar(&key, &blob)
                .map_err(|e| format!("{e}"))?;
            use base64::Engine;
            return Ok(base64::engine::general_purpose::STANDARD.encode(&bytes));
        }

        // Legacy: plaintext meta/avatar.{ext} (pre-M1 fix). Migrate to
        // encrypted storage on first read, then delete the plaintext.
        let avatar_path = handle.path.join(format!("meta/avatar.{ext}"));
        if !avatar_path.exists() {
            return Ok(String::new());
        }
        let data = std::fs::read(&avatar_path).map_err(|e| format!("read avatar: {e}"))?;
        // Migrate: encrypt and write to avatar.enc
        let key = handle.derive_avatar_key();
        let blob =
            baluard_core::vault::avatar::encrypt_avatar(&key, &data).map_err(|e| format!("{e}"))?;
        baluard_core::vault::write_vault_file(&enc_path, &blob)
            .map_err(|e| format!("write avatar: {e}"))?;
        // Delete the plaintext legacy file
        let _ = std::fs::remove_file(&avatar_path);
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&data))
    }

    /// Set avatar image from base64. Payload: JSON {"data": "<base64>", "ext": "png"}
    /// M1 fix: encrypts avatar with AES-256-GCM (key from SGK) and stores
    /// at meta/avatar.enc. Legacy plaintext meta/avatar.{ext} files are
    /// deleted on next set.
    pub async fn avatar_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let b64 = v["data"].as_str().unwrap_or("");
        let ext_raw = v["ext"].as_str().unwrap_or("png");

        // Load current profile from encrypted storage
        let mut profile = handle.load_profile().unwrap_or_default();

        if b64.is_empty() {
            // Remove avatar: delete both encrypted and any legacy plaintext
            let enc_path = handle.path.join("meta/avatar.enc");
            let _ = std::fs::remove_file(&enc_path);
            if let Some(ref old_ext) = profile.avatar_ext {
                let old_ext_clean = old_ext.trim().to_lowercase();
                if matches!(
                    old_ext_clean.as_str(),
                    "png" | "jpg" | "jpeg" | "gif" | "webp"
                ) {
                    let old_path = handle.path.join(format!("meta/avatar.{old_ext_clean}"));
                    let _ = std::fs::remove_file(&old_path);
                }
            }
            profile.avatar_ext = None;
            handle.save_profile(&profile).map_err(|e| format!("{e}"))?;
            return Ok(());
        }

        // Validate extension to prevent path traversal
        let ext = ext_raw.trim().to_lowercase();
        if !matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
            return Err("Invalid avatar extension".into());
        }

        // Cap avatar size (~350KB base64 = ~256KB decoded)
        if b64.len() > 350_000 {
            return Err("Avatar too large (max 256KB)".into());
        }

        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("base64 decode: {e}"))?;

        // M1 fix: encrypt with avatar key derived from SGK
        let key = handle.derive_avatar_key();
        let blob = baluard_core::vault::avatar::encrypt_avatar(&key, &bytes)
            .map_err(|e| format!("{e}"))?;

        // Atomic write with 0600 permissions
        let enc_path = handle.path.join("meta/avatar.enc");
        baluard_core::vault::write_vault_file(&enc_path, &blob)
            .map_err(|e| format!("write avatar: {e}"))?;

        // Remove ALL whitelisted legacy plaintext avatar files.
        // Peer review fix: previously only removed files matching the old ext,
        // leaving stray plaintext files with the same or different extensions.
        for legacy_ext in ["png", "jpg", "jpeg", "gif", "webp"] {
            let legacy_path = handle.path.join(format!("meta/avatar.{legacy_ext}"));
            let _ = std::fs::remove_file(&legacy_path);
        }
        profile.avatar_ext = Some(ext);
        handle.save_profile(&profile).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    /// Save plaintext locale to meta/locale (readable before vault unlock).
    /// Payload: plain lang string (e.g. "es").
    pub async fn locale_save(&self, lang: &str) -> Result<(), String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        handle.save_locale(lang).map_err(|e| format!("{e}"))
    }

    /// Generate an SSH keypair. Payload: JSON {"type": "ed25519"|"ecdsa256"}
    /// Returns JSON {"public_key": "ssh-ed25519 ...", "fingerprint": "SHA256:...", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
    /// Key material stays in the daemon process; only formatted strings cross IPC.
    ///
    /// L7 fix: RSA 4096 was removed. The `rsa` crate has RUSTSEC-2023-0071
    /// (Marvin Attack, timing sidechannel, no upstream fix), pulled in
    /// transitively by `ssh-key`'s `rsa` feature. Ed25519 (default) and
    /// ECDSA P-256 cover modern needs; RSA 4096 SSH keys are legacy
    /// compat only and the audit's "must-fix" recommendation was to
    /// drop the feature.
    pub async fn ssh_generate_key(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let key_type = v["type"].as_str().unwrap_or("ed25519");

        // Validate key type early. RSA removed (see L7 fix above).
        if !matches!(key_type, "ed25519" | "ecdsa256") {
            return Err(format!(
                "Unknown SSH key type: {key_type}. Use ed25519 or ecdsa256"
            ));
        }

        // Generate keypair using system CSRNG
        // For Ed25519: construct from raw 32-byte seed (fast, no trait compat issues)
        // For RSA/ECDSA: use ssh_key's built-in random via a rand_core adapter
        use rand::RngCore;
        let private_key = if key_type == "ed25519" {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let kp = ssh_key::private::Ed25519Keypair::from_seed(&seed);
            ssh_key::private::PrivateKey::new(
                ssh_key::private::KeypairData::Ed25519(kp),
                String::new(),
            )
            .map_err(|e| format!("Ed25519 key construction failed: {e}"))?
        } else {
            // Adapter: rand 0.8 OsRng -> ssh_key::rand_core 0.10 traits
            // OsRng never fails, so we use Infallible as the error type
            use std::convert::Infallible;
            struct Adapter;
            impl ssh_key::rand_core::TryRng for Adapter {
                type Error = Infallible;
                fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                    Ok(rand::rngs::OsRng.next_u32())
                }
                fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                    Ok(rand::rngs::OsRng.next_u64())
                }
                fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                    rand::rngs::OsRng.fill_bytes(dst);
                    Ok(())
                }
            }
            impl ssh_key::rand_core::TryCryptoRng for Adapter {}
            // L7 fix: RSA removed. Only ECDSA P-256 for the non-Ed25519 path.
            ssh_key::private::PrivateKey::random(
                &mut Adapter,
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256,
                },
            )
            .map_err(|e| format!("SSH key generation failed: {e}"))?
        };

        // Encode public key in OpenSSH format
        let public_key = private_key
            .public_key()
            .to_openssh()
            .map_err(|e| format!("Public key encoding failed: {e}"))?;

        // Compute SHA256 fingerprint
        let fingerprint = private_key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();

        // Encode private key in OpenSSH PEM format (unencrypted, will be encrypted by vault)
        let private_key_pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| format!("Private key encoding failed: {e}"))?;

        let result = serde_json::json!({
            "public_key": public_key,
            "fingerprint": fingerprint,
            "private_key": private_key_pem.as_ref() as &str,
        });

        serde_json::to_string(&result).map_err(|e| format!("JSON serialization: {e}"))
    }

    // ── Generator history ──

    /// Add a generated password/passphrase to history.
    /// Payload: `{ "value": "...", "kind": "password", "params": { "length": 16, ... } }`
    /// Returns the updated history list (display-capped, newest first).
    pub async fn generator_history_add(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;

        let value = v["value"]
            .as_str()
            .ok_or("Missing 'value' field")?
            .to_string();
        let kind_str = v["kind"].as_str().unwrap_or("password");
        let kind = match kind_str {
            "passphrase" => baluard_core::types::GeneratorKind::Passphrase,
            _ => baluard_core::types::GeneratorKind::Password,
        };
        let params: baluard_core::types::GeneratorParams = serde_json::from_value(
            v["params"].clone(),
        )
        .unwrap_or(baluard_core::types::GeneratorParams {
            length: if matches!(kind, baluard_core::types::GeneratorKind::Password) {
                16
            } else {
                5
            },
            upper: true,
            numbers: true,
            symbols: true,
            separator: None,
        });

        let entry = baluard_core::types::GeneratorHistoryEntry {
            value,
            kind,
            params,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let display = handle
            .add_generator_history_entry(entry)
            .map_err(|e| format!("{e}"))?;

        serde_json::to_string(&display).map_err(|e| format!("JSON serialization: {e}"))
    }

    /// List generator history (display-capped, newest first).
    pub async fn generator_history_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        let display = handle
            .list_generator_history_display()
            .map_err(|e| format!("{e}"))?;
        serde_json::to_string(&display).map_err(|e| format!("JSON serialization: {e}"))
    }

    /// Clear all generator history.
    pub async fn generator_history_clear(&self) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        handle.clear_generator_history().map_err(|e| format!("{e}"))
    }

    // ── Passkey ceremony (Phase 1) ──

    /// List passkey ciphers, optionally filtered by rp_id.
    /// Payload: `{ "rp_id": "example.com" }` or `{}` for all.
    pub async fn passkey_list(&self, payload: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        let v: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
        let rp_filter = v["rp_id"].as_str().filter(|s| !s.is_empty());

        // TODO(Phase 2): Replace N+1 pattern with batch get method.
        // Performance matters for browser extension autofill trigger.
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;
        let mut passkeys = Vec::new();
        for meta in &metas {
            if meta.cipher_type != baluard_core::types::CipherType::Login {
                continue;
            }
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                if let baluard_core::types::CipherKind::Login(data) = &c.kind {
                    let has_password = data.password.is_some();
                    if let Some(ref fido2_list) = data.fido2_credentials {
                        for pk in fido2_list {
                            if rp_filter.is_none_or(|rp| pk.rp_id == rp) {
                                passkeys.push(serde_json::json!({
                                    "id": meta.id.to_string(),
                                    "login_name": meta.name,
                                    "has_password": has_password,
                                    "pk_name": pk.name,
                                    "cipher_type": "login",
                                    "favorite": meta.favorite,
                                    "rp_id": pk.rp_id,
                                    "rp_name": pk.rp_name,
                                    "user_name": pk.user_name,
                                    "credential_id": pk.credential_id,
                                    "counter": pk.counter,
                                    "private_key_missing": pk.private_key_missing,
                                }));
                            }
                        }
                    }
                }
            }
        }

        Ok(serde_json::to_string(&passkeys).unwrap_or_else(|_| "[]".into()))
    }

    /// Start a registration ceremony. Runs passkey-rs ceremony, caches result.
    /// Payload: `{ "rp_id": "...", "rp_name": "...", "user_name": "...", "user_display_name": "...", "origin": "https://..." }`
    pub async fn passkey_challenge_register(&self, payload: &str) -> Result<String, String> {
        use baluard_core::crypto::webauthn::{CeremonyState, run_registration};
        use baluard_core::vault::handle::CipherRead;

        self.ceremony_cache.evict_expired().await;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let rp_id = v["rp_id"].as_str().ok_or("Missing 'rp_id'")?.to_string();
        let rp_name = v["rp_name"].as_str().unwrap_or(&rp_id).to_string();
        let user_name = v["user_name"].as_str().unwrap_or("").to_string();
        let user_display_name = v["user_display_name"]
            .as_str()
            .unwrap_or(&user_name)
            .to_string();
        let origin_str = v["origin"].as_str().ok_or("Missing 'origin'")?;
        let origin = url::Url::parse(origin_str).map_err(|e| format!("Invalid origin: {e}"))?;
        let user_id: Vec<u8> = v["user_id"]
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_else(|| rand::random::<[u8; 32]>().to_vec());

        // Build passkey index from vault
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                ciphers.push(c.clone());
            }
        }
        let index = baluard_core::crypto::webauthn::PasskeyIndex::from_boxed_ciphers(&ciphers);
        drop(guard);

        let result = run_registration(
            &origin,
            rp_id.clone(),
            rp_name.clone(),
            user_name.clone(),
            user_display_name.clone(),
            user_id.clone(),
            &index,
        )
        .await?;

        let ceremony_id = hex::encode(rand::random::<[u8; 32]>());

        self.ceremony_cache
            .insert(
                ceremony_id.clone(),
                CeremonyState::Registration {
                    rp_id,
                    rp_name,
                    user_name,
                    user_display_name,
                    user_id,
                    created_at: std::time::Instant::now(),
                },
            )
            .await;

        let pk_data_json = serde_json::to_value(&result.passkey_data)
            .map_err(|e| format!("Serialize error: {e}"))?;

        let response = serde_json::json!({
            "ceremony_id": ceremony_id,
            "credential_id": result.credential_id_b64,
            "attestation_response": serde_json::from_str::<serde_json::Value>(&result.attestation_response)
                .unwrap_or_default(),
            "passkey_data": pk_data_json,
        });

        Ok(response.to_string())
    }

    /// Complete a registration ceremony. Saves passkey to vault.
    /// Payload: `{ "ceremony_id": "...", "passkey_data": {...} }`
    ///
    /// SECURITY NOTE (Phase 1 only): passkey_data is echoed from the
    /// challenge_register response. This is acceptable within the same-process
    /// trust boundary (desktop). Phase 2 (browser extension) MUST store
    /// passkey_data in CeremonyState and retrieve it here, never trusting
    /// client-supplied data.
    pub async fn passkey_finish_register(&self, payload: &str) -> Result<String, String> {
        use baluard_core::crypto::webauthn::CeremonyState;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let ceremony_id = v["ceremony_id"].as_str().ok_or("Missing 'ceremony_id'")?;

        let state = self
            .ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        match &state {
            CeremonyState::Registration { .. } => {}
            _ => return Err("Expected registration ceremony".into()),
        }

        let pk_data: baluard_core::types::PasskeyData =
            serde_json::from_value(v["passkey_data"].clone())
                .map_err(|e| format!("Invalid passkey_data: {e}"))?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;

        // Find existing Login cipher for this RP, or create one
        let mut found_id = None;
        for meta in &metas {
            if meta.cipher_type != baluard_core::types::CipherType::Login {
                continue;
            }
            use baluard_core::vault::handle::CipherRead;
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                if let baluard_core::types::CipherKind::Login(data) = &c.kind {
                    if data.uris.iter().any(|u| u.uri.contains(&pk_data.rp_id)) {
                        found_id = Some(meta.id);
                        break;
                    }
                }
            }
        }

        if let Some(id) = found_id {
            // Append passkey to existing Login cipher
            use baluard_core::vault::handle::CipherRead;
            let cipher = match handle.get_cipher(id) {
                Ok(CipherRead::Decrypted(c)) => c,
                _ => return Err("Cipher not found".into()),
            };
            if let baluard_core::types::CipherKind::Login(mut data) = cipher.kind.clone() {
                let mut list = data.fido2_credentials.unwrap_or_default();
                list.push(pk_data.clone());
                data.fido2_credentials = Some(list);
                let input = baluard_core::types::CipherInput {
                    name: cipher.name.clone(),
                    folder_id: cipher.folder_id,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    tags: cipher.tags.clone(),
                    kind: baluard_core::types::CipherKind::Login(data),
                    notes: cipher.notes.clone(),
                    custom_fields: cipher.custom_fields.clone(),
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history.clone(),
                    attachments: cipher.attachments.clone(),
                    archived: cipher.archived,
                };
                handle
                    .update_cipher(id, &input)
                    .map_err(|e| e.to_string())?;
                return Ok(serde_json::json!({
                    "id": id.to_string(),
                    "credential_id": pk_data.credential_id,
                })
                .to_string());
            }
            Err("Expected Login kind".into())
        } else {
            // Create new Login cipher with passkey
            let input = baluard_core::types::CipherInput {
                name: pk_data
                    .rp_name
                    .clone()
                    .unwrap_or_else(|| pk_data.rp_id.clone()),
                folder_id: None,
                favorite: false,
                reprompt: false,
                tags: vec!["passkey".to_string()],
                kind: baluard_core::types::CipherKind::Login(baluard_core::types::LoginData {
                    username: pk_data.user_name.clone(),
                    uris: vec![baluard_core::types::LoginUri {
                        uri: format!("https://{}", pk_data.rp_id),
                        match_strategy: baluard_core::types::UriMatchStrategy::Domain,
                    }],
                    fido2_credentials: Some(vec![pk_data.clone()]),
                    ..Default::default()
                }),
                notes: None,
                custom_fields: Vec::new(),
                created_at: None,
                password_history: Vec::new(),
                attachments: Vec::new(),
                archived: false,
            };
            let cipher_id = handle.add_cipher(&input).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "id": cipher_id.to_string(),
                "credential_id": pk_data.credential_id,
            })
            .to_string())
        }
    }

    /// Start an assertion ceremony. Runs passkey-rs assertion, caches result.
    /// Payload: `{ "rp_id": "example.com", "origin": "https://example.com" }`
    pub async fn passkey_challenge_assert(&self, payload: &str) -> Result<String, String> {
        use baluard_core::crypto::webauthn::{CeremonyState, run_assertion};
        use baluard_core::vault::handle::CipherRead;

        self.ceremony_cache.evict_expired().await;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let rp_id = v["rp_id"].as_str().ok_or("Missing 'rp_id'")?.to_string();
        let origin_str = v["origin"].as_str().ok_or("Missing 'origin'")?;
        let origin = url::Url::parse(origin_str).map_err(|e| format!("Invalid origin: {e}"))?;

        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                ciphers.push(c.clone());
            }
        }
        let index = baluard_core::crypto::webauthn::PasskeyIndex::from_boxed_ciphers(&ciphers);
        drop(guard);

        let result = run_assertion(&origin, &rp_id, &index).await?;

        let ceremony_id = hex::encode(rand::random::<[u8; 32]>());

        self.ceremony_cache
            .insert(
                ceremony_id.clone(),
                CeremonyState::Assertion {
                    rp_id,
                    created_at: std::time::Instant::now(),
                },
            )
            .await;

        let response = serde_json::json!({
            "ceremony_id": ceremony_id,
            "credential_id": result.credential_id_b64,
            "new_counter": result.new_counter,
            "assertion_response": serde_json::from_str::<serde_json::Value>(&result.assertion_response)
                .unwrap_or_default(),
        });

        Ok(response.to_string())
    }

    /// Complete an assertion ceremony. Updates counter in vault.
    /// Payload: `{ "ceremony_id": "...", "credential_id": "...", "new_counter": 42 }`
    ///
    /// SECURITY NOTE (Phase 1 only): credential_id and new_counter are echoed
    /// from the challenge_assert response. Phase 2 MUST store these in
    /// CeremonyState::Assertion and verify credential_id belongs to the RP
    /// from the ceremony. A malicious client could otherwise forge counters
    /// or update cross-RP credentials.
    pub async fn passkey_finish_assert(&self, payload: &str) -> Result<String, String> {
        use baluard_core::crypto::webauthn::CeremonyState;
        use baluard_core::vault::handle::CipherRead;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let ceremony_id = v["ceremony_id"].as_str().ok_or("Missing 'ceremony_id'")?;

        let state = self
            .ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        match &state {
            CeremonyState::Assertion { .. } => {}
            _ => return Err("Expected assertion ceremony".into()),
        }

        let credential_id_b64 = v["credential_id"]
            .as_str()
            .ok_or("Missing 'credential_id'")?;
        let new_counter = v["new_counter"].as_u64().ok_or("Missing 'new_counter'")? as u32;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;

        for meta in &metas {
            if meta.cipher_type != baluard_core::types::CipherType::Login {
                continue;
            }
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                if let baluard_core::types::CipherKind::Login(ref data) = c.kind {
                    if let Some(ref mut fido2_list) = data.fido2_credentials.clone() {
                        for pk in fido2_list.iter_mut() {
                            if pk.credential_id == credential_id_b64 {
                                pk.counter = pk.counter.max(new_counter);
                                let input = baluard_core::types::CipherInput {
                                    name: c.name.clone(),
                                    folder_id: c.folder_id,
                                    favorite: c.favorite,
                                    reprompt: c.reprompt,
                                    tags: c.tags.clone(),
                                    kind: baluard_core::types::CipherKind::Login(
                                        baluard_core::types::LoginData {
                                            fido2_credentials: Some(fido2_list.clone()),
                                            ..data.clone()
                                        },
                                    ),
                                    notes: c.notes.clone(),
                                    custom_fields: c.custom_fields.clone(),
                                    created_at: Some(c.created_at),
                                    password_history: c.password_history.clone(),
                                    attachments: c.attachments.clone(),
                                    archived: c.archived,
                                };
                                handle
                                    .update_cipher(meta.id, &input)
                                    .map_err(|e| e.to_string())?;
                                return Ok(serde_json::json!({
                                    "credential_id": credential_id_b64,
                                    "counter": new_counter,
                                })
                                .to_string());
                            }
                        }
                    }
                }
            }
        }

        Err(format!("Passkey credential not found: {credential_id_b64}"))
    }

    /// Delete a specific passkey credential from a Login cipher.
    /// Payload: `{ "id": "<uuid>", "credential_id": "<base64url>" }`
    /// If the Login has no other data after removal, deletes the cipher entirely.
    pub async fn passkey_delete(&self, payload: &str) -> Result<(), String> {
        use baluard_core::vault::handle::CipherRead;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let id_str = v["id"].as_str().ok_or("Missing 'id'")?;
        let credential_id = v["credential_id"]
            .as_str()
            .ok_or("Missing 'credential_id'")?;
        let id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;

        let cipher = match handle.get_cipher(id) {
            Ok(CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found or not decrypted".into()),
        };
        match &cipher.kind {
            baluard_core::types::CipherKind::Login(data) => {
                let mut fido2_list = match data.fido2_credentials.clone() {
                    Some(list) if !list.is_empty() => list,
                    _ => return Err("Cipher has no passkeys".into()),
                };
                let before = fido2_list.len();
                fido2_list.retain(|pk| pk.credential_id != credential_id);
                if fido2_list.len() == before {
                    return Err(format!("Credential not found: {credential_id}"));
                }
                if fido2_list.is_empty()
                    && data.username.is_none()
                    && data.password.is_none()
                    && data.uris.is_empty()
                    && data.totp_uri.is_none()
                {
                    drop(cipher);
                    return handle.delete_cipher(id).map_err(|e| e.to_string());
                }
                let updated_data = baluard_core::types::LoginData {
                    fido2_credentials: if fido2_list.is_empty() {
                        None
                    } else {
                        Some(fido2_list)
                    },
                    ..data.clone()
                };
                let input = baluard_core::types::CipherInput {
                    name: cipher.name.clone(),
                    folder_id: cipher.folder_id,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    tags: cipher.tags.clone(),
                    kind: baluard_core::types::CipherKind::Login(updated_data),
                    notes: cipher.notes.clone(),
                    custom_fields: cipher.custom_fields.clone(),
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history.clone(),
                    attachments: cipher.attachments.clone(),
                    archived: cipher.archived,
                };
                drop(cipher);
                handle.update_cipher(id, &input).map_err(|e| e.to_string())
            }
            _ => Err("Not a Login cipher".into()),
        }
    }

    /// Rename a specific passkey credential within a Login cipher.
    /// Payload: `{ "id": "<uuid>", "credential_id": "<base64url>", "name": "new name" }`
    /// Updates `PasskeyData.name` on the matching credential. Does NOT
    /// change the Login cipher's display name.
    pub async fn passkey_rename(&self, payload: &str) -> Result<(), String> {
        use baluard_core::vault::handle::CipherRead;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let id_str = v["id"].as_str().ok_or("Missing 'id'")?;
        let credential_id = v["credential_id"]
            .as_str()
            .ok_or("Missing 'credential_id'")?;
        let new_name = v["name"].as_str().ok_or("Missing 'name'")?;
        let id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;

        let cipher = match handle.get_cipher(id) {
            Ok(CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found or not decrypted".into()),
        };
        match &cipher.kind {
            baluard_core::types::CipherKind::Login(data) => {
                let mut fido2_list = match data.fido2_credentials.clone() {
                    Some(list) if !list.is_empty() => list,
                    _ => return Err("Cipher has no passkeys".into()),
                };
                let found = fido2_list
                    .iter_mut()
                    .find(|pk| pk.credential_id == credential_id);
                match found {
                    Some(pk) => pk.name = Some(new_name.to_string()),
                    None => return Err(format!("Credential not found: {credential_id}")),
                }
                let updated_data = baluard_core::types::LoginData {
                    fido2_credentials: Some(fido2_list),
                    ..data.clone()
                };
                let input = baluard_core::types::CipherInput {
                    name: cipher.name.clone(),
                    folder_id: cipher.folder_id,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    tags: cipher.tags.clone(),
                    kind: baluard_core::types::CipherKind::Login(updated_data),
                    notes: cipher.notes.clone(),
                    custom_fields: cipher.custom_fields.clone(),
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history.clone(),
                    attachments: cipher.attachments.clone(),
                    archived: cipher.archived,
                };
                drop(cipher);
                handle.update_cipher(id, &input).map_err(|e| e.to_string())
            }
            _ => Err("Not a Login cipher".into()),
        }
    }

    /// Fetch a favicon for a given domain/URI.
    /// Payload: plain string (domain or full URI).
    /// Returns base64-encoded PNG on success, or empty string if disabled/failed.
    pub async fn fetch_favicon(&self, payload: &str) -> Result<String, String> {
        // Check if favicon fetching is enabled
        {
            let guard = self.inner.read().await;
            if let Some(handle) = guard.as_ref() {
                let settings = handle.get_settings().map_err(|e| format!("{e}"))?;
                // H7 fix: default-off. Only fetch when explicitly enabled.
                if !matches!(settings.fetch_favicons, Some(true)) {
                    return Ok(String::new());
                }
            }
        }

        // Extract domain from payload (could be full URI or bare domain)
        let domain = Self::extract_domain(payload.trim());
        if domain.is_empty() {
            return Ok(String::new());
        }

        // C20 fix: fetch via the in-tree reqwest client instead of spawning
        // `curl` (no argv exposure, no dependency on a system binary, proper
        // TLS from the same stack the providers use). The domain rides as a
        // percent-encoded query parameter (see `favicon_url`), so a domain
        // containing '&' or '=' cannot inject extra query params.
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return Ok(String::new()),
        };
        let data = match client.get(Self::favicon_url(&domain)).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(b) => b.to_vec(),
                Err(_) => return Ok(String::new()),
            },
            Err(_) => return Ok(String::new()),
        };

        // Validate it looks like image data (PNG/JPEG/ICO/WEBP magic bytes)
        // and cap the size so a misbehaving endpoint can't push a huge blob
        // into the cipher (which would inflate the envelope toward the XL tier).
        if data.len() < 4 || data.len() > 16_384 {
            return Ok(String::new());
        }

        // Accept PNG (89 50 4E 47), JPEG (FF D8 FF), ICO (00 00 01 00), or webp (52 49 46 46)
        let is_image = (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
            || (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
            || (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01)
            || (data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46);

        if !is_image {
            return Ok(String::new());
        }

        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

        // Determine mime type from magic bytes
        let mime = if data[0] == 0x89 {
            "image/png"
        } else if data[0] == 0xFF {
            "image/jpeg"
        } else if data[0] == 0x52 {
            "image/webp"
        } else {
            "image/x-icon"
        };

        Ok(serde_json::json!({"data": b64, "mime": mime}).to_string())
    }

    /// Build the favicon-service URL with the domain percent-encoded as a
    /// query value. Audit C20: the previous raw `format!` let a domain
    /// containing '&' or '=' inject extra query parameters into the request.
    fn favicon_url(domain: &str) -> String {
        let mut url = url::Url::parse("https://www.google.com/s2/favicons")
            .expect("static base URL always parses");
        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("sz", "32");
        url.into()
    }

    /// Extract domain from a URI or bare string.
    fn extract_domain(input: &str) -> String {
        let stripped = input
            .strip_prefix("https://")
            .or_else(|| input.strip_prefix("http://"))
            .unwrap_or(input);

        // Remove path, query, fragment, port
        let host = stripped.split('/').next().unwrap_or(stripped);
        let host = host.split(':').next().unwrap_or(host);
        let host = host.split('?').next().unwrap_or(host);

        // Remove leading www.
        let host = host.strip_prefix("www.").unwrap_or(host);

        host.to_lowercase()
    }

    /// Add a new cipher. Requires vault to be unlocked.
    pub async fn add_cipher(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let input: baluard_core::types::CipherInput =
            serde_json::from_str(payload).map_err(|e| format!("Invalid cipher input: {e}"))?;

        let cipher_id = handle.add_cipher(&input).map_err(|e| format!("{e}"))?;
        let _ = handle.rebuild_tag_index();

        Ok(cipher_id.to_string())
    }

    /// Update an existing cipher.
    pub async fn update_cipher(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let update: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;

        let cipher_id = update["id"]
            .as_str()
            .ok_or("Missing 'id' field")?
            .parse::<uuid::Uuid>()
            .map_err(|e| format!("Invalid UUID: {e}"))?;

        // Get existing cipher to merge updates
        let existing = handle.get_cipher(cipher_id).map_err(|e| format!("{e}"))?;
        let existing_cipher = match existing {
            baluard_core::vault::handle::CipherRead::Decrypted(c) => *c,
            _ => return Err("Cipher not found or vault locked".to_string()),
        };

        // Build merged input from existing + updates (proper PATCH semantics)
        // Distinguishes "key absent" from "key present with null"
        let input = baluard_core::types::CipherInput {
            name: update
                .get("name")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| existing_cipher.name.clone()),
            folder_id: if update
                .get("folder_id")
                .map(|v| v.is_null())
                .unwrap_or(false)
            {
                None // explicit null clears folder
            } else {
                update
                    .get("folder_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<uuid::Uuid>().ok())
                    .or(existing_cipher.folder_id)
            },
            kind: update
                .get("kind")
                .and_then(|v| {
                    serde_json::from_value::<baluard_core::types::CipherKind>(v.clone()).ok()
                })
                .unwrap_or_else(|| existing_cipher.kind.clone()),
            favorite: update
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(existing_cipher.favorite),
            reprompt: update
                .get("reprompt")
                .and_then(|v| v.as_bool())
                .unwrap_or(existing_cipher.reprompt),
            notes: if update.get("notes").map(|v| v.is_null()).unwrap_or(false) {
                None // explicit null clears notes
            } else {
                update
                    .get("notes")
                    .and_then(|v| v.as_str().map(String::from))
                    .or(existing_cipher.notes.clone())
            },
            custom_fields: {
                match update.get("custom_fields") {
                    Some(v) => {
                        serde_json::from_value::<Vec<baluard_core::types::CustomField>>(v.clone())
                            .unwrap_or_else(|e| {
                                log::error!("custom_fields deser failed: {e}");
                                existing_cipher.custom_fields.clone()
                            })
                    }
                    None => existing_cipher.custom_fields.clone(),
                }
            },
            created_at: Some(existing_cipher.created_at),
            password_history: existing_cipher.password_history.clone(),
            attachments: existing_cipher.attachments.clone(),
            archived: existing_cipher.archived,
            tags: match update.get("tags") {
                Some(v) => serde_json::from_value::<Vec<String>>(v.clone()).unwrap_or_else(|e| {
                    log::error!("tags deser failed: {e}");
                    existing_cipher.tags.clone()
                }),
                None => existing_cipher.tags.clone(),
            },
        };

        handle
            .update_cipher(cipher_id, &input)
            .map_err(|e| format!("{e}"))?;
        let _ = handle.rebuild_tag_index();
        Ok(())
    }

    /// Clone a cipher by ID (duplicate with new UUID, empty history).
    pub async fn clone_cipher(&self, id_str: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        let new_id = handle.clone_cipher(cipher_id).map_err(|e| format!("{e}"))?;
        Ok(new_id.to_string())
    }

    /// Generate TOTP code for a cipher. Returns JSON {code, period_seconds, expires_at}.
    /// The otpauth URI (seed) is NEVER included in the response.
    pub async fn totp_code(&self, id_str: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        let cipher = handle.get_cipher(cipher_id).map_err(|e| format!("{e}"))?;

        let cipher_ref = match cipher {
            baluard_core::vault::handle::CipherRead::Decrypted(c) => *c,
            baluard_core::vault::handle::CipherRead::Locked(_) => {
                return Err("Cipher is locked".into());
            }
        };

        // Extract totp_uri from the Login kind
        let totp_uri = match &cipher_ref.kind {
            baluard_core::types::CipherKind::Login(data) => data.totp_uri.as_deref(),
            _ => None,
        }
        .ok_or("No TOTP URI found for this cipher")?;

        let params = baluard_core::crypto::totp::parse_totp_uri(totp_uri)
            .map_err(|e| format!("Invalid TOTP URI: {e}"))?;

        let (code, period_seconds, expires_at) = baluard_core::crypto::totp::generate_totp(&params);

        // Return ONLY the code + metadata. Never the seed.
        serde_json::to_string(&serde_json::json!({
            "code": code,
            "period_seconds": period_seconds,
            "expires_at": expires_at,
        }))
        .map_err(|e| format!("{e}"))
    }

    // ── Folder CRUD ──

    /// List all folders.
    pub async fn list_folders(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;
        serde_json::to_string(&folders).map_err(|e| format!("{e}"))
    }

    /// Create a folder. Payload: JSON {"name": "...", "parent_id": "..." (optional)}
    pub async fn create_folder(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        // Try JSON format first, fall back to plain name
        let (name, parent_id) = match serde_json::from_str::<serde_json::Value>(payload) {
            Ok(v) => (
                v["name"].as_str().unwrap_or(payload).to_string(),
                v["parent_id"]
                    .as_str()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok()),
            ),
            Err(_) => (payload.to_string(), None),
        };

        let id = handle
            .create_folder_with_parent(&name, parent_id)
            .map_err(|e| format!("{e}"))?;
        Ok(id.to_string())
    }

    /// Rename a folder. Payload: JSON {"id": "...", "name": "new name"}
    pub async fn rename_folder(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let data: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let id_str = data["id"].as_str().ok_or("Missing 'id' field")?;
        let name = data["name"].as_str().ok_or("Missing 'name' field")?;
        let folder_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        handle
            .rename_folder(folder_id, name)
            .map_err(|e| format!("{e}"))
    }

    /// Import ciphers from parsed data. Creates folders from folder_map, then batch-creates ciphers.
    pub async fn import_ciphers(
        &self,
        import_result: baluard_core::import::ImportResult,
    ) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        // Create folders and build name->id map
        let mut folder_id_map: std::collections::HashMap<String, uuid::Uuid> =
            std::collections::HashMap::new();
        for folder_name in import_result.folder_map.keys() {
            match handle.create_folder(folder_name) {
                Ok(id) => {
                    folder_id_map.insert(folder_name.clone(), id);
                }
                Err(_) => {
                    // Folder may already exist; try to find it
                    if let Ok(folders) = handle.list_folders() {
                        if let Some(existing) = folders.iter().find(|f| f.name == *folder_name) {
                            folder_id_map.insert(folder_name.clone(), existing.id);
                        }
                    }
                }
            }
        }

        let total = import_result.ciphers.len();
        let mut created = 0usize;
        let mut errors = import_result.errors.clone();

        for (idx, mut cipher) in import_result.ciphers.into_iter().enumerate() {
            // Assign folder_id if this cipher belongs to a folder
            let folder_name = import_result
                .folder_map
                .iter()
                .find(|(_, indices)| indices.contains(&idx))
                .map(|(name, _)| name.clone());
            if let Some(name) = folder_name {
                cipher.folder_id = folder_id_map.get(&name).copied();
            }

            match handle.add_cipher(&cipher) {
                Ok(_) => created += 1,
                Err(e) => errors.push(format!("Cipher '{}': {e}", cipher.name)),
            }
        }

        let response = serde_json::json!({
            "imported": created,
            "skipped": import_result.skipped + (total - created),
            "folders_created": folder_id_map.len(),
            "errors": errors,
        });
        Ok(response.to_string())
    }

    /// Export all ciphers as BW-compatible JSON.
    pub async fn export_bw_json(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        let metas = handle.list_cipher_meta_full().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(c)) => ciphers.push(*c),
                Ok(CipherRead::Locked(_)) => continue,
                Err(e) => log::warn!("[export] skipping {}: {e}", meta.id),
            }
        }

        // Get folders
        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;
        let folder_pairs: Vec<(uuid::Uuid, String)> =
            folders.into_iter().map(|f| (f.id, f.name)).collect();

        baluard_core::import::export::export_bw_json(&ciphers, &folder_pairs)
    }

    /// Export all ciphers as BW-compatible CSV (logins only).
    pub async fn export_bw_csv(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        let metas = handle.list_cipher_meta_full().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(c)) => ciphers.push(*c),
                Ok(CipherRead::Locked(_)) => continue,
                Err(e) => log::warn!("[export] skipping {}: {e}", meta.id),
            }
        }

        baluard_core::import::export::export_bw_csv(&ciphers)
    }

    /// Delete a folder. Unassigns all ciphers in that folder.
    pub async fn delete_folder(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let folder_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        handle.delete_folder(folder_id).map_err(|e| format!("{e}"))
    }

    // ── Tag operations ──

    pub async fn list_tags(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let tags = handle.list_tags().map_err(|e| format!("{e}"))?;
        serde_json::to_string(&tags).map_err(|e| format!("{e}"))
    }

    pub async fn create_tag(&self, name: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle.create_tag(name).map_err(|e| format!("{e}"))?;
        Ok(name.to_string())
    }

    pub async fn rename_tag(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let data: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let old = data["old"].as_str().ok_or("Missing 'old' field")?;
        let new = data["new"].as_str().ok_or("Missing 'new' field")?;
        handle.rename_tag(old, new).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    pub async fn delete_tag(&self, name: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let count = handle.delete_tag(name).map_err(|e| format!("{e}"))?;
        serde_json::to_string(&serde_json::json!({"updated": count})).map_err(|e| format!("{e}"))
    }

    pub async fn rebuild_tag_index(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle.rebuild_tag_index().map_err(|e| format!("{e}"))?;
        let tags = handle.list_tags().map_err(|e| format!("{e}"))?;
        serde_json::to_string(&serde_json::json!({"tags": tags.len()})).map_err(|e| format!("{e}"))
    }

    /// Delete a cipher by ID. Uses write lock for filesystem mutation.
    pub async fn delete_cipher(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        handle.delete_cipher(cipher_id).map_err(|e| format!("{e}"))
    }

    /// List all trash cipher IDs.
    pub async fn list_trash_ids(&self) -> Result<Vec<String>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let ids = handle.list_trash_ids().map_err(|e| format!("{e}"))?;
        Ok(ids.iter().map(|id| id.to_string()).collect())
    }

    /// Restore a cipher by ID.
    pub async fn restore_cipher(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        handle.restore_cipher(cipher_id).map_err(|e| format!("{e}"))
    }

    /// Purge trash older than configurable days.
    pub async fn purge_old_trash(&self, days: u32) -> Result<usize, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        handle.purge_old_trash(days).map_err(|e| format!("{e}"))
    }

    /// Archive a cipher (hide from main list).
    pub async fn archive_cipher(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        handle.archive_cipher(cipher_id).map_err(|e| format!("{e}"))
    }

    /// Unarchive a cipher (restore to main list).
    pub async fn unarchive_cipher(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        handle
            .unarchive_cipher(cipher_id)
            .map_err(|e| format!("{e}"))
    }

    /// List archived cipher metadata.
    pub async fn list_archived_meta(&self) -> Result<Vec<baluard_core::types::CipherMeta>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        handle.list_archived_meta().map_err(|e| format!("{e}"))
    }

    /// Resolve this vault's deterministic `vault_id` as a string, for
    /// namespacing per-vault keychain entries. Prefers the loaded handle's
    /// id (available even while locked); falls back to deriving it from
    /// on-disk KDF params when the handle is not yet open.
    pub async fn vault_id_str(&self) -> Result<String, String> {
        if let Some(handle) = self.inner.read().await.as_ref() {
            return Ok(handle.vault_id.to_string());
        }
        baluard_core::vault::handle::VaultHandle::vault_id_for_path(&self.vault_path)
            .map(|u| u.to_string())
            .map_err(|e| format!("{e}"))
    }

    /// Phase 2b-2: decrypt the head pending conflict's base/local/remote
    /// versions, run `merge_ciphers`, and either auto-resolve (Merged) or
    /// return a masked conflict for the UI. Returns a JSON body shaped for
    /// the `sync.conflict` route.
    ///
    /// Cross-epoch safety (per design review): if any side's envelope is at
    /// an epoch this device's held SpaceGroupKey cannot reach, decryption
    /// fails cleanly. That is treated as "cannot merge" and the conflict is
    /// surfaced with a `cross_epoch: true` flag so the UI can explain it and
    /// offer keep_local/keep_remote (raw-blob, no decrypt) as the only safe
    /// verdicts. keep_both is refused for cross-epoch conflicts.
    pub async fn conflict_decrypt_and_merge(&self) -> Result<String, String> {
        use baluard_core::sync::conflict::{MergeResult, merge_ciphers};
        use baluard_core::sync::engine::SyncEngine;
        use baluard_core::types::CipherInput;

        // Phase 2b review fix #2: serialize against the sync cycle's cycle_lock
        // so two overlapping sync.conflict polls (10s + focus/visibility) can't
        // race finalize_conflicts' HEAD-tip guard. Held across the spawn_blocking
        // git reads + finalize, mirroring fire_sync / pull_only.
        let _cycle_guard = self.autosync.cycle_lock_guard().await;

        let pending = self
            .autosync
            .peek_pending_conflict()
            .await
            .ok_or_else(|| "no pending conflict".to_string())?;

        // Parse cipher_id from the (single, flat) conflicting file path
        // `ciphers/<uuid>.enc`.
        if pending.files.len() != 1 {
            return Err(format!(
                "multi-file conflicts not yet supported (got {}): {:?}",
                pending.files.len(),
                pending.files
            ));
        }
        let file_path = pending.files[0].clone();
        let cipher_id = file_path
            .strip_prefix("ciphers/")
            .and_then(|s| s.strip_suffix(".enc"))
            .ok_or_else(|| format!("unexpected conflict path shape: {file_path}"))?
            .parse::<uuid::Uuid>()
            .map_err(|e| format!("cipher_id parse from {file_path}: {e}"))?;

        // Phase 1 (blocking pool): git reads only — returns owned envelope
        // bytes for base/local/remote. No handle access, so no lifetime issue.
        let vault_path = self.vault_path.clone();
        let local_oid = pending.local_oid;
        let remote_oid = pending.remote_oid;
        let fp_for_read = file_path.clone();
        // C1: seal subkey for the engine's signing-key load.
        let devkey_seal = {
            let g = self.inner.read().await;
            g.as_ref().and_then(|h| h.devkey_seal())
        };
        let (base_bytes, local_bytes, remote_bytes) = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(
                #[allow(clippy::type_complexity)]
                move || -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
                    let engine =
                        SyncEngine::new(&vault_path, "conflict-merge", devkey_seal.as_ref());
                    let repo = engine.open_repo().map_err(|e| format!("open repo: {e}"))?;
                    let merge_base = repo
                        .merge_base(local_oid, remote_oid)
                        .map_err(|e| format!("merge_base: {e}"))?;
                    let base = SyncEngine::read_blob_from_commit(&repo, merge_base, &fp_for_read)
                        .map_err(|e| format!("read base: {e}"))?;
                    let local = SyncEngine::read_blob_from_commit(&repo, local_oid, &fp_for_read)
                        .map_err(|e| format!("read local: {e}"))?;
                    let remote = SyncEngine::read_blob_from_commit(&repo, remote_oid, &fp_for_read)
                        .map_err(|e| format!("read remote: {e}"))?;
                    Ok((base, local, remote))
                },
            ),
        )
        .await
        .map_err(|_| "conflict blob read timed out".to_string())?
        .map_err(|e| format!("blob read task join: {e}"))??;

        // Phase 2 (inline): decrypt + merge + re-encrypt. Holds the vault
        // handle borrow; these are fast CPU ops (a handful of AEAD/HKDF calls).
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let count = self.autosync.pending_conflict_count().await;
        let cross_epoch_ret = |which: &'static str, detail: String, count: usize| -> String {
            serde_json::json!({
                "pending": true,
                "cross_epoch": true,
                "unreachable_side": which,
                "detail": detail,
                "count": count,
            })
            .to_string()
        };

        let base_cipher = match handle.decrypt_cipher_bytes(cipher_id, &base_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(guard);
                return Ok(cross_epoch_ret("base", format!("{e}"), count));
            }
        };
        let local_cipher = match handle.decrypt_cipher_bytes(cipher_id, &local_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(guard);
                return Ok(cross_epoch_ret("local", format!("{e}"), count));
            }
        };
        let remote_cipher = match handle.decrypt_cipher_bytes(cipher_id, &remote_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(guard);
                return Ok(cross_epoch_ret("remote", format!("{e}"), count));
            }
        };

        // The vault handle knows its own device_id (canonical, from the
        // registry). Capture it for the SyncEngine commit-author context
        // before we drop the borrow. NB: this feeds device-activity tracking
        // only; commit signing key lookup iterates all devices regardless.
        let device_id = handle.device_id.to_string();
        let base_input = CipherInput::from_cipher(&base_cipher);
        let local_input = CipherInput::from_cipher(&local_cipher);
        let remote_input = CipherInput::from_cipher(&remote_cipher);
        let merge_result = merge_ciphers(&base_input, &local_input, &remote_input);

        match merge_result {
            MergeResult::Merged(merged) => {
                // Re-encrypt + finalize. Epoch = current active (design review
                // Q1: the merging device's held epoch); seq = max+1.
                let new_seq = local_cipher.update_seq.max(remote_cipher.update_seq) + 1;
                let epoch = handle.current_epoch().ok_or("vault locked mid-merge")?;
                let file = baluard_core::vault::cipher::encrypt_cipher(
                    handle.vault_id,
                    cipher_id,
                    &merged,
                    &handle.derive_item_key(cipher_id, epoch),
                    epoch,
                    new_seq,
                )
                .map_err(|e| format!("re-encrypt merged: {e}"))?;
                let resolved = vec![(file_path.clone(), file.envelope_bytes)];
                drop(guard);
                // Phase 3 (blocking pool): write merge commit + push.
                // Distinguish push-failure (merge commit landed) from real
                // failure: a SyncError::Network on push must still drain the
                // conflict or it wedges (the finalize_conflicts HEAD guard
                // would reject all later retries against the now-advanced HEAD).
                let vault_path = self.vault_path.clone();
                let pending_for_finalize = pending.clone();
                // C1: seal subkey for the finalize commit's signing key.
                let devkey_seal = {
                    let g = self.inner.read().await;
                    g.as_ref().and_then(|h| h.devkey_seal())
                };
                let push_failed = tokio::time::timeout(
                    crate::autosync::SYNC_OP_TIMEOUT,
                    tokio::task::spawn_blocking(move || -> Result<bool, String> {
                        let engine = SyncEngine::new(&vault_path, &device_id, devkey_seal.as_ref());
                        let repo = engine.open_repo().map_err(|e| format!("open repo: {e}"))?;
                        match engine.finalize_conflicts(&repo, &pending_for_finalize, &resolved) {
                            Ok(_) => Ok(false),
                            Err(e) if baluard_core::sync::engine::is_network_error(&e) => {
                                // Merge commit landed; only the push failed.
                                // The next debounce cycle pushes it. Treat as
                                // resolved so the conflict clears.
                                Ok(true)
                            }
                            Err(e) => Err(format!("finalize merged: {e}")),
                        }
                    }),
                )
                .await
                .map_err(|_| "conflict finalize timed out".to_string())?
                .map_err(|e| format!("finalize task join: {e}"))??;
                self.autosync.note_resolved().await;
                self.rebuild_cipher_index().await;
                Ok(serde_json::json!({
                    "pending": self.autosync.pending_conflict_count().await > 0,
                    "auto_merged": true,
                    "push_pending": push_failed,
                })
                .to_string())
            }
            MergeResult::Conflict(info) => {
                let masked = mask_conflict(&local_cipher, &info);
                drop(guard);
                Ok(serde_json::json!({
                    "pending": true,
                    "cross_epoch": false,
                    "count": self.autosync.pending_conflict_count().await,
                    "cipher_id": cipher_id.to_string(),
                    "name": masked.name,
                    "cipher_type": masked.cipher_type,
                    "fields": masked.fields,
                })
                .to_string())
            }
        }
    }

    /// Phase 2b: rebuild `meta/index.enc` after a conflict resolution wrote
    /// cipher files directly via SyncEngine (bypassing VaultHandle's
    /// add/update/delete hooks that normally rebuild it). Without this, a
    /// keep_both clone (new cipher_id never indexed) is invisible in
    /// vault.list until an unrelated edit triggers a rebuild. Best-effort:
    /// a rebuild failure is logged, not fatal (the index is a cache; it
    /// self-heals on the next VaultHandle mutation).
    pub async fn rebuild_cipher_index(&self) {
        let guard = self.inner.read().await;
        if let Some(handle) = guard.as_ref() {
            if let Err(e) = handle.rebuild_index() {
                log::warn!("[conflict] index rebuild failed (will self-heal): {e}");
            }
        }
    }

    /// Phase 2b-3 (keep_both verdict): the local version stays at the original
    /// path (winning raw blob) AND a fresh second cipher is written under a new
    /// UUID with the remote side's decrypted content, re-encrypted under the
    /// new cipher_id + current epoch + seq 1 (mirrors `VaultHandle::add_cipher`'s
    /// new-object path per the design review). Both files go into the
    /// `finalize_conflicts` resolved vec so a single merge commit lands both.
    ///
    /// Cross-epoch: if the remote side can't be decrypted (foreign epoch),
    /// keep_both cannot run (can't clone a side we can't read) and the conflict
    /// stays pending with a cross_epoch flag for the UI.
    pub async fn conflict_resolve_keep_both(&self) -> Result<String, String> {
        use baluard_core::sync::engine::SyncEngine;
        use baluard_core::types::CipherInput;
        use baluard_core::vault::cipher::encrypt_cipher;

        // Phase 2b review fix #2: serialize against cycle_lock (same reason as
        // conflict_decrypt_and_merge).
        let _cycle_guard = self.autosync.cycle_lock_guard().await;

        let pending = self
            .autosync
            .peek_pending_conflict()
            .await
            .ok_or_else(|| "no pending conflict to resolve".to_string())?;
        if pending.files.len() != 1 {
            return Err("keep_both supports only single-file conflicts".to_string());
        }
        let file_path = pending.files[0].clone();
        let cipher_id = file_path
            .strip_prefix("ciphers/")
            .and_then(|s| s.strip_suffix(".enc"))
            .ok_or_else(|| format!("unexpected conflict path shape: {file_path}"))?
            .parse::<uuid::Uuid>()
            .map_err(|e| format!("cipher_id parse from {file_path}: {e}"))?;

        // device_id for the SyncEngine commit-author context (2b-2 review fix).
        let device_id_str = {
            let guard = self.inner.read().await;
            guard
                .as_ref()
                .ok_or("Vault not opened".to_string())?
                .device_id
                .to_string()
        };

        // Phase 1 (blocking): read both sides' raw blobs.
        let vault_path = self.vault_path.clone();
        let local_oid = pending.local_oid;
        let remote_oid = pending.remote_oid;
        let fp_for_read = file_path.clone();
        // C1: seal subkey for the engine's signing-key load.
        let devkey_seal = {
            let g = self.inner.read().await;
            g.as_ref().and_then(|h| h.devkey_seal())
        };
        let (local_bytes, remote_bytes) = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>), String> {
                let engine =
                    SyncEngine::new(&vault_path, "conflict-keep-both", devkey_seal.as_ref());
                let repo = engine.open_repo().map_err(|e| format!("open repo: {e}"))?;
                let local = SyncEngine::read_blob_from_commit(&repo, local_oid, &fp_for_read)
                    .map_err(|e| format!("read local: {e}"))?;
                let remote = SyncEngine::read_blob_from_commit(&repo, remote_oid, &fp_for_read)
                    .map_err(|e| format!("read remote: {e}"))?;
                Ok((local, remote))
            }),
        )
        .await
        .map_err(|_| "conflict blob read timed out".to_string())?
        .map_err(|e| format!("blob read task join: {e}"))??;

        // Phase 2 (inline): decrypt remote, re-encrypt under a new UUID.
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let remote_cipher = match handle.decrypt_cipher_bytes(cipher_id, &remote_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(guard);
                return Ok(serde_json::json!({
                    "pending": true,
                    "cross_epoch": true,
                    "unreachable_side": "remote",
                    "detail": format!("{e}"),
                    "error": "keep_both needs to decrypt the remote side, which is at an unreachable epoch",
                })
                .to_string());
            }
        };
        let new_id = uuid::Uuid::new_v4();
        let epoch = handle.current_epoch().ok_or("vault locked mid-keep-both")?;
        let remote_input = CipherInput::from_cipher(&remote_cipher);
        let new_file = encrypt_cipher(
            handle.vault_id,
            new_id,
            &remote_input,
            &handle.derive_item_key(new_id, epoch),
            epoch,
            1, // new cipher: seq starts at 1, mirrors add_cipher
        )
        .map_err(|e| format!("re-encrypt clone: {e}"))?;
        let new_path = format!("ciphers/{new_id}.enc");
        // resolved = [original path with LOCAL bytes, new path with CLONE bytes]
        let resolved = vec![
            (file_path.clone(), local_bytes),
            (new_path, new_file.envelope_bytes),
        ];
        drop(guard);

        // Phase 3 (blocking): finalize (single merge commit lands both files).
        // Distinguish push-failure (merge landed) from real failure so the
        // conflict doesn't wedge against finalize_conflicts' HEAD guard.
        let vault_path = self.vault_path.clone();
        let pending_for_finalize = pending.clone();
        // C1: seal subkey for the finalize commit's signing key.
        let devkey_seal = {
            let g = self.inner.read().await;
            g.as_ref().and_then(|h| h.devkey_seal())
        };
        let push_failed = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(move || -> Result<bool, String> {
                let engine = SyncEngine::new(&vault_path, &device_id_str, devkey_seal.as_ref());
                let repo = engine.open_repo().map_err(|e| format!("open repo: {e}"))?;
                match engine.finalize_conflicts(&repo, &pending_for_finalize, &resolved) {
                    Ok(_) => Ok(false),
                    Err(e) if baluard_core::sync::engine::is_network_error(&e) => Ok(true),
                    Err(e) => Err(format!("finalize keep_both: {e}")),
                }
            }),
        )
        .await
        .map_err(|_| "conflict finalize timed out".to_string())?
        .map_err(|e| format!("finalize task join: {e}"))??;
        self.autosync.note_resolved().await;
        // The clone is a brand-new cipher_id the index has never seen; rebuild
        // so vault.list surfaces it immediately.
        self.rebuild_cipher_index().await;
        Ok(serde_json::json!({
            "resolved": true,
            "remaining": self.autosync.pending_conflict_count().await,
            "new_cipher_id": new_id.to_string(),
            "push_pending": push_failed,
        })
        .to_string())
    }

    /// Phase 2b-1 (keep_local / keep_remote verdicts): read the raw blob from
    /// the chosen side's OID and hand the bytes to `finalize_conflicts` —
    /// no decryption happens on this path (cross-epoch safe by construction).
    /// `keep_both` delegates to [`VaultState::conflict_resolve_keep_both`].
    ///
    /// Single implementation shared by the daemon's `sync.conflict.resolve`
    /// route and the mobile FFI (one implementation, two hosts, zero drift).
    pub async fn conflict_resolve_verdict(&self, verdict: &str) -> Result<String, String> {
        use baluard_core::sync::engine::SyncEngine;

        if verdict == "keep_both" {
            return self.conflict_resolve_keep_both().await;
        }

        // Serialize against cycle_lock: two overlapping resolve calls could
        // race finalize_conflicts' HEAD-tip guard (2b review fix #2).
        let _cycle_guard = self.autosync.cycle_lock_guard().await;

        let pending = self
            .autosync
            .peek_pending_conflict()
            .await
            .ok_or_else(|| "no pending conflict to resolve".to_string())?;

        let src_oid = match verdict {
            "keep_local" => pending.local_oid,
            "keep_remote" => pending.remote_oid,
            other => return Err(format!("unknown verdict: {other}")),
        };

        let vault_path = self.vault_path.clone();
        let device = registry_device_id(&vault_path);
        let pending_clone = pending.clone();
        // C1: seal subkey for the finalize commit's signing key.
        let devkey_seal = {
            let g = self.inner.read().await;
            g.as_ref().and_then(|h| h.devkey_seal())
        };
        let join_result = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(move || -> (bool, Option<String>) {
                let engine = SyncEngine::new(&vault_path, &device, devkey_seal.as_ref());
                let repo = match engine.open_repo() {
                    Ok(r) => r,
                    Err(e) => return (false, Some(format!("open repo: {e}"))),
                };
                // Read each conflicting file's bytes from the chosen side.
                let mut resolved: Vec<(String, Vec<u8>)> =
                    Vec::with_capacity(pending_clone.files.len());
                for f in &pending_clone.files {
                    let bytes = match SyncEngine::read_blob_from_commit(&repo, src_oid, f) {
                        Ok(b) => b,
                        Err(e) => return (false, Some(format!("read {f}: {e}"))),
                    };
                    resolved.push((f.clone(), bytes));
                }
                match engine.finalize_conflicts(&repo, &pending_clone, &resolved) {
                    Ok(_) => (true, None),
                    // Push network failure still leaves the merge commit
                    // written locally; treat as success for queue-draining
                    // (the coordinator retries the push on the next cycle).
                    Err(e) if baluard_core::sync::engine::is_network_error(&e) => (true, None),
                    Err(e) => (false, Some(format!("finalize: {e}"))),
                }
            }),
        )
        .await;
        let (merge_ok, err) = match join_result {
            Ok(Ok(inner)) => inner,
            Ok(Err(join_e)) => (false, Some(format!("finalize task join: {join_e}"))),
            Err(_) => (false, Some("conflict finalize timed out".to_string())),
        };
        if !merge_ok {
            return Err(err.unwrap_or_else(|| "finalize failed".to_string()));
        }

        // Drain the head. note_resolved transitions to Dirty (re-sync) when
        // the queue empties.
        self.autosync.note_resolved().await;
        // The resolution wrote cipher files via SyncEngine, bypassing
        // VaultHandle's index-rebuild hooks. Rebuild (best-effort).
        self.rebuild_cipher_index().await;

        Ok(serde_json::json!({
            "resolved": true,
            "remaining": self.autosync.pending_conflict_count().await,
        })
        .to_string())
    }

    /// Get biometric unlock status for THIS vault only.
    pub async fn biometric_status(&self) -> Result<String, String> {
        let available = baluard_core::biometric::is_available();
        let enabled = if available {
            let vault_id = self.vault_id_str().await?;
            baluard_core::biometric::is_enabled(&vault_id)
        } else {
            false
        };
        Ok(serde_json::json!({
            "available": available,
            "enabled": enabled,
            // Audit C3: false means reads have no user-presence gate
            // (Linux/Windows keyring). UIs surface the asymmetry.
            "read_gated": baluard_core::biometric::read_gated(),
        })
        .to_string())
    }

    /// Enable biometric unlock for THIS vault. Validates password against
    /// the vault first, then stores in OS keychain under this vault's id.
    pub async fn biometric_enable(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let password = req["password"].as_str().ok_or("missing password")?;

        // Verify the password can unlock the vault before storing
        // Open a temp handle, try unlock, discard
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        let vault_path = handle.path.clone();
        let vault_id = handle.vault_id.to_string();
        drop(guard);

        let mut temp = baluard_core::vault::handle::VaultHandle::open(&vault_path)
            .map_err(|e| format!("Open failed: {e}"))?;
        temp.unlock(password)
            .map_err(|_| "Incorrect master password".to_string())?;
        temp.lock();

        baluard_core::biometric::enable(&vault_id, password)?;

        Ok(serde_json::json!({
            "enabled": true,
            // Audit C3: false means the stored password is silently readable
            // by any same-UID process (no per-read gate on this platform).
            "read_gated": baluard_core::biometric::read_gated(),
        })
        .to_string())
    }

    /// Disable biometric unlock for THIS vault only.
    pub async fn biometric_disable(&self) -> Result<String, String> {
        let vault_id = self.vault_id_str().await?;
        baluard_core::biometric::disable(&vault_id)?;
        Ok(serde_json::json!({"disabled": true}).to_string())
    }

    /// Biometric unlock for THIS vault. Retrieves this vault's stored master
    /// password from the OS keychain and performs vault unlock. The secret
    /// NEVER leaves this process.
    pub async fn biometric_unlock(&self) -> Result<String, String> {
        let vault_id = self.vault_id_str().await?;
        let master_password = baluard_core::biometric::unlock(&vault_id)?;
        self.unlock(&master_password).await?;
        Ok(serde_json::json!({"success": true}).to_string())
    }

    // ── Session-bound PIN Quick Unlock ───────────────────────────────────
    //
    // In-memory KEK escrow: after the first master-password unlock the user
    // can enable a 6-digit PIN that re-unlocks for the rest of the daemon
    // session without re-running Argon2id. Nothing PIN-derivable touches
    // disk. See `pin::PinEscrow` for the full security model.

    /// Is PIN Quick Unlock enabled for this vault THIS session?
    /// Pre-unlock safe: it is an in-memory check, independent of the handle.
    pub async fn pin_status(&self) -> Result<String, String> {
        let enabled = self.pin.lock().await.is_some();
        Ok(serde_json::json!({"enabled": enabled}).to_string())
    }

    /// Enable PIN Quick Unlock. Validates the master password against the
    /// vault, derives the KEK, and stores the escrow in memory. The master
    /// password and raw PIN are never retained — only the KEK + an
    /// Argon2id verifier over the PIN.
    /// Payload: { "password": "...", "pin": "123456" }
    pub async fn pin_enable(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let password = req["password"].as_str().ok_or("missing password")?;
        let pin = req["pin"].as_str().ok_or("missing pin")?;
        crate::pin::validate_pin(pin)?;

        // Verify the master password by opening a temp handle and unlocking.
        // The KEK we derive here is the same value the daemon's VaultState
        // would use internally; we need it to seed the escrow.
        let mut temp = baluard_core::vault::handle::VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Open failed: {e}"))?;
        // Confirm the password is correct (raises clear error + advances
        // nothing persistent — temp handle is discarded).
        temp.unlock(password)
            .map_err(|_| "Incorrect master password".to_string())?;
        let kek = baluard_core::crypto::kdf::derive_kek(password, &temp.kdf_params)
            .map_err(|e| format!("derive kek: {e}"))?;

        let escrow = crate::pin::PinEscrow::new(kek, pin)?;
        *self.pin.lock().await = Some(escrow);
        self.pin_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(serde_json::json!({"enabled": true}).to_string())
    }

    /// Disable PIN Quick Unlock (clears the escrow + resets the counter).
    pub async fn pin_disable(&self) -> Result<String, String> {
        // Drop the Option, which zeroizes the KEK + PIN verifier on drop.
        *self.pin.lock().await = None;
        self.pin_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(serde_json::json!({"disabled": true}).to_string())
    }

    /// Re-unlock the vault using the PIN. Verifies the PIN against the
    /// in-memory escrow in constant time, then runs `unlock_with_kek`
    /// (skips Argon2id; still re-verifies keywrap + canaries). On the
    /// `MAX_PIN_FAILURES`-th wrong PIN the escrow is destroyed: the master
    /// password becomes mandatory and the user must re-enable the PIN.
    ///
    /// Concurrency: verify + counter-increment + nuke run under ONE hold of
    /// the escrow mutex, so no concurrent `pin_unlock` can slip a verified
    /// guess in between the verify and the cap check. The slow
    /// `unlock_with_kek` runs AFTER the lock is released, which is safe
    /// because a correct PIN returns the KEK out (the escrow stays put) and
    /// a wrong PIN never reaches it.
    pub async fn pin_unlock(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let pin = req["pin"].as_str().ok_or("missing pin")?;

        // Atomic verify-and-record under a single escrow lock hold. This is
        // the fix for the TOCTOU where a concurrent wrong-PIN attempt could
        // verify against the still-live escrow before the counter advanced /
        // the escrow was nuked. We must NOT run unlock_with_kek in here
        // (slow) — so on a correct PIN we copy the KEK out and release.
        let kek = {
            let mut guard = self.pin.lock().await;
            let Some(escrow) = guard.as_ref() else {
                return Err("PIN Quick Unlock is not enabled for this vault. \
                     Unlock with the master password and re-enable it."
                    .to_string());
            };
            match escrow.verify_or_record_failure(pin, &self.pin_failures) {
                Ok(kek) => kek,
                Err(msg) if msg == crate::pin::PIN_NUKED_SENTINEL => {
                    // Cap reached: destroy the escrow NOW, under this lock,
                    // so the next attempt sees None.
                    *guard = None;
                    return Err("Too many wrong PINs. PIN Quick Unlock has been disabled — \
                         use the master password and re-enable PIN to continue."
                        .to_string());
                }
                Err(msg) => return Err(msg),
            }
        };

        // unlock_with_kek runs the shared tail (keywrap HPKE unwrap +
        // canaries) so a corrupted/stale keywrap still fails closed.
        let mut new_handle = baluard_core::vault::handle::VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Failed to open vault for unlock: {e}"))?;
        match new_handle.unlock_with_kek(&kek) {
            Ok(()) => {
                // Success: clear the PIN failure counter, swap in the handle,
                // mint a session token — same contract as `unlock()`.
                self.pin_failures
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                let mut guard = self.inner.write().await;
                *guard = Some(new_handle);
                drop(guard);
                let mut token_guard = self.session_token.write().await;
                *token_guard = Some(generate_session_token());
                self.session_token_created.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );
                Ok(serde_json::json!({ "success": true }).to_string())
            }
            Err(e) => {
                // Correct PIN but unlock failed: the retained KEK is stale
                // (e.g. password changed on another device + synced). The
                // escrow is now useless — every future correct-PIN attempt
                // would fail the same way. Nuke it immediately so the user
                // gets a clear “re-enable PIN” signal instead of burning the
                // 5-strike budget on a PIN they remember correctly.
                *self.pin.lock().await = None;
                Err(format!(
                    "PIN unlock failed (the saved key is stale, usually because \
                     the master password changed). Re-enable PIN unlock. Underlying error: {e}"
                ))
            }
        }
    }

    /// Upload attachment to a cipher.
    /// Payload: { cipher_id, filename, data_base64 }
    pub async fn attach_upload(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let cipher_id: uuid::Uuid = req["cipher_id"]
            .as_str()
            .ok_or("missing cipher_id")?
            .parse()
            .map_err(|e| format!("invalid cipher_id: {e}"))?;
        let filename = req["filename"].as_str().ok_or("missing filename")?;
        let data_b64 = req["data_base64"].as_str().ok_or("missing data_base64")?;
        let mut plaintext = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if plaintext.len() > baluard_core::vault::attachment::MAX_ATTACHMENT_SIZE {
            return Err(format!(
                "File too large: {} bytes (max 1.9MB)",
                plaintext.len()
            ));
        }

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        // Get cipher to find its item key and existing attachments
        let cipher = match handle.get_cipher(cipher_id) {
            Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) => *c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Derive item key
        let item_key = handle.derive_item_key(cipher_id, cipher.key_epoch);

        // Generate attachment ID
        let attach_id = uuid::Uuid::new_v4().to_string();
        let attach_uuid: uuid::Uuid = attach_id
            .parse()
            .map_err(|e| format!("generated id not a uuid: {e}"))?;

        // Encrypt (audit C4: tier-padded + AAD-bound to vault/cipher/attachment)
        let encrypted = baluard_core::vault::attachment::encrypt_attachment(
            handle.vault_id,
            cipher_id,
            attach_uuid,
            item_key.as_bytes(),
            &plaintext,
            cipher.key_epoch,
            cipher.update_seq,
        )
        .map_err(|e| format!("{e}"))?;

        // M8 fix: capture size before zeroize
        let plaintext_size = plaintext.len() as u64;
        let encrypted_size = encrypted.len() as u64;

        // Zeroize plaintext after encryption
        plaintext.zeroize();

        // Create attachment directory
        let attach_dir = handle
            .path
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments");
        std::fs::create_dir_all(&attach_dir).map_err(|e| format!("mkdir: {e}"))?;

        // Write encrypted file (owner-only from the first byte; audit C17)
        let attach_path = attach_dir.join(format!("{}.enc", attach_id));
        baluard_core::secret_file::write_secret_file(&attach_path, &encrypted)
            .map_err(|e| format!("write: {e}"))?;

        // Update cipher metadata with new attachment
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let meta = baluard_core::vault::attachment::AttachmentMeta {
            id: attach_id.clone(),
            filename: filename.to_string(),
            size: plaintext_size,
            encrypted_size,
            mime_type: baluard_core::vault::attachment::detect_mime(filename),
            created_at: now,
        };

        let mut attachments = cipher.attachments.clone();
        attachments.push(meta);

        // Update cipher with new attachments list
        let input = baluard_core::types::CipherInput {
            name: cipher.name.clone(),
            folder_id: cipher.folder_id,
            kind: cipher.kind.clone(),
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            notes: cipher.notes.clone(),
            custom_fields: cipher.custom_fields.clone(),
            created_at: Some(cipher.created_at),
            password_history: cipher.password_history.clone(),
            attachments,
            archived: cipher.archived,
            tags: cipher.tags.clone(),
        };
        handle.update_cipher(cipher_id, &input).map_err(|e| {
            // Clean up orphaned encrypted file on update failure
            let _ = std::fs::remove_file(&attach_path);
            format!("{e}")
        })?;

        Ok(serde_json::json!({"id": attach_id, "filename": filename}).to_string())
    }

    /// Download attachment from a cipher.
    /// Payload: { cipher_id, attachment_id }
    pub async fn attach_download(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let cipher_id: uuid::Uuid = req["cipher_id"]
            .as_str()
            .ok_or("missing cipher_id")?
            .parse()
            .map_err(|e| format!("invalid cipher_id: {e}"))?;
        let attach_id = req["attachment_id"]
            .as_str()
            .ok_or("missing attachment_id")?;

        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let cipher = match handle.get_cipher(cipher_id) {
            Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) => *c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Verify attachment exists in metadata
        let meta = cipher
            .attachments
            .iter()
            .find(|a| a.id == attach_id)
            .ok_or("Attachment not found")?;

        let item_key = handle.derive_item_key(cipher_id, cipher.key_epoch);

        let attach_path = handle
            .path
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments")
            .join(format!("{}.enc", attach_id));

        let encrypted = std::fs::read(&attach_path).map_err(|e| format!("read: {e}"))?;
        let attach_uuid: uuid::Uuid = attach_id
            .parse()
            .map_err(|e| format!("invalid attachment_id: {e}"))?;
        let mut plaintext = baluard_core::vault::attachment::decrypt_attachment(
            handle.vault_id,
            cipher_id,
            attach_uuid,
            item_key.as_bytes(),
            &encrypted,
        )
        .map_err(|e| format!("{e}"))?;

        let result = serde_json::json!({
            "filename": meta.filename,
            "mime_type": meta.mime_type,
            "size": meta.size,
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&plaintext),
        })
        .to_string();

        // Zeroize plaintext after encoding
        plaintext.zeroize();

        Ok(result)
    }

    /// Delete attachment from a cipher.
    /// Payload: { cipher_id, attachment_id }
    pub async fn attach_delete(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let cipher_id: uuid::Uuid = req["cipher_id"]
            .as_str()
            .ok_or("missing cipher_id")?
            .parse()
            .map_err(|e| format!("invalid cipher_id: {e}"))?;
        let attach_id = req["attachment_id"]
            .as_str()
            .ok_or("missing attachment_id")?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let cipher = match handle.get_cipher(cipher_id) {
            Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) => *c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Remove from attachments list
        let mut attachments = cipher.attachments.clone();
        let idx = attachments
            .iter()
            .position(|a| a.id == attach_id)
            .ok_or("Attachment not found")?;
        attachments.remove(idx);

        // Delete encrypted file
        let attach_path = handle
            .path
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments")
            .join(format!("{}.enc", attach_id));
        if attach_path.exists() {
            std::fs::remove_file(&attach_path).map_err(|e| format!("delete: {e}"))?;
        }

        // Update cipher
        let input = baluard_core::types::CipherInput {
            name: cipher.name.clone(),
            folder_id: cipher.folder_id,
            kind: cipher.kind.clone(),
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            notes: cipher.notes.clone(),
            custom_fields: cipher.custom_fields.clone(),
            created_at: Some(cipher.created_at),
            password_history: cipher.password_history.clone(),
            attachments,
            archived: cipher.archived,
            tags: cipher.tags.clone(),
        };
        handle
            .update_cipher(cipher_id, &input)
            .map_err(|e| format!("{e}"))?;

        Ok(serde_json::json!({"deleted": true}).to_string())
    }

    /// Get password health report.
    pub async fn health_report(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let metas = handle.list_cipher_meta_full().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) => ciphers.push(*c),
                _ => continue,
            }
        }

        let report = baluard_core::health::analyze(&ciphers);
        serde_json::to_string(&report).map_err(|e| format!("{e}"))
    }

    /// Return device fleet activity data.
    /// Reads encrypted activity.enc and cross-references with the device registry.
    pub async fn device_activity(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let index = handle.load_activity_enc().map_err(|e| format!("{e}"))?;
        let registry = handle.device_manager.registry();

        let mut devices = Vec::new();
        for (uuid_str, entry) in &index.devices {
            let uuid: uuid::Uuid = match uuid_str.parse() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let name = registry
                .devices
                .get(&uuid)
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "Unknown".into());
            devices.push(serde_json::json!({
                "id": uuid_str,
                "name": name,
                "last_push": entry.last_push,
                "last_commit": entry.last_commit,
                "epoch": entry.epoch,
            }));
        }

        serde_json::to_string(&serde_json::json!({ "devices": devices, "self_device_id": handle.device_id.to_string() }))
            .map_err(|e| format!("{e}"))
    }

    /// Revoke a device by UUID. Removes it from the registry and rotates keys.
    /// Only works for the current (self) device initiating the revoke.
    pub async fn device_revoke(&self, device_id_str: &str) -> Result<String, String> {
        let device_id: uuid::Uuid = device_id_str.parse().map_err(|_| "Invalid UUID")?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        if device_id == handle.device_id {
            return Err("Cannot revoke the current device".into());
        }

        if !handle.registry.devices.contains_key(&device_id) {
            return Err(format!("Device {device_id} not found in registry"));
        }

        // Revoke + rekey: rotates root key, re-encrypts ciphers, writes keywrap
        let result = handle
            .revoke_device_and_rekey(device_id)
            .map_err(|e| format!("Revocation failed: {e}"))?;

        // Clean activity index
        if let Err(e) = baluard_core::device_manager::DeviceActivityIndex::remove_device(
            &self.vault_path,
            &device_id,
        ) {
            log::warn!("failed to clean activity index: {e}");
        }

        let json = serde_json::json!({
            "revoked_device": result.revoked_device_id.to_string(),
            "revoked_name": result.revoked_name,
            "new_epoch": result.new_epoch,
        });
        Ok(json.to_string())
    }

    /// Verify master password for reprompt. Opens a temporary handle and attempts unlock.
    /// Returns a short-lived grant. Does NOT change the main vault state.
    pub async fn reprompt_verify(&self, master_password: &str) -> Result<String, String> {
        // Open a temporary handle
        let mut temp_handle =
            VaultHandle::open(&self.vault_path).map_err(|e| format!("Open failed: {e}"))?;

        // Try to unlock with the provided password
        temp_handle
            .unlock(master_password)
            .map_err(|_| "Incorrect master password".to_string())?;

        // Password verified. The grant is time-window only: `expires_at` is
        // all the client needs. No grant_token is minted — a returned token
        // would be a bearer capability for other same-UID processes (audit
        // C12), and no consumer ever validated it anyway.
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 30; // 30 second grant

        // Lock the temporary handle (zeroize keys)
        temp_handle.lock();

        Ok(serde_json::json!({
            "granted": true,
            "expires_at": expires_at,
        })
        .to_string())
    }

    /// Get vault info (ID, device, state).
    pub async fn info(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let cipher_count = handle.list_cipher_ids().map(|ids| ids.len()).unwrap_or(0);

        let json = serde_json::json!({
            "vault_id": handle.vault_id.to_string(),
            "device_id": handle.device_id.to_string(),
            "unlocked": handle.is_unlocked(),
            "cipher_count": cipher_count,
        });
        Ok(json.to_string())
    }

    /// List enrolled devices.
    pub async fn devices(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        // C5: names come from the encrypted settings map (fold-and-strip
        // migration on unlock); the registry file is the pre-migration
        // fallback for entries not yet folded.
        let names = handle.device_display_names();
        let devices: Vec<serde_json::Value> = handle.registry.devices.values().map(|entry| {
            let name = names
                .get(&entry.device_id.to_string())
                .cloned()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| entry.name.clone());
            serde_json::json!({
                "name": name,
                "device_id": entry.device_id,
                "encryption_key": format!("{}...{}",
                    entry.encryption_public_key.get(..8).unwrap_or(&entry.encryption_public_key),
                    entry.encryption_public_key.get(56..).unwrap_or("")),
                "signing_key": format!("{}...{}",
                    entry.signing_public_key.get(..8).unwrap_or(&entry.signing_public_key),
                    entry.signing_public_key.get(56..).unwrap_or("")),
                "enrolled_at": entry.enrolled_at,
            })
        }).collect();

        let json = serde_json::json!({
            "devices": devices,
            "total": handle.registry.count(),
        });
        Ok(json.to_string())
    }

    /// Enroll this device into an existing vault using the recovery phrase.
    /// Non-destructive: existing devices remain in the registry.
    /// Requires the vault's `enrollment_policy` to be `Personal`.
    pub async fn enroll_with_recovery_phrase(&self, phrase: &str) -> Result<String, String> {
        use baluard_core::device_manager::{DeviceManager, EnrollmentPayload};
        use rand::RngCore;

        // Validate phrase shape
        let word_count = phrase.split_whitespace().count();
        if word_count != 24 {
            return Err(format!(
                "recovery phrase must be 24 words, got {word_count}"
            ));
        }

        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let vault_path = handle.path.clone();

        // PR-3 fix: load policy and pass to the core method. The method
        // enforces Strict rejection itself; no pre-check here (would be
        // redundant and TOCTOU-prone). Read failures are fail-closed:
        // we read settings ONCE and pass the loaded value.
        let settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        let policy = settings.enrollment_policy;
        let _ = handle;

        // Build EnrollmentPayload for this device
        let (x25519_secret, x25519_public) =
            baluard_core::crypto::hpke_wrap::generate_x25519_keypair();
        let (ed25519_signing, ed25519_verifying) =
            baluard_core::crypto::signature::generate_ed25519_keypair();

        let mut nonce_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

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
            name: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "Daemon Device".to_string()),
            vault_id: None,
            epoch: None,
            registry_version: None,
        };

        // Open DeviceManager and call enroll_with_recovery_phrase.
        // Peer review fix: pass the caller's private keys (owned) — whose
        // public halves are in the payload. The method enrolls those public
        // keys, encrypts the keywrap to the X25519 public key, and returns
        // the private keys for the caller to persist.
        let mut dm = DeviceManager::load_from_vault(&vault_path)
            .map_err(|e| format!("load device manager: {e}"))?;
        let result = dm
            .enroll_with_recovery_phrase(&payload, phrase, x25519_secret, ed25519_signing, policy)
            .map_err(|e| format!("enroll: {e}"))?;

        // Persist device-privkey for this device using the keys RETURNED
        // by the method (same keys the registry and keywrap were built
        // with — guarantees consistency).
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode(result.x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(result.ed25519_signing.to_bytes()),
        });
        let privkey_path = vault_path.join("meta/device-privkey.json");
        let privkey_tmp = privkey_path.with_extension("json.tmp");
        std::fs::write(
            &privkey_tmp,
            serde_json::to_string_pretty(&privkey_data).map_err(|e| format!("{e}"))?,
        )
        .map_err(|e| format!("write privkey: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&privkey_tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&privkey_tmp, &privkey_path).map_err(|e| format!("rename privkey: {e}"))?;

        // F3 fix: update self.inner under write lock so in-process state holds the new device_id
        {
            let mut guard = self.inner.write().await;
            if let Some(handle) = guard.as_mut() {
                handle.device_id = result.device_id;
                handle.device_manager = dm;
                if let Ok(data) = std::fs::read_to_string(vault_path.join("meta/devices.json")) {
                    if let Ok(reg) = serde_json::from_str(&data) {
                        handle.registry = reg;
                    }
                }
            }
        }

        let json = serde_json::json!({
            "device_id": result.device_id.to_string(),
            "name": result.entry.name,
            "enrollment_policy": "personal",
            "non_destructive": true,
        });
        Ok(json.to_string())
    }

    /// Create a new vault at the configured vault_path.
    /// Input JSON: {"password": "...", "profile": "desktop_std"}
    /// Returns JSON with vault_id, device_id, recovery_phrase.
    pub async fn create_vault(&self, payload_json: &str) -> Result<String, String> {
        // Guard: refuse to overwrite an existing vault
        if self.vault_path.join("meta/kdf-params.json").exists() {
            return Err(
                "Vault already exists at this path. Delete it first if you want to recreate."
                    .into(),
            );
        }

        let v: serde_json::Value =
            serde_json::from_str(payload_json).map_err(|e| format!("Invalid JSON: {e}"))?;
        // Extract password into zeroizing wrapper
        let password = v["password"]
            .as_str()
            .ok_or("Missing 'password' field")?
            .to_string();
        let mut password = zeroize::Zeroizing::new(password);

        let profile_str = v["profile"].as_str().unwrap_or("desktop_std");
        // Optional user-facing vault name (displayed in the switcher / login).\n        // Falls back to the slug downstream when absent.
        let vault_name = v["name"].as_str().map(|s| s.to_string());
        let profile = match profile_str {
            "mobile_low" => baluard_core::types::KdfProfile::MobileLow,
            "desktop_std" => baluard_core::types::KdfProfile::DesktopStd,
            "desktop_high" => baluard_core::types::KdfProfile::DesktopHigh,
            _ => {
                return Err(format!(
                    "Unknown profile: {profile_str}. Use mobile_low, desktop_std, or desktop_high"
                ));
            }
        };

        // Run creation ceremony (CPU-heavy, no lock needed)
        // Pass the slug from the payload so the .baluard marker is written
        // at creation (marker write is gated on slug being set; without it
        // the vault is created but undetectable by discover_orphans / detach).
        let slug_for_marker = v
            .get("slug")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let (handle, secrets) = baluard_core::vault::creation::VaultCreator::new(
            &self.vault_path,
            &password,
            "this-device",
        )
        .slug(slug_for_marker)
        .kdf_profile(profile)
        .profile(vault_name.clone(), None)
        .execute()
        .map_err(|e| format!("Vault creation failed: {e}"))?;

        // Zeroize password as soon as ceremony completes
        zeroize::Zeroize::zeroize(&mut *password);

        let mut guard = self.inner.write().await;
        *guard = Some(handle);

        // R7-2: Generate session token for newly created vault
        let token = generate_session_token();
        let mut token_guard = self.session_token.write().await;
        *token_guard = Some(token.clone());
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        let response = serde_json::json!({
            "vault_id": secrets.vault_id.to_string(),
            "device_id": secrets.device_id.to_string(),
            "recovery_phrase": secrets.recovery_phrase.phrase(),
            "trust_fingerprint": hex::encode(secrets.trust_fingerprint),
            "session_token": token,
            "vault_name": vault_name,
        });
        Ok(response.to_string())
    }

    // ── R7-2: Session token management ──

    /// Verify a client-provided session token against the stored one.
    /// Uses constant-time comparison to prevent timing side channels.
    /// H6 fix: rejects expired tokens (default 4-hour TTL).
    pub async fn verify_session_token(&self, provided: &str) -> Result<(), String> {
        // H6: Check token expiry before comparison
        const SESSION_TOKEN_TTL_SECONDS: u64 = 4 * 3600; // 4 hours
        let created = self.session_token_created.load(Ordering::Relaxed);
        if created > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now.saturating_sub(created) > SESSION_TOKEN_TTL_SECONDS {
                // Expired: clear token and reject
                *self.session_token.write().await = None;
                self.session_token_created.store(0, Ordering::Relaxed);
                return Err("Session token expired. Re-unlock the vault.".into());
            }
        }

        let guard = self.session_token.read().await;
        match *guard {
            Some(ref stored)
                if crate::crypto::constant_time_eq(provided.as_bytes(), stored.as_bytes()) =>
            {
                Ok(())
            }
            Some(_) => Err("Invalid session token. Re-unlock the vault.".into()),
            None => Err("Vault is locked. Unlock first.".into()),
        }
    }

    /// Get the current session token (for embedding in unlock/create responses).
    pub async fn get_session_token(&self) -> Option<String> {
        self.session_token.read().await.clone()
    }
}

/// Shared vault state type.
pub type SharedVaultState = Arc<VaultState>;

/// Serialize a decrypted cipher to JSON, matching the format returned by `get_cipher`.
fn cipher_to_json(c: &baluard_core::types::Cipher) -> serde_json::Value {
    let mut json = serde_json::json!({
        "id": c.id.to_string(),
        "name": c.name,
        "type": serde_json::to_value(c.kind.cipher_type()).unwrap_or(serde_json::Value::Null),
        "favorite": c.favorite,
        "reprompt": c.reprompt,
        "notes": c.notes,
        "tier": format!("{:?}", c.tier),
        "epoch": c.key_epoch,
        "seq": c.update_seq,
        "folder_id": c.folder_id,
        "tags": c.tags,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
        "password_history": c.password_history,
        "attachments": c.attachments,
        "custom_fields": c.custom_fields,
    });
    json["kind"] = serde_json::to_value(&c.kind).unwrap_or(serde_json::Value::Null);
    match &c.kind {
        baluard_core::types::CipherKind::Login(data) => {
            json["username"] = serde_json::json!(data.username);
            json["password"] = serde_json::json!(data.password);
            json["uris"] = serde_json::json!(data.uris);
            json["totp"] = serde_json::json!(data.totp_uri);
            if let Some(ref fav) = data.favicon {
                json["favicon"] = serde_json::to_value(fav).unwrap_or(serde_json::Value::Null);
            }
            if let Some(ref fido2_list) = data.fido2_credentials {
                if !fido2_list.is_empty() {
                    json["fido2_credentials"] = serde_json::json!(
                        fido2_list
                            .iter()
                            .map(|pk| serde_json::json!({
                                "credential_id": pk.credential_id,
                                "rp_id": pk.rp_id,
                                "rp_name": pk.rp_name,
                                "user_name": pk.user_name,
                                "name": pk.name,
                                "counter": pk.counter,
                                "creation_date": pk.creation_date,
                                "private_key_missing": pk.private_key_missing,
                            }))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        baluard_core::types::CipherKind::Card(data) => {
            json["cardholder_name"] = serde_json::json!(data.cardholder_name);
            json["brand"] = serde_json::json!(data.brand);
            json["number"] = serde_json::json!(data.number);
            json["exp_month"] = serde_json::json!(data.exp_month);
            json["exp_year"] = serde_json::json!(data.exp_year);
            json["code"] = serde_json::json!(data.code);
        }
        baluard_core::types::CipherKind::Identity(data) => {
            json["title"] = serde_json::json!(data.title);
            json["first_name"] = serde_json::json!(data.first_name);
            json["middle_name"] = serde_json::json!(data.middle_name);
            json["last_name"] = serde_json::json!(data.last_name);
            json["username"] = serde_json::json!(data.username);
            json["company"] = serde_json::json!(data.company);
            json["email"] = serde_json::json!(data.email);
            json["phone"] = serde_json::json!(data.phone);
            json["address1"] = serde_json::json!(data.address1);
            json["address2"] = serde_json::json!(data.address2);
            json["address3"] = serde_json::json!(data.address3);
            json["city"] = serde_json::json!(data.city);
            json["state"] = serde_json::json!(data.state);
            json["postal_code"] = serde_json::json!(data.postal_code);
            json["country"] = serde_json::json!(data.country);
            json["ssn"] = serde_json::json!(data.ssn);
            json["passport_number"] = serde_json::json!(data.passport_number);
            json["license_number"] = serde_json::json!(data.license_number);
        }
        baluard_core::types::CipherKind::SshKey(data) => {
            json["public_key"] = serde_json::json!(data.public_key);
            json["private_key"] = serde_json::json!(data.private_key);
            json["fingerprint"] = serde_json::json!(data.key_fingerprint);
        }
        baluard_core::types::CipherKind::BankAccount(data) => {
            json["bank_name"] = serde_json::json!(data.bank_name);
            json["name_on_account"] = serde_json::json!(data.name_on_account);
            json["account_type"] = serde_json::json!(data.account_type);
            json["account_number"] = serde_json::json!(data.account_number);
            json["routing_number"] = serde_json::json!(data.routing_number);
            json["branch_number"] = serde_json::json!(data.branch_number);
            json["pin"] = serde_json::json!(data.pin);
            json["swift_code"] = serde_json::json!(data.swift_code);
            json["iban"] = serde_json::json!(data.iban);
            json["bank_contact_phone"] = serde_json::json!(data.bank_contact_phone);
        }
        baluard_core::types::CipherKind::DriversLicense(data) => {
            json["first_name"] = serde_json::json!(data.first_name);
            json["middle_name"] = serde_json::json!(data.middle_name);
            json["last_name"] = serde_json::json!(data.last_name);
            json["date_of_birth"] = serde_json::json!(data.date_of_birth);
            json["license_number"] = serde_json::json!(data.license_number);
            json["issuing_country"] = serde_json::json!(data.issuing_country);
            json["issuing_state"] = serde_json::json!(data.issuing_state);
            json["issue_date"] = serde_json::json!(data.issue_date);
            json["expiration_date"] = serde_json::json!(data.expiration_date);
            json["issuing_authority"] = serde_json::json!(data.issuing_authority);
            json["license_class"] = serde_json::json!(data.license_class);
        }
        baluard_core::types::CipherKind::Passport(data) => {
            json["surname"] = serde_json::json!(data.surname);
            json["given_name"] = serde_json::json!(data.given_name);
            json["date_of_birth"] = serde_json::json!(data.date_of_birth);
            json["sex"] = serde_json::json!(data.sex);
            json["birth_place"] = serde_json::json!(data.birth_place);
            json["nationality"] = serde_json::json!(data.nationality);
            json["issuing_country"] = serde_json::json!(data.issuing_country);
            json["passport_number"] = serde_json::json!(data.passport_number);
            json["passport_type"] = serde_json::json!(data.passport_type);
            json["national_identification_number"] =
                serde_json::json!(data.national_identification_number);
            json["issuing_authority"] = serde_json::json!(data.issuing_authority);
            json["issue_date"] = serde_json::json!(data.issue_date);
            json["expiration_date"] = serde_json::json!(data.expiration_date);
        }
        baluard_core::types::CipherKind::SecureNote => {}
    }
    json
}

/// R7-2: Generate a cryptographically random session token (32 bytes hex = 64 chars).
fn generate_session_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Commit-label identity for sync writes that may run while the handle is
/// absent (conflict verdicts): first device id from the on-disk registry.
/// C5: identity is the device UUID — display names are stripped from the
/// git-tracked devices.json and live encrypted in settings.enc.
fn registry_device_id(vault_path: &std::path::Path) -> String {
    let reg_path = vault_path.join("meta/devices.json");
    if let Ok(data) = std::fs::read_to_string(&reg_path) {
        if let Ok(reg) = serde_json::from_str::<baluard_core::devices::DeviceRegistry>(&data) {
            if let Some((id, _)) = reg.devices.iter().next() {
                return id.to_string();
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod favicon_tests {
    use super::VaultState;

    /// Audit C20: a domain containing '&' must not inject extra query
    /// parameters into the favicon-service URL.
    #[test]
    fn favicon_url_escapes_ampersand_domain() {
        let url = VaultState::favicon_url("evil.com&sz=64");
        let parsed = url::Url::parse(&url).expect("built URL parses");
        let mut pairs = parsed.query_pairs();
        assert_eq!(
            pairs.next(),
            Some(("domain".into(), "evil.com&sz=64".into()))
        );
        assert_eq!(pairs.next(), Some(("sz".into(), "32".into())));
        assert_eq!(pairs.next(), None);
    }

    #[test]
    fn favicon_url_plain_domain_unescaped_happy_path() {
        let url = VaultState::favicon_url("example.com");
        assert_eq!(
            url,
            "https://www.google.com/s2/favicons?domain=example.com&sz=32"
        );
    }
}
