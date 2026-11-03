//! Vault state management for the daemon.
//!
//! Holds an unlocked VaultHandle in memory behind a shared lock.
//! The daemon routes gateway actions through this state.

use baluard_core::crypto::webauthn::CeremonyState;
use baluard_core::vault::handle::{CipherRead, VaultHandle};
use base64::Engine;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

/// UI-facing masked conflict. NO secret values; field labels + a sensitive
/// flag only. Mirrors `PendingConflict` in the frontend contract
/// (`docs/adr/0093-conflict-resolution-panel.md`).
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
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "totp_uri",
        "code",
        "number",
        "private_key",
        "passphrase",
    ];
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
    /// P1c: Lock generation counter. Bumped on every `lock()`; the session
    /// token is only valid while its mint-time generation matches. Even if
    /// a future lock path forgets to clear the token, a stale token dies
    /// here (defense in depth for the lock chokepoint cascade).
    session_generation: AtomicU64,
    /// D80: peer-bound agent grants; invalidated through the same lock
    /// generation so explicit/auto lock needs no extra grant scan.
    agent_grants: crate::agents::AgentGrants,
    /// P1c: Generation at which the current token was minted (0 = none).
    session_token_generation: AtomicU64,
    /// Last activity timestamp (seconds since epoch). Updated on every IPC request.
    last_activity: AtomicU64,
    /// Cover commit scheduler handle. Cancelled on lock.
    cover_timer: RwLock<Option<tokio::task::JoinHandle<()>>>,
    /// M1: serializes device-file read-modify-write cycles (enable /
    /// disable / consent / password change). Two racing ops can
    /// interleave the seal and keywrap halves and strand the vault.
    devkey_ops: tokio::sync::Mutex<()>,
    /// Whether a post-mutation cover commit is already pending.
    /// Prevents spawning multiple cover tasks from rapid sequential edits.
    cover_pending: std::sync::atomic::AtomicBool,
    /// Legacy Contact view session: unlocked from a kit, read-only by
    /// daemon allowlist. Never true for owner sessions.
    contact_view: std::sync::atomic::AtomicBool,
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

/// Why a quick-unlock primitive failed. The daemon rate limiter charges
/// only credential guesses: a wrong PIN or unusable request is a Guess,
/// while a failure AFTER the credential proved itself (hardware-seal
/// outcome, stale key material, operational error) is budget-neutral.
#[derive(Debug)]
pub enum QuickUnlockError {
    Guess(String),
    Proven(String),
}

impl QuickUnlockError {
    pub fn message(&self) -> &str {
        match self {
            QuickUnlockError::Guess(m) | QuickUnlockError::Proven(m) => m,
        }
    }
}

impl std::fmt::Display for QuickUnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl Drop for VaultState {
    fn drop(&mut self) {
        // The runtime state owns the session lifecycle; temporary core
        // handles (reprompt, migration) must not clear another session's
        // cache when they drop.
        baluard_core::vault::handle::clear_cached_device_signing_keys_for_vault(&self.vault_path);
    }
}

impl VaultState {
    /// Create a new empty state pointing at a vault directory.
    pub fn new(vault_path: PathBuf) -> Self {
        Self::with_contact_view(vault_path, false)
    }

    /// Legacy Contact view constructor: the session is read-only by
    /// daemon allowlist from birth.
    pub fn with_contact_view(vault_path: PathBuf, contact_view: bool) -> Self {
        let autosync = crate::autosync::AutoSyncHandle::new(&vault_path);
        Self {
            vault_path,
            inner: RwLock::new(None),
            session_token: RwLock::new(None),
            session_token_created: AtomicU64::new(0),
            session_generation: AtomicU64::new(0),
            session_token_generation: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            cover_timer: RwLock::new(None),
            cover_pending: std::sync::atomic::AtomicBool::new(false),
            contact_view: std::sync::atomic::AtomicBool::new(contact_view),
            cover_session: AtomicU64::new(0),
            ceremony_cache: baluard_core::crypto::webauthn::CeremonyCache::new(),
            pin: tokio::sync::Mutex::new(None),
            devkey_ops: tokio::sync::Mutex::new(()),
            pin_failures: std::sync::atomic::AtomicU32::new(0),
            agent_grants: crate::agents::AgentGrants::new(),
            autosync,
        }
    }

    /// D80: current lock generation for agent-grant minting.
    fn agent_generation(&self) -> u64 {
        self.session_generation.load(Ordering::Relaxed)
    }

    /// D80: mint an agent grant after a human approval. The daemon never
    /// returns the token again; only its digest is retained.
    pub fn agent_mint(
        &self,
        peer: crate::agents::PeerBinding,
        item_ids: Vec<String>,
        ttl_secs: u64,
    ) -> String {
        self.agent_grants
            .mint(peer, item_ids, ttl_secs, self.agent_generation())
    }

    /// D80: verify an agent token against this vault's live grants. Agent
    /// traffic never feeds `touch_activity`, so polling cannot hold off
    /// auto-lock.
    pub fn verify_agent_token(
        &self,
        token: &str,
    ) -> Result<crate::agents::AgentVerdict, baluard_core::error::BaluardError> {
        self.agent_grants.verify(token, self.agent_generation())
    }

    pub fn agent_live_peers(&self) -> Vec<crate::agents::PeerBinding> {
        self.agent_grants.live_peers(self.agent_generation())
    }

    pub fn agent_live_grants(&self) -> Vec<crate::agents::AgentGrantView> {
        self.agent_grants.live_grant_views(self.agent_generation())
    }

    /// D80 blur-lock exemption: vaults.on_app_blur skips vaults with live
    /// grants; explicit lock and auto-lock never consult this.
    pub fn has_live_agent_grants(&self) -> bool {
        self.agent_grants.has_live_grants(self.agent_generation())
    }

    pub fn revoke_agent_grants(&self) {
        self.agent_grants.revoke_all();
    }

    pub fn revoke_agent_token(&self, token: &str) -> bool {
        self.agent_grants
            .revoke_token(token, self.agent_generation())
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
    /// Activate autosync after a remote is attached post-unlock (the mobile
    /// git-backup path). The unlock-time activation only fires when a remote
    /// already exists, so a vault that gains its remote later — the common
    /// onboarding order: create, then wire the backup — would otherwise leave
    /// autosync inactive and every later debounced nudge would silently
    /// no-op at the !active guard, stranding local-only artifacts (pending
    /// invites, purpose writes) until the next unlock.
    pub async fn activate_autosync_after_remote(&self) {
        if self.autosync.is_active().await {
            return;
        }
        let device_id = self
            .inner
            .read()
            .await
            .as_ref()
            .map(|h| h.device_id.to_string())
            .unwrap_or_default();
        if device_id.is_empty() {
            return;
        }
        let devkey_seal = self.devkey_seal().await;
        let enroll_vk = {
            let guard = self.inner.read().await;
            guard.as_ref().and_then(|h| h.enroll_verify_key())
        };
        let has_remote = baluard_core::sync::engine::SyncEngine::new(
            &self.vault_path,
            &device_id,
            devkey_seal.as_ref(),
        )
        .open_repo()
        .and_then(|repo| baluard_core::sync::engine::SyncEngine::has_remote(&repo))
        .unwrap_or(false);
        if has_remote && std::env::var("BALUARD_AUTOSYNC").ok().as_deref() != Some("0") {
            self.autosync
                .activate(device_id, devkey_seal, enroll_vk)
                .await;
        }
    }

    pub async fn devkey_seal(&self) -> Option<[u8; 32]> {
        let g = self.inner.read().await;
        g.as_ref().and_then(|h| h.devkey_seal())
    }

    /// Enrollment-proof verifier from the unlocked handle; `None` while
    /// locked. Threads root-keyed proof verification into sync paths the
    /// same way devkey_seal threads commit signing.
    pub async fn enroll_verify_key(&self) -> Option<baluard_core::sync::engine::EnrollVerifyKey> {
        let g = self.inner.read().await;
        g.as_ref().and_then(|h| h.enroll_verify_key())
    }

    /// Unlock the vault with the master password.
    ///
    /// KDF derivation (Argon2id) runs OUTSIDE the write lock to avoid
    /// blocking all reads during the expensive derivation (~300ms-1s).
    /// Opens the vault once, unlocks it, then swaps it in.
    pub async fn unlock(
        self: &Arc<Self>,
        master_password: &str,
    ) -> Result<(), baluard_core::error::BaluardError> {
        // Quick check: already unlocked?
        {
            let guard = self.inner.read().await;
            if let Some(ref handle) = *guard {
                if handle.is_unlocked() {
                    drop(guard);
                    // A session token is a bearer capability: minting or
                    // acknowledging one demands the master password, the
                    // same canary oracle a locked unlock pays first. The
                    // short-circuit skips the tail, never the proof.
                    self.verify_master_password(master_password)
                        .await
                        .map_err(|e| {
                            if e == "master password incorrect" {
                                baluard_core::error::BaluardError::from(
                                    baluard_core::error::VaultError::PasswordMismatch,
                                )
                            } else {
                                baluard_core::error::BaluardError::from(
                                    baluard_core::error::VaultError::Metadata(e),
                                )
                            }
                        })?;
                    if self.get_session_token().await.is_none() {
                        return self.finish_unlock_already_open().await;
                    }
                    return Ok(());
                }
            }
        }

        // Open a fresh handle and derive the KEK on a blocking thread:
        // Argon2id pins a worker for ~1s and 64-256MB otherwise.
        let vault_path = self.vault_path.clone();
        let password = Zeroizing::new(master_password.to_string());
        let new_handle = tokio::task::spawn_blocking(
            move || -> Result<VaultHandle, baluard_core::error::BaluardError> {
                let mut h = VaultHandle::open(&vault_path)?;
                h.unlock(&password)?;
                Ok(h)
            },
        )
        .await
        .map_err(|e| {
            baluard_core::error::BaluardError::from(baluard_core::error::VaultError::Metadata(
                format!("unlock task: {e}"),
            ))
        })??;

        self.finish_unlock(new_handle).await
    }

    /// Session-only unlock landing: swap in the handle and mint the
    /// session token. The Android :autofill process lands here — the
    /// sync tail would run git writes in the memory-capped process
    /// concurrently with the main app's coordinator (per-process
    /// cycle_lock does not protect across processes).
    async fn finish_unlock_session(
        &self,
        new_handle: baluard_core::vault::handle::VaultHandle,
    ) -> Result<(), baluard_core::error::BaluardError> {
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
        self.session_token_generation.store(
            self.session_generation.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        drop(token_guard);

        Ok(())
    }

    /// Full unlock landing: session swap + token, then the unlock-time
    /// sync/sweep tail. unlock, unlock_with_kek and pin_unlock (daemon,
    /// desktop and mobile-main processes) all land here.
    async fn finish_unlock(
        self: &Arc<Self>,
        new_handle: baluard_core::vault::handle::VaultHandle,
    ) -> Result<(), baluard_core::error::BaluardError> {
        self.finish_unlock_session(new_handle).await?;
        self.run_unlock_sync_tail().await;
        Ok(())
    }

    /// Mint a fresh session token (caller has proven a credential).
    async fn mint_session_token(&self) {
        let mut token_guard = self.session_token.write().await;
        *token_guard = Some(generate_session_token());
        self.session_token_generation.store(
            self.session_generation.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
    }

    /// Full unlock landing for an already-open vault whose token was
    /// lost (4h idle expiry): mint and run the sync tail.
    async fn finish_unlock_already_open(
        self: &Arc<Self>,
    ) -> Result<(), baluard_core::error::BaluardError> {
        self.mint_session_token().await;
        self.run_unlock_sync_tail().await;
        Ok(())
    }

    /// Unlock-time work shared by every full unlock: device-name
    /// migration, merge-cache refresh, autosync activation, expiry
    /// sweeps. The mobile autofill lean path does not run it.
    async fn run_unlock_sync_tail(self: &Arc<Self>) {
        // Whether the legacy heartbeat wrote a fresh record this unlock;
        // consumed by the autosync block below (a fresh alive record
        // only protects the owner once it reaches the remote).
        let mut heartbeat_wrote = false;
        let guard = self.inner.read().await;
        // C5: fold plaintext device names into settings.enc + strip them from
        // the git-tracked devices.json. Runs on every unlock (idempotent;
        // re-folds names reintroduced by a legacy remote's registry). Runs
        // outside git-sync so non-syncing vaults migrate too. Best-effort:
        // a failure logs and retries on the next unlock.
        if let Some(handle) = guard.as_ref() {
            if let Err(e) = handle.migrate_device_names_into_settings() {
                log::warn!("[state] device-name migration deferred: {e}");
            }
            // G24 device-local merge cache (family-spaces step 7):
            // record the ceiling as of this unlock so locked-vault
            // eligibility stays answerable. Best-effort: a registry
            // hiccup must never block an unlock.
            let ceiling = handle
                .get_settings()
                .map(|s| baluard_core::vault::space::effective_personal_merge(&s, &self.vault_path))
                .unwrap_or(false);
            match baluard_core::vault::registry::VaultRegistry::load_locked() {
                Ok(mut reg) => {
                    if let Some(slug) = reg.slug_for_path(&self.vault_path) {
                        if reg.set_merge_cache(&slug, ceiling).is_ok() {
                            let _ = reg.save_locked();
                        }
                    }
                }
                Err(e) => log::warn!("[state] merge cache refresh skipped: {e}"),
            }
            // Legacy contact heartbeat: refresh the signed alive record
            // when the last one is over a week old. Best-effort; the next
            // unlock retries.
            match baluard_core::legacy::heartbeat(&self.vault_path, handle) {
                Ok(wrote) => heartbeat_wrote = wrote,
                Err(e) => log::warn!("[state] legacy heartbeat deferred: {e}"),
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
            // Enrollment-proof verifier (public key material only).
            let enroll_vk = guard.as_ref().and_then(|h| h.enroll_verify_key());
            // Drop the handle guard before the post-unlock tail: the
            // no-remote expiry sweep takes the write lock and would
            // self-deadlock behind it.
            drop(guard);
            if !device_id.is_empty() {
                let has_remote = baluard_core::sync::engine::SyncEngine::new(
                    &self.vault_path,
                    &device_id,
                    devkey_seal.as_ref(),
                )
                .open_repo()
                .and_then(|repo| baluard_core::sync::engine::SyncEngine::has_remote(&repo))
                .unwrap_or(false);
                // E2E harness opt-out: explicit sync commands in tests must
                // not race the debounced background push/pull.
                if has_remote && std::env::var("BALUARD_AUTOSYNC").ok().as_deref() != Some("0") {
                    self.autosync
                        .activate(device_id.clone(), devkey_seal, enroll_vk)
                        .await;
                    // Pull remote changes the moment the vault opens so the UI
                    // reflects other-device edits immediately (event-driven,
                    // not waiting on the 30-min idle cadence). Spawned off the
                    // unlock IPC path so unlock returns without waiting on a
                    // network fetch; pull_only's generation check no-ops if the
                    // vault is locked before the fetch completes.
                    let handle = self.autosync.clone();
                    // S3-3 (review F1): the expiry sweep must run AFTER the
                    // unlock pull — pull_only force-checkouts the worktree,
                    // which would discard an uncommitted sweep written
                    // before it, and the sweep's file changes only reach
                    // peers once committed. The spawned task pulls first,
                    // sweeps (admin-gated), then nudges autosync so the
                    // rotation commits and pushes on the normal cycle.
                    let state = self.clone();
                    tokio::spawn(async move {
                        handle.pull_only(device_id.clone()).await;
                        if heartbeat_wrote {
                            // The contact's clone measures silence on the
                            // remote, so the fresh alive record must ride
                            // the commit-and-push cycle — nudged only AFTER
                            // the pull, whose force-checkout would revert
                            // the still-uncommitted record.
                            handle.nudge(device_id.clone()).await;
                        }
                        let removed = state.sweep_grants_if_admin_inner().await;
                        let (vault_id, seats) = state.sweep_join_approvals_if_admin_inner().await;
                        if removed > 0 || !seats.is_empty() {
                            handle.on_mutation(device_id).await;
                        }
                        // P8c seat upgrades run outside the vault lock.
                        for (username, role) in seats {
                            // Fail toward no seat change: an unresolvable
                            // role upgrades nothing (manual-path parity).
                            let Some(role) = role else {
                                continue;
                            };
                            let permission =
                                if matches!(role, baluard_core::vault::members::MemberRole::Viewer)
                                {
                                    baluard_core::providers::types::CollaboratorPermission::ReadOnly
                                } else {
                                    baluard_core::providers::types::CollaboratorPermission::Write
                                };
                            if let Some(username) = username.filter(|u| !u.trim().is_empty()) {
                                if let Some(vault_id) = vault_id {
                                    if let Some((provider, owner, repo)) =
                                        state.vault_transport_coords(vault_id)
                                    {
                                        let _ = crate::providers::add_collaborator(
                                            provider, &owner, &repo, &username, permission,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    });
                } else {
                    // No remote: no pull can race, so sweep inline.
                    let removed = self.sweep_grants_if_admin_inner().await;
                    let (vault_id, seats) = self.sweep_join_approvals_if_admin_inner().await;
                    if removed > 0 {
                        log::warn!("[state] grant expiry sweep removed expired grants");
                    }
                    for (username, role) in seats {
                        // Fail toward no seat change (manual-path parity).
                        let Some(role) = role else {
                            continue;
                        };
                        let permission =
                            if matches!(role, baluard_core::vault::members::MemberRole::Viewer) {
                                baluard_core::providers::types::CollaboratorPermission::ReadOnly
                            } else {
                                baluard_core::providers::types::CollaboratorPermission::Write
                            };
                        if let Some(username) = username.filter(|u| !u.trim().is_empty()) {
                            if let Some(vault_id) = vault_id {
                                if let Some((provider, owner, repo)) =
                                    self.vault_transport_coords(vault_id)
                                {
                                    let _ = crate::providers::add_collaborator(
                                        provider, &owner, &repo, &username, permission,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// S3-3 expiry-that-rotates executor: drop expired grants + rotate
    /// the affected collections' keys, but only when the unlocking
    /// device can authorize the write (Owner/Admin, or a legacy vault
    /// without meta/members — same admin-equivalence as the other
    /// collection mutators). A non-admin client must never attempt the
    /// admin-only write: the commit would be refused at pull time on
    /// every peer. Best-effort: failures retry at the next unlock.
    /// Returns the number of removed grants.
    async fn sweep_grants_if_admin_inner(&self) -> usize {
        let mut guard = self.inner.write().await;
        let Some(handle) = guard.as_mut() else {
            return 0;
        };
        if !handle.is_unlocked() {
            return 0;
        }
        let admin_equivalent = !self.vault_path.join("meta/members").is_dir();
        let is_admin = matches!(
            baluard_core::vault::members::member_role_for_device(
                &self.vault_path,
                handle.device_id,
            ),
            Some(baluard_core::vault::members::MemberRole::Owner)
                | Some(baluard_core::vault::members::MemberRole::Admin)
        );
        if !(is_admin || admin_equivalent) {
            return 0;
        }
        match handle.collections_sweep() {
            Ok(rows) => rows.len(),
            Err(e) => {
                log::warn!("[state] grant expiry sweep failed: {e}");
                0
            }
        }
    }

    /// §6.5 join_approval=code executor: approve queued join
    /// introductions whose one-time-code secret check passes. Possession
    /// of the code IS the approval; every gate inside
    /// approve_queued_join (pair-Space cap, readiness, role floor,
    /// template snapshot) still applies. Only `secret_ok` rows are
    /// candidates — a hostile or stale row is never approved and stays
    /// queued for admin visibility; a refused approval also stays
    /// queued. Runs on the same admin gate as the grant sweep: a member
    /// device must never mint the approval commit. Returns (transport
    /// username, invite role) pairs for the P8c seat upgrades.
    async fn sweep_join_approvals_if_admin_inner(
        &self,
    ) -> (
        Option<uuid::Uuid>,
        Vec<(
            Option<String>,
            Option<baluard_core::vault::members::MemberRole>,
        )>,
    ) {
        let mut guard = self.inner.write().await;
        let Some(handle) = guard.as_mut() else {
            return (None, Vec::new());
        };
        if !handle.is_unlocked() {
            return (None, Vec::new());
        }
        // Captured under the lock: reading it after release races the
        // vault locking and would silently drop every seat upgrade.
        let vault_id = handle.vault_id;
        let admin_equivalent = !self.vault_path.join("meta/members").is_dir();
        let is_admin = matches!(
            baluard_core::vault::members::member_role_for_device(
                &self.vault_path,
                handle.device_id,
            ),
            Some(baluard_core::vault::members::MemberRole::Owner)
                | Some(baluard_core::vault::members::MemberRole::Admin)
        );
        if !(is_admin || admin_equivalent) {
            return (Some(vault_id), Vec::new());
        }
        match handle.get_settings().map(|s| s.join_approval) {
            Ok(baluard_core::vault::manifest::JoinApproval::Code) => {}
            _ => return (Some(vault_id), Vec::new()),
        }
        let (rows, _malformed) = match baluard_core::vault::members::list_requests(&handle.path) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[state] join queue walk failed: {e}");
                return (Some(vault_id), Vec::new());
            }
        };
        let mut seats = Vec::new();
        for row in rows {
            if !row.secret_ok {
                continue;
            }
            // P8c parity: read username + role BEFORE the approval
            // consumes the invite.
            let mut username = None;
            let mut role = None;
            if let Ok(intro) = baluard_core::vault::members::read_request(&handle.path, row.req_id)
            {
                if let Ok(pending) =
                    baluard_core::vault::members::read_pending_invite(&handle.path, intro.invite_id)
                {
                    username = pending.transport_username;
                    role = Some(pending.role);
                }
            }
            match handle.approve_queued_join(row.req_id) {
                Ok(_) => seats.push((username, role)),
                Err(e) => {
                    log::warn!("[state] join auto-approve refused {}: {e}", row.req_id);
                }
            }
        }
        (Some(vault_id), seats)
    }

    /// Stop the auto-sync loop without locking the vault. Host-level
    /// close/insert-replace uses this so a closed vault's background
    /// loop cannot outlive the map entry.
    pub async fn autosync_deactivate(&self) {
        self.autosync.deactivate().await;
    }

    /// Lock the vault, zeroizing keys in memory. Clears the session token.
    pub async fn lock(&self) -> Result<(), String> {
        // P1c: bump the lock generation FIRST — any in-flight or forgotten
        // token minted at the previous generation dies here even if a
        // future code path forgets the explicit clear below (defense in
        // depth for the lock chokepoint cascade).
        self.session_generation.fetch_add(1, Ordering::Relaxed);
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
        self.session_token_generation.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// D79 update prep for one vault: wait for any in-flight sync cycle to
    /// finish (bounded), then lock while STILL holding the cycle guard so no
    /// new cycle can start between drain and lock. A wedged network cycle
    /// refuses the update instead of hanging it; the desktop surfaces the
    /// retry. The cycle guard and lock() take locks in the same order the
    /// sync cycle uses (cycle_lock, then inner), so this cannot deadlock.
    pub async fn prepare_for_update(&self) -> Result<(), String> {
        const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        self.prepare_for_update_with_timeout(DRAIN_TIMEOUT).await
    }

    pub(crate) async fn prepare_for_update_with_timeout(
        &self,
        drain_timeout: std::time::Duration,
    ) -> Result<(), String> {
        let _cycle = tokio::time::timeout(drain_timeout, self.autosync.cycle_lock_guard())
            .await
            .map_err(|_| "a sync cycle is still running; retry in a moment".to_string())?;
        self.lock().await
    }

    /// Change the master password. Requires vault to be unlocked.
    /// H1 fix: re-wraps KEK and disables stale biometric secret.
    pub async fn change_master_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        // M1: take the devkey op lock BEFORE the inner lock (the hierarchy
        // every devkey op follows), so a racing hw_enable / hw_disable /
        // consent change cannot interleave its device-file
        // read-modify-write with the re-seal inside the password change.
        let _ops = self.devkey_ops.lock().await;
        // H7: snapshot what the core op needs under a READ lock, then run
        // the change OFF the vault lock — the chip taps must not pin
        // other vault operations for their duration.
        let (vault_path, vault_id, device_id, kdf_params, root_key) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault not opened")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked".into());
            }
            let root = handle
                .unlocked()
                .root()
                .map_err(|e| format!("{e}"))?
                .clone();
            (
                handle.path.clone(),
                handle.vault_id,
                handle.device_id,
                handle.kdf_params.clone(),
                root,
            )
        };
        let old = old_password.to_string();
        let new = new_password.to_string();
        let files_path = vault_path.clone();
        let (new_session_key, new_devkey_seal) = tokio::task::spawn_blocking(move || {
            baluard_core::vault::handle::VaultHandle::change_master_password_files(
                &files_path,
                vault_id,
                device_id,
                &kdf_params,
                &root_key,
                &old,
                &new,
            )
        })
        .await
        .map_err(|e| format!("password change task: {e}"))?
        .map_err(|e| format!("{e}"))?;
        // Short write lock: commit the in-memory keys. A lock or close
        // mid-change is fine — the files already carry the new keys and
        // the next unlock verifies them; a different vault in the slot
        // must not receive them.
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if handle.path != vault_path || handle.device_id != device_id {
            return Err("Vault changed during the password change".into());
        }
        handle.apply_master_password_change(new_session_key, new_devkey_seal);
        Ok(())
    }

    /// Replace the vault's recovery phrase (master-password gated in the
    /// core). Returns {"phrase": ...} — the new 24 words, shown once.
    /// Holds the autosync cycle lock so a background cycle cannot commit
    /// the escrow mid-swap (review F5).
    pub async fn rotate_recovery_phrase(&self, old_password: &str) -> Result<String, String> {
        let _cycle = self.autosync.cycle_lock_guard().await;
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let phrase = handle
            .rotate_recovery_phrase(old_password)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "phrase": phrase }).to_string())
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
    pub async fn unlock_with_kek(
        self: &Arc<Self>,
        kek: &[u8; 32],
    ) -> Result<(), baluard_core::error::BaluardError> {
        // Already unlocked with a live token: keep the existing session.
        // Swapping in a fresh handle + token would strand the caller's.
        {
            let guard = self.inner.read().await;
            if let Some(ref handle) = *guard {
                if handle.is_unlocked() && self.get_session_token().await.is_some() {
                    return Ok(());
                }
            }
        }
        // No KDF, but the HPKE unwrap + canary check still touch the
        // keywrap: run on a blocking thread like the password path.
        let vault_path = self.vault_path.clone();
        let kek = *kek;
        let mut new_handle = tokio::task::spawn_blocking(
            move || -> Result<VaultHandle, baluard_core::error::BaluardError> {
                let mut h = VaultHandle::open(&vault_path)?;
                h.unlock_with_kek(&kek)?;
                Ok(h)
            },
        )
        .await
        .map_err(|e| {
            baluard_core::error::BaluardError::from(baluard_core::error::VaultError::Metadata(
                format!("unlock task: {e}"),
            ))
        })??;

        self.finish_unlock(new_handle).await
    }
    /// KEK quick-unlock without the sync/sweep tail. The Android
    /// :autofill process (and any embedded consumer) uses this: the tail
    /// would run git writes in the memory-capped process concurrently
    /// with the main app's autosync coordinator.
    pub async fn unlock_with_kek_lean(
        &self,
        kek: &[u8; 32],
    ) -> Result<(), baluard_core::error::BaluardError> {
        // Already unlocked with a live token: keep the existing session.
        {
            let guard = self.inner.read().await;
            if let Some(ref handle) = *guard {
                if handle.is_unlocked() && self.get_session_token().await.is_some() {
                    return Ok(());
                }
            }
        }
        let vault_path = self.vault_path.clone();
        let kek = *kek;
        let new_handle = tokio::task::spawn_blocking(
            move || -> Result<VaultHandle, baluard_core::error::BaluardError> {
                let mut h = VaultHandle::open(&vault_path)?;
                h.unlock_with_kek(&kek)?;
                Ok(h)
            },
        )
        .await
        .map_err(|e| {
            baluard_core::error::BaluardError::from(baluard_core::error::VaultError::Metadata(
                format!("unlock task: {e}"),
            ))
        })??;
        self.finish_unlock_session(new_handle).await
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
        let result = self.full_envelope().await?;
        serde_json::to_string(&result).map_err(|e| format!("Serialization: {e}"))
    }

    /// The `vault.list_full` payload as a structured Value. Shared by the
    /// single-vault route and the merged multi-vault `vaults.list_full_all`
    /// host route (S2-5).
    pub async fn full_envelope(&self) -> Result<serde_json::Value, String> {
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
                        "collection_id": meta.collection_id,
                    });
                    ciphers.push(json);
                }
                _ => continue,
            }
        }

        // Trash
        let trash_entries = handle.list_trash_entries().map_err(|e| format!("{e}"))?;
        let mut trash = Vec::with_capacity(trash_entries.len());
        for (id, collection_id) in &trash_entries {
            match handle.get_cipher(*id) {
                Ok(CipherRead::Decrypted(ref c)) => {
                    let mut json = cipher_to_json(c);
                    let username = match &c.kind {
                        baluard_core::types::CipherKind::Login(data) => data.username.clone(),
                        _ => None,
                    };
                    json["_meta"] = serde_json::json!({
                        "id": id.to_string(),
                        "name": c.name,
                        "cipher_type": c.kind.cipher_type(),
                        "favorite": c.favorite,
                        "username": username,
                        "collection_id": collection_id,
                    });
                    trash.push(json);
                }
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
                        "collection_id": meta.collection_id,
                    });
                    archived.push(json);
                }
                _ => continue,
            }
        }

        // Rebuild tag index from decrypted cipher data
        let _ = handle.rebuild_tag_index();
        let tags = handle.list_tags().unwrap_or_default();

        Ok(serde_json::json!({
            "ciphers": ciphers,
            "folders": folders,
            "trash": trash,
            "archived": archived,
            "tags": tags,
        }))
    }

    /// Autofill credential query (Phase 6, plan D1/D2/D4).
    ///
    /// Decrypts LOGIN ciphers only (never trash, never archived), matches
    /// each stored URI against `target` using that URI's own strategy, and
    /// returns a JSON object `{matches: [...], app_suggestions: [...]}`
    /// ranked favorites-first then by name. Passwords and TOTP seeds NEVER
    /// appear in the output; the caller fetches the chosen cipher separately.
    ///
    /// `app_suggestions` carries the path-B app-to-web flow: for
    /// `androidapp://` targets with `suggest_app_logins` enabled, web-saved
    /// logins whose registrable domain equals a package-derived candidate
    /// surface here (untrusted) or flow straight into `matches` (trusted
    /// pairs). Rejected pairs never surface.
    pub async fn autofill_query(&self, target: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let settings = handle.get_settings().ok();
        // User-defined equivalent domain groups (Bitwarden parity): loaded
        // from vault settings, consulted by the Domain strategy in addition
        // to the bundled global list.
        let custom_groups: Vec<Vec<String>> = settings
            .as_ref()
            .and_then(|s| s.custom_equivalent_domains.clone())
            .unwrap_or_default();
        let app_ctx = app_match_context(settings.as_ref(), target);

        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut matched: Vec<serde_json::Value> = Vec::new();
        // (entry json, web registrable domains) for suggestion assembly.
        let mut web_entries: Vec<(serde_json::Value, Vec<String>)> = Vec::new();
        for meta in &metas {
            if meta.cipher_type != baluard_core::types::CipherType::Login {
                continue;
            }
            let decrypted = match handle.get_cipher(meta.id) {
                Ok(baluard_core::vault::handle::CipherRead::Decrypted(c)) => c,
                _ => continue,
            };
            let baluard_core::types::CipherKind::Login(login) = &decrypted.kind else {
                continue;
            };
            let hit = login.uris.iter().any(|lu| {
                lu.match_strategy
                    .matches_with(&lu.uri, target, &custom_groups)
            });
            let web_regs: Vec<String> = login
                .uris
                .iter()
                .filter_map(|lu| baluard_core::types::web_uri_registrable(&lu.uri))
                .collect();
            // Trusted pair (path B): a web entry whose registrable domain
            // was trusted for this package fills like a direct match.
            let trusted_hit = web_regs
                .iter()
                .any(|r| app_ctx.as_ref().is_some_and(|c| c.trusted.contains(r)));
            let entry = serde_json::json!({
                "id": meta.id.to_string(),
                "name": meta.name,
                "username": meta.username,
                "favorite": meta.favorite,
            });
            if hit || trusted_hit {
                matched.push(entry);
            } else if !web_regs.is_empty() {
                web_entries.push((entry, web_regs));
            }
        }
        matched.sort_by(|a, b| {
            let fav = |v: &serde_json::Value| v["favorite"].as_bool().unwrap_or(false);
            fav(b).cmp(&fav(a)).then_with(|| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["name"].as_str().unwrap_or(""))
            })
        });
        let matched_ids: Vec<&str> = matched.iter().filter_map(|v| v["id"].as_str()).collect();
        let app_suggestions: Vec<serde_json::Value> = match &app_ctx {
            Some(ctx) => ctx
                .candidates
                .iter()
                .filter(|c| !ctx.trusted.contains(c) && !ctx.rejected.contains(c))
                .filter_map(|c| {
                    let m: Vec<&serde_json::Value> = web_entries
                        .iter()
                        .filter(|(_, regs)| regs.iter().any(|r| r == c))
                        .map(|(j, _)| j)
                        .filter(|j| !matched_ids.contains(&j["id"].as_str().unwrap_or("")))
                        .collect();
                    (!m.is_empty()).then(|| serde_json::json!({"domain": c, "matches": m}))
                })
                .collect(),
            None => Vec::new(),
        };
        serde_json::to_string(
            &serde_json::json!({"matches": matched, "app_suggestions": app_suggestions}),
        )
        .map_err(|e| format!("serialization: {e}"))
    }

    /// G24 (ADR 0098 §4.3): the fill-time origin check rides
    /// the SAME matcher as bridge.match - UriMatchStrategy over the
    /// cipher's URIs plus the vault's custom equivalent domains - so a
    /// credential suggested for a page is exactly the credential
    /// readable for it. Returns false for non-login and URI-less
    /// ciphers (the route layer decides the URI-less policy).
    pub async fn cipher_matches_uri(&self, id_str: &str, url: &str) -> Result<bool, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let cid = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;
        let cipher = handle.get_cipher(cid).map_err(|e| format!("{e}"))?;
        let c = match cipher {
            baluard_core::vault::handle::CipherRead::Decrypted(c) => *c,
            baluard_core::vault::handle::CipherRead::Locked(_) => {
                return Err("Cipher is locked".into());
            }
        };
        let settings = handle.get_settings().ok();
        let custom_groups: Vec<Vec<String>> = settings
            .as_ref()
            .and_then(|s| s.custom_equivalent_domains.clone())
            .unwrap_or_default();
        let baluard_core::types::CipherKind::Login(login) = &c.kind else {
            return Ok(false);
        };
        Ok(login
            .uris
            .iter()
            .any(|lu| lu.match_strategy.matches_with(&lu.uri, url, &custom_groups)))
    }

    /// Record a user trust decision for a (package, registrable domain)
    /// pairing (path B app-to-web matching). [trust] true records trust
    /// (the pair's web entries fill in that app); false records rejection
    /// (the picker never suggests the pairing again). A later decision for
    /// the same pair overrides the earlier one. The domain folds through
    /// the PSL before storage, so lookalike hosts cannot smuggle in.
    pub async fn autofill_app_trust_set(
        &self,
        package: &str,
        domain: &str,
        trust: bool,
    ) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let package = package.trim().to_ascii_lowercase();
        // Lands in settings.enc and trust decisions key on it: bound the
        // size and keep it a plausible package name.
        if package.is_empty()
            || package.len() > 256
            || !package
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        {
            return Err("invalid package name".into());
        }
        if package.is_empty() || package.contains("://") || package.contains('/') {
            return Err("Invalid package name".into());
        }
        let domain = baluard_core::types::web_uri_registrable(domain).ok_or("Invalid domain")?;
        let mut settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        let pair = baluard_core::vault::manifest::AppDomainTrust {
            package: package.clone(),
            domain: domain.clone(),
        };
        let (add, remove) = if trust {
            (
                &mut settings.trusted_app_packages,
                &mut settings.rejected_app_packages,
            )
        } else {
            (
                &mut settings.rejected_app_packages,
                &mut settings.trusted_app_packages,
            )
        };
        let list = add.get_or_insert_with(Vec::new);
        list.retain(|p| p.package != package || p.domain != domain);
        list.push(pair);
        if let Some(rm) = remove.as_mut() {
            rm.retain(|p| p.package != package || p.domain != domain);
        }
        // Read-modify-write against a possibly-open main process (last-
        // write-wins file): the window is one settings field, written
        // only on an explicit user tap. Accepted risk.
        handle.save_settings(&settings).map_err(|e| format!("{e}"))
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
    /// Shared gate for writes to git-tracked vault meta (settings,
    /// profile, avatar): legacy personal vaults pass (the founder
    /// manages); team vaults require Owner/Admin. A member writing
    /// tracked meta would commit fine locally and be refused at every
    /// peer pull, wedging the whole space — refuse here instead.
    async fn is_managing_device(vault_path: &std::path::Path, device_id: uuid::Uuid) -> bool {
        let members_dir = vault_path.join(baluard_core::vault::members::MEMBERS_DIR);
        if !members_dir.exists() {
            return true; // legacy personal vault: the founder manages
        }
        matches!(
            baluard_core::vault::members::member_role_for_device(vault_path, device_id),
            Some(baluard_core::vault::members::MemberRole::Owner)
                | Some(baluard_core::vault::members::MemberRole::Admin)
        )
    }

    async fn ensure_managing_device(
        vault_path: &std::path::Path,
        device_id: uuid::Uuid,
    ) -> Result<(), String> {
        if !Self::is_managing_device(vault_path, device_id).await {
            return Err("This change can only be made on a managing device.".into());
        }
        Ok(())
    }

    pub async fn settings_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;

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
            if let Some(ext) = &settings.avatar_ext {
                if !avatar_ext_allowed(ext) {
                    return Err("Unsupported avatar format".into());
                }
            }
        }
        if let Some(v) = partial.get("custom_equivalent_domains") {
            settings.custom_equivalent_domains = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid custom_equivalent_domains: {e}"))?;
        }
        if let Some(v) = partial.get("suggest_app_logins") {
            settings.suggest_app_logins = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid suggest_app_logins: {e}"))?;
        }
        if let Some(v) = partial.get("trusted_app_packages") {
            settings.trusted_app_packages = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid trusted_app_packages: {e}"))?;
        }
        if let Some(v) = partial.get("rejected_app_packages") {
            settings.rejected_app_packages = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid rejected_app_packages: {e}"))?;
        }
        if let Some(v) = partial.get("lang") {
            let lang = v.as_str().ok_or("lang must be a string")?;
            // Lands in git-tracked plaintext settings-pub.json: keep it a
            // plausible locale tag, not free-form text.
            if lang.len() > 16
                || !lang
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("lang must be a short locale tag".into());
            }
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
        // Resolve the read job under a short lock: the byte I/O below runs
        // on a blocking worker, so no lock may span it. Both avatar keys
        // are extracted here because decrypt_avatar_blob's legacy-epoch
        // fallback needs the SGK key, not a handle.
        enum Job {
            Encrypted {
                path: std::path::PathBuf,
                key: Zeroizing<[u8; 32]>,
                legacy_key: Option<Zeroizing<[u8; 32]>>,
            },
            Legacy {
                path: std::path::PathBuf,
                ext: String,
                device_id: uuid::Uuid,
            },
        }
        let job = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let ext = handle
                .load_profile()
                .ok()
                .and_then(|p| p.avatar_ext)
                .unwrap_or_default();
            if ext.is_empty() || !avatar_ext_allowed(&ext) {
                return Ok(String::new());
            }
            let enc_path = handle.path.join("meta").join("avatar.enc");
            let legacy_path = handle.path.join("meta").join(format!("avatar.{ext}"));
            if enc_path.exists() {
                let key = Zeroizing::new(
                    handle
                        .derive_avatar_key()
                        .map_err(|e| format!("avatar key: {e}"))?,
                );
                let legacy_key = handle
                    .unlocked()
                    .sgk()
                    .ok()
                    .map(|sgk| Zeroizing::new(sgk.derive_avatar_key(sgk.epoch())));
                Job::Encrypted {
                    path: enc_path,
                    key,
                    legacy_key,
                }
            } else if legacy_path.exists() {
                Job::Legacy {
                    path: legacy_path,
                    ext,
                    device_id: handle.device_id,
                }
            } else {
                return Ok(String::new());
            }
        };
        let managing = match &job {
            Job::Encrypted { .. } => true,
            Job::Legacy { device_id, .. } => {
                Self::is_managing_device(self.vault_path.as_path(), *device_id).await
            }
        };
        // The read itself is the slow part and stays off the lock; the
        // migration write-back commits under the write lock below.
        type AvatarRead = (String, Option<(Vec<u8>, String)>);
        let (encoded, migration) =
            tokio::task::spawn_blocking(move || -> Result<AvatarRead, String> {
                use base64::Engine;
                match job {
                    Job::Encrypted {
                        path,
                        key,
                        legacy_key,
                    } => {
                        let blob = std::fs::read(&path).map_err(|e| format!("read avatar: {e}"))?;
                        let bytes = match baluard_core::vault::avatar::decrypt_avatar(&key, &blob) {
                            Ok(bytes) => bytes,
                            Err(_) => match legacy_key {
                                Some(legacy_key) => {
                                    baluard_core::vault::avatar::decrypt_avatar(&legacy_key, &blob)
                                        .map_err(|_| "avatar could not be decrypted".to_string())?
                                }
                                None => return Err("avatar could not be decrypted".into()),
                            },
                        };
                        Ok((
                            base64::engine::general_purpose::STANDARD.encode(&bytes),
                            None,
                        ))
                    }
                    Job::Legacy { path, ext, .. } => {
                        let data = std::fs::read(&path).map_err(|e| format!("read avatar: {e}"))?;
                        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
                        // The migration writes git-tracked meta; a member device
                        // reads the legacy bytes without migrating (the admin
                        // migrates).
                        if managing {
                            Ok((encoded, Some((data, ext))))
                        } else {
                            Ok((encoded, None))
                        }
                    }
                }
            })
            .await
            .map_err(|e| format!("avatar task: {e}"))??;

        if let Some((data, ext)) = migration {
            let guard = self.inner.write().await;
            let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
            if handle.is_unlocked() {
                let enc_path = self.vault_path.join("meta").join("avatar.enc");
                let legacy_path = self.vault_path.join("meta").join(format!("avatar.{ext}"));
                // A removal or a concurrent set may have consumed the legacy
                // file while the bytes were in flight; whichever deleted it
                // owns the outcome, so migrate only if it still exists. The
                // key derives here so a rotation during the read is honored.
                if legacy_path.exists() {
                    let fresh_key = Zeroizing::new(
                        handle
                            .derive_avatar_key()
                            .map_err(|e| format!("avatar key: {e}"))?,
                    );
                    let blob = baluard_core::vault::avatar::encrypt_avatar(&fresh_key, &data)
                        .map_err(|e| format!("{e}"))?;
                    baluard_core::vault::write_vault_file(&enc_path, &blob)
                        .map_err(|e| format!("write avatar: {e}"))?;
                }
                let _ = std::fs::remove_file(&legacy_path);
            } else {
                log::warn!("avatar migration skipped: the vault locked mid-read");
            }
        }
        Ok(encoded)
    }

    /// Set avatar image from base64. Payload: JSON {"data": "<base64>", "ext": "png"}
    /// M1 fix: encrypts avatar with AES-256-GCM (key from SGK) and stores
    /// at meta/avatar.enc. Legacy plaintext meta/avatar.{ext} files are
    /// deleted on next set.
    pub async fn avatar_set(&self, payload: &str) -> Result<(), String> {
        let (vault_path, device_id) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            (handle.path.clone(), handle.device_id)
        };
        Self::ensure_managing_device(vault_path.as_path(), device_id).await?;
        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let b64 = v["data"].as_str().unwrap_or("");
        let ext_raw = v["ext"].as_str().unwrap_or("png");

        if b64.is_empty() {
            // Removals are fast unlinks; run them inside the commit lock
            // so a concurrent set cannot resurrect a removed file.
            let guard = self.inner.write().await;
            let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let _ = std::fs::remove_file(vault_path.join("meta").join("avatar.enc"));
            // The removal owns the final profile: clean the legacy file for
            // whatever extension it currently records.
            let mut fresh = handle.load_profile().map_err(|e| format!("{e}"))?;
            if let Some(old_ext) = fresh.avatar_ext.as_ref() {
                let clean = old_ext.trim().to_lowercase();
                if matches!(clean.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
                    let _ = std::fs::remove_file(
                        vault_path.join("meta").join(format!("avatar.{clean}")),
                    );
                }
            }
            fresh.avatar_ext = None;
            handle.save_profile(&fresh).map_err(|e| format!("{e}"))?;
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

        // Single commit under the write lock: encrypting is milliseconds
        // against the 256KB cap, and one section keeps the profile
        // read-modify-write atomic with the blob swap, so a rotation or a
        // concurrent settings write cannot land between key use and save.
        let mut guard = self.inner.write().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let key = Zeroizing::new(
            handle
                .derive_avatar_key()
                .map_err(|e| format!("avatar key: {e}"))?,
        );
        let blob = baluard_core::vault::avatar::encrypt_avatar(&key, &bytes)
            .map_err(|e| format!("{e}"))?;
        baluard_core::vault::write_vault_file(&vault_path.join("meta").join("avatar.enc"), &blob)
            .map_err(|e| format!("write avatar: {e}"))?;
        // Remove ALL whitelisted legacy plaintext avatar files so a stray
        // plaintext cannot survive an extension change.
        for legacy_ext in ["png", "jpg", "jpeg", "gif", "webp"] {
            let _ =
                std::fs::remove_file(vault_path.join("meta").join(format!("avatar.{legacy_ext}")));
        }
        let mut fresh = handle.load_profile().map_err(|e| format!("{e}"))?;
        fresh.avatar_ext = Some(ext);
        handle.save_profile(&fresh).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    /// Save plaintext locale to meta/locale (readable before vault unlock).
    /// Payload: plain lang string (e.g. "es").
    pub async fn locale_save(&self, lang: &str) -> Result<(), String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        // Gated at every state: a pre-unlock member device writing
        // settings-pub.json would see the change committed by its first
        // post-unlock sync and wedge the space. Per-member language
        // preferences are a future local-store item.
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;
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
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;

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
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;
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
                // Only Logins with passkeys matter: cloning everything
                // copies the whole vault's plaintext into heap.
                if let baluard_core::types::CipherKind::Login(ref d) = c.kind {
                    if d.fido2_credentials.as_ref().is_none_or(|v| v.is_empty()) {
                        continue;
                    }
                    ciphers.push(c.clone());
                }
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

        // SEC-1: the fresh private key stays in the ceremony cache. The
        // response carries only public metadata; finish_register reads
        // the passkey back from the cache, never from the client echo.
        let mut pk_public = serde_json::to_value(&result.passkey_data)
            .map_err(|e| format!("Serialize error: {e}"))?;
        if let Some(obj) = pk_public.as_object_mut() {
            obj.remove("private_key");
            obj.remove("prf_key");
        }

        self.ceremony_cache
            .insert(
                ceremony_id.clone(),
                CeremonyState::Registration {
                    rp_id,
                    rp_name,
                    user_name,
                    user_display_name,
                    user_id,
                    passkey_data: Box::new(result.passkey_data),
                    created_at: std::time::Instant::now(),
                },
            )
            .await;

        let response = serde_json::json!({
            "ceremony_id": ceremony_id,
            "credential_id": result.credential_id_b64,
            "attestation_response": serde_json::from_str::<serde_json::Value>(&result.attestation_response)
                .unwrap_or_default(),
            "passkey_data": pk_public,
        });

        Ok(response.to_string())
    }

    /// Complete a registration ceremony. Saves passkey to vault.
    /// Payload: `{ "ceremony_id": "...", "credential_id": "..." }`
    ///
    /// SEC-1: the passkey comes from the ceremony cache, not from the
    /// client — the challenge_register response redacts key material,
    /// so no client could supply it anyway.
    pub async fn passkey_finish_register(&self, payload: &str) -> Result<String, String> {
        use baluard_core::crypto::webauthn::CeremonyState;

        let v: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let ceremony_id = v["ceremony_id"].as_str().ok_or("Missing 'ceremony_id'")?;

        // Validate before consuming: a locked vault must not destroy the
        // pending ceremony (the RP has already registered the credential).
        let state = self
            .ceremony_cache
            .get(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        let pk_data = match &state {
            CeremonyState::Registration { passkey_data, .. } => passkey_data.as_ref().clone(),
            _ => return Err("Expected registration ceremony".into()),
        };
        {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked".into());
            }
        }
        if let Some(echoed) = v["credential_id"].as_str() {
            if echoed != pk_data.credential_id {
                return Err("credential_id does not match this ceremony".into());
            }
        }

        let state = self
            .ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony expired during validation")?;

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
                    // Registrable-domain match: a substring hit would file
                    // the passkey under lookalike hosts (ex.com vs
                    // annex.com, ex.com.evil.tld).
                    if data.uris.iter().any(|u| {
                        baluard_core::types::UriMatchStrategy::Domain
                            .matches(&u.uri, &pk_data.rp_id)
                    }) {
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
                    collection_id: None,
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
                collection_id: None,
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
                // Only Logins with passkeys matter: cloning everything
                // copies the whole vault's plaintext into heap.
                if let baluard_core::types::CipherKind::Login(ref d) = c.kind {
                    if d.fido2_credentials.as_ref().is_none_or(|v| v.is_empty()) {
                        continue;
                    }
                    ciphers.push(c.clone());
                }
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

        // Validate before consuming: a locked vault or malformed payload
        // must not destroy the pending ceremony.
        let state = self
            .ceremony_cache
            .get(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        match &state {
            CeremonyState::Assertion { .. } => {}
            _ => return Err("Expected assertion ceremony".into()),
        }

        let credential_id_b64 = v["credential_id"]
            .as_str()
            .ok_or("Missing 'credential_id'")?;
        let new_counter = v["new_counter"]
            .as_u64()
            .ok_or("Missing 'new_counter'")?
            .min(u32::MAX as u64) as u32;

        {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked".into());
            }
        }

        self.ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony expired during validation")?;

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
                                    collection_id: None,
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
                // An empty list must stay an explicit Some: the core
                // merge treats None as "keep existing credentials", so
                // flattening it here would silently fail the delete.
                let updated_data = baluard_core::types::LoginData {
                    fido2_credentials: Some(fido2_list),
                    ..data.clone()
                };
                let input = baluard_core::types::CipherInput {
                    name: cipher.name.clone(),
                    folder_id: cipher.folder_id,
                    collection_id: None,
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
                    collection_id: None,
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

    // ── Provider-grade passkey ceremonies (ADR 0095 §8) ──
    //
    // The Android credential-provider surface. Pending credentials stay
    // Rust-side behind ceremony ids (SEC-1); responses are
    // PublicKeyCredential.toJSON()-shaped strings handed straight back to the
    // calling platform.

    fn vault_passkey_index(
        &self,
        guard: &tokio::sync::RwLockReadGuard<'_, Option<VaultHandle>>,
    ) -> Result<baluard_core::crypto::webauthn::PasskeyIndex, String> {
        use baluard_core::vault::handle::CipherRead;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let metas = handle.list_cipher_meta().map_err(|e| e.to_string())?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                // Only Logins with passkeys matter: cloning everything
                // copies the whole vault's plaintext into heap.
                if let baluard_core::types::CipherKind::Login(ref d) = c.kind {
                    if d.fido2_credentials.as_ref().is_none_or(|v| v.is_empty()) {
                        continue;
                    }
                    ciphers.push(c.clone());
                }
            }
        }
        Ok(baluard_core::crypto::webauthn::PasskeyIndex::from_boxed_ciphers(&ciphers))
    }

    /// Run a provider registration ceremony. Args are discrete (UniFFI calls
    /// this directly): the RP's create-options JSON, the validated origin, an
    /// optional base64url clientDataHash from a privileged browser caller,
    /// and the per-call UV grant.
    ///
    /// Returns `{ ceremony_id, attestation_response, rp_id, credential_id,
    /// user_name }`; the fresh credential is held pending until
    /// `passkey_store_registered` consumes it.
    pub async fn passkey_provider_register(
        &self,
        request_json: &str,
        origin: &str,
        client_data_json_b64: Option<&str>,
        client_data_hash_b64: Option<&str>,
        user_verified: bool,
    ) -> Result<String, String> {
        use base64::Engine;

        self.ceremony_cache.evict_expired().await;
        let origin_url = url::Url::parse(origin).map_err(|e| format!("Invalid origin: {e}"))?;
        let decode_b64 = |b64: Option<&str>| match b64.filter(|s| !s.is_empty()) {
            Some(s) => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s.trim_end_matches('='))
                .map(Some)
                .map_err(|_| "client data is not valid base64url".to_string()),
            None => Ok(None),
        };
        let client_data_json = decode_b64(client_data_json_b64)?;
        let client_data_hash = decode_b64(client_data_hash_b64)?;

        let guard = self.inner.read().await;
        let index = self.vault_passkey_index(&guard)?;
        drop(guard);

        let result = baluard_core::crypto::webauthn::run_provider_registration(
            &origin_url,
            request_json,
            client_data_json,
            client_data_hash,
            user_verified,
            &index,
        )
        .await?;

        let ceremony_id = hex::encode(rand::random::<[u8; 32]>());
        self.ceremony_cache
            .insert(
                ceremony_id.clone(),
                CeremonyState::ProviderRegistration {
                    passkey_data: Box::new(result.passkey_data.clone()),
                    rp_id: result.rp_id.clone(),
                    user_name: result.user_name.clone(),
                    created_at: std::time::Instant::now(),
                },
            )
            .await;

        Ok(serde_json::json!({
            "ceremony_id": ceremony_id,
            "attestation_response": serde_json::from_str::<serde_json::Value>(
                &result.attestation_response,
            )
            .unwrap_or_default(),
            "rp_id": result.rp_id,
            "credential_id": result.credential_id_b64,
            "user_name": result.user_name,
        })
        .to_string())
    }

    /// Run a provider assertion ceremony for one selected credential.
    /// Returns `{ ceremony_id, assertion_response, new_counter }`.
    pub async fn passkey_provider_assert(
        &self,
        request_json: &str,
        origin: &str,
        credential_id: &str,
        client_data_json_b64: Option<&str>,
        client_data_hash_b64: Option<&str>,
        user_verified: bool,
    ) -> Result<String, String> {
        use base64::Engine;

        self.ceremony_cache.evict_expired().await;
        let origin_url = url::Url::parse(origin).map_err(|e| format!("Invalid origin: {e}"))?;
        let decode_b64 = |b64: Option<&str>| match b64.filter(|s| !s.is_empty()) {
            Some(s) => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s.trim_end_matches('='))
                .map(Some)
                .map_err(|_| "client data is not valid base64url".to_string()),
            None => Ok(None),
        };
        let client_data_json = decode_b64(client_data_json_b64)?;
        let client_data_hash = decode_b64(client_data_hash_b64)?;

        let guard = self.inner.read().await;
        let index = self.vault_passkey_index(&guard)?;
        drop(guard);

        let result = baluard_core::crypto::webauthn::run_provider_assertion(
            &origin_url,
            request_json,
            credential_id,
            client_data_json,
            client_data_hash,
            user_verified,
            &index,
        )
        .await?;

        let ceremony_id = hex::encode(rand::random::<[u8; 32]>());
        self.ceremony_cache
            .insert(
                ceremony_id.clone(),
                CeremonyState::ProviderAssertion {
                    cipher_id: result.cipher_id,
                    credential_id: result.credential_id_b64.clone(),
                    new_counter: result.new_counter,
                    created_at: std::time::Instant::now(),
                },
            )
            .await;

        Ok(serde_json::json!({
            "ceremony_id": ceremony_id,
            "assertion_response": serde_json::from_str::<serde_json::Value>(
                &result.assertion_response,
            )
            .unwrap_or_default(),
            "new_counter": result.new_counter,
        })
        .to_string())
    }

    /// Consume a pending provider registration: file the credential into the
    /// chosen existing Login (`cipher_id`) or a new one built from
    /// `new_login` (`{name, username?, uri?}`; uri defaults to
    /// `https://<rp_id>`). Pending state lives only Rust-side, so nothing
    /// client-supplied can choose the key material.
    pub async fn passkey_store_registered(
        &self,
        ceremony_id: &str,
        cipher_id: Option<&str>,
        new_login: Option<&str>,
    ) -> Result<String, String> {
        // Peek-validate-then-remove: a locked vault or malformed input must
        // not consume the pending ceremony (the fresh passkey exists only in
        // this cache; losing it here would lock the user out of the RP).
        let state = self
            .ceremony_cache
            .get(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        let (pk_data, rp_id) = match &state {
            CeremonyState::ProviderRegistration {
                passkey_data: boxed_pk,
                rp_id,
                ..
            } => ((&**boxed_pk).clone(), rp_id.clone()),
            _ => return Err("Expected a provider registration ceremony".into()),
        };
        {
            let guard = self.inner.read().await;
            let handle = guard
                .as_ref()
                .ok_or("Vault is locked. Unlock first.".to_string())?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
        }
        let parsed_cipher_id = match cipher_id.filter(|s| !s.is_empty()) {
            Some(id_str) => {
                Some(uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?)
            }
            None => None,
        };
        let new_login_value: Option<serde_json::Value> = match new_login.filter(|s| !s.is_empty()) {
            Some(s) => {
                Some(serde_json::from_str(s).map_err(|e| format!("Invalid new_login: {e}"))?)
            }
            None => None,
        };

        // Consume the ceremony; values from the peeked clone stay valid (a
        // concurrent consumer would have made remove() return None here).
        self.ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony expired during validation")?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;

        if let Some(id) = parsed_cipher_id {
            // (existing-cipher append below holds the write guard throughout)
            use baluard_core::vault::handle::CipherRead;
            let cipher = match handle.get_cipher(id) {
                Ok(CipherRead::Decrypted(c)) => c,
                _ => return Err("Cipher not found".into()),
            };
            match &cipher.kind {
                baluard_core::types::CipherKind::Login(data) => {
                    let mut list = data.fido2_credentials.clone().unwrap_or_default();
                    list.push(pk_data.clone());
                    let mut updated = data.clone();
                    updated.fido2_credentials = Some(list);
                    let input = baluard_core::types::CipherInput {
                        name: cipher.name.clone(),
                        folder_id: cipher.folder_id,
                        collection_id: None,
                        favorite: cipher.favorite,
                        reprompt: cipher.reprompt,
                        tags: cipher.tags.clone(),
                        kind: baluard_core::types::CipherKind::Login(updated),
                        notes: cipher.notes.clone(),
                        custom_fields: cipher.custom_fields.clone(),
                        created_at: Some(cipher.created_at),
                        password_history: cipher.password_history.clone(),
                        attachments: cipher.attachments.clone(),
                        archived: cipher.archived,
                    };
                    drop(cipher);
                    handle
                        .update_cipher(id, &input)
                        .map_err(|e| e.to_string())?;
                    return Ok(serde_json::json!({
                        "cipher_id": id.to_string(),
                        "credential_id": pk_data.credential_id,
                    })
                    .to_string());
                }
                _ => return Err("Not a Login cipher".into()),
            }
        }

        // New login. Rides the state-layer add path so family/org vaults get
        // the member add-routing defaults instead of a flat admin-only write.
        let login: serde_json::Value = new_login_value.unwrap_or_else(|| serde_json::json!({}));
        let name = login["name"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| pk_data.rp_name.clone().unwrap_or_else(|| rp_id.clone()));
        let username = login["username"].as_str().map(|s| s.to_string());
        let uri = login["uri"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("https://{}", pk_data.rp_id));
        let input = baluard_core::types::CipherInput {
            name,
            folder_id: None,
            collection_id: None,
            favorite: false,
            reprompt: false,
            tags: vec!["passkey".to_string()],
            kind: baluard_core::types::CipherKind::Login(baluard_core::types::LoginData {
                username,
                uris: vec![baluard_core::types::LoginUri {
                    uri,
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
        let payload = serde_json::to_string(&input).map_err(|e| format!("Serialize error: {e}"))?;
        drop(guard);
        let cipher_id = self.add_cipher(&payload).await.map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "cipher_id": cipher_id,
            "credential_id": pk_data.credential_id,
        })
        .to_string())
    }

    /// Consume a pending provider assertion. Synced-model counters stay zero,
    /// so this is normally a no-op; a nonzero counter is written back to the
    /// credential (max of stored and observed).
    pub async fn passkey_consume_assertion(&self, ceremony_id: &str) -> Result<String, String> {
        let state = self
            .ceremony_cache
            .remove(ceremony_id)
            .await
            .ok_or("Ceremony not found or expired")?;
        let (cipher_id, credential_id, new_counter) = match &state {
            CeremonyState::ProviderAssertion {
                cipher_id,
                credential_id,
                new_counter,
                ..
            } => (*cipher_id, credential_id.clone(), *new_counter),
            _ => return Err("Expected a provider assertion ceremony".into()),
        };
        if new_counter == 0 {
            return Ok(serde_json::json!({ "recorded": 0 }).to_string());
        }

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        use baluard_core::vault::handle::CipherRead;
        let cipher = match handle.get_cipher(cipher_id) {
            Ok(CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found".into()),
        };
        match &cipher.kind {
            baluard_core::types::CipherKind::Login(data) => {
                let mut list = data.fido2_credentials.clone().unwrap_or_default();
                let found = list.iter_mut().find(|pk| pk.credential_id == credential_id);
                let Some(pk) = found else {
                    return Err(format!("Credential not found: {credential_id}"));
                };
                if new_counter > pk.counter {
                    pk.counter = new_counter;
                }
                let recorded = pk.counter;
                let mut updated = data.clone();
                updated.fido2_credentials = Some(list);
                let input = baluard_core::types::CipherInput {
                    name: cipher.name.clone(),
                    folder_id: cipher.folder_id,
                    collection_id: None,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    tags: cipher.tags.clone(),
                    kind: baluard_core::types::CipherKind::Login(updated),
                    notes: cipher.notes.clone(),
                    custom_fields: cipher.custom_fields.clone(),
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history.clone(),
                    attachments: cipher.attachments.clone(),
                    archived: cipher.archived,
                };
                drop(cipher);
                handle
                    .update_cipher(cipher_id, &input)
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "recorded": recorded }).to_string())
            }
            _ => Err("Not a Login cipher".into()),
        }
    }

    /// Fetch a favicon for a given domain/URI.
    ///
    /// Origin-first pipeline (Bitwarden-style, but site-before-Google:
    /// the site only sees one anonymous hit and Google is only consulted
    /// when the site publishes no icon):
    /// 1. `https://{domain}/favicon.ico`, then `.png`, then `.jpg`
    /// 2. scrape the page for `<link rel*="icon">` targets
    /// 3. Google's favicon service as last resort
    ///
    /// Every hop passes an SSRF guard: private, loopback, link-local and
    /// CGNAT addresses are refused by name and by DNS resolution, and
    /// redirects must stay https + public. Payload: plain string (domain
    /// or full URI). Returns JSON `{data, mime}` or empty string when
    /// disabled or nothing was found.
    pub async fn fetch_favicon(&self, payload: &str) -> Result<String, String> {
        // Check if favicon fetching is enabled. No open (or locked) vault
        // fails closed: the fetch never runs on a stale opt-in.
        {
            let guard = self.inner.read().await;
            let Some(handle) = guard.as_ref() else {
                return Ok(String::new());
            };
            if !handle.is_unlocked() {
                return Ok(String::new());
            }
            let settings = handle.get_settings().map_err(|e| format!("{e}"))?;
            // H7 fix: default-off. Only fetch when explicitly enabled.
            if !matches!(settings.fetch_favicons, Some(true)) {
                return Ok(String::new());
            }
        }

        // Extract domain from payload (could be full URI or bare domain)
        let domain = Self::extract_domain(payload.trim());
        if domain.is_empty() || !Self::host_fetchable_str(&domain) {
            return Ok(String::new());
        }
        if !Self::host_resolves_public(&domain).await {
            return Ok(String::new());
        }

        let client = match Self::build_icon_client() {
            Some(c) => c,
            None => return Ok(String::new()),
        };

        // Overall deadline: a dead network must not stall the caller for
        // the full sum of per-request timeouts (~40s sequential worst
        // case). 12s covers the happy path (DNS + one 200 probe) with
        // room for one fallback.
        let crawl = async {
            // 1-3. Well-known static paths, cheapest probes first.
            for path in Self::STATIC_ICON_PATHS {
                let url = format!("https://{domain}{path}");
                if let Some(icon) = Self::try_fetch_icon(&client, &url).await {
                    return Some(icon);
                }
            }

            // 4. Scrape the page for <link rel="...icon..."> targets.
            for url in Self::scrape_icon_links(&client, &domain).await {
                if let Some(icon) = Self::try_fetch_icon(&client, &url).await {
                    return Some(icon);
                }
            }

            // 5. Google's favicon service, last resort.
            Self::try_fetch_icon(&client, &Self::favicon_url(&domain)).await
        };
        match tokio::time::timeout(std::time::Duration::from_secs(12), crawl).await {
            Ok(Some(icon)) => Ok(icon),
            _ => Ok(String::new()),
        }
    }

    /// Well-known favicon paths, in probe order. favicon.ico stays first:
    /// it is by far the most common.
    const STATIC_ICON_PATHS: [&'static str; 3] = ["/favicon.ico", "/favicon.png", "/favicon.jpg"];

    /// Shared HTTP client for icon fetching: short timeout, https-only
    /// redirects, and every redirect hop re-checked against the plain-name
    /// SSRF guard so a redirect cannot bounce into localhost or a private
    /// range by name. (DNS is re-checked per candidate host by
    /// [Self::host_resolves_public]; redirect hops to a public name that
    /// resolves privately are out of scope for a client-side fetcher.)
    fn build_icon_client() -> Option<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() > 5 {
                    return attempt.error("too many redirects");
                }
                let url = attempt.url();
                if url.scheme() != "https"
                    || !Self::host_fetchable_str(url.host_str().unwrap_or(""))
                {
                    return attempt.stop();
                }
                attempt.follow()
            }))
            .build()
            .ok()
    }

    /// One icon GET: returns base64 JSON when the response looks like a
    /// supported image, None otherwise (a miss means the caller tries the
    /// next candidate). Size cap keeps a misbehaving endpoint from pushing
    /// a huge blob into the cipher envelope.
    async fn try_fetch_icon(client: &reqwest::Client, url: &str) -> Option<String> {
        let resp = client.get(url).send().await.ok()?;
        // Cap before buffering: content-length lies get the response
        // dropped instead of read into memory.
        if let Some(len) = resp.content_length() {
            if len > 16_384 {
                return None;
            }
        }
        let data = resp.bytes().await.ok()?;
        if data.len() < 4 || data.len() > 16_384 || !Self::looks_like_image(&data) {
            return None;
        }
        let mime = if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            "image/png"
        } else if data[0] == 0xFF {
            "image/jpeg"
        } else if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP" {
            "image/webp"
        } else {
            "image/x-icon"
        };
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
        Some(serde_json::json!({"data": b64, "mime": mime}).to_string())
    }

    fn looks_like_image(data: &[u8]) -> bool {
        data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) // PNG
            || data.starts_with(&[0xFF, 0xD8, 0xFF]) // JPEG
            || data.starts_with(&[0x00, 0x00, 0x01, 0x00]) // ICO
            || data.starts_with(b"RIFF") // WEBP
    }

    /// Plain-name SSRF guard: rejects trivially internal targets —
    /// localhost, dot-less LAN names, and private/loopback/link-local/CGNAT
    /// IP literals. Public IP literals pass; DNS results are re-checked in
    /// [Self::host_resolves_public].
    fn host_fetchable_str(host: &str) -> bool {
        let h = host.trim().trim_end_matches('.');
        let h = h.trim_start_matches('[').trim_end_matches(']');
        if h.is_empty() || !h.contains('.') {
            return false;
        }
        // Non-standard IP encodings (octal 0177.0.0.1, hex 0x7f.0.0.1):
        // IpAddr::parse rejects them, the OS resolver accepts them. A
        // zero-padded all-numeric label or any 0x label means the "host"
        // is an encoded address, not a domain — refuse. Also covers the
        // pure-decimal form via the dot check.
        let looks_encoded = h.split('.').any(|part| {
            part.starts_with("0x")
                || part.starts_with("0X")
                || (part.len() > 1
                    && part.starts_with('0')
                    && part.chars().all(|c| c.is_ascii_digit()))
        });
        if looks_encoded {
            return false;
        }
        match h.parse::<std::net::IpAddr>() {
            Ok(ip) => !Self::ip_is_blocklisted(ip),
            Err(_) => true,
        }
    }

    /// DNS-layer guard: EVERY resolved address must be public. Resolution
    /// failure fails closed.
    async fn host_resolves_public(host: &str) -> bool {
        let h = host.to_string();
        tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            match (h.as_str(), 443u16).to_socket_addrs() {
                Ok(mut addrs) => addrs.all(|addr| !Self::ip_is_blocklisted(addr.ip())),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Refuse address ranges that must never be contacted by a favicon
    /// fetch: loopback, private, link-local, CGNAT (Tailscale and
    /// friends), multicast/reserved, and IPv4-mapped IPv6 forms.
    fn ip_is_blocklisted(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => matches!(
                v4.octets(),
                [0, ..] // this-network
                    | [10, ..] // private
                    | [127, ..] // loopback
                    | [169, 254, ..] // link-local
                    | [172, 16..=31, ..] // private
                    | [192, 168, ..] // private
                    | [100, 64..=127, ..] // CGNAT
                    | [192, 0, 0, _] // IETF protocol assignments
                    | [198, 18..=19, ..] // benchmarking
                    | [224..=255, ..] // multicast + reserved
            ),
            std::net::IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    return Self::ip_is_blocklisted(std::net::IpAddr::V4(mapped));
                }
                v6.is_loopback()
                    || matches!(v6.segments(), [0xfe80..=0xfebf, ..]) // link-local
                    || matches!(v6.segments(), [0xfc00..=0xfdff, ..]) // ULA
                    || v6.is_unspecified()
            }
        }
    }

    /// Fetch the site's landing page and extract `<link rel*="icon">`
    /// targets, best-first: regular icons before apple-touch variants.
    /// Bounded: pages over 256KB are skipped, at most 3 candidate URLs
    /// come back, and every candidate must be https + fetchable by name.
    async fn scrape_icon_links(client: &reqwest::Client, domain: &str) -> Vec<String> {
        let page_url = format!("https://{domain}/");
        let resp = match client.get(&page_url).send().await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        if body.len() > 262_144 {
            return Vec::new();
        }
        let html = String::from_utf8_lossy(&body);
        let base = match url::Url::parse(&page_url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let mut plain: Vec<String> = Vec::new();
        let mut apple: Vec<String> = Vec::new();
        for (href, is_apple) in Self::icon_hrefs(&html) {
            if plain.len() + apple.len() >= 3 {
                break;
            }
            let Ok(absolute) = base.join(&href) else {
                continue;
            };
            if absolute.scheme() != "https" {
                continue;
            }
            // Scraped targets are attacker-influenced content: the host
            // must pass the plain-name guard AND resolve public (Review
            // finding #1 — a dotted name like internal.corp passes the
            // name guard but must never be fetched).
            let Some(host) = absolute.host_str() else {
                continue;
            };
            if !Self::host_fetchable_str(host) || !Self::host_resolves_public(host).await {
                continue;
            }
            if is_apple {
                apple.push(absolute.to_string());
            } else {
                plain.push(absolute.to_string());
            }
        }
        plain.extend(apple);
        plain
    }

    /// Hand-rolled `<link>` scan: no HTML parser dependency. Returns
    /// (href, is_apple_touch) pairs in document order for tags whose rel
    /// contains "icon". Attribute values are read from the ORIGINAL text;
    /// only the matching uses a length-preserving lowercased copy.
    fn icon_hrefs(html: &str) -> Vec<(String, bool)> {
        // Comments first, removed from BOTH strings with identical ranges
        // so the lower/orig byte alignment survives. A <link> inside
        // <!-- --> is markup debris, never a live tag.
        let (html, lower) = Self::strip_comments(html);
        let mut out = Vec::new();
        let mut cursor = 0;
        while let Some(found) = lower[cursor..].find("<link") {
            let tag_start = cursor + found;
            let Some(tag_end) = lower[tag_start..].find('>') else {
                break;
            };
            let tag = &lower[tag_start..=tag_start + tag_end];
            let orig = &html[tag_start..=tag_start + tag_end];
            cursor = tag_start + tag_end + 1;
            let Some(rel_val) = Self::tag_attr(tag, orig, "rel") else {
                continue;
            };
            if !rel_val.contains("icon") {
                continue;
            }
            let Some(href) = Self::tag_attr(tag, orig, "href") else {
                continue;
            };
            let href = href.trim();
            if href.is_empty() {
                continue;
            }
            out.push((href.to_string(), rel_val.contains("apple")));
        }
        out
    }

    /// Removes <!-- --> comments from [html] and returns the cleaned
    /// original plus its length-preserving lowercase twin, byte-aligned.
    fn strip_comments(html: &str) -> (String, String) {
        let lower = html.to_ascii_lowercase();
        let mut cleaned = String::with_capacity(html.len());
        let mut cleaned_lower = String::with_capacity(html.len());
        let mut cursor = 0;
        while let Some(found) = lower[cursor..].find("<!--") {
            let start = cursor + found;
            let rest = &lower[start..];
            match rest.find("-->") {
                Some(len) => {
                    cleaned.push_str(&html[cursor..start]);
                    cleaned_lower.push_str(&lower[cursor..start]);
                    cursor = start + len + 3;
                }
                None => break,
            }
        }
        cleaned.push_str(&html[cursor..]);
        cleaned_lower.push_str(&lower[cursor..]);
        (cleaned, cleaned_lower)
    }

    /// Best-effort attribute reader: `name="v"`, `name='v'`, `name=v`.
    /// Attribute NAMES are matched case-insensitively on [tag_lower];
    /// VALUES are sliced from [tag_orig] so their case survives. The two
    /// strings must be byte-aligned slices of the same tag. Slicing is
    /// boundary-checked: a non-boundary offset (cannot happen with the
    /// ASCII-lowercase invariant, but must never panic) yields None.
    fn tag_attr(tag_lower: &str, tag_orig: &str, name: &str) -> Option<String> {
        for quote in ['"', '\''] {
            let pat = format!("{name}={quote}");
            if let Some(p) = tag_lower.find(&pat) {
                let start = p + pat.len();
                let rest = &tag_lower[start..];
                let end = rest.find(quote).unwrap_or(rest.len());
                return tag_orig.get(start..start + end).map(str::to_string);
            }
        }
        let pat = format!("{name}=");
        if let Some(p) = tag_lower.find(&pat) {
            let start = p + pat.len();
            let rest = &tag_lower[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '>')
                .unwrap_or(rest.len());
            return tag_orig.get(start..start + end).map(str::to_string);
        }
        None
    }

    /// Build the favicon-service URL with the domain percent-encoded as a
    /// query value. Audit C20: the previous raw `format!` let a domain
    /// containing '&' or '=' inject extra query parameters into the request.
    fn favicon_url(domain: &str) -> String {
        let mut url = url::Url::parse("https://www.google.com/s2/favicons")
            .expect("static base URL always parses");
        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("sz", "64");
        url.into()
    }

    /// Extract the fetchable host from a URI or bare string: strips
    /// scheme, path/query/fragment, port, and userinfo (@). The host is
    /// kept exactly as entered (www. is NOT stripped): origin probes must
    /// hit the host the entry actually points at — many sites serve no
    /// certificate on the apex.
    fn extract_domain(input: &str) -> String {
        let stripped = input
            .strip_prefix("https://")
            .or_else(|| input.strip_prefix("http://"))
            .unwrap_or(input);

        // Remove path, query, fragment, port, userinfo
        let host = stripped.split('/').next().unwrap_or(stripped);
        let host = host.split('?').next().unwrap_or(host);
        let host = host.rsplit('@').next().unwrap_or(host);
        let host = host.split(':').next().unwrap_or(host);

        host.to_lowercase()
    }

    // ── §4.8-1: sharing surfaces (People + join queue + activity) ──
    // All routes token-gated by the daemon's default-deny gate (none are
    // in TOKEN_EXEMPT_ACTIONS); mutating ones are listed in
    // COVER_MUTATION_ACTIONS so autosync ships the artifacts.

    /// People surface: every member row. Legacy vaults (no member
    /// directory) return an empty list — the UI shows owner-only state.
    pub async fn members_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let members =
            baluard_core::vault::members::list_members(&handle.path).map_err(|e| e.to_string())?;
        // §4.8-3: the viewer's own identity + role gate the UI actions —
        // computed once here, not per row.
        let self_member_id =
            baluard_core::vault::members::member_id_for_device(&handle.path, handle.device_id);
        let your_role = self_member_id
            .as_ref()
            .and_then(|mid| members.iter().find(|m| &m.id == mid))
            .and_then(|m| serde_json::to_value(m.role).ok())
            .and_then(|v| v.as_str().map(str::to_string));
        let rows: Vec<serde_json::Value> = members
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id.to_string(),
                    "display_name": m.display_name,
                    "email": m.email,
                    "role": m.role,
                    "trust": m.trust,
                    "reset": m.reset.is_some(),
                    "removed": m.removed.is_some(),
                    "identity_rotated_at": m.identity_rotated_at,
                    "identity_signing_pubkey": m.identity_signing_pubkey,
                    "is_self": self_member_id == Some(m.id),
                })
            })
            .collect();
        Ok(serde_json::json!({ "members": rows, "your_role": your_role }).to_string())
    }

    /// Member-email wave: the admin corrects a member's self-declared
    /// email. The only writer of the delta-frozen field.
    pub async fn members_set_email(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id = match v["member_id"].as_str().map(uuid::Uuid::parse_str) {
            Some(Ok(id)) => id,
            _ => return Err("missing or malformed 'member_id'".into()),
        };
        let email = v["email"].as_str();
        handle
            .members_set_email(member_id, email)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    /// Mint a one-time invite code for the given role. The pending
    /// invite record ships to the repo via autosync (COVER_MUTATION).
    pub async fn members_invite(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        // Fail closed on role parsing: a typo'd or missing role must NEVER
        // silently become an Editor invite (write seat + keywrap).
        let role = match v["role"].as_str() {
            Some("admin") => baluard_core::vault::members::MemberRole::Admin,
            Some("editor") => baluard_core::vault::members::MemberRole::Editor,
            Some("viewer") => baluard_core::vault::members::MemberRole::Viewer,
            _ => {
                return Err(
                    "invalid or missing 'role'; expected 'admin', 'editor', or 'viewer'".into(),
                );
            }
        };
        let transport_username = v["transport_username"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // S3-4: an optional role template. Present-but-unparseable
        // refuses (fail closed) — silently dropping it would mint an
        // invite with no grants where the admin picked a template. A
        // non-STRING value (number, bool, object) is equally unparseable
        // and refuses too.
        let template_id = match v.get("template_id") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(raw)) if raw.trim().is_empty() => None,
            Some(serde_json::Value::String(raw)) => Some(
                uuid::Uuid::parse_str(raw.trim())
                    .map_err(|_| "invalid 'template_id'; expected a UUID".to_string())?,
            ),
            Some(_) => return Err("invalid 'template_id'; expected a UUID".to_string()),
        };
        // Family-spaces §8: on a family vault an invite without an
        // explicit template carries the family default — Read on the
        // Shared collection — so every join lands with household basics
        // without the admin hand-building a template first.
        let family_shared = {
            let s = handle.get_settings().map_err(|e| e.to_string())?;
            if baluard_core::vault::space::read_purpose(&handle.path)
                == baluard_core::vault::space::SpacePurpose::Family
            {
                s.family_shared_collection
            } else {
                None
            }
        };
        let code = match template_id {
            Some(template_id) => handle
                .invite_create_with_template(role, transport_username.clone(), template_id)
                .map_err(|e| e.to_string())?,
            None => match family_shared {
                Some(shared_id) => handle
                    .invite_create_with_embedded_grants(
                        role,
                        transport_username.clone(),
                        baluard_core::vault::templates::EmbeddedTemplate {
                            name: "Family member (Shared read)".into(),
                            grants: vec![baluard_core::vault::templates::TemplateGrant {
                                collection_id: shared_id,
                                access: baluard_core::vault::collections::CollectionAccess::Read,
                                expires_in_days: None,
                            }],
                        },
                        // The family default is never a minor invite:
                        // flagged children come from the creation
                        // wizard with per-person grants.
                        false,
                    )
                    .map_err(|e| e.to_string())?,
                None => handle
                    .invite_create(role, transport_username.clone())
                    .map_err(|e| e.to_string())?,
            },
        };
        let vault_id = handle.vault_id;
        // P8c: the seat grant is network I/O — release the exclusive vault
        // lock before touching the forge API so cipher reads/unlock never
        // wait on an HTTP round-trip.
        drop(guard);

        // Grant the read-only transport seat so the joiner can clone.
        // Best-effort: a seat failure never fails the invite — the
        // response reports it and the owner can grant access manually.
        let mut seat_granted = false;
        let mut seat_error: Option<String> = None;
        if let Some(username) = transport_username {
            match self.vault_transport_coords(vault_id) {
                Some((provider, owner, repo)) => {
                    match crate::providers::add_collaborator(
                        provider,
                        &owner,
                        &repo,
                        &username,
                        baluard_core::providers::types::CollaboratorPermission::ReadOnly,
                    )
                    .await
                    {
                        Ok(_) => seat_granted = true,
                        Err(e) => seat_error = Some(e.to_string()),
                    }
                }
                None => {
                    seat_error =
                        Some("vault has no provider remote; grant clone access manually".into())
                }
            }
        }
        Ok(
            serde_json::json!({ "code": code, "seat_granted": seat_granted, "seat_error": seat_error })
                .to_string(),
        )
    }

    /// P8c: the (provider, owner, repo) coordinates of this vault's
    /// remote, resolved from the on-disk registry entry. None = no
    /// provider remote (local-only vault) or an unparseable URL.
    fn vault_transport_coords(
        &self,
        vault_id: uuid::Uuid,
    ) -> Option<(baluard_core::providers::Provider, String, String)> {
        let reg = baluard_core::vault::registry::VaultRegistry::load_locked().ok()?;
        for entry in reg.vaults.values() {
            // Match by VAULT ID: raw path comparison breaks on symlinks
            // and differing path spellings (Fedora /home -> /var/home).
            if entry.vault_id != vault_id {
                continue;
            }
            let provider = match entry.provider.as_deref()? {
                "github" => baluard_core::providers::Provider::GitHub,
                "gitlab" => baluard_core::providers::Provider::GitLab,
                "codeberg" => baluard_core::providers::Provider::Codeberg,
                _ => return None,
            };
            let remote_url = entry.remote_url.clone()?;
            let (owner, repo) = baluard_core::providers::split_owner_repo(provider, &remote_url)?;
            return Some((provider, owner, repo));
        }
        None
    }

    /// §4.8-3: member reset (admin-only, core-gated). Returns the
    /// successor member id and the one-time reset code the admin hands
    /// back to the member out-of-band.
    pub async fn members_reset(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id = uuid::Uuid::parse_str(v["member_id"].as_str().ok_or("missing member_id")?)
            .map_err(|e| e.to_string())?;
        let outcome = handle
            .member_reset(member_id, None)
            .map_err(|e| e.to_string());
        drop(guard);
        if let Err(e) = &outcome {
            // A quorum refusal leaves a pending ask on disk — ship it.
            self.ship_pending_approval().await;
            return Err(e.clone());
        }
        let (successor_id, reset_code) = outcome.unwrap();
        Ok(serde_json::json!({
            "successor_id": successor_id.to_string(),
            "reset_code": reset_code,
        })
        .to_string())
    }

    /// §4.8-3: ownership transfer (owner-only, core-gated).
    pub async fn members_transfer(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id = uuid::Uuid::parse_str(v["member_id"].as_str().ok_or("missing member_id")?)
            .map_err(|e| e.to_string())?;
        let outcome = handle
            .transfer_ownership(member_id)
            .map_err(|e| e.to_string());
        drop(guard);
        if let Err(e) = &outcome {
            self.ship_pending_approval().await;
            return Err(e.clone());
        }
        Ok("{}".into())
    }

    /// §13: an admin claims ownership when the Owner cannot act. The
    /// quorum ask binds both member ids; a refusal ships the ask to
    /// peers so a second admin can confirm the SAME ask by repeating
    /// the claimant's id.
    pub async fn members_claim(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id = uuid::Uuid::parse_str(v["member_id"].as_str().ok_or("missing member_id")?)
            .map_err(|e| e.to_string())?;
        // D61 contest window: snapshot the pending record before the
        // claim so an ARMED window can be told apart from a plain
        // refusal after the call. The arming must surface as success,
        // or the daemon skips the cover commit and the record - the
        // owner's only notice - never syncs.
        let before = handle.ownership_contest_status().ok().flatten();
        let outcome = handle.ownership_claim(member_id).map_err(|e| e.to_string());
        let after = handle.ownership_contest_status().ok().flatten();
        drop(guard);
        match outcome {
            Ok(()) => Ok(serde_json::json!({ "executed": true }).to_string()),
            Err(e) => {
                // Armed iff a record exists after the call, names this
                // ask, and DIFFERS from the before-snapshot (a fresh
                // or superseded window). An unchanged record is the
                // re-touch refusal - still an Err.
                let armed = match &after {
                    Some((old, new, until)) => {
                        *new == member_id
                            && old != new
                            && before
                                .as_ref()
                                .map(|b| b.2 != *until || b.0 != *old || b.1 != *new)
                                .unwrap_or(true)
                    }
                    None => false,
                };
                if armed {
                    // A fresh (or superseded) contest record is on
                    // disk: return success so COVER commits and the
                    // autosync nudge ship the owner's notice.
                    return Ok(serde_json::json!({
                        "armed": true,
                        "window_until": after.as_ref().unwrap().2,
                    })
                    .to_string());
                }
                self.ship_pending_approval().await;
                Err(e)
            }
        }
    }

    /// Screen 6: aggregated actionable notices for the People surface.
    /// Filesystem-derived notices (reset-pending members, stale invites,
    /// malformed join requests) are always current; transport seat checks
    /// run only when `refresh_transport` is true — network I/O, executed
    /// WITHOUT the vault lock (P8c-1 lesson), bounded by client timeouts.
    pub async fn notices_list(&self, payload: &str) -> Result<String, String> {
        let v = serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
        let refresh_transport = v["refresh_transport"].as_bool().unwrap_or(false);

        let (members, invites, malformed, pending_requests, vault_id, collections) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let members = baluard_core::vault::members::list_members(&handle.path)
                .map_err(|e| e.to_string())?;
            let invites = baluard_core::vault::members::list_pending_invites(&handle.path)
                .map_err(|e| e.to_string())?;
            let (requests, malformed) = handle.join_queue_list().map_err(|e| e.to_string())?;
            let pending_requests = requests.len();
            // S3-3 surfacing: pending grant expirations are member-visible
            // (plan line 153) so holidays do not extend contractor access.
            // Read-only here — the rotation itself runs in the admin's
            // unlock sweep; expired-but-unenforced grants are surfaced as
            // their own notice until it lands.
            let collections = handle.collections_list().unwrap_or_default();
            (
                members,
                invites,
                malformed,
                pending_requests,
                handle.vault_id,
                collections,
            )
        };

        let mut notices = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let stale_cutoff = now.saturating_sub(7 * 24 * 3600);

        // Reset-pending members: the notice lives only while the reset
        // chain is ALIVE — the successor exists, is not removed, and has
        // not re-joined (no device binding). A successor removed before
        // re-joining means the admin evicted the re-join path; emitting
        // then would ghost forever (both rows tombstoned, nothing can
        // clear it).
        for m in &members {
            if let Some(reset) = &m.reset {
                let successor = members.iter().find(|s| s.id == reset.successor);
                let chain_alive = successor.map(|s| s.removed.is_none()).unwrap_or(false);
                let devices_dir = self
                    .vault_path
                    .join("meta/members")
                    .join(reset.successor.to_string())
                    .join("devices");
                let rejoined = std::fs::read_dir(&devices_dir)
                    .map(|d| d.count() > 0)
                    .unwrap_or(false);
                if chain_alive && !rejoined {
                    notices.push(serde_json::json!({
                        "kind": "reset_pending",
                        "name": m.display_name,
                    }));
                }
            }
        }
        // Stale invites: GitHub invitations expire after 7 days; an
        // expired one is simply absent server-side, so "likely expired"
        // is the honest framing. Old records without created_at (0) are
        // never treated as stale.
        let stale_count = invites
            .iter()
            .filter(|i| i.created_at != 0 && i.created_at < stale_cutoff)
            .count();
        if stale_count > 0 {
            notices.push(serde_json::json!({
                "kind": "stale_invite",
                "count": stale_count,
            }));
        }
        // Unreadable join requests: inert but worth surfacing.
        if malformed > 0 {
            notices.push(serde_json::json!({
                "kind": "malformed_requests",
                "count": malformed,
            }));
        }

        // Grant expirations (S3-3): expiring within 7 days = act now;
        // expired-but-still-present = the admin client's sweep has not
        // landed yet (it executes at the next admin unlock and
        // converges on pull). Counts only — grant rows live on
        // collections.list.
        let expiring = collections
            .iter()
            .flat_map(|(_, _, grants)| grants.iter())
            .filter(|g| {
                g.expires_at
                    .is_some_and(|e| e > now && e - now <= 7 * 24 * 3600)
            })
            .count();
        if expiring > 0 {
            notices.push(serde_json::json!({
                "kind": "grant_expiring",
                "count": expiring,
            }));
        }
        let expired = collections
            .iter()
            .flat_map(|(_, _, grants)| grants.iter())
            .filter(|g| g.expires_at.is_some_and(|e| e != 0 && e <= now))
            .count();
        if expired > 0 {
            notices.push(serde_json::json!({
                "kind": "grant_expired",
                "count": expired,
            }));
        }

        // Transport seat statuses (optional network; best-effort). §4.5
        // ensure_access_accepted: an expired invitation (GitHub's 7-day
        // window) reads as `None` and is healed by a re-invite with the
        // member's approved permission — surfaced per member so the admin
        // sees who is waiting vs who has access. Tombstoned rows (reset /
        // removed) never get seat checks: their seats were struck at
        // offboarding, and a None must never resurrect their access.
        let mut transport = Vec::new();
        if refresh_transport {
            if let Some((provider, owner, repo)) = self.vault_transport_coords(vault_id) {
                let mut seen = std::collections::BTreeSet::new();
                for m in members.iter() {
                    if m.reset.is_some() || m.removed.is_some() {
                        continue;
                    }
                    // Unbound rows (pending joiners, reset successors
                    // awaiting re-join) are not live members yet: their
                    // seat state is meaningless and a `None` must never
                    // re-invite them ahead of approval — the staging rule
                    // keeps them read-only at best. The reset-pending and
                    // stale-invite notices already cover their wait states.
                    let devices_dir = self
                        .vault_path
                        .join("meta/members")
                        .join(m.id.to_string())
                        .join("devices");
                    let bound = std::fs::read_dir(&devices_dir)
                        .map(|d| d.count() > 0)
                        .unwrap_or(false);
                    if !bound {
                        continue;
                    }
                    // The owner's repo access is structural (they own the
                    // repo); a managed-seat check there only produces forge
                    // errors after an ownership transfer (GitHub 422s the
                    // re-add of a repo owner).
                    if m.role == baluard_core::vault::members::MemberRole::Owner {
                        continue;
                    }
                    let Some(username) = m
                        .transport_username
                        .as_deref()
                        .map(str::trim)
                        .filter(|u| !u.is_empty())
                    else {
                        continue;
                    };
                    if !seen.insert(username.to_string()) {
                        continue;
                    }
                    // Staging rule: viewers stay read-only; editor and
                    // above ride write.
                    let permission = match m.role {
                        baluard_core::vault::members::MemberRole::Viewer => {
                            baluard_core::providers::types::CollaboratorPermission::ReadOnly
                        }
                        _ => baluard_core::providers::types::CollaboratorPermission::Write,
                    };
                    let row = match crate::providers::ensure_access_accepted(
                        provider, &owner, &repo, username, permission,
                    )
                    .await
                    {
                        Ok((status, reinvited)) => serde_json::json!({
                            "username": username,
                            "status": status.to_string(),
                            "reinvited": reinvited,
                        }),
                        Err(e) => serde_json::json!({
                            "username": username,
                            "status": format!("unknown: {e}"),
                        }),
                    };
                    transport.push(row);
                }
            }
        }

        Ok(serde_json::json!({
            "notices": notices,
            "pending_requests": pending_requests,
            "transport": transport,
        })
        .to_string())
    }

    /// D21 read scope: bridge (browser-extension) writes ride the desktop
    /// session's write scope. Legacy vaults (no member directory) are
    /// owner-equivalent. Strict vaults fail closed: Viewer rows and
    /// unbound/pending devices are refused here, where the extension can
    /// show the error — an accepted capture would otherwise wedge at push
    /// time (cipher paths are editor-scope in the policy table).
    pub async fn bridge_write_allowed(&self) -> Result<(), String> {
        let device_id = {
            let guard = self.inner.read().await;
            // The extension treats the literal "locked" as its
            // unlock-prompt state; a lock racing this check (auto-lock
            // walker, focus lock-all) must surface as exactly that.
            let handle = guard.as_ref().ok_or_else(|| "locked".to_string())?;
            handle.device_id
        };
        let members_dir = self
            .vault_path
            .join(baluard_core::vault::members::MEMBERS_DIR);
        if !members_dir.exists() {
            return Ok(()); // legacy personal vault: admin-equivalent
        }
        match baluard_core::vault::members::member_role_for_device(&self.vault_path, device_id) {
            Some(role) if role != baluard_core::vault::members::MemberRole::Viewer => Ok(()),
            Some(_) => Err(
                "You have view-only access to this vault. Entries cannot be saved or changed from the browser extension."
                    .into(),
            ),
            // Unbound on a strict vault = a removed/reset member still
            // holding a session (joiners cannot unlock before approval).
            // Same refusal, wording that fits both.
            None => Err(
                "You do not have permission to save or change entries in this vault.".into(),
            ),
        }
    }

    /// Stage an out-of-band introduction code into the join queue. The
    /// admin received the code from the joiner (chat, email); this is the
    /// consuming step the whole join loop was missing a surface for.
    pub async fn requests_stage(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let intro_code = v["intro_code"]
            .as_str()
            .ok_or("missing intro_code")?
            .trim()
            .to_string();
        // Re-staging the same reply must not pile up dead duplicates: the
        // invite is consumed at approval, so a second request row for the
        // same (invite, device) could never be approved. Idempotent: an
        // already-staged reply returns its existing request id.
        let intro = baluard_core::vault::members::Introduction::decode(&intro_code)
            .map_err(|e| e.to_string())?;
        let (existing, _) = handle.join_queue_list().map_err(|e| e.to_string())?;
        if let Some(row) = existing
            .iter()
            .find(|r| r.invite_id == intro.invite_id && r.device_id == intro.device_id)
        {
            // Retroactive: a row staged before the address-book seed
            // existed still gets the joiner's card on re-stage.
            Self::seed_contact_card(handle, &intro_code)?;
            return Ok(serde_json::json!({ "req_id": row.req_id.to_string() }).to_string());
        }
        // Import BEFORE submit: a failure leaves nothing persisted, so a
        // retry is a clean redo. A card-less introduction (old clients)
        // stages fine.
        Self::seed_contact_card(handle, &intro_code)?;
        let req_id = handle
            .join_queue_submit(&intro_code)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "req_id": req_id.to_string() }).to_string())
    }

    /// Best-effort address-book seed from a staged introduction. Fails only
    /// on real errors (I/O, malformed decode); a card-less introduction
    /// (old clients) is tolerated. Idempotent: upsert never downgrades.
    fn seed_contact_card(
        handle: &mut baluard_core::vault::VaultHandle,
        intro_code: &str,
    ) -> Result<(), String> {
        match handle.contacts_import_intro(intro_code) {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("carries no contact card") {
                    Ok(())
                } else {
                    Err(msg)
                }
            }
        }
    }

    /// Join queue: well-shaped staged requests plus the malformed count.
    pub async fn requests_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let (requests, malformed) = handle.join_queue_list().map_err(|e| e.to_string())?;
        let rows: Vec<serde_json::Value> = requests
            .iter()
            .map(|r| {
                serde_json::json!({
                    "req_id": r.req_id.to_string(),
                    "invite_id": r.invite_id.to_string(),
                    "device_id": r.device_id.to_string(),
                    "display_name": r.display_name,
                    "email": r.email,
                    "secret_ok": r.secret_ok,
                })
            })
            .collect();
        Ok(serde_json::json!({ "requests": rows, "malformed": malformed }).to_string())
    }

    /// Approve a queued request through the standard verification path.
    /// Consumed only on success — refusals stay queued for retry.
    pub async fn requests_approve(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let req_id = uuid::Uuid::parse_str(v["req_id"].as_str().ok_or("missing req_id")?)
            .map_err(|e| e.to_string())?;
        // P8c: read the invite's transport username + role BEFORE the
        // approval consumes it, so the seat can be re-permitted afterwards
        // to match the approved role (viewers stay read-only).
        let (transport_username, invite_role) = {
            let intro = baluard_core::vault::members::read_request(&handle.path, req_id)
                .map_err(|e| e.to_string())?;
            match baluard_core::vault::members::read_pending_invite(&handle.path, intro.invite_id) {
                Ok(pending) => (pending.transport_username, Some(pending.role)),
                Err(_) => (None, None),
            }
        };
        let member_id = handle
            .approve_queued_join(req_id)
            .map_err(|e| e.to_string())?;
        let vault_id = handle.vault_id;
        // P8c: the seat permission follows the APPROVED role (the staging
        // rule: viewers stay read-only; editor and above ride push). Drop
        // the vault lock before the forge API call (network I/O must not
        // block cipher reads or unlock).
        let permission = invite_role.map(|role| match role {
            baluard_core::vault::members::MemberRole::Viewer => {
                baluard_core::providers::types::CollaboratorPermission::ReadOnly
            }
            _ => baluard_core::providers::types::CollaboratorPermission::Write,
        });
        drop(guard);

        let mut seat_upgraded = false;
        if let (Some(username), Some(permission)) = (
            transport_username.filter(|u| !u.trim().is_empty()),
            permission,
        ) {
            if let Some((provider, owner, repo)) = self.vault_transport_coords(vault_id) {
                seat_upgraded = crate::providers::add_collaborator(
                    provider, &owner, &repo, &username, permission,
                )
                .await
                .is_ok();
            }
        }
        Ok(serde_json::json!({
            "member_id": member_id.to_string(),
            "seat_upgraded": seat_upgraded,
        })
        .to_string())
    }

    /// Deny (drop) a queued request.
    pub async fn requests_deny(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let req_id = uuid::Uuid::parse_str(v["req_id"].as_str().ok_or("missing req_id")?)
            .map_err(|e| e.to_string())?;
        handle.deny_queued_join(req_id).map_err(|e| e.to_string())?;
        Ok("{}".into())
    }

    /// P8c-2: offboard members with the transport pre-flight. Each
    /// removed member's provider seat is struck BEFORE the rotation; a
    /// failed strike refuses the removal unless `offline_override` is
    /// explicit (provider outage / offline admin). The strike is network
    /// I/O and runs WITHOUT the vault write lock; only the rotation
    /// itself takes the lock.
    pub async fn members_remove(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let mut ids = Vec::new();
        for x in v["member_ids"].as_array().ok_or("missing member_ids")? {
            let s = x.as_str().ok_or("member id must be a string")?;
            ids.push(uuid::Uuid::parse_str(s).map_err(|e| e.to_string())?);
        }
        let offline_override = v["offline_override"].as_bool().unwrap_or(false);
        self.remove_members_exec(ids, offline_override, "removed")
            .await
    }

    /// Family-spaces §6: file the calling device's departure request.
    /// Any live member may file; the Owner row refuses until ownership
    /// transfers. Idempotent on re-file.
    pub async fn members_leave_file(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let member_id =
            baluard_core::vault::members::file_leave_record(&handle.path, handle.device_id)
                .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "member_id": member_id.to_string() }).to_string())
    }

    /// Pending departures for the admin surfaces (manage-gated).
    /// D61 contest window (family-spaces v1.1): the current owner
    /// cancels a pending ownership claim.
    pub async fn member_contest_cancel(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle
            .ownership_contest_cancel()
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "cancelled": true }).to_string())
    }

    /// Pending ownership-claim contest (owner-device notice surface).
    pub async fn member_contest_status(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle
            .assert_can_manage_members()
            .map_err(|e| e.to_string())?;
        let pending = handle
            .ownership_contest_status()
            .map_err(|e| e.to_string())?;
        Ok(match pending {
            Some((old, new, until)) => serde_json::json!({
                "pending": true,
                "old_owner_id": old.to_string(),
                "new_owner_id": new.to_string(),
                "window_until": until,
            })
            .to_string(),
            None => serde_json::json!({"pending": false}).to_string(),
        })
    }

    pub async fn members_leave_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle
            .assert_can_manage_members()
            .map_err(|e| e.to_string())?;
        let pending = baluard_core::vault::members::list_leave_records(&handle.path)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "pending": pending }).to_string())
    }

    /// Execute an approved departure: the standard removal ceremony
    /// (strike, tombstone "left", rotation) plus the family extras —
    /// collection-key rotation for every collection the leaver could
    /// open, a kit re-issue whose new phrase returns exactly once, and
    /// a refusal while the leaver still owns the transport repo.
    pub async fn members_leave_approve(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id = uuid::Uuid::parse_str(v["member_id"].as_str().ok_or("missing member_id")?)
            .map_err(|e| e.to_string())?;
        let offline_override = v["offline_override"].as_bool().unwrap_or(false);

        // Pre-flight under a READ lock: the record must still be live,
        // the actor must manage, the repo must not be the leaver's, and
        // the collections to rotate are captured BEFORE the removal
        // prunes the leaver's grants.
        let (_vault_id, rotate_ids, had_kit) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            handle
                .assert_can_manage_members()
                .map_err(|e| e.to_string())?;
            if !baluard_core::vault::members::leave_record_exists(&handle.path, member_id) {
                return Err("No pending departure for that member.".into());
            }
            // Repo ownership: the seat coordinate owner IS the leaver's
            // transport username -> migration must come first or the
            // vault's transport dies with their account.
            let vault_id = handle.vault_id;
            if let Some((_, username)) =
                baluard_core::vault::members::member_file_by_id(&handle.path, member_id)
                    .map(|m| ((), m.transport_username.clone()))
            {
                if let (Some(username), Some((_, owner, _))) = (
                    username.filter(|u| !u.trim().is_empty()),
                    self.vault_transport_coords(vault_id),
                ) {
                    if username.eq_ignore_ascii_case(&owner) {
                        return Err(
                            "This member owns the vault's repository. Move it to your own account first (vault migration), then approve the departure."
                                .into(),
                        );
                    }
                }
            }
            let leaver_collections = Self::leaver_openable_collections(handle, member_id)?;
            // Only a guardian's departure forces the kit re-issue: a
            // child leaving must not stage a doomed two-admin ask.
            let leaver_is_guardian =
                baluard_core::vault::members::member_file_by_id(&handle.path, member_id)
                    .map(|m| {
                        matches!(
                            m.role,
                            baluard_core::vault::members::MemberRole::Owner
                                | baluard_core::vault::members::MemberRole::Admin
                        )
                    })
                    .unwrap_or(false);
            let had_kit = leaver_is_guardian
                && baluard_core::vault::recovery_kit::kit_exists(&handle.path)
                    .map_err(|e| e.to_string())?;
            (vault_id, leaver_collections, had_kit)
        };
        let drop_ids = rotate_ids;

        // The removal ceremony (strike + tombstone "left" + rotation).
        let mut report = self
            .remove_members_exec(vec![member_id], offline_override, "left")
            .await?;
        let mut parsed: serde_json::Value =
            serde_json::from_str(&report).map_err(|e| e.to_string())?;

        // Family extras under a fresh write lock: rotate every
        // collection the leaver could open (the CK survives the Root
        // Key rotation — S3-7c) and re-issue the kit (the old phrase
        // unwraps the fresh Root Key until replaced).
        // The removal has already executed, so failures cannot abort.
        // They surface in the response instead of vanishing:
        // `rotation_failed` lists collections still keyed for the
        // leaver, and `kit_reissue_failed` says the old phrase must be
        // treated as live until a re-issue succeeds.
        let mut kit_phrase = None;
        let mut rotation_failed: Vec<String> = Vec::new();
        let mut kit_reissue_failed: Option<String> = None;
        {
            let mut guard = self.inner.write().await;
            let handle = guard.as_mut().ok_or("Vault is locked")?;
            if handle.is_unlocked() {
                for cid in &drop_ids {
                    if let Err(e) = handle.collection_rotate_key(*cid, Some(member_id)) {
                        rotation_failed.push(format!("{cid}: {e}"));
                    }
                }
                if had_kit {
                    match handle.space_recovery_kit_enable() {
                        Ok(phrase) => kit_phrase = Some(phrase),
                        Err(e) => kit_reissue_failed = Some(e.to_string()),
                    }
                }
            }
        }
        {
            let guard = self.inner.read().await;
            if let Some(handle) = guard.as_ref() {
                baluard_core::vault::members::consume_leave_record(&handle.path, member_id);
            }
        }
        if let Some(obj) = parsed.as_object_mut() {
            obj.insert("reason".into(), serde_json::Value::String("left".into()));
            obj.insert(
                "collections_rotated".into(),
                serde_json::json!(drop_ids.len() - rotation_failed.len()),
            );
            if !rotation_failed.is_empty() {
                obj.insert("rotation_failed".into(), serde_json::json!(rotation_failed));
            }
            if let Some(p) = kit_phrase {
                obj.insert("new_kit_phrase".into(), serde_json::Value::String(p));
            }
            if let Some(e) = kit_reissue_failed {
                obj.insert("kit_reissue_failed".into(), serde_json::Value::String(e));
            }
        }
        report = parsed.to_string();
        Ok(report)
    }

    /// Collections `member_id` could open pre-removal. An Admin (or the
    /// Owner) holds the SGK, and resolve_ck unwraps ANY collection key
    /// from it, so their openable set is ALL collections regardless of
    /// grants (ADR 0086 section 6). Everyone else: any grant
    /// row that names them directly or through a group, EXPIRED ONES
    /// INCLUDED: an expired grant still decrypts until a sweep rotates,
    /// and the departure must prune the dead row either way.
    fn leaver_openable_collections(
        handle: &baluard_core::vault::VaultHandle,
        member_id: uuid::Uuid,
    ) -> Result<Vec<uuid::Uuid>, String> {
        let role = baluard_core::vault::members::member_file_by_id(&handle.path, member_id)
            .map(|row| row.role);
        let is_admin = matches!(
            role,
            Some(baluard_core::vault::members::MemberRole::Owner)
                | Some(baluard_core::vault::members::MemberRole::Admin)
        );
        if is_admin {
            return Ok(handle
                .collections_list()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|(id, _, _)| id)
                .collect());
        }
        let groups: std::collections::HashSet<uuid::Uuid> = handle
            .groups_list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(_, _, members)| members.contains(&member_id))
            .map(|(id, _, _)| id)
            .collect();
        let mut out = Vec::new();
        for (cid, _, grants) in handle.collections_list().map_err(|e| e.to_string())? {
            let openable = grants.iter().any(|g| match &g.target {
                baluard_core::vault::collections::GrantTarget::Member { id } => *id == member_id,
                baluard_core::vault::collections::GrantTarget::Group { id } => groups.contains(id),
            });
            if openable {
                out.push(cid);
            }
        }
        Ok(out)
    }

    /// Replacement grants for a reset successor: the same openable set
    /// the departure ceremony captures, but with the member's real
    /// access levels so the replacement invite restores what the child
    /// had (family-spaces section 8). Admins ride the SGK, so their
    /// cosmetic re-grants come back as Read.
    #[allow(clippy::type_complexity)]
    fn replacement_grants_for_member(
        handle: &baluard_core::vault::VaultHandle,
        member_id: uuid::Uuid,
    ) -> Result<
        Vec<(
            uuid::Uuid,
            baluard_core::vault::collections::CollectionAccess,
        )>,
        String,
    > {
        use baluard_core::vault::collections::{CollectionAccess, GrantTarget};
        use baluard_core::vault::members::MemberRole;
        let role = baluard_core::vault::members::member_file_by_id(&handle.path, member_id)
            .map(|row| row.role);
        if matches!(role, Some(MemberRole::Owner) | Some(MemberRole::Admin)) {
            return Ok(handle
                .collections_list()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|(id, _, _)| (id, CollectionAccess::Read))
                .collect());
        }
        let groups: std::collections::HashSet<uuid::Uuid> = handle
            .groups_list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(_, _, members)| members.contains(&member_id))
            .map(|(id, _, _)| id)
            .collect();
        let rank = |a: &CollectionAccess| match a {
            CollectionAccess::Read => 0,
            CollectionAccess::Write => 1,
            CollectionAccess::Manage => 2,
        };
        let mut best: std::collections::HashMap<uuid::Uuid, CollectionAccess> =
            std::collections::HashMap::new();
        for (cid, _, grants) in handle.collections_list().map_err(|e| e.to_string())? {
            for g in &grants {
                let hit = match &g.target {
                    GrantTarget::Member { id } => *id == member_id,
                    GrantTarget::Group { id } => groups.contains(id),
                };
                if hit
                    && best
                        .get(&cid)
                        .map(|b| rank(b) < rank(&g.access))
                        .unwrap_or(true)
                {
                    best.insert(cid, g.access);
                }
            }
        }
        Ok(best.into_iter().collect())
    }

    /// Shared removal executor: pre-flight under a read lock, provider
    /// strikes (bounded, overridable), then the rotation under the
    /// write lock with the caller's tombstone reason.
    async fn remove_members_exec(
        &self,
        ids: Vec<uuid::Uuid>,
        offline_override: bool,
        reason: &str,
    ) -> Result<String, String> {
        // Pre-flight capture under a READ lock: authorization, batch
        // validation, and the seats to strike — via the SAME precheck
        // member_remove runs, so strikes can never happen for an
        // unauthorized caller or an invalid batch (a Viewer must not be
        // able to strip a member's repo access).
        let (vault_id, usernames) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let outcome = handle
                .member_remove_precheck(&ids)
                .map_err(|e| e.to_string());
            let vault_id = handle.vault_id;
            drop(guard);
            if let Err(e) = &outcome {
                // Quorum refusal: the pending ask must reach the other
                // admins before anything else can happen.
                self.ship_pending_approval().await;
                return Err(e.clone());
            }
            (vault_id, outcome.unwrap())
        };

        // Strike seats before the rotation. A failure refuses the whole
        // removal unless the admin explicitly overrides: a removed member
        // keeping push access is worse than delaying the offboarding.
        let mut seats_struck = Vec::new();
        let mut seat_failures = Vec::new();
        if !usernames.is_empty() {
            if let Some((provider, owner, repo)) = self.vault_transport_coords(vault_id) {
                for username in &usernames {
                    // P8c-2 review: the strike is bounded even if the
                    // provider client hangs — an unbounded call would
                    // wedge the route forever.
                    let strike =
                        crate::providers::remove_collaborator(provider, &owner, &repo, username);
                    match tokio::time::timeout(std::time::Duration::from_secs(20), strike).await {
                        Ok(Ok(())) => seats_struck.push(username.clone()),
                        Ok(Err(e)) => seat_failures.push(format!("{username}: {e}")),
                        Err(_) => {
                            seat_failures.push(format!("{username}: provider strike timed out"))
                        }
                    }
                }
            }
            if !seat_failures.is_empty() && !offline_override {
                return Err(format!(
                    "provider seat removal failed ({}); the offboarding was NOT run. Retry, or repeat with offline_override to remove anyway.",
                    seat_failures.join("; ")
                ));
            }
        }

        // The rotation: local crypto + git only, under the write lock.
        let report = {
            let mut guard = self.inner.write().await;
            let handle = guard.as_mut().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            handle
                .member_remove_with_reason(&ids, reason)
                .map_err(|e| e.to_string())?
        };
        // P8c-2 review: a member added between the pre-flight and the
        // rotation would be offboarded with a seat no one struck —
        // surface the gap for the notices surface instead of hiding it.
        let mut unstruck_seats: Vec<String> = report
            .transport_usernames
            .iter()
            .filter(|u| {
                !seats_struck.contains(u)
                    && !seat_failures
                        .iter()
                        .any(|f| f.starts_with(format!("{u}: ").as_str()))
            })
            .cloned()
            .collect();
        unstruck_seats.extend(seat_failures.clone());
        Ok(serde_json::json!({
            "removed": report.removed_members,
            "new_epoch": report.new_epoch,
            "seats_struck": seats_struck,
            "unstruck_seats": unstruck_seats,
        })
        .to_string())
    }

    /// Activity surface: the sharing event log (human sentences),
    /// newest last.
    pub async fn activity_events(&self, payload: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
        let limit = v["limit"].as_u64().unwrap_or(100).min(500) as usize;
        let events = handle.share_events(limit).map_err(|e| e.to_string())?;
        let rows: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "seq": e.seq,
                    "at": e.at,
                    "kind": e.kind,
                    "detail": e.detail,
                })
            })
            .collect();
        serde_json::to_string(&rows).map_err(|e| e.to_string())
    }

    /// Activity surface: this device's local refusal log lines.
    pub async fn activity_refusals(&self, payload: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault is locked")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
        let limit = v["limit"].as_u64().unwrap_or(50).min(200) as usize;
        let lines = handle.refusal_log(limit);
        serde_json::to_string(&lines).map_err(|e| e.to_string())
    }

    /// Family-spaces §3: the collections where `member_id` may write —
    /// own unexpired Write+ grants plus Write+ grants through the
    /// member's groups. Sorted and deduped so the caller's
    /// zero/one/many decision is deterministic.
    fn family_writable_collections(
        handle: &baluard_core::vault::VaultHandle,
        _member_id: uuid::Uuid,
    ) -> Result<Vec<uuid::Uuid>, String> {
        // Member devices resolve their writables through the member-side
        // listing: it folds direct AND group grants via plaintext
        // memberships and needs no SGK (groups_list refuses on member
        // devices, so a grant-table scan can never work here). Members
        // are the only callers of this helper — admins take the
        // type-based routing branch above.
        // Rank floor: grants scope WHERE an editor writes but never lift
        // a viewer's rank, so a viewer's writable set is empty no matter
        // what its grants say (the floor is enforced again at write time).
        if matches!(
            baluard_core::vault::members::member_role_for_device(&handle.path, handle.device_id),
            Some(baluard_core::vault::members::MemberRole::Viewer)
        ) {
            return Ok(Vec::new());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = std::collections::BTreeSet::new();
        for row in handle.my_collections_list().map_err(|e| e.to_string())? {
            let unexpired = row.expires_at.map(|e| e > now).unwrap_or(true);
            if unexpired
                && matches!(
                    row.access,
                    baluard_core::vault::collections::CollectionAccess::Write
                        | baluard_core::vault::collections::CollectionAccess::Manage
                )
            {
                out.insert(row.collection_id);
            }
        }
        Ok(out.into_iter().collect())
    }

    // ── founding.rs copy accessors (family-spaces step 8b) ──
    // The copy flow reads decrypted ciphers out of one open vault and
    // re-adds them into another through the ordinary add path. These
    // accessors keep VaultState.inner private while exposing exactly
    // the two operations the copy needs.

    pub(crate) async fn read_decrypted_for_copy(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<baluard_core::types::Cipher>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Source vault is not open")?;
        if !handle.is_unlocked() {
            return Err("Source vault is locked. Unlock it first.".into());
        }
        Ok(match handle.get_cipher(id) {
            Ok(CipherRead::Decrypted(c)) => Some(*c),
            Ok(CipherRead::Locked(_)) => {
                return Err("Source vault is locked. Unlock it first.".into());
            }
            Err(baluard_core::error::BaluardError::Vault(
                baluard_core::error::VaultError::CipherNotFound(_),
            )) => None,
            Err(e) => return Err(e.to_string()),
        })
    }

    pub(crate) async fn list_cipher_ids_for_copy(&self) -> Result<Vec<uuid::Uuid>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Source vault is not open")?;
        if !handle.is_unlocked() {
            return Err("Source vault is locked. Unlock it first.".into());
        }
        Ok(handle
            .list_cipher_meta()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| m.id)
            .collect())
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

        // S3-7c / 4.8: collection_id in the payload routes the create
        // straight into the collection dir (the member path — flat
        // creation refuses on granted members, so there is no
        // create-then-move window).
        let collection_id = match input.collection_id {
            Some(id) => Some(id),
            // Family-spaces §3 add-cipher defaults: on a family vault an
            // unfiled entry lands somewhere shareable instead of the
            // admin-only flat namespace. Logins and notes go to Shared;
            // sensitive types (cards, identities, bank accounts, licenses,
            // passports, SSH keys) stay admin-only by default. A member
            // (non-admin) cannot write flat at all, so their unfiled
            // create routes to their single Write-granted collection —
            // the per-person collection — and refuses when zero or
            // several qualify, asking them to pick explicitly. The gate
            // is the FLIPPED SHAPE, not is_space: pair Spaces are
            // unflipped (and can never flip), so their editors hold the
            // root key and must keep writing flat — an is_space gate
            // broke them with the guardian refusal (found by review).
            None if baluard_core::vault::space_meta::shape_flipped(&handle.path) => {
                let actor_role = baluard_core::vault::members::member_role_for_device(
                    &handle.path,
                    handle.device_id,
                );
                let is_admin = matches!(
                    actor_role,
                    Some(baluard_core::vault::members::MemberRole::Owner)
                        | Some(baluard_core::vault::members::MemberRole::Admin)
                );
                if is_admin {
                    match input.kind {
                        baluard_core::types::CipherKind::Login(_)
                        | baluard_core::types::CipherKind::SecureNote => handle
                            .get_settings()
                            .ok()
                            .and_then(|s| s.family_shared_collection),
                        _ => None,
                    }
                } else {
                    let member_id = actor_role.and_then(|_| {
                        baluard_core::vault::members::member_file_for_device(
                            &handle.path,
                            handle.device_id,
                        )
                        .map(|(_, row)| row.id)
                    });
                    let Some(member_id) = member_id else {
                        return Err("Join the vault before adding entries.".to_string());
                    };
                    let writable = Self::family_writable_collections(handle, member_id)?;
                    match writable.as_slice() {
                        [only] => Some(*only),
                        [] => {
                            return Err(
                                "No collection is open for your edits. Ask a guardian to grant one, then file this entry there."
                                    .to_string(),
                            );
                        }
                        // Step 8c sugar: with several writables, the
                        // guardian-designated default wins when the
                        // member can still write it (it is in the
                        // writable set by construction here only if
                        // granted - check explicitly).
                        _ => match handle
                            .get_settings()
                            .ok()
                            .and_then(|s| s.default_add_collection)
                        {
                            Some(d) if writable.contains(&d) => Some(d),
                            _ => return Err(
                                "Several collections accept your edits. Pick one for this entry."
                                    .to_string(),
                            ),
                        },
                    }
                }
            }
            other => other,
        };
        let cipher_id = handle
            .add_cipher_in_collection(&input, collection_id)
            .map_err(|e| format!("{e}"))?;
        let _ = handle.rebuild_tag_index();

        Ok(cipher_id.to_string())
    }

    /// S2 IS-3: export a cipher as a one-shot item package for a
    /// contact (address-book lookup by identity signing pubkey, hex).
    /// Returns base64 package file bytes.
    pub async fn export_item_package(
        &self,
        cipher_id: &str,
        contact_pubkey: &str,
    ) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let contact = handle
            .contacts_list()
            .map_err(|e| format!("{e}"))?
            .into_iter()
            .find(|entry| entry.card.identity_signing_pubkey == contact_pubkey)
            .ok_or_else(|| "That person is not in your contacts.".to_string())?;
        let bytes = handle
            .export_item_package(cid, &contact.card)
            .map_err(|e| format!("{e}"))?;
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// S2 IS-3: open an item package and import the item as a fresh
    /// entry. Returns `{id, sender}`.
    pub async fn import_item_package(&self, package_b64: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let trimmed = package_b64.trim();
        if trimmed.len() > baluard_core::vault::packages::MAX_PACKAGE_FILE_BYTES * 2 {
            return Err("Shared file too large.".to_string());
        }
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|_| "Not a valid shared file.".to_string())?;
        let (cipher_id, sender) = handle
            .import_item_package(&bytes)
            .map_err(|e| format!("{e}"))?;
        let _ = handle.rebuild_tag_index();

        Ok(serde_json::json!({
            "id": cipher_id.to_string(),
            "sender": sender,
        })
        .to_string())
    }

    /// S2 IS-6 contact-key flavor: seal a Login's reveal fields to a
    /// contact. Returns the base64 reveal file.
    pub async fn export_contact_reveal(
        &self,
        cipher_id: &str,
        contact_pubkey: &str,
        expires_at: u64,
        include_totp: bool,
    ) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let contact = handle
            .contacts_list()
            .map_err(|e| format!("{e}"))?
            .into_iter()
            .find(|entry| entry.card.identity_signing_pubkey == contact_pubkey)
            .ok_or_else(|| "That person is not in your contacts.".to_string())?;
        let bytes = handle
            .export_contact_reveal(cid, &contact.card, expires_at, include_totp)
            .map_err(|e| format!("{e}"))?;
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// S2 IS-6 passphrase-guest flavor: seal a Login's reveal fields
    /// under an app-generated passphrase. Returns `{reveal, passphrase}`;
    /// the passphrase travels by voice, never beside the file.
    pub async fn export_guest_reveal(
        &self,
        cipher_id: &str,
        expires_at: u64,
        include_totp: bool,
    ) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let (bytes, passphrase) = handle
            .export_guest_reveal(cid, expires_at, include_totp)
            .map_err(|e| format!("{e}"))?;
        use base64::Engine as _;
        Ok(serde_json::json!({
            "reveal": base64::engine::general_purpose::STANDARD.encode(bytes),
            "passphrase": passphrase,
        })
        .to_string())
    }

    /// S2 IS-6: open a contact-key reveal with this vault's identity.
    /// Read-only: nothing is added to the vault. Returns the
    /// [`OpenedReveal`] JSON (TOTP seed never crosses IPC; only the
    /// current code).
    pub async fn open_contact_reveal(&self, reveal_b64: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let trimmed = reveal_b64.trim();
        if trimmed.len() > baluard_core::vault::reveals::MAX_REVEAL_FILE_BYTES * 2 {
            return Err("That file is too large to be a shared item.".to_string());
        }
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|_| "Not a valid shared file.".to_string())?;
        let opened = handle
            .open_contact_reveal(&bytes)
            .map_err(|e| format!("{e}"))?;
        serde_json::to_string(&opened).map_err(|e| format!("{e}"))
    }

    // ── S2 UI wave: address book (contact cards + trust dial) ──

    /// List the address book for the contacts manager. The verification
    /// code rides along so the UI can run the Level 2 code check.
    pub async fn contacts_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard
            .as_ref()
            .ok_or("Vault is locked. Unlock first.".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let rows: Vec<serde_json::Value> = handle
            .contacts_list()
            .map_err(|e| format!("{e}"))?
            .into_iter()
            .map(|entry| {
                serde_json::json!({
                    "display_name": entry.card.display_name,
                    "identity_signing_pubkey": entry.card.identity_signing_pubkey,
                    "has_wrap_key": !entry.card.identity_wrap_pubkey.is_empty(),
                    "trust": entry.trust,
                    "verification_code": entry.card.verification_code(),
                    "updated_at": entry.updated_at,
                })
            })
            .collect();
        Ok(serde_json::json!({ "contacts": rows }).to_string())
    }

    /// Export this device's signed contact card (URL-safe base64 code)
    /// plus its verification code for the Level 2 check.
    pub async fn my_contact_card(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard
            .as_ref()
            .ok_or("Vault is locked. Unlock first.".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let card = handle.contact_card_signed().map_err(|e| format!("{e}"))?;
        let code = base64::engine::general_purpose::URL_SAFE
            .encode(serde_json::to_vec(&card).map_err(|e| format!("{e}"))?);
        Ok(serde_json::json!({
            "card": code,
            "verification_code": card.card.verification_code(),
        })
        .to_string())
    }

    /// Import an out-of-band contact card code. The signature is
    /// verified against the card's own identity key; the entry lands at
    /// Channel until the code check. Payload: `{card}`.
    pub async fn contacts_import_card(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let card = v["card"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or("Missing card in payload".to_string())?;
        let mut guard = self.inner.write().await;
        let handle = guard
            .as_mut()
            .ok_or("Vault is locked. Unlock first.".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;
        let trust = handle
            .contacts_import_card(card)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "trust": trust }).to_string())
    }

    /// Record the Level 2 code check. Payload:
    /// `{identity_signing_pubkey}`.
    pub async fn contacts_mark_verified(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let pubkey = v["identity_signing_pubkey"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or("Missing identity_signing_pubkey in payload".to_string())?;
        let mut guard = self.inner.write().await;
        let handle = guard
            .as_mut()
            .ok_or("Vault is locked. Unlock first.".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;
        handle
            .contacts_mark_verified(pubkey)
            .map_err(|e| format!("{e}"))?;
        Ok("{}".to_string())
    }

    /// Remove a contact from the address book. Payload:
    /// `{identity_signing_pubkey}`. Local dial state only — nothing the
    /// contact already received is affected.
    pub async fn contacts_remove(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let pubkey = v["identity_signing_pubkey"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or("Missing identity_signing_pubkey in payload".to_string())?;
        let mut guard = self.inner.write().await;
        let handle = guard
            .as_mut()
            .ok_or("Vault is locked. Unlock first.".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        Self::ensure_managing_device(self.vault_path.as_path(), handle.device_id).await?;
        handle.contacts_remove(pubkey).map_err(|e| format!("{e}"))?;
        Ok("{}".to_string())
    }

    // ── S2 IS-4b: per-recipient outboxes (live mirror) ──

    /// Publish (or re-publish) a cipher into a recipient's outbox
    /// folder. The contact is resolved from the address book by
    /// signing-pubkey hex.
    pub async fn outbox_publish(
        &self,
        outbox_path: &str,
        cipher_id: &str,
        contact_pubkey: &str,
    ) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let contact = handle
            .contacts_list()
            .map_err(|e| format!("{e}"))?
            .into_iter()
            .find(|entry| entry.card.identity_signing_pubkey == contact_pubkey)
            .ok_or_else(|| "That person is not in your contacts.".to_string())?;
        let report = handle
            .outbox_publish(std::path::Path::new(outbox_path), cid, &contact.card)
            .map_err(|e| format!("{e}"))?;
        serde_json::to_string(&report).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_unpublish(
        &self,
        outbox_path: &str,
        cipher_id: &str,
    ) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let report = handle
            .outbox_unpublish(std::path::Path::new(outbox_path), cid)
            .map_err(|e| format!("{e}"))?;
        serde_json::to_string(&report).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_revoke(&self, outbox_path: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        handle
            .outbox_revoke(std::path::Path::new(outbox_path))
            .map_err(|e| format!("{e}"))
    }

    pub async fn outbox_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let rows = handle.outbox_list().map_err(|e| format!("{e}"))?;
        // Content keys stay in the sealed registry; never over IPC.
        let mut json = serde_json::to_value(&rows).map_err(|e| format!("{e}"))?;
        if let Some(arr) = json.as_array_mut() {
            for row in arr {
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("content_key_hex");
                }
            }
        }
        serde_json::to_string(&json).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_link(&self, outbox_path: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let link = handle
            .outbox_link(std::path::Path::new(outbox_path))
            .map_err(|e| format!("{e}"))?;
        // The content key stays in the sealed links file; it never
        // crosses IPC.
        let mut json = serde_json::to_value(&link).map_err(|e| format!("{e}"))?;
        if let Some(obj) = json.as_object_mut() {
            obj.remove("content_key_hex");
        }
        serde_json::to_string(&json).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_links(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let links = handle.outbox_links().map_err(|e| format!("{e}"))?;
        // Strip content keys from the IPC surface (F6: raw symmetric
        // keys must not cross the socket).
        let mut json = serde_json::to_value(&links).map_err(|e| format!("{e}"))?;
        if let Some(arr) = json.as_array_mut() {
            for row in arr {
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("content_key_hex");
                }
            }
        }
        serde_json::to_string(&json).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_forget(&self, outbox_id: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let id = uuid::Uuid::parse_str(outbox_id).map_err(|_| "Invalid outbox ID.".to_string())?;
        handle.outbox_forget(id).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_read(&self, outbox_id: &str, cipher_id: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let oid = uuid::Uuid::parse_str(outbox_id).map_err(|_| "Invalid outbox ID.".to_string())?;
        let cid = uuid::Uuid::parse_str(cipher_id).map_err(|_| "Invalid item ID.".to_string())?;
        let opened = handle.outbox_read(oid, cid).map_err(|e| format!("{e}"))?;
        serde_json::to_string(&opened).map_err(|e| format!("{e}"))
    }

    pub async fn outbox_entries(&self, outbox_id: &str) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let oid = uuid::Uuid::parse_str(outbox_id).map_err(|_| "Invalid outbox ID.".to_string())?;
        let rows = handle
            .outbox_list_entries(oid)
            .map_err(|e| format!("{e}"))?;
        serde_json::to_string(&rows).map_err(|e| format!("{e}"))
    }

    /// Move a cipher into (or out of) a collection's scoped directory
    /// (plan P5). Admin-agnostic by design: the core refuses writes the
    /// actor has no write scope for, and the vault gate stays the
    /// session unlock.
    pub async fn cipher_set_collection(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked".to_string());
        }
        let parsed: serde_json::Value = serde_json::from_str(payload)
            .map_err(|_| "Invalid cipher assignment JSON".to_string())?;
        let cipher_id = parsed["cipher_id"].as_str().unwrap_or("");
        let collection_raw = parsed.get("collection_id");
        let cid: Option<uuid::Uuid> = match collection_raw {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(x)) if x.is_empty() => None,
            Some(serde_json::Value::String(x)) => Some(
                uuid::Uuid::parse_str(x)
                    .map_err(|_| "That collection id is not valid.".to_string())?,
            ),
            _ => return Err("That collection id is not valid.".to_string()),
        };
        let cipher_id = cipher_id
            .parse::<uuid::Uuid>()
            .map_err(|_| "That entry id is not valid.".to_string())?;
        handle
            .assign_cipher_to_collection(cipher_id, cid)
            .map_err(|e| format!("{e}"))?;
        Ok("{}".to_string())
    }

    /// S3-3: on-demand admin sweep (drop expired grants + rotate their
    /// collection keys). Admin-gated in core; this wrapper is the route
    /// surface.
    pub async fn collections_sweep(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let removed = handle.collections_sweep().map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "removed": removed.len() }).to_string())
    }

    // ── S3-7a: Space Meta Key groundwork ──
    // Both routes token-gated by the daemon's default-deny gate;
    // space.prepare rides COVER_MUTATION_ACTIONS so autosync ships the
    // store + wraps.

    /// Mint (or idempotently refresh) the SMK store + per-member wraps.
    /// Admin-gated at the core layer.
    pub async fn space_prepare(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let report = handle.space_prepare().map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "smk_fresh": report.smk_fresh,
            "wrapped": report.wrapped,
            "missing_wrap_pubkey": report
                .missing_wrap_pubkey
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        })
        .to_string())
    }

    /// Readiness counts for the Team-shape flip. Admin-gated at the
    /// core layer.
    pub async fn space_status(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let st = handle.space_status().map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "prepared": st.prepared,
            "wrapped": st.wrapped,
            "missing_wrap_pubkey": st.missing_wrap_pubkey,
            "pending_wrap": st.pending_wrap,
            "flipped": baluard_core::vault::space_meta::shape_flipped(&self.vault_path),
            "needs_rotation": st.needs_rotation,
        })
        .to_string())
    }

    /// S3-7b: flip the vault to team shape (admin, mutating).
    pub async fn space_flip(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let r = handle.space_flip().map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "already_flipped": r.already_flipped,
            "files_reencrypted": r.files_reencrypted,
            "keywraps_removed": r.keywraps_removed,
        })
        .to_string())
    }

    /// S3-7b completion: rotate the Root Key on an admin device. The flip
    /// strips member keywraps at HEAD, but pre-flip members' keywraps in
    /// git history still unwrap the CURRENT root until a rotation bumps
    /// it — the flip surface prompts this immediately after a fresh flip.
    /// Admin rank lives in the core op; the quorum gate lives in the
    /// runtime caller (member_set_role / member_set_minor below).
    /// Family-spaces §5: set or clear the guardian-controlled minor
    /// flag on a live member row (admin-only, family vaults only).
    pub async fn member_set_minor(&self, payload: &str) -> Result<(), String> {
        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let member_id = partial["member_id"]
            .as_str()
            .ok_or("member_id is required")?;
        let minor = partial["minor"]
            .as_bool()
            .ok_or("minor must be a boolean")?;
        let uuid =
            uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member id: {e}"))?;
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle
            .member_set_minor(uuid, minor)
            .map_err(|e| e.to_string())
    }

    /// Role change (admin surface). Quorum-gated like the other member
    /// lifecycle ops: the digest binds member id and target role so two
    /// admins confirming the same change approve one ask.
    pub async fn member_set_role(&self, payload: &str) -> Result<String, String> {
        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let member_id = partial["member_id"]
            .as_str()
            .ok_or("member_id is required")?;
        let role = partial["role"].as_str().ok_or("role is required")?;
        let uuid =
            uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member id: {e}"))?;
        if matches!(role, "owner") {
            return Err("ownership moves via transfer or claim, not a role edit".into());
        }
        let parsed = serde_json::from_value::<baluard_core::vault::members::MemberRole>(
            serde_json::json!(role),
        )
        .map_err(|_| "role must be one of: admin, editor, viewer".to_string())?;
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        if let Err(e) = handle.assert_op_quorum(
            "member_role",
            &serde_json::json!({ "member_id": member_id, "to": role }),
        ) {
            drop(guard);
            self.ship_pending_approval().await;
            return Err(e.to_string());
        }
        handle
            .member_set_role(uuid, parsed)
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    }

    /// Family-spaces §2: record the vault's purpose — `org` from a
    /// personal vault (the flip journey's first step) or `family`
    /// through creation only. Core gates both; the route exists so the
    /// flip UI has a single call.
    pub async fn space_set_purpose(&self, payload: &str) -> Result<(), String> {
        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let purpose = partial["purpose"].as_str().ok_or("purpose is required")?;
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle.space_set_purpose(purpose).map_err(|e| e.to_string())
    }

    pub async fn space_rotate_root(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        handle.rotate_root_key().map_err(|e| e.to_string())?;
        // D78: the autosync coordinator caches the enrollment-proof
        // verifier at activation; rotation invalidates it. Refresh so
        // background pulls accept new-epoch proofs without a relock.
        let enroll_vk = handle.enroll_verify_key();
        drop(guard);
        self.autosync.refresh_enroll_vk(enroll_vk).await;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    /// S4-7: kit surfaces (admin, per the core gate). Enable returns the
    /// 24-word phrase exactly once; disable reports whether a kit
    /// existed; status is a plain boolean.
    pub async fn space_kit_enable(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        // The fixed kit threshold may arm an ask; ship it promptly so the
        // co-admin sees it on the next pull (space_migrate precedent).
        match handle.space_recovery_kit_enable() {
            Ok(phrase) => Ok(serde_json::json!({ "phrase": phrase }).to_string()),
            Err(e) => {
                drop(guard);
                self.ship_pending_approval().await;
                Err(e.to_string())
            }
        }
    }

    pub async fn space_kit_disable(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        match handle.space_recovery_kit_disable() {
            Ok(removed) => Ok(serde_json::json!({ "removed": removed }).to_string()),
            Err(e) => {
                drop(guard);
                self.ship_pending_approval().await;
                Err(e.to_string())
            }
        }
    }

    // ── Legacy Contact (owner side; core protocol in core::legacy) ──

    /// True while this state is a contact's read-only kit view.
    pub fn is_contact_view(&self) -> bool {
        self.contact_view.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Attach an already-unlocked contact view handle and mint its
    /// session token. The daemon route owns the allowlist that keeps
    /// the session read-only.
    pub async fn contact_attach(&self, handle: baluard_core::vault::handle::VaultHandle) {
        let _ = self.finish_unlock_session(handle).await;
        self.mint_session_token().await;
    }

    pub async fn legacy_status(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        super::legacy::status_json(&self.vault_path, handle)
    }

    pub async fn legacy_arm(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        super::legacy::arm_json(&self.vault_path, handle, payload).await
    }

    pub async fn legacy_close(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        super::legacy::close_json(&self.vault_path, handle, payload).await
    }

    pub async fn legacy_resend(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        super::legacy::resend_json(&self.vault_path, handle)
    }

    pub async fn space_kit_status(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let enabled = handle
            .space_recovery_kit_status()
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "enabled": enabled }).to_string())
    }

    /// S3-8: move this vault's sync to a new remote (admin-only). The
    /// announcement lands on the old remote, origin re-points, and the
    /// full history pushes to the new address; every device follows on
    /// its next pull (the engine applies the announcement before each
    /// fetch). Blocking git work runs in spawn_blocking per the sync
    /// rules; the cycle holds the vault write lock so autosync cannot
    /// interleave a second cycle.
    pub async fn space_migrate(&self, payload: &str) -> Result<String, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|_| "Invalid migration payload".to_string())?;
        let new_url = parsed["clone_url"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("Missing clone_url".to_string())?;

        // Admin gate: managing-device check with the legacy founder
        // equivalence (no member directory = admin). Mirrors the gate
        // every other admin surface uses.
        {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let device_id = handle.device_id;
            let members_dir = self
                .vault_path
                .join(baluard_core::vault::members::MEMBERS_DIR);
            if members_dir.exists() {
                match baluard_core::vault::members::member_role_for_device(
                    &self.vault_path,
                    device_id,
                ) {
                    Some(baluard_core::vault::members::MemberRole::Owner)
                    | Some(baluard_core::vault::members::MemberRole::Admin) => {}
                    _ => {
                        return Err(
                            "Only a manager of this space can move its sync address.".into()
                        );
                    }
                }
            }
            // §6.5 quorum_admin_ops: above the default threshold, moving
            // the sync address needs a second admin's confirmation. The
            // digest binds the TRIMMED url only, so two admins spelling
            // the same move differently still approve one ask.
            let gate = handle.assert_op_quorum(
                "space_migrate",
                &serde_json::json!({ "clone_url": new_url }),
            );
            if let Err(e) = gate {
                drop(guard);
                self.ship_pending_approval().await;
                return Err(e.to_string());
            }
        }

        let vault_path = self.vault_path.clone();
        let (device_id_str, devkey_seal) = {
            let g = self.inner.read().await;
            let handle = g.as_ref().ok_or("Vault not opened".to_string())?;
            (handle.device_id.to_string(), handle.devkey_seal())
        };
        let device_id_for_pull = device_id_str.clone();
        // Hold cycle_lock_guard so autosync background pulls and debounce pushes
        // cannot run concurrently while migration rewires git configuration.
        let _cycle = self.autosync.cycle_lock_guard().await;
        let report = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(
                move || -> Result<baluard_core::sync::engine::RemoteMigrateReport, String> {
                    let engine = baluard_core::sync::engine::SyncEngine::new(
                        &vault_path,
                        &device_id_str,
                        devkey_seal.as_ref(),
                    );
                    let repo = engine.open_repo().map_err(|e| format!("open repo: {e}"))?;
                    engine
                        .migrate_remote(&repo, &new_url)
                        .map_err(|e| e.to_string())
                },
            ),
        )
        .await
        .map_err(|_| "remote migration timed out".to_string())?
        .map_err(|e| format!("migration task join: {e}"))??;

        // The autosync coordinator's push bookkeeping points at the old
        // head log; a nudge keeps the next cycle coherent.
        self.autosync.pull_now(device_id_for_pull).await;
        Ok(serde_json::json!({
            "migrated": true,
            "from": report.from,
            "to": report.to,
        })
        .to_string())
    }

    /// S3-8: current sync-address status — the live origin URL, the
    /// announced URL (if a migration pointer is committed), whether
    /// they agree, and whether the current device is a manager. Keyless
    /// reads; unlocked guard keeps the surface consistent with the
    /// other sync views.
    pub async fn space_remote(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let device_id = handle.device_id;
        let members_dir = self
            .vault_path
            .join(baluard_core::vault::members::MEMBERS_DIR);
        let is_manager = if members_dir.exists() {
            matches!(
                baluard_core::vault::members::member_role_for_device(&self.vault_path, device_id),
                Some(baluard_core::vault::members::MemberRole::Owner)
                    | Some(baluard_core::vault::members::MemberRole::Admin)
            )
        } else {
            true
        };
        let vault_path = self.vault_path.clone();
        let (origin, announced) = tokio::task::spawn_blocking(
            move || -> Result<(Option<String>, Option<String>), String> {
                let engine =
                    baluard_core::sync::engine::SyncEngine::new(&vault_path, "status", None);
                let origin = engine.open_repo().ok().and_then(|repo| {
                    repo.find_remote("origin")
                        .ok()
                        .and_then(|r| r.url().map(|s| s.to_string()))
                });
                let announced = baluard_core::sync::engine::read_remote_announcement(&vault_path);
                Ok((origin, announced))
            },
        )
        .await
        .map_err(|e| format!("status task join: {e}"))??;
        Ok(serde_json::json!({
            "origin": origin,
            "announced": announced,
            "pending_follow": announced.is_some() && announced != origin,
            "is_manager": is_manager,
        })
        .to_string())
    }

    // ── S3-9: Space settings (§6.5 foundation knobs) ──

    /// Read the Space policy knobs. Unlocked-gated: settings.enc.
    pub async fn space_settings_get(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let s = handle.get_settings().map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({
            "space_invite_authority": if s.space_invite_authority
                == baluard_core::vault::manifest::InviteAuthority::Owners
            {
                "owners"
            } else {
                "admins"
            },
            "allow_viewer_export": s.allow_viewer_export,
            "guest_enabled": s.guest_enabled == Some(true),
            "trash_policy": if s.trash_policy
                == baluard_core::vault::manifest::TrashPolicy::AdminsOnly
            {
                "admins_only"
            } else {
                "write_scope_can_trash"
            },
            // Exhaustive on purpose: a future variant must be rendered
            // here, never silently stringified as the default.
            "restore_policy": match s.restore_policy {
                baluard_core::vault::manifest::RestorePolicy::AdminsOnly => "admins_only",
            },
            "join_approval": match s.join_approval {
                baluard_core::vault::manifest::JoinApproval::Manual => "manual",
                baluard_core::vault::manifest::JoinApproval::Code => "code",
            },
            // None and Some(1) both render as the default: one admin.
            "personal_merge": s.personal_merge,
            "quorum_admin_ops": s.quorum_admin_ops.unwrap_or(1).max(1),
            "default_add_collection": s.default_add_collection.map(|u| u.to_string()),
            "collection_create_authority": match s.collection_create_authority {
                baluard_core::vault::manifest::CollectionCreateAuthority::Admins => "admins",
                baluard_core::vault::manifest::CollectionCreateAuthority::Editors => "editors",
            },
        })
        .to_string())
    }

    /// Write Space policy knobs (partial). Admin-gated: owner/admin, with
    /// the legacy no-member-directory founder equivalence. Unknown payload
    /// keys are ignored (settings.set convention).
    pub async fn space_settings_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let members_dir = self
            .vault_path
            .join(baluard_core::vault::members::MEMBERS_DIR);
        let allowed = if !members_dir.exists() {
            true // legacy personal vault: the founder manages
        } else {
            matches!(
                baluard_core::vault::members::member_role_for_device(
                    &self.vault_path,
                    handle.device_id
                ),
                Some(baluard_core::vault::members::MemberRole::Owner)
                    | Some(baluard_core::vault::members::MemberRole::Admin)
            )
        };
        if !allowed {
            return Err("Only the owner or an admin can change space settings.".into());
        }
        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let mut settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        if let Some(v) = partial.get("space_invite_authority") {
            let s = v
                .as_str()
                .ok_or("space_invite_authority must be a string")?;
            settings.space_invite_authority = match s {
                "admins" => baluard_core::vault::manifest::InviteAuthority::Admins,
                "owners" => baluard_core::vault::manifest::InviteAuthority::Owners,
                _ => return Err("space_invite_authority must be admins or owners".into()),
            };
        }
        if let Some(v) = partial.get("allow_viewer_export") {
            settings.allow_viewer_export =
                v.as_bool().ok_or("allow_viewer_export must be a boolean")?;
        }
        if let Some(v) = partial.get("guest_enabled") {
            settings.guest_enabled = Some(v.as_bool().ok_or("guest_enabled must be a boolean")?);
        }
        if let Some(v) = partial.get("trash_policy") {
            let s = v.as_str().ok_or("trash_policy must be a string")?;
            settings.trash_policy = match s {
                "write_scope_can_trash" => {
                    baluard_core::vault::manifest::TrashPolicy::WriteScopeCanTrash
                }
                "admins_only" => baluard_core::vault::manifest::TrashPolicy::AdminsOnly,
                _ => return Err("trash_policy must be write_scope_can_trash or admins_only".into()),
            };
        }
        if let Some(v) = partial.get("restore_policy") {
            let s = v.as_str().ok_or("restore_policy must be a string")?;
            settings.restore_policy = match s {
                "admins_only" => baluard_core::vault::manifest::RestorePolicy::AdminsOnly,
                _ => return Err("restore_policy must be admins_only".into()),
            };
        }
        if let Some(v) = partial.get("join_approval") {
            let s = v.as_str().ok_or("join_approval must be a string")?;
            settings.join_approval = match s {
                "manual" => baluard_core::vault::manifest::JoinApproval::Manual,
                "code" => baluard_core::vault::manifest::JoinApproval::Code,
                _ => return Err("join_approval must be manual or code".into()),
            };
        }
        if let Some(v) = partial.get("personal_merge") {
            let b = v.as_bool().ok_or("personal_merge must be a boolean")?;
            settings.personal_merge = Some(b);
        }
        if let Some(v) = partial.get("quorum_admin_ops") {
            // A number below the JSON parse; bools/strings refuse. 1 and
            // absent both mean the default; 2..=5 raise the threshold.
            let n = v.as_u64().ok_or("quorum_admin_ops must be a number")?;
            if !(1..=5).contains(&n) {
                return Err("quorum_admin_ops must be between 1 and 5".into());
            }
            // S4-3 ratchet: lowering the threshold is itself sensitive
            // and is gated at the CURRENT threshold. The knob on disk
            // still holds the old value (the save happens below), so
            // quorum_gate evaluates at the live bar; a genuine lowering
            // always demands >= 2 approvals. Raising stays instant.
            let current = settings.quorum_admin_ops.unwrap_or(1).max(1);
            if (n as u8) < current {
                if let Err(e) =
                    handle.assert_op_quorum("quorum_lower", &serde_json::json!({ "to": n }))
                {
                    drop(guard);
                    self.ship_pending_approval().await;
                    return Err(e.to_string());
                }
            }
            settings.quorum_admin_ops = Some(n as u8);
        }
        if let Some(v) = partial.get("default_add_collection") {
            // Family-spaces step 8c: the guardian-designated member
            // filing default. A UUID string; it must name a collection
            // that exists (admins fix it by setting a new one).
            let s = v
                .as_str()
                .ok_or("default_add_collection must be a UUID string")?;
            let id = uuid::Uuid::parse_str(s)
                .map_err(|_| "default_add_collection must be a UUID string".to_string())?;
            if !handle
                .collections_list()
                .map_err(|e| e.to_string())?
                .iter()
                .any(|(cid, _, _)| *cid == id)
            {
                return Err("default_add_collection names no collection in this vault".into());
            }
            settings.default_add_collection = Some(id);
        }
        if let Some(v) = partial.get("collection_create_authority") {
            let s = v
                .as_str()
                .ok_or("collection_create_authority must be a string")?;
            settings.collection_create_authority = match s {
                "admins" => baluard_core::vault::manifest::CollectionCreateAuthority::Admins,
                "editors" => baluard_core::vault::manifest::CollectionCreateAuthority::Editors,
                _ => return Err("collection_create_authority must be admins or editors".into()),
            };
        }
        handle
            .save_settings(&settings)
            .map_err(|e| format!("{e}"))?;
        // The merge cache must not wait for the next unlock: a ceiling
        // change mid-session is visible to eligibility the moment the
        // save lands (ADR 0098: refreshed at every unlock
        // AND settings pull). Same best-effort contract as unlock.
        let ceiling =
            baluard_core::vault::space::effective_personal_merge(&settings, &self.vault_path);
        if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
            if let Some(slug) = reg.slug_for_path(&self.vault_path) {
                if reg.set_merge_cache(&slug, ceiling).is_ok() {
                    let _ = reg.save_locked();
                }
            }
        }
        Ok(())
    }

    // ── S3-6: request-access JIT ──
    // All routes token-gated by the daemon's default-deny gate; the
    // mutating ones ride COVER_MUTATION_ACTIONS so autosync ships the
    // artifacts.

    /// Pending sensitive-op approvals (§6.5 quorum_admin_ops). Admin
    /// surface: every admin device sees the asks awaiting confirmation.
    pub async fn approvals_pending(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let rows = handle.pending_op_approvals();
        Ok(serde_json::json!({ "pending": rows }).to_string())
    }

    /// Access review (S4-4): the aggregated who-can-see-what report.
    /// Read-only; the core gate refuses non-admins in plain language.
    pub async fn access_review(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let report = handle.access_review().map_err(|e| e.to_string())?;
        Ok(report.to_string())
    }

    /// S4-5: the derived activity timeline (newest-first), admin-gated
    /// in the handle like the access review.
    pub async fn activity_timeline(&self, limit: u64) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let feed = handle
            .activity_timeline(limit.clamp(1, 500) as usize)
            .map_err(|e| e.to_string())?;
        Ok(feed.to_string())
    }

    /// Advisory org policies (S4-6): publish or clear (empty map).
    /// The core gate refuses non-admins in plain language.
    pub async fn policies_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;
        let map = parsed
            .as_object()
            .ok_or("The payload must be an object of policy recommendations.")?
            .clone();
        handle.policies_set(map).map_err(|e| e.to_string())
    }

    /// Advisory org policies (S4-6): read what is published. Any
    /// unlocked device may read; no keys involved. Empty object when
    /// nothing is published.
    pub async fn policies_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let published = handle.policies_list().map_err(|e| e.to_string())?;
        let policies = published
            .and_then(|v| v.get("policies").cloned())
            .unwrap_or_else(|| serde_json::json!({}));
        Ok(serde_json::json!({ "policies": policies }).to_string())
    }

    /// A quorum refusal just wrote (or matched) a pending record on
    /// THIS device. The ask only matters if the other admins ever see
    /// it, so ship it with a best-effort signed sync cycle (commit →
    /// pull → push). Silent on failure: the record stays on disk and
    /// the next successful sync carries it.
    async fn ship_pending_approval(&self) {
        if baluard_core::vault::approvals::list_pending(&self.vault_path).is_empty() {
            return;
        }
        let vault_path = self.vault_path.clone();
        let (device_id, seal, enroll_vk) = {
            let g = self.inner.read().await;
            match g.as_ref() {
                Some(h) if h.is_unlocked() => (
                    h.device_id.to_string(),
                    h.devkey_seal(),
                    h.enroll_verify_key(),
                ),
                _ => return,
            }
        };
        let _ = tokio::time::timeout(
            crate::autosync::SYNC_OP_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let mut engine = baluard_core::sync::engine::SyncEngine::new(
                    &vault_path,
                    &device_id,
                    seal.as_ref(),
                );
                if let Some(vk) = enroll_vk {
                    engine = engine.with_enroll_verify_key(vk);
                }
                if let Ok(repo) = engine.open_repo() {
                    let _ = engine.run_sync_cycle(&repo);
                }
            }),
        )
        .await;
    }

    /// Member side: submit a JIT ask for collection access.
    pub async fn collection_request_access(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let id = v["collection_id"]
            .as_str()
            .ok_or("Missing collection_id in payload")?;
        let collection_id =
            uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid collection_id: {e}"))?;
        let access = Self::parse_request_access(&v)?;
        let note = v["note"].as_str().unwrap_or("");
        let request_id = handle
            .collection_access_request(collection_id, access, note)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "request_id": request_id.to_string() }).to_string())
    }

    /// Fail closed on a mistyped access: an unknown string must never
    /// silently become a write seat (the S3-4 parsing rule).
    fn parse_request_access(
        v: &serde_json::Value,
    ) -> Result<baluard_core::vault::collections::CollectionAccess, String> {
        match v["access"].as_str() {
            Some("read") => Ok(baluard_core::vault::collections::CollectionAccess::Read),
            Some("write") => Ok(baluard_core::vault::collections::CollectionAccess::Write),
            _ => Err("'access' must be \"read\" or \"write\"".into()),
        }
    }

    /// Member side: the caller's own pending asks.
    pub async fn collection_requests_mine(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let rows: Vec<serde_json::Value> = handle
            .my_access_requests()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "collection_id": r.collection_id.to_string(),
                    "access": r.access,
                    "created_at": r.created_at,
                })
            })
            .collect();
        Ok(serde_json::json!({ "requests": rows }).to_string())
    }

    /// Member side: withdraw one of the caller's own pending asks.
    pub async fn collection_requests_withdraw(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let id = v["request_id"]
            .as_str()
            .ok_or("Missing request_id in payload")?;
        let request_id =
            uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid request_id: {e}"))?;
        handle
            .withdraw_access_request(request_id)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "withdrawn": true }).to_string())
    }

    /// Admin side: the decrypted inbox plus the inert-file count.
    pub async fn collection_requests_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let (rows, malformed) = handle.access_requests_inbox().map_err(|e| e.to_string())?;
        let rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "request_id": r.request_id.to_string(),
                    "requester_member_id": r.requester_member_id.to_string(),
                    "requester_name": r.requester_name,
                    "collection_id": r.collection_id.to_string(),
                    "collection_name": r.collection_name,
                    "access": r.access,
                    "note": r.note,
                    "created_at": r.created_at,
                })
            })
            .collect();
        Ok(serde_json::json!({ "requests": rows, "malformed": malformed }).to_string())
    }

    /// Admin side: approve a JIT ask. Optional access override + expiry
    /// are the admin's decision; collection and requester come from the
    /// sealed ask.
    pub async fn collection_requests_approve(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let rid = v["request_id"]
            .as_str()
            .ok_or("Missing request_id in payload")?;
        let request_id =
            uuid::Uuid::parse_str(rid).map_err(|e| format!("Invalid request_id: {e}"))?;
        let mid = v["requester_member_id"]
            .as_str()
            .ok_or("Missing requester_member_id in payload")?;
        let requester_member_id =
            uuid::Uuid::parse_str(mid).map_err(|e| format!("Invalid requester_member_id: {e}"))?;
        let access = match v.get("access") {
            None | Some(serde_json::Value::Null) => None,
            Some(_) => Some(Self::parse_request_access(&v)?),
        };
        // A present-but-mistyped expiry must refuse, not silently become
        // "no expiry" (permanent access).
        let expires_at = match v.get("expires_at") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(n)) => Some(
                n.as_u64()
                    .ok_or("'expires_at' must be a whole number of unix seconds.")?,
            ),
            Some(_) => return Err("'expires_at' must be a whole number of unix seconds.".into()),
        };
        let row = handle
            .approve_access_request(requester_member_id, request_id, access, expires_at)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "approved": true,
            "request_id": row.request_id.to_string(),
            "requester_member_id": row.requester_member_id.to_string(),
            "requester_name": row.requester_name,
            "collection_id": row.collection_id.to_string(),
            "collection_name": row.collection_name,
            "access": row.access,
        })
        .to_string())
    }

    /// Admin side: deny a JIT ask (consume it, grant nothing).
    pub async fn collection_requests_deny(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let rid = v["request_id"]
            .as_str()
            .ok_or("Missing request_id in payload")?;
        let request_id =
            uuid::Uuid::parse_str(rid).map_err(|e| format!("Invalid request_id: {e}"))?;
        let mid = v["requester_member_id"]
            .as_str()
            .ok_or("Missing requester_member_id in payload")?;
        let requester_member_id =
            uuid::Uuid::parse_str(mid).map_err(|e| format!("Invalid requester_member_id: {e}"))?;
        handle
            .deny_access_request(requester_member_id, request_id)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "denied": true }).to_string())
    }

    /// Admin side: publish (or replace/clear) the plaintext catalog.
    pub async fn collection_catalog_set(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        match v.get("entries") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(rows)) => {
                for row in rows {
                    let cid = row["collection_id"]
                        .as_str()
                        .ok_or("'entries[].collection_id' must be a string UUID.")?;
                    let collection_id = uuid::Uuid::parse_str(cid).map_err(|_| {
                        "'entries[].collection_id' must be a string UUID.".to_string()
                    })?;
                    let name = row["name"]
                        .as_str()
                        .ok_or("'entries[].name' must be a string.")?;
                    entries.push(baluard_core::vault::access_requests::CatalogEntry {
                        collection_id,
                        name: name.to_string(),
                    });
                }
            }
            Some(_) => return Err("'entries' must be a list of catalog rows.".into()),
        }
        handle.catalog_publish(entries).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "published": true }).to_string())
    }

    /// Any member: the catalog as requesters see it (empty when
    /// unpublished).
    pub async fn collection_catalog_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        let rows: Vec<serde_json::Value> = handle
            .catalog_entries()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "collection_id": e.collection_id.to_string(),
                    "name": e.name,
                })
            })
            .collect();
        Ok(serde_json::json!({ "catalog": rows }).to_string())
    }

    /// Whether this device manages the space (holds the Root Key).
    /// The precise admin marker: collections_list branches on it, and
    /// unlike counting admin rows it holds for zero-collection vaults.
    /// This device's member role, role-gated surfaces' source of truth.
    /// Personal vaults (no member directory) are "owner" — the founder
    /// manages. Flipped vaults: the row's role, even though admins hold
    /// no Root Key there (isAdminDevice stays the key-holding signal).
    pub async fn my_role(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let members_dir = self.vault_path.join("meta").join("members");
        if !members_dir.is_dir() {
            return Ok("owner".to_string());
        }
        Ok(
            baluard_core::vault::members::member_role_for_device(
                &self.vault_path,
                handle.device_id,
            )
            .map(|r| format!("{r:?}").to_lowercase())
            .unwrap_or_else(|| "owner".to_string()),
        )
    }

    pub async fn is_admin_device(&self) -> Result<bool, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        Ok(handle.holds_root())
    }

    /// Removal-notice check: does THIS device look removed from the
    /// Space? Two signals, strongest first: a local tombstone (the own
    /// member row on disk carries removed/reset — the removal commit
    /// reached this clone before access died) is CONFIRMED; a streak of
    /// consecutive access-denied syncs (the provider seat was struck) is
    /// PROBABLE. Personal vaults (no meta/members) are always none.
    /// Keyless and read-only — the session-token gate is the only guard,
    /// and the answer leaks nothing but a status word.
    pub async fn removal_notice(&self) -> Result<String, String> {
        let members_dir = self.vault_path.join("meta").join("members");
        if !members_dir.is_dir() {
            // Personal vault: no membership, nothing to be removed from.
            return Ok(serde_json::json!({ "status": "none" }).to_string());
        }
        let device = uuid::Uuid::parse_str(&self.device_id().await)
            .map_err(|_| "device identity is not a uuid".to_string())?;
        // Deterministic own-row resolution (review F5): a device can carry
        // a binding to a tombstoned row AND to a live successor row (reset
        // plus same-device re-enrollment), and read_dir order must never
        // decide the answer. Scan every member row bound to this device;
        // liveness wins, otherwise the tombstone kind names the reason.
        let mut bound_live = false;
        let mut bound_tombstone: Option<&'static str> = None;
        if let Ok(rows) = std::fs::read_dir(&members_dir) {
            for entry in rows.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let binding = path
                    .parent()
                    .map(|p| {
                        p.join(stem)
                            .join("devices")
                            .join(format!("{device}.json"))
                            .is_file()
                    })
                    .unwrap_or(false);
                if !binding {
                    continue;
                }
                let row: Option<baluard_core::vault::members::MemberFile> = std::fs::read(&path)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
                let Some(row) = row else { continue };
                if row.removed.is_some() || row.reset.is_some() {
                    // The removal (or reset) commit reached this clone:
                    // confirmed, no guessing needed. Reset keeps its own
                    // reason so the copy can say reset, not removed (F8).
                    bound_tombstone = Some(if row.removed.is_some() {
                        "local-tombstone"
                    } else {
                        "local-reset"
                    });
                } else {
                    bound_live = true;
                }
            }
        }
        if !bound_live {
            if let Some(reason) = bound_tombstone {
                return Ok(serde_json::json!({ "status": "removed", "reason": reason }).to_string());
            }
        }
        let streak = self.autosync.status().await.access_denied_streak;
        if streak >= crate::autosync::ACCESS_DENIED_STREAK_FOR_REMOVAL {
            return Ok(serde_json::json!({
                "status": "probable",
                "reason": "persistent-auth-failures",
                "streak": streak,
            })
            .to_string());
        }
        Ok(serde_json::json!({ "status": "none" }).to_string())
    }

    /// Mint a collection (admin-gated).
    pub async fn collection_create(&self, name: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let id = handle.collection_create(name).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "id": id.to_string() }).to_string())
    }

    pub async fn collections_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        // S3-7c / 4.8: one route, role-aware output. Admins get every
        // collection with the full grant table; members get only what
        // they can open (names via their grant wrap). `access: "admin"`
        // marks the managing side so the UI can gate controls.
        let mut rows: Vec<serde_json::Value> = Vec::new();
        if handle.holds_root() {
            for (id, name, grants) in handle.collections_list().map_err(|e| format!("{e}"))? {
                rows.push(serde_json::json!({
                    "id": id.to_string(),
                    "name": name,
                    "access": "admin",
                    "expires_at": null,
                    "grants": grants.iter().map(|g| serde_json::json!({
                        "kind": match g.target {
                            baluard_core::vault::collections::GrantTarget::Member { .. } => "member",
                            baluard_core::vault::collections::GrantTarget::Group { .. } => "group",
                        },
                        "id": match g.target {
                            baluard_core::vault::collections::GrantTarget::Member { id } => id.to_string(),
                            baluard_core::vault::collections::GrantTarget::Group { id } => id.to_string(),
                        },
                        "access": g.access,
                        "expires_at": g.expires_at,
                    })).collect::<Vec<_>>(),
                }));
            }
        } else {
            for r in handle.my_collections_list().map_err(|e| format!("{e}"))? {
                rows.push(serde_json::json!({
                    "id": r.collection_id.to_string(),
                    "name": r.name,
                    "access": r.access,
                    "expires_at": r.expires_at,
                }));
            }
        }
        Ok(serde_json::json!({ "collections": rows }).to_string())
    }

    /// S3-4: role templates. Create parses {name, role, grants:
    /// [{collection_id, access, expires_in_days?}]} with a fail-closed
    /// role parse (same discipline as members.invite).
    pub async fn templates_create(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let name = v["name"].as_str().unwrap_or_default().trim();
        let role = match v["role"].as_str() {
            Some("admin") => baluard_core::vault::members::MemberRole::Admin,
            Some("editor") => baluard_core::vault::members::MemberRole::Editor,
            Some("viewer") => baluard_core::vault::members::MemberRole::Viewer,
            _ => {
                return Err(
                    "invalid or missing 'role'; expected 'admin', 'editor', or 'viewer'".into(),
                );
            }
        };
        let mut grants = Vec::new();
        // Present-but-mistyped refuses (fail closed); absent means a
        // role-only template with no grants.
        match v.get("grants") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(rows)) => {
                for row in rows {
                    let collection_id = row["collection_id"]
                        .as_str()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                        .ok_or("invalid 'grants[].collection_id'; expected a UUID")?;
                    let access = match row["access"].as_str() {
                        Some("read") => baluard_core::vault::collections::CollectionAccess::Read,
                        Some("write") => baluard_core::vault::collections::CollectionAccess::Write,
                        Some("manage") => {
                            baluard_core::vault::collections::CollectionAccess::Manage
                        }
                        _ => {
                            return Err(
                                "invalid 'grants[].access'; expected 'read', 'write', or 'manage'"
                                    .into(),
                            );
                        }
                    };
                    // A negative or non-integer value must refuse, not
                    // silently become "no expiry" (permanent access).
                    let expires_in_days = match row.get("expires_in_days") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(serde_json::Value::Number(n)) => {
                            let days = n.as_u64().ok_or(
                                "'grants[].expires_in_days' must be a whole number of days.",
                            )?;
                            if days > u32::MAX as u64 {
                                return Err("'grants[].expires_in_days' is too large.".into());
                            }
                            Some(days as u32)
                        }
                        Some(_) => {
                            return Err(
                                "'grants[].expires_in_days' must be a whole number of days.".into(),
                            );
                        }
                    };
                    grants.push(baluard_core::vault::templates::TemplateGrant {
                        collection_id,
                        access,
                        expires_in_days,
                    });
                }
            }
            Some(_) => return Err("'grants' must be a list of collection entries.".into()),
        }
        let t = handle
            .template_create(name, role, grants)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({
            "id": t.id.to_string(),
            "name": t.name,
            "role": t.role,
            "grants": t.grants.iter().map(|g| serde_json::json!({
                "collection_id": g.collection_id.to_string(),
                "access": g.access,
                "expires_in_days": g.expires_in_days,
            })).collect::<Vec<_>>(),
        })
        .to_string())
    }

    pub async fn templates_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let rows: Vec<serde_json::Value> = handle
            .templates_list()
            .map_err(|e| format!("{e}"))?
            .into_iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id.to_string(),
                    "name": t.name,
                    "role": t.role,
                    "grants": t.grants.iter().map(|g| serde_json::json!({
                        "collection_id": g.collection_id.to_string(),
                        "access": g.access,
                        "expires_in_days": g.expires_in_days,
                    })).collect::<Vec<_>>(),
                    "created_at": t.created_at,
                })
            })
            .collect();
        Ok(serde_json::json!({ "templates": rows }).to_string())
    }

    pub async fn template_delete(&self, template_id: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let id = uuid::Uuid::parse_str(template_id)
            .map_err(|_| "That template id is not valid.".to_string())?;
        handle.template_delete(id).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "deleted": true }).to_string())
    }

    pub async fn collection_rename(&self, id: &str, name: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let uuid = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid collection id: {e}"))?;
        handle
            .collection_rename(uuid, name)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn collection_delete(&self, id: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let uuid = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid collection id: {e}"))?;
        handle.collection_delete(uuid).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn collection_grant(
        &self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let uuid = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid collection id: {e}"))?;
        // The target names a member or a group (S4-2): {kind: member|group,
        // target_id}. member_id stays accepted as a member shorthand.
        // "id" remains the collection id everywhere in collections.*.
        let target: baluard_core::vault::collections::GrantTarget = if let Some(kind) =
            payload["kind"].as_str()
        {
            let tid = payload["target_id"]
                .as_str()
                .ok_or("Missing target_id in payload")?;
            let tid = uuid::Uuid::parse_str(tid).map_err(|e| format!("Invalid target_id: {e}"))?;
            match kind {
                "member" => baluard_core::vault::collections::GrantTarget::Member { id: tid },
                "group" => baluard_core::vault::collections::GrantTarget::Group { id: tid },
                other => return Err(format!("Invalid target kind: {other}")),
            }
        } else {
            let member_id = payload["member_id"]
                .as_str()
                .ok_or("Missing member_id in payload")?;
            let member =
                uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member_id: {e}"))?;
            baluard_core::vault::collections::GrantTarget::Member { id: member }
        };
        let access: baluard_core::vault::collections::CollectionAccess =
            serde_json::from_value(payload["access"].clone())
                .map_err(|e| format!("Invalid access: {e}"))?;
        let expires_at = payload["expires_at"].as_u64();
        handle
            .collection_grant(uuid, target, access, expires_at)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn collection_revoke(
        &self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let uuid = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid collection id: {e}"))?;
        let target: baluard_core::vault::collections::GrantTarget = if let Some(kind) =
            payload["kind"].as_str()
        {
            let tid = payload["target_id"]
                .as_str()
                .ok_or("Missing target_id in payload")?;
            let tid = uuid::Uuid::parse_str(tid).map_err(|e| format!("Invalid target_id: {e}"))?;
            match kind {
                "member" => baluard_core::vault::collections::GrantTarget::Member { id: tid },
                "group" => baluard_core::vault::collections::GrantTarget::Group { id: tid },
                other => return Err(format!("Invalid target kind: {other}")),
            }
        } else {
            let member_id = payload["member_id"]
                .as_str()
                .ok_or("Missing member_id in payload")?;
            let member =
                uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member_id: {e}"))?;
            baluard_core::vault::collections::GrantTarget::Member { id: member }
        };
        handle
            .collection_revoke(uuid, target)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    // ── Groups (S4-2) ──

    pub async fn groups_list(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let rows = handle.groups_list().map_err(|e| format!("{e}"))?;
        let groups: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(id, name, members)| {
                serde_json::json!({
                    "id": id.to_string(),
                    "name": name,
                    "members": members.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(serde_json::json!({ "groups": groups }).to_string())
    }

    pub async fn group_create(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        let name = parsed["name"].as_str().ok_or("Missing name in payload")?;
        let id = handle.group_create(name).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "id": id.to_string() }).to_string())
    }

    pub async fn group_rename(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        let id = parsed["id"].as_str().ok_or("Missing id in payload")?;
        let id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid id: {e}"))?;
        let name = parsed["name"].as_str().ok_or("Missing name in payload")?;
        handle.group_rename(id, name).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn group_delete(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        let id = parsed["id"].as_str().ok_or("Missing id in payload")?;
        let id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid id: {e}"))?;
        handle.group_delete(id).map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn group_member_add(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        let id = parsed["id"].as_str().ok_or("Missing id in payload")?;
        let id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid id: {e}"))?;
        let member_id = parsed["member_id"]
            .as_str()
            .ok_or("Missing member_id in payload")?;
        let member_id =
            uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member_id: {e}"))?;
        handle
            .group_member_add(id, member_id)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    pub async fn group_member_remove(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        let id = parsed["id"].as_str().ok_or("Missing id in payload")?;
        let id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid id: {e}"))?;
        let member_id = parsed["member_id"]
            .as_str()
            .ok_or("Missing member_id in payload")?;
        let member_id =
            uuid::Uuid::parse_str(member_id).map_err(|e| format!("Invalid member_id: {e}"))?;
        handle
            .group_member_remove(id, member_id)
            .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({ "ok": true }).to_string())
    }

    /// Live-mirror tick: re-publish every entry in every outbox from
    /// the current cipher state. Idempotent; used by the daemon's
    /// post-CRUD hook and the explicit resync route.
    /// Live-mirror tick: re-publish every entry in every outbox from
    /// the current cipher state. Idempotent; used by the daemon's
    /// post-CRUD hook and the explicit resync route.
    pub async fn outbox_resync(&self) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;
        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let results = handle.outbox_resync_all().map_err(|e| format!("{e}"))?;
        let json: Vec<serde_json::Value> = results
            .into_iter()
            .map(|(id, committed)| {
                serde_json::json!({ "cipher_id": id.to_string(), "committed": committed })
            })
            .collect();
        serde_json::to_string(&json).map_err(|e| format!("{e}"))
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
            collection_id: None,
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

        // Hierarchy path (baluard.vault): parents precede children in the
        // import result, so one pass creates the tree. Same-named siblings
        // already in the vault are reused, empty folders are kept, and a
        // failed folder is reported while its subtree is skipped.
        let mut tree_folder_ids: Vec<Option<uuid::Uuid>> = Vec::new();
        let mut folder_errors: Vec<String> = Vec::new();
        // Folders this import created, for duplicate-in-file reuse: the
        // `existing` snapshot predates the loop.
        let mut created_here: Vec<(String, Option<uuid::Uuid>, uuid::Uuid)> = Vec::new();
        if !import_result.folders.is_empty() {
            let existing = handle.list_folders().unwrap_or_default();
            for f in &import_result.folders {
                // A failed parent's subtree is skipped, never re-rooted:
                // Some(p) with a None result means the parent died above.
                let parent = match f.parent {
                    None => None,
                    Some(p) => match tree_folder_ids.get(p).and_then(|o| *o) {
                        Some(pid) => Some(pid),
                        None => {
                            folder_errors.push(format!(
                                "folder '{}': skipped because its parent could not be created",
                                f.name
                            ));
                            tree_folder_ids.push(None);
                            continue;
                        }
                    },
                };
                let id = existing
                    .iter()
                    .find(|x| x.name == f.name && x.parent_id == parent)
                    .map(|x| x.id)
                    .or_else(|| {
                        created_here
                            .iter()
                            .find(|(n, p, _)| *n == f.name && *p == parent)
                            .map(|(_, _, id)| *id)
                    })
                    .or_else(|| {
                        handle
                            .create_folder_with_parent(&f.name, parent)
                            .map_err(|e| format!("folder '{}': {e}", f.name))
                            .ok()
                    });
                if let Some(id) = id {
                    created_here.push((f.name.clone(), parent, id));
                } else {
                    folder_errors.push(format!("folder '{}': could not be created", f.name));
                }
                tree_folder_ids.push(id);
            }
        }

        let total = import_result.ciphers.len();
        let mut created = 0usize;
        let mut errors = import_result.errors.clone();
        errors.append(&mut folder_errors);

        for (idx, mut cipher) in import_result.ciphers.into_iter().enumerate() {
            // Assign folder_id: the hierarchy path indexes the created tree,
            // the flat path scans the name map.
            if let Some(fi) = import_result.cipher_folders.get(idx).and_then(|o| *o) {
                cipher.folder_id = tree_folder_ids.get(fi).and_then(|o| *o);
            } else {
                let folder_name = import_result
                    .folder_map
                    .iter()
                    .find(|(_, indices)| indices.contains(&idx))
                    .map(|(name, _)| name.clone());
                if let Some(name) = folder_name {
                    cipher.folder_id = folder_id_map.get(&name).copied();
                }
            }

            match handle.add_cipher(&cipher) {
                Ok(_) => created += 1,
                Err(e) => errors.push(format!("Cipher '{}': {e}", cipher.name)),
            }
        }

        let folders_created = if tree_folder_ids.is_empty() {
            folder_id_map.len()
        } else {
            tree_folder_ids.iter().flatten().count()
        };
        let response = serde_json::json!({
            "imported": created,
            "skipped": import_result.skipped + (total - created),
            "folders_created": folders_created,
            "errors": errors,
        });
        Ok(response.to_string())
    }

    /// Export all ciphers as BW-compatible JSON.
    /// Space policy (§6.5 allow_viewer_export, default false): export is
    /// Editor-and-above unless the Space opts its viewers in. Legacy
    /// founders (no member directory) pass. On a strict vault a None
    /// resolution REFUSES: member_role_for_device skips tombstoned rows,
    /// so a removed/reset member's still-open session would otherwise
    /// fall through the catch-all and export (review finding, S3-9).
    fn assert_export_allowed(&self, handle: &VaultHandle) -> Result<(), String> {
        if handle
            .get_settings()
            .map_err(|e| format!("{e}"))?
            .allow_viewer_export
        {
            return Ok(());
        }
        let members_dir = self
            .vault_path
            .join(baluard_core::vault::members::MEMBERS_DIR);
        if !members_dir.exists() {
            return Ok(()); // legacy personal vault: the founder exports
        }
        match baluard_core::vault::members::member_role_for_device(
            &self.vault_path,
            handle.device_id,
        ) {
            Some(baluard_core::vault::members::MemberRole::Viewer) => {
                Err("View-only access cannot export this vault's data.".into())
            }
            Some(_) => Ok(()),
            None => Err("This device can no longer export this vault's data.".into()),
        }
    }

    pub async fn export_bw_json(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        self.assert_export_allowed(handle)?;

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
        self.assert_export_allowed(handle)?;

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

    /// Export the whole vault as a Baluard backup (baluard.vault v1):
    /// full-fidelity JSON in Baluard's own domain model — folders with
    /// hierarchy, tags, re-prompt flags, history and passkey private keys
    /// all survive a roundtrip. Returned string is UNENCRYPTED.
    pub async fn export_backup_json(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }
        self.assert_export_allowed(handle)?;

        let metas = handle.list_cipher_meta_full().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(c)) => ciphers.push(*c),
                Ok(CipherRead::Locked(_)) => continue,
                Err(e) => log::warn!("[export] skipping {}: {e}", meta.id),
            }
        }

        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;
        let folder_tuples: Vec<(uuid::Uuid, String, Option<uuid::Uuid>, Option<String>)> = folders
            .into_iter()
            .map(|f| (f.id, f.name, f.parent_id, f.icon))
            .collect();

        baluard_core::import::baluard_json::export_backup(
            &ciphers,
            &folder_tuples,
            None,
            env!("CARGO_PKG_VERSION"),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    /// Encrypted backup (docs/adr/0099-encrypted-backup.md §7–§8): the same v1
    /// payload inside the passphrase-protected container. The file key
    /// derives ONLY from the passphrase — no vault key material enters the
    /// file — so the result is vault-independent and any Baluard vault can
    /// re-import it under its own keys. Auto-verifies in memory before
    /// returning (re-derives from the passphrase string, so a normalization
    /// bug cannot hide) and yields the entry count for the "checked" toast.
    pub async fn export_backup_encrypted(
        &self,
        passphrase: &str,
    ) -> Result<(Vec<u8>, u32), String> {
        use baluard_core::import::backup_container;
        if passphrase.len() < 8 {
            return Err("Use at least 8 characters for the backup passphrase".to_string());
        }
        // The plaintext JSON holds every secret in the vault: it lives only
        // in zeroized buffers, and the Argon2id + AES work runs on the
        // blocking pool like the unlock path (spawn_blocking per D5).
        let payload = Zeroizing::new(self.export_backup_json().await?);
        let pw = Zeroizing::new(passphrase.to_string());
        tokio::task::spawn_blocking(move || {
            let container =
                backup_container::encrypt(payload.as_bytes(), &pw).map_err(|e| e.to_string())?;
            backup_container::verify(&container, &pw, payload.as_bytes())
                .map_err(|e| e.to_string())?;
            // The manifest count feeds the "Backup checked" toast. A payload
            // that cannot be parsed is an internal bug, never a silent 0.
            let entries = serde_json::from_str::<serde_json::Value>(&payload)
                .map_err(|e| format!("backup manifest unreadable: {e}"))?;
            let entries = entries["manifest"]["cipher_count"]
                .as_u64()
                .ok_or_else(|| "backup manifest unreadable".to_string())?
                as u32;
            Ok((container, entries))
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Decrypt + import an encrypted backup. Wrong passphrase and corruption
    /// are one error by design ("wrong password or damaged file") and reach
    /// the user as a route error, never a skipped-entry summary.
    pub async fn import_backup_encrypted(
        &self,
        passphrase: &str,
        container: &[u8],
    ) -> Result<String, String> {
        use baluard_core::import::backup_container;
        // Argon2id + AES run on the blocking pool (spawn_blocking per D5);
        // the decrypted plaintext stays in its zeroized buffer and is
        // borrowed as &str, never copied out.
        let pw = Zeroizing::new(passphrase.to_string());
        let owned = container.to_vec();
        let payload = tokio::task::spawn_blocking(move || {
            backup_container::decrypt(&owned, &pw).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
        let text = std::str::from_utf8(&payload)
            .map_err(|_| backup_container::ContainerError::Damaged.to_string())?;
        let backup = baluard_core::import::baluard_json::parse_backup(text)?;
        self.import_ciphers(baluard_core::import::baluard_json::backup_to_import(backup))
            .await
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

    /// List cipher metadata for entries that have a TOTP seed (hub card).
    /// Archived entries are excluded: archive hides from lists and search.
    pub async fn list_totp_meta(&self) -> Result<Vec<baluard_core::types::CipherMeta>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut out = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(ref c)) => {
                    if let baluard_core::types::CipherKind::Login(ref data) = c.kind {
                        if data.totp_uri.as_deref().is_some_and(|u| !u.is_empty()) {
                            out.push(meta.clone());
                        }
                    }
                }
                _ => continue,
            }
        }
        Ok(out)
    }

    /// List trashed cipher metadata (Trash view).
    pub async fn list_trash_meta(&self) -> Result<Vec<baluard_core::types::CipherMeta>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        // §4.8-5: trash rows carry their origin collection so the
        // trash view can badge entries correctly.
        let entries = handle.list_trash_entries().map_err(|e| format!("{e}"))?;
        let mut metas = Vec::with_capacity(entries.len());
        for (id, collection_id) in &entries {
            match handle.get_cipher(*id) {
                Ok(CipherRead::Decrypted(ref c)) => {
                    let username = match &c.kind {
                        baluard_core::types::CipherKind::Login(data) => data.username.clone(),
                        _ => None,
                    };
                    let expires_at = match &c.kind {
                        baluard_core::types::CipherKind::SigningKey(data) => data.expires_at,
                        _ => None,
                    };
                    metas.push(baluard_core::types::CipherMeta {
                        id: c.id,
                        name: c.name.clone(),
                        folder_id: c.folder_id,
                        cipher_type: c.kind.cipher_type(),
                        favorite: c.favorite,
                        reprompt: c.reprompt,
                        username,
                        tier: c.tier,
                        key_epoch: c.key_epoch,
                        update_seq: c.update_seq,
                        updated_at: c.updated_at,
                        archived: c.archived,
                        tags: c.tags.clone(),
                        collection_id: *collection_id,
                        expires_at,
                    });
                }
                _ => continue, // undecryptable trash blob: skip
            }
        }
        Ok(metas)
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

        // A side written by a newer app (item schema this build cannot
        // model) must not go through the typed merge: merge and keep_both
        // re-encrypt typed and would strip the newer fields into a merge
        // commit. Same restriction as cross_epoch: only the raw-blob
        // verdicts (keep_local / keep_remote) are offered.
        for (which, bytes) in [
            ("base", &base_bytes),
            ("local", &local_bytes),
            ("remote", &remote_bytes),
        ] {
            if let Ok(schema) = handle.stored_item_schema_bytes(cipher_id, bytes)
                && schema > baluard_core::types::ITEM_SCHEMA_VERSION
            {
                drop(guard);
                return Ok(serde_json::json!({
                    "pending": true,
                    "newer_schema": true,
                    "unreachable_side": which,
                    "count": count,
                })
                .to_string());
            }
        }

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
        // keep_both clones the remote side typed: refuse when this build
        // cannot model it, or the clone silently drops the newer fields.
        // Only the raw-blob verdicts apply (same restriction as the merge
        // gate's newer_schema response).
        for bytes in [&local_bytes, &remote_bytes] {
            if let Ok(schema) = handle.stored_item_schema_bytes(cipher_id, bytes)
                && schema > baluard_core::types::ITEM_SCHEMA_VERSION
            {
                return Err(
                    "keep_both is unavailable for entries written by a newer app version; use keep local or keep remote"
                        .to_string(),
                );
            }
        }
        let remote_cipher = match handle.decrypt_cipher_bytes(cipher_id, &remote_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(guard);
                // Only a genuine epoch mismatch is cross_epoch; damaged
                // bytes should not masquerade as one in the UI.
                let cross = matches!(
                    e,
                    baluard_core::error::BaluardError::Vault(
                        baluard_core::error::VaultError::CrossEpoch { .. }
                    )
                );
                return Ok(serde_json::json!({
                    "pending": true,
                    "cross_epoch": cross,
                    "unreachable_side": "remote",
                    "detail": format!("{e}"),
                    "error": "keep_both needs to decrypt the remote side, which is at an unreachable epoch",
                })
                .to_string());
            }
        };
        let new_id = uuid::Uuid::new_v4();
        let epoch = handle.current_epoch().ok_or("vault locked mid-keep-both")?;
        let mut remote_input = CipherInput::from_cipher(&remote_cipher);
        // The clone is a fresh cipher id: attachment files stay bound to
        // the original (their AAD names the old cipher), so copying the
        // metadata alone would list undecryptable entries. The user
        // re-attaches on the clone.
        remote_input.attachments = Vec::new();
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
        let availability = baluard_core::biometric::availability();
        let available = availability == baluard_core::biometric::Availability::Available;
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
            // Distro install command when the missing Linux Secret Service
            // is why Quick Unlock is unavailable. The app prints the
            // command; the user runs it (AGENTS.md UX PRINCIPLES).
            "install_hint": if !available {
                baluard_core::biometric::unavailability_hint()
            } else {
                None
            },
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

        self.verify_master_password(password)
            .await
            .map_err(|_| "Incorrect master password".to_string())?;
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
    pub async fn biometric_unlock(self: &Arc<Self>) -> Result<String, QuickUnlockError> {
        let vault_id = self.vault_id_str().await.map_err(QuickUnlockError::Guess)?;
        let master_password =
            baluard_core::biometric::unlock(&vault_id).map_err(QuickUnlockError::Guess)?;
        self.unlock(&master_password).await.map_err(|e| {
            // Only a canary rejection is a credential guess (a stale
            // stored password); every other failure — hardware-seal
            // outcome proving the password, stale keywrap, unpaired
            // device — is budget-neutral for the daemon's rate limiter.
            if baluard_core::error::is_password_failure(&e) {
                QuickUnlockError::Guess(e.to_string())
            } else {
                QuickUnlockError::Proven(e.to_string())
            }
        })?;
        Ok(serde_json::json!({"success": true}).to_string())
    }

    // ── Session-bound PIN Quick Unlock ───────────────────────────────────
    //
    // In-memory KEK escrow: after the first master-password unlock the user
    // can enable a 6-digit PIN that re-unlocks for the rest of the daemon
    // session without re-running Argon2id. Nothing PIN-derivable touches
    // disk. See `pin::PinEscrow` for the full security model.

    // Hardware-backed devkey seal (progressive enhancement; plan:
    // docs/adr/0097-hardware-backed-keys.md). Devices without a usable chip
    // report capable:false and every toggle call fails closed.

    /// Pre-unlock safe: chip capability + the devkey file's seal kind.
    pub async fn hw_status(&self) -> Result<String, String> {
        use baluard_core::vault::device_privkey::PrivkeyFileKind;
        let vault_path = self.vault_path.clone();
        tokio::task::spawn_blocking(move || {
            let global = baluard_core::hwkey::probe_status();
            let disabled = matches!(
                &global,
                baluard_core::hwkey::HwCapability::Unavailable { reason } if reason == "disabled"
            );
            let stores = baluard_core::hwkey::installed_all();
            let mut backends = Vec::with_capacity(stores.len());
            let mut first_available = None;
            for store in &stores {
                let capability = if disabled {
                    baluard_core::hwkey::HwCapability::Unavailable {
                        reason: "disabled".into(),
                    }
                } else {
                    store.probe()
                };
                let (capable, reason) = match capability {
                    baluard_core::hwkey::HwCapability::Available { .. } => {
                        first_available.get_or_insert_with(|| store.backend_id().to_string());
                        (true, serde_json::Value::Null)
                    }
                    baluard_core::hwkey::HwCapability::Unavailable { reason } => {
                        (false, serde_json::Value::String(reason))
                    }
                };
                backends.push(serde_json::json!({
                    "backend": store.backend_id(),
                    "capable": capable,
                    "reason": reason,
                    "interaction": match store.interaction() {
                        baluard_core::hwkey::Interaction::Never => "never",
                        baluard_core::hwkey::Interaction::PerUse => "per-use",
                    },
                }));
            }

            let privkey_path = vault_path.join("meta/device-privkey.json");
            let kind = baluard_core::vault::device_privkey::file_kind(&privkey_path);
            let seal = match kind {
                PrivkeyFileKind::Sealed => "v1",
                PrivkeyFileKind::SealedHw => "v2-hw",
                PrivkeyFileKind::LegacyPlaintext => "legacy",
                PrivkeyFileKind::Damaged => "damaged",
                PrivkeyFileKind::Absent => "absent",
            };
            let sealed_backend = if seal == "v2-hw" {
                std::fs::read(&privkey_path).ok().and_then(|bytes| {
                    baluard_core::vault::device_privkey::hw_backend_of(&bytes).ok()
                })
            } else {
                None
            };
            let current_backend = sealed_backend.or_else(|| first_available.clone());
            let consent_supported = current_backend.as_deref().is_some_and(|backend| {
                stores
                    .iter()
                    .any(|store| store.backend_id() == backend && store.supports_consent())
            });
            let consent = seal == "v2-hw"
                && baluard_core::vault::device_privkey::file_consents(&privkey_path);
            let attestation = baluard_core::vault::device_privkey::hw_attestation_of(&privkey_path)
                .map(|att| att.as_str().to_string());
            let reason = if first_available.is_some() {
                serde_json::Value::Null
            } else {
                match global {
                    baluard_core::hwkey::HwCapability::Unavailable { reason } => {
                        serde_json::Value::String(reason)
                    }
                    baluard_core::hwkey::HwCapability::Available { .. } => serde_json::Value::Null,
                }
            };
            Ok(serde_json::json!({
                "capable": first_available.is_some(),
                "reason": reason,
                "backend": current_backend,
                "backends": backends,
                "seal": seal,
                "enabled": seal == "v2-hw",
                "consent_supported": consent_supported,
                "consent": consent,
                "attestation": attestation
            })
            .to_string())
        })
        .await
        .map_err(|e| format!("hardware status task: {e}"))?
    }

    /// Store or update the custom-remote credentials (device-local files).
    /// Token-gated but NOT a cover mutation: the artifacts are gitignored
    /// device-local state with nothing to sync.
    pub async fn git_credentials_set(&self, payload: &str) -> Result<String, String> {
        use base64::Engine as _;
        #[derive(serde::Deserialize)]
        struct Payload {
            host: String,
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            username: Option<String>,
            #[serde(default)]
            ssh_passphrase: Option<String>,
            #[serde(default)]
            ssh_key_b64: Option<String>,
        }
        let p: Payload =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {e}"))?;
        if p.host.trim().is_empty() {
            return Err("custom remote host is required".into());
        }
        let ssh_pem = match p.ssh_key_b64.as_deref() {
            None | Some("") => None,
            Some(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|_| "ssh_key_b64 is not valid base64".to_string())?;
                Some(
                    String::from_utf8(bytes)
                        .map_err(|_| "SSH key material is not valid UTF-8".to_string())?,
                )
            }
        };
        let mut update = baluard_core::sync::credentials::CustomCredentialsUpdate {
            token: p.token,
            username: p.username,
            ssh_passphrase: p.ssh_passphrase,
            ssh_key_pem: ssh_pem,
        };
        baluard_core::sync::credentials::apply_custom_credentials(
            &self.vault_path,
            &p.host,
            &update,
        )?;
        // The update struct holds plaintext secrets with no zeroize on
        // drop; wipe them before it goes out of scope.
        update.token.zeroize();
        update.ssh_passphrase.zeroize();
        update.ssh_key_pem.zeroize();
        Ok(r#"{"stored": true}"#.to_string())
    }

    /// The remote URL of the vault's origin, for the UI's test-connection
    /// and credential flows.
    pub async fn git_remote_url(&self) -> Result<String, String> {
        let path = self.vault_path.clone();
        tokio::task::spawn_blocking(move || {
            let repo =
                git2::Repository::open(&path).map_err(|e| format!("git open failed: {e}"))?;
            repo.find_remote("origin")
                .map_err(|e| format!("no origin remote: {e}"))?
                .url()
                .map(|s| s.to_string())
                .ok_or_else(|| "origin has no URL".to_string())
        })
        .await
        .map_err(|e| format!("join error: {e}"))?
    }

    /// Enable the hardware seal (the settings toggle). Requires an
    /// unlocked session (the seal subkey lives on the handle).
    pub async fn hw_enable(
        &self,
        consent: bool,
        backend: Option<String>,
    ) -> Result<String, String> {
        let _ops = self.devkey_ops.lock().await;
        let selected = match backend.as_deref() {
            Some(id) => baluard_core::hwkey::store_for(id),
            None => baluard_core::hwkey::available(),
        }
        .ok_or_else(|| "This device has no usable security chip.".to_string())?;
        if consent
            && selected.interaction() == baluard_core::hwkey::Interaction::Never
            && !selected.supports_consent()
        {
            return Err(
                "This device's security chip cannot require confirmation on each unlock."
                    .to_string(),
            );
        }
        let vault_id =
            baluard_core::vault::registry::BaluardMarker::read_from_vault(&self.vault_path)
                .map_err(|e| format!("read vault marker: {e}"))?
                .map(|m| m.vault_id)
                .ok_or_else(|| "vault marker missing".to_string())?;
        let vault_path = self.vault_path.clone();
        let privkey_path = self.vault_path.join("meta/device-privkey.json");
        // The rotation needs the seal subkey and (on managing devices)
        // the root key; members pass None and keep the existing path.
        let (seal, root_key, device_id) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked. Unlock first.")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            (
                handle.unlocked().devkey_seal,
                handle.unlocked().root().ok().cloned(),
                handle.device_id,
            )
        };
        let backend_id = selected.backend_id().to_string();
        let task_backend = backend_id.clone();
        let probe_or_attestation = tokio::task::spawn_blocking(
            move || -> Result<Result<Option<String>, String>, baluard_core::error::BaluardError> {
                if let baluard_core::hwkey::HwCapability::Unavailable { reason } = selected.probe()
                {
                    // Reason rides the message so the caller sees WHY the token
                    // was refused (uv-forced, no-token, security key: <detail>).
                    let msg = if task_backend == "fido2" {
                        format!("Connect a compatible security key. ({reason})")
                    } else {
                        format!("This device has no usable security chip. ({reason})")
                    };
                    return Ok(Err(msg));
                }
                baluard_core::vault::device_privkey::enable_hw_seal_rotating(
                    &vault_path,
                    vault_id,
                    device_id,
                    &seal,
                    root_key.as_ref(),
                    consent,
                    Some(&task_backend),
                )?;
                let attestation =
                    baluard_core::vault::device_privkey::hw_attestation_of(&privkey_path)
                        .map(|att| att.as_str().to_string());
                Ok(Ok(attestation))
            },
        )
        .await
        .map_err(|e| format!("hardware seal task: {e}"))?
        .map_err(|e| match &e {
            baluard_core::error::BaluardError::Vault(
                baluard_core::error::VaultError::HardwareUnavailable,
            ) => match backend_id.as_str() {
                "fido2" => "Connect a compatible security key.".to_string(),
                _ => "This device has no usable security chip.".to_string(),
            },
            _ => format!("{e}"),
        })?;
        let attestation: Option<String> = probe_or_attestation?;
        Ok(
            serde_json::json!({"enabled": true, "backend": backend_id, "attestation": attestation})
                .to_string(),
        )
    }

    /// Canary-only master-password proof for seal-downgrade gates: the
    /// honest oracle without a full unlock (no chip tap, no temp handle).
    /// Wrong passwords are the caller's rate-limit business.
    pub async fn verify_master_password(&self, master_password: &str) -> Result<(), String> {
        let vault_path = self.vault_path.clone();
        let password = master_password.to_string();
        tokio::task::spawn_blocking(move || {
            let kdf_json = std::fs::read_to_string(vault_path.join("meta/kdf-params.json"))
                .map_err(|e| format!("reading kdf params: {e}"))?;
            let kdf_params: baluard_core::types::KdfParams =
                serde_json::from_str(&kdf_json).map_err(|e| format!("corrupt kdf params: {e}"))?;
            let kek = zeroize::Zeroizing::new(
                baluard_core::crypto::kdf::derive_kek(&password, &kdf_params)
                    .map_err(|e| format!("kdf: {e}"))?,
            );
            let session_key = zeroize::Zeroizing::new(
                baluard_core::crypto::hkdf_derive::derive_session_key(&kek)
                    .map_err(|e| format!("kdf: {e}"))?,
            );
            let canary = std::fs::read(vault_path.join("meta/kek-canary.enc"))
                .map_err(|e| format!("reading kek canary: {e}"))?;
            baluard_core::vault::canary::verify_kek_canary(&session_key, &canary)
                .map_err(|_| "master password incorrect".to_string())
        })
        .await
        .map_err(|e| format!("verify task: {e}"))?
    }

    /// Disable the hardware seal: downgrade to v1. Needs the chip once
    /// (resolved from the seal file's recorded backend).
    pub async fn hw_disable(&self) -> Result<String, String> {
        let _ops = self.devkey_ops.lock().await;
        let seal = self
            .devkey_seal()
            .await
            .ok_or_else(|| "Vault is locked. Unlock first.".to_string())?;
        let privkey_path = self.vault_path.join("meta/device-privkey.json");
        let file =
            std::fs::read(&privkey_path).map_err(|e| format!("reading hardware seal: {e}"))?;
        if baluard_core::vault::device_privkey::file_kind(&privkey_path)
            == baluard_core::vault::device_privkey::PrivkeyFileKind::SealedHw
        {
            let backend = baluard_core::vault::device_privkey::hw_backend_of(&file)
                .map_err(|e| e.to_string())?;
            if baluard_core::hwkey::store_for(&backend).is_none() {
                return Err(if backend == "fido2" {
                    "Connect the security key that guards this vault.".to_string()
                } else {
                    "This device has no usable security chip.".to_string()
                });
            }
        } else if baluard_core::hwkey::available().is_none() {
            return Err("This device has no usable security chip.".to_string());
        }
        let device_id = baluard_core::vault::device_privkey::read_device_id(&self.vault_path);
        tokio::task::spawn_blocking(move || {
            baluard_core::vault::device_privkey::disable_hw_seal(&privkey_path, &seal, device_id)
        })
        .await
        .map_err(|e| format!("hardware seal task: {e}"))?
        .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({"enabled": false}).to_string())
    }

    /// Switch the hw seal between silent and per-use-consent modes. Needs
    /// the unlocked seal subkey (it re-keys the devkey file) and the chip.
    pub async fn hw_set_consent(&self, consent: bool) -> Result<String, String> {
        let _ops = self.devkey_ops.lock().await;
        let seal = self
            .devkey_seal()
            .await
            .ok_or_else(|| "Vault is locked. Unlock first.".to_string())?;
        let privkey_path = self.vault_path.join("meta/device-privkey.json");
        let file =
            std::fs::read(&privkey_path).map_err(|e| format!("reading hardware seal: {e}"))?;
        if baluard_core::vault::device_privkey::file_kind(&privkey_path)
            == baluard_core::vault::device_privkey::PrivkeyFileKind::SealedHw
        {
            let backend = baluard_core::vault::device_privkey::hw_backend_of(&file)
                .map_err(|e| e.to_string())?;
            if baluard_core::hwkey::store_for(&backend).is_none() {
                return Err(if backend == "fido2" {
                    "Connect the security key that guards this vault.".to_string()
                } else {
                    "This device has no usable security chip.".to_string()
                });
            }
        } else if baluard_core::hwkey::available().is_none() {
            return Err("This device has no usable security chip.".to_string());
        }
        let device_id = baluard_core::vault::device_privkey::read_device_id(&self.vault_path);
        let changed = tokio::task::spawn_blocking(move || {
            baluard_core::vault::device_privkey::set_hw_seal_consent(
                &privkey_path,
                &seal,
                device_id,
                consent,
            )
        })
        .await
        .map_err(|e| format!("hardware seal task: {e}"))?
        .map_err(|e| format!("{e}"))?;
        Ok(serde_json::json!({"consent": consent, "changed": changed}).to_string())
    }

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
        // Open, verify, and derive the escrow KEK on a blocking thread:
        // two Argon2id runs would otherwise pin the worker ~2s.
        let vault_path = self.vault_path.clone();
        let password = Zeroizing::new(password.to_string());
        let (mut temp, kek) =
            tokio::task::spawn_blocking(move || -> Result<(VaultHandle, [u8; 32]), String> {
                let mut temp =
                    VaultHandle::open(&vault_path).map_err(|e| format!("Open failed: {e}"))?;
                // Confirm the password is correct (raises clear error +
                // advances nothing persistent — temp handle is discarded).
                temp.unlock(&password)
                    .map_err(|_| "Incorrect master password".to_string())?;
                let kek = baluard_core::crypto::kdf::derive_kek(&password, &temp.kdf_params)
                    .map_err(|e| format!("derive kek: {e}"))?;
                Ok((temp, kek))
            })
            .await
            .map_err(|e| format!("verify task: {e}"))??;

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
    /// (skips Argon2id; still re-verifies keywrap + canaries) on the
    /// blocking pool, so an hw-sealed vault's tap wait never pins a tokio
    /// worker. On the `MAX_PIN_FAILURES`-th wrong PIN the escrow is
    /// destroyed: the master password becomes mandatory and the user must
    /// re-enable the PIN. A canary rejection after a CORRECT PIN means the
    /// escrowed key is stale (password changed elsewhere) — the escrow is
    /// destroyed there too, since every future attempt would fail the same
    /// way. Every other failure (hardware outcomes, unpaired keywrap,
    /// damaged metadata) keeps the escrow: the PIN still holds and the
    /// error passes through with the same copy the password path uses.
    ///
    /// Concurrency: verify + counter-increment + nuke run under ONE hold of
    /// the escrow mutex, so no concurrent `pin_unlock` can slip a verified
    /// guess in between the verify and the cap check. The slow
    /// `unlock_with_kek` runs AFTER the lock is released, which is safe
    /// because a correct PIN returns the KEK out (the escrow stays put) and
    /// a wrong PIN never reaches it.
    pub async fn pin_unlock(self: &Arc<Self>, payload: &str) -> Result<String, QuickUnlockError> {
        let req: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| QuickUnlockError::Guess(e.to_string()))?;
        let pin = req["pin"]
            .as_str()
            .ok_or(QuickUnlockError::Guess("missing pin".into()))?;

        // Atomic verify-and-record under a single escrow lock hold. This is
        // the fix for the TOCTOU where a concurrent wrong-PIN attempt could
        // verify against the still-live escrow before the counter advanced /
        // the escrow was nuked. We must NOT run unlock_with_kek in here
        // (slow) — so on a correct PIN we copy the KEK out and release.
        let kek = {
            let mut guard = self.pin.lock().await;
            let Some(escrow) = guard.as_ref() else {
                return Err(QuickUnlockError::Guess(
                    "PIN Quick Unlock is not enabled for this vault. \
                     Unlock with the master password and re-enable it."
                        .into(),
                ));
            };
            match escrow.verify_or_record_failure(pin, &self.pin_failures) {
                Ok(kek) => kek,
                Err(msg) if msg == crate::pin::PIN_NUKED_SENTINEL => {
                    // Cap reached: destroy the escrow NOW, under this lock,
                    // so the next attempt sees None.
                    *guard = None;
                    return Err(QuickUnlockError::Guess(
                        "Too many wrong PINs. PIN Quick Unlock has been disabled — \
                         use the master password and re-enable PIN to continue."
                            .into(),
                    ));
                }
                Err(msg) => return Err(QuickUnlockError::Guess(msg)),
            }
        };

        // unlock_with_kek runs the shared tail (keywrap HPKE unwrap +
        // canaries) so a corrupted/stale keywrap still fails closed —
        // spawn_blocking inside, so the chip tap never pins a worker.
        match self.unlock_with_kek(&kek).await {
            Ok(()) => {
                // Success: clear the PIN failure counter; unlock_with_kek
                // already landed the shared tail (token mint + migration +
                // autosync + sweeps) — same contract as `unlock()`.
                self.pin_failures
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                Ok(serde_json::json!({ "success": true }).to_string())
            }
            Err(e) if baluard_core::error::is_password_failure(&e) => {
                // Correct PIN but the canary rejected the escrowed key:
                // it is stale (e.g. password changed on another device +
                // synced). The escrow is now useless — every future
                // correct-PIN attempt would fail the same way. Nuke it
                // immediately so the user gets a clear “re-enable PIN”
                // signal instead of burning the 5-strike budget on a PIN
                // they remember correctly.
                *self.pin.lock().await = None;
                Err(QuickUnlockError::Proven(format!(
                    "PIN unlock failed (the saved key is stale, usually because \
                     the master password changed). Re-enable PIN unlock. Underlying error: {e}"
                )))
            }
            Err(e) => {
                // Hardware outcome (chip gone, tap timeout, tap cancelled),
                // unpaired keywrap, damaged metadata: not the PIN's fault
                // and the escrowed key is still valid. Keep the escrow and
                // pass the typed copy through — surfaces map it exactly
                // like the password path.
                Err(QuickUnlockError::Proven(e.to_string()))
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
        // Domain-aware: a collection-resident entry keys from the
        // collection key; derive_item_key would panic without an SGK.
        let item_key = handle
            .resolve_cipher_item_key(cipher_id, cipher.key_epoch)
            .map_err(|e| e.to_string())?;

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
            collection_id: None,
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
        // Validate before any path use: the id later joins a filesystem
        // path, and synced cipher meta is member-writable data.
        let attach_uuid: uuid::Uuid = attach_id
            .parse()
            .map_err(|e| format!("invalid attachment_id: {e}"))?;

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

        // Domain-aware: a collection-resident entry keys from the
        // collection key; derive_item_key would panic without an SGK.
        let item_key = handle
            .resolve_cipher_item_key(cipher_id, cipher.key_epoch)
            .map_err(|e| e.to_string())?;

        let attach_path = handle
            .path
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments")
            .join(format!("{}.enc", attach_id));

        // Vault contents arrive over git: refuse non-regular files
        // (symlinks) and bound the read, mirroring the backup container
        // guards. A git-supplied symlink at this path would otherwise
        // read /dev/zero or a huge file into memory.
        let attach_stat =
            std::fs::symlink_metadata(&attach_path).map_err(|e| format!("read: {e}"))?;
        if !attach_stat.is_file() {
            return Err("Attachment is not a regular file".into());
        }
        const MAX_ATTACHMENT_READ: u64 = 4 * 1024 * 1024;
        if attach_stat.len() > MAX_ATTACHMENT_READ {
            return Err("Attachment exceeds the size limit".into());
        }
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
        // Parse before any path use: the attachments metadata is
        // member-writable synced data, so a crafted id must never reach a
        // path join (same gate as attach_download).
        let attach_uuid: uuid::Uuid = attach_id
            .parse()
            .map_err(|_| "invalid attachment_id".to_string())?;
        let attach_id = attach_uuid.to_string();

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

        // Update cipher FIRST, then delete the file: a failed update must
        // not leave metadata pointing at a missing file. An orphaned file
        // (delete failed after a successful update) rides the trash purge.
        let attach_path = handle
            .path
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments")
            .join(format!("{}.enc", attach_id));

        // Update cipher
        let input = baluard_core::types::CipherInput {
            name: cipher.name.clone(),
            folder_id: cipher.folder_id,
            collection_id: None,
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

        if attach_path.exists() {
            // Metadata already removed: a failed delete must not turn the
            // operation into a reported error (a retry would find no
            // attachment). The orphan rides cleanup.
            if let Err(e) = std::fs::remove_file(&attach_path) {
                log::warn!("[state] attachment file left behind: {e}");
            }
        }

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
    /// Family-spaces section 8, the stolen-device journey in one
    /// op: tombstone the member with a fresh successor (their invite
    /// code returns exactly once), optionally revoke-and-rekey the
    /// stolen device (Root Key rotation, cipher re-encryption, kit
    /// rewrap, D78 verifier refresh), then rotate every collection the
    /// member could open so keys the thief extracted die with the old
    /// epoch. The successor keeps the member's minor flag; re-grants
    /// ride the replacement invite's embedded template.
    pub async fn members_replace_device(&self, payload: &str) -> Result<String, String> {
        let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let member_id: uuid::Uuid = v["member_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or("invalid or missing 'member_id'")?;
        let revoke_device = v
            .get("revoke_device")
            .and_then(|r| r.as_bool())
            .unwrap_or(true);

        // Pre-flight under a read lock: the member must be live and
        // not the actor; capture the openable set BEFORE anything dies.
        let (grants_to_restore, had_kit, vault_id) = {
            let guard = self.inner.read().await;
            let handle = guard.as_ref().ok_or("Vault is locked")?;
            if !handle.is_unlocked() {
                return Err("Vault is locked. Unlock first.".into());
            }
            let row = baluard_core::vault::members::member_file_by_id(&handle.path, member_id)
                .ok_or_else(|| format!("no member row {member_id}"))?;
            if row.removed.is_some() || row.reset.is_some() {
                return Err("that member row is already gone".into());
            }
            if baluard_core::vault::members::member_id_for_device(&handle.path, handle.device_id)
                == Some(member_id)
            {
                return Err("resetting your own member row would lock you out".into());
            }
            (
                Self::replacement_grants_for_member(handle, member_id)?,
                baluard_core::vault::recovery_kit::kit_exists(&handle.path).unwrap_or(false),
                handle.vault_id,
            )
        };

        // Reset: tombstone + successor + replacement invite code. The
        // invite embeds the captured grants so the rejoining child
        // keeps Shared and their own collections (a reset successor
        // starts with zero grants otherwise).
        let replacement = baluard_core::vault::templates::EmbeddedTemplate {
            name: "Replacement device (restored grants)".to_string(),
            grants: grants_to_restore
                .iter()
                .map(
                    |(cid, access)| baluard_core::vault::templates::TemplateGrant {
                        collection_id: *cid,
                        access: *access,
                        expires_in_days: None,
                    },
                )
                .collect(),
        };
        let (successor, invite_code) = {
            let mut guard = self.inner.write().await;
            let handle = guard.as_mut().ok_or("Vault is locked")?;
            handle
                .member_reset(member_id, Some(replacement))
                .map_err(|e| e.to_string())?
        };

        // Optional revoke-and-rekey of the stolen device. Best-effort:
        // if the device is already gone the reset struck it; report.
        let mut revoke_error = None;
        if revoke_device {
            // The member's bound devices (bindings stay on disk and
            // inert after a reset, so the walk still finds them).
            let devices_dir = {
                let guard = self.inner.read().await;
                let handle = guard.as_ref().ok_or("Vault is locked")?;
                handle
                    .path
                    .join(baluard_core::vault::members::MEMBERS_DIR)
                    .join(member_id.to_string())
                    .join("devices")
            };
            let stolen: Vec<uuid::Uuid> = std::fs::read_dir(&devices_dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter_map(|e| {
                            // Binding files are <device_id>.json.
                            let name = e.file_name();
                            uuid::Uuid::parse_str(name.to_string_lossy().strip_suffix(".json")?)
                                .ok()
                        })
                        .collect()
                })
                .unwrap_or_default();
            for device_id in stolen {
                let mut guard = self.inner.write().await;
                let handle = guard.as_mut().ok_or("Vault is locked")?;
                if device_id == handle.device_id {
                    continue;
                }
                if let Err(e) = handle.revoke_device_and_rekey(device_id) {
                    // Keep revoking the rest: stopping at the first
                    // failure would leave later stolen devices live.
                    revoke_error = Some(match revoke_error.take() {
                        Some(prev) => format!("{prev}; {device_id}: {e}"),
                        None => format!("{device_id}: {e}"),
                    });
                }
            }
        }

        // Rotate the captured collections under the (possibly new)
        // epoch, pruning the old member's grant rows and wraps. The
        // successor re-grants ride the replacement invite; the rotation
        // kills keys the thief may hold in memory.
        let mut rotation_failed: Vec<String> = Vec::new();
        {
            let mut guard = self.inner.write().await;
            let handle = guard.as_mut().ok_or("Vault is locked")?;
            if handle.is_unlocked() {
                for (cid, _access) in &grants_to_restore {
                    if let Err(e) = handle.collection_rotate_key(*cid, Some(member_id)) {
                        rotation_failed.push(format!("{cid}: {e}"));
                    }
                }
            } else {
                // Locked handle: nothing rotated. Reporting these as done
                // would hide keys the thief may still hold.
                for (cid, _access) in &grants_to_restore {
                    rotation_failed.push(format!("{cid}: vault locked, rotation skipped"));
                }
            }
        }

        let report = serde_json::json!({
            "successor": successor.to_string(),
            "invite_code": invite_code,
            "collections_rotated": grants_to_restore.len() - rotation_failed.len(),
            "rotation_failed": rotation_failed,
            "revoke_error": revoke_error,
            // Informational: a theft does not compromise the kit
            // phrase (it never rode the stolen device), and the
            // revoke-and-rekey leg rewraps the kit file to the new
            // Root Key without it.
            "kit_present": had_kit,
            "vault_id": vault_id.to_string(),
        });
        Ok(report.to_string())
    }

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
        // D78: rekey bumped the Root Key epoch — refresh the autosync
        // coordinator's cached enrollment-proof verifier so background
        // pulls accept new-epoch proofs.
        let enroll_vk = handle.enroll_verify_key();
        drop(guard);
        self.autosync.refresh_enroll_vk(enroll_vk).await;
        Ok(json.to_string())
    }

    /// Verify the master password without opening a second vault session.
    pub async fn reprompt_verify(&self, master_password: &str) -> Result<String, String> {
        self.verify_master_password(master_password)
            .await
            .map_err(|_| "Incorrect master password".to_string())?;

        // Password verified. The grant is time-window only: `expires_at` is
        // all the client needs. No grant_token is minted — a returned token
        // would be a bearer capability for other same-UID processes (audit
        // C12), and no consumer ever validated it anyway.
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 30;
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
    pub async fn enroll_with_recovery_phrase(
        &self,
        phrase: &str,
        master_password: &str,
    ) -> Result<String, String> {
        use baluard_core::device_manager::{DeviceManager, EnrollmentPayload};
        use rand::RngCore;

        // Validate phrase shape
        let word_count = phrase.split_whitespace().count();
        if word_count != 24 {
            return Err(format!(
                "recovery phrase must be 24 words, got {word_count}"
            ));
        }

        // A fresh clone is locked by definition ("device private key not
        // found" until enrolled), so enrollment MUST NOT require an open
        // handle. The vault path comes from this vault's state; core reads
        // the real policy from settings.enc under the phrase-recovered
        // root key. The read guard stays across the disk phase so a
        // concurrent lock/unlock cannot interleave with the registry
        // writes; it drops before the F3 write-lock update below.
        let vault_path = self.vault_path.clone();
        let state_guard = self.inner.read().await;

        // Prove the master password BEFORE any enrollment write (the same
        // ghost-device guard as the providers join flow): a mistyped
        // password must not mint roster entries or key files. The verified
        // KEK also seals the fresh device key at birth below — the creation
        // flow seals, so enroll must not leave a plaintext window between
        // enroll and the next unlock.
        let kdf_json = std::fs::read_to_string(vault_path.join("meta/kdf-params.json"))
            .map_err(|e| format!("reading kdf params: {e}"))?;
        let kdf_params: baluard_core::types::KdfParams =
            serde_json::from_str(&kdf_json).map_err(|e| format!("corrupt kdf params: {e}"))?;
        let kek = zeroize::Zeroizing::new(
            baluard_core::crypto::kdf::derive_kek(master_password, &kdf_params)
                .map_err(|e| format!("kdf: {e}"))?,
        );
        let session_key = zeroize::Zeroizing::new(
            baluard_core::crypto::hkdf_derive::derive_session_key(&kek)
                .map_err(|e| format!("kdf: {e}"))?,
        );
        let devkey_seal = zeroize::Zeroizing::new(
            baluard_core::crypto::hkdf_derive::derive_devkey_seal_key(&kek)
                .map_err(|e| format!("kdf: {e}"))?,
        );
        let canary = std::fs::read(vault_path.join("meta/kek-canary.enc"))
            .map_err(|e| format!("reading kek canary: {e}"))?;
        baluard_core::vault::canary::verify_kek_canary(&session_key, &canary)
            .map_err(|_| "master password incorrect".to_string())?;
        drop(session_key);

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
            .enroll_with_recovery_phrase(&payload, phrase, x25519_secret, ed25519_signing)
            .map_err(|e| format!("enroll: {e}"))?;
        drop(state_guard);

        // Persist device-privkey for this device using the keys RETURNED
        // by the method (same keys the registry and keywrap were built
        // with — guarantees consistency). Sealed at birth under the
        // verified KEK's devkey seal subkey, 0600 atomic via seal_file.
        let privkey_data = serde_json::json!({
            "device_id": result.device_id.to_string(),
            "x25519_private": hex::encode(result.x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(result.ed25519_signing.to_bytes()),
        });
        let privkey_path = vault_path.join("meta/device-privkey.json");
        let privkey_json =
            serde_json::to_string_pretty(&privkey_data).map_err(|e| format!("{e}"))?;
        baluard_core::vault::device_privkey::seal_file(
            &privkey_path,
            &privkey_json,
            &devkey_seal,
            Some(result.device_id),
        )
        .map_err(|e| format!("seal privkey: {e}"))?;

        // F3 fix: update self.inner under write lock so in-process state holds the new device_id
        {
            let mut guard = self.inner.write().await;
            if let Some(handle) = guard.as_mut() {
                handle.device_id = result.device_id;
                handle.device_manager = dm;
                let reg_json = std::fs::read_to_string(vault_path.join("meta/devices.json"))
                    .map_err(|e| format!("reading devices.json: {e}"))?;
                let reg = serde_json::from_str(&reg_json)
                    .map_err(|e| format!("parse devices.json: {e}"))?;
                handle.registry = reg;
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
        // Family-spaces section 13 step 6: create the vault AS a family
        // vault (purpose, Shared + Guardians, team shape, kit) in the
        // one transaction; the response carries the kit phrase.
        let family = v.get("family").and_then(|f| f.as_bool()).unwrap_or(false);
        let (handle, secrets) = baluard_core::vault::creation::VaultCreator::new(
            &self.vault_path,
            &password,
            "this-device",
        )
        .slug(slug_for_marker)
        .kdf_profile(profile)
        .profile(vault_name.clone(), None)
        .family(family)
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
        self.session_token_generation.store(
            self.session_generation.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        let mut response = serde_json::json!({
            "vault_id": secrets.vault_id.to_string(),
            "device_id": secrets.device_id.to_string(),
            "recovery_phrase": secrets.recovery_phrase.phrase(),
            "trust_fingerprint": hex::encode(secrets.trust_fingerprint),
            "session_token": token,
            "vault_name": vault_name,
        });
        // The family kit phrase rides the creation response exactly
        // once; absent (not null) on personal vaults and resumed runs.
        if let Some(kit) = &secrets.kit_phrase {
            response["kit_phrase"] = serde_json::Value::String(kit.to_string());
        }
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
                self.session_token_generation.store(0, Ordering::Relaxed);
                return Err("Session token expired. Re-unlock the vault.".into());
            }
        }

        // P1c: generation check. A token minted at generation G is only
        // valid while the vault is still at generation G. `lock()` bumps
        // the generation, so a stale token dies here even if a code path
        // ever forgets the explicit clear (defense in depth).
        if self.session_token_generation.load(Ordering::Relaxed)
            != self.session_generation.load(Ordering::Relaxed)
        {
            // Stale generation: the token is dead; clear the residue.
            *self.session_token.write().await = None;
            self.session_token_created.store(0, Ordering::Relaxed);
            self.session_token_generation.store(0, Ordering::Relaxed);
            return Err("Vault was locked and re-unlocked. Re-unlock required.".into());
        }

        let guard = self.session_token.read().await;
        match *guard {
            Some(ref stored)
                if crate::crypto::constant_time_eq(provided.as_bytes(), stored.as_bytes()) =>
            {
                // Sliding renewal on AUTHENTICATED activity: the token
                // lives 4h of inactivity (matching the activity-based
                // auto-lock). Renewing before the compare would let any
                // request — even a wrong token — hold the session open.
                let created = self.session_token_created.load(Ordering::Relaxed);
                if created > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now.saturating_sub(created) > SESSION_TOKEN_TTL_SECONDS / 2 {
                        self.session_token_created.store(now, Ordering::Relaxed);
                    }
                }
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

    /// Test-only: mint a session token exactly like the unlock paths do
    /// (token + creation time + current generation stamp), without needing
    /// a real unlocked vault. Lets host-level tests exercise the P1c
    /// chokepoint cascade.
    #[cfg(test)]
    pub(crate) async fn test_mint_session_token(&self, token: &str) {
        *self.session_token.write().await = Some(token.to_string());
        self.session_token_generation.store(
            self.session_generation.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.session_token_created.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
    }
}

/// Shared vault state type.
pub type SharedVaultState = Arc<VaultState>;

/// Serialize a decrypted cipher to JSON, matching the format returned by `get_cipher`.
/// The nested kind mirrors the encrypted envelope shape, so it carries
/// the passkey key material the flat fields above deliberately omit;
/// strip it before the value crosses IPC.
/// Extensions the avatar file may carry. Enforced on every path that
/// turns `avatar_ext` into a filename: the value rides in profile.enc
/// (Space-admin writable) and an unvalidated join would give a crafted
/// extension a `..` path on platforms that normalize lexically.
fn avatar_ext_allowed(ext: &str) -> bool {
    matches!(ext, "png" | "jpg" | "jpeg" | "gif" | "webp")
}

fn redact_kind_secrets(mut kind: serde_json::Value) -> serde_json::Value {
    if let Some(creds) = kind
        .get_mut("data")
        .and_then(|d| d.get_mut("fido2_credentials"))
        .and_then(|v| v.as_array_mut())
    {
        for cred in creds {
            if let Some(obj) = cred.as_object_mut() {
                obj.remove("private_key");
                obj.remove("prf_key");
            }
        }
    }
    kind
}

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
    json["kind"] =
        redact_kind_secrets(serde_json::to_value(&c.kind).unwrap_or(serde_json::Value::Null));
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
        baluard_core::types::CipherKind::SigningKey(data) => {
            json["public_key"] = serde_json::json!(data.public_key);
            json["private_key"] = serde_json::json!(data.private_key);
            json["passphrase"] = serde_json::json!(data.passphrase);
            json["certificates"] = serde_json::json!(data.certificates);
            json["key_format"] =
                serde_json::to_value(data.key_format).unwrap_or(serde_json::Value::Null);
            json["expires_at"] = serde_json::json!(data.expires_at);
            json["issuer"] = serde_json::json!(data.issuer);
            json["subject"] = serde_json::json!(data.subject);
            json["fingerprint"] = serde_json::json!(data.fingerprint);
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
    // Per-clone identity (meta/device-id first): a HashMap-order roster
    // scan can pick another device and mis-sign conflict commits.
    baluard_core::vault::device_privkey::local_device_id(vault_path)
}

/// App-to-web matching context for a fill target (path B). Some(_) only
/// when the setting is on AND the target is `androidapp://<package>`:
/// trusted/rejected registrable domains for that package plus the
/// package-derived candidates. Everything else (web targets, setting off)
/// yields None and autofill behaves exactly as before.
fn app_match_context(
    settings: Option<&baluard_core::vault::manifest::VaultSettings>,
    target: &str,
) -> Option<AppMatchContext> {
    let s = settings?;
    if !s.suggest_app_logins.unwrap_or(false) {
        return None;
    }
    let pkg = target.trim().to_ascii_lowercase();
    let pkg = pkg.strip_prefix("androidapp://")?;
    if pkg.is_empty() {
        return None;
    }
    let trusted: Vec<String> = s
        .trusted_app_packages
        .iter()
        .flatten()
        .filter(|t| t.package == pkg)
        .map(|t| t.domain.clone())
        .collect();
    let rejected: Vec<String> = s
        .rejected_app_packages
        .iter()
        .flatten()
        .filter(|t| t.package == pkg)
        .map(|t| t.domain.clone())
        .collect();
    let candidates = baluard_core::types::app_domain_candidates(pkg);
    Some(AppMatchContext {
        trusted,
        rejected,
        candidates,
    })
}

struct AppMatchContext {
    trusted: Vec<String>,
    rejected: Vec<String>,
    candidates: Vec<String>,
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
        assert_eq!(pairs.next(), Some(("sz".into(), "64".into())));
        assert_eq!(pairs.next(), None);
    }

    #[test]
    fn favicon_url_plain_domain_unescaped_happy_path() {
        let url = VaultState::favicon_url("example.com");
        assert_eq!(
            url,
            "https://www.google.com/s2/favicons?domain=example.com&sz=64"
        );
    }

    /// SSRF guard: internal addresses must never be contactable, in any
    /// notation (decimal, IPv4-mapped IPv6, bracketed literals).
    #[test]
    fn ip_blocklist_refuses_internal_ranges() {
        let blocked = [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:192.168.1.1",
        ];
        for s in blocked {
            let ip: std::net::IpAddr = s.parse().expect("test ip parses");
            assert!(VaultState::ip_is_blocklisted(ip), "{s} must be blocklisted");
        }
        let public = ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"];
        for s in public {
            let ip: std::net::IpAddr = s.parse().expect("test ip parses");
            assert!(
                !VaultState::ip_is_blocklisted(ip),
                "{s} must NOT be blocklisted"
            );
        }
    }

    /// Plain-name guard: LAN hostnames, localhost, and internal IP
    /// literals are refused before any DNS or HTTP work. Real domains and
    /// public IP literals pass.
    #[test]
    fn host_fetchable_str_rejects_internal_names() {
        let refused = [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "myserver",
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "[::1]",
            "::ffff:127.0.0.1",
            "",
        ];
        for h in refused {
            assert!(!VaultState::host_fetchable_str(h), "{h} must be refused");
        }
        let allowed = ["example.com", "sub.example.co.uk", "1.1.1.1"];
        for h in allowed {
            assert!(VaultState::host_fetchable_str(h), "{h} must be allowed");
        }
    }

    /// Probe order is part of the design: ico, then png, then jpg.
    #[test]
    fn static_icon_paths_ordered() {
        assert_eq!(
            VaultState::STATIC_ICON_PATHS,
            ["/favicon.ico", "/favicon.png", "/favicon.jpg"]
        );
    }

    /// The <link> scan finds icon rels in document order, separates
    /// apple-touch variants, reads hrefs from the original text (case
    /// preserved), resolves nothing here (that is the caller's job), and
    /// ignores non-icon links and tags without hrefs.
    #[test]
    fn icon_hrefs_extracts_icon_links_best_first() {
        let html = concat!(
            "<head>",
            "<link rel=\"stylesheet\" href=\"style.css\">",
            "<link rel=\"apple-touch-icon\" sizes=\"180x180\"",
            " href=\"https://cdn.example.com/apple.png\">",
            "<LINK REL='shortcut icon' HREF='/favicons/custom.ico'>",
            "<link rel=\"icon\" type=\"image/png\" href=\"logo.png\">",
            "<link rel=\"icon\">",
            "</head>"
        );
        let found = VaultState::icon_hrefs(html);
        assert_eq!(found.len(), 3, "icon links only: {found:?}");
        assert!(found[0].1, "apple-touch first in document order");
        assert_eq!(found[0].0, "https://cdn.example.com/apple.png");
        assert!(!found[1].1, "shortcut icon is not apple");
        assert_eq!(found[1].0, "/favicons/custom.ico");
        assert!(!found[2].1);
        assert_eq!(found[2].0, "logo.png");
    }

    /// Review fixes: userinfo stripped, www. preserved (probes must
    /// hit the host the entry points at), encoded-IP forms refused.
    #[test]
    fn extract_domain_strips_userinfo_keeps_www() {
        assert_eq!(
            VaultState::extract_domain("https://admin@127.0.0.1/x"),
            "127.0.0.1"
        );
        assert_eq!(
            VaultState::extract_domain("https://www.example.com/a?b"),
            "www.example.com"
        );
        assert_eq!(
            VaultState::extract_domain("example.com:8443/x"),
            "example.com"
        );
    }

    #[test]
    fn host_fetchable_str_rejects_encoded_ips() {
        let refused = ["0177.0.0.1", "0x7f.0.0.1", "127.0.0.001"];
        for h in refused {
            assert!(!VaultState::host_fetchable_str(h), "{h} must be refused");
        }
        // Zero-prefixed but non-numeric labels are legitimate domains.
        assert!(VaultState::host_fetchable_str("0cloud.com"));
    }

    /// Links inside HTML comments are markup debris, never live tags.
    #[test]
    fn icon_hrefs_ignores_commented_links() {
        let html = concat!(
            "<!-- <link rel=\"icon\" href=\"https://evil.example/favicon.ico\"> -->",
            "<link rel=\"icon\" href=\"real.png\">"
        );
        let found = VaultState::icon_hrefs(html);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "real.png");
    }

    /// Magic-byte validation gates every candidate response.
    #[test]
    fn looks_like_image_checks_magic_bytes() {
        assert!(VaultState::looks_like_image(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D
        ]));
        assert!(VaultState::looks_like_image(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(VaultState::looks_like_image(&[0x00, 0x00, 0x01, 0x00]));
        assert!(VaultState::looks_like_image(b"RIFFxxxxWEBP"));
        assert!(!VaultState::looks_like_image(b"<html>"));
        assert!(!VaultState::looks_like_image(b"Not Found"));
        assert!(!VaultState::looks_like_image(&[0x00, 0x01]));
    }
}

#[cfg(test)]
mod totp_meta_tests {
    use super::VaultState;

    /// Archived TOTP logins must vanish from the Authenticator card and its
    /// list search: archive hides from lists and search, not just the main
    /// list. Regression for the list_cipher_meta_full -> list_cipher_meta fix.
    #[tokio::test]
    async fn list_totp_meta_excludes_archived() {
        // VaultState creation probes the OS keyring; the env guard keeps
        // headless runs hermetic (same pattern as the sibling tests).
        if baluard_core::keyring_disabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());
        state
            .create_vault(r#"{"password":"t3st-v4ult","profile":"mobile_low"}"#)
            .await
            .unwrap();
        // create_vault leaves the handle unlocked.

        // add_cipher returns the new cipher's bare UUID string.
        let id = state
            .add_cipher(
                r#"{"name":"Bank","kind":{"type":"login","data":{
                     "username":"u","totp_uri":"otpauth://totp/bank?secret=ABC"}}}"#,
            )
            .await
            .unwrap();

        assert_eq!(state.list_totp_meta().await.unwrap().len(), 1);

        state.archive_cipher(&id).await.unwrap();
        assert!(state.list_totp_meta().await.unwrap().is_empty());
    }
}

#[cfg(test)]
mod avatar_ext_tests {
    #[test]
    fn avatar_ext_whitelist_rejects_traversal() {
        assert!(super::avatar_ext_allowed("png"));
        assert!(super::avatar_ext_allowed("webp"));
        for bad in ["x/../../../target", "..", "", "PNG", "a/b"] {
            assert!(!super::avatar_ext_allowed(bad), "{bad}");
        }
    }
}

#[cfg(test)]
mod session_token_tests {
    use super::VaultState;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    /// P1c: a fresh state has no token; verify fails closed with the
    /// locked-vault message.
    #[tokio::test]
    async fn verify_fails_closed_when_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());
        let err = state.verify_session_token("whatever").await.unwrap_err();
        assert!(err.contains("locked"), "got: {err}");
    }

    /// P1c: lock() bumps the generation. A token re-injected at the OLD
    /// generation is dead even though the explicit clear was bypassed —
    /// the defense-in-depth property of the chokepoint cascade.
    #[tokio::test]
    async fn lock_generation_kills_stale_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());
        let gen0 = state.session_generation.load(Ordering::Relaxed);

        state.test_mint_session_token("token-g0").await;
        state.verify_session_token("token-g0").await.unwrap();

        state.lock().await.unwrap();
        assert_eq!(
            state.session_generation.load(Ordering::Relaxed),
            gen0 + 1,
            "lock must bump the generation"
        );
        // Normal path: lock cleared the token.
        assert!(state.verify_session_token("token-g0").await.is_err());

        // Bug-class simulation: a future lock path forgets the clear and
        // the old token resurfaces. Generation mismatch must kill it.
        *state.session_token.write().await = Some("token-g0".to_string());
        let err = state.verify_session_token("token-g0").await.unwrap_err();
        assert!(
            err.contains("locked and re-unlocked"),
            "stale-generation token must be rejected: {err}"
        );
        // The residue was cleared by the check itself.
        assert!(state.session_token.read().await.is_none());
    }

    /// P1c: a token minted at the CURRENT generation verifies; the same
    /// string minted at a different generation does not.
    #[tokio::test]
    async fn remint_at_current_generation_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());

        state.test_mint_session_token("tok-a").await;
        state.verify_session_token("tok-a").await.unwrap();

        state.lock().await.unwrap();
        state.test_mint_session_token("tok-b").await;
        state.verify_session_token("tok-b").await.unwrap();
        assert!(state.verify_session_token("tok-a").await.is_err());

        // A second lock invalidates tok-b too (monotonic cascade).
        state.lock().await.unwrap();
        assert!(state.verify_session_token("tok-b").await.is_err());
    }

    /// P1c plan rule: the lock cascade must NEVER await the sync
    /// cycle_lock (it is held across 60s network spawn_blocking calls
    /// whose timeouts do not cancel the blocking task). Holding
    /// cycle_lock must not delay lock().
    #[tokio::test]
    async fn lock_does_not_await_cycle_lock() {
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());

        let cycle = state.autosync.cycle_lock_guard().await;
        let locked = tokio::time::timeout(Duration::from_secs(2), state.lock()).await;
        drop(cycle);
        assert!(
            locked.is_ok(),
            "lock() deadlocked behind cycle_lock — the chokepoint must not await it"
        );
        locked.unwrap().unwrap();
    }

    /// P1c regression: the REAL mint paths (create_vault, unlock) must
    /// stamp the mint generation. Without the stamps, the first
    /// token-gated call after a re-unlock wipes the session (review finding:
    /// "locked out on the very first request after re-unlocking"). Runs
    /// hermetically under BALUARD_DISABLE_KEYRING=1 (just test); skips
    /// elsewhere to avoid a headless keyring probe hang.
    #[tokio::test]
    async fn real_unlock_mints_generation_stamped_token() {
        if !baluard_core::keyring_disabled() {
            eprintln!("skipping: set BALUARD_DISABLE_KEYRING=1 to run hermetically");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::new(dir.path().to_path_buf());
        state
            .create_vault(r#"{"password":"test-pass-123","profile":"mobile_low"}"#)
            .await
            .unwrap();

        // Creation mint is stamped: the echoed token verifies.
        let tok = state.get_session_token().await.unwrap();
        state.verify_session_token(&tok).await.unwrap();

        state.lock().await.unwrap();
        assert!(state.verify_session_token(&tok).await.is_err());

        // Re-unlock via the REAL master-password path; the new token must
        // verify on the first gated call (this is exactly what unstamped
        // mint sites broke).
        let state = std::sync::Arc::new(state);
        state.unlock("test-pass-123").await.unwrap();
        let tok2 = state.get_session_token().await.unwrap();
        assert_ne!(tok, tok2, "re-unlock must mint a fresh token");
        state.verify_session_token(&tok2).await.unwrap();
    }
}

#[cfg(test)]
mod enroll_phrase_seal_tests {
    use super::VaultState;
    use baluard_core::vault::device_privkey::{PrivkeyFileKind, file_kind};
    use std::sync::Arc;

    const PASSWORD: &str = "correct horse battery";

    async fn vault_with_phrase(dir: &tempfile::TempDir) -> (Arc<VaultState>, String) {
        let state = VaultState::new(dir.path().to_path_buf());
        let payload =
            serde_json::json!({ "password": PASSWORD, "profile": "mobile_low" }).to_string();
        let created = state.create_vault(&payload).await.unwrap();
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        let phrase = created["recovery_phrase"].as_str().unwrap().to_string();
        state.lock().await.unwrap();
        (Arc::new(state), phrase)
    }

    /// Phrase enrollment seals the fresh device key at birth: the private
    /// key never rests as plaintext on disk between enroll and the next
    /// unlock (the creation flow seals; enroll must not write plaintext).
    #[tokio::test]
    async fn enroll_with_phrase_seals_the_device_key_at_birth() {
        if !baluard_core::keyring_disabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (state, phrase) = vault_with_phrase(&dir).await;

        state
            .enroll_with_recovery_phrase(&phrase, PASSWORD)
            .await
            .unwrap();

        let privkey_path = dir.path().join("meta/device-privkey.json");
        let raw = std::fs::read_to_string(&privkey_path).unwrap();
        assert!(
            !raw.contains("x25519_private"),
            "plaintext key material on disk: {raw}"
        );
        assert_eq!(file_kind(&privkey_path), PrivkeyFileKind::Sealed);
        // The sealed file opens under the password's devkey seal subkey.
        state.unlock(PASSWORD).await.unwrap();
    }

    /// The password is proven against the KEK canary BEFORE any enrollment
    /// write: a mistyped password must not mint a ghost device or disturb
    /// the vault (same guard as the providers join flow).
    #[tokio::test]
    async fn enroll_with_phrase_refuses_a_wrong_password_without_writes() {
        if !baluard_core::keyring_disabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (state, phrase) = vault_with_phrase(&dir).await;
        let roster_before = std::fs::read_to_string(dir.path().join("meta/devices.json")).unwrap();
        let privkey_before =
            std::fs::read_to_string(dir.path().join("meta/device-privkey.json")).unwrap();

        let err = state
            .enroll_with_recovery_phrase(&phrase, "not the password")
            .await
            .unwrap_err();
        assert!(err.contains("master password incorrect"), "err: {err}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("meta/devices.json")).unwrap(),
            roster_before
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("meta/device-privkey.json")).unwrap(),
            privkey_before
        );
    }
}

/// D79: the desktop stops the daemon only after prepare_update reports
/// success, so a refused drain must leave the vault unlocked and a finished
/// cycle must drain-and-lock. The with_timeout variant keeps the refusal
/// test fast instead of waiting out the 30s production budget.
#[cfg(test)]
mod unlock_proof_tests {
    use super::*;

    const MASTER: &str = "unlock-proof-master-password";

    async fn unlocked_vault() -> (tempfile::TempDir, Arc<VaultState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": MASTER, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(MASTER).await.unwrap();
        (dir, state)
    }

    // B1: while the vault is open, vault.unlock with an arbitrary
    // password used to return Ok and re-mint the session token with no
    // proof at all, handing the bearer capability to any same-user
    // caller. The short-circuit may skip the tail, never the proof.
    #[tokio::test]
    async fn unlock_on_an_open_vault_demands_the_master_password() {
        let (_dir, state) = unlocked_vault().await;
        let err = state
            .unlock("definitely-not-the-password")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("master password incorrect"),
            "got: {err}"
        );
        state
            .unlock(MASTER)
            .await
            .expect("the real password still unlocks");
        assert!(state.get_session_token().await.is_some());
    }
}

#[cfg(test)]
mod prepare_update_tests {
    use super::*;
    use std::time::Duration;

    const MASTER: &str = "prepare-update-master-password";

    async fn unlocked_vault() -> (tempfile::TempDir, Arc<VaultState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": MASTER, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(MASTER).await.unwrap();
        (dir, state)
    }

    #[tokio::test]
    async fn prepare_for_update_refuses_while_a_sync_cycle_is_in_flight() {
        let (_dir, state) = unlocked_vault().await;
        let cycle = state.autosync.cycle_lock_guard().await;
        let err = state
            .prepare_for_update_with_timeout(Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(err.contains("sync cycle is still running"), "got: {err}");
        assert!(state.is_unlocked().await, "a refused prepare must not lock");
        drop(cycle);
        state
            .prepare_for_update_with_timeout(Duration::from_secs(2))
            .await
            .expect("drains and locks once the cycle finishes");
        assert!(!state.is_unlocked().await);
    }
}

/// The avatar byte I/O must not hold the inner vault lock: a FIFO keeps
/// the blocking read alive for a known window and a probe taking the
/// write lock inside that window proves nothing else holds it.
/// Unix-only: named pipes.
#[cfg(all(test, unix))]
mod avatar_lock_tests {
    use super::VaultState;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const MASTER: &str = "avatar-lock-pass-3";

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn avatar_io_does_not_hold_the_vault_lock() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": MASTER, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(MASTER).await.unwrap();
        {
            let guard = state.inner.write().await;
            let handle = guard.as_ref().expect("unlocked");
            let mut profile = handle.load_profile().unwrap_or_default();
            profile.avatar_ext = Some("png".into());
            handle.save_profile(&profile).unwrap();
        }

        let fifo = dir.path().join("meta").join("avatar.png");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");

        let (opened_tx, opened_rx) = std::sync::mpsc::channel::<()>();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel::<Instant>();
        let writer_fifo = fifo.clone();
        std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_fifo)
                .unwrap();
            let _ = opened_tx.send(());
            std::thread::sleep(Duration::from_millis(400));
            use std::io::Write;
            let _ = f.write_all(b"fifo probe bytes");
            drop(f);
            let _ = closed_tx.send(Instant::now());
        });

        let getter_state = state.clone();
        let getter = tokio::spawn(async move { getter_state.avatar_get().await });

        // The FIFO only opens once avatar_get has entered the read, so a
        // lock acquired before the writer closes proves the lock is not
        // held across the blocked I/O.
        opened_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut acquired: Option<Instant> = None;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if state.inner.try_write().is_ok() {
                acquired = Some(Instant::now());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let closed = closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let result = getter.await.unwrap();
        assert!(result.is_ok(), "avatar_get should complete: {result:?}");
        let acquired = acquired.expect("probe must acquire the lock while the avatar read blocks");
        assert!(
            acquired < closed,
            "avatar I/O held the vault lock across the blocked read"
        );
    }

    /// A removal that commits while a legacy read is in flight must win:
    /// the migration commit must not resurrect avatar.enc from bytes it
    /// read before the remove.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn avatar_remove_wins_over_an_inflight_migration() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": MASTER, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(MASTER).await.unwrap();
        {
            let guard = state.inner.write().await;
            let handle = guard.as_ref().expect("unlocked");
            let mut profile = handle.load_profile().unwrap_or_default();
            profile.avatar_ext = Some("png".into());
            handle.save_profile(&profile).unwrap();
        }

        let fifo = dir.path().join("meta").join("avatar.png");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");

        let (opened_tx, opened_rx) = std::sync::mpsc::channel::<()>();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();
        let writer_fifo = fifo.clone();
        std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_fifo)
                .unwrap();
            let _ = opened_tx.send(());
            std::thread::sleep(Duration::from_millis(400));
            use std::io::Write;
            let _ = f.write_all(b"stale bytes");
            drop(f);
            let _ = closed_tx.send(());
        });

        let getter_state = state.clone();
        let getter = tokio::spawn(async move { getter_state.avatar_get().await });
        // The remove payload commits while the legacy bytes are still in
        // flight, so the migration commit races the removal.
        let _ = opened_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        state
            .avatar_set(&serde_json::json!({"data": "", "ext": "png"}).to_string())
            .await
            .unwrap();
        let result = getter.await.unwrap();
        assert!(result.is_ok(), "avatar_get should complete: {result:?}");
        let _ = closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let enc = dir.path().join("meta").join("avatar.enc");
        assert!(
            !enc.exists(),
            "a removed avatar must not be resurrected by the in-flight migration"
        );
        assert!(!fifo.exists(), "the legacy plaintext must stay removed");
        {
            let guard = state.inner.read().await;
            let handle = guard.as_ref().expect("unlocked");
            let profile = handle.load_profile().unwrap_or_default();
            assert_eq!(
                profile.avatar_ext, None,
                "the removal must own the final profile"
            );
        }
    }
}

#[cfg(test)]
mod pin_hw_escrow_tests {
    use super::VaultState;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const MASTER: &str = "pin-hw-master-pass-7";
    const PIN: &str = "246813";

    pub(super) static TEST_STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static TAP_OFF_WORKER: AtomicBool = AtomicBool::new(false);

    /// H5 red signal: a chip derive reached from inside `block_on` panics
    /// on a tokio worker (blocking-region guard) but succeeds on the
    /// blocking pool. The flag records which thread paid the tap.
    struct PinHwMock {
        probe_blocking_thread: bool,
    }

    impl baluard_core::hwkey::HardwareKeyStore for PinHwMock {
        fn backend_id(&self) -> &'static str {
            "mock"
        }

        fn probe(&self) -> baluard_core::hwkey::HwCapability {
            baluard_core::hwkey::HwCapability::Available {
                backend: "mock".into(),
            }
        }

        fn interaction(&self) -> baluard_core::hwkey::Interaction {
            baluard_core::hwkey::Interaction::PerUse
        }

        fn create_binding(
            &self,
            vault_id: uuid::Uuid,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::BindingInfo, baluard_core::error::BaluardError> {
            Ok(baluard_core::hwkey::BindingInfo {
                binding: baluard_core::hwkey::binding_tag(vault_id),
                attestation: None,
            })
        }

        fn derive_ephemeral(
            &self,
            binding: &str,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<
            (
                baluard_core::hwkey::Handshake,
                baluard_core::hwkey::SharedSecret,
            ),
            baluard_core::error::BaluardError,
        > {
            let mut secret = [0u8; 32];
            for (index, byte) in binding.bytes().chain([0x04, 0x02]).enumerate() {
                secret[index % 32] ^= byte;
            }
            Ok((
                baluard_core::hwkey::Handshake(vec![0x04, 0x02]),
                zeroize::Zeroizing::new(secret),
            ))
        }

        fn derive(
            &self,
            binding: &str,
            handshake: &baluard_core::hwkey::Handshake,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::SharedSecret, baluard_core::error::BaluardError> {
            // H5 red signal lives HERE: the reopen tap path. block_on
            // panics on a tokio worker (blocking-region guard) but works
            // on the blocking pool, so the flag records which thread paid
            // the tap.
            if self.probe_blocking_thread {
                let on_worker = std::panic::catch_unwind(|| {
                    tokio::runtime::Handle::current().block_on(async { 1u8 })
                })
                .is_err();
                TAP_OFF_WORKER.store(!on_worker, Ordering::SeqCst);
            }
            let mut secret = [0u8; 32];
            for (index, byte) in binding
                .bytes()
                .chain(handshake.0.iter().copied())
                .enumerate()
            {
                secret[index % 32] ^= byte;
            }
            Ok(zeroize::Zeroizing::new(secret))
        }

        fn delete_binding(&self, _: &str) -> Result<(), baluard_core::error::BaluardError> {
            Ok(())
        }
    }

    /// Drop-based kill-switch restore: the runtime suite runs under
    /// BALUARD_DISABLE_HWKEY, but the pin_unlock paths consult the hwkey
    /// registry and would skip the mock. Restores the env + clears the
    /// process-global store even when an assertion panics.
    pub(super) struct HwEnvGuard {
        old: Option<String>,
    }

    impl HwEnvGuard {
        pub(super) fn clear() -> Self {
            let old = std::env::var(baluard_core::hwkey::DISABLE_ENV).ok();
            // SAFETY: serialized by TEST_STORE_LOCK; sibling hw test
            // modules hold the same lock while touching the var.
            unsafe {
                std::env::remove_var(baluard_core::hwkey::DISABLE_ENV);
            }
            baluard_core::hwkey::uninstall();
            Self { old }
        }
    }

    impl Drop for HwEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.old {
                    Some(v) => std::env::set_var(baluard_core::hwkey::DISABLE_ENV, v),
                    None => std::env::remove_var(baluard_core::hwkey::DISABLE_ENV),
                }
            }
            baluard_core::hwkey::uninstall();
        }
    }

    /// Unlocked vault with PIN escrow enabled and the device key sealed to
    /// the mock; returns locked, with the store UNINSTALLED so a plain
    /// `pin_unlock` hits the chip-gone path.
    async fn sealed_pin_vault(probe: bool) -> (tempfile::TempDir, Arc<VaultState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": MASTER, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(MASTER).await.unwrap();
        state
            .pin_enable(&serde_json::json!({"password": MASTER, "pin": PIN}).to_string())
            .await
            .unwrap();
        let (seal_key, vault_id, device_id, path) = {
            let guard = state.inner.read().await;
            let handle = guard.as_ref().expect("unlocked");
            (
                handle.unlocked().devkey_seal,
                handle.vault_id,
                handle.device_id,
                handle.path.clone(),
            )
        };
        // enable_hw_seal resolves a backend store; install the mock for
        // the seal, the caller decides what is plugged in afterwards.
        baluard_core::hwkey::install(Arc::new(PinHwMock {
            probe_blocking_thread: probe,
        }));
        baluard_core::vault::device_privkey::enable_hw_seal(
            &path.join("meta/device-privkey.json"),
            &seal_key,
            vault_id,
            Some(device_id),
            false,
            None,
        )
        .unwrap();
        state.lock().await.unwrap();
        // The caller decides what is "plugged in": strip the store so a
        // plain pin_unlock hits the chip-gone path.
        baluard_core::hwkey::uninstall();
        (dir, state)
    }

    /// H5: a correct PIN with the chip unplugged must NOT destroy the
    /// escrow — the PIN still holds, only the hardware is absent. The
    /// user retries with the key plugged in and unlocks without ever
    /// typing the master password.
    #[tokio::test]
    async fn pin_unlock_keeps_the_escrow_on_hardware_errors() {
        let _lock = TEST_STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _env = HwEnvGuard::clear();
        let (_dir, state) = sealed_pin_vault(false).await;

        // Chip gone: the unlock fails with the typed chip-unavailable
        // error (the PIN itself verified).
        let err = state
            .pin_unlock(&serde_json::json!({"pin": PIN}).to_string())
            .await
            .unwrap_err();
        let msg = err.message();
        assert!(
            msg.contains("chip is unavailable"),
            "expected the chip-unavailable copy, got: {msg}"
        );

        // The escrow must survive: PIN is still enabled.
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(
            s["enabled"], true,
            "hardware error destroyed the PIN escrow"
        );

        // Chip back: the same PIN unlocks, paying the tap.
        baluard_core::hwkey::install(Arc::new(PinHwMock {
            probe_blocking_thread: false,
        }));
        state
            .pin_unlock(&serde_json::json!({"pin": PIN}).to_string())
            .await
            .expect("PIN unlock after the key returns");
        assert!(state.is_unlocked().await);
    }

    /// H5: the tap wait must run on the blocking pool, not pin a tokio
    /// worker (spawn_blocking, like the password unlock path).
    #[tokio::test]
    async fn pin_unlock_tap_runs_off_the_runtime_worker() {
        let _lock = TEST_STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _env = HwEnvGuard::clear();
        TAP_OFF_WORKER.store(false, Ordering::SeqCst);
        let (_dir, state) = sealed_pin_vault(false).await;
        baluard_core::hwkey::install(Arc::new(PinHwMock {
            probe_blocking_thread: true,
        }));

        state
            .pin_unlock(&serde_json::json!({"pin": PIN}).to_string())
            .await
            .expect("PIN unlock with the chip present");

        assert!(
            TAP_OFF_WORKER.load(Ordering::SeqCst),
            "the chip derive ran on the async runtime worker"
        );
    }

    #[tokio::test]
    async fn password_rechecks_keep_the_live_signing_cache_without_tapping() {
        let _lock = TEST_STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _env = HwEnvGuard::clear();
        let (dir, state) = sealed_pin_vault(false).await;
        baluard_core::hwkey::install(Arc::new(PinHwMock {
            probe_blocking_thread: false,
        }));
        state.unlock(MASTER).await.unwrap();
        let info = serde_json::from_str::<serde_json::Value>(&state.info().await.unwrap()).unwrap();
        let device_id = uuid::Uuid::parse_str(info["device_id"].as_str().unwrap()).unwrap();
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(dir.path(), device_id).is_some()
        );

        // Password-only proofs must work with the key unplugged and must not
        // let a temporary handle evict the live session's signing key.
        baluard_core::hwkey::uninstall();
        state.reprompt_verify(MASTER).await.unwrap();
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(dir.path(), device_id).is_some()
        );
        state.reprompt_verify("definitely-wrong").await.unwrap_err();
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(dir.path(), device_id).is_some()
        );

        let _ = state
            .biometric_enable(&serde_json::json!({"password": MASTER}).to_string())
            .await;
        assert!(
            baluard_core::vault::handle::cached_device_signing_key(dir.path(), device_id).is_some(),
            "biometric password verification evicted the live signing key"
        );
    }
}

/// M1: device-file read-modify-write cycles (enable / disable / consent
/// / password change) mutate meta/device-privkey.json and the keywrap
/// as a pair; two racing ops can interleave the halves and strand the
/// seal against the keywrap, so they serialize per vault.
#[cfg(test)]
mod devkey_op_lock_tests {
    use super::VaultState;
    use super::pin_hw_escrow_tests::{HwEnvGuard, TEST_STORE_LOCK};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OPEN_BINDINGS: AtomicUsize = AtomicUsize::new(0);
    static MAX_OPEN_BINDINGS: AtomicUsize = AtomicUsize::new(0);

    struct RacingMock;

    impl baluard_core::hwkey::HardwareKeyStore for RacingMock {
        fn backend_id(&self) -> &'static str {
            "racing"
        }

        fn probe(&self) -> baluard_core::hwkey::HwCapability {
            baluard_core::hwkey::HwCapability::Available {
                backend: "racing".into(),
            }
        }

        fn interaction(&self) -> baluard_core::hwkey::Interaction {
            baluard_core::hwkey::Interaction::PerUse
        }

        fn create_binding(
            &self,
            vault_id: uuid::Uuid,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::BindingInfo, baluard_core::error::BaluardError> {
            let open = OPEN_BINDINGS.fetch_add(1, Ordering::SeqCst) + 1;
            MAX_OPEN_BINDINGS.fetch_max(open, Ordering::SeqCst);
            // Widen the window: a second enable reaching create_binding
            // while the first is still here proves no serialization.
            std::thread::sleep(std::time::Duration::from_millis(150));
            OPEN_BINDINGS.fetch_sub(1, Ordering::SeqCst);
            Ok(baluard_core::hwkey::BindingInfo {
                binding: baluard_core::hwkey::binding_tag(vault_id),
                attestation: None,
            })
        }

        fn derive_ephemeral(
            &self,
            binding: &str,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<
            (
                baluard_core::hwkey::Handshake,
                baluard_core::hwkey::SharedSecret,
            ),
            baluard_core::error::BaluardError,
        > {
            let mut secret = [0u8; 32];
            for (index, byte) in binding.bytes().chain([0x04, 0x02]).enumerate() {
                secret[index % 32] ^= byte;
            }
            Ok((
                baluard_core::hwkey::Handshake(vec![0x04, 0x02]),
                zeroize::Zeroizing::new(secret),
            ))
        }

        fn derive(
            &self,
            binding: &str,
            handshake: &baluard_core::hwkey::Handshake,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::SharedSecret, baluard_core::error::BaluardError> {
            let mut secret = [0u8; 32];
            for (index, byte) in binding
                .bytes()
                .chain(handshake.0.iter().copied())
                .enumerate()
            {
                secret[index % 32] ^= byte;
            }
            Ok(zeroize::Zeroizing::new(secret))
        }

        fn delete_binding(&self, _: &str) -> Result<(), baluard_core::error::BaluardError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn device_key_operations_serialize_per_vault() {
        let _store = TEST_STORE_LOCK.lock().unwrap();
        let _env = HwEnvGuard::clear();
        baluard_core::hwkey::install(Arc::new(RacingMock));
        MAX_OPEN_BINDINGS.store(0, Ordering::SeqCst);

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        state
            .create_vault(
                &serde_json::json!({"password": "op-lock-pass-1", "profile": "mobile_low"})
                    .to_string(),
            )
            .await
            .unwrap();
        state.unlock("op-lock-pass-1").await.unwrap();

        let (a, b) = tokio::join!(
            state.hw_enable(false, Some("racing".into())),
            state.hw_enable(false, Some("racing".into())),
        );
        a.unwrap();
        b.unwrap();

        assert_eq!(
            MAX_OPEN_BINDINGS.load(Ordering::SeqCst),
            1,
            "racing enables overlapped inside create_binding"
        );
    }

    struct SlowSealMock;

    impl baluard_core::hwkey::HardwareKeyStore for SlowSealMock {
        fn backend_id(&self) -> &'static str {
            "slow-seal"
        }

        fn probe(&self) -> baluard_core::hwkey::HwCapability {
            baluard_core::hwkey::HwCapability::Available {
                backend: "slow-seal".into(),
            }
        }

        fn interaction(&self) -> baluard_core::hwkey::Interaction {
            baluard_core::hwkey::Interaction::PerUse
        }

        fn create_binding(
            &self,
            vault_id: uuid::Uuid,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::BindingInfo, baluard_core::error::BaluardError> {
            Ok(baluard_core::hwkey::BindingInfo {
                binding: baluard_core::hwkey::binding_tag(vault_id),
                attestation: None,
            })
        }

        fn derive_ephemeral(
            &self,
            binding: &str,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<
            (
                baluard_core::hwkey::Handshake,
                baluard_core::hwkey::SharedSecret,
            ),
            baluard_core::error::BaluardError,
        > {
            let mut secret = [0u8; 32];
            for (index, byte) in binding.bytes().chain([0x04, 0x02]).enumerate() {
                secret[index % 32] ^= byte;
            }
            Ok((
                baluard_core::hwkey::Handshake(vec![0x04, 0x02]),
                zeroize::Zeroizing::new(secret),
            ))
        }

        fn derive(
            &self,
            binding: &str,
            handshake: &baluard_core::hwkey::Handshake,
            _: baluard_core::hwkey::HwConsent,
        ) -> Result<baluard_core::hwkey::SharedSecret, baluard_core::error::BaluardError> {
            // The reopen tap: slow enough that the test can observe the
            // lock state while the "user holds the key" window is open.
            std::thread::sleep(std::time::Duration::from_millis(400));
            let mut secret = [0u8; 32];
            for (index, byte) in binding
                .bytes()
                .chain(handshake.0.iter().copied())
                .enumerate()
            {
                secret[index % 32] ^= byte;
            }
            Ok(zeroize::Zeroizing::new(secret))
        }

        fn delete_binding(&self, _: &str) -> Result<(), baluard_core::error::BaluardError> {
            Ok(())
        }
    }

    /// The chip wait in a password change must not pin the vault lock:
    /// other vault operations stay readable while the user holds the key.
    /// Multi-thread flavor: the unsplit path uses block_in_place, which
    /// panics on the current-thread test runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_change_does_not_hold_the_write_lock_across_taps() {
        let _store = TEST_STORE_LOCK.lock().unwrap();
        let _env = HwEnvGuard::clear();
        baluard_core::hwkey::install(Arc::new(SlowSealMock));

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(VaultState::new(dir.path().to_path_buf()));
        let old_pass = format!("slow-seal-pass-{}", 1);
        let new_pass = format!("slow-seal-pass-{}", 2);
        state
            .create_vault(
                &serde_json::json!({"password": old_pass, "profile": "mobile_low"}).to_string(),
            )
            .await
            .unwrap();
        state.unlock(&old_pass).await.unwrap();
        state
            .hw_enable(false, Some("slow-seal".into()))
            .await
            .unwrap();

        let changer = {
            let st = state.clone();
            let old = old_pass.clone();
            let new = new_pass.clone();
            tokio::spawn(async move { st.change_master_password(&old, &new).await })
        };
        // Give the change time to reach its chip wait (which runs under
        // the write lock on the unsplit path).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let started = std::time::Instant::now();
        state.is_unlocked().await;
        let elapsed = started.elapsed();
        changer.await.unwrap().unwrap();
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "a vault read blocked {elapsed:?} behind the password change's tap"
        );

        state.lock().await.unwrap();
        state.unlock(&new_pass).await.unwrap();
    }
}
