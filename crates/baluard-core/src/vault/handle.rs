//! Vault handle: locked/unlocked session state.
//!
//! The VaultHandle is the primary interface for vault operations.
//! Locked: can list cipher metadata (filenames, envelope headers).
//! Unlocked: can decrypt ciphers, add/update/delete with proper key material.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::crypto::hkdf_derive;
use crate::crypto::hpke_wrap;
use crate::crypto::kdf;
use crate::device_manager::DeviceManager;
use crate::devices::DeviceRegistry;
use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::{ItemKey, RootKey};
use crate::types::{Cipher, CipherInput, KdfParams, Tier};
use crate::vault::cipher;
use crate::vault::index;

use zeroize::Zeroize;

/// Vault session state.
/// Collect a folder ID and all its descendant folder IDs.
fn collect_descendant_ids(
    folder_id: Uuid,
    folders: &[crate::vault::manifest::Folder],
) -> HashSet<Uuid> {
    let mut result = HashSet::new();
    result.insert(folder_id);
    let mut queue = vec![folder_id];
    while let Some(current) = queue.pop() {
        for f in folders {
            if f.parent_id == Some(current) {
                result.insert(f.id);
                queue.push(f.id);
            }
        }
    }
    result
}

pub struct VaultHandle {
    /// Path to the vault directory on disk.
    pub path: PathBuf,
    /// Vault ID (set at creation, loaded from metadata).
    pub vault_id: Uuid,
    /// KDF parameters (loaded from meta/kdf-params.json).
    pub kdf_params: KdfParams,
    /// Device registry (loaded from meta/devices.json).
    /// Kept for backward compat; DeviceManager is the authoritative owner.
    pub registry: DeviceRegistry,
    /// Current device ID.
    pub device_id: Uuid,
    /// Device lifecycle coordinator (MISS-2).
    /// Loaded on open, manages epoch state, enrollment, and rotation.
    pub device_manager: DeviceManager,
    /// Session state.
    pub state: VaultState,
}

/// Vault lock state with key material.
pub enum VaultState {
    /// Vault is locked. No key material in memory.
    Locked,
    /// Vault is unlocked. Root Key and session keys available.
    Unlocked(UnlockedState),
}

/// Key material held while vault is unlocked.
pub struct UnlockedState {
    /// Root Key (512-bit, per-epoch).
    pub root_key: RootKey,
    /// Space Group Key (256-bit, per-space). DESIGN-3: intermediate layer.
    /// Derived from RootKey for single-user; random for multi-user/org.
    pub space_group_key: crate::keys::hierarchy::SpaceGroupKey,
    /// Session Key (for local cache encryption).
    pub session_key: [u8; 32],
    /// Sync-Only Key (for locked background sync).
    pub sync_key: [u8; 32],
    /// Cached Item Keys: cipher_id → ItemKey.
    /// Loaded on-demand, cached for performance.
    pub item_keys: HashMap<Uuid, ItemKey>,
    /// Device-privkey seal subkey (C1): HKDF(KEK, "baluard-devkey-v1").
    /// Lets post-unlock consumers (sync signing, password change) open the
    /// sealed `meta/device-privkey.json` without keeping the KEK resident.
    pub devkey_seal: [u8; 32],
    /// Current key epoch (read from RK canary or envelope).
    pub current_epoch: u64,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.space_group_key.zeroize();
        self.session_key.zeroize();
        self.sync_key.zeroize();
    }
}

impl VaultHandle {
    /// Open a vault from disk (locked state).
    /// Reads metadata files but does NOT decrypt anything.
    pub fn open(path: &Path) -> Result<Self, BaluardError> {
        let kdf_path = path.join("meta/kdf-params.json");
        if !kdf_path.exists() {
            return Err(VaultError::NotInitialized.into());
        }

        let kdf_json = std::fs::read_to_string(&kdf_path)
            .map_err(|e| VaultError::Metadata(format!("reading kdf params: {e}")))?;
        let kdf_params: KdfParams = serde_json::from_str(&kdf_json)
            .map_err(|e| VaultError::Corrupt(format!("kdf params: {e}")))?;

        let registry_path = path.join("meta/devices.json");
        let registry = if registry_path.exists() {
            let reg_json = std::fs::read_to_string(&registry_path)
                .map_err(|e| VaultError::Metadata(format!("reading devices: {e}")))?;
            serde_json::from_str(&reg_json)
                .map_err(|e| VaultError::Corrupt(format!("devices: {e}")))?
        } else {
            DeviceRegistry::new()
        };

        // Find our device ID from the keywrap files
        let device_id = Self::find_device_id(path)?;

        // Derive vault_id deterministically from KDF salt (stable, unique per vault).
        // No meta file needed: same salt always produces the same UUID.
        let vault_id = Self::derive_vault_id(&kdf_params);

        // MISS-2: Load DeviceManager from vault directory
        let mut device_manager = if DeviceManager::vault_files_exist(path) {
            DeviceManager::load_from_vault(path)?
        } else {
            let mut dm = DeviceManager::new();
            dm.set_vault_path(path);
            dm.epoch
                .activate()
                .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
            dm
        };
        // Ensure epoch is ACTIVE for existing vaults (may be CREATED after load)
        if device_manager.epoch_state() == crate::keys::epoch::EpochState::Created {
            device_manager
                .epoch
                .activate()
                .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
        }

        // B-1 fix: reconcile an interrupted root-key rotation.
        //
        // `rotate_root_key` writes staged .tmp files then renames them in
        // order (ciphers -> canary -> keywrap, keywrap being the point of no
        // return). The RAII RotationGuard sweeps .tmp on drop if the function
        // unwinds, but a hard process kill leaves the marker + leftover .tmp
        // behind. We cannot finish a half-applied rotation here (no new
        // RootKey), so the safe reconciliation is: sweep any staged .tmp
        // files so the next rotation starts clean, and surface the marker
        // loudly so the user knows the vault may be in a mixed-epoch state.
        //
        // The marker only exists for the brief rotation window; if it
        // survives to here the rotation did not commit cleanly.
        let pending_marker = path.join("meta/.rotation-pending");
        if pending_marker.exists() {
            eprintln!(
                "WARNING: vault at {} has a leftover .rotation-pending marker; \
                 a root-key rotation did not complete cleanly. Sweeping staged files.",
                path.display()
            );
            for dir_name in &["ciphers", "trash", "meta", "meta/keywrap"] {
                remove_tmp_files(&path.join(dir_name));
            }
            remove_tmp_files_recursive(&path.join("entries"));
            // Leave the marker in place: a sweep is not a successful commit,
            // and the epoch state below may still need operator attention.
        }

        // H3 fix: Rollback detection on vault open.
        // Load integrity manifest and compare against actual file state.
        // Warn on rollback (don't block: manifest is in writable tree, not externally anchored).
        if let Ok(manifest) = crate::integrity::IntegrityManifest::load(path) {
            let mut actual_seqs = HashMap::new();
            let ciphers_dir = path.join("ciphers");
            if ciphers_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&ciphers_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.ends_with(".enc") {
                            let object_id = name_str.trim_end_matches(".enc").to_string();
                            if let Ok(data) = std::fs::read(entry.path()) {
                                if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                                    actual_seqs.insert(object_id, envelope.header.update_seq);
                                }
                            }
                        }
                    }
                }
            }
            let rollbacks = manifest.detect_rollback(&actual_seqs);
            if !rollbacks.is_empty() {
                eprintln!(
                    "WARNING: rollback detected! {} object(s) have lower sequence numbers than expected:",
                    rollbacks.len()
                );
                for rb in &rollbacks {
                    eprintln!(
                        "  - {} expected_seq={} actual_seq={}",
                        rb.object_id, rb.expected_seq, rb.actual_seq
                    );
                }
            }
        }

        Ok(VaultHandle {
            path: path.to_path_buf(),
            vault_id,
            kdf_params,
            registry,
            device_id,
            device_manager,
            state: VaultState::Locked,
        })
    }

    /// Unlock the vault with the master password.
    ///
    /// Flow:
    /// 1. Derive KEK from password + KDF params
    /// 2. Read our device's keywrap file
    /// 3. HPKE-decapsulate Root Key using device X25519 private key
    ///
    /// Note: In CLI mode, the device X25519 private key is stored in the
    /// keywrap JSON for simplicity. In production, this lives in OS keystore.
    pub fn unlock(&mut self, master_password: &str) -> Result<(), BaluardError> {
        // Step 0: Rate limit check
        self.check_attempt_rate_limit()?;

        // Step 1: Derive KEK (expensive Argon2id)
        let kek = kdf::derive_kek(master_password, &self.kdf_params)?;

        // Steps 2-8: shared unlock tail. For the master-password path a
        // failed canary/keywrap verification MUST record a failed attempt so
        // the on-disk attempt counter advances (brute-force protection).
        match self.unlock_with_kek(&kek) {
            Ok(()) => {
                self.clear_failed_attempts()?;
                Ok(())
            }
            Err(e) => {
                let _ = self.record_failed_attempt();
                Err(e)
            }
        }
    }

    /// Unlock the vault using a pre-derived KEK, skipping the expensive
    /// Argon2id derivation. Runs the shared unlock tail: derive session/sync
    /// keys, HPKE-unwrap the Root Key, verify both canaries, swap state.
    ///
    /// Used by session PIN Quick Unlock: the daemon retains the KEK in
    /// memory (mlocked, zeroized on drop) after the first master-password
    /// unlock, and a PIN gate re-unlocks without re-running Argon2id. The
    /// PIN path does NOT record on-disk failed attempts; the daemon's
    /// per-vault PIN counter owns attempt accounting and nukes the escrow
    /// after `MAX_PIN_FAILURES` tries (Bitwarden-equivalent policy).
    ///
    /// No key material crosses IPC. `kek` is zeroized by the caller when done.
    pub fn unlock_with_kek(&mut self, kek: &[u8; 32]) -> Result<(), BaluardError> {
        // Step 2: Derive session + sync keys, plus the device-privkey seal
        // subkey (C1). The subkey, never the KEK, is retained post-unlock.
        let session_key = hkdf_derive::derive_session_key(kek)?;
        let sync_key = hkdf_derive::derive_sync_key(kek)?;
        let devkey_seal = hkdf_derive::derive_devkey_seal_key(kek)?;

        // Step 3: Verify KEK is correct by decrypting the KEK canary
        // Canary plaintext MUST equal b"baluard-kek-ok" — this catches wrong passwords
        // even when AES-GCM doesn't fail (cosmically unlikely but defense-in-depth).
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_data = std::fs::read(self.path.join("meta/kek-canary.enc"))
                .map_err(|e| VaultError::Metadata(format!("reading kek canary: {e}")))?;
            super::canary::verify_kek_canary(&session_key, &canary_data)?;
        }

        // Step 4: HPKE-decapsulate Root Key using device private key (keyring or file).
        // If unwrap fails on a fast-path resolved device_id, fall back through other
        // enrolled candidates to provide self-healing recovery against corrupted or
        // spoofed meta/device-id entries (F1 self-healing fix).
        let (root_key, _matched_device_id) = {
            let attempt_unwrap = |dev_id: Uuid| -> Result<RootKey, BaluardError> {
                let kw_path = self.path.join(format!("meta/keywrap/{dev_id}.json"));
                if !kw_path.exists() {
                    return Err(VaultError::NotFound(format!("keywrap for {dev_id}")).into());
                }
                let kw_json = std::fs::read_to_string(&kw_path)
                    .map_err(|e| VaultError::Metadata(format!("reading keywrap: {e}")))?;
                let parsed_kw = super::keywrap::parse_keywrap_json(&kw_json)?;
                let privs = load_device_privkeys(&self.path, dev_id, Some(&devkey_seal))?;
                let unwrapped = hpke_wrap::unwrap_key(
                    &parsed_kw.ephemeral_public,
                    &parsed_kw.encrypted_key,
                    &parsed_kw.tag,
                    &privs.x25519,
                )?;
                let rk_bytes: [u8; 64] = unwrapped
                    .try_into()
                    .map_err(|_| VaultError::Corrupt("unwrapped root key not 64 bytes".into()))?;
                let rk = RootKey::from_bytes(rk_bytes);
                self.verify_root_key(&rk)?;
                Ok(rk)
            };

            match attempt_unwrap(self.device_id) {
                Ok(rk) => (rk, self.device_id),
                Err(primary_err) => {
                    let keywrap_dir = self.path.join("meta/keywrap");
                    let mut healed = None;
                    if keywrap_dir.exists() {
                        if let Ok(entries) = std::fs::read_dir(&keywrap_dir) {
                            for entry in entries.flatten() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                if let Some(id_str) = name.strip_suffix(".json") {
                                    if let Ok(candidate_id) = Uuid::parse_str(id_str) {
                                        if candidate_id != self.device_id {
                                            if let Ok(rk) = attempt_unwrap(candidate_id) {
                                                healed = Some((rk, candidate_id));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some((rk, healed_id)) = healed {
                        self.device_id = healed_id;
                        let _ =
                            crate::vault::device_privkey::write_device_id(&self.path, healed_id);
                        (rk, healed_id)
                    } else {
                        return Err(primary_err);
                    }
                }
            }
        };

        // Step 7: Determine current epoch from any existing cipher or RK canary
        let current_epoch = self.determine_current_epoch();

        self.state = VaultState::Unlocked(UnlockedState {
            root_key: root_key.clone(),
            space_group_key: crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                &root_key,
                current_epoch,
            ),
            session_key,
            sync_key,
            devkey_seal,
            item_keys: HashMap::new(),
            current_epoch,
        });

        // C1: lazily re-seal a legacy plaintext device-privkey file now that
        // the KEK is proven correct. Best-effort — a failure must not fail
        // the unlock; the next unlock retries.
        {
            let path = self.path.join("meta/device-privkey.json");
            let _ = crate::vault::device_privkey::reseal_if_legacy(
                &path,
                &devkey_seal,
                Some(self.device_id),
            );
            let _ = crate::vault::device_privkey::write_device_id(&self.path, self.device_id);
        }

        // M6 fix: ensure registries stay in sync after unlock
        self.sync_registry_to_device_manager();

        // Migrate plaintext metadata to encrypted format
        self.migrate_plaintext_metadata();

        Ok(())
    }

    /// Change the master password. Requires unlocked vault.
    ///
    /// H1 fix: Re-derives KEK, re-wraps the Root Key, re-encrypts the KEK canary,
    /// updates KDF params, and disables stale biometric secrets.
    ///
    /// **Security note**: The master password gates the KEK canary (password verification)
    /// and the keywrap (encrypted via device X25519 key). The device private key
    /// (from OS keyring or `meta/device-privkey.json`) independently controls Root Key
    /// access. Password change alone does NOT protect against an attacker who holds
    /// the device private key. For post-compromise remediation, call `rotate_root_key()`
    /// or `revoke_device_and_rekey()` after changing the password.
    pub fn change_master_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        // Step 1: Verify old password
        let old_kek = kdf::derive_kek(old_password, &self.kdf_params)?;
        let old_session_key = hkdf_derive::derive_session_key(&old_kek)?;
        let old_devkey_seal = hkdf_derive::derive_devkey_seal_key(&old_kek)?;
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_data = std::fs::read(self.path.join("meta/kek-canary.enc"))?;
            super::canary::verify_kek_canary(&old_session_key, &canary_data)
                .map_err(|_| VaultError::Corrupt("old master password incorrect".into()))?;
        }

        // C1 pre-check: a sealed devkey file must open under the OLD seal
        // key BEFORE we rotate anything, otherwise a later failure would
        // leave a file the next unlock cannot open (lockout). Fail here,
        // before any write.
        let devkey_path = self.path.join("meta/device-privkey.json");
        if crate::vault::device_privkey::file_kind(&devkey_path)
            == crate::vault::device_privkey::PrivkeyFileKind::Sealed
        {
            let file = std::fs::read_to_string(&devkey_path)?;
            crate::vault::device_privkey::open_bytes(&old_devkey_seal, file.as_bytes())?;
        }

        // Step 2: Derive new KEK with existing KDF params
        // (could optionally re-calibrate, but keep it simple for now)
        let new_kek = kdf::derive_kek(new_password, &self.kdf_params)?;
        let new_session_key = hkdf_derive::derive_session_key(&new_kek)?;

        // Step 3: Get current root key from unlocked state
        let root_key = match &self.state {
            VaultState::Unlocked(u) => u.root_key.clone(),
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // Step 4: Load device private key for HPKE re-wrap
        let privkeys = load_device_privkeys(&self.path, self.device_id, Some(&old_devkey_seal))?;
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);

        // Step 5: HPKE re-wrap Root Key with new session key
        let (eph_pub, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(root_key.as_bytes(), &x25519_public)?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_json = serde_json::to_string_pretty(&keywrap_data).unwrap();
        super::write_vault_file(&keywrap_path, keywrap_json.as_bytes())?;

        // Step 6: Re-encrypt KEK canary with new session key
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_bytes = super::canary::create_kek_canary(&new_session_key, self.vault_id)?;
            let canary_path = self.path.join("meta/kek-canary.enc");
            super::write_vault_file(&canary_path, &canary_bytes)?;
        }

        // Step 7: Update in-memory session key and rotate the devkey seal
        // (C1): the KEK changed, so the seal subkey changed with it. The
        // upfront pre-check validated the old seal opens the file, so this
        // write cannot strand the vault.
        let new_devkey_seal = hkdf_derive::derive_devkey_seal_key(&new_kek)?;
        crate::vault::device_privkey::rotate_seal_key(
            &devkey_path,
            &old_devkey_seal,
            &new_devkey_seal,
            Some(self.device_id),
        )?;
        let _ = crate::vault::device_privkey::write_device_id(&self.path, self.device_id);
        if let VaultState::Unlocked(ref mut u) = self.state {
            u.session_key = new_session_key;
            u.devkey_seal = new_devkey_seal;
        }

        // Step 8: Disable old biometric secret (it stores the old password)
        // Caller should re-enable biometric with the new password after this.
        // Scoped to this vault's vault_id so other vaults' Quick Unlock is
        // untouched. Log on failure: stale secret will cause canary mismatch
        // on next biometric unlock, which is self-correcting (user falls
        // back to manual password entry).
        if let Err(e) = crate::biometric::disable(&self.vault_id.to_string()) {
            eprintln!("warning: failed to disable biometric after password change: {e}");
        }

        Ok(())
    }

    /// Migrate plaintext metadata files to encrypted format.
    /// Called after successful unlock. Best-effort: logs errors but does not fail unlock.
    fn migrate_plaintext_metadata(&self) {
        // Migrate folders.json -> folders.enc
        let folders_json = self.path.join("meta/folders.json");
        let folders_enc = self.path.join("meta/folders.enc");
        if folders_json.exists() && !folders_enc.exists() {
            if let Ok(data) = std::fs::read_to_string(&folders_json) {
                if let Ok(folders) =
                    serde_json::from_str::<Vec<crate::vault::manifest::Folder>>(&data)
                {
                    if self.save_folders(&folders).is_ok() {
                        let _ = std::fs::remove_file(&folders_json);
                    }
                }
            }
        }

        // Migrate tag_index.json -> tags.enc
        let tags_json = self.path.join("meta/tag_index.json");
        let tags_enc = self.path.join("meta/tags.enc");
        if tags_json.exists() && !tags_enc.exists() {
            if let Ok(data) = std::fs::read_to_string(&tags_json) {
                if let Ok(index) = serde_json::from_str::<crate::vault::manifest::TagIndex>(&data) {
                    if self.save_tags_enc(&index).is_ok() {
                        let _ = std::fs::remove_file(&tags_json);
                    }
                }
            }
        }

        // Migrate settings.json identity fields -> profile.enc
        let profile_enc = self.path.join("meta/profile.enc");
        if !profile_enc.exists() {
            if let Ok(settings) = self.get_settings() {
                let has_identity = settings.display_name.is_some()
                    || settings.subtitle.is_some()
                    || settings.avatar_ext.is_some();
                if has_identity {
                    let profile = crate::vault::manifest::UserProfile {
                        display_name: settings.display_name,
                        subtitle: settings.subtitle,
                        avatar_ext: settings.avatar_ext,
                    };
                    let _ = self.save_profile_and_strip_settings(&profile);
                }
            }
        }

        // Migrate device_activity.json -> activity.enc
        let activity_enc = self.path.join("meta/activity.enc");
        if !activity_enc.exists() {
            let plaintext = crate::device_manager::DeviceActivityIndex::read(&self.path);
            if !plaintext.devices.is_empty() {
                let _ = self.save_activity_enc(&plaintext);
            }
        }
    }

    /// Lock the vault: zeroize all key material.
    /// File timestamp normalization runs in a background thread to avoid
    /// blocking the lock operation on large vaults.
    pub fn lock(&mut self) {
        self.state = VaultState::Locked;
        let path_clone = self.path.clone();
        let creation_ts = self
            .registry
            .devices
            .values()
            .map(|d| d.enrolled_at)
            .min()
            .unwrap_or(0);
        std::thread::spawn(move || {
            Self::normalize_timestamps_bg(&path_clone, creation_ts);
        });
    }

    /// Background timestamp normalization (static, no &self).
    fn normalize_timestamps_bg(vault_path: &std::path::Path, creation_ts: u64) {
        use filetime::{FileTime, set_file_mtime};
        let target = FileTime::from_unix_time(creation_ts as i64, 0);

        fn normalize_dir(dir: &std::path::Path, target: FileTime) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = set_file_mtime(&path, target);
                    } else if path.is_dir() {
                        normalize_dir(&path, target);
                    }
                }
            }
        }

        let dirs = ["ciphers", "trash", "meta"];
        for dir_name in &dirs {
            normalize_dir(&vault_path.join(dir_name), target);
        }
        if let Ok(entries) = std::fs::read_dir(vault_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "enc") {
                    let _ = set_file_mtime(&path, target);
                }
            }
        }
    }

    /// Check if vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked(_))
    }

    /// Device-privkey seal subkey (C1). `Some` only while unlocked: the
    /// subkey lives in `UnlockedState` and is dropped on lock, exactly like
    /// the session key. Consumers: daemon sync signing (autosync), direct
    /// CLI sync after an in-process unlock.
    pub fn devkey_seal(&self) -> Option<[u8; 32]> {
        match &self.state {
            VaultState::Unlocked(u) => Some(u.devkey_seal),
            VaultState::Locked => None,
        }
    }

    /// Helper: get vault path as &Path for observer hooks.
    fn vault_path_as_ref(&self) -> Option<&Path> {
        Some(&self.path)
    }

    /// M6 fix: sync VaultHandle.registry with device_manager.registry.
    /// Call after loading or mutating either registry.
    fn sync_registry_to_device_manager(&mut self) {
        self.device_manager.registry = self.registry.clone();
    }

    /// Sync VaultHandle.registry with device_manager.registry.
    /// Call after operations that mutate device_manager's registry.
    fn sync_registry_from_device_manager(&mut self) {
        self.registry = self.device_manager.registry.clone();
    }

    /// Get a reference to the unlocked state (panics if locked).
    pub fn unlocked(&self) -> &UnlockedState {
        match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => panic!("vault is locked"),
        }
    }

    /// Get a mutable reference to the unlocked state (panics if locked).
    pub fn unlocked_mut(&mut self) -> &mut UnlockedState {
        match &mut self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => panic!("vault is locked"),
        }
    }

    /// M1 fix: Derive the avatar encryption key from the unlocked SGK.
    /// Domain-separated from item keys; epoch-bound so avatar is re-wrapped
    /// on root key rotation.
    pub fn derive_avatar_key(&self) -> [u8; 32] {
        let unlocked = self.unlocked();
        unlocked
            .space_group_key
            .derive_avatar_key(unlocked.space_group_key.epoch())
    }

    /// Encrypt metadata JSON and write to disk atomically.
    /// Shared by save_folders, save_tags_enc, save_profile.
    /// Caller must ensure vault is unlocked and derive the key.
    fn encrypt_and_write_meta(
        &self,
        key: &[u8; 32],
        json: &[u8],
        enc_path: &std::path::Path,
        epoch: u64,
    ) -> Result<(), BaluardError> {
        let nonce = crate::crypto::aead::build_random_nonce();
        // Header stores only a u64 `nonce_counter`; derive it from the first
        // 8 bytes of the 96-bit random nonce so the field stays populated
        // (metadata-only — decrypt reads the full 12-byte nonce from the
        // envelope, not this field). A-1 fix: previously build_nonce(counter,
        // Uuid::nil()) zeroed the shard tail, leaving only 64 random bits.
        let nonce_counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());
        let aad = crate::crypto::aead::build_aad(
            self.vault_id,
            crate::types::ObjectType::Meta,
            Uuid::nil(),
            None,
            crate::ALG_AES_256_GCM,
            epoch,
            1,
        );
        let header = crate::types::EnvelopeHeader {
            version: crate::BALUARD_VERSION,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: epoch,
            nonce_counter,
            update_seq: 1,
            tier: None,
        };
        let envelope = crate::crypto::aead::encrypt(key, json, &aad, &nonce, header)?;
        let envelope_bytes = crate::vault::envelope::serialize(&envelope)?;
        super::write_vault_file(enc_path, &envelope_bytes)?;
        Ok(())
    }

    /// Get vault settings (reads from disk).
    pub fn get_settings(&self) -> Result<crate::vault::manifest::VaultSettings, BaluardError> {
        // Split storage (2026-06-26): display prefs in plaintext settings-pub.json,
        // the rest encrypted under the root key in settings.enc. Legacy
        // settings.json is migrated on first unlock.
        //
        // Public (pre-unlock) fields: theme + lang.
        // Encrypted (post-unlock) fields: vault_timeout, default_uri_match,
        // fetch_favicons, slug, enrollment_policy. slug confirmed to have no
        // pre-unlock consumer (authoritative source is the .baluard marker +
        // registry); the rest are post-unlock only.
        let pub_path = self.path.join("meta/settings-pub.json");
        let enc_path = self.path.join("meta/settings.enc");
        let legacy_path = self.path.join("meta/settings.json");

        // 1. Plaintext public prefs (theme + lang). Fall back to legacy
        //    meta/locale for lang during migration.
        let (theme, lang) = if pub_path.exists() {
            let data = std::fs::read_to_string(&pub_path)?;
            let v: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("settings-pub parse: {e}")))?;
            (
                v.get("theme")
                    .and_then(|t| serde_json::from_value(t.clone()).ok()),
                v.get("lang").and_then(|l| l.as_str()).map(String::from),
            )
        } else {
            // Legacy: no settings-pub.json yet. lang lived in meta/locale or
            // settings.json; theme only in settings.json. The migration below
            // (or the legacy fallback path) fills these in.
            let lang = self.load_locale().or_else(|| {
                std::fs::read_to_string(&legacy_path).ok().and_then(|d| {
                    serde_json::from_str::<serde_json::Value>(&d)
                        .ok()
                        .and_then(|v| v["lang"].as_str().map(String::from))
                })
            });
            let theme = std::fs::read_to_string(&legacy_path).ok().and_then(|d| {
                serde_json::from_str::<serde_json::Value>(&d)
                    .ok()
                    .and_then(|v| serde_json::from_value(v["theme"].clone()).ok())
            });
            (theme, lang)
        };

        // 2. Encrypted settings. Requires unlocked vault.
        let encrypted = match &self.state {
            VaultState::Unlocked(unlocked) => {
                if enc_path.exists() {
                    let key = hkdf_derive::derive_settings_key(unlocked.root_key.as_bytes())
                        .map_err(|e| {
                            VaultError::Metadata(format!("settings key derivation: {e}"))
                        })?;
                    let data = std::fs::read(&enc_path)?;
                    let envelope = crate::vault::envelope::deserialize(&data)?;
                    let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
                    Some(
                        serde_json::from_slice::<crate::vault::manifest::EncryptedSettings>(
                            &decrypted,
                        )
                        .map_err(|e| VaultError::Metadata(format!("settings.enc parse: {e}")))?,
                    )
                } else {
                    None
                }
            }
            VaultState::Locked => None,
        };

        // 3. Legacy migration: if settings.enc is absent but settings.json
        //    exists, read the encrypted fields from it. The next save_settings
        //    (or an explicit migrate) writes settings.enc and settings-pub.json,
        //    deprecating settings.json.
        let (enc_fields, migrated_lang) = match encrypted {
            Some(e) => (Some(e), None),
            None => {
                if legacy_path.exists() {
                    let data = std::fs::read_to_string(&legacy_path)?;
                    let v: serde_json::Value = serde_json::from_str(&data)
                        .map_err(|e| VaultError::Metadata(format!("settings parse: {e}")))?;
                    let enc = crate::vault::manifest::EncryptedSettings {
                        vault_timeout: serde_json::from_value(v["vault_timeout"].clone())
                            .unwrap_or_else(|_| {
                                crate::vault::manifest::VaultTimeout::default_for_new()
                            }),
                        default_uri_match: serde_json::from_value(v["default_uri_match"].clone())
                            .ok(),
                        fetch_favicons: v["fetch_favicons"].as_bool(),
                        slug: v["slug"].as_str().map(String::from),
                        device_names: None,
                        enrollment_policy: serde_json::from_value(v["enrollment_policy"].clone())
                            .unwrap_or(crate::vault::manifest::EnrollmentPolicy::Strict),
                        // These post-date the legacy settings.json split: a
                        // legacy file never carries them.
                        custom_equivalent_domains: None,
                        suggest_app_logins: None,
                        trusted_app_packages: None,
                        rejected_app_packages: None,
                    };
                    let legacy_lang = v["lang"].as_str().map(String::from);
                    (Some(enc), legacy_lang)
                } else {
                    (None, None)
                }
            }
        };

        // 4. Assemble. Effective lang prefers the explicit pub value, then the
        //    legacy-file value discovered during migration.
        let lang = lang.or(migrated_lang);
        Ok(crate::vault::manifest::VaultSettings {
            vault_timeout: enc_fields
                .as_ref()
                .map(|e| e.vault_timeout)
                .unwrap_or_else(crate::vault::manifest::VaultTimeout::default_for_new),
            theme,
            lang,
            default_uri_match: enc_fields.as_ref().and_then(|e| e.default_uri_match),
            fetch_favicons: enc_fields.as_ref().and_then(|e| e.fetch_favicons),
            slug: enc_fields.as_ref().and_then(|e| e.slug.clone()),
            // Identity fields live in profile.enc now; kept for struct compat.
            display_name: None,
            subtitle: None,
            avatar_ext: None,
            custom_equivalent_domains: enc_fields
                .as_ref()
                .and_then(|e| e.custom_equivalent_domains.clone()),
            suggest_app_logins: enc_fields.as_ref().and_then(|e| e.suggest_app_logins),
            trusted_app_packages: enc_fields
                .as_ref()
                .and_then(|e| e.trusted_app_packages.clone()),
            rejected_app_packages: enc_fields
                .as_ref()
                .and_then(|e| e.rejected_app_packages.clone()),
            enrollment_policy: enc_fields
                .as_ref()
                .map(|e| e.enrollment_policy)
                .unwrap_or(crate::vault::manifest::EnrollmentPolicy::Strict),
        })
    }

    /// Save vault settings using the split layout: theme+lang to plaintext
    /// settings-pub.json, everything else to encrypted settings.enc. Performs
    /// a one-time migration from legacy settings.json if it still exists.
    pub fn save_settings(
        &self,
        settings: &crate::vault::manifest::VaultSettings,
    ) -> Result<(), BaluardError> {
        let pub_path = self.path.join("meta/settings-pub.json");
        let enc_path = self.path.join("meta/settings.enc");

        // Public prefs (plaintext, pre-unlock).
        let pub_json = serde_json::json!({
            "theme": settings.theme,
            "lang": settings.lang,
        });
        let pub_str = serde_json::to_string_pretty(&pub_json)
            .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
        super::write_vault_file(&pub_path, pub_str.as_bytes())?;

        // Encrypted settings (post-unlock only).
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => {
                // Locked save: only the public prefs can be persisted. This is
                // rare (settings.set is token-gated), but be safe.
                return Ok(());
            }
        };
        let enc_settings = crate::vault::manifest::EncryptedSettings {
            vault_timeout: settings.vault_timeout,
            default_uri_match: settings.default_uri_match,
            fetch_favicons: settings.fetch_favicons,
            slug: settings.slug.clone(),
            // C5: preserve the encrypted device-name map across rewrites —
            // VaultSettings does not carry it, so carry the stored value.
            device_names: {
                let names = self.device_display_names();
                if names.is_empty() { None } else { Some(names) }
            },
            enrollment_policy: settings.enrollment_policy,
            custom_equivalent_domains: settings.custom_equivalent_domains.clone(),
            suggest_app_logins: settings.suggest_app_logins,
            trusted_app_packages: settings.trusted_app_packages.clone(),
            rejected_app_packages: settings.rejected_app_packages.clone(),
        };
        let key = hkdf_derive::derive_settings_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("settings key derivation: {e}")))?;
        let json = serde_json::to_vec(&enc_settings)
            .map_err(|e| VaultError::Metadata(format!("settings.enc serialization: {e}")))?;
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;

        // One-time migration: drop the legacy plaintext settings.json now that
        // the split files are written. Identity fields already live in
        // profile.enc; nothing else remains here.
        let legacy = self.path.join("meta/settings.json");
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }
        Ok(())
    }

    /// Device display names from the encrypted settings map (audit C5).
    /// Empty map when the vault is locked or the file is absent. The
    /// registry file may briefly hold names pre-migration; this accessor is
    /// the post-unlock source of truth.
    pub fn device_display_names(&self) -> std::collections::HashMap<String, String> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return std::collections::HashMap::new(),
        };
        let enc_path = self.path.join("meta/settings.enc");
        if !enc_path.exists() {
            return std::collections::HashMap::new();
        }
        let Ok(key) = hkdf_derive::derive_settings_key(unlocked.root_key.as_bytes()) else {
            return std::collections::HashMap::new();
        };
        let Ok(data) = std::fs::read(&enc_path) else {
            return std::collections::HashMap::new();
        };
        let Ok(envelope) = crate::vault::envelope::deserialize(&data) else {
            return std::collections::HashMap::new();
        };
        let Ok(decrypted) = crate::crypto::aead::decrypt(&key, &envelope) else {
            return std::collections::HashMap::new();
        };
        serde_json::from_slice::<crate::vault::manifest::EncryptedSettings>(&decrypted)
            .ok()
            .and_then(|e| e.device_names)
            .unwrap_or_default()
    }

    /// Fold plaintext device display names from meta/devices.json into the
    /// encrypted settings map and strip them from the registry file
    /// (audit C5: devices.json is git-tracked; names are PII). Idempotent —
    /// re-runs re-fold names reintroduced by a legacy remote's registry
    /// during sync and then no-op. Best-effort callers may log and continue.
    pub fn migrate_device_names_into_settings(&self) -> Result<(), BaluardError> {
        // Requires the root key (settings.enc encryption). Pre-unlock is a
        // no-op; the next unlock retries.
        if !self.is_unlocked() {
            return Ok(());
        }
        let reg_path = self.path.join("meta/devices.json");
        let Some(reg_json) = std::fs::read_to_string(&reg_path).ok() else {
            return Ok(());
        };
        let Ok(mut reg) = serde_json::from_str::<crate::devices::DeviceRegistry>(&reg_json) else {
            // Corrupt registry: leave untouched; sync surfaces it elsewhere.
            return Ok(());
        };

        // Fold every non-empty name into the encrypted map and blank it.
        let mut names = self.device_display_names();
        let mut folded = false;
        for (id, entry) in reg.devices.iter_mut() {
            if !entry.name.is_empty() {
                names.insert(id.to_string(), std::mem::take(&mut entry.name));
                folded = true;
            }
        }
        if !folded {
            return Ok(()); // already clean: the common path after first run
        }

        // Persist the map first, then the stripped registry. A crash between
        // the two only causes a redundant re-fold on the next unlock.
        let settings = self.get_settings()?;
        let enc = crate::vault::manifest::EncryptedSettings {
            vault_timeout: settings.vault_timeout,
            default_uri_match: settings.default_uri_match,
            fetch_favicons: settings.fetch_favicons,
            slug: settings.slug.clone(),
            device_names: Some(names),
            enrollment_policy: settings.enrollment_policy,
            // The fold rewrite must carry every encrypted field or the
            // migration would silently wipe them (settings.enc is the
            // only store for these).
            custom_equivalent_domains: settings.custom_equivalent_domains.clone(),
            suggest_app_logins: settings.suggest_app_logins,
            trusted_app_packages: settings.trusted_app_packages.clone(),
            rejected_app_packages: settings.rejected_app_packages.clone(),
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Ok(()),
        };
        let key = hkdf_derive::derive_settings_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("settings key derivation: {e}")))?;
        let json = serde_json::to_vec(&enc)
            .map_err(|e| VaultError::Metadata(format!("settings.enc serialization: {e}")))?;
        let enc_path = self.path.join("meta/settings.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;

        let stripped = serde_json::to_string_pretty(&reg)
            .map_err(|e| VaultError::Metadata(format!("devices serialization: {e}")))?;
        super::write_vault_file(&reg_path, stripped.as_bytes())?;
        Ok(())
    }

    /// Load encrypted user profile from meta/profile.enc.
    /// Returns default (empty) profile if file doesn't exist yet.
    /// Falls back to reading identity fields from plaintext settings.json (legacy).
    pub fn load_profile(&self) -> Result<crate::vault::manifest::UserProfile, BaluardError> {
        let enc_path = self.path.join("meta/profile.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_profile_key(unlocked.root_key.as_bytes())
                .map_err(|e| VaultError::Metadata(format!("profile key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let profile: crate::vault::manifest::UserProfile =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("profile decrypt parse: {e}")))?;
            // Cleanup: strip stale identity fields from plaintext settings.json
            // (crash window: profile.enc written but settings.json not yet stripped)
            if let Ok(mut settings) = self.get_settings() {
                if settings.display_name.is_some()
                    || settings.subtitle.is_some()
                    || settings.avatar_ext.is_some()
                {
                    settings.display_name = None;
                    settings.subtitle = None;
                    settings.avatar_ext = None;
                    let _ = self.save_settings(&settings);
                }
            }
            return Ok(profile);
        }

        // Legacy fallback: extract identity fields from plaintext settings.json
        if let Ok(settings) = self.get_settings() {
            return Ok(crate::vault::manifest::UserProfile {
                display_name: settings.display_name,
                subtitle: settings.subtitle,
                avatar_ext: settings.avatar_ext,
            });
        }

        Ok(crate::vault::manifest::UserProfile {
            display_name: None,
            subtitle: None,
            avatar_ext: None,
        })
    }

    /// Save encrypted user profile to meta/profile.enc (atomic write).
    /// Does NOT modify settings.json. Caller is responsible for stripping
    /// identity fields from plaintext settings if needed.
    pub fn save_profile(
        &self,
        profile: &crate::vault::manifest::UserProfile,
    ) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_profile_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("profile key derivation: {e}")))?;
        let json = serde_json::to_vec(profile)
            .map_err(|e| VaultError::Metadata(format!("profile serialization: {e}")))?;
        let enc_path = self.path.join("meta/profile.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        Ok(())
    }

    /// Save profile AND strip identity fields from plaintext settings.json.
    /// Used by migration and crash-window cleanup where caller owns the settings state.
    pub fn save_profile_and_strip_settings(
        &self,
        profile: &crate::vault::manifest::UserProfile,
    ) -> Result<(), BaluardError> {
        self.save_profile(profile)?;
        let mut settings = self.get_settings().unwrap_or_default();
        settings.display_name = None;
        settings.subtitle = None;
        settings.avatar_ext = None;
        self.save_settings(&settings)?;
        Ok(())
    }

    // ── Locale ──

    /// Save plaintext locale to meta/locale.
    /// This file is readable before vault unlock (login screen needs language).
    /// Save the language pref to the plaintext settings-pub.json (the pre-unlock
    /// display-prefs file). Merges with any existing theme value so we don't
    /// clobber it. Replaces the old meta/locale sidecar (2026-06-26).
    pub fn save_locale(&self, lang: &str) -> Result<(), BaluardError> {
        let path = self.path.join("meta/settings-pub.json");
        // Read existing pub prefs to preserve theme.
        let existing = std::fs::read_to_string(&path).ok().and_then(|d| {
            serde_json::from_str::<serde_json::Value>(&d)
                .ok()
                .and_then(|v| {
                    serde_json::from_value::<crate::types::ThemeMode>(v["theme"].clone()).ok()
                })
        });
        let json = serde_json::json!({
            "theme": existing,
            "lang": lang,
        });
        let body = serde_json::to_string_pretty(&json)
            .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
        super::write_vault_file(&path, body.as_bytes())?;
        Ok(())
    }

    /// Load the language pref. Reads from settings-pub.json; falls back to the
    /// legacy meta/locale sidecar during migration.
    pub fn load_locale(&self) -> Option<String> {
        let pub_path = self.path.join("meta/settings-pub.json");
        if let Ok(data) = std::fs::read_to_string(&pub_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(s) = v.get("lang").and_then(|l| l.as_str()) {
                    return Some(s.trim().to_string());
                }
            }
        }
        // Legacy fallback.
        let legacy = self.path.join("meta/locale");
        std::fs::read_to_string(legacy)
            .ok()
            .map(|s| s.trim().to_string())
    }

    // ── Device Activity ──

    /// Load encrypted device activity index from meta/activity.enc.
    /// Falls back to plaintext meta/device_activity.json (legacy).
    pub fn load_activity_enc(
        &self,
    ) -> Result<crate::device_manager::DeviceActivityIndex, BaluardError> {
        // Sync engine writes plaintext device_activity.json after every commit.
        // If it exists, re-encrypt it (fresh data) before reading .enc.
        let json_path = self.path.join("meta/device_activity.json");
        if json_path.exists() {
            let fresh = crate::device_manager::DeviceActivityIndex::read(&self.path);
            if !fresh.devices.is_empty() {
                let _ = self.save_activity_enc(&fresh);
            }
            return Ok(fresh);
        }

        let enc_path = self.path.join("meta/activity.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_activity_key(unlocked.root_key.as_bytes())
                .map_err(|e| VaultError::Metadata(format!("activity key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let index: crate::device_manager::DeviceActivityIndex =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("activity decrypt parse: {e}")))?;
            return Ok(index);
        }
        // No data at all
        Ok(crate::device_manager::DeviceActivityIndex::new())
    }

    /// Save encrypted device activity index to meta/activity.enc (atomic write).
    /// Does NOT modify plaintext device_activity.json (sync engine may still write it).
    fn save_activity_enc(
        &self,
        index: &crate::device_manager::DeviceActivityIndex,
    ) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_activity_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("activity key derivation: {e}")))?;
        let json = serde_json::to_vec(index)
            .map_err(|e| VaultError::Metadata(format!("activity serialization: {e}")))?;
        let enc_path = self.path.join("meta/activity.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        // Remove legacy plaintext
        let json_path = self.path.join("meta/device_activity.json");
        if json_path.exists() {
            let _ = std::fs::remove_file(&json_path);
        }
        Ok(())
    }

    // ── Generator History ──

    /// Maximum stored entries (FIFO cap).
    const MAX_GENERATOR_HISTORY: usize = 100;
    /// Maximum entries returned to UI.
    const DISPLAY_GENERATOR_HISTORY: usize = 67;

    /// Load encrypted generator history from meta/generator-history.enc.
    /// Returns empty vec if file doesn't exist yet.
    pub fn load_generator_history(
        &self,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let enc_path = self.path.join("meta/generator-history.enc");
        if !enc_path.exists() {
            return Ok(vec![]);
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_generator_history_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("generator history key derivation: {e}")))?;
        let data = std::fs::read(&enc_path)?;
        let envelope = crate::vault::envelope::deserialize(&data)?;
        let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
        let entries: Vec<crate::types::GeneratorHistoryEntry> = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Metadata(format!("generator history decrypt parse: {e}")))?;
        Ok(entries)
    }

    /// Append a generator history entry, enforce FIFO cap, persist.
    /// Returns the updated list (capped to DISPLAY_GENERATOR_HISTORY).
    pub fn add_generator_history_entry(
        &self,
        entry: crate::types::GeneratorHistoryEntry,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let mut history = self.load_generator_history()?;
        history.push(entry);
        // FIFO cap: trim oldest
        if history.len() > Self::MAX_GENERATOR_HISTORY {
            history.drain(0..history.len() - Self::MAX_GENERATOR_HISTORY);
        }
        self.save_generator_history(&history)?;
        // Return display-capped slice (latest first)
        let display = Self::display_slice(&history);
        Ok(display)
    }

    /// Clear all generator history (deletes the encrypted file).
    pub fn clear_generator_history(&self) -> Result<(), BaluardError> {
        let enc_path = self.path.join("meta/generator-history.enc");
        if enc_path.exists() {
            std::fs::remove_file(&enc_path)?;
        }
        Ok(())
    }

    /// Get latest DISPLAY_GENERATOR_HISTORY entries (newest first).
    pub fn list_generator_history_display(
        &self,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let history = self.load_generator_history()?;
        Ok(Self::display_slice(&history))
    }

    /// Merge histories from two sync sides by timestamp, dedupe, cap at MAX.
    /// Returns merged list sorted newest-first.
    ///
    /// **Not yet wired into the sync engine.** Currently, `generator-history.enc`
    /// is treated as an opaque AEAD blob by git merge (last-writer-wins on
    /// binary conflict). This function is kept as a utility for when the sync
    /// engine gains a decrypt-merge-reencrypt path for vault metadata files.
    pub fn merge_generator_history(
        local: &[crate::types::GeneratorHistoryEntry],
        remote: &[crate::types::GeneratorHistoryEntry],
    ) -> Vec<crate::types::GeneratorHistoryEntry> {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let mut merged: Vec<crate::types::GeneratorHistoryEntry> = Vec::new();
        // Interleave newest-first
        let mut all: Vec<&crate::types::GeneratorHistoryEntry> =
            local.iter().chain(remote.iter()).collect();
        all.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        for entry in all {
            let key = (entry.value.clone(), entry.created_at);
            if seen.insert(key) {
                merged.push(entry.clone());
            }
            if merged.len() >= Self::MAX_GENERATOR_HISTORY {
                break;
            }
        }
        merged
    }

    /// Save generator history to meta/generator-history.enc (atomic write).
    fn save_generator_history(
        &self,
        entries: &[crate::types::GeneratorHistoryEntry],
    ) -> Result<(), BaluardError> {
        if entries.is_empty() {
            return self.clear_generator_history();
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_generator_history_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("generator history key derivation: {e}")))?;
        let json = serde_json::to_vec(entries)
            .map_err(|e| VaultError::Metadata(format!("generator history serialization: {e}")))?;
        let enc_path = self.path.join("meta/generator-history.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        Ok(())
    }

    /// Return the display-capped slice of history (newest first).
    fn display_slice(
        history: &[crate::types::GeneratorHistoryEntry],
    ) -> Vec<crate::types::GeneratorHistoryEntry> {
        let start = history
            .len()
            .saturating_sub(Self::DISPLAY_GENERATOR_HISTORY);
        let mut slice: Vec<_> = history[start..].to_vec();
        slice.reverse(); // newest first
        slice
    }

    // ── Folder CRUD ──

    /// List all folders (decrypts from meta/folders.enc, falls back to plaintext folders.json).
    pub fn list_folders(&self) -> Result<Vec<crate::vault::manifest::Folder>, BaluardError> {
        let enc_path = self.path.join("meta/folders.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_folders_key(unlocked.root_key.as_bytes())
                .map_err(|e| VaultError::Metadata(format!("folders key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let folders: Vec<crate::vault::manifest::Folder> =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("folders decrypt parse: {e}")))?;
            // Cleanup stale plaintext if encrypted version decrypts cleanly
            let _ = std::fs::remove_file(self.path.join("meta/folders.json"));
            return Ok(folders);
        }
        // Legacy fallback: plaintext folders.json
        let json_path = self.path.join("meta/folders.json");
        if json_path.exists() {
            let data = std::fs::read_to_string(&json_path)?;
            let folders: Vec<crate::vault::manifest::Folder> = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("folders parse: {e}")))?;
            return Ok(folders);
        }
        Ok(Vec::new())
    }

    /// Save folders to disk (encrypted, atomic write).
    fn save_folders(&self, folders: &[crate::vault::manifest::Folder]) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_folders_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("folders key derivation: {e}")))?;
        let json = serde_json::to_vec(folders)
            .map_err(|e| VaultError::Metadata(format!("folders serialization: {e}")))?;
        let enc_path = self.path.join("meta/folders.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        // Remove legacy plaintext file if it still exists
        let json_path = self.path.join("meta/folders.json");
        if json_path.exists() {
            let _ = std::fs::remove_file(&json_path);
        }
        Ok(())
    }

    /// Create a new folder.
    pub fn create_folder(&mut self, name: &str) -> Result<Uuid, BaluardError> {
        self.create_folder_with_parent(name, None)
    }

    /// Maximum folder nesting depth.
    const MAX_FOLDER_DEPTH: usize = 16;

    /// Create a new folder with optional parent.
    pub fn create_folder_with_parent(
        &mut self,
        name: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, BaluardError> {
        if name.trim().is_empty() {
            return Err(
                crate::error::VaultError::Metadata("folder name cannot be empty".into()).into(),
            );
        }
        let trimmed = name.trim();
        let mut folders = self.list_folders()?;
        // Check for duplicate name within the same parent
        if folders
            .iter()
            .any(|f| f.name == trimmed && f.parent_id == parent_id)
        {
            return Err(crate::error::VaultError::Metadata(format!(
                "folder '{trimmed}' already exists"
            ))
            .into());
        }
        // Validate parent exists and check depth
        if let Some(pid) = parent_id {
            if !folders.iter().any(|f| f.id == pid) {
                return Err(
                    crate::error::VaultError::Metadata("parent folder not found".into()).into(),
                );
            }
            // Walk parent chain to check depth
            let mut depth = 1;
            let mut current = pid;
            while let Some(parent) = folders.iter().find(|f| f.id == current) {
                match parent.parent_id {
                    Some(gp) => {
                        depth += 1;
                        current = gp;
                    }
                    None => break,
                }
                if depth >= Self::MAX_FOLDER_DEPTH {
                    return Err(crate::error::VaultError::Metadata(format!(
                        "folder nesting too deep (max {})",
                        Self::MAX_FOLDER_DEPTH
                    ))
                    .into());
                }
            }
        }
        let id = Uuid::new_v4();
        folders.push(crate::vault::manifest::Folder {
            id,
            name: trimmed.to_string(),
            parent_id,
            icon: None,
        });
        self.save_folders(&folders)?;
        Ok(id)
    }

    /// Rename a folder by ID.
    pub fn rename_folder(&mut self, folder_id: Uuid, new_name: &str) -> Result<(), BaluardError> {
        if new_name.trim().is_empty() {
            return Err(
                crate::error::VaultError::Metadata("folder name cannot be empty".into()).into(),
            );
        }
        let mut folders = self.list_folders()?;
        let folder = folders
            .iter_mut()
            .find(|f| f.id == folder_id)
            .ok_or_else(|| {
                BaluardError::from(crate::error::VaultError::NotFound(format!(
                    "folder {folder_id}"
                )))
            })?;
        folder.name = new_name.trim().to_string();
        self.save_folders(&folders)?;
        Ok(())
    }

    /// Delete a folder by ID. Cascades to child folders.
    /// All ciphers with this folder_id (or any child's) become unassigned.
    pub fn delete_folder(&mut self, folder_id: Uuid) -> Result<(), BaluardError> {
        // Collect this folder + all descendants
        let all_folders = self.list_folders()?;
        let ids_to_delete = collect_descendant_ids(folder_id, &all_folders);

        if !all_folders.iter().any(|f| f.id == folder_id) {
            return Err(BaluardError::from(crate::error::VaultError::NotFound(
                format!("folder {folder_id}"),
            )));
        }

        // Remove all collected folders (persist only after cipher unassignment succeeds)
        let mut folders = all_folders;
        folders.retain(|f| !ids_to_delete.contains(&f.id));

        // Unassign all ciphers in any of the deleted folders
        let cipher_ids = self.list_cipher_ids()?;
        for cipher_id in cipher_ids {
            let file_path = self.path.join(format!("ciphers/{cipher_id}.enc"));
            if !file_path.exists() {
                continue;
            }
            let existing_bytes = std::fs::read(&file_path)?;
            let existing_file = cipher::CipherFile {
                id: cipher_id,
                envelope_bytes: existing_bytes,
            };
            let _existing_envelope =
                crate::vault::envelope::deserialize(&existing_file.envelope_bytes)?;
            let existing_cipher = {
                let unlocked = match &self.state {
                    VaultState::Unlocked(u) => u,
                    VaultState::Locked => return Err(VaultError::Locked.into()),
                };
                self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file)?
            };

            if existing_cipher
                .folder_id
                .is_some_and(|fid| ids_to_delete.contains(&fid))
            {
                // Reuse update_cipher to maintain all invariants (history, timestamps, etc.)
                let input = CipherInput {
                    name: existing_cipher.name.clone(),
                    folder_id: None, // unassign
                    kind: existing_cipher.kind.clone(),
                    favorite: existing_cipher.favorite,
                    reprompt: existing_cipher.reprompt,
                    notes: existing_cipher.notes.clone(),
                    custom_fields: existing_cipher.custom_fields.clone(),
                    created_at: Some(existing_cipher.created_at),
                    password_history: existing_cipher.password_history.clone(),
                    attachments: existing_cipher.attachments.clone(),
                    archived: existing_cipher.archived,
                    tags: existing_cipher.tags.clone(),
                };
                self.update_cipher(cipher_id, &input)?;
            }
        }

        // NOW remove folder from index (after all ciphers unassigned successfully)
        self.save_folders(&folders)?;

        Ok(())
    }

    /// List cipher IDs from filenames in ciphers/ directory.
    pub fn list_cipher_ids(&self) -> Result<Vec<Uuid>, BaluardError> {
        let ciphers_dir = self.path.join("ciphers");
        if !ciphers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&ciphers_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_suffix(".enc") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// List cipher metadata (requires unlocked vault for full CipherMeta).
    /// Decrypts from index.enc if available, otherwise auto-heals by scanning directory.
    /// List cipher metadata (non-archived only). Requires unlocked vault.
    /// Decrypts from index.enc if available, otherwise auto-heals.
    pub fn list_cipher_meta(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        Ok(self
            .list_cipher_meta_full()?
            .into_iter()
            .filter(|m| !m.archived)
            .collect())
    }

    /// List ALL cipher metadata (including archived). Exposed for export, health, and sync.
    pub fn list_cipher_meta_full(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // Try reading from index.enc
        let index_path = self.path.join("meta/index.enc");
        if index_path.exists() {
            if let Ok(index_key) =
                crate::crypto::hkdf_derive::derive_index_key(unlocked.root_key.as_bytes())
            {
                if let Ok(envelope_bytes) = std::fs::read(&index_path) {
                    if let Ok(ciphers) =
                        index::decrypt_index(self.vault_id, &envelope_bytes, &index_key)
                    {
                        return Ok(ciphers);
                    }
                }
            }
        }

        // Auto-heal: rebuild index and save
        let ids = self.list_cipher_ids()?;
        let mut metas = Vec::with_capacity(ids.len());

        for id in ids {
            let file_path = self.path.join(format!("ciphers/{}.enc", id));
            if !file_path.exists() {
                continue;
            }
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile { id, envelope_bytes };

            let c = match self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &file) {
                Ok(c) => c,
                Err(crate::error::BaluardError::Vault(crate::error::VaultError::CrossEpoch {
                    envelope_epoch,
                    held_epoch,
                })) => {
                    // Cipher at a key epoch the held RootKey/SGK cannot reach.
                    // Previously this was silently `continue`d, which made the
                    // entry vanish from vault.list with no signal. Surface it
                    // so the user knows a re-sync / device refresh is needed
                    // (B-2 fix). Still skip rather than fail the whole list —
                    // a vault with one stray remote blob should still render.
                    eprintln!(
                        "warning: cipher {id} at epoch {envelope_epoch} cannot be decrypted with held epoch {held_epoch}; skipping from index",
                    );
                    continue;
                }
                Err(e) => {
                    // Genuine corrupt envelope / IO error: log and skip rather
                    // than abort the whole index (graceful degradation), but
                    // keep this path noisy so it does not hide silent loss.
                    eprintln!("warning: cipher {id} skipped during index build: {e}");
                    continue;
                }
            };

            let username = match &c.kind {
                crate::types::CipherKind::Login(data) => data.username.clone(),
                _ => None,
            };

            metas.push(crate::types::CipherMeta {
                id: c.id,
                name: c.name,
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
            });
        }

        // Save healed index
        if let Ok(index_key) =
            crate::crypto::hkdf_derive::derive_index_key(unlocked.root_key.as_bytes())
        {
            if let Ok(enc_bytes) =
                index::encrypt_index(self.vault_id, &metas, &index_key, unlocked.current_epoch)
            {
                let tmp_path = index_path.with_extension("enc.tmp");
                if std::fs::write(&tmp_path, enc_bytes).is_ok() {
                    let _ = std::fs::rename(tmp_path, &index_path);
                }
            }
        }

        Ok(metas)
    }

    /// Verify root key by decrypting the Root Key canary.
    /// The canary is stored at vault creation as AES-256-GCM("baluard-rk-ok")
    /// encrypted with a key derived from Root Key.
    fn verify_root_key(&self, root_key: &RootKey) -> Result<(), BaluardError> {
        let canary_path = self.path.join("meta/rk-canary.enc");
        if !canary_path.exists() {
            // No canary (legacy vault). Fall back to first-cipher check.
            return self.verify_root_key_fallback(root_key);
        }

        let canary_data = std::fs::read(&canary_path)
            .map_err(|e| VaultError::Metadata(format!("reading rk canary: {e}")))?;
        super::canary::verify_rk_canary(root_key, &canary_data)?;
        Ok(())
    }

    /// Fallback: verify root key by decrypting the first existing cipher.
    /// Only used for legacy vaults without `meta/rk-canary.enc`.
    fn verify_root_key_fallback(&self, root_key: &RootKey) -> Result<(), BaluardError> {
        let cipher_ids = self.list_cipher_ids()?;
        if cipher_ids.is_empty() {
            // Empty vault with no RK canary: cannot verify root key.
            // Refuse unlock rather than accept any key silently.
            return Err(VaultError::Corrupt(
                "vault has no ciphers and no root key canary. Re-initialize vault.".into(),
            )
            .into());
        }

        let canary_id = cipher_ids[0];
        let file_path = self.path.join(format!("ciphers/{}.enc", canary_id));
        let envelope_bytes = std::fs::read(&file_path)?;
        let file = crate::vault::cipher::CipherFile {
            id: canary_id,
            envelope_bytes,
        };

        match self.try_decrypt_cipher_with_root_key(root_key, &file) {
            Ok(_) => Ok(()),
            Err(_) => Err(VaultError::Corrupt(
                "master password incorrect (root key verification failed)".into(),
            )
            .into()),
        }
    }

    /// Try to decrypt a cipher using the Root Key (derives Item Key).
    fn try_decrypt_cipher_with_root_key(
        &self,
        root_key: &RootKey,
        file: &crate::vault::cipher::CipherFile,
    ) -> Result<Cipher, BaluardError> {
        let item_key = {
            let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
            Self::derive_item_key_from_root(root_key, file.id, envelope.header.key_epoch)
        };
        crate::vault::cipher::decrypt_cipher(self.vault_id, file.id, file, &item_key)
    }

    /// Derive an item key from the cached Space Group Key in UnlockedState.
    /// DESIGN-3: Uses the SGK already held in UnlockedState, avoiding redundant derivation.
    ///
    /// Routes through the checked `try_derive_item_key` so a cipher at a key
    /// epoch the held SGK cannot reach surfaces as a typed `CrossEpoch` error
    /// instead of (a) panicking in debug builds or (b) silently deriving the
    /// wrong key in release builds and failing the downstream AEAD check,
    /// which the index rebuild then dropped with no signal (B-2 fix).
    fn derive_item_key_from_sgk(
        sgk: &crate::keys::hierarchy::SpaceGroupKey,
        cipher_id: Uuid,
        epoch: u64,
    ) -> Result<ItemKey, BaluardError> {
        sgk.try_derive_item_key(cipher_id, epoch).ok_or_else(|| {
            VaultError::CrossEpoch {
                envelope_epoch: epoch,
                held_epoch: sgk.epoch(),
            }
            .into()
        })
    }

    /// Fallback: derive item key from RootKey by first deriving an SGK.
    /// Used only when we have a RootKey but no cached SGK (e.g., verify_root_key).
    fn derive_item_key_from_root(root_key: &RootKey, cipher_id: Uuid, epoch: u64) -> ItemKey {
        let sgk = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(root_key, epoch);
        sgk.derive_item_key(cipher_id, epoch)
    }

    /// Derive item key for a cipher (requires unlocked vault).
    pub fn derive_item_key(
        &self,
        cipher_id: Uuid,
        key_epoch: u64,
    ) -> crate::keys::hierarchy::ItemKey {
        let sgk = match &self.state {
            VaultState::Unlocked(u) => &u.space_group_key,
            VaultState::Locked => panic!("derive_item_key called on locked vault"),
        };
        // Routed through the checked derive so a genuine held-epoch mismatch
        // (encrypt/re-encrypt path with the wrong key_epoch) panics with a
        // typed message instead of silently deriving the wrong key. Callers
        // on the encrypt path always pass the held current_epoch, so a
        // mismatch here is an invariant violation, not user data.
        Self::derive_item_key_from_sgk(sgk, cipher_id, key_epoch)
            .expect("derive_item_key: key_epoch does not match held SpaceGroupKey epoch")
    }

    /// The currently-held epoch (the RootKey/SGK this device has in memory).
    /// None when locked. Used by Phase 2b conflict merge to stamp re-encrypted
    /// merged ciphers with the merging device's actual current epoch (per the
    /// design review: an envelope's epoch must match held key material).
    pub fn current_epoch(&self) -> Option<u64> {
        match &self.state {
            VaultState::Unlocked(u) => Some(u.current_epoch),
            VaultState::Locked => None,
        }
    }

    /// Get a cipher (decrypts if unlocked, returns metadata only if locked).
    /// Looks up in both active ciphers and trash.
    pub fn get_cipher(&self, cipher_id: Uuid) -> Result<CipherRead, BaluardError> {
        let active_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        let trash_path = self.path.join(format!("trash/{}.enc", cipher_id));

        let file_path = if active_path.exists() {
            active_path
        } else if trash_path.exists() {
            trash_path
        } else {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        };

        let envelope_bytes = std::fs::read(&file_path)?;
        let file = crate::vault::cipher::CipherFile {
            id: cipher_id,
            envelope_bytes,
        };

        match &self.state {
            VaultState::Unlocked(unlocked) => {
                // Read epoch from envelope header for correct Item Key derivation
                let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
                let item_key = Self::derive_item_key_from_sgk(
                    &unlocked.space_group_key,
                    cipher_id,
                    envelope.header.key_epoch,
                )?;
                let cipher = crate::vault::cipher::decrypt_cipher(
                    self.vault_id,
                    cipher_id,
                    &file,
                    &item_key,
                )?;
                Ok(CipherRead::Decrypted(Box::new(cipher)))
            }
            VaultState::Locked => {
                let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
                Ok(CipherRead::Locked(LockedCipherInfo {
                    id: cipher_id,
                    key_epoch: envelope.header.key_epoch,
                    update_seq: envelope.header.update_seq,
                    tier: envelope.header.tier,
                    ciphertext_len: envelope.ciphertext.len(),
                }))
            }
        }
    }

    /// Decrypt a cipher from raw envelope bytes (e.g. read from a specific git
    /// commit via `SyncEngine::read_blob_from_commit`), rather than from the
    /// working tree. Used by Phase 2b field-level conflict merge to decrypt
    /// the base / local / remote versions of a conflicting cipher.
    ///
    /// The `key_epoch` is read from the envelope header (NOT supplied by the
    /// caller); the item key is derived for that epoch via
    /// [`derive_item_key`]. If the vault's held SpaceGroupKey cannot reach the
    /// envelope's epoch (cross-rotation: remote pre-rotation with destroyed
    /// old RootKey, or local behind post-rotation), decryption fails cleanly —
    /// callers MUST treat this as "cannot merge this side," not retry.
    ///
    /// AAD is recomputed from the envelope's own header fields (same invariant
    /// as `get_cipher`), so a blob swapped from a different cipher_id or vault
    /// fails closed.
    pub fn decrypt_cipher_bytes(
        &self,
        cipher_id: Uuid,
        envelope_bytes: &[u8],
    ) -> Result<crate::types::Cipher, BaluardError> {
        let envelope = crate::vault::envelope::deserialize(envelope_bytes)?;
        // Cross-epoch safe path: the envelope may be at a foreign epoch (e.g.
        // a remote pre-rotation version whose RootKey this device no longer
        // holds). try_derive_item_key returns None on epoch mismatch instead
        // of panicking (the plain derive_item_key debug-asserts, which would
        // crash the daemon on the exact safety path). Map None to a clean Err
        // the caller reports as `cross_epoch`.
        let sgk = match &self.state {
            VaultState::Unlocked(u) => &u.space_group_key,
            VaultState::Locked => {
                return Err(VaultError::Corrupt(
                    "decrypt_cipher_bytes called on locked vault".into(),
                )
                .into());
            }
        };
        let item_key = sgk
            .try_derive_item_key(cipher_id, envelope.header.key_epoch)
            .ok_or_else(|| {
                BaluardError::from(VaultError::Corrupt(format!(
                    "cross-epoch decrypt: envelope epoch {} != held SGK epoch {}",
                    envelope.header.key_epoch,
                    sgk.epoch()
                )))
            })?;
        let file = crate::vault::cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: envelope_bytes.to_vec(),
        };
        crate::vault::cipher::decrypt_cipher(self.vault_id, cipher_id, &file, &item_key)
    }

    /// Delete a cipher by ID. By default, moves it to trash.
    /// If it is already in trash, deletes it permanently.
    pub fn delete_cipher(&self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let active_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        let trash_path = self.path.join(format!("trash/{}.enc", cipher_id));

        if active_path.exists() {
            let trash_dir = self.path.join("trash");
            std::fs::create_dir_all(&trash_dir)?;
            let envelope_bytes = std::fs::read(&active_path)?;
            super::write_vault_file(&trash_path, &envelope_bytes)?;
            std::fs::remove_file(&active_path)?;
            self.remove_integrity(&cipher_id.to_string());
            self.rebuild_index()?;
            Ok(())
        } else if trash_path.exists() {
            std::fs::remove_file(&trash_path)?;
            self.remove_integrity(&cipher_id.to_string());
            self.rebuild_index()?;
            Ok(())
        } else {
            Err(VaultError::CipherNotFound(cipher_id.to_string()).into())
        }
    }

    /// List deleted cipher IDs in trash.
    pub fn list_trash_ids(&self) -> Result<Vec<Uuid>, BaluardError> {
        let trash_dir = self.path.join("trash");
        if !trash_dir.exists() {
            return Ok(Vec::new());
        }

        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&trash_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_suffix(".enc") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Restore a deleted cipher from trash back to active.
    pub fn restore_cipher(&self, cipher_id: Uuid) -> Result<(), BaluardError> {
        let active_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        let trash_path = self.path.join(format!("trash/{}.enc", cipher_id));

        if !trash_path.exists() {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        }

        let ciphers_dir = self.path.join("ciphers");
        std::fs::create_dir_all(&ciphers_dir)?;
        let envelope_bytes = std::fs::read(&trash_path)?;
        super::write_vault_file(&active_path, &envelope_bytes)?;
        std::fs::remove_file(&trash_path)?;
        self.rebuild_index()?;
        Ok(())
    }

    /// Purge deleted entries from trash that were deleted more than `days` ago.
    pub fn purge_old_trash(&self, days: u32) -> Result<usize, BaluardError> {
        let trash_dir = self.path.join("trash");
        if !trash_dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        let limit =
            std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86400);

        for entry in std::fs::read_dir(&trash_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified < limit {
                            std::fs::remove_file(&path)?;
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Add a cipher (requires unlocked vault).
    pub fn add_cipher(&mut self, input: &CipherInput) -> Result<Uuid, BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let validated_tags = Self::validate_tags(&input.tags)?;
        let input = CipherInput {
            tags: validated_tags,
            ..input.clone()
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let cipher_id = Uuid::new_v4();
        let item_key = Self::derive_item_key_from_sgk(
            &unlocked.space_group_key,
            cipher_id,
            unlocked.current_epoch,
        )?;

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input,
            &item_key,
            unlocked.current_epoch, // epoch
            1,                      // update_seq
        )?;

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        super::write_vault_file(&file_path, &file.envelope_bytes)?;
        self.rebuild_index()?;
        self.record_integrity(&cipher_id.to_string(), 1);

        Ok(cipher_id)
    }

    /// Update an existing cipher (requires unlocked vault).
    /// Re-encrypts with incremented update_seq.
    pub fn update_cipher(
        &mut self,
        cipher_id: Uuid,
        input: &CipherInput,
    ) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let validated_tags = Self::validate_tags(&input.tags)?;
        let input = CipherInput {
            tags: validated_tags,
            ..input.clone()
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        if !file_path.exists() {
            return Err(VaultError::NotFound(format!("cipher {cipher_id}")).into());
        }

        // Read existing envelope to get current update_seq and key_epoch
        let existing_bytes = std::fs::read(&file_path)?;
        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: existing_bytes,
        };
        let existing_envelope = crate::vault::envelope::deserialize(&existing_file.envelope_bytes)?;
        let new_update_seq = existing_envelope.header.update_seq + 1;
        let key_epoch = existing_envelope.header.key_epoch;

        // Read existing cipher to preserve created_at
        let existing_cipher =
            self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file)?;

        let mut input_owned = input.clone();
        input_owned.created_at = Some(existing_cipher.created_at);

        // Auto-append old password to history if password changed
        let old_password = match &existing_cipher.kind {
            crate::types::CipherKind::Login(data) => data.password.clone(),
            _ => None,
        };
        let new_password = match &input_owned.kind {
            crate::types::CipherKind::Login(data) => data.password.clone(),
            _ => None,
        };
        if let Some(ref old_pw) = old_password {
            if old_password != new_password {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut history = existing_cipher.password_history.clone();
                history.push(crate::types::PasswordHistoryEntry {
                    password: old_pw.clone(),
                    last_used_date: now,
                });
                // Cap history at 10 entries (BW parity default is 5, but 10 is more practical)
                const MAX_PASSWORD_HISTORY: usize = 10;
                if history.len() > MAX_PASSWORD_HISTORY {
                    history.drain(0..history.len() - MAX_PASSWORD_HISTORY);
                }
                input_owned.password_history = history;

                // Update password_revision_date on LoginData
                if let crate::types::CipherKind::Login(ref mut data) = input_owned.kind {
                    data.password_revision_date = Some(now);
                }
            }
        } else if input_owned.password_history.is_empty() {
            // Preserve existing history if caller didn't provide one and password didn't change.
            // History is append-only: passing password_history: vec![] preserves existing history.
            input_owned.password_history = existing_cipher.password_history.clone();
        }

        let item_key =
            Self::derive_item_key_from_sgk(&unlocked.space_group_key, cipher_id, key_epoch)?;

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input_owned,
            &item_key,
            key_epoch,
            new_update_seq,
        )?;

        super::write_vault_file(&file_path, &file.envelope_bytes)?;
        self.rebuild_index()?;
        self.record_integrity(&cipher_id.to_string(), new_update_seq);

        Ok(())
    }

    /// Clone a cipher: duplicate with new UUID, empty password history, reset update_seq.
    pub fn clone_cipher(&mut self, cipher_id: Uuid) -> Result<Uuid, BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        if !file_path.exists() {
            return Err(VaultError::NotFound(format!("cipher {cipher_id}")).into());
        }

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file)?;

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: None,         // fresh timestamp for the clone
            password_history: vec![], // empty history for clone
            attachments: existing.attachments.clone(),
            archived: existing.archived,
            tags: existing.tags.clone(),
        };

        // add_cipher handles new UUID + encryption
        self.add_cipher(&input)
    }

    /// Archive a cipher: sets `archived: true`, hides from main list.
    /// Re-encrypts with updated flag.
    pub fn archive_cipher(&mut self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        if !file_path.exists() {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        }

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file)?;

        if existing.archived {
            return Ok(()); // Already archived, idempotent
        }

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: Some(existing.created_at),
            password_history: existing.password_history,
            attachments: existing.attachments,
            archived: true,
            tags: existing.tags.clone(),
        };
        self.update_cipher(cipher_id, &input)
    }

    /// Unarchive a cipher: sets `archived: false`, restores to main list.
    pub fn unarchive_cipher(&mut self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        if !file_path.exists() {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        }

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file)?;

        if !existing.archived {
            return Ok(()); // Already unarchived, idempotent
        }

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: Some(existing.created_at),
            password_history: existing.password_history,
            attachments: existing.attachments,
            archived: false,
            tags: existing.tags.clone(),
        };
        self.update_cipher(cipher_id, &input)
    }

    /// List archived cipher metadata (ciphers with `archived: true`).
    pub fn list_archived_meta(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        Ok(self
            .list_cipher_meta_full()?
            .into_iter()
            .filter(|m| m.archived)
            .collect())
    }

    // ── Tag operations ──

    /// Validate a single tag name: trim, reject empty/whitespace, max 64 chars, lowercase.
    pub fn validate_tag(name: &str) -> Result<String, BaluardError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(
                VaultError::Metadata("tag name cannot be empty or whitespace".into()).into(),
            );
        }
        if trimmed.chars().count() > 64 {
            return Err(VaultError::Metadata("tag name exceeds 64 characters".into()).into());
        }
        Ok(trimmed.to_lowercase())
    }

    /// Validate a slice of tags: each validated, case-insensitive dedup, max 20.
    pub fn validate_tags(tags: &[String]) -> Result<Vec<String>, BaluardError> {
        let mut validated = Vec::with_capacity(tags.len());
        let mut seen = std::collections::HashSet::new();
        for tag in tags {
            let normalized = Self::validate_tag(tag)?;
            if seen.insert(normalized.clone()) {
                validated.push(normalized);
            }
        }
        if validated.len() > 20 {
            return Err(VaultError::Metadata("cipher cannot have more than 20 tags".into()).into());
        }
        Ok(validated)
    }

    /// List all tags (decrypts from meta/tags.enc, falls back to plaintext tag_index.json).
    /// Returns empty vec if index file is missing.
    pub fn list_tags(&self) -> Result<Vec<String>, BaluardError> {
        let enc_path = self.path.join("meta/tags.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_tags_key(unlocked.root_key.as_bytes())
                .map_err(|e| VaultError::Metadata(format!("tags key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let index: crate::vault::manifest::TagIndex = serde_json::from_slice(&decrypted)
                .map_err(|e| VaultError::Metadata(format!("tags decrypt parse: {e}")))?;
            // Cleanup stale plaintext if encrypted version decrypts cleanly
            let _ = std::fs::remove_file(self.path.join("meta/tag_index.json"));
            return Ok(index.tags);
        }
        // Legacy fallback: plaintext tag_index.json
        let json_path = self.path.join("meta/tag_index.json");
        if json_path.exists() {
            let data = std::fs::read_to_string(&json_path)?;
            let index: crate::vault::manifest::TagIndex = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("tag index deserialization: {e}")))?;
            return Ok(index.tags);
        }
        Ok(vec![])
    }

    /// Rebuild tag index from all decrypted cipher metas (encrypted).
    pub fn rebuild_tag_index(&self) -> Result<(), BaluardError> {
        let metas = self.list_cipher_meta_full()?;
        let mut tag_set = std::collections::HashSet::new();
        for meta in &metas {
            for tag in &meta.tags {
                tag_set.insert(tag.clone());
            }
        }
        let mut tags: Vec<String> = tag_set.into_iter().collect();
        tags.sort();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = crate::vault::manifest::TagIndex {
            tags,
            updated_at: now,
        };

        self.save_tags_enc(&index)?;
        Ok(())
    }

    /// Create a new tag in the index (without assigning to any cipher).
    pub fn create_tag(&mut self, name: &str) -> Result<(), BaluardError> {
        let normalized = Self::validate_tag(name)?;
        let mut tags = self.list_tags()?;
        // Case-insensitive check
        if tags.iter().any(|t| t.eq_ignore_ascii_case(&normalized)) {
            return Ok(()); // idempotent
        }
        tags.push(normalized);
        tags.sort();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = crate::vault::manifest::TagIndex {
            tags,
            updated_at: now,
        };

        self.save_tags_enc(&index)?;
        Ok(())
    }

    /// Encrypt and save tag index to meta/tags.enc (atomic write).
    fn save_tags_enc(&self, index: &crate::vault::manifest::TagIndex) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_tags_key(unlocked.root_key.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("tags key derivation: {e}")))?;
        let json = serde_json::to_vec(index)
            .map_err(|e| VaultError::Metadata(format!("tags serialization: {e}")))?;
        let enc_path = self.path.join("meta/tags.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        // Remove legacy plaintext file if it still exists
        let json_path = self.path.join("meta/tag_index.json");
        if json_path.exists() {
            let _ = std::fs::remove_file(&json_path);
        }
        Ok(())
    }

    /// Rename a tag across all ciphers. Returns count of affected ciphers.
    pub fn rename_tag(&mut self, old: &str, new: &str) -> Result<usize, BaluardError> {
        let old_normalized = Self::validate_tag(old)?;
        let new_normalized = Self::validate_tag(new)?;
        if old_normalized == new_normalized {
            return Ok(0);
        }

        let metas = self.list_cipher_meta_full()?;
        let mut affected = 0usize;

        for meta in &metas {
            if meta
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&old_normalized))
            {
                // Decrypt full cipher
                let cipher = self.get_cipher(meta.id)?;
                let cipher = match cipher {
                    CipherRead::Decrypted(c) => c,
                    _ => continue,
                };

                let mut updated_tags: Vec<String> = cipher
                    .tags
                    .iter()
                    .map(|t| {
                        if t.eq_ignore_ascii_case(&old_normalized) {
                            new_normalized.clone()
                        } else {
                            t.clone()
                        }
                    })
                    .collect();
                updated_tags.sort();
                updated_tags.dedup();

                let input = CipherInput {
                    name: cipher.name,
                    folder_id: cipher.folder_id,
                    kind: cipher.kind,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    notes: cipher.notes,
                    custom_fields: cipher.custom_fields,
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history,
                    attachments: cipher.attachments,
                    archived: cipher.archived,
                    tags: updated_tags,
                };
                self.update_cipher(meta.id, &input)?;
                affected += 1;
            }
        }

        self.rebuild_tag_index()?;
        Ok(affected)
    }

    /// Delete a tag from all ciphers. Returns count of affected ciphers.
    pub fn delete_tag(&mut self, name: &str) -> Result<usize, BaluardError> {
        let normalized = Self::validate_tag(name)?;

        let metas = self.list_cipher_meta_full()?;
        let mut affected = 0usize;

        for meta in &metas {
            if meta
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&normalized))
            {
                let cipher = self.get_cipher(meta.id)?;
                let cipher = match cipher {
                    CipherRead::Decrypted(c) => c,
                    _ => continue,
                };

                let updated_tags: Vec<String> = cipher
                    .tags
                    .iter()
                    .filter(|t| !t.eq_ignore_ascii_case(&normalized))
                    .cloned()
                    .collect();

                let input = CipherInput {
                    name: cipher.name,
                    folder_id: cipher.folder_id,
                    kind: cipher.kind,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    notes: cipher.notes,
                    custom_fields: cipher.custom_fields,
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history,
                    attachments: cipher.attachments,
                    archived: cipher.archived,
                    tags: updated_tags,
                };
                self.update_cipher(meta.id, &input)?;
                affected += 1;
            }
        }

        self.rebuild_tag_index()?;
        Ok(affected)
    }

    fn find_device_id(path: &Path) -> Result<Uuid, BaluardError> {
        let keywrap_dir = path.join("meta/keywrap");
        if !keywrap_dir.exists() {
            return Err(VaultError::NotInitialized.into());
        }

        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(&keywrap_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_suffix(".json") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    candidates.push(id);
                }
            }
        }

        if candidates.is_empty() {
            return Err(VaultError::NotFound("no keywrap files found".into()).into());
        }

        // 1. Direct local device identity from meta/device-id or device-privkey.json
        if let Some(local_id) = crate::vault::device_privkey::read_device_id(path) {
            if candidates.contains(&local_id) {
                return Ok(local_id);
            }
        }

        // F1 fix: match local device public key against devices.json registry per device
        let registry_path = path.join("meta/devices.json");
        let registry: Option<DeviceRegistry> = if registry_path.exists() {
            std::fs::read_to_string(&registry_path)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
        } else {
            None
        };

        for candidate in &candidates {
            // C1: discovery runs pre-unlock (no seal key); the sealed file
            // arm fails closed, so only keyring-backed candidates can be
            // confirmed here. Single-keywrap fallback below still covers
            // keystore-less vaults.
            if let Ok(privkeys) = load_device_privkeys(path, *candidate, None) {
                let pub_key = x25519_dalek::PublicKey::from(&privkeys.x25519);
                let local_pub_hex = hex::encode(pub_key.as_bytes());
                if let Some(ref reg) = registry {
                    if let Some(device_rec) = reg.devices.get(candidate) {
                        if device_rec.encryption_public_key == local_pub_hex {
                            let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                            return Ok(*candidate);
                        }
                    }
                } else if candidates.len() == 1 {
                    let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                    return Ok(*candidate);
                }
            }
        }

        // Fallback: candidate where load_device_privkeys succeeds
        for candidate in &candidates {
            if load_device_privkeys(path, *candidate, None).is_ok() {
                let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                return Ok(*candidate);
            }
        }

        // Fallback for single keywrap file
        if candidates.len() == 1 {
            let _ = crate::vault::device_privkey::write_device_id(path, candidates[0]);
            return Ok(candidates[0]);
        }

        Err(VaultError::NotFound("matching device keywrap not found for this device".into()).into())
    }

    pub fn derive_vault_id(kdf_params: &KdfParams) -> Uuid {
        // Derive a stable UUID from the KDF salt
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"baluard-vault-id-v1");
        hasher.update(&kdf_params.salt);
        let hash = hasher.finalize();
        Uuid::from_bytes(hash[..16].try_into().unwrap())
    }

    /// Derive the vault_id from on-disk KDF params without fully opening
    /// the vault. Used by callers (e.g. daemon biometric status, which runs
    /// while the vault is locked) that need a stable per-vault identity to
    /// namespace per-vault keychain entries.
    pub fn vault_id_for_path(path: &Path) -> Result<Uuid, BaluardError> {
        let kdf_path = path.join("meta/kdf-params.json");
        let kdf_json = std::fs::read_to_string(&kdf_path)
            .map_err(|e| VaultError::Metadata(format!("reading kdf params: {e}")))?;
        let kdf_params: KdfParams = serde_json::from_str(&kdf_json)
            .map_err(|e| VaultError::Corrupt(format!("kdf params: {e}")))?;
        Ok(Self::derive_vault_id(&kdf_params))
    }

    // ── Rate limiting ──

    /// Check if too many failed unlock attempts have occurred.
    /// Exponential backoff: after N failures, wait 2^(N-5) seconds.
    /// First 5 attempts: no delay. After that: 1s, 2s, 4s, 8s, ...
    ///
    /// **Note**: This is a soft deterrent, not hard brute-force protection.
    /// The counter is stored in `meta/kdf-attempts.json` which can be deleted
    /// by any process with write access. Argon2id provides the real defense.
    fn check_attempt_rate_limit(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        if !path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(&path)
            .map_err(|e| VaultError::Metadata(format!("reading attempts: {e}")))?;
        let info: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| VaultError::Corrupt(format!("attempts json: {e}")))?;
        let count = info["failed_count"].as_u64().unwrap_or(0);
        let last_ts = info["last_failed_at"].as_u64().unwrap_or(0);

        if count > 5 {
            let delay_secs = 1u64 << (count - 5).min(10); // cap at 2^10 = 1024s
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now.saturating_sub(last_ts) < delay_secs {
                return Err(VaultError::Corrupt(format!(
                    "too many failed attempts, wait {} seconds",
                    delay_secs - (now - last_ts)
                ))
                .into());
            }
        }
        Ok(())
    }

    fn record_failed_attempt(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (count, _) = if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| VaultError::Metadata(format!("reading attempts: {e}")))?;
            let info: serde_json::Value = serde_json::from_str(&data).unwrap_or_default();
            (info["failed_count"].as_u64().unwrap_or(0), 0u64)
        } else {
            (0, 0)
        };

        let record = serde_json::json!({
            "failed_count": count + 1,
            "last_failed_at": now,
        });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record)
                .map_err(|e| VaultError::Corrupt(format!("attempts serialize: {e}")))?
                .as_bytes(),
        )?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn clear_failed_attempts(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Determine the current key epoch from existing vault data.
    fn determine_current_epoch(&self) -> u64 {
        // Try RK canary first (has key_epoch)
        let rk_path = self.path.join("meta/rk-canary.enc");
        if rk_path.exists() {
            if let Ok(data) = std::fs::read(&rk_path) {
                if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                    return envelope.header.key_epoch;
                }
            }
        }
        // Try first cipher envelope
        if let Ok(ids) = self.list_cipher_ids() {
            if let Some(first_id) = ids.first() {
                let file_path = self.path.join(format!("ciphers/{}.enc", first_id));
                if let Ok(data) = std::fs::read(&file_path) {
                    if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                        return envelope.header.key_epoch;
                    }
                }
            }
        }
        // Default: epoch 1
        1
    }

    // ── Key Rotation (MISS-1 + MISS-2) ──

    /// Full root key rotation for single-device vaults.
    ///
    /// Atomic rotation with staged writes:
    /// 1. Generate new Root Key
    /// 2. Re-encrypt all ciphers (active + trash) to .tmp files
    /// 3. Update RK canary with new Root Key
    /// 4. Write new keywrap file for this device
    /// 5. Rename all .tmp -> final (single pass)
    /// 6. Transition epoch via DeviceManager lifecycle
    /// 7. Zeroize old Root Key
    ///
    /// After this, the old Root Key cannot decrypt any cipher.
    /// Forward secrecy is achieved.
    ///
    /// Requires unlocked vault.
    pub fn rotate_root_key(&mut self) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt(
                "rotation in progress, use finalize_rotation()".into(),
            )
            .into());
        }

        let old_epoch = match &self.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let new_epoch = old_epoch + 1;
        let new_root_key = RootKey::generate();

        // Collect both active and trash cipher IDs
        let active_ids = self.list_cipher_ids()?;
        let trash_ids = self.list_trash_ids()?;
        let all_ids: Vec<(Uuid, bool)> = active_ids
            .iter()
            .map(|id| (*id, false))
            .chain(trash_ids.iter().map(|id| (*id, true)))
            .collect();

        // Write rotation-pending marker for crash recovery
        let pending_marker = self.path.join("meta/.rotation-pending");
        let pending_data = serde_json::json!({
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
        });
        std::fs::write(
            &pending_marker,
            serde_json::to_string_pretty(&pending_data).unwrap(),
        )?;
        let _ = std::fs::set_permissions(&pending_marker, std::fs::Permissions::from_mode(0o600));
        // B-1 fix: arm the RAII guard so a panic or early-return mid-rotation
        // sweeps staged .tmp files (ciphers, canary, keywrap) and leaves the
        // marker in place for VaultHandle::open to reconcile. Without this, a
        // crash mid-rename-loop left a mixed-epoch vault with no recovery.
        let mut _guard = RotationGuard::new(&self.path, &pending_marker);

        // Phase 1: Re-encrypt all ciphers to .tmp files (staged)
        let mut staged_renames: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (cipher_id, is_trash) in &all_ids {
            let dir = if *is_trash { "trash" } else { "ciphers" };
            let file_path = self.path.join(dir).join(format!("{cipher_id}.enc"));
            if !file_path.exists() {
                continue;
            }
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile {
                id: *cipher_id,
                envelope_bytes,
            };

            let old_root = match &self.state {
                VaultState::Unlocked(u) => u.root_key.clone(),
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let mut existing = self.try_decrypt_cipher_with_root_key(&old_root, &file)?;
            drop(old_root);

            let input = CipherInput {
                name: existing.name.clone(),
                folder_id: existing.folder_id,
                kind: existing.kind.clone(),
                favorite: existing.favorite,
                reprompt: existing.reprompt,
                notes: existing.notes.clone(),
                custom_fields: existing.custom_fields.clone(),
                created_at: Some(existing.created_at),
                password_history: existing.password_history.clone(),
                attachments: existing.attachments.clone(),
                archived: existing.archived,
                tags: existing.tags.clone(),
            };

            let new_item_key =
                Self::derive_item_key_from_root(&new_root_key, *cipher_id, new_epoch);
            let new_file = cipher::encrypt_cipher(
                self.vault_id,
                *cipher_id,
                &input,
                &new_item_key,
                new_epoch,
                existing.update_seq,
            )?;

            // Zeroize decrypted plaintext after re-encrypt (B-5: rotate_root_key
            // previously skipped this, leaving every secret in freed heap
            // after a routine non-revocation rotation).
            Self::zeroize_decrypted_cipher(&mut existing);

            // Write to .tmp path (staged)
            let tmp_path = file_path.with_extension("enc.tmp");
            std::fs::write(&tmp_path, &new_file.envelope_bytes)?;
            staged_renames.push((tmp_path, file_path));
        }

        // Phase 2: Update RK canary (staged)
        let rk_canary = super::canary::create_rk_canary(&new_root_key, self.vault_id, new_epoch)?;
        let canary_path = self.path.join("meta/rk-canary.enc");
        let canary_tmp = canary_path.with_extension("enc.tmp");
        std::fs::write(&canary_tmp, &rk_canary)?;
        let canary_rename = (canary_tmp.clone(), canary_path.clone());

        // Phase 3: Write new keywrap file (staged)
        let seal_key = self.devkey_seal();
        let privkeys = match load_device_privkeys(&self.path, self.device_id, seal_key.as_ref()) {
            Ok(k) => k,
            Err(_) => {
                // Cleanup staged files on error
                for (tmp, _) in &staged_renames {
                    let _ = std::fs::remove_file(tmp);
                }
                let _ = std::fs::remove_file(&canary_tmp);
                return Err(VaultError::NotFound(
                    "device private key not found for keywrap".into(),
                )
                .into());
            }
        };
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);
        let (eph_pub, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(new_root_key.as_bytes(), &x25519_public)?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_tmp = keywrap_path.with_extension("json.tmp");
        std::fs::write(
            &keywrap_tmp,
            serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // Phase 4: Atomic commit - rename all .tmp -> final
        // Order matters for crash safety: ciphers first, canary second, keywrap last.
        // If crash occurs mid-way, .rotation-pending marker enables recovery.
        // 1. Commit all cipher files first (the bulk of the data)
        for (tmp, final_path) in &staged_renames {
            std::fs::rename(tmp, final_path)?;
        }
        // 2. Commit RK canary (signals new root key is active)
        std::fs::rename(&canary_rename.0, &canary_rename.1)?;
        // 3. Commit keywrap last (point of no return)
        std::fs::rename(&keywrap_tmp, &keywrap_path)?;

        // Read folders/tags/profile with OLD root key before swap
        let old_folders = self.list_folders().ok();
        let old_tags = self.list_tags().ok();
        let old_profile = self.load_profile().ok();
        let old_activity = self.load_activity_enc().ok();

        // Phase 5: Swap Root Key and update epoch via DeviceManager lifecycle
        match &mut self.state {
            VaultState::Unlocked(u) => {
                u.root_key.zeroize();
                u.root_key = new_root_key.clone();
                u.space_group_key.zeroize();
                u.space_group_key = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                    &new_root_key,
                    new_epoch,
                );
                u.current_epoch = new_epoch;
                u.item_keys.clear();
            }
            VaultState::Locked => return Err(VaultError::Locked.into()),
        }

        // H4 fix: proper epoch lifecycle through DeviceManager
        // Clean transition: old ACTIVE -> new ACTIVE (single-device shortcut)
        self.device_manager
            .single_device_commit_rotation(new_epoch)?;

        // Fire observer hook
        if let Some(vp) = self.vault_path_as_ref() {
            self.device_manager.notify_rotation_committed(new_epoch, vp);
        }

        // Re-encrypt folders/tags/profile with NEW root key
        if let Some(folders) = old_folders {
            let _ = self.save_folders(&folders);
        }
        if let Some(tags) = old_tags {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let index = crate::vault::manifest::TagIndex {
                tags,
                updated_at: now,
            };
            let _ = self.save_tags_enc(&index);
        }
        if let Some(profile) = old_profile {
            let _ = self.save_profile(&profile);
        }
        if let Some(activity) = old_activity {
            let _ = self.save_activity_enc(&activity);
        }

        // Clean up rotation-pending marker (disarm guard first)
        _guard.disarm();
        let _ = std::fs::remove_file(self.path.join("meta/.rotation-pending"));

        // H4 fix: re-wrap recovery key with new Root Key (propagate error)
        Self::rewrap_recovery_key(&self.path, &new_root_key)?;

        Ok(())
    }

    /// Zeroize sensitive plaintext fields of a decrypted cipher in place.
    ///
    /// Shared by `rotate_root_key` and `revoke_device_and_rekey` so the
    /// per-kind zeroize logic cannot drift between them (B-5: rotate_root_key
    /// previously skipped this entirely, leaving every secret in the vault
    /// lingering in freed heap after a routine non-revocation rotation).
    ///
    /// Mirrors the field set in [`crate::sync::conflict::ConflictInfo::drop`].
    /// Notes, custom-field hidden values, and the kind-specific secret fields
    /// (Login password/TOTP/passkey keys, Card number/code, SshKey private
    /// key) are zeroized. Public/non-secret fields (names, URIs, etc.) are
    /// left for the caller to drop normally.
    fn zeroize_decrypted_cipher(existing: &mut crate::types::Cipher) {
        use zeroize::Zeroize;
        if let Some(n) = existing.notes.as_mut() {
            n.zeroize();
        }
        for cf in existing.custom_fields.iter_mut() {
            if matches!(cf.field_type, crate::types::CustomFieldType::Hidden) {
                cf.value.zeroize();
            }
        }
        match &mut existing.kind {
            crate::types::CipherKind::Login(d) => {
                if let Some(p) = d.password.as_mut() {
                    p.zeroize();
                }
                if let Some(u) = d.username.as_mut() {
                    u.zeroize();
                }
                if let Some(t) = d.totp_uri.as_mut() {
                    t.zeroize();
                }
                if let Some(ref mut fido2_list) = d.fido2_credentials {
                    for pk in fido2_list.iter_mut() {
                        if let Some(k) = pk.private_key.as_mut() {
                            k.zeroize();
                        }
                        if let Some(k) = pk.prf_key.as_mut() {
                            k.zeroize();
                        }
                    }
                }
            }
            crate::types::CipherKind::Card(d) => {
                if let Some(n) = d.number.as_mut() {
                    n.zeroize();
                }
                if let Some(c) = d.code.as_mut() {
                    c.zeroize();
                }
            }
            crate::types::CipherKind::SshKey(d) => {
                if let Some(k) = d.private_key.as_mut() {
                    k.zeroize();
                }
            }
            crate::types::CipherKind::Identity(_)
            | crate::types::CipherKind::BankAccount(_)
            | crate::types::CipherKind::DriversLicense(_)
            | crate::types::CipherKind::Passport(_)
            | crate::types::CipherKind::SecureNote => {}
        }
    }

    /// Re-wrap the Root Key in meta/recovery.json after rotation.
    /// Reads the stored recovery X25519 public key and HPKE-wraps the new Root Key.
    /// If recovery.json doesn't exist or lacks the pubkey field, silently skips.
    fn rewrap_recovery_key(vault_path: &Path, new_root_key: &RootKey) -> Result<(), BaluardError> {
        let recovery_path = vault_path.join("meta/recovery.json");
        if !recovery_path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(&recovery_path)
            .map_err(|e| VaultError::Metadata(format!("read recovery.json: {e}")))?;
        let mut json: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| VaultError::Corrupt(format!("parse recovery.json: {e}")))?;

        let pubkey_hex = match json["recovery_x25519_pubkey"].as_str() {
            Some(h) => h,
            None => {
                // Legacy vault without pubkey field — cannot re-wrap.
                // Recovery phrase will unwrap the OLD Root Key, which is stale after rotation.
                // Log loudly; user should re-create vault or re-enroll via recovery phrase.
                eprintln!(
                    "WARNING: recovery.json lacks recovery_x25519_pubkey; recovery re-wrap skipped. \
                     Recovery phrase will NOT work after this rotation. \
                     Re-enroll via recovery phrase to fix."
                );
                return Ok(());
            }
        };

        let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex)
            .map_err(|e| VaultError::Corrupt(format!("recovery pubkey hex: {e}")))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("recovery pubkey wrong length".into()))?;

        let pubkey = x25519_dalek::PublicKey::from(pubkey_bytes);
        let (eph_pub, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(new_root_key.as_bytes(), &pubkey)?;

        // Update the JSON in-place
        json["ephemeral_public"] = serde_json::Value::String(hex::encode(eph_pub));
        json["encrypted_key"] = serde_json::Value::String(hex::encode(ct));
        json["tag"] = serde_json::Value::String(hex::encode(tag));

        let tmp = recovery_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&json).unwrap())?;
        // H4 fix: enforce 0600 on file holding HPKE-wrapped Root Key
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, &recovery_path)?;

        Ok(())
    }
    ///
    /// Generates a new Root Key, wraps it for all enrolled devices,
    /// and transitions the epoch to ROTATING.
    ///
    /// After calling this, the caller should:
    /// Revoke a device and perform full root key rotation.
    ///
    /// This is the correct entry point for device revocation. It:
    /// 1. Validates all preconditions (unlocked, not self, privkey readable)
    /// 2. Writes crash-recovery marker
    /// 3. Removes the target device from the registry and generates new Root Key
    /// 4. Re-encrypts all ciphers (active + trash) and attachments with the new key
    /// 5. Updates the RK canary
    /// 6. Writes a new keywrap file for this device
    /// 7. Updates in-memory state
    /// 8. Cleans up the revoked device's keywrap
    ///
    /// Cannot revoke self. Use force-evict from another device for that.
    /// Requires unlocked vault.
    pub fn revoke_device_and_rekey(
        &mut self,
        target_device_id: Uuid,
    ) -> Result<crate::device_manager::RevokeDeviceResult, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        if target_device_id == self.device_id {
            return Err(VaultError::InvalidOperation(
                "cannot revoke the current device. Use force-evict from another device.".into(),
            )
            .into());
        }

        let old_epoch = match &self.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // ── Precheck: validate privkey accessible BEFORE any irreversible change ──
        let seal_key = self.devkey_seal();
        let privkeys = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())?;

        // ── Write crash-recovery marker and setup cleanup guard ──
        let pending_marker = self.path.join("meta/.rotation-pending");
        let pending_data = serde_json::json!({
            "old_epoch": old_epoch,
            "new_epoch": old_epoch + 1,
        });
        std::fs::write(
            &pending_marker,
            serde_json::to_string_pretty(&pending_data).unwrap(),
        )?;
        let _ = std::fs::set_permissions(&pending_marker, std::fs::Permissions::from_mode(0o600));
        let mut _guard = RotationGuard::new(&self.path, &pending_marker);

        // ── Commit: revoke in registry and get new root key ──
        let mut result = self
            .device_manager
            .revoke_device_and_rotate(target_device_id, self.device_id)?;
        let new_root_key = result
            .new_root_key
            .as_ref()
            .ok_or_else(|| VaultError::Corrupt("revoke returned no new root key".into()))?
            .clone();
        let new_epoch = result.new_epoch;

        // ── Clone old root key once (borrow-safe for loop) ──
        let old_root = match &self.state {
            VaultState::Unlocked(u) => u.root_key.clone(),
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // ── Re-encrypt all ciphers (active + trash) and attachments to .tmp ──
        let active_ids = self.list_cipher_ids()?;
        let trash_ids = self.list_trash_ids()?;
        let all_ids: Vec<(Uuid, bool)> = active_ids
            .iter()
            .map(|id| (*id, false))
            .chain(trash_ids.iter().map(|id| (*id, true)))
            .collect();

        let mut staged_renames: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (cipher_id, is_trash) in &all_ids {
            let dir = if *is_trash { "trash" } else { "ciphers" };
            let file_path = self.path.join(dir).join(format!("{cipher_id}.enc"));
            if !file_path.exists() {
                continue;
            }
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile {
                id: *cipher_id,
                envelope_bytes,
            };

            let mut existing = self.try_decrypt_cipher_with_root_key(&old_root, &file)?;

            // Re-encrypt attachment blobs with new item key
            let new_item_key =
                Self::derive_item_key_from_root(&new_root_key, *cipher_id, new_epoch);
            let old_item_key = Self::derive_item_key_from_root(&old_root, *cipher_id, old_epoch);
            for attach_meta in &existing.attachments {
                let attach_dir = self
                    .path
                    .join("entries")
                    .join(cipher_id.to_string())
                    .join("attachments");
                let attach_path = attach_dir.join(format!("{}.enc", attach_meta.id));
                if !attach_path.exists() {
                    continue;
                }
                let enc_blob = std::fs::read(&attach_path)?;
                let attach_uuid: Uuid = attach_meta
                    .id
                    .parse()
                    .map_err(|e| VaultError::Corrupt(format!("attachment id not a uuid: {e}")))?;
                let mut plaintext = crate::vault::attachment::decrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    old_item_key.as_bytes(),
                    &enc_blob,
                )?;
                let new_enc = crate::vault::attachment::encrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    new_item_key.as_bytes(),
                    &plaintext,
                    new_epoch,
                    existing.update_seq,
                )?;
                plaintext.zeroize();
                let attach_tmp = attach_path.with_extension("enc.tmp");
                std::fs::write(&attach_tmp, &new_enc)?;
                staged_renames.push((attach_tmp, attach_path));
            }

            let input = CipherInput {
                name: existing.name.clone(),
                folder_id: existing.folder_id,
                kind: existing.kind.clone(),
                favorite: existing.favorite,
                reprompt: existing.reprompt,
                notes: existing.notes.clone(),
                custom_fields: existing.custom_fields.clone(),
                created_at: Some(existing.created_at),
                password_history: existing.password_history.clone(),
                attachments: existing.attachments.clone(),
                archived: existing.archived,
                tags: existing.tags.clone(),
            };

            let new_file = cipher::encrypt_cipher(
                self.vault_id,
                *cipher_id,
                &input,
                &new_item_key,
                new_epoch,
                existing.update_seq,
            )?;

            // Zeroize decrypted plaintext after use (B-5: shared helper so
            // rotate_root_key and revoke_device_and_rekey cannot drift).
            Self::zeroize_decrypted_cipher(&mut existing);

            let tmp_path = file_path.with_extension("enc.tmp");
            std::fs::write(&tmp_path, &new_file.envelope_bytes)?;
            staged_renames.push((tmp_path, file_path));
        }
        drop(old_root);

        // ── Update RK canary (staged) ──
        let rk_canary = super::canary::create_rk_canary(&new_root_key, self.vault_id, new_epoch)?;
        let canary_path = self.path.join("meta/rk-canary.enc");
        let canary_tmp = canary_path.with_extension("enc.tmp");
        std::fs::write(&canary_tmp, &rk_canary)?;

        // ── Write keywrap for current device (staged) ──
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);
        let (eph_pub, ct, tag) = hpke_wrap::wrap_key(new_root_key.as_bytes(), &x25519_public)?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_tmp = keywrap_path.with_extension("json.tmp");
        std::fs::write(
            &keywrap_tmp,
            serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // ── Atomic commit: rename all .tmp -> final ──
        for (tmp, final_path) in &staged_renames {
            std::fs::rename(tmp, final_path)?;
        }
        std::fs::rename(&canary_tmp, &canary_path)?;
        std::fs::rename(&keywrap_tmp, &keywrap_path)?;

        // ── Remove revoked device's keywrap file ──
        let revoked_keywrap = self
            .path
            .join(format!("meta/keywrap/{target_device_id}.json"));
        let _ = std::fs::remove_file(&revoked_keywrap);

        // Read folders/tags/profile with OLD root key before swap
        let old_folders = self.list_folders().ok();
        let old_tags = self.list_tags().ok();
        let old_profile = self.load_profile().ok();
        let old_activity = self.load_activity_enc().ok();

        // ── Update in-memory state ──
        match &mut self.state {
            VaultState::Unlocked(u) => {
                u.root_key.zeroize();
                u.root_key = new_root_key.clone();
                u.space_group_key.zeroize();
                u.space_group_key = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                    &new_root_key,
                    new_epoch,
                );
                u.current_epoch = new_epoch;
                u.item_keys.clear();
            }
            VaultState::Locked => return Err(VaultError::Locked.into()),
        }

        // Zeroize new root key in result (callers only need metadata)
        result.new_root_key = None;

        self.sync_registry_from_device_manager();

        if let Some(vp) = self.vault_path_as_ref() {
            self.device_manager.notify_rotation_committed(new_epoch, vp);
        }

        // Re-encrypt folders/tags/profile with NEW root key
        if let Some(folders) = old_folders {
            let _ = self.save_folders(&folders);
        }
        if let Some(tags) = old_tags {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let index = crate::vault::manifest::TagIndex {
                tags,
                updated_at: now,
            };
            let _ = self.save_tags_enc(&index);
        }
        if let Some(profile) = old_profile {
            let _ = self.save_profile(&profile);
        }
        if let Some(activity) = old_activity {
            let _ = self.save_activity_enc(&activity);
        }

        // Clean up rotation-pending marker (disarm guard first)
        _guard.disarm();
        let _ = std::fs::remove_file(&pending_marker);

        // H4 fix: re-wrap recovery key with new Root Key (propagate error)
        Self::rewrap_recovery_key(&self.path, &new_root_key)?;

        Ok(result)
    }

    /// 1. If multi-device: git push the .txn file
    /// 2. If single-device: call `finalize_rotation()` immediately
    ///
    /// Requires unlocked vault.
    pub fn initiate_key_rotation(&mut self) -> Result<RootKey, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        let (new_root, _tx) = self.device_manager.initiate_rotation(self.device_id)?;
        Ok(new_root)
    }

    /// Check if there is a pending rotation that needs processing.
    pub fn has_pending_rotation(&self) -> bool {
        self.device_manager.epoch_state() == crate::keys::epoch::EpochState::Rotating
    }

    /// Get the current epoch state from DeviceManager.
    pub fn epoch_state(&self) -> crate::keys::epoch::EpochState {
        self.device_manager.epoch_state()
    }

    /// Finalize a rotation after quorum is reached (or single-device self-ack).
    ///
    /// This method:
    /// 1. Records a self-ack for single-device scenarios
    /// 2. Commits the rotation if quorum is reached
    ///
    /// Returns true if the rotation was committed.
    pub fn finalize_rotation(&mut self) -> Result<bool, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        let _epoch = self.device_manager.current_epoch();
        let tx_ref = self.device_manager.pending_transaction();
        let tx = match tx_ref {
            Some(tx) => tx,
            None => return Err(VaultError::Corrupt("no pending rotation".into()).into()),
        };

        // Build self-ack: sign with this device's Ed25519 key
        let txn_hash = crate::device_manager::compute_txn_hash(tx);

        let sign_input =
            crate::device_manager::build_ack_sign_input(tx.new_epoch, &self.device_id, &txn_hash);

        // Load signing key
        let seal_key = self.devkey_seal();
        let privkeys = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())?;

        use crate::crypto::signature;
        let ack_sig = signature::sign(&privkeys.ed25519, &sign_input)?;

        let ack = crate::device_manager::RotationAck {
            epoch: tx.new_epoch,
            device_id: self.device_id,
            txn_hash: txn_hash.clone(),
            signature: ack_sig.to_bytes().to_vec(),
        };

        self.device_manager.record_ack(ack)
    }

    /// Emergency force evict: removes all other devices, initiates rotation.
    /// For single-device vaults, commits immediately.
    ///
    /// Returns the result of the eviction.
    pub fn force_evict_and_rotate(
        &mut self,
    ) -> Result<crate::device_manager::ForceEvictResult, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let result = self.device_manager.force_evict_and_rotate(self.device_id)?;
        // M6 fix: sync registry after eviction
        self.sync_registry_from_device_manager();
        Ok(result)
    }

    /// Recover vault from BIP-39 recovery phrase.
    /// Resets the device registry and enrolls this device as sole survivor.
    ///
    /// Returns the recovered Root Key and new device entry.
    pub fn recover_from_phrase(
        &mut self,
        phrase: &str,
        device_name: &str,
    ) -> Result<crate::device_manager::RecoveryResult, BaluardError> {
        let result = self
            .device_manager
            .recover_from_phrase(phrase, device_name)?;
        // M6 fix: sync registry after recovery
        self.sync_registry_from_device_manager();
        Ok(result)
    }

    /// Rebuild index.enc from active ciphers on disk.
    pub fn rebuild_index(&self) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let ids = self.list_cipher_ids()?;
        let mut metas = Vec::with_capacity(ids.len());

        for id in ids {
            let file_path = self.path.join(format!("ciphers/{}.enc", id));
            if !file_path.exists() {
                continue;
            }
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile { id, envelope_bytes };

            let c = match self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &file) {
                Ok(c) => c,
                Err(crate::error::BaluardError::Vault(crate::error::VaultError::CrossEpoch {
                    envelope_epoch,
                    held_epoch,
                })) => {
                    // Cipher at a key epoch the held RootKey/SGK cannot reach.
                    // Previously this was silently `continue`d, which made the
                    // entry vanish from vault.list with no signal. Surface it
                    // so the user knows a re-sync / device refresh is needed
                    // (B-2 fix). Still skip rather than fail the whole list —
                    // a vault with one stray remote blob should still render.
                    eprintln!(
                        "warning: cipher {id} at epoch {envelope_epoch} cannot be decrypted with held epoch {held_epoch}; skipping from index",
                    );
                    continue;
                }
                Err(e) => {
                    // Genuine corrupt envelope / IO error: log and skip rather
                    // than abort the whole index (graceful degradation), but
                    // keep this path noisy so it does not hide silent loss.
                    eprintln!("warning: cipher {id} skipped during index build: {e}");
                    continue;
                }
            };

            let username = match &c.kind {
                crate::types::CipherKind::Login(data) => data.username.clone(),
                _ => None,
            };

            metas.push(crate::types::CipherMeta {
                id: c.id,
                name: c.name,
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
            });
        }

        let index_key = hkdf_derive::derive_index_key(unlocked.root_key.as_bytes())?;
        let enc_bytes =
            index::encrypt_index(self.vault_id, &metas, &index_key, unlocked.current_epoch)?;

        let index_dir = self.path.join("meta");
        std::fs::create_dir_all(&index_dir)?;
        let index_path = index_dir.join("index.enc");
        let tmp_path = index_path.with_extension("enc.tmp");
        super::write_vault_file(&tmp_path, &enc_bytes)?;
        std::fs::rename(&tmp_path, &index_path)?;

        Ok(())
    }

    /// H3 fix: Record integrity checkpoint after cipher writes.
    /// Best-effort: loads manifest, records checkpoint signed with device Ed25519 key,
    /// saves. Failures are logged, not propagated (integrity is defense-in-depth, not gating).
    fn record_integrity(&self, object_id: &str, seq: u64) {
        let Ok(mut manifest) = crate::integrity::IntegrityManifest::load(&self.path) else {
            return;
        };
        let seal_key = self.devkey_seal();
        let Ok(privkeys) = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())
        else {
            return;
        };
        let signing_key = privkeys.ed25519;
        if manifest
            .record(object_id, seq, &self.device_id.to_string(), &signing_key)
            .is_err()
        {
            return;
        }
        if manifest.save(&self.path).is_err() {
            // intentionally ignored: this is the last step, fall through
        }
    }
    /// H3 fix: Remove integrity checkpoint on cipher delete.
    /// Prevents false rollback alarms for legitimately deleted entries.
    fn remove_integrity(&self, object_id: &str) {
        let Ok(mut manifest) = crate::integrity::IntegrityManifest::load(&self.path) else {
            return;
        };
        manifest.checkpoints.remove(object_id);
        let _ = manifest.save(&self.path);
    }
}

/// RAII guard: on drop, removes all .tmp files in vault dirs and the rotation-pending marker.
/// Disarm with `disarm()` after successful commit.
struct RotationGuard {
    vault_path: PathBuf,
    pending_marker: PathBuf,
    armed: bool,
}

impl RotationGuard {
    fn new(vault_path: &Path, pending_marker: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            pending_marker: pending_marker.to_path_buf(),
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RotationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = std::fs::remove_file(&self.pending_marker);
        // Sweep flat dirs
        for dir_name in &["ciphers", "trash"] {
            remove_tmp_files(&self.vault_path.join(dir_name));
        }
        // Sweep entries/ recursively (attachments live in entries/<id>/attachments/)
        remove_tmp_files_recursive(&self.vault_path.join("entries"));
        // Sweep meta/ and meta/keywrap/
        remove_tmp_files(&self.vault_path.join("meta"));
        remove_tmp_files(&self.vault_path.join("meta/keywrap"));
    }
}

/// Remove .tmp files in a single directory (non-recursive).
fn remove_tmp_files(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "tmp") {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Remove .tmp files in a directory tree recursively.
fn remove_tmp_files_recursive(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                remove_tmp_files_recursive(&p);
            } else if p.extension().is_some_and(|e| e == "tmp") {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Result of reading a cipher: either decrypted content or locked metadata.
pub enum CipherRead {
    Decrypted(Box<Cipher>),
    Locked(LockedCipherInfo),
}

/// Cipher metadata available when vault is locked.
pub struct LockedCipherInfo {
    pub id: Uuid,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub tier: Option<Tier>,
    pub ciphertext_len: usize,
}

// ── Keyring-backed device private key storage ──

/// Device private key material (X25519 + Ed25519).
struct DevicePrivKeys {
    x25519: x25519_dalek::StaticSecret,
    ed25519: ed25519_dalek::SigningKey,
}

/// Build a stable keyring service name from vault salt.
/// Uses first 8 bytes of salt to avoid collisions between multiple vaults.
fn keyring_service(vault_path: &Path) -> String {
    // Read salt from kdf-params.json for a stable fingerprint
    let kdf_path = vault_path.join("meta/kdf-params.json");
    if let Ok(data) = std::fs::read_to_string(&kdf_path) {
        if let Ok(params) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(salt_hex) = params["salt"].as_str() {
                if salt_hex.len() >= 16 {
                    return format!("baluard-{}", &salt_hex[..16]);
                }
            }
        }
    }
    // Fallback: hash the vault path
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    vault_path.hash(&mut hasher);
    format!("baluard-fallback-{:016x}", hasher.finish())
}

/// Load device private keys from OS keyring, falling back to plaintext file.
/// On successful file read, migrates to keyring and deletes the file.
fn load_device_privkeys(
    vault_path: &Path,
    device_id: Uuid,
    seal_key: Option<&[u8; 32]>,
) -> Result<DevicePrivKeys, BaluardError> {
    // 0. Consult SecureKeystore (global or injected)
    if let Some(keystore) = crate::vault::creation::get_global_keystore() {
        if let Ok(bytes) = keystore
            .get_secret(&device_id.to_string())
            .or_else(|_| keystore.get_secret(&format!("device:{device_id}")))
            .or_else(|_| keystore.get_secret("device_x25519_secret"))
        {
            if let Ok(json) = String::from_utf8(bytes) {
                if let Ok(keys) = parse_privkey_json(&json) {
                    return Ok(keys);
                }
            }
        }
    }

    let service = keyring_service(vault_path);
    let account = device_id.to_string();

    // 1. Try OS keyring first (skipped in tests: unsigned binaries trigger
    // interactive keychain prompts on macOS; see `keyring_disabled`).
    if !crate::keyring_disabled() {
        if let Ok(entry) = keyring::Entry::new(&service, &account) {
            if let Ok(json) = entry.get_password() {
                return parse_privkey_json(&json);
            }
        }
    }

    // 2. Fall back to the device-privkey file. Since the C1 fix the file
    // is an AES-256-GCM envelope sealed under a KEK-derived subkey;
    // legacy plaintext (phrase-flow writes, pre-seal vaults) is still
    // readable here and gets re-sealed lazily on the next successful
    // unlock.
    let privkey_path = vault_path.join("meta/device-privkey.json");
    if privkey_path.exists() {
        let json = crate::vault::device_privkey::read_privkey_file(&privkey_path, seal_key)?;
        let keys = parse_privkey_json(&json)?;

        // Migration attempt: store in keyring for future use
        // Keep the file as fallback -- don't delete it.
        // Keyring may not persist reliably in all environments (CI, headless).
        if !crate::keyring_disabled() {
            if let Ok(entry) = keyring::Entry::new(&service, &account) {
                let _ = entry.set_password(&json);
            }
        }

        return Ok(keys);
    }

    Err(VaultError::NotFound("device private key not found".into()).into())
}

/// Parse device private keys from JSON string.
fn parse_privkey_json(json: &str) -> Result<DevicePrivKeys, BaluardError> {
    let data: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| VaultError::Corrupt(format!("privkey json: {e}")))?;

    let x_bytes = hex::decode(data["x25519_private"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("x25519 hex: {e}")))?;
    let x_arr: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| VaultError::Corrupt("invalid x25519 key length".into()))?;

    let ed_bytes = hex::decode(data["ed25519_private"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("ed25519 hex: {e}")))?;
    let ed_arr: [u8; 32] = ed_bytes
        .try_into()
        .map_err(|_| VaultError::Corrupt("invalid ed25519 key length".into()))?;

    Ok(DevicePrivKeys {
        x25519: x25519_dalek::StaticSecret::from(x_arr),
        ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_arr),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KdfProfile;
    use crate::vault::creation;

    fn create_test_vault() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let password = "test-password-unlock-flow";

        let (handle, _secrets) = creation::VaultCreator::new(dir.path(), password, "test-device")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .execute()
            .unwrap();
        drop(handle); // Release locks so tests can re-open

        (dir, password.to_string())
    }

    #[test]
    fn open_and_unlock_roundtrip() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(!handle.is_unlocked());

        handle.unlock(&password).unwrap();
        assert!(handle.is_unlocked());

        handle.lock();
        assert!(!handle.is_unlocked());
    }

    #[test]
    fn wrong_password_fails() {
        let (dir, _password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(handle.unlock("wrong-password").is_err());
    }

    #[test]
    fn unlock_with_kek_roundtrip() {
        // unlock_with_kek must produce the same unlocked state as the
        // full master-password unlock (same KEK -> same root/session keys).
        // This is the contract the session-PIN path relies on.
        let (dir, password) = create_test_vault();

        // Derive the KEK the same way the daemon does for PIN escrow.
        let probe = VaultHandle::open(dir.path()).unwrap();
        let kek = crate::crypto::kdf::derive_kek(&password, &probe.kdf_params).unwrap();

        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(!handle.is_unlocked());
        handle.unlock_with_kek(&kek).expect("correct KEK unlocks");
        assert!(handle.is_unlocked(), "unlock_with_kek sets Unlocked state");
    }

    #[test]
    fn unlock_with_kek_wrong_kek_fails() {
        // A wrong KEK must fail closed (canary mismatch) without panicking.
        // The PIN path's rate limiter handles attempt accounting.
        let (dir, _password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        let wrong_kek = [0u8; 32];
        assert!(handle.unlock_with_kek(&wrong_kek).is_err());
        assert!(!handle.is_unlocked());
    }

    #[test]
    fn add_and_decrypt_cipher() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@example.com".into()),
                password: Some("s3cret!".into()),
                uris: vec![crate::types::LoginUri::new("https://github.com".into())],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let cipher_id = handle.add_cipher(&input).unwrap();

        // Re-open and unlock to verify persistence
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password).unwrap();

        let result = handle2.get_cipher(cipher_id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.username.as_deref(), Some("user@example.com"));
                        assert_eq!(data.password.as_deref(), Some("s3cret!"));
                    }
                    _ => panic!("expected Login kind"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted cipher"),
        }
    }

    #[test]
    fn locked_vault_returns_metadata_only() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Test".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("pw".into()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                fido2_credentials: None,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let cipher_id = handle.add_cipher(&input).unwrap();
        handle.lock();

        let result = handle.get_cipher(cipher_id).unwrap();
        match result {
            CipherRead::Locked(info) => {
                assert_eq!(info.id, cipher_id);
                assert_eq!(info.key_epoch, 1);
            }
            CipherRead::Decrypted(_) => panic!("expected locked metadata"),
        }
    }

    #[test]
    fn trash_soft_delete_restore_purge() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Delete Me".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("val".into()),
                uris: vec![],
                totp_uri: None,
                fido2_credentials: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let id = handle.add_cipher(&input).unwrap();
        assert!(handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().is_empty());

        // Delete moves it to trash
        handle.delete_cipher(id).unwrap();
        assert!(!handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().contains(&id));

        // Restore moves it back
        handle.restore_cipher(id).unwrap();
        assert!(handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().is_empty());

        // Delete to trash again
        handle.delete_cipher(id).unwrap();
        assert!(handle.list_trash_ids().unwrap().contains(&id));

        // Purge (0 days removes it immediately)
        let count = handle.purge_old_trash(0).unwrap();
        assert_eq!(count, 1);
        assert!(handle.list_trash_ids().unwrap().is_empty());
    }

    #[test]
    fn list_cipher_meta_returns_type_and_favorite() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Add a login
        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("s3cret".into()),
                uris: vec![],
                fido2_credentials: None,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.add_cipher(&input).unwrap();

        // Add a card
        let card_input = CipherInput {
            name: "Visa".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Card(crate::types::CardData {
                brand: Some("Visa".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.add_cipher(&card_input).unwrap();

        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 2);

        let login_meta = metas.iter().find(|m| m.name == "GitHub").unwrap();
        assert_eq!(login_meta.cipher_type, crate::types::CipherType::Login);
        assert!(login_meta.favorite);
        assert_eq!(login_meta.username.as_deref(), Some("user@gh.com"));

        let card_meta = metas.iter().find(|m| m.name == "Visa").unwrap();
        assert_eq!(card_meta.cipher_type, crate::types::CipherType::Card);
        assert!(!card_meta.favorite);
        assert!(card_meta.username.is_none());
    }

    #[test]
    fn update_cipher_changes_name() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Old Name".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        let updated = CipherInput {
            name: "New Name".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(id, &updated).unwrap();

        // Re-read to verify
        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "New Name");
                assert!(c.favorite);
                assert_eq!(c.update_seq, 2);
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn password_change_appends_history() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("old-pass-1".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password 3 times
        for pw in ["old-pass-2", "old-pass-3", "new-pass"] {
            let updated = CipherInput {
                name: "GitHub".into(),
                folder_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData {
                    username: Some("user@gh.com".into()),
                    password: Some(pw.into()),
                    ..Default::default()
                }),
                favorite: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                tags: vec![],
                reprompt: false,
            };
            handle.update_cipher(id, &updated).unwrap();
        }

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 3);
                assert_eq!(c.password_history[0].password, "old-pass-1");
                assert_eq!(c.password_history[1].password, "old-pass-2");
                assert_eq!(c.password_history[2].password, "old-pass-3");
                // Ascending timestamps
                assert!(
                    c.password_history[0].last_used_date <= c.password_history[1].last_used_date
                );
                assert!(
                    c.password_history[1].last_used_date <= c.password_history[2].last_used_date
                );
                // Current password is the new one
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.password.as_deref(), Some("new-pass"));
                        // password_revision_date must be set after change
                        assert!(data.password_revision_date.is_some());
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn clone_has_empty_history_and_different_id() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Create entry with some password history
        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass1".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: Some("notes".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password to create history
        let updated = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass2".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: Some("notes".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(id, &updated).unwrap();

        // Clone
        let cloned_id = handle.clone_cipher(id).unwrap();
        assert_ne!(cloned_id, id, "clone must have different UUID");

        // Verify clone
        let result = handle.get_cipher(cloned_id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                assert!(c.favorite);
                assert!(
                    c.password_history.is_empty(),
                    "clone must have empty history"
                );
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.password.as_deref(), Some("pass2"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify original still has history
        let original = handle.get_cipher(id).unwrap();
        match original {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 1);
                assert_eq!(c.password_history[0].password, "pass1");
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn password_history_capped_at_ten() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Test".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                password: Some("pw0".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password 15 times
        for i in 1..=15 {
            let updated = CipherInput {
                name: "Test".into(),
                folder_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData {
                    password: Some(format!("pw{i}")),
                    ..Default::default()
                }),
                favorite: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                tags: vec![],
                reprompt: false,
            };
            handle.update_cipher(id, &updated).unwrap();
        }

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 10, "history must be capped at 10");
                // Oldest entries evicted: should have pw5..pw14 (10 most recent)
                assert_eq!(c.password_history[0].password, "pw5");
                assert_eq!(c.password_history[9].password, "pw14");
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn folder_create_list_rename_delete() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Initially empty
        let folders = handle.list_folders().unwrap();
        assert!(folders.is_empty());

        // Create
        let id1 = handle.create_folder("Work").unwrap();
        let id2 = handle.create_folder("Personal").unwrap();
        assert_ne!(id1, id2);

        // List
        let folders = handle.list_folders().unwrap();
        assert_eq!(folders.len(), 2);
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Work"));
        assert!(names.contains(&"Personal"));

        // Rename
        handle.rename_folder(id1, "Work - Renamed").unwrap();
        let folders = handle.list_folders().unwrap();
        let renamed = folders.iter().find(|f| f.id == id1).unwrap();
        assert_eq!(renamed.name, "Work - Renamed");

        // Delete
        handle.delete_folder(id2).unwrap();
        let folders = handle.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, id1);

        // Delete non-existent
        let result = handle.delete_folder(id2);
        assert!(result.is_err());
    }

    #[test]
    fn folder_delete_unassigns_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let folder_id = handle.create_folder("Social").unwrap();

        // Add cipher assigned to folder
        let input = CipherInput {
            name: "Twitter".into(),
            folder_id: Some(folder_id),
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Verify folder assignment
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => assert_eq!(c.folder_id, Some(folder_id)),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Delete folder
        handle.delete_folder(folder_id).unwrap();

        // Verify cipher is now unassigned
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => {
                assert_eq!(
                    c.folder_id, None,
                    "cipher should be unassigned after folder delete"
                );
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn folder_move_cipher_between_folders() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let folder_a = handle.create_folder("A").unwrap();
        let folder_b = handle.create_folder("B").unwrap();

        // Add cipher to folder A
        let input = CipherInput {
            name: "Test".into(),
            folder_id: Some(folder_a),
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Move to folder B via update_cipher
        let updated = CipherInput {
            name: "Test".into(),
            folder_id: Some(folder_b),
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(cipher_id, &updated).unwrap();

        // Verify
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.folder_id, Some(folder_b));
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    // MISS-1: rotate_root_key re-encrypts all ciphers
    #[test]
    fn rotate_root_key_re_encrypts_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Add some ciphers
        let input1 = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("secret123".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input1).unwrap();

        let input2 = CipherInput {
            name: "AWS".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("admin".into()),
                password: Some("aws-key".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id2 = handle.add_cipher(&input2).unwrap();

        // Capture old epoch
        let old_epoch = handle.unlocked().current_epoch;

        // Rotate root key
        handle.rotate_root_key().unwrap();

        // Verify epoch incremented
        let new_epoch = handle.unlocked().current_epoch;
        assert_eq!(new_epoch, old_epoch + 1);

        // Verify both ciphers still decrypt correctly
        match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                assert!(c.favorite);
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.username.as_deref(), Some("user@gh.com"));
                        assert_eq!(d.password.as_deref(), Some("secret123"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "AWS");
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.password.as_deref(), Some("aws-key"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify persistence: re-open vault and verify decryption still works
        let password2 = password.clone();
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password2).unwrap();
        assert_eq!(handle2.unlocked().current_epoch, new_epoch);

        match handle2.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "GitHub"),
            CipherRead::Locked(_) => panic!("expected decrypted after re-open"),
        }
    }

    #[test]
    fn test_index_fast_lookup_and_auto_heal() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // 1. Initial empty index is created on unlock/load/add
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 0);

        // Verify index.enc exists
        let index_path = handle.path.join("meta/index.enc");
        assert!(index_path.exists());

        // 2. Add some ciphers - should automatically update index
        let _id1 = handle
            .add_cipher(&CipherInput {
                name: "GH1".into(),
                ..Default::default()
            })
            .unwrap();

        let _id2 = handle
            .add_cipher(&CipherInput {
                name: "AWS1".into(),
                ..Default::default()
            })
            .unwrap();

        // List metadata - should read from index.enc
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 2);
        assert!(metas.iter().any(|m| m.name == "GH1"));
        assert!(metas.iter().any(|m| m.name == "AWS1"));

        // 3. Test Auto-Heal: corrupt the index.enc by writing junk bytes to it
        std::fs::write(&index_path, b"corrupted-junk-bytes").unwrap();

        // List metadata should trigger decryption failure on index, then auto-heal,
        // scan ciphers folder, rebuild index, and return valid metadata
        let metas_healed = handle.list_cipher_meta().unwrap();
        assert_eq!(metas_healed.len(), 2);
        assert!(metas_healed.iter().any(|m| m.name == "GH1"));
        assert!(metas_healed.iter().any(|m| m.name == "AWS1"));

        // Verify that index.enc was automatically rewritten and is now healthy again
        let envelope_bytes = std::fs::read(&index_path).unwrap();
        let unlocked = handle.unlocked();
        let index_key =
            crate::crypto::hkdf_derive::derive_index_key(unlocked.root_key.as_bytes()).unwrap();
        let decoded = index::decrypt_index(handle.vault_id, &envelope_bytes, &index_key).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn archive_unarchive_roundtrip() {
        let (dir, password) = create_test_vault();
        let path = dir.path();
        let mut handle = VaultHandle::open(path).unwrap();
        handle.unlock(&password).unwrap();

        // Add a cipher
        let input = CipherInput {
            name: "ArchiveMe".into(),
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("arch@example.com".into()),
                password: Some("s3cret".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Verify it appears in list
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].id, cipher_id);
        assert!(!metas[0].archived);

        // Archive it
        handle.archive_cipher(cipher_id).unwrap();

        // Should NOT appear in normal list
        let metas = handle.list_cipher_meta().unwrap();
        assert!(
            metas.is_empty(),
            "archived cipher should not appear in list"
        );

        // Should appear in archived list
        let archived = handle.list_archived_meta().unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].id, cipher_id);
        assert!(archived[0].archived);

        // Verify cipher data still intact
        let cipher = match handle.get_cipher(cipher_id).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(cipher.name, "ArchiveMe");
        assert!(cipher.archived);

        // Unarchive
        handle.unarchive_cipher(cipher_id).unwrap();

        // Should reappear in normal list
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
        assert!(!metas[0].archived);

        // Archived list should be empty
        let archived = handle.list_archived_meta().unwrap();
        assert!(archived.is_empty());
    }

    #[test]
    fn archive_idempotent() {
        let (dir, password) = create_test_vault();
        let path = dir.path();
        let mut handle = VaultHandle::open(path).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "DoubleArchive".into(),
            ..Default::default()
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Archive twice should not error
        handle.archive_cipher(cipher_id).unwrap();
        handle.archive_cipher(cipher_id).unwrap();

        let archived = handle.list_archived_meta().unwrap();
        assert_eq!(archived.len(), 1);

        // Unarchive twice should not error
        handle.unarchive_cipher(cipher_id).unwrap();
        handle.unarchive_cipher(cipher_id).unwrap();

        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
    }

    #[test]
    fn revoke_device_and_rekey_re_encrypts_and_persists() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Enroll a second device directly in the registry
        let dev2_id = uuid::Uuid::new_v4();
        let dev2_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev2_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev2_x_pub = x25519_dalek::PublicKey::from(&dev2_x);

        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev2_id,
                "device-2".into(),
                dev2_x_pub.to_bytes(),
                dev2_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();

        // Write keywrap for dev2
        let unlocked = handle.unlocked();
        let (eph, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(unlocked.root_key.as_bytes(), &dev2_x_pub).unwrap();
        let _ = unlocked;
        let kw = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.path().join(format!("meta/keywrap/{dev2_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        // Add a cipher
        let input = CipherInput {
            name: "Secret".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass123".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: Some("sensitive note".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input).unwrap();

        let old_epoch = handle.unlocked().current_epoch;

        // Revoke dev2
        let result = handle.revoke_device_and_rekey(dev2_id).unwrap();
        assert_eq!(result.revoked_device_id, dev2_id);
        assert_eq!(result.revoked_name, "device-2");
        assert_ne!(result.new_epoch, old_epoch);
        assert!(result.new_root_key.is_none()); // zeroized after use

        // Epoch changed in memory
        assert_ne!(handle.unlocked().current_epoch, old_epoch);

        // Dev2's keywrap removed, self keywrap present
        assert!(
            !dir.path()
                .join(format!("meta/keywrap/{dev2_id}.json"))
                .exists()
        );
        assert!(
            dir.path()
                .join(format!("meta/keywrap/{}.json", handle.device_id))
                .exists()
        );

        // No rotation-pending marker left
        assert!(!dir.path().join("meta/.rotation-pending").exists());

        // Cipher still decrypts correctly after re-encryption
        match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "Secret");
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.password.as_deref(), Some("pass123"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Re-open vault and verify persistence with new keywrap
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password).unwrap();
        assert_eq!(handle2.unlocked().current_epoch, result.new_epoch);
        match handle2.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Secret"),
            CipherRead::Locked(_) => panic!("expected decrypted after re-open"),
        }
    }

    #[test]
    fn revoke_device_cannot_revoke_self() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let self_id = handle.device_id;
        let result = handle.revoke_device_and_rekey(self_id);
        assert!(result.is_err());
        match result {
            Err(BaluardError::Vault(VaultError::InvalidOperation(msg))) => {
                assert!(msg.contains("cannot revoke the current device"));
            }
            _other => panic!("expected InvalidOperation"),
        }
    }

    #[test]
    fn revoke_device_re_encrypts_attachments_and_trash() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Enroll a second device
        let dev2_id = uuid::Uuid::new_v4();
        let dev2_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev2_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev2_x_pub = x25519_dalek::PublicKey::from(&dev2_x);
        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev2_id,
                "device-2".into(),
                dev2_x_pub.to_bytes(),
                dev2_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();

        // Write keywrap for dev2
        let unlocked = handle.unlocked();
        let (eph, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(unlocked.root_key.as_bytes(), &dev2_x_pub).unwrap();
        let _ = unlocked;
        let kw = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.path().join(format!("meta/keywrap/{dev2_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        // Add a cipher with an attachment
        let attach_id = uuid::Uuid::new_v4();
        let input = CipherInput {
            name: "WithAttachment".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![crate::vault::attachment::AttachmentMeta {
                id: attach_id.to_string(),
                filename: "secret.txt".into(),
                size: 12,
                encrypted_size: 0, // informational only (C4: blobs are tier-padded)
                mime_type: "text/plain".into(),
                created_at: 1000,
            }],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input).unwrap();

        // Write the encrypted attachment file
        let attach_dir = dir
            .path()
            .join("entries")
            .join(id1.to_string())
            .join("attachments");
        std::fs::create_dir_all(&attach_dir).unwrap();
        let item_key_epoch = handle.unlocked().current_epoch;
        let item_key = handle.derive_item_key(id1, item_key_epoch);
        let enc_blob = crate::vault::attachment::encrypt_attachment(
            handle.vault_id,
            id1,
            attach_id,
            item_key.as_bytes(),
            b"hello world",
            item_key_epoch,
            1,
        )
        .unwrap();
        std::fs::write(attach_dir.join(format!("{attach_id}.enc")), &enc_blob).unwrap();

        // Add a cipher, then move it to trash
        let trash_input = CipherInput {
            name: "Trashed".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("trash".into()),
                password: Some("trashed-pass".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id2 = handle.add_cipher(&trash_input).unwrap();
        handle.delete_cipher(id2).unwrap(); // moves to trash

        // Revoke dev2
        let result = handle.revoke_device_and_rekey(dev2_id).unwrap();
        assert_eq!(result.revoked_device_id, dev2_id);

        // Verify attachment was re-encrypted (file still exists and is readable)
        let attach_path = attach_dir.join(format!("{attach_id}.enc"));
        assert!(
            attach_path.exists(),
            "attachment file should exist after rekey"
        );
        let new_enc_blob = std::fs::read(&attach_path).unwrap();
        let new_item_key = handle.derive_item_key(id1, handle.unlocked().current_epoch);
        let decrypted = crate::vault::attachment::decrypt_attachment(
            handle.vault_id,
            id1,
            attach_id,
            new_item_key.as_bytes(),
            &new_enc_blob,
        )
        .unwrap();
        assert_eq!(decrypted, b"hello world");

        // Verify trashed cipher still decrypts
        match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Trashed"),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify no .tmp files remain anywhere
        fn check_no_tmp(dir: &Path) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        check_no_tmp(&p);
                    } else {
                        assert!(
                            p.extension().is_none_or(|e| e != "tmp"),
                            "leftover .tmp file: {}",
                            p.display()
                        );
                    }
                }
            }
        }
        check_no_tmp(dir.path());
    }

    // ── Tag tests ──

    #[test]
    fn tag_validation_rejects_empty() {
        assert!(VaultHandle::validate_tag("").is_err());
        assert!(VaultHandle::validate_tag("   ").is_err());
        assert!(VaultHandle::validate_tag("\t\n").is_err());
        assert!(VaultHandle::validate_tag("valid").is_ok());
    }

    #[test]
    fn tag_validation_max_length() {
        let long_tag = "a".repeat(65);
        assert!(VaultHandle::validate_tag(&long_tag).is_err());
        let exact_tag = "a".repeat(64);
        assert!(VaultHandle::validate_tag(&exact_tag).is_ok());
    }

    #[test]
    fn tag_validation_normalizes_case() {
        let result = VaultHandle::validate_tag("Work").unwrap();
        assert_eq!(result, "work");
    }

    #[test]
    fn create_cipher_with_tags() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Tagged".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["work".into(), "email".into()],
        };
        let id = handle.add_cipher(&input).unwrap();

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.tags, vec!["work".to_string(), "email".to_string()]);
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn rebuild_tag_index() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Create ciphers with various tags
        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["work".into(), "email".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["personal".into(), "email".into()],
        };
        handle.add_cipher(&input1).unwrap();
        handle.add_cipher(&input2).unwrap();

        handle.rebuild_tag_index().unwrap();
        let tags = handle.list_tags().unwrap();
        assert_eq!(
            tags,
            vec![
                "email".to_string(),
                "personal".to_string(),
                "work".to_string()
            ]
        );
    }

    #[test]
    fn create_tag_to_index() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        handle.create_tag("Work").unwrap();
        let tags = handle.list_tags().unwrap();
        assert_eq!(tags, vec!["work".to_string()]);

        // Idempotent
        handle.create_tag("WORK").unwrap();
        let tags2 = handle.list_tags().unwrap();
        assert_eq!(tags2, vec!["work".to_string()]);
    }

    #[test]
    fn rename_tag_updates_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["old-tag".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["old-tag".into(), "keep".into()],
        };
        let id1 = handle.add_cipher(&input1).unwrap();
        let id2 = handle.add_cipher(&input2).unwrap();

        let count = handle.rename_tag("old-tag", "new-tag").unwrap();
        assert_eq!(count, 2);

        // Verify cipher 1
        let c1 = match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c1.tags, vec!["new-tag".to_string()]);

        // Verify cipher 2
        let c2 = match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert!(c2.tags.contains(&"new-tag".to_string()));
        assert!(c2.tags.contains(&"keep".to_string()));

        // Index updated
        let tags = handle.list_tags().unwrap();
        assert!(!tags.contains(&"old-tag".to_string()));
        assert!(tags.contains(&"new-tag".to_string()));
    }

    #[test]
    fn delete_tag_removes_from_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["delete-me".into(), "keep".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["keep".into()],
        };
        let id1 = handle.add_cipher(&input1).unwrap();
        let id2 = handle.add_cipher(&input2).unwrap();

        let count = handle.delete_tag("delete-me").unwrap();
        assert_eq!(count, 1);

        // Verify cipher 1 no longer has delete-me
        let c1 = match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c1.tags, vec!["keep".to_string()]);

        // Verify cipher 2 untouched
        let c2 = match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c2.tags, vec!["keep".to_string()]);

        // Index updated
        let tags = handle.list_tags().unwrap();
        assert!(!tags.contains(&"delete-me".to_string()));
        assert!(tags.contains(&"keep".to_string()));
    }

    /// Regression for the settings split (2026-06-26): display prefs (theme,
    /// lang) must live in plaintext settings-pub.json; the rest must be
    /// encrypted under the root key in settings.enc. slug confirmed to have no
    /// pre-unlock consumer, so it lives in the encrypted half.
    #[test]
    fn settings_split_roundtrip_and_encryption() {
        let (dir, password) = create_test_vault();

        // Open + unlock, save settings across both halves.
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let settings = crate::vault::manifest::VaultSettings {
            vault_timeout: crate::vault::manifest::VaultTimeout::Minutes(15),
            theme: Some(crate::types::ThemeMode::Dark),
            lang: Some("es".into()),
            default_uri_match: Some(crate::types::UriMatchStrategy::Exact),
            fetch_favicons: Some(false),
            slug: Some("leaky-slug".into()),
            display_name: None,
            subtitle: None,
            avatar_ext: None,
            custom_equivalent_domains: None,
            suggest_app_logins: None,
            trusted_app_packages: None,
            rejected_app_packages: None,
            enrollment_policy: crate::vault::manifest::EnrollmentPolicy::Personal,
        };
        handle.save_settings(&settings).unwrap();

        // Public file is plaintext and contains only theme + lang.
        let pub_str = std::fs::read_to_string(dir.path().join("meta/settings-pub.json")).unwrap();
        assert!(
            pub_str.contains("\"theme\""),
            "public file must contain theme"
        );
        assert!(
            pub_str.contains("\"lang\""),
            "public file must contain lang"
        );
        assert!(
            !pub_str.contains("slug"),
            "slug must NOT be in plaintext public file"
        );
        assert!(!pub_str.contains("enrollment_policy"));
        assert!(!pub_str.contains("fetch_favicons"));

        // Encrypted file is NOT plaintext JSON of those fields.
        let enc_bytes = std::fs::read(dir.path().join("meta/settings.enc")).unwrap();
        let enc_str = String::from_utf8_lossy(&enc_bytes);
        assert!(
            !enc_str.contains("leaky-slug"),
            "slug must be encrypted, not plaintext"
        );
        assert!(!enc_str.contains("enrollment_policy"));

        // Legacy settings.json must be removed after migration.
        assert!(!dir.path().join("meta/settings.json").exists());

        // Re-open and read back: all fields round-trip.
        let read_back = handle.get_settings().unwrap();
        assert_eq!(read_back.theme, Some(crate::types::ThemeMode::Dark));
        assert_eq!(read_back.lang.as_deref(), Some("es"));
        assert_eq!(read_back.slug.as_deref(), Some("leaky-slug"));
        assert_eq!(read_back.fetch_favicons, Some(false));
        assert_eq!(
            read_back.enrollment_policy,
            crate::vault::manifest::EnrollmentPolicy::Personal
        );
    }

    /// Regression: a vault with a legacy plaintext settings.json must migrate
    /// transparently on first get_settings (post-unlock). Nothing lost.
    #[test]
    fn settings_legacy_json_migrates_on_read() {
        let (dir, password) = create_test_vault();

        // Write a legacy plaintext settings.json with mixed fields.
        let legacy = serde_json::json!({
            "vault_timeout": "OnRestart",
            "theme": "dark",
            "lang": "es",
            "default_uri_match": "exact",
            "fetch_favicons": false,
            "slug": "legacy-vault",
            "enrollment_policy": "Strict",
        });
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(
            dir.path().join("meta/settings.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Read picks up the legacy values via the fallback path.
        let s = handle.get_settings().unwrap();
        assert_eq!(s.slug.as_deref(), Some("legacy-vault"));
        assert_eq!(s.lang.as_deref(), Some("es"));
        assert_eq!(s.fetch_favicons, Some(false));

        // A save migrates: writes the split files and drops settings.json.
        handle.save_settings(&s).unwrap();
        assert!(dir.path().join("meta/settings-pub.json").exists());
        assert!(dir.path().join("meta/settings.enc").exists());
        assert!(!dir.path().join("meta/settings.json").exists());
    }

    /// Regression: a keystore-less vault with multiple devices and a sealed
    /// device-privkey file must open in locked state and resolve the local device_id.
    #[test]
    fn multi_device_locked_open_with_sealed_devkey_and_no_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let password = "test-password-123!";

        // 1. Create vault (device 1)
        let (_h, secrets) = creation::VaultCreator::new(path, password, "Desktop")
            .kdf_profile(crate::types::KdfProfile::MobileLow)
            .execute()
            .unwrap();

        // 2. Enroll device 2 with recovery phrase
        let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (ed25519_signing, ed25519_verifying) =
            crate::crypto::signature::generate_ed25519_keypair();
        let dev2_id = Uuid::new_v4();
        let payload = crate::device_manager::EnrollmentPayload {
            device_id: dev2_id,
            encryption_public_key: hex::encode(x25519_public.to_bytes()),
            signing_public_key: hex::encode(crate::crypto::signature::verifying_key_bytes(
                &ed25519_verifying,
            )),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            nonce: hex::encode([1u8; 32]),
            name: "Mobile".into(),
            vault_id: None,
            epoch: None,
            registry_version: None,
        };

        let mut dm = DeviceManager::load_from_vault(path).unwrap();
        let res = dm
            .enroll_with_recovery_phrase(
                &payload,
                &secrets.recovery_phrase.phrase(),
                x25519_secret,
                ed25519_signing,
                crate::vault::manifest::EnrollmentPolicy::Personal,
            )
            .unwrap();

        // Write device 2's device-privkey.json as sealed file with device 2's keys
        let kek =
            crate::crypto::kdf::derive_kek(password, &VaultHandle::open(path).unwrap().kdf_params)
                .unwrap();
        let devkey_seal = crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek).unwrap();
        let privkey_json = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "x25519_private": hex::encode(res.x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(res.ed25519_signing.to_bytes()),
        });
        crate::vault::device_privkey::seal_file(
            &path.join("meta/device-privkey.json"),
            &privkey_json.to_string(),
            &devkey_seal,
            Some(dev2_id),
        )
        .unwrap();

        // Verify meta/keywrap has 2 files
        let kw_count = std::fs::read_dir(path.join("meta/keywrap"))
            .unwrap()
            .count();
        assert_eq!(kw_count, 2);

        // Verify file is sealed
        assert_eq!(
            crate::vault::device_privkey::file_kind(&path.join("meta/device-privkey.json")),
            crate::vault::device_privkey::PrivkeyFileKind::Sealed
        );

        // 3. Open locked vault — must find device 2 without password or keyring
        let mut handle = VaultHandle::open(path).unwrap();
        assert_eq!(handle.device_id, dev2_id);

        // 4. Unlock vault
        handle.unlock(password).unwrap();
        assert!(handle.is_unlocked());

        // 5. Test F1 self-healing: spoof meta/device-id with device 1's ID
        handle.lock();
        let dev1_id = secrets.device_id;
        crate::vault::device_privkey::write_device_id(path, dev1_id).unwrap();

        // Re-open: fast path selects dev1_id initially
        let mut handle2 = VaultHandle::open(path).unwrap();
        assert_eq!(handle2.device_id, dev1_id);

        // Unlock should heal and succeed by falling back to dev2_id
        handle2.unlock(password).unwrap();
        assert!(handle2.is_unlocked());
        assert_eq!(handle2.device_id, dev2_id);

        // Verify meta/device-id was corrected
        assert_eq!(
            crate::vault::device_privkey::read_device_id(path),
            Some(dev2_id)
        );
    }
}
