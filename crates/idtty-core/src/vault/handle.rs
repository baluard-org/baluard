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
use crate::devices::DeviceRegistry;
use crate::error::{IdttyError, VaultError};
use crate::keys::hierarchy::{ItemKey, RootKey};
use crate::types::{Cipher, CipherInput, KdfParams, Tier};
use crate::vault::cipher;

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
    pub registry: DeviceRegistry,
    /// Current device ID.
    pub device_id: Uuid,
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
    /// Session Key (for local cache encryption).
    pub session_key: [u8; 32],
    /// Sync-Only Key (for locked background sync).
    pub sync_key: [u8; 32],
    /// Cached Item Keys: cipher_id → ItemKey.
    /// Loaded on-demand, cached for performance.
    pub item_keys: HashMap<Uuid, ItemKey>,
    /// Current key epoch (read from RK canary or envelope).
    pub current_epoch: u64,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.sync_key.zeroize();
    }
}

impl VaultHandle {
    /// Open a vault from disk (locked state).
    /// Reads metadata files but does NOT decrypt anything.
    pub fn open(path: &Path) -> Result<Self, IdttyError> {
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

        // Derive vault_id from KDF salt (stable, unique per vault)
        // TODO: store vault_id explicitly in a meta file during creation
        let vault_id = Self::derive_vault_id(&kdf_params);

        Ok(VaultHandle {
            path: path.to_path_buf(),
            vault_id,
            kdf_params,
            registry,
            device_id,
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
    pub fn unlock(&mut self, master_password: &str) -> Result<(), IdttyError> {
        // Step 0: Rate limit check
        self.check_attempt_rate_limit()?;

        // Step 1: Derive KEK
        let kek = kdf::derive_kek(master_password, &self.kdf_params)?;

        // Step 2: Derive session + sync keys
        let session_key = hkdf_derive::derive_session_key(&kek)?;
        let sync_key = hkdf_derive::derive_sync_key(&kek)?;

        // Step 3: Read keywrap file
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        if !keywrap_path.exists() {
            return Err(VaultError::NotFound(format!(
                "keywrap file for device {}",
                self.device_id
            ))
            .into());
        }

        let keywrap_json = std::fs::read_to_string(&keywrap_path)
            .map_err(|e| VaultError::Metadata(format!("reading keywrap: {e}")))?;
        let keywrap: serde_json::Value = serde_json::from_str(&keywrap_json)
            .map_err(|e| VaultError::Corrupt(format!("keywrap json: {e}")))?;

        let eph_pub = hex::decode(keywrap["ephemeral_public"].as_str().unwrap_or(""))
            .map_err(|e| VaultError::Corrupt(format!("ephemeral_public hex: {e}")))?;
        if eph_pub.len() != 32 {
            return Err(VaultError::Corrupt(format!(
                "ephemeral_public: expected 32 bytes, got {}",
                eph_pub.len()
            ))
            .into());
        }
        let ct = hex::decode(keywrap["encrypted_key"].as_str().unwrap_or(""))
            .map_err(|e| VaultError::Corrupt(format!("encrypted_key hex: {e}")))?;
        if ct.len() < 32 {
            return Err(VaultError::Corrupt(format!(
                "encrypted_key: too short ({} bytes)",
                ct.len()
            ))
            .into());
        }
        let tag_hex = keywrap["tag"].as_str().unwrap_or("");
        let mut tag = [0u8; 16];
        let tag_bytes =
            hex::decode(tag_hex).map_err(|e| VaultError::Corrupt(format!("tag hex: {e}")))?;
        if tag_bytes.len() != 16 {
            return Err(VaultError::Corrupt("invalid tag length".into()).into());
        }
        tag.copy_from_slice(&tag_bytes);

        // Step 4: Verify KEK is correct by decrypting the KEK canary
        // Canary plaintext MUST equal b"idtty-kek-ok" — this catches wrong passwords
        // even when AES-GCM doesn't fail (cosmically unlikely but defense-in-depth).
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_data = std::fs::read(self.path.join("meta/kek-canary.enc"))
                .map_err(|e| VaultError::Metadata(format!("reading kek canary: {e}")))?;
            let canary_envelope = crate::vault::envelope::deserialize(&canary_data)?;
            let canary_pt =
                crate::crypto::aead::decrypt(&session_key, &canary_envelope).map_err(|_| {
                    let _ = self.record_failed_attempt();
                    VaultError::Corrupt("master password incorrect".into())
                })?;
            if canary_pt != b"idtty-kek-ok" {
                let _ = self.record_failed_attempt();
                return Err(VaultError::Corrupt(
                    "master password incorrect (KEK canary plaintext mismatch)".into(),
                )
                .into());
            }
        }

        // Step 5: HPKE-decapsulate Root Key
        // CLI mode: stored in meta/device-privkey.json (NOT for production!)
        let privkey_path = self.path.join("meta/device-privkey.json");
        let root_key = if privkey_path.exists() {
            let pk_json = std::fs::read_to_string(&privkey_path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            let pk_data: serde_json::Value = serde_json::from_str(&pk_json)
                .map_err(|e| VaultError::Corrupt(format!("privkey json: {e}")))?;
            let priv_bytes = hex::decode(pk_data["x25519_private"].as_str().unwrap_or(""))
                .map_err(|e| VaultError::Corrupt(format!("privkey hex: {e}")))?;
            let priv_arr: [u8; 32] = priv_bytes
                .try_into()
                .map_err(|_| VaultError::Corrupt("invalid private key length".into()))?;
            let priv_key = x25519_dalek::StaticSecret::from(priv_arr);

            let unwrapped = hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, &priv_key)?;
            let rk_bytes: [u8; 64] = unwrapped
                .try_into()
                .map_err(|_| VaultError::Corrupt("unwrapped root key not 64 bytes".into()))?;
            RootKey::from_bytes(rk_bytes)
        } else {
            return Err(VaultError::NotFound(
                "device private key not found (CLI mode requires meta/device-privkey.json)".into(),
            )
            .into());
        };

        // Step 6: Verify root key with RK canary
        if let Err(e) = self.verify_root_key(&root_key) {
            self.record_failed_attempt()?;
            return Err(e);
        }

        // Step 7: Clear attempt counter on success
        self.clear_failed_attempts()?;

        // Step 8: Determine current epoch from any existing cipher or RK canary
        let current_epoch = self.determine_current_epoch();

        self.state = VaultState::Unlocked(UnlockedState {
            root_key,
            session_key,
            sync_key,
            item_keys: HashMap::new(),
            current_epoch,
        });

        Ok(())
    }

    /// Lock the vault: zeroize all key material.
    pub fn lock(&mut self) {
        self.state = VaultState::Locked;
    }

    /// Check if vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked(_))
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

    /// Get vault settings (reads from disk).
    pub fn get_settings(&self) -> Result<crate::vault::manifest::VaultSettings, IdttyError> {
        let settings_path = self.path.join("meta/settings.json");
        if !settings_path.exists() {
            return Ok(crate::vault::manifest::VaultSettings {
                auto_lock_minutes: None,
                theme: None,
                default_uri_match: None,
            });
        }
        let data = std::fs::read_to_string(&settings_path)?;
        let settings: crate::vault::manifest::VaultSettings = serde_json::from_str(&data)
            .map_err(|e| crate::error::VaultError::Metadata(format!("settings parse: {e}")))?;
        Ok(settings)
    }

    /// Save vault settings to disk (atomic write).
    pub fn save_settings(
        &self,
        settings: &crate::vault::manifest::VaultSettings,
    ) -> Result<(), IdttyError> {
        let settings_path = self.path.join("meta/settings.json");
        let tmp_path = settings_path.with_extension("tmp");
        let json = serde_json::to_string_pretty(settings).map_err(|e| {
            crate::error::VaultError::Metadata(format!("settings serialization: {e}"))
        })?;
        std::fs::write(&tmp_path, &json)?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp_path, &settings_path)?;
        Ok(())
    }

    // ── Folder CRUD ──

    /// List all folders.
    pub fn list_folders(&self) -> Result<Vec<crate::vault::manifest::Folder>, IdttyError> {
        let folders_path = self.path.join("meta/folders.json");
        if !folders_path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&folders_path)?;
        let folders: Vec<crate::vault::manifest::Folder> = serde_json::from_str(&data)
            .map_err(|e| crate::error::VaultError::Metadata(format!("folders parse: {e}")))?;
        Ok(folders)
    }

    /// Save folders to disk (atomic write).
    fn save_folders(&self, folders: &[crate::vault::manifest::Folder]) -> Result<(), IdttyError> {
        let folders_path = self.path.join("meta/folders.json");
        let tmp_path = folders_path.with_extension("tmp");
        let json = serde_json::to_string_pretty(folders).map_err(|e| {
            crate::error::VaultError::Metadata(format!("folders serialization: {e}"))
        })?;
        std::fs::write(&tmp_path, &json)?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp_path, &folders_path)?;
        Ok(())
    }

    /// Create a new folder.
    pub fn create_folder(&mut self, name: &str) -> Result<Uuid, IdttyError> {
        self.create_folder_with_parent(name, None)
    }

    /// Maximum folder nesting depth.
    const MAX_FOLDER_DEPTH: usize = 16;

    /// Create a new folder with optional parent.
    pub fn create_folder_with_parent(
        &mut self,
        name: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, IdttyError> {
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
                    crate::error::VaultError::Metadata(format!("parent folder not found")).into(),
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
    pub fn rename_folder(&mut self, folder_id: Uuid, new_name: &str) -> Result<(), IdttyError> {
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
                IdttyError::from(crate::error::VaultError::NotFound(format!(
                    "folder {folder_id}"
                )))
            })?;
        folder.name = new_name.trim().to_string();
        self.save_folders(&folders)?;
        Ok(())
    }

    /// Delete a folder by ID. Cascades to child folders.
    /// All ciphers with this folder_id (or any child's) become unassigned.
    pub fn delete_folder(&mut self, folder_id: Uuid) -> Result<(), IdttyError> {
        // Collect this folder + all descendants
        let all_folders = self.list_folders()?;
        let ids_to_delete = collect_descendant_ids(folder_id, &all_folders);

        if !all_folders.iter().any(|f| f.id == folder_id) {
            return Err(IdttyError::from(crate::error::VaultError::NotFound(
                format!("folder {folder_id}"),
            )));
        }

        // Remove all collected folders
        let mut folders = all_folders;
        folders.retain(|f| !ids_to_delete.contains(&f.id));
        self.save_folders(&folders)?;

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
                .map_or(false, |fid| ids_to_delete.contains(&fid))
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
                };
                self.update_cipher(cipher_id, &input)?;
            }
        }

        // NOW remove folder from index (after all ciphers unassigned successfully)
        self.save_folders(&folders)?;

        Ok(())
    }

    /// List cipher IDs from filenames in ciphers/ directory.
    pub fn list_cipher_ids(&self) -> Result<Vec<Uuid>, IdttyError> {
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
    /// Decrypts each cipher to extract name, type, favorite, username.
    pub fn list_cipher_meta(&self) -> Result<Vec<crate::types::CipherMeta>, IdttyError> {
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
                Err(_) => continue, // skip undecryptable entries
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
            });
        }

        Ok(metas)
    }

    /// Verify root key by decrypting the Root Key canary.
    /// The canary is stored at vault creation as AES-256-GCM("idtty-rk-ok")
    /// encrypted with a key derived from Root Key.
    fn verify_root_key(&self, root_key: &RootKey) -> Result<(), IdttyError> {
        let canary_path = self.path.join("meta/rk-canary.enc");
        if !canary_path.exists() {
            // No canary (legacy vault). Fall back to first-cipher check.
            return self.verify_root_key_fallback(root_key);
        }

        // Derive a canary-specific key from Root Key
        let canary_key = Self::derive_root_key_canary_key(root_key);

        let canary_data = std::fs::read(&canary_path)
            .map_err(|e| VaultError::Metadata(format!("reading rk canary: {e}")))?;
        let canary_envelope = crate::vault::envelope::deserialize(&canary_data)?;
        let canary_pt = crate::crypto::aead::decrypt(&canary_key, &canary_envelope)
            .map_err(|_| VaultError::Corrupt("root key verification failed".into()))?;
        if canary_pt != b"idtty-rk-ok" {
            return Err(VaultError::Corrupt(
                "root key verification failed (plaintext mismatch)".into(),
            )
            .into());
        }
        Ok(())
    }

    /// Fallback: verify root key by decrypting the first existing cipher.
    /// Only used for legacy vaults without `meta/rk-canary.enc`.
    fn verify_root_key_fallback(&self, root_key: &RootKey) -> Result<(), IdttyError> {
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
    ) -> Result<Cipher, IdttyError> {
        let item_key = {
            let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
            Self::derive_item_key_static(root_key, file.id, envelope.header.key_epoch)
        };
        crate::vault::cipher::decrypt_cipher(self.vault_id, file.id, file, &item_key)
    }

    /// Derive a key specifically for the Root Key canary.
    /// Separate from Item Key derivation to maintain key separation.
    fn derive_root_key_canary_key(root_key: &RootKey) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"idtty-rk-canary-v1", &mut key)
            .expect("32 bytes is valid for HKDF-SHA256");
        key
    }

    /// Static version for borrow-friendly calls.
    fn derive_item_key_static(root_key: &RootKey, cipher_id: Uuid, epoch: u64) -> ItemKey {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut info = Vec::with_capacity(32 + 8 + 16);
        info.extend_from_slice(b"idtty-item-v1");
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(cipher_id.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .expect("32 bytes is valid output length for HKDF-SHA256");

        ItemKey::from_bytes(key)
    }

    /// Derive item key for a cipher (requires unlocked vault).
    pub fn derive_item_key(
        &self,
        cipher_id: Uuid,
        key_epoch: u64,
    ) -> crate::keys::hierarchy::ItemKey {
        let root_key = match &self.state {
            VaultState::Unlocked(u) => &u.root_key,
            VaultState::Locked => panic!("derive_item_key called on locked vault"),
        };
        Self::derive_item_key_static(root_key, cipher_id, key_epoch)
    }

    /// Get a cipher (decrypts if unlocked, returns metadata only if locked).
    /// Looks up in both active ciphers and trash.
    pub fn get_cipher(&self, cipher_id: Uuid) -> Result<CipherRead, IdttyError> {
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
                let item_key = Self::derive_item_key_static(
                    &unlocked.root_key,
                    cipher_id,
                    envelope.header.key_epoch,
                );
                let cipher = crate::vault::cipher::decrypt_cipher(
                    self.vault_id,
                    cipher_id,
                    &file,
                    &item_key,
                )?;
                Ok(CipherRead::Decrypted(cipher))
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

    /// Delete a cipher by ID. By default, moves it to trash.
    /// If it is already in trash, deletes it permanently.
    pub fn delete_cipher(&self, cipher_id: Uuid) -> Result<(), IdttyError> {
        let active_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        let trash_path = self.path.join(format!("trash/{}.enc", cipher_id));

        if active_path.exists() {
            let trash_dir = self.path.join("trash");
            std::fs::create_dir_all(&trash_dir)?;
            let envelope_bytes = std::fs::read(&active_path)?;
            std::fs::write(&trash_path, &envelope_bytes)?;
            std::fs::remove_file(&active_path)?;
            Ok(())
        } else if trash_path.exists() {
            std::fs::remove_file(&trash_path)?;
            Ok(())
        } else {
            Err(VaultError::CipherNotFound(cipher_id.to_string()).into())
        }
    }

    /// List deleted cipher IDs in trash.
    pub fn list_trash_ids(&self) -> Result<Vec<Uuid>, IdttyError> {
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
    pub fn restore_cipher(&self, cipher_id: Uuid) -> Result<(), IdttyError> {
        let active_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        let trash_path = self.path.join(format!("trash/{}.enc", cipher_id));

        if !trash_path.exists() {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        }

        let ciphers_dir = self.path.join("ciphers");
        std::fs::create_dir_all(&ciphers_dir)?;
        let envelope_bytes = std::fs::read(&trash_path)?;
        std::fs::write(&active_path, &envelope_bytes)?;
        std::fs::remove_file(&trash_path)?;
        Ok(())
    }

    /// Purge deleted entries from trash that were deleted more than `days` ago.
    pub fn purge_old_trash(&self, days: u32) -> Result<usize, IdttyError> {
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
    pub fn add_cipher(&mut self, input: &CipherInput) -> Result<Uuid, IdttyError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let cipher_id = Uuid::new_v4();
        let item_key =
            Self::derive_item_key_static(&unlocked.root_key, cipher_id, unlocked.current_epoch);

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            input,
            &item_key,
            1, // epoch
            1, // update_seq
            0, // nonce_counter
        )?;

        let file_path = self.path.join(format!("ciphers/{}.enc", cipher_id));
        std::fs::write(&file_path, &file.envelope_bytes)?;

        Ok(cipher_id)
    }

    /// Update an existing cipher (requires unlocked vault).
    /// Re-encrypts with incremented update_seq.
    pub fn update_cipher(
        &mut self,
        cipher_id: Uuid,
        input: &CipherInput,
    ) -> Result<(), IdttyError> {
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
            match self.try_decrypt_cipher_with_root_key(&unlocked.root_key, &existing_file) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

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
        if old_password.is_some() && old_password != new_password {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut history = existing_cipher.password_history.clone();
            history.push(crate::types::PasswordHistoryEntry {
                password: old_password.unwrap(),
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
        } else if input_owned.password_history.is_empty() {
            // Preserve existing history if caller didn't provide one and password didn't change.
            // History is append-only: passing password_history: vec![] preserves existing history.
            input_owned.password_history = existing_cipher.password_history.clone();
        }

        let item_key = Self::derive_item_key_static(&unlocked.root_key, cipher_id, key_epoch);

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input_owned,
            &item_key,
            key_epoch,
            new_update_seq,
            new_update_seq, // nonce_counter: use update_seq to ensure unique nonce per update
        )?;

        std::fs::write(&file_path, &file.envelope_bytes)?;

        Ok(())
    }

    /// Clone a cipher: duplicate with new UUID, empty password history, reset update_seq.
    pub fn clone_cipher(&mut self, cipher_id: Uuid) -> Result<Uuid, IdttyError> {
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
        };

        // add_cipher handles new UUID + encryption
        self.add_cipher(&input)
    }

    fn find_device_id(path: &Path) -> Result<Uuid, IdttyError> {
        let keywrap_dir = path.join("meta/keywrap");
        if !keywrap_dir.exists() {
            return Err(VaultError::NotInitialized.into());
        }

        for entry in std::fs::read_dir(&keywrap_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_suffix(".json") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    return Ok(id);
                }
            }
        }

        Err(VaultError::NotFound("no keywrap files found".into()).into())
    }

    pub fn derive_vault_id(kdf_params: &KdfParams) -> Uuid {
        // Derive a stable UUID from the KDF salt
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"idtty-vault-id-v1");
        hasher.update(&kdf_params.salt);
        let hash = hasher.finalize();
        Uuid::from_bytes(hash[..16].try_into().unwrap())
    }

    // ── Rate limiting ──

    /// Check if too many failed unlock attempts have occurred.
    /// Exponential backoff: after N failures, wait 2^(N-5) seconds.
    /// First 5 attempts: no delay. After that: 1s, 2s, 4s, 8s, ...
    ///
    /// **Note**: This is a soft deterrent, not hard brute-force protection.
    /// The counter is stored in `meta/kdf-attempts.json` which can be deleted
    /// by any process with write access. Argon2id provides the real defense.
    fn check_attempt_rate_limit(&self) -> Result<(), IdttyError> {
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

    fn record_failed_attempt(&self) -> Result<(), IdttyError> {
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
                .map_err(|e| VaultError::Corrupt(format!("attempts serialize: {e}")))?,
        )?;
        Ok(())
    }

    fn clear_failed_attempts(&self) -> Result<(), IdttyError> {
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
}

/// Result of reading a cipher: either decrypted content or locked metadata.
pub enum CipherRead {
    Decrypted(Cipher),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KdfProfile;
    use crate::vault::creation;

    fn create_test_vault() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let password = "test-password-unlock-flow";

        let result = creation::create_vault_ceremony(password, KdfProfile::MobileLow).unwrap();

        let path = dir.path();

        // Write vault structure
        std::fs::create_dir_all(path.join("ciphers")).unwrap();
        std::fs::create_dir_all(path.join("meta/keywrap")).unwrap();

        // KDF params
        std::fs::write(
            path.join("meta/kdf-params.json"),
            serde_json::to_string_pretty(&result.kdf_params).unwrap(),
        )
        .unwrap();

        // Device registry
        let mut registry = DeviceRegistry::new();
        let pub_enc = x25519_dalek::PublicKey::from(&result.device_x25519_secret);
        let verifying = result.device_ed25519_signing.verifying_key();
        registry
            .enroll(
                "this-device".into(),
                pub_enc.to_bytes(),
                verifying.to_bytes(),
            )
            .unwrap();
        std::fs::write(
            path.join("meta/devices.json"),
            serde_json::to_string_pretty(&registry).unwrap(),
        )
        .unwrap();

        // Keywrap
        let (eph_pub, ct, tag) = &result.wrapped_root_key;
        let keywrap_data = serde_json::json!({
            "device_id": result.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            path.join(format!("meta/keywrap/{}.json", result.device_id)),
            serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )
        .unwrap();

        // CLI mode: store device private key (NOT for production!)
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode(result.device_x25519_secret.to_bytes()),
        });
        std::fs::write(
            path.join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )
        .unwrap();

        // KEK canary (for password verification)
        std::fs::write(path.join("meta/kek-canary.enc"), &result.kek_canary).unwrap();

        // Root Key canary (for RK verification)
        std::fs::write(path.join("meta/rk-canary.enc"), &result.rk_canary).unwrap();

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
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
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
                password_revision_date: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
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
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
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
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
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
}
