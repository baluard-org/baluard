//! Vault state management for the daemon.
//!
//! Holds an unlocked VaultHandle in memory behind a shared lock.
//! The daemon routes gateway actions through this state.

use idtty_core::vault::handle::VaultHandle;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

impl VaultState {
    /// Create a new empty state pointing at a vault directory.
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            inner: RwLock::new(None),
            session_token: RwLock::new(None),
        }
    }

    /// Open a vault from disk (locked state).
    pub async fn open(&self) -> Result<(), String> {
        let handle = VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Failed to open vault: {e}"))?;
        let mut guard = self.inner.write().await;
        *guard = Some(handle);
        Ok(())
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

        Ok(())
    }

    /// Lock the vault, zeroizing keys in memory. Clears the session token.
    pub async fn lock(&self) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        if let Some(ref mut handle) = *guard {
            handle.lock();
        }
        // R7-2: Invalidate session token on lock
        let mut token_guard = self.session_token.write().await;
        *token_guard = None;
        Ok(())
    }

    /// Check if vault is currently unlocked.
    #[allow(dead_code)]
    pub async fn is_unlocked(&self) -> bool {
        let guard = self.inner.read().await;
        guard.as_ref().map_or(false, |h| h.is_unlocked())
    }

    /// List all cipher IDs (works locked or unlocked).
    pub async fn list_cipher_ids(&self) -> Result<Vec<String>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let ids = handle.list_cipher_ids().map_err(|e| format!("{e}"))?;
        Ok(ids.iter().map(|id| id.to_string()).collect())
    }

    /// List cipher metadata (requires unlocked vault).
    pub async fn list_cipher_meta(&self) -> Result<Vec<idtty_core::types::CipherMeta>, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        handle.list_cipher_meta().map_err(|e| format!("{e}"))
    }

    /// Get a cipher by ID. Requires vault to be unlocked for decryption.
    pub async fn get_cipher(&self, id_str: &str, decrypt: bool) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let cipher_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        let result = handle.get_cipher(cipher_id).map_err(|e| format!("{e}"))?;

        match result {
            idtty_core::vault::handle::CipherRead::Decrypted(c) => {
                let mut json = serde_json::json!({
                    "id": c.id.to_string(),
                    "name": c.name,
                    "type": serde_json::to_value(c.kind.cipher_type()).unwrap_or(serde_json::Value::Null),
                    "favorite": c.favorite,
                    "notes": c.notes,
                    "tier": format!("{:?}", c.tier),
                    "epoch": c.key_epoch,
                    "seq": c.update_seq,
                });
                match &c.kind {
                    idtty_core::types::CipherKind::Login(data) => {
                        json["username"] = serde_json::json!(data.username);
                        json["password"] = serde_json::json!(data.password);
                        json["uris"] = serde_json::json!(data.uris);
                        json["totp"] = serde_json::json!(data.totp_uri);
                    }
                    idtty_core::types::CipherKind::Card(data) => {
                        json["cardholder_name"] = serde_json::json!(data.cardholder_name);
                        json["brand"] = serde_json::json!(data.brand);
                        json["number"] = serde_json::json!(data.number);
                    }
                    idtty_core::types::CipherKind::Identity(data) => {
                        json["first_name"] = serde_json::json!(data.first_name);
                        json["last_name"] = serde_json::json!(data.last_name);
                        json["email"] = serde_json::json!(data.email);
                    }
                    _ => {}
                }
                Ok(json.to_string())
            }
            idtty_core::vault::handle::CipherRead::Locked(info) => {
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
    pub async fn settings_get(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;
        let settings = handle.get_settings().map_err(|e| format!("{e}"))?;
        serde_json::to_string(&settings).map_err(|e| format!("settings serialization: {e}"))
    }

    /// Update vault settings from partial JSON.
    pub async fn settings_set(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        let partial: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid JSON: {e}"))?;

        let mut settings = handle.get_settings().map_err(|e| format!("{e}"))?;

        if let Some(v) = partial.get("auto_lock_minutes") {
            settings.auto_lock_minutes = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid auto_lock_minutes: {e}"))?;
        }
        if let Some(v) = partial.get("theme") {
            settings.theme = serde_json::from_value(v.clone())
                .map_err(|e| format!("Invalid theme: {e}"))?;
        }
        if let Some(v) = partial.get("default_uri_match") {
            let s = v.as_str().ok_or("default_uri_match must be a string")?;
            settings.default_uri_match = Some(
                idtty_core::types::UriMatchStrategy::from_str_strict(s)
                    .map_err(|e| e)?,
            );
        }

        handle.save_settings(&settings).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    /// Add a new cipher. Requires vault to be unlocked.
    pub async fn add_cipher(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let input: idtty_core::types::CipherInput =
            serde_json::from_str(payload).map_err(|e| format!("Invalid cipher input: {e}"))?;

        let cipher_id = handle.add_cipher(&input).map_err(|e| format!("{e}"))?;

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
            idtty_core::vault::handle::CipherRead::Decrypted(c) => c,
            _ => return Err("Cipher not found or vault locked".to_string()),
        };

        // Build merged input from existing + updates (proper PATCH semantics)
        // Distinguishes "key absent" from "key present with null"
        let input = idtty_core::types::CipherInput {
            name: update
                .get("name")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| existing_cipher.name.clone()),
            folder_id: if update.get("folder_id").map(|v| v.is_null()).unwrap_or(false) {
                None // explicit null clears folder
            } else {
                update
                    .get("folder_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.parse::<uuid::Uuid>().ok())
                    .flatten()
                    .or(existing_cipher.folder_id)
            },
            kind: existing_cipher.kind.clone(),
            favorite: update
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(existing_cipher.favorite),
            notes: if update.get("notes").map(|v| v.is_null()).unwrap_or(false) {
                None // explicit null clears notes
            } else {
                update
                    .get("notes")
                    .and_then(|v| v.as_str().map(String::from))
                    .or(existing_cipher.notes.clone())
            },
            custom_fields: existing_cipher.custom_fields.clone(),
            created_at: Some(existing_cipher.created_at),
            password_history: existing_cipher.password_history.clone(),
        };

        handle
            .update_cipher(cipher_id, &input)
            .map_err(|e| format!("{e}"))
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

    // ── Folder CRUD ──

    /// List all folders.
    pub async fn list_folders(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened".to_string())?;

        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;
        serde_json::to_string(&folders).map_err(|e| format!("{e}"))
    }

    /// Create a folder.
    pub async fn create_folder(&self, name: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let id = handle.create_folder(name).map_err(|e| format!("{e}"))?;
        Ok(id.to_string())
    }

    /// Rename a folder. Payload: JSON {"id": "...", "name": "new name"}
    pub async fn rename_folder(&self, payload: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let data: serde_json::Value = serde_json::from_str(payload)
            .map_err(|e| format!("Invalid JSON: {e}"))?;
        let id_str = data["id"].as_str().ok_or("Missing 'id' field")?;
        let name = data["name"].as_str().ok_or("Missing 'name' field")?;
        let folder_id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("Invalid UUID: {e}"))?;

        handle.rename_folder(folder_id, name).map_err(|e| format!("{e}"))
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

        let devices: Vec<serde_json::Value> = handle.registry.devices.values().map(|entry| {
            serde_json::json!({
                "name": entry.name,
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
        let profile = match profile_str {
            "mobile_low" => idtty_core::types::KdfProfile::MobileLow,
            "desktop_std" => idtty_core::types::KdfProfile::DesktopStd,
            "desktop_high" => idtty_core::types::KdfProfile::DesktopHigh,
            _ => {
                return Err(format!(
                    "Unknown profile: {profile_str}. Use mobile_low, desktop_std, or desktop_high"
                ));
            }
        };

        // Run creation ceremony (CPU-heavy, no lock needed)
        let (handle, secrets) = idtty_core::vault::creation::VaultCreator::new(&self.vault_path, &password, "this-device")
            .kdf_profile(profile)
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
        let response = serde_json::json!({
            "vault_id": secrets.vault_id.to_string(),
            "device_id": secrets.device_id.to_string(),
            "recovery_phrase": secrets.recovery_phrase.phrase(),
            "trust_fingerprint": hex::encode(secrets.trust_fingerprint),
            "session_token": token,
        });
        Ok(response.to_string())
    }

    // ── R7-2: Session token management ──

    /// Verify a client-provided session token against the stored one.
    /// Uses constant-time comparison to prevent timing side channels.
    pub async fn verify_session_token(&self, provided: &str) -> Result<(), String> {
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

/// R7-2: Generate a cryptographically random session token (32 bytes hex = 64 chars).
fn generate_session_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}
