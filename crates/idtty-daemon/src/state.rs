//! Vault state management for the daemon.
//!
//! Holds an unlocked VaultHandle in memory behind a shared lock.
//! The daemon routes gateway actions through this state.

use idtty_core::vault::handle::{CipherRead, VaultHandle};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use base64::Engine;
use zeroize::Zeroize;
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
    /// Last activity timestamp (seconds since epoch). Updated on every IPC request.
    last_activity: AtomicU64,
}

impl VaultState {
    /// Create a new empty state pointing at a vault directory.
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            inner: RwLock::new(None),
            session_token: RwLock::new(None),
            last_activity: AtomicU64::new(0),
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

    /// Get seconds since last activity.
    pub fn seconds_since_activity(&self) -> u64 {
        let last = self.last_activity.load(Ordering::Relaxed);
        if last == 0 { return 0; }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last)
    }

    /// Spawn auto-lock background checker. Checks every 30s.
    pub fn spawn_auto_lock_checker(state: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                // Read auto_lock_minutes from settings
                let timeout_minutes = {
                    let guard = state.inner.read().await;
                    if let Some(handle) = guard.as_ref() {
                        handle.get_settings().ok()
                            .and_then(|s| s.auto_lock_minutes)
                            .unwrap_or(15) // default 15 minutes
                    } else {
                        continue; // no vault open
                    }
                };

                let elapsed = state.seconds_since_activity();
                let timeout_secs = (timeout_minutes as u64) * 60;

                if elapsed >= timeout_secs && timeout_secs > 0 {
                    eprintln!("Auto-lock: {}s idle >= {}s timeout, locking vault", elapsed, timeout_secs);
                    let mut guard = state.inner.write().await;
                    if let Some(handle) = guard.as_mut() {
                        if handle.is_unlocked() {
                            let _ = handle.lock();
                            *state.session_token.write().await = None;
                            state.last_activity.store(0, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
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
    #[allow(dead_code)]
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
                    "reprompt": c.reprompt,
                    "notes": c.notes,
                    "tier": format!("{:?}", c.tier),
                    "epoch": c.key_epoch,
                    "seq": c.update_seq,
                    "folder_id": c.folder_id,
                    "created_at": c.created_at,
                    "updated_at": c.updated_at,
                    "password_history": c.password_history,
                    "attachments": c.attachments,
                });
                // Emit kind as nested object matching CipherKind serde format
                json["kind"] = serde_json::to_value(&c.kind).unwrap_or(serde_json::Value::Null);
                // Also emit flat top-level fields for backward compat
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
                        json["exp_month"] = serde_json::json!(data.exp_month);
                        json["exp_year"] = serde_json::json!(data.exp_year);
                        json["code"] = serde_json::json!(data.code);
                    }
                    idtty_core::types::CipherKind::Identity(data) => {
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
                    idtty_core::types::CipherKind::SshKey(data) => {
                        json["public_key"] = serde_json::json!(data.public_key);
                        json["private_key"] = serde_json::json!(data.private_key);
                        json["fingerprint"] = serde_json::json!(data.key_fingerprint);
                    }
                    idtty_core::types::CipherKind::SecureNote => {}
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
            kind: update
                .get("kind")
                .and_then(|v| serde_json::from_value::<idtty_core::types::CipherKind>(v.clone()).ok())
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
            custom_fields: existing_cipher.custom_fields.clone(),
            created_at: Some(existing_cipher.created_at),
            password_history: existing_cipher.password_history.clone(),
                    attachments: existing_cipher.attachments.clone(),
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
            idtty_core::vault::handle::CipherRead::Decrypted(c) => c,
            idtty_core::vault::handle::CipherRead::Locked(_) => return Err("Cipher is locked".into()),
        };

        // Extract totp_uri from the Login kind
        let totp_uri = match &cipher_ref.kind {
            idtty_core::types::CipherKind::Login(data) => data.totp_uri.as_deref(),
            _ => None,
        }.ok_or("No TOTP URI found for this cipher")?;

        let params = idtty_core::crypto::totp::parse_totp_uri(totp_uri)
            .map_err(|e| format!("Invalid TOTP URI: {e}"))?;

        let (code, period_seconds, expires_at) = idtty_core::crypto::totp::generate_totp(&params);

        // Return ONLY the code + metadata. Never the seed.
        serde_json::to_string(&serde_json::json!({
            "code": code,
            "period_seconds": period_seconds,
            "expires_at": expires_at,
        })).map_err(|e| format!("{e}"))
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

    /// Import ciphers from parsed data. Creates folders from folder_map, then batch-creates ciphers.
    pub async fn import_ciphers(&self, import_result: idtty_core::import::ImportResult) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        // Create folders and build name->id map
        let mut folder_id_map: std::collections::HashMap<String, uuid::Uuid> = std::collections::HashMap::new();
        for folder_name in import_result.folder_map.keys() {
            match handle.create_folder(folder_name) {
                Ok(id) => { folder_id_map.insert(folder_name.clone(), id); }
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
            let folder_name = import_result.folder_map.iter()
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

        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(c)) => ciphers.push(c),
                Ok(CipherRead::Locked(_)) => continue,
                Err(e) => eprintln!("[export] skipping {}: {e}", meta.id),
            }
        }

        // Get folders
        let folders = handle.list_folders().map_err(|e| format!("{e}"))?;
        let folder_pairs: Vec<(uuid::Uuid, String)> = folders.into_iter().map(|f| (f.id, f.name)).collect();

        idtty_core::import::export::export_bw_json(&ciphers, &folder_pairs)
    }

    /// Export all ciphers as BW-compatible CSV (logins only).
    pub async fn export_bw_csv(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".into());
        }

        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(CipherRead::Decrypted(c)) => ciphers.push(c),
                Ok(CipherRead::Locked(_)) => continue,
                Err(e) => eprintln!("[export] skipping {}: {e}", meta.id),
            }
        }

        idtty_core::import::export::export_bw_csv(&ciphers)
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

    /// Get biometric unlock status.
    pub async fn biometric_status(&self) -> Result<String, String> {
        let available = idtty_core::biometric::is_available();
        let enabled = if available {
            idtty_core::biometric::is_enabled()
        } else {
            false
        };
        Ok(serde_json::json!({
            "available": available,
            "enabled": enabled,
        }).to_string())
    }

    /// Enable biometric unlock. Validates password against vault first,
    /// then stores in OS keychain.
    pub async fn biometric_enable(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload)
            .map_err(|e| format!("{e}"))?;
        let password = req["password"].as_str().ok_or("missing password")?;

        // Verify the password can unlock the vault before storing
        // Open a temp handle, try unlock, discard
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;
        let vault_path = handle.path.clone();
        drop(guard);

        let mut temp = idtty_core::vault::handle::VaultHandle::open(&vault_path)
            .map_err(|e| format!("Open failed: {e}"))?;
        temp.unlock(password)
            .map_err(|_| "Incorrect master password".to_string())?;
        temp.lock();

        idtty_core::biometric::enable(password)?;

        Ok(serde_json::json!({"enabled": true}).to_string())
    }

    /// Disable biometric unlock.
    pub async fn biometric_disable(&self) -> Result<String, String> {
        idtty_core::biometric::disable()?;
        Ok(serde_json::json!({"disabled": true}).to_string())
    }

    /// Biometric unlock. Retrieves stored master password from OS keychain
    /// and performs vault unlock. The secret NEVER leaves this process.
    pub async fn biometric_unlock(&self) -> Result<String, String> {
        let master_password = idtty_core::biometric::unlock()?;
        self.unlock(&master_password).await?;
        Ok(serde_json::json!({"success": true}).to_string())
    }

    /// Upload attachment to a cipher.
    /// Payload: { cipher_id, filename, data_base64 }
    pub async fn attach_upload(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let cipher_id: uuid::Uuid = req["cipher_id"].as_str()
            .ok_or("missing cipher_id")?
            .parse().map_err(|e| format!("invalid cipher_id: {e}"))?;
        let filename = req["filename"].as_str().ok_or("missing filename")?;
        let data_b64 = req["data_base64"].as_str().ok_or("missing data_base64")?;
        let mut plaintext = base64::engine::general_purpose::STANDARD.decode(data_b64)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if plaintext.len() > idtty_core::vault::attachment::MAX_ATTACHMENT_SIZE {
            return Err(format!("File too large: {} bytes (max 2MB)", plaintext.len()));
        }

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        // Get cipher to find its item key and existing attachments
        let cipher = match handle.get_cipher(cipher_id) {
            Ok(idtty_core::vault::handle::CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Derive item key
        let item_key = handle.derive_item_key(cipher_id, cipher.key_epoch);

        // Generate attachment ID
        let attach_id = uuid::Uuid::new_v4().to_string();

        // Encrypt
        let encrypted = idtty_core::vault::attachment::encrypt_attachment(
            item_key.as_bytes(), &plaintext
        ).map_err(|e| format!("{e}"))?;

        // Zeroize plaintext after encryption
        plaintext.zeroize();

        // Create attachment directory
        let attach_dir = handle.path.join("entries").join(cipher_id.to_string()).join("attachments");
        std::fs::create_dir_all(&attach_dir).map_err(|e| format!("mkdir: {e}"))?;

        // Write encrypted file
        let attach_path = attach_dir.join(format!("{}.enc", attach_id));
        std::fs::write(&attach_path, &encrypted).map_err(|e| format!("write: {e}"))?;

        // Update cipher metadata with new attachment
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let meta = idtty_core::vault::attachment::AttachmentMeta {
            id: attach_id.clone(),
            filename: filename.to_string(),
            size: plaintext.len() as u64,
            encrypted_size: encrypted.len() as u64,
            mime_type: idtty_core::vault::attachment::detect_mime(filename),
            created_at: now,
        };

        let mut attachments = cipher.attachments.clone();
        attachments.push(meta);

        // Update cipher with new attachments list
        let input = idtty_core::types::CipherInput {
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
        let cipher_id: uuid::Uuid = req["cipher_id"].as_str()
            .ok_or("missing cipher_id")?
            .parse().map_err(|e| format!("invalid cipher_id: {e}"))?;
        let attach_id = req["attachment_id"].as_str().ok_or("missing attachment_id")?;

        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let cipher = match handle.get_cipher(cipher_id) {
            Ok(idtty_core::vault::handle::CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Verify attachment exists in metadata
        let meta = cipher.attachments.iter()
            .find(|a| a.id == attach_id)
            .ok_or("Attachment not found")?;

        let item_key = handle.derive_item_key(cipher_id, cipher.key_epoch);

        let attach_path = handle.path
            .join("entries").join(cipher_id.to_string())
            .join("attachments").join(format!("{}.enc", attach_id));

        let encrypted = std::fs::read(&attach_path).map_err(|e| format!("read: {e}"))?;
        let mut plaintext = idtty_core::vault::attachment::decrypt_attachment(item_key.as_bytes(), &encrypted)
            .map_err(|e| format!("{e}"))?;

        let result = serde_json::json!({
            "filename": meta.filename,
            "mime_type": meta.mime_type,
            "size": meta.size,
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&plaintext),
        }).to_string();

        // Zeroize plaintext after encoding
        plaintext.zeroize();

        Ok(result)
    }

    /// Delete attachment from a cipher.
    /// Payload: { cipher_id, attachment_id }
    pub async fn attach_delete(&self, payload: &str) -> Result<String, String> {
        let req: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("{e}"))?;
        let cipher_id: uuid::Uuid = req["cipher_id"].as_str()
            .ok_or("missing cipher_id")?
            .parse().map_err(|e| format!("invalid cipher_id: {e}"))?;
        let attach_id = req["attachment_id"].as_str().ok_or("missing attachment_id")?;

        let mut guard = self.inner.write().await;
        let handle = guard.as_mut().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let cipher = match handle.get_cipher(cipher_id) {
            Ok(idtty_core::vault::handle::CipherRead::Decrypted(c)) => c,
            _ => return Err("Cipher not found or vault locked".into()),
        };

        // Remove from attachments list
        let mut attachments = cipher.attachments.clone();
        let idx = attachments.iter().position(|a| a.id == attach_id)
            .ok_or("Attachment not found")?;
        attachments.remove(idx);

        // Delete encrypted file
        let attach_path = handle.path
            .join("entries").join(cipher_id.to_string())
            .join("attachments").join(format!("{}.enc", attach_id));
        if attach_path.exists() {
            std::fs::remove_file(&attach_path).map_err(|e| format!("delete: {e}"))?;
        }

        // Update cipher
        let input = idtty_core::types::CipherInput {
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
        };
        handle.update_cipher(cipher_id, &input).map_err(|e| format!("{e}"))?;

        Ok(serde_json::json!({"deleted": true}).to_string())
    }

    /// Get password health report.
    pub async fn health_report(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref().ok_or("Vault not opened")?;

        if !handle.is_unlocked() {
            return Err("Vault is locked".into());
        }

        let metas = handle.list_cipher_meta().map_err(|e| format!("{e}"))?;
        let mut ciphers = Vec::new();
        for meta in &metas {
            match handle.get_cipher(meta.id) {
                Ok(idtty_core::vault::handle::CipherRead::Decrypted(c)) => ciphers.push(c),
                _ => continue,
            }
        }

        let report = idtty_core::health::analyze(&ciphers);
        serde_json::to_string(&report).map_err(|e| format!("{e}"))
    }

    /// Verify master password for reprompt. Opens a temporary handle and attempts unlock.
    /// Returns a short-lived grant. Does NOT change the main vault state.
    pub async fn reprompt_verify(&self, master_password: &str) -> Result<String, String> {
        // Open a temporary handle
        let mut temp_handle = VaultHandle::open(&self.vault_path)
            .map_err(|e| format!("Open failed: {e}"))?;

        // Try to unlock with the provided password
        temp_handle
            .unlock(master_password)
            .map_err(|_| "Incorrect master password".to_string())?;

        // Password verified. Generate a short-lived grant token.
        let mut token_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
        let grant = hex::encode(token_bytes);
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 30; // 30 second grant

        // Lock the temporary handle (zeroize keys)
        temp_handle.lock();

        Ok(serde_json::json!({
            "granted": true,
            "expires_at": expires_at,
            "grant_token": grant,
        }).to_string())
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
