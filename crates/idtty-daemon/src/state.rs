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

        new_handle.unlock(master_password)
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
        let handle = guard.as_ref()
            .ok_or("Vault not opened".to_string())?;
        let ids = handle.list_cipher_ids()
            .map_err(|e| format!("{e}"))?;
        Ok(ids.iter().map(|id| id.to_string()).collect())
    }

    /// Get a cipher by ID. Requires vault to be unlocked for decryption.
    pub async fn get_cipher(&self, id_str: &str, decrypt: bool) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref()
            .ok_or("Vault not opened".to_string())?;

        let cipher_id = uuid::Uuid::parse_str(id_str)
            .map_err(|e| format!("Invalid UUID: {e}"))?;

        let result = handle.get_cipher(cipher_id)
            .map_err(|e| format!("{e}"))?;

        match result {
            idtty_core::vault::handle::CipherRead::Decrypted(c) => {
                let json = serde_json::json!({
                    "id": c.id.to_string(),
                    "name": c.name,
                    "username": c.username,
                    "password": c.password,
                    "uris": c.uris,
                    "notes": c.notes,
                    "totp": c.totp_uri,
                    "tier": format!("{:?}", c.tier),
                    "epoch": c.key_epoch,
                    "seq": c.update_seq,
                });
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

    /// Add a new cipher. Requires vault to be unlocked.
    pub async fn add_cipher(&self, payload: &str) -> Result<String, String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut()
            .ok_or("Vault not opened".to_string())?;

        if !handle.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let input: idtty_core::types::CipherInput = serde_json::from_str(payload)
            .map_err(|e| format!("Invalid cipher input: {e}"))?;

        let cipher_id = handle.add_cipher(&input)
            .map_err(|e| format!("{e}"))?;

        Ok(cipher_id.to_string())
    }

    /// Delete a cipher by ID. Uses write lock for filesystem mutation.
    pub async fn delete_cipher(&self, id_str: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let handle = guard.as_mut()
            .ok_or("Vault not opened".to_string())?;

        let cipher_id = uuid::Uuid::parse_str(id_str)
            .map_err(|e| format!("Invalid UUID: {e}"))?;

        handle.delete_cipher(cipher_id)
            .map_err(|e| format!("{e}"))
    }

    /// Get vault info (ID, device, state).
    pub async fn info(&self) -> Result<String, String> {
        let guard = self.inner.read().await;
        let handle = guard.as_ref()
            .ok_or("Vault not opened".to_string())?;

        let cipher_count = handle.list_cipher_ids()
            .map(|ids| ids.len())
            .unwrap_or(0);

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
        let handle = guard.as_ref()
            .ok_or("Vault not opened".to_string())?;

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
            return Err("Vault already exists at this path. Delete it first if you want to recreate.".into());
        }

        let v: serde_json::Value = serde_json::from_str(payload_json)
            .map_err(|e| format!("Invalid JSON: {e}"))?;
        // Extract password into zeroizing wrapper
        let password = v["password"].as_str()
            .ok_or("Missing 'password' field")?
            .to_string();
        let mut password = zeroize::Zeroizing::new(password);

        let profile_str = v["profile"].as_str().unwrap_or("desktop_std");
        let profile = match profile_str {
            "mobile_low" => idtty_core::types::KdfProfile::MobileLow,
            "desktop_std" => idtty_core::types::KdfProfile::DesktopStd,
            "desktop_high" => idtty_core::types::KdfProfile::DesktopHigh,
            _ => return Err(format!("Unknown profile: {profile_str}. Use mobile_low, desktop_std, or desktop_high")),
        };

        // Run creation ceremony (CPU-heavy, no lock needed)
        let result = idtty_core::vault::creation::create_vault_ceremony(&password, profile)
            .map_err(|e| format!("Vault creation failed: {e}"))?;

        // Zeroize password as soon as ceremony completes
        zeroize::Zeroize::zeroize(&mut *password);

        let path = &self.vault_path;
        std::fs::create_dir_all(path.join("ciphers"))
            .map_err(|e| format!("mkdir ciphers: {e}"))?;
        std::fs::create_dir_all(path.join("meta/keywrap"))
            .map_err(|e| format!("mkdir keywrap: {e}"))?;
        std::fs::create_dir_all(path.join("meta/sequences"))
            .map_err(|e| format!("mkdir sequences: {e}"))?;

        // Helper: write file with restrictive permissions for sensitive data
        let write_secret = |file_path: std::path::PathBuf, data: &[u8]| -> Result<(), String> {
            std::fs::write(&file_path, data)
                .map_err(|e| format!("Write {}: {e}", file_path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("chmod {}: {e}", file_path.display()))?;
            }
            Ok(())
        };

        // Device registry
        let mut registry = idtty_core::devices::DeviceRegistry::new();
        let pub_enc = x25519_dalek::PublicKey::from(&result.device_x25519_secret);
        let verifying = result.device_ed25519_signing.verifying_key();
        registry.enroll(
            "this-device".into(),
            pub_enc.to_bytes(),
            verifying.to_bytes(),
        ).map_err(|e| format!("Device enrollment: {e}"))?;
        write_secret(
            path.join("meta/devices.json"),
            serde_json::to_string_pretty(&registry).map_err(|e| format!("Serialize devices: {e}"))?.as_bytes(),
        )?;

        // KDF params
        write_secret(
            path.join("meta/kdf-params.json"),
            serde_json::to_string_pretty(&result.kdf_params).map_err(|e| format!("Serialize kdf: {e}"))?.as_bytes(),
        )?;

        // Keywrap
        let (eph_pub, ct, tag) = &result.wrapped_root_key;
        let keywrap_data = serde_json::json!({
            "device_id": result.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        write_secret(
            path.join(format!("meta/keywrap/{}.json", result.device_id)),
            serde_json::to_string_pretty(&keywrap_data).map_err(|e| format!("Serialize keywrap: {e}"))?.as_bytes(),
        )?;

        // Device private key (TODO: encrypt at rest with platform keystore)
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode(result.device_x25519_secret.to_bytes()),
        });
        write_secret(
            path.join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).map_err(|e| format!("Serialize privkey: {e}"))?.as_bytes(),
        )?;

        // .gitignore
        std::fs::write(
            path.join(".gitignore"),
            "# Secrets - never push these\nmeta/device-privkey.json\n",
        ).map_err(|e| format!("Write gitignore: {e}"))?;

        // Canaries
        write_secret(path.join("meta/kek-canary.enc"), &result.kek_canary)?;
        write_secret(path.join("meta/rk-canary.enc"), &result.rk_canary)?;

        // Now open the vault so it's ready for use
        let handle = VaultHandle::open(path)
            .map_err(|e| format!("Open after create: {e}"))?;
        let mut guard = self.inner.write().await;
        *guard = Some(handle);

        // R7-2: Generate session token for newly created vault
        let token = generate_session_token();
        let mut token_guard = self.session_token.write().await;
        *token_guard = Some(token.clone());
        let response = serde_json::json!({
            "vault_id": result.vault_id.to_string(),
            "device_id": result.device_id.to_string(),
            "recovery_phrase": result.recovery_phrase.phrase(),
            "trust_fingerprint": hex::encode(result.trust_fingerprint),
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
            Some(ref stored) if crate::crypto::constant_time_eq(provided.as_bytes(), stored.as_bytes()) => Ok(()),
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
