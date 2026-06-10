//! Vault registry: tracks all known vaults on this machine.
//!
//! Stored at `<data_dir>/registry.json` (plaintext, not secret).
//! Uses atomic writes (temp + rename) and cross-process locking via `fd-lock`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fd_lock::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths::data_dir;
use crate::vault::slug::validate_slug;

// ── .baluard Marker File ──

/// Current marker file version.
const MARKER_VERSION: u32 = 1;

/// Content of the `.baluard` marker file at the vault root.
/// Not encrypted (not secret data). Used for fast vault detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaluardMarker {
    /// Marker schema version.
    pub version: u32,
    /// Unique vault identifier (stable UUID).
    pub vault_id: Uuid,
    /// Vault slug (filesystem-safe identifier).
    pub slug: String,
}

impl BaluardMarker {
    /// Create a new marker for a vault.
    pub fn new(vault_id: Uuid, slug: &str) -> Self {
        Self {
            version: MARKER_VERSION,
            vault_id,
            slug: slug.to_string(),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, RegistryError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| RegistryError::Serialize(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, RegistryError> {
        serde_json::from_str(json)
            .map_err(|e| RegistryError::Corrupt(e.to_string()))
    }

    /// Write the marker file to a vault directory.
    pub fn write_to_vault(&self, vault_path: &Path) -> Result<(), RegistryError> {
        let marker_path = vault_path.join(".baluard");
        let json = self.to_json()?;

        // Use atomic write pattern
        let tmp_path = marker_path.with_extension("tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        std::fs::rename(&tmp_path, &marker_path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;

        Ok(())
    }

    /// Read the marker from a vault directory. Returns None if not found.
    pub fn read_from_vault(vault_path: &Path) -> Result<Option<Self>, RegistryError> {
        let marker_path = vault_path.join(".baluard");
        if !marker_path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&marker_path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        let marker = Self::from_json(&json)?;
        Ok(Some(marker))
    }
}

// ── Vault Registry ──

/// Registry schema version.
const REGISTRY_VERSION: u32 = 1;

/// Vault entry in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Machine-friendly slug (filesystem-safe, URL-safe).
    pub slug: String,
    /// Human-readable display name (e.g. "Personal Vault").
    pub display_name: String,
    /// Absolute path to the vault directory on disk.
    pub path: PathBuf,
    /// Connected provider, if any ("github", "gitlab", "codeberg").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Remote URL for git sync (e.g. "https://github.com/user/vault.git").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    /// Unix timestamp of last successful sync (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced: Option<String>,
    /// Unix timestamp of last open (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_opened: Option<String>,
    /// Vault UUID (from the .baluard marker).
    pub vault_id: Uuid,
}

/// The vault registry, persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRegistry {
    /// Schema version.
    pub version: u32,
    /// Known vaults, keyed by slug.
    pub vaults: HashMap<String, VaultEntry>,
    /// Currently active vault slug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_vault: Option<String>,
    /// Default provider for new sync setups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
}

impl Default for VaultRegistry {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            vaults: HashMap::new(),
            active_vault: None,
            default_provider: None,
        }
    }
}

impl VaultRegistry {
    /// Returns the path to the registry file.
    pub fn path() -> PathBuf {
        data_dir().join("registry.json")
    }

    /// Load the registry from disk. Returns default if file doesn't exist.
    pub fn load() -> Result<Self, RegistryError> {
        let path = Self::path();
        Self::load_from(&path)
    }

    /// Load the registry with cross-process file lock.
    /// Use when concurrent access is possible (e.g., CLI + daemon both running).
    pub fn load_locked() -> Result<Self, RegistryError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RegistryError::Io(e.to_string()))?;
        }
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        let mut locker = RwLock::new(lock_file);
        let _guard = locker.write().map_err(|e| RegistryError::Io(e.to_string()))?;
        Self::load_from(&path)
    }

    /// Load the registry from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, RegistryError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        let reg: VaultRegistry = serde_json::from_str(&data)
            .map_err(|e| RegistryError::Corrupt(e.to_string()))?;
        if reg.version != REGISTRY_VERSION {
            return Err(RegistryError::Version(reg.version, REGISTRY_VERSION));
        }
        Ok(reg)
    }

    /// Save the registry to disk atomically.
    pub fn save(&self) -> Result<(), RegistryError> {
        let path = Self::path();
        self.save_to(&path)
    }

    /// Save the registry with cross-process file lock.
    pub fn save_locked(&self) -> Result<(), RegistryError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RegistryError::Io(e.to_string()))?;
        }
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        let mut locker = RwLock::new(lock_file);
        let _guard = locker.write().map_err(|e| RegistryError::Io(e.to_string()))?;
        self.save_to(&path)
    }

    /// Save the registry to a specific path atomically (temp + rename).
    pub fn save_to(&self, path: &Path) -> Result<(), RegistryError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RegistryError::Io(e.to_string()))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| RegistryError::Serialize(e.to_string()))?;

        // Atomic write: temp file + rename
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| RegistryError::Io(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| RegistryError::Io(e.to_string()))?;
        }

        std::fs::rename(&tmp_path, path)
            .map_err(|e| RegistryError::Io(e.to_string()))?;

        Ok(())
    }

    /// Add a new vault to the registry.
    pub fn add(&mut self, entry: VaultEntry) -> Result<(), RegistryError> {
        validate_slug(&entry.slug)
            .map_err(|e| RegistryError::InvalidSlug(e.to_string()))?;

        if self.vaults.contains_key(&entry.slug) {
            return Err(RegistryError::DuplicateSlug(entry.slug));
        }

        self.vaults.insert(entry.slug.clone(), entry);
        Ok(())
    }

    /// Remove a vault from the registry by slug.
    pub fn remove(&mut self, slug: &str) -> Option<VaultEntry> {
        let removed = self.vaults.remove(slug);
        // Clear active_vault if it was this one
        if self.active_vault.as_deref() == Some(slug) {
            self.active_vault = None;
        }
        removed
    }

    /// Get a vault entry by slug.
    pub fn get(&self, slug: &str) -> Option<&VaultEntry> {
        self.vaults.get(slug)
    }

    /// Get a mutable vault entry by slug.
    pub fn get_mut(&mut self, slug: &str) -> Option<&mut VaultEntry> {
        self.vaults.get_mut(slug)
    }

    /// Set the active vault. Returns error if slug doesn't exist.
    pub fn set_active(&mut self, slug: &str) -> Result<(), RegistryError> {
        if !self.vaults.contains_key(slug) {
            return Err(RegistryError::NotFound(slug.to_string()));
        }
        self.active_vault = Some(slug.to_string());
        Ok(())
    }

    /// Get the active vault entry.
    pub fn active(&self) -> Option<&VaultEntry> {
        self.active_vault
            .as_deref()
            .and_then(|slug| self.vaults.get(slug))
    }

    /// Touch the last_opened timestamp for a vault.
    pub fn touch(&mut self, slug: &str) {
        if let Some(entry) = self.vaults.get_mut(slug) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            entry.last_opened = Some(now.as_secs().to_string());
        }
    }

    /// List all vault slugs.
    pub fn list_slugs(&self) -> Vec<&str> {
        self.vaults.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a slug is already registered.
    pub fn exists(&self, slug: &str) -> bool {
        self.vaults.contains_key(slug)
    }
}

#[derive(Debug)]
pub enum RegistryError {
    Io(String),
    Corrupt(String),
    Serialize(String),
    Version(u32, u32),
    InvalidSlug(String),
    DuplicateSlug(String),
    NotFound(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Io(e) => write!(f, "Registry I/O error: {e}"),
            RegistryError::Corrupt(e) => write!(f, "Registry corrupt: {e}"),
            RegistryError::Serialize(e) => write!(f, "Registry serialization: {e}"),
            RegistryError::Version(found, expected) => {
                write!(f, "Registry version {found}, expected {expected}")
            }
            RegistryError::InvalidSlug(e) => write!(f, "Invalid slug: {e}"),
            RegistryError::DuplicateSlug(s) => write!(f, "Slug already registered: {s}"),
            RegistryError::NotFound(s) => write!(f, "Vault not found: {s}"),
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(slug: &str) -> VaultEntry {
        VaultEntry {
            slug: slug.to_string(),
            display_name: slug.to_string(),
            path: PathBuf::from(format!("/tmp/vaults/{slug}")),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn add_and_get() {
        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        assert!(reg.get("baluard-personal").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn duplicate_slug_rejected() {
        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        let err = reg.add(test_entry("baluard-personal"));
        assert!(matches!(err, Err(RegistryError::DuplicateSlug(_))));
    }

    #[test]
    fn remove_clears_active() {
        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        reg.set_active("baluard-personal").unwrap();
        assert_eq!(reg.active_vault, Some("baluard-personal".to_string()));

        reg.remove("baluard-personal");
        assert!(reg.active_vault.is_none());
    }

    #[test]
    fn set_active_unknown_slug() {
        let mut reg = VaultRegistry::default();
        let err = reg.set_active("nope");
        assert!(matches!(err, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn atomic_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");

        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        reg.set_active("baluard-personal").unwrap();

        reg.save_to(&path).unwrap();
        let loaded = VaultRegistry::load_from(&path).unwrap();

        assert_eq!(loaded.version, REGISTRY_VERSION);
        assert_eq!(loaded.active_vault, Some("baluard-personal".to_string()));
        assert!(loaded.get("baluard-personal").is_some());
    }

    #[test]
    fn load_missing_file_returns_default() {
        let reg = VaultRegistry::load_from(Path::new("/tmp/no-such-file-reg-test"));
        assert!(reg.is_ok());
        assert!(reg.unwrap().vaults.is_empty());
    }

    #[test]
    fn touch_updates_timestamp() {
        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        assert!(reg.get("baluard-personal").unwrap().last_opened.is_none());

        reg.touch("baluard-personal");
        assert!(reg.get("baluard-personal").unwrap().last_opened.is_some());
    }

    #[test]
    fn list_slugs() {
        let mut reg = VaultRegistry::default();
        reg.add(test_entry("baluard-personal")).unwrap();
        reg.add(test_entry("work")).unwrap();
        let mut slugs = reg.list_slugs();
        slugs.sort();
        assert_eq!(slugs, vec!["baluard-personal", "work"]);
    }

    #[test]
    fn invalid_slug_rejected_on_add() {
        let mut reg = VaultRegistry::default();
        let bad_entry = VaultEntry {
            slug: "AB".to_string(), // too short + uppercase
            display_name: "Bad".to_string(),
            path: PathBuf::from("/tmp/bad"),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
        };
        let err = reg.add(bad_entry);
        assert!(matches!(err, Err(RegistryError::InvalidSlug(_))));
    }

    // ── Marker tests ──

    #[test]
    fn marker_round_trip_json() {
        let id = Uuid::new_v4();
        let marker = BaluardMarker::new(id, "baluard-personal");
        let json = marker.to_json().unwrap();
        let back = BaluardMarker::from_json(&json).unwrap();
        assert_eq!(back, marker);
    }

    #[test]
    fn marker_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("my-vault");
        std::fs::create_dir_all(&vault_path).unwrap();

        let id = Uuid::new_v4();
        let marker = BaluardMarker::new(id, "baluard-personal");
        marker.write_to_vault(&vault_path).unwrap();

        assert!(vault_path.join(".baluard").exists());

        let loaded = BaluardMarker::read_from_vault(&vault_path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.vault_id, id);
        assert_eq!(loaded.slug, "baluard-personal");
    }

    #[test]
    fn marker_read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = BaluardMarker::read_from_vault(dir.path()).unwrap();
        assert!(result.is_none());
    }
}
