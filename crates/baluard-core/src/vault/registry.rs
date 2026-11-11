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
        serde_json::to_string_pretty(self).map_err(|e| RegistryError::Serialize(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, RegistryError> {
        serde_json::from_str(json).map_err(|e| RegistryError::Corrupt(e.to_string()))
    }

    /// Write the marker file to a vault directory.
    pub fn write_to_vault(&self, vault_path: &Path) -> Result<(), RegistryError> {
        let marker_path = vault_path.join(".baluard");
        let json = self.to_json()?;

        // Use atomic write pattern
        let tmp_path = marker_path.with_extension("tmp");
        std::fs::write(&tmp_path, &json).map_err(|e| RegistryError::Io(e.to_string()))?;
        std::fs::rename(&tmp_path, &marker_path).map_err(|e| RegistryError::Io(e.to_string()))?;

        Ok(())
    }

    /// Read the marker from a vault directory. Returns None if not found.
    pub fn read_from_vault(vault_path: &Path) -> Result<Option<Self>, RegistryError> {
        let marker_path = vault_path.join(".baluard");
        if !marker_path.exists() {
            return Ok(None);
        }
        let json =
            std::fs::read_to_string(&marker_path).map_err(|e| RegistryError::Io(e.to_string()))?;
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
    pub last_synced: Option<u64>,
    /// Unix timestamp of last open (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_opened: Option<u64>,
    /// Vault UUID (from the .baluard marker).
    pub vault_id: Uuid,
    /// G24 device-local opt-out (family-spaces step 7): the member can
    /// keep a Space out of their personal search and autofill on this
    /// device even when the admin ceiling is on. None = no answer yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_opt_in: Option<bool>,
    /// G24 device-local cache of the merge ceiling, refreshed at every
    /// unlock: true means the ceiling was on the last time this device
    /// opened the vault. A Space never unlocked here has false (no
    /// cache) and stays ineligible - fail closed, never nags.
    #[serde(default)]
    pub merge_ceiling_seen: bool,
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
            std::fs::create_dir_all(parent).map_err(|e| RegistryError::Io(e.to_string()))?;
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
        let _guard = locker
            .write()
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        Self::load_from(&path)
    }

    /// Load the registry from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, RegistryError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path).map_err(|e| RegistryError::Io(e.to_string()))?;
        let reg: VaultRegistry =
            serde_json::from_str(&data).map_err(|e| RegistryError::Corrupt(e.to_string()))?;
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
            std::fs::create_dir_all(parent).map_err(|e| RegistryError::Io(e.to_string()))?;
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
        let _guard = locker
            .write()
            .map_err(|e| RegistryError::Io(e.to_string()))?;
        self.save_to(&path)
    }

    /// Save the registry to a specific path atomically (temp + rename).
    pub fn save_to(&self, path: &Path) -> Result<(), RegistryError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RegistryError::Io(e.to_string()))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| RegistryError::Serialize(e.to_string()))?;

        // 0600 from the first byte (no umask window) via the shared
        // secret-file primitive: tmp name is random, symlink-safe.
        crate::secret_file::write_secret_file(path, json.as_bytes())
            .map_err(|e| RegistryError::Io(e.to_string()))?;

        Ok(())
    }

    /// Add a new vault to the registry.
    pub fn add(&mut self, entry: VaultEntry) -> Result<(), RegistryError> {
        validate_slug(&entry.slug).map_err(|e| RegistryError::InvalidSlug(e.to_string()))?;

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

    /// G24 device-local cache refresh (family-spaces step 7): record
    /// whether the merge ceiling was on at this unlock. Best-effort on
    /// the caller side; the cache must never block an unlock.
    pub fn set_merge_cache(&mut self, slug: &str, ceiling: bool) -> Result<(), RegistryError> {
        let Some(entry) = self.vaults.get_mut(slug) else {
            return Err(RegistryError::NotFound(slug.to_string()));
        };
        entry.merge_ceiling_seen = ceiling;
        Ok(())
    }

    /// The slug registered for a vault path, if any.
    pub fn slug_for_path(&self, path: &Path) -> Option<String> {
        self.vaults
            .values()
            .find(|e| e.path == path)
            .map(|e| e.slug.clone())
    }

    /// G24 eligibility for one registered vault, keyless: a personal
    /// vault is always eligible; a Space needs the cached ceiling from
    /// its last unlock here and no device-local opt-out.
    pub fn merge_eligible(&self, slug: &str) -> bool {
        let Some(entry) = self.vaults.get(slug) else {
            return false;
        };
        if entry.merge_opt_in == Some(false) {
            return false;
        }
        if !is_space_conservative(&entry.path) {
            return true;
        }
        entry.merge_ceiling_seen
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
            entry.last_opened = Some(now.as_secs());
        }
    }

    /// Discover orphaned vaults on disk that are missing from the registry.
    ///
    /// Scans the default vaults directory (`<data_dir>/vaults/*`) for
    /// subdirectories containing a `.baluard` marker. Any marker whose slug is
    /// not already in this registry is returned as a `VaultEntry`, ready to
    /// `add()`.
    ///
    /// `display_name` falls back to the slug (the human-friendly name lives in
    /// the encrypted `profile.enc`, only readable after unlock); the UI
    /// refreshes it once the vault is opened.
    /// Re-discover vault directories under the default vaults dir that no
    /// registry entry references. Recovery only runs when the registry file
    /// itself was lost or unreadable — a valid empty registry is a deliberate
    /// detach and is never re-populated (see `VaultHost::list`).
    ///
    /// Backup copies of a vault (e.g. `myslug.bak.<epoch>`) share the
    /// marker's slug with the real folder, so when a slug maps to several
    /// directories exactly one directory whose NAME equals the slug wins;
    /// if the choice stays ambiguous the slug is skipped rather than guessed.
    pub fn discover_orphans(&self) -> Vec<VaultEntry> {
        let vaults_dir = crate::paths::vaults_dir();
        let entries = match std::fs::read_dir(&vaults_dir) {
            Ok(rd) => rd,
            Err(_) => return Vec::new(), // dir missing — nothing to discover
        };
        // Group candidate directories by their resolved slug so backup copies
        // sharing a marker slug cannot win adoption by read_dir order.
        let mut by_slug: std::collections::BTreeMap<String, Vec<PathBuf>> =
            std::collections::BTreeMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Must be a real vault (has the marker).
            let marker = match BaluardMarker::read_from_vault(&path) {
                Ok(Some(m)) => m,
                _ => continue, // no marker or unreadable — skip
            };
            // Already registered? Skip.
            if self.vaults.contains_key(&marker.slug) {
                continue;
            }
            // Slug also derives from the dir name as a fallback; the marker
            // is authoritative.
            let slug = if marker.slug.is_empty() {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("vault")
                    .to_string()
            } else {
                marker.slug.clone()
            };
            by_slug.entry(slug).or_default().push(path);
        }
        let mut found = Vec::new();
        for (slug, mut paths) in by_slug {
            if paths.len() > 1 {
                // Copies present: the directory named exactly after the slug
                // is the live one; anything else is ambiguous, skip the slug.
                let slug_dir = format!("{slug}");
                paths.retain(|p| p.file_name().and_then(|n| n.to_str()) == Some(slug_dir.as_str()));
                if paths.len() != 1 {
                    continue;
                }
            }
            let path = paths.remove(0);
            let vault_id = BaluardMarker::read_from_vault(&path)
                .ok()
                .flatten()
                .map(|m| m.vault_id)
                .unwrap_or_default();
            found.push(VaultEntry {
                slug: slug.clone(),
                display_name: slug, // updated from profile.enc after first unlock
                path,
                provider: None,
                remote_url: None,
                last_synced: None,
                last_opened: None,
                vault_id,
                merge_opt_in: None,
                merge_ceiling_seen: false,
            });
        }
        found
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

/// Merge-eligibility classification that fails CLOSED on a damaged
/// settings-pub.json: an unreadable or unparseable shape flag counts as
/// a Space (merge needs the ceiling cache), never as a personal vault.
fn is_space_conservative(vault_path: &Path) -> bool {
    if crate::vault::space::read_purpose(vault_path) != crate::vault::space::SpacePurpose::Absent {
        return true;
    }
    if crate::vault::space_meta::shape_flipped(vault_path) {
        return true;
    }
    let flag_path = vault_path.join("meta/settings-pub.json");
    if !flag_path.exists() {
        return false;
    }
    // A VALID file with no "space" key is the normal personal-vault state;
    // an unreadable or unparseable file fails closed to Space.
    let Ok(data) = std::fs::read_to_string(&flag_path) else {
        return true;
    };
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(v) => v.get("space").and_then(|s| s.as_bool()).unwrap_or(false),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    /// Backup copies share the marker slug with the real folder; discovery
    /// must adopt the directory NAMED after the slug and skip the slug when
    /// the choice stays ambiguous (2026-11-11 Mac: a .bak copy was adopted
    /// over the real vault by read_dir order).
    #[test]
    fn discover_prefers_the_slug_named_directory_and_skips_ambiguity() {
        let _env = crate::test_support::lock_env();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var("BALUARD_DATA_DIR").ok();
        // SAFETY: serialized by the crate-shared env lock.
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", dir.path().to_string_lossy().to_string());
        }
        let vaults_dir = crate::paths::vaults_dir();
        std::fs::create_dir_all(&vaults_dir).unwrap();

        let write_marker = |p: &Path, slug: &str| {
            let marker = BaluardMarker {
                version: 1,
                vault_id: Uuid::new_v4(),
                slug: slug.to_string(),
            };
            std::fs::create_dir_all(p).unwrap();
            std::fs::write(p.join(".baluard"), serde_json::to_vec(&marker).unwrap()).unwrap();
        };
        write_marker(&vaults_dir.join("baluard-orph.bak.123"), "baluard-orph");
        write_marker(&vaults_dir.join("baluard-orph"), "baluard-orph");

        let reg = VaultRegistry::default();
        let found = reg.discover_orphans();
        assert_eq!(found.len(), 1, "one slug, one winner: {found:?}");
        assert_eq!(
            found[0].path.file_name().unwrap().to_str().unwrap(),
            "baluard-orph",
            "the slug-named directory must win over the backup copy"
        );

        // Ambiguous: two copies, neither named after the slug — skip, never
        // guess between backups.
        std::fs::remove_dir_all(vaults_dir.join("baluard-orph")).unwrap();
        write_marker(&vaults_dir.join("baluard-orph.copy2"), "baluard-orph");
        let found = VaultRegistry::default().discover_orphans();
        assert!(
            found.is_empty(),
            "an ambiguous slug must be skipped, not guessed: {found:?}"
        );

        // Restore the process env for sibling tests.
        unsafe {
            match &prev {
                Some(v) => std::env::set_var("BALUARD_DATA_DIR", v),
                None => std::env::remove_var("BALUARD_DATA_DIR"),
            }
        }
    }

    use super::*;

    // ── G24 merge eligibility (family-spaces step 7) ──

    fn entry_for(slug: &str, path: &Path) -> VaultEntry {
        VaultEntry {
            slug: slug.to_string(),
            display_name: slug.to_string(),
            path: path.to_path_buf(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
            merge_opt_in: None,
            merge_ceiling_seen: false,
        }
    }

    #[test]
    fn merge_eligibility_is_keyless_and_fails_closed() {
        let personal_dir = tempfile::tempdir().unwrap();
        let family_dir = tempfile::tempdir().unwrap();
        crate::vault::space::set_purpose(
            family_dir.path(),
            crate::vault::space::SpacePurpose::Family,
        )
        .unwrap();
        let mut reg = VaultRegistry::default();
        reg.add(entry_for("baluard-personal", personal_dir.path()))
            .unwrap();
        reg.add(entry_for("baluard-family", family_dir.path()))
            .unwrap();

        // A personal vault is always eligible, cache or not.
        assert!(reg.merge_eligible("baluard-personal"));
        // A settings-pub.json WITHOUT a space key is the normal personal
        // state, not a damaged flag (regression: the conservative read used
        // to classify every fresh vault as a Space and dead the search
        // fan-out).
        let fresh = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(fresh.path().join("meta")).unwrap();
        std::fs::write(
            fresh.path().join("meta/settings-pub.json"),
            r#"{"theme":"system","lang":"en"}"#,
        )
        .unwrap();
        reg.add(entry_for("baluard-fresh", fresh.path())).unwrap();
        assert!(reg.merge_eligible("baluard-fresh"));
        // A damaged (unparseable) flag file fails closed to Space.
        let damaged = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(damaged.path().join("meta")).unwrap();
        std::fs::write(damaged.path().join("meta/settings-pub.json"), "{not json").unwrap();
        reg.add(entry_for("baluard-dmg", damaged.path())).unwrap();
        assert!(!reg.merge_eligible("baluard-dmg"));
        // A Space never unlocked on this device has no cache: it fails
        // closed and never nags.
        assert!(!reg.merge_eligible("baluard-family"));
        // After an unlock observes the ceiling ON, the Space merges.
        reg.set_merge_cache("baluard-family", true).unwrap();
        assert!(reg.merge_eligible("baluard-family"));
        // The member's device-local opt-out wins over the ceiling.
        reg.vaults.get_mut("baluard-family").unwrap().merge_opt_in = Some(false);
        assert!(!reg.merge_eligible("baluard-family"));
        reg.vaults.get_mut("baluard-family").unwrap().merge_opt_in = None;
        // A later unlock observing the ceiling OFF (family flipped to
        // org semantics via the explicit knob) drops eligibility again.
        reg.set_merge_cache("baluard-family", false).unwrap();
        assert!(!reg.merge_eligible("baluard-family"));
        // Unknown slugs are simply ineligible.
        assert!(!reg.merge_eligible("ghost"));
    }

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
            merge_opt_in: None,
            merge_ceiling_seen: false,
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
            merge_opt_in: None,
            merge_ceiling_seen: false,
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

// ── Active Vault Resolution ──

/// Source of a resolved vault path. Used for daemon startup logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultSource {
    /// User passed `--vault-slug` and the slug was found in the registry.
    ExplicitSlug,
    /// User passed an explicit `--vault-path`. Registry was not consulted.
    ExplicitPath,
    /// Loaded from the registry's `active_vault` field on startup.
    RegistryActive,
    /// Registry's `active_vault` pointed at a slug that is no longer
    /// registered (vanished entry). Daemon falls back to `fallback_path`.
    /// The String is the missing slug, so the caller can log a precise
    /// diagnostic instead of a generic "no active vault" message.
    StaleActive(String),
    /// No resolution source found; using the fallback path.
    Fallback,
}

/// Vault path + the source that determined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVault {
    pub path: PathBuf,
    pub source: VaultSource,
    /// Slug if resolved from a slug (ExplicitSlug or RegistryActive), else None.
    pub slug: Option<String>,
}

impl std::fmt::Display for ResolvedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            VaultSource::ExplicitSlug => write!(
                f,
                "Serving vault from --vault-slug '{}' at {}",
                self.slug.as_deref().unwrap_or(""),
                self.path.display()
            ),
            VaultSource::ExplicitPath => {
                write!(
                    f,
                    "Serving vault from --vault-path at {}",
                    self.path.display()
                )
            }
            VaultSource::RegistryActive => write!(
                f,
                "Serving active vault '{}' from registry at {}",
                self.slug.as_deref().unwrap_or(""),
                self.path.display()
            ),
            VaultSource::StaleActive(stale_slug) => write!(
                f,
                "Registry active_vault '{}' is not present in the vault map \
                 (entry was removed or renamed). Falling back to {}. \
                 Run `baluard vaults switch <slug>` to repair.",
                stale_slug,
                self.path.display()
            ),
            VaultSource::Fallback => write!(
                f,
                "No active vault in registry, no --vault-slug, no --vault-path. \
                 Using fallback path {}. Create a vault with `baluard init` to register it.",
                self.path.display()
            ),
        }
    }
}

/// Failure modes for `resolve_active_vault`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `--vault-slug` was passed but the slug is not in the registry.
    UnknownSlug(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::UnknownSlug(s) => write!(f, "Vault '{s}' not found in registry"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolve which vault path the daemon should serve on startup.
///
/// Priority (highest first):
/// 1. `explicit_slug`: must be in the registry. Returns `UnknownSlug` if not.
/// 2. `explicit_path`: use as-is. Registry is not consulted.
/// 3. `registry.active_vault`: use that vault's path.
/// 4. `fallback_path`: last resort (e.g. the legacy `--vault-path` default).
///
/// "active_vault" pointing at a slug that no longer exists in `vaults`
/// is treated as unset and the resolver falls through to `fallback_path`.
/// Callers should log a warning in that case.
pub fn resolve_active_vault(
    explicit_slug: Option<&str>,
    explicit_path: Option<&Path>,
    registry: &VaultRegistry,
    fallback_path: &Path,
) -> Result<ResolvedVault, ResolveError> {
    if let Some(slug) = explicit_slug {
        return match registry.get(slug) {
            Some(entry) => Ok(ResolvedVault {
                path: entry.path.clone(),
                source: VaultSource::ExplicitSlug,
                slug: Some(slug.to_string()),
            }),
            None => Err(ResolveError::UnknownSlug(slug.to_string())),
        };
    }

    if let Some(path) = explicit_path {
        return Ok(ResolvedVault {
            path: path.to_path_buf(),
            source: VaultSource::ExplicitPath,
            slug: None,
        });
    }

    if let Some(active_slug) = registry.active_vault.as_deref() {
        if let Some(entry) = registry.get(active_slug) {
            return Ok(ResolvedVault {
                path: entry.path.clone(),
                source: VaultSource::RegistryActive,
                slug: Some(active_slug.to_string()),
            });
        }
        // active_vault points at a vanished entry. Surface the stale slug
        // in the source so the caller can log "active_vault 'X' not in
        // registry" instead of the generic "no active vault" message.
        return Ok(ResolvedVault {
            path: fallback_path.to_path_buf(),
            source: VaultSource::StaleActive(active_slug.to_string()),
            slug: Some(active_slug.to_string()),
        });
    }

    Ok(ResolvedVault {
        path: fallback_path.to_path_buf(),
        source: VaultSource::Fallback,
        slug: None,
    })
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn reg_with_active(slug: &str, path: &str) -> VaultRegistry {
        let mut reg = VaultRegistry::default();
        reg.add(VaultEntry {
            slug: slug.to_string(),
            display_name: slug.to_string(),
            path: PathBuf::from(path),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
            merge_opt_in: None,
            merge_ceiling_seen: false,
        })
        .unwrap();
        reg.set_active(slug).unwrap();
        reg
    }

    #[test]
    fn explicit_slug_takes_priority() {
        // Build a registry with two vaults. `baluard-personal` is the
        // active_vault, but the caller passes --vault-slug=work, which
        // must win.
        let mut combined = VaultRegistry::default();
        for slug in ["baluard-personal", "work"] {
            combined
                .add(VaultEntry {
                    slug: slug.to_string(),
                    display_name: slug.to_string(),
                    path: PathBuf::from(format!("/{slug}")),
                    provider: None,
                    remote_url: None,
                    last_synced: None,
                    last_opened: None,
                    vault_id: Uuid::new_v4(),
                    merge_opt_in: None,
                    merge_ceiling_seen: false,
                })
                .unwrap();
        }
        combined.set_active("baluard-personal").unwrap();

        let r = resolve_active_vault(
            Some("work"),
            Some(Path::new("/ignored")),
            &combined,
            Path::new("/fallback"),
        )
        .unwrap();
        assert_eq!(r.source, VaultSource::ExplicitSlug);
        assert_eq!(r.path, PathBuf::from("/work"));
        assert_eq!(r.slug.as_deref(), Some("work"));
    }

    #[test]
    fn explicit_slug_not_in_registry_errors() {
        let reg = reg_with_active("baluard-personal", "/active/path");
        let err =
            resolve_active_vault(Some("nope"), None, &reg, Path::new("/fallback")).unwrap_err();
        assert_eq!(err, ResolveError::UnknownSlug("nope".to_string()));
    }

    #[test]
    fn explicit_path_used_when_no_slug() {
        let reg = reg_with_active("baluard-personal", "/active/path");
        let r = resolve_active_vault(
            None,
            Some(Path::new("/custom/path")),
            &reg,
            Path::new("/fallback"),
        )
        .unwrap();
        assert_eq!(r.source, VaultSource::ExplicitPath);
        assert_eq!(r.path, PathBuf::from("/custom/path"));
        assert!(r.slug.is_none());
    }

    #[test]
    fn explicit_path_overrides_active_vault() {
        // When --vault-path is given, the active_vault is ignored.
        let reg = reg_with_active("baluard-personal", "/active/path");
        let r = resolve_active_vault(
            None,
            Some(Path::new("/explicit")),
            &reg,
            Path::new("/fallback"),
        )
        .unwrap();
        assert_eq!(r.source, VaultSource::ExplicitPath);
        assert_eq!(r.path, PathBuf::from("/explicit"));
    }

    #[test]
    fn registry_active_used_when_no_flags() {
        let reg = reg_with_active("baluard-personal", "/active/path");
        let r = resolve_active_vault(None, None, &reg, Path::new("/fallback")).unwrap();
        assert_eq!(r.source, VaultSource::RegistryActive);
        assert_eq!(r.path, PathBuf::from("/active/path"));
        assert_eq!(r.slug.as_deref(), Some("baluard-personal"));
    }

    #[test]
    fn no_active_vault_falls_back() {
        // Registry exists but no active_vault set.
        let mut reg = VaultRegistry::default();
        reg.add(VaultEntry {
            slug: "baluard-personal".to_string(),
            display_name: "x".into(),
            path: PathBuf::from("/some/path"),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
            merge_opt_in: None,
            merge_ceiling_seen: false,
        })
        .unwrap();
        // No set_active call.
        let r = resolve_active_vault(None, None, &reg, Path::new("/fallback")).unwrap();
        assert_eq!(r.source, VaultSource::Fallback);
        assert_eq!(r.path, PathBuf::from("/fallback"));
    }

    #[test]
    fn empty_registry_falls_back() {
        let reg = VaultRegistry::default();
        let r = resolve_active_vault(None, None, &reg, Path::new("/fallback")).unwrap();
        assert_eq!(r.source, VaultSource::Fallback);
        assert_eq!(r.path, PathBuf::from("/fallback"));
    }

    #[test]
    fn active_vault_pointing_to_vanished_entry_yields_stale_source() {
        // active_vault set to a slug not in vaults map (data inconsistency).
        // The resolver must surface this as StaleActive so the caller can
        // log a precise diagnostic instead of a generic fallback message.
        let reg = VaultRegistry {
            active_vault: Some("ghost".to_string()),
            ..VaultRegistry::default()
        };
        let r = resolve_active_vault(None, None, &reg, Path::new("/fallback")).unwrap();
        assert_eq!(r.source, VaultSource::StaleActive("ghost".to_string()));
        assert_eq!(r.path, PathBuf::from("/fallback"));
        assert_eq!(r.slug.as_deref(), Some("ghost"));
    }

    #[test]
    fn unknown_slug_error_displays_human_message() {
        let err = ResolveError::UnknownSlug("my-vault".to_string());
        assert_eq!(err.to_string(), "Vault 'my-vault' not found in registry");
    }
}
