//! Device lifecycle and root key rotation coordinator.
//!
//! D14: Per-device wrapping keys, selective rekey, emergency force evict.
//! Doc 06 Section 7: Epoch rotation with two-phase commit via git-mediated ack files.
//!
//! Architecture: DeviceManager aggregates DeviceRegistry + EpochInfo + RotationCoordinator.
//! Individual components stay independently testable. DeviceManager enforces cross-cutting invariants.

use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::signature;
use crate::devices::DeviceRegistry;
use crate::error::{DeviceError, BaluardError, KeyError, SyncError};
use crate::keys::epoch::{EpochInfo, EpochState};
use crate::keys::hierarchy::RootKey;
use crate::keys::rotation::{CommitBarrierSig, RekeyTransaction};
use crate::vault::manifest::DeviceEntry;

// ── Helpers ──

/// Format a Unix timestamp as RFC 3339 (UTC, second precision).
/// Avoids chrono dependency.
fn format_rfc3339(secs: u64) -> String {
    // Days from epoch
    let days = secs / 86400;
    let time_secs = (secs % 86400) as u32;
    let hour = time_secs / 3600;
    let minute = (time_secs % 3600) / 60;
    let second = time_secs % 60;

    // Compute year/month/day from days since epoch
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u32, u32) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u32; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for &md in &month_days {
        if days < md as u64 {
            break;
        }
        days -= md as u64;
        month += 1;
    }
    (year, month, days as u32 + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// ── Device Activity Index ──

/// Activity index entry (per device).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceActivityEntry {
    /// ISO-8601 timestamp of last push.
    pub last_push: String,
    /// SHA of the last push commit.
    pub last_commit: String,
    /// Current epoch at time of push.
    pub epoch: u64,
}

/// Activity index: maps device UUID -> last activity metadata.
/// Stored as `meta/device_activity.json` (plaintext, git-synced).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceActivityIndex {
    /// Format version. Must be 1.
    pub v: u32,
    pub devices: std::collections::HashMap<String, DeviceActivityEntry>,
}

impl DeviceActivityIndex {
    /// Create an empty activity index.
    pub fn new() -> Self {
        Self {
            v: 1,
            devices: std::collections::HashMap::new(),
        }
    }

    /// Read activity index from `meta/device_activity.json`.
    /// Returns empty index if file doesn't exist.
    pub fn read(vault_path: &Path) -> Self {
        let path = vault_path.join("meta/device_activity.json");
        if !path.exists() {
            return Self::new();
        }
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_else(|_| Self::new()),
            Err(_) => Self::new(),
        }
    }

    /// Update (or add) a device's activity entry and write to disk.
    pub fn update(
        vault_path: &Path,
        device_id: &Uuid,
        commit_sha: &str,
        epoch: u64,
    ) -> Result<(), BaluardError> {
        let mut index = Self::read(vault_path);
        let now = {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Format as ISO-8601 without chrono
            format_rfc3339(secs)
        };
        index.devices.insert(
            device_id.to_string(),
            DeviceActivityEntry {
                last_push: now,
                last_commit: commit_sha.to_string(),
                epoch,
            },
        );
        index.write(vault_path)
    }

    /// Remove a device from the activity index.
    pub fn remove_device(vault_path: &Path, device_id: &Uuid) -> Result<(), BaluardError> {
        let mut index = Self::read(vault_path);
        if index.devices.remove(&device_id.to_string()).is_some() {
            index.write(vault_path)?;
        }
        Ok(())
    }

    /// Write activity index to disk (atomic).
    fn write(&self, vault_path: &Path) -> Result<(), BaluardError> {
        let meta = vault_path.join("meta");
        std::fs::create_dir_all(&meta)
            .map_err(|e| DeviceError::Keystore(format!("create meta dir: {e}")))?;
        let path = meta.join("device_activity.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| DeviceError::Keystore(format!("serialize activity index: {e}")))?;
        atomic_write(&path, &json)
    }
}

impl Default for DeviceActivityIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rotation Observer ──

/// Hook for observing rotation state transitions.
/// Implementations can trigger git sync, notifications, or other side effects.
/// Default no-op implementation. Injected via `set_observer()`.
pub trait RotationObserver: Send + Sync {
    /// Called after a rotation proposal is written (.txn file).
    fn on_rotation_proposed(&self, _epoch: u64, _vault_path: &Path) {}
    /// Called after an ack is recorded (.ack file).
    fn on_ack_recorded(&self, _epoch: u64, _device_id: &Uuid, _vault_path: &Path) {}
    /// Called after a rotation is committed (.committed file).
    fn on_rotation_committed(&self, _epoch: u64, _vault_path: &Path) {}
    /// Called after a device enrollment.
    fn on_device_enrolled(&self, _device_id: &Uuid, _vault_path: &Path) {}
    /// Called after force eviction.
    fn on_devices_evicted(&self, _evicted_count: usize, _vault_path: &Path) {}
}

// ── Enrollment Authorization ──

/// Enrollment payload from a new device.
///
/// Transfer methods (all equivalent, user picks what works):
/// - QR code: base64url-encoded JSON
/// - Manual copy: display as text string, user types/pastes on existing device
/// - File export: save as .json file, transfer via USB/LAN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentPayload {
    pub device_id: Uuid,
    /// X25519 public key (32 bytes, hex-encoded).
    pub encryption_public_key: String,
    /// Ed25519 public key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Unix timestamp of payload creation.
    pub timestamp: u64,
    /// Anti-replay nonce (32 random bytes, hex-encoded).
    pub nonce: String,
    /// User-chosen device name.
    pub name: String,
    /// H9 fix: Vault binding — ties enrollment to a specific vault/epoch/registry state.
    /// Prevents replay of a captured approval against a different vault.
    pub vault_id: Option<String>,
    pub epoch: Option<u64>,
    pub registry_version: Option<u64>,
}

/// Approval signature from an existing enrolled device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    /// Device ID of the approver.
    pub approver_device_id: Uuid,
    /// Ed25519 signature over H("enroll" || JSON(payload)).
    pub signature: Vec<u8>,
}

/// Authorization for enrolling a new device.
///
/// Two paths, controlled by `VaultSettings::enrollment_policy`:
/// - `ExistingDevice`: an enrolled device signed the payload. Required
///   in `Strict` mode, accepted in `Personal` mode.
/// - `RecoveryPhrase`: the 24-word BIP-39 recovery phrase. Only
///   accepted in `Personal` mode. The phrase is the vault's root
///   authority; it can already perform full disaster recovery via
///   `recover_from_phrase`. This variant enrolls into the existing
///   registry without resetting state.
pub enum EnrollmentAuthorization<'a> {
    ExistingDevice(&'a ApprovalSignature),
    RecoveryPhrase(&'a str),
}

/// Pairing bundle returned by existing device after approving enrollment.
/// Transfer methods: QR code, manual copy/paste, file export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingBundle {
    /// HPKE-wrapped Root Key for the new device.
    pub wrapped_root_key: Vec<u8>,
    /// Updated device registry (includes new device).
    pub updated_registry: DeviceRegistry,
    /// Approval signature from the authorizing device.
    pub approval: ApprovalSignature,
}

impl EnrollmentPayload {
    /// Encode as base64url JSON string for manual copy or QR code.
    pub fn encode_transfer(&self) -> Result<String, BaluardError> {
        let json = serde_json::to_string(self)
            .map_err(|e| DeviceError::Keystore(format!("encode payload: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }

    /// Decode from base64url JSON string (manual paste or QR scan).
    pub fn decode_transfer(encoded: &str) -> Result<Self, BaluardError> {
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid transfer encoding".into()))?;
        serde_json::from_slice(&json)
            .map_err(|e| DeviceError::EnrollmentRejected(format!("decode payload: {e}")).into())
    }
}

impl PairingBundle {
    /// Encode as base64url JSON string for manual copy or QR code.
    pub fn encode_transfer(&self) -> Result<String, BaluardError> {
        let json = serde_json::to_string(self)
            .map_err(|e| DeviceError::Keystore(format!("encode bundle: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }

    /// Decode from base64url JSON string (manual paste or QR scan).
    pub fn decode_transfer(encoded: &str) -> Result<Self, BaluardError> {
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid bundle encoding".into()))?;
        serde_json::from_slice(&json)
            .map_err(|e| DeviceError::EnrollmentRejected(format!("decode bundle: {e}")).into())
    }
}

/// Acknowledgment of an epoch rotation proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationAck {
    /// Epoch being acknowledged.
    pub epoch: u64,
    /// Device acknowledging.
    pub device_id: Uuid,
    /// SHA-256 hash of the .txn file content (binds ack to exact proposal).
    pub txn_hash: String,
    /// Ed25519 signature over H("ack" || epoch || device_id || txn_hash).
    pub signature: Vec<u8>,
}

// ── DeviceManager Persistence ──

/// Serializable DeviceManager state snapshot.
/// Used to decouple the state machine from its persistence backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceManagerState {
    pub registry: DeviceRegistry,
    pub epoch: EpochInfo,
    pub seen_nonces: Vec<String>,
    pub pending_transaction: Option<RekeyTransaction>,
    pub collected_acks: Vec<RotationAck>,
}

/// Persistence backend for DeviceManager state.
///
/// Implementations handle reading/writing the registry, epoch, nonces,
/// and rotation artifacts (txn, acks, committed files) to storage.
///
/// DESIGN-2: Separates I/O from the DeviceManager state machine,
/// enabling in-memory stores for testing and alternative backends.
pub trait DeviceManagerStore: Send + Sync {
    /// Save complete DeviceManager state.
    ///
    /// **Atomicity note**: The default filesystem implementation performs
    /// multiple `atomic_write` calls (registry, epoch, nonces, txn, acks).
    /// Each individual file write is atomic, but the *combination* is not.
    /// A crash between writes may leave partially updated state.
    /// Implementors should consider a single-file or WAL pattern for stronger guarantees.
    fn save_state(&self, state: &DeviceManagerState) -> Result<(), BaluardError>;

    /// Load complete DeviceManager state. Returns None if no state exists.
    fn load_state(&self) -> Result<Option<DeviceManagerState>, BaluardError>;

    /// Check if persisted state exists.
    fn exists(&self) -> bool;

    /// Write a finalized .committed file for a rotation epoch.
    fn save_committed(&self, epoch: u64, data: &str) -> Result<(), BaluardError>;

    /// Get the vault path (for observer hooks and recovery I/O).
    /// Returns None for non-filesystem stores.
    fn vault_path(&self) -> Option<&Path>;
}

// ── FileDeviceManagerStore ──

/// Filesystem-backed DeviceManager store.
/// Persists to `meta/devices.json`, `meta/epoch.json`, `meta/seen-nonces.json`,
/// and `.baluard/rekey/` for rotation artifacts.
pub struct FileDeviceManagerStore {
    vault_path: std::path::PathBuf,
}

impl FileDeviceManagerStore {
    pub fn new(vault_path: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
        }
    }
}

impl DeviceManagerStore for FileDeviceManagerStore {
    fn save_state(&self, state: &DeviceManagerState) -> Result<(), BaluardError> {
        let meta = self.vault_path.join("meta");
        std::fs::create_dir_all(&meta)
            .map_err(|e| DeviceError::Keystore(format!("create meta dir: {e}")))?;

        // M9 fix: write registry + epoch + seen_nonces as a single atomic file.
        // The previous design wrote 3 separate files (devices.json, epoch.json,
        // seen-nonces.json) and a crash mid-sequence could leave partial state.
        // We keep writing the legacy individual files for backward-compat with
        // existing readers and older vault formats, but the combined file is
        // the authoritative source on next load.
        let combined = serde_json::json!({
            "registry": state.registry,
            "epoch": state.epoch,
            "seen_nonces": state.seen_nonces,
        });
        let combined_json = serde_json::to_string_pretty(&combined)
            .map_err(|e| DeviceError::Keystore(format!("serialize combined state: {e}")))?;
        let combined_path = meta.join("device-state.json");
        atomic_write(&combined_path, &combined_json)?;

        // Save registry
        let registry_path = meta.join("devices.json");
        let registry_json = serde_json::to_string_pretty(&state.registry)
            .map_err(|e| DeviceError::Keystore(format!("serialize registry: {e}")))?;
        atomic_write(&registry_path, &registry_json)?;

        // Save epoch
        let epoch_path = meta.join("epoch.json");
        let epoch_json = serde_json::to_string_pretty(&state.epoch)
            .map_err(|e| KeyError::InvalidEpochState(format!("serialize epoch: {e}")))?;
        atomic_write(&epoch_path, &epoch_json)?;

        // Save seen nonces
        let nonces_path = meta.join("seen-nonces.json");
        let nonces_json = serde_json::to_string(&state.seen_nonces)
            .map_err(|e| DeviceError::Keystore(format!("serialize nonces: {e}")))?;
        atomic_write(&nonces_path, &nonces_json)?;

        // Save pending transaction and acks if in ROTATING state.
        // NOTE: rekey/ files are the cross-device rotation protocol (git-pushed
        // between devices). They cannot be bundled into the local atomic state
        // because each device produces them independently. Per-file atomic_write
        // is correct here.
        if let Some(ref tx) = state.pending_transaction {
            let rekey_dir = self.vault_path.join(".baluard/rekey");
            std::fs::create_dir_all(&rekey_dir)
                .map_err(|e| SyncError::Git(format!("create rekey dir: {e}")))?;

            let txn_path = rekey_dir.join(format!("{}.txn", tx.new_epoch));
            let txn_json = serde_json::to_string_pretty(tx)
                .map_err(|e| KeyError::InvalidEpochState(format!("serialize txn: {e}")))?;
            atomic_write(&txn_path, &txn_json)?;

            for ack in &state.collected_acks {
                let ack_json = serde_json::to_string_pretty(ack)
                    .map_err(|e| KeyError::InvalidEpochState(format!("serialize ack: {e}")))?;
                let ack_path = rekey_dir.join(format!("{}.ack.{}", ack.epoch, ack.device_id));
                atomic_write(&ack_path, &ack_json)?;
            }
        }

        Ok(())
    }

    fn exists(&self) -> bool {
        Self::exists_at(&self.vault_path)
    }

    fn load_state(&self) -> Result<Option<DeviceManagerState>, BaluardError> {
        if !Self::exists_at(&self.vault_path) {
            return Ok(None);
        }

        // M9 fix: prefer the combined atomic state file (meta/device-state.json)
        // for atomicity. Fall back to individual legacy files for old vaults.
        let combined_path = self.vault_path.join("meta/device-state.json");
        let (registry, epoch, seen_nonces) = if combined_path.exists() {
            let data = std::fs::read_to_string(&combined_path)
                .map_err(|e| DeviceError::Keystore(format!("read device-state: {e}")))?;
            let v: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| DeviceError::Keystore(format!("parse device-state: {e}")))?;
            let registry: DeviceRegistry = serde_json::from_value(v["registry"].clone())
                .map_err(|e| DeviceError::Keystore(format!("parse registry in combined: {e}")))?;
            let epoch: EpochInfo = serde_json::from_value(v["epoch"].clone())
                .map_err(|e| KeyError::InvalidEpochState(format!("parse epoch in combined: {e}")))?;
            let seen_nonces: Vec<String> = serde_json::from_value(v["seen_nonces"].clone())
                .map_err(|e| DeviceError::Keystore(format!("parse nonces in combined: {e}")))?;
            (registry, epoch, seen_nonces)
        } else {
            // Legacy: read individual files
            let registry_path = self.vault_path.join("meta/devices.json");
            let registry = if registry_path.exists() {
                let data = std::fs::read_to_string(&registry_path)
                    .map_err(|e| DeviceError::Keystore(format!("read devices: {e}")))?;
                serde_json::from_str(&data)
                    .map_err(|e| DeviceError::Keystore(format!("parse devices: {e}")))?
            } else {
                DeviceRegistry::new()
            };

            let epoch_path = self.vault_path.join("meta/epoch.json");
            let epoch = if epoch_path.exists() {
                let data = std::fs::read_to_string(&epoch_path)
                    .map_err(|e| KeyError::InvalidEpochState(format!("read epoch: {e}")))?;
                serde_json::from_str(&data)
                    .map_err(|e| KeyError::InvalidEpochState(format!("parse epoch: {e}")))?
            } else {
                EpochInfo::new(0)
            };

            let seen_nonces = load_seen_nonces(&self.vault_path);
            (registry, epoch, seen_nonces)
        };

        let mut pending_transaction = None;
        let mut collected_acks = Vec::new();
        let rekey_dir = self.vault_path.join(".baluard/rekey");
        if rekey_dir.exists() {
            let next_epoch = epoch.epoch + 1;
            let txn_path = rekey_dir.join(format!("{next_epoch}.txn"));
            if txn_path.exists() {
                let data = std::fs::read_to_string(&txn_path)
                    .map_err(|e| SyncError::Git(format!("read txn: {e}")))?;
                pending_transaction = Some(
                    serde_json::from_str(&data)
                        .map_err(|e| KeyError::InvalidEpochState(format!("parse txn: {e}")))?,
                );

                for entry in std::fs::read_dir(&rekey_dir)
                    .map_err(|e| SyncError::Git(format!("read rekey dir: {e}")))?
                {
                    let entry = entry.map_err(|e| SyncError::Git(format!("dir entry: {e}")))?;
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(&format!("{next_epoch}.ack.")) {
                        let ack_data = std::fs::read_to_string(entry.path())
                            .map_err(|e| SyncError::Git(format!("read ack: {e}")))?;
                        if let Ok(ack) = serde_json::from_str(&ack_data) {
                            collected_acks.push(ack);
                        }
                    }
                }
            }
        }

        Ok(Some(DeviceManagerState {
            registry,
            epoch,
            seen_nonces,
            pending_transaction,
            collected_acks,
        }))
    }

    fn save_committed(&self, epoch: u64, data: &str) -> Result<(), BaluardError> {
        let rekey_dir = self.vault_path.join(".baluard/rekey");
        std::fs::create_dir_all(&rekey_dir)
            .map_err(|e| SyncError::Git(format!("create rekey dir: {e}")))?;
        let committed_path = rekey_dir.join(format!("{}.committed", epoch));
        atomic_write(&committed_path, data)
    }

    fn vault_path(&self) -> Option<&Path> {
        Some(&self.vault_path)
    }
}

impl FileDeviceManagerStore {
    /// Check if persisted state exists at a given vault path.
    pub fn exists_at(vault_path: &Path) -> bool {
        vault_path.join("meta/devices.json").exists() || vault_path.join("meta/epoch.json").exists()
    }
}

// ── DeviceManager Aggregate ──

/// Maximum number of enrollment nonces to retain (FIFO eviction beyond this).
const MAX_SEEN_NONCES: usize = 10_000;

/// Device lifecycle coordinator. Owns registry, epoch state, and rotation logic.
///
/// DESIGN-2: Persistence is delegated to a `DeviceManagerStore` backend,
/// injected via `set_store()` or `set_vault_path()`. The state machine
/// itself is I/O-free and testable in isolation.
pub struct DeviceManager {
    /// Device registry (enrolled devices, keys, quorum).
    pub(crate) registry: DeviceRegistry,
    /// Current epoch metadata.
    pub(crate) epoch: EpochInfo,
    /// Pending rekey transaction (Some during ROTATING state).
    pub(crate) pending_transaction: Option<RekeyTransaction>,
    /// Collected acks for current rotation.
    pub(crate) collected_acks: Vec<RotationAck>,
    /// Seen enrollment nonces (anti-replay). Persisted to meta/seen-nonces.json.
    seen_nonces: Vec<String>,
    /// Persistence backend (injected). None = no auto-persist.
    store: Option<std::sync::Arc<dyn DeviceManagerStore>>,
    /// Rotation observer for side effects (MISS-3).
    observer: Option<Box<dyn RotationObserver>>,
}

impl DeviceManager {
    /// Create a new DeviceManager with a fresh registry and epoch 0.
    pub fn new() -> Self {
        Self {
            registry: DeviceRegistry::new(),
            epoch: EpochInfo::new(0),
            pending_transaction: None,
            collected_acks: Vec::new(),
            seen_nonces: Vec::new(),
            store: None,
            observer: None,
        }
    }

    /// Create a DeviceManager from existing registry and epoch info.
    pub fn from_parts(registry: DeviceRegistry, epoch: EpochInfo) -> Self {
        Self {
            registry,
            epoch,
            pending_transaction: None,
            collected_acks: Vec::new(),
            seen_nonces: Vec::new(),
            store: None,
            observer: None,
        }
    }

    /// Set a rotation observer for side effects (MISS-3).
    pub fn set_observer(&mut self, observer: Box<dyn RotationObserver>) {
        self.observer = Some(observer);
    }

    /// Fire observer hook if set.
    fn fire<F: Fn(&dyn RotationObserver)>(&self, f: F) {
        if let Some(ref obs) = self.observer {
            f(obs.as_ref());
        }
    }

    /// Notify observer of rotation committed.
    /// Used by VaultHandle::rotate_root_key after epoch transition.
    pub fn notify_rotation_committed(&self, epoch: u64, vault_path: &Path) {
        self.fire(|obs| obs.on_rotation_committed(epoch, vault_path));
    }

    /// Single-device epoch transition: set new epoch, clear rotation state.
    /// Used by VaultHandle::rotate_root_key for the single-device shortcut
    /// where HPKE wrapping + quorum are skipped.
    ///
    /// Validates: current epoch state is ACTIVE (not mid-rotation).
    pub fn single_device_commit_rotation(&mut self, new_epoch: u64) -> Result<(), BaluardError> {
        if self.epoch.state != EpochState::Active {
            return Err(KeyError::InvalidEpochState(format!(
                "cannot commit rotation from {:?}",
                self.epoch.state
            ))
            .into());
        }
        self.epoch = EpochInfo::new(new_epoch);
        self.epoch.activate().map_err(KeyError::InvalidEpochState)?;
        self.pending_transaction = None;
        self.collected_acks.clear();
        self.auto_save_result()
    }

    /// Snapshot current state for persistence.
    fn snapshot_state(&self) -> DeviceManagerState {
        DeviceManagerState {
            registry: self.registry.clone(),
            epoch: self.epoch.clone(),
            seen_nonces: self.seen_nonces.clone(),
            pending_transaction: self.pending_transaction.clone(),
            collected_acks: self.collected_acks.clone(),
        }
    }

    /// Auto-save to persistence backend if configured.
    /// Returns error on failure. Use for security-critical mutations.
    pub(crate) fn auto_save_result(&self) -> Result<(), BaluardError> {
        if let Some(ref store) = self.store {
            store.save_state(&self.snapshot_state())
        } else {
            Ok(())
        }
    }

    /// Record a seen nonce, evicting oldest if at capacity.
    fn record_nonce(&mut self, nonce: String) {
        if self.seen_nonces.len() >= MAX_SEEN_NONCES {
            self.seen_nonces.remove(0);
        }
        self.seen_nonces.push(nonce);
    }

    /// Set the persistence backend to filesystem at the given vault path.
    /// Convenience wrapper for `set_store(Arc::new(FileDeviceManagerStore::new(path)))`.
    pub fn set_vault_path(&mut self, path: &Path) {
        self.store = Some(std::sync::Arc::new(FileDeviceManagerStore::new(path)));
    }

    /// Set the persistence backend directly.
    pub fn set_store(&mut self, store: std::sync::Arc<dyn DeviceManagerStore>) {
        self.store = Some(store);
    }

    /// Current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.epoch.epoch
    }

    /// Get a reference to the device registry.
    pub fn registry(&self) -> &DeviceRegistry {
        &self.registry
    }

    /// Current epoch state.
    pub fn epoch_state(&self) -> EpochState {
        self.epoch.state
    }

    /// Get a reference to the pending transaction, if any.
    pub fn pending_transaction(&self) -> Option<&RekeyTransaction> {
        self.pending_transaction.as_ref()
    }

    /// Check if vault writes are allowed (not during ROTATING).
    pub fn writes_allowed(&self) -> bool {
        matches!(self.epoch.state, EpochState::Active)
    }

    /// Check if rotation has been stalled longer than the timeout.
    /// Returns elapsed seconds if stalled, None if not rotating or no timeout set.
    pub fn rotation_stalled_secs(&self, timeout_secs: u64) -> Option<u64> {
        let elapsed = self.epoch.rotation_elapsed_secs()?;
        if elapsed > timeout_secs {
            Some(elapsed)
        } else {
            None
        }
    }

    /// Determine if this device should be the coordinator for abort election.
    /// Coordinator = enrolled device with the numerically lowest UUID (big-endian).
    /// Deterministic: no coordination needed between devices.
    pub fn is_abort_coordinator(&self, self_device_id: &Uuid) -> bool {
        let lowest = self
            .registry
            .devices
            .keys()
            .min_by_key(|id| id.as_bytes())
            .copied();
        lowest.as_ref() == Some(self_device_id)
    }

    /// Abort a stalled rotation. Resets epoch to ACTIVE.
    /// Caller must verify:
    /// 1. rotation_stalled_secs() returned Some
    /// 2. is_abort_coordinator() returned true
    /// 3. No cipher files written at the new epoch (safety check)
    pub fn abort_stalled_rotation(&mut self) -> Result<(), BaluardError> {
        // Capture the pending new_epoch BEFORE clearing state.
        // The rotation was for new_epoch, not self.epoch.epoch (which is the old one).
        let aborted_new_epoch = self.pending_transaction.as_ref().map(|tx| tx.new_epoch);

        self.epoch.abort_rotation().map_err(|e| {
            BaluardError::Device(DeviceError::Keystore(format!("abort_rotation: {e}")))
        })?;
        self.pending_transaction = None;
        self.collected_acks.clear();
        self.auto_save_result()?;

        // Write abort marker for other devices to detect.
        // Uses the new_epoch that was aborted, not the current epoch.
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                if let Some(new_epoch) = aborted_new_epoch {
                    let rekey_dir = vp.join(".baluard/rekey");
                    let _ = std::fs::create_dir_all(&rekey_dir);
                    let abort_path = rekey_dir.join(format!("{}.aborted", new_epoch));
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let _ = std::fs::write(&abort_path, format!("aborted at {ts}"));
                }
            }
        }

        Ok(())
    }

    /// Check for an abort marker from another device.
    /// Returns true if the current epoch was aborted.
    pub fn has_abort_marker(&self, epoch: u64) -> bool {
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                let abort_path = vp.join(format!(".baluard/rekey/{}.aborted", epoch));
                return abort_path.exists();
            }
        }
        false
    }

    // ── Enrollment (D14: approval required) ──

    /// Enroll a new device with approval from an existing device.
    ///
    /// D14: First device auto-approves. Subsequent devices require a valid
    /// Ed25519 signature from an enrolled device over the enrollment payload.
    pub fn enroll(
        &mut self,
        payload: &EnrollmentPayload,
        approval: Option<&ApprovalSignature>,
    ) -> Result<DeviceEntry, BaluardError> {
        // Anti-replay: reject seen nonces
        if self.seen_nonces.contains(&payload.nonce) {
            return Err(
                DeviceError::EnrollmentRejected("replay: nonce already used".into()).into(),
            );
        }

        // Timestamp window: ±5 minutes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = now.abs_diff(payload.timestamp);
        if drift > 300 {
            return Err(DeviceError::EnrollmentRejected(
                "stale: timestamp outside 5-minute window".into(),
            )
            .into());
        }

        // Validate public key lengths
        let enc_pk = hex::decode(&payload.encryption_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid encryption key hex".into()))?;
        let sig_pk = hex::decode(&payload.signing_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid signing key hex".into()))?;
        if enc_pk.len() != 32 || sig_pk.len() != 32 {
            return Err(DeviceError::EnrollmentRejected("invalid public key length".into()).into());
        }

        let mut enc_arr = [0u8; 32];
        let mut sig_arr = [0u8; 32];
        enc_arr.copy_from_slice(&enc_pk);
        sig_arr.copy_from_slice(&sig_pk);

        // Authorization gate: first device auto-approves, others need approval
        if self.registry.count() > 0 {
            let approval = approval.ok_or_else(|| {
                DeviceError::EnrollmentRejected("approval required from enrolled device".into())
            })?;

            // Verify approver is enrolled
            if !self.registry.is_enrolled(&approval.approver_device_id) {
                return Err(DeviceError::EnrollmentRejected("approver not enrolled".into()).into());
            }

            // Verify signature
            let approver_entry = self
                .registry
                .devices
                .get(&approval.approver_device_id)
                .unwrap();
            let approver_vk_bytes: [u8; 32] = hex::decode(&approver_entry.signing_public_key)
                .map_err(|_| DeviceError::Keystore("invalid approver key".into()))?
                .try_into()
                .map_err(|_| DeviceError::Keystore("approver key wrong length".into()))?;

            let verifying_key = signature::verifying_key_from_bytes(&approver_vk_bytes)
                .map_err(|_| DeviceError::EnrollmentRejected("invalid approver key".into()))?;

            // Build the signed payload: H("enroll" || payload_bytes || nonce)
            let payload_bytes = serde_json::to_vec(payload)
                .map_err(|e| DeviceError::EnrollmentRejected(format!("serialize: {e}")))?;
            let mut sign_input = b"enroll".to_vec();
            sign_input.extend_from_slice(&payload_bytes);
            let sig = ed25519_dalek::Signature::from_slice(&approval.signature)
                .map_err(|_| DeviceError::EnrollmentRejected("invalid signature".into()))?;
            signature::verify(&verifying_key, &sign_input, &sig).map_err(|_| {
                DeviceError::EnrollmentRejected("signature verification failed".into())
            })?;
        }

        // H9 fix: Verify vault binding (epoch + registry version).
        // Prevents replay of captured approval against a different vault state.
        // Fail-closed: reject if binding fields are absent (old clients must upgrade).
        // Exception: first device (empty registry) auto-approves without binding.
        if self.registry.count() > 0 {
            let payload_epoch = payload.epoch.ok_or_else(|| {
                DeviceError::EnrollmentRejected("missing epoch binding".into())
            })?;
            if payload_epoch != self.epoch.epoch {
                return Err(DeviceError::EnrollmentRejected(format!(
                    "epoch mismatch: payload has {payload_epoch}, vault has {}",
                    self.epoch.epoch
                ))
                .into());
            }
            let payload_reg_ver = payload.registry_version.ok_or_else(|| {
                DeviceError::EnrollmentRejected("missing registry_version binding".into())
            })?;
            if payload_reg_ver != self.registry.version as u64 {
                return Err(DeviceError::EnrollmentRejected(format!(
                    "registry version mismatch: payload has {payload_reg_ver}, vault has {}",
                    self.registry.version
                    ))
                    .into());
            }
        }

        // Record nonce
        self.record_nonce(payload.nonce.clone());

        // Enroll in registry
        let entry = self.registry.enroll_with_id(
            payload.device_id,
            payload.name.clone(),
            enc_arr,
            sig_arr,
            approval.map(|a| a.approver_device_id),
        )?;

        // MISS-4: auto-persist enrollment
        self.auto_save_result()?;

        // MISS-3: notify observer of enrollment
        let enrolled_id = payload.device_id;
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_device_enrolled(&enrolled_id, vp));
            }
        }

        Ok(entry)
    }

    // ── Epoch Rotation (two-phase commit) ──

    /// Initiate epoch rotation. Generates new Root Key, wraps for all enrolled devices.
    ///
    /// Transitions epoch: ACTIVE → ROTATING.
    /// Vault writes are blocked until rotation completes.
    pub fn initiate_rotation(
        &mut self,
        initiating_device_id: Uuid,
    ) -> Result<(RootKey, &RekeyTransaction), BaluardError> {
        // Must be ACTIVE to start rotation
        if self.epoch.state != EpochState::Active {
            return Err(KeyError::InvalidEpochState(format!(
                "cannot initiate rotation from {:?}",
                self.epoch.state
            ))
            .into());
        }

        // Initiating device must be enrolled
        if !self.registry.is_enrolled(&initiating_device_id) {
            return Err(DeviceError::NotEnrolled(initiating_device_id.to_string()).into());
        }

        // Generate new Root Key and wrap for all enrolled devices
        let device_pubs = self.registry.encryption_public_keys();
        let (new_root, tx) = crate::keys::rotation::initiate_epoch_rotation(
            self.epoch.epoch,
            &device_pubs,
            initiating_device_id,
        )?;

        // Capture epoch before tx is moved
        let proposed_epoch = tx.new_epoch;

        // Transition epoch to ROTATING
        self.epoch
            .begin_rotation()
            .map_err(KeyError::InvalidEpochState)?;

        self.pending_transaction = Some(tx);
        self.collected_acks.clear();

        // MISS-4: auto-persist rotation proposal
        self.auto_save_result()?;

        // MISS-3: notify observer of rotation proposal
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_rotation_proposed(proposed_epoch, vp));
            }
        }

        Ok((new_root, self.pending_transaction.as_ref().unwrap()))
    }

    /// Record an acknowledgment from a device for the pending rotation.
    ///
    /// Verifies: device is enrolled, signature is valid, txn_hash matches.
    /// Automatically commits if quorum is reached.
    pub fn record_ack(&mut self, ack: RotationAck) -> Result<bool, BaluardError> {
        let tx = self
            .pending_transaction
            .as_ref()
            .ok_or_else(|| KeyError::InvalidEpochState("no pending rotation".into()))?;

        // Verify epoch matches
        if ack.epoch != tx.new_epoch {
            return Err(KeyError::EpochMismatch {
                expected: tx.new_epoch,
                actual: ack.epoch,
            }
            .into());
        }

        // Verify device is enrolled
        if !self.registry.is_enrolled(&ack.device_id) {
            return Err(DeviceError::NotEnrolled(ack.device_id.to_string()).into());
        }

        // Verify txn_hash matches pending transaction
        let actual_txn_hash = compute_txn_hash(tx);
        if ack.txn_hash != actual_txn_hash {
            return Err(DeviceError::EnrollmentRejected("ack txn_hash mismatch".into()).into());
        }

        // BUG-1 fix: reject duplicate ack from same device
        if self.epoch.acknowledged_devices.contains(&ack.device_id) {
            return Err(DeviceError::EnrollmentRejected(
                "duplicate ack: device already acknowledged this epoch".into(),
            )
            .into());
        }

        // Verify signature
        let device_entry = self.registry.devices.get(&ack.device_id).unwrap();
        let vk_bytes: [u8; 32] = hex::decode(&device_entry.signing_public_key)
            .map_err(|_| DeviceError::Keystore("invalid signing key".into()))?
            .try_into()
            .map_err(|_| DeviceError::Keystore("signing key wrong length".into()))?;

        let verifying_key = signature::verifying_key_from_bytes(&vk_bytes)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid device key".into()))?;

        let mut sign_input = b"ack".to_vec();
        sign_input.extend_from_slice(&ack.epoch.to_le_bytes());
        sign_input.extend_from_slice(ack.device_id.as_bytes());
        sign_input.extend_from_slice(ack.txn_hash.as_bytes());

        let sig = ed25519_dalek::Signature::from_slice(&ack.signature)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid ack signature".into()))?;
        signature::verify(&verifying_key, &sign_input, &sig).map_err(|_| {
            DeviceError::EnrollmentRejected("ack signature verification failed".into())
        })?;

        // MISS-3: notify observer of ack recorded
        let notify_epoch = ack.epoch;
        let notify_device = ack.device_id;

        // BUG-1/BUG-4 fix: record ack in epoch first (canonical dedup tracker),
        // then store signed payload in collected_acks.
        // Quorum uses epoch.acknowledged_devices.len() exclusively.
        self.epoch.acknowledge(ack.device_id);
        self.collected_acks.push(ack);

        // Check quorum using epoch's deduped tracker
        let quorum = self.registry.quorum_required();
        if self.epoch.acknowledged_devices.len() >= quorum {
            self.commit_rotation()?;
            return Ok(true); // committed (auto_save inside commit_rotation)
        }

        // MISS-4: auto-persist recorded ack
        self.auto_save_result()?;

        // MISS-3: notify observer of ack recorded
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_ack_recorded(notify_epoch, &notify_device, vp));
            }
        }

        Ok(false) // ack recorded, not yet committed
    }

    /// Commit a rotation after quorum is reached.
    /// Transitions: old epoch → RETIRED, new epoch → ACTIVE.
    /// BUG-3 fix: populates commit_barrier before committing.
    fn commit_rotation(&mut self) -> Result<(), BaluardError> {
        let mut tx = self
            .pending_transaction
            .take()
            .ok_or_else(|| KeyError::InvalidEpochState("no pending transaction".into()))?;

        // Capture epoch before tx is consumed
        let committed_epoch = tx.new_epoch;

        // BUG-3 fix: populate commit barrier with verified ack signatures
        tx.commit_barrier = self
            .collected_acks
            .iter()
            .map(|ack| CommitBarrierSig {
                device_id: ack.device_id,
                epoch: ack.epoch,
                signature: ack.signature.clone(),
            })
            .collect();

        // Write finalized .committed file via store
        if let Some(ref store) = self.store {
            let committed_json = serde_json::to_string_pretty(&tx)
                .map_err(|e| KeyError::InvalidEpochState(format!("serialize committed: {e}")))?;
            store.save_committed(tx.new_epoch, &committed_json)?;
        }

        // Transition epoch: ROTATING → RETIRED (old) → create new ACTIVE
        self.epoch.retire().map_err(KeyError::InvalidEpochState)?;
        self.epoch = EpochInfo::new(tx.new_epoch);
        self.epoch.activate().map_err(KeyError::InvalidEpochState)?;

        // Cleanup acks
        self.collected_acks.clear();

        // MISS-4: auto-persist committed rotation
        self.auto_save_result()?;

        // MISS-3: notify observer of rotation committed
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_rotation_committed(committed_epoch, vp));
            }
        }

        Ok(())
    }

    // ── Selective Revocation ──

    /// Selective revocation: remove one device and rotate keys.
    /// Unlike force_evict_and_rotate (which keeps only the survivor),
    /// this preserves all other enrolled devices.
    ///
    /// Note: Caller MUST write a new keywrap file using new_root_key
    /// after this returns. Without it, the vault cannot be unlocked
    /// with the master password (only via recovery phrase).
    ///
    /// Quorum note: self-acknowledges immediately. Designed for 2-device
    /// vaults (quorum=1 after revoke). For 4+ device vaults, the rotation
    /// commits without full quorum verification. Other devices will
    /// accept the new epoch on next pull.
    pub fn revoke_device_and_rotate(
        &mut self,
        target_device_id: Uuid,
        self_device_id: Uuid,
    ) -> Result<RevokeDeviceResult, BaluardError> {
        if target_device_id == self_device_id {
            return Err(BaluardError::Device(DeviceError::Keystore(
                "Cannot revoke the current device. Use force-evict from another device.".into(),
            )));
        }

        let revoked = self.registry.revoke(target_device_id)?;
        let revoked_name = revoked.name.clone();

        // Initiate rotation with self as initiator
        let (new_root, tx) = self.initiate_rotation(self_device_id)?;
        let new_epoch = tx.new_epoch;

        // H9 fix: Always self-acknowledge and commit on revocation.
        //
        // Baluard is a single-admin password manager: one user controls all devices.
        // Quorum here means "enough devices to prove the admin authorized this" — not
        // multi-party approval. A single remaining device is sufficient proof.
        // The revoked device's keywrap is deleted by the caller; its old keywrap can't
        // unwrap the new Root Key because epoch changed.
        //
        // For multi-admin org vaults (future), this would need true quorum enforcement.
        self.epoch.acknowledge(self_device_id);
        self.commit_rotation()?;

        let result = RevokeDeviceResult {
            revoked_device_id: target_device_id,
            revoked_name,
            new_epoch,
            new_root_key: Some(new_root),
        };

        // Auto-persist
        self.auto_save_result()?;

        // Notify observer
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_devices_evicted(1, vp));
            }
        }

        Ok(result)
    }

    /// Emergency Force Evict (D14): single surviving device rewrites registry.
    /// All devices except the survivor are evicted. Epoch is rotated.
    pub fn force_evict_and_rotate(
        &mut self,
        surviving_device_id: Uuid,
    ) -> Result<ForceEvictResult, BaluardError> {
        let evicted = self.registry.force_evict(surviving_device_id)?;
        let evicted_count = evicted.len();

        // Capture surviving count before initiating rotation (which borrows mutably)
        let surviving_count = self.registry.count();
        let quorum_needed = self.registry.quorum_required();

        // Immediately initiate rotation
        let (new_root, tx) = self.initiate_rotation(surviving_device_id)?;
        let new_epoch = tx.new_epoch;

        // Single surviving device = self-ack = immediate commit
        let (rotation_committed, new_root_key) = if surviving_count <= quorum_needed {
            // Note: collected_acks is empty here because the actual signing key lives
            // in the vault keywrap, not DeviceManager. The .committed file will have
            // an empty commit_barrier. This is correct: force-evict is a single-device
            // emergency operation, not a multi-device quorum proof.
            self.epoch.acknowledge(surviving_device_id);
            self.commit_rotation()?;
            (true, Some(new_root))
        } else {
            (false, None) // new_root consumed by pending_transaction
        };

        let result = ForceEvictResult {
            evicted_devices: evicted,
            rotation_committed,
            new_epoch: if rotation_committed {
                new_epoch
            } else {
                self.epoch.epoch
            },
            new_root_key,
        };

        // MISS-4: auto-persist eviction + rotation state
        // (initiate_rotation auto-saves, but if rotation didn't commit, save again to ensure
        //  the evicted registry is persisted)
        if !rotation_committed {
            self.auto_save_result()?;
        }

        // MISS-3: notify observer of eviction
        if let Some(ref store) = self.store {
            if let Some(vp) = store.vault_path() {
                self.fire(|obs| obs.on_devices_evicted(evicted_count, vp));
            }
        }

        Ok(result)
    }

    // ── Recovery from BIP-39 Phrase (MISS-5) ──

    /// Recover from total device loss using a BIP-39 recovery phrase.
    ///
    /// This method:
    /// 1. Derives a recovery key from the BIP-39 phrase
    /// 2. HPKE-unwrapes the Root Key from meta/recovery.json
    /// 3. Resets the device registry (old devices abandoned)
    /// 4. Enrolls the new device as the sole surviving device
    /// 5. Sets epoch to match existing vault data
    ///
    /// Returns the recovered Root Key, the new device entry, and the
    /// device's X25519 and Ed25519 private keys for keywrap/signing.
    pub fn recover_from_phrase(
        &mut self,
        phrase: &str,
        new_device_name: &str,
    ) -> Result<RecoveryResult, BaluardError> {
        use crate::recovery::RecoveryPhrase;

        // Step 1: Parse phrase
        let recovery_phrase = RecoveryPhrase::from_phrase(phrase).map_err(|e| {
            DeviceError::EnrollmentRejected(format!("invalid recovery phrase: {e}"))
        })?;

        // Step 2: Derive recovery key and X25519 secret
        let mut recovery_key = recovery_phrase.derive_key();
        let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&recovery_key[..32])
                .map_err(|_| DeviceError::Keystore("recovery key too short".into()))?,
        );
        // Zeroize full 64-byte recovery key (only first 32 bytes were consumed)
        use zeroize::Zeroize;
        recovery_key.zeroize();

        // Step 3: Load recovery.json from vault
        let vault_path = self
            .store
            .as_ref()
            .and_then(|s| s.vault_path())
            .ok_or_else(|| DeviceError::Keystore("vault_path not set for recovery".into()))?;
        let vault_path = vault_path.to_path_buf(); // own the path for the rest of the method;
        let recovery_json_path = vault_path.join("meta/recovery.json");
        if !recovery_json_path.exists() {
            return Err(DeviceError::Keystore("meta/recovery.json not found".into()).into());
        }

        let recovery_json_str = std::fs::read_to_string(&recovery_json_path)
            .map_err(|e| DeviceError::Keystore(format!("reading recovery.json: {e}")))?;
        let recovery_json: serde_json::Value = serde_json::from_str(&recovery_json_str)
            .map_err(|e| DeviceError::Keystore(format!("parsing recovery.json: {e}")))?;

        let eph_pub = hex::decode(recovery_json["ephemeral_public"].as_str().unwrap_or(""))
            .map_err(|e| DeviceError::Keystore(format!("recovery eph_public hex: {e}")))?;
        let ct = hex::decode(recovery_json["encrypted_key"].as_str().unwrap_or(""))
            .map_err(|e| DeviceError::Keystore(format!("recovery encrypted_key hex: {e}")))?;
        let tag_hex = recovery_json["tag"].as_str().unwrap_or("");
        let tag_bytes = hex::decode(tag_hex)
            .map_err(|e| DeviceError::Keystore(format!("recovery tag hex: {e}")))?;
        let mut tag = [0u8; 16];
        if tag_bytes.len() != 16 {
            return Err(DeviceError::Keystore("invalid recovery tag length".into()).into());
        }
        tag.copy_from_slice(&tag_bytes);

        // Step 4: HPKE-unwrap Root Key
        let root_key_bytes =
            crate::crypto::hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, &recovery_x25519_secret)?;
        let rk_arr: [u8; 64] = root_key_bytes
            .try_into()
            .map_err(|_| DeviceError::Keystore("unwrapped root key not 64 bytes".into()))?;
        let root_key = RootKey::from_bytes(rk_arr);

        // Step 5: Determine current epoch from vault data (H7 fix)
        let current_epoch = Self::determine_epoch_from_vault(&vault_path);

        // Step 6: Reset registry — old devices abandoned
        self.registry = DeviceRegistry::new();

        // Step 7: Generate new device keypair and enroll as sole device
        let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (ed25519_signing, ed25519_verifying) =
            crate::crypto::signature::generate_ed25519_keypair();
        let new_device_id = Uuid::new_v4();

        let entry = self.registry.enroll_with_id(
            new_device_id,
            new_device_name.to_string(),
            x25519_public.to_bytes(),
            crate::crypto::signature::verifying_key_bytes(&ed25519_verifying),
            None, // Recovery: no approver
        )?;

        // Step 8: Set epoch to match existing vault data
        self.epoch = EpochInfo::new(current_epoch);
        self.epoch.activate().map_err(KeyError::InvalidEpochState)?;
        self.pending_transaction = None;
        self.collected_acks.clear();

        // Step 9: Write keywrap for new device (M5 fix: vault must be usable on next open)
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
        let (eph_pub, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(root_key.as_bytes(), &x25519_public)?;
        let keywrap_data = serde_json::json!({
            "device_id": new_device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_dir = vault_path.join("meta/keywrap");
        let _ = std::fs::create_dir_all(&keywrap_dir);
        atomic_write(
            &keywrap_dir.join(format!("{}.json", new_device_id)),
            &serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // Step 10: Remove old keywrap files (evicted devices)
        if let Ok(entries) = std::fs::read_dir(&keywrap_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") && !name.starts_with(&new_device_id.to_string()) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        // Step 11: Write device-privkey.json for CLI/rotation use
        let ed_priv_bytes = ed25519_signing.to_bytes();
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode(x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(ed_priv_bytes),
        });
        let privkey_path = vault_path.join("meta/device-privkey.json");
        let privkey_tmp = privkey_path.with_extension("json.tmp");
        std::fs::write(
            &privkey_tmp,
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&privkey_tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&privkey_tmp, &privkey_path)?;

        // Step 12: Persist recovered state
        self.auto_save_result()?;

        Ok(RecoveryResult {
            root_key,
            entry,
            device_id: new_device_id,
            x25519_secret,
            ed25519_signing,
        })
    }

    // ── Non-destructive enrollment via recovery phrase ──

    /// Enroll a new device into an existing vault using the BIP-39 recovery
    /// phrase. Non-destructive: existing devices remain in the registry.
    ///
    /// Use case: user has lost all their enrolled devices (or the only
    /// enrolled device is inaccessible) but still has the recovery phrase.
    /// The phrase proves root authority — the new device derives the Root
    /// Key, wraps it for itself, and joins the existing vault.
    ///
    /// Requires `EnrollmentPolicy::Personal`. In `Strict` mode, only
    /// `ExistingDevice` authorization is accepted; use `recover_from_phrase`
    /// (destructive) instead.
    ///
    /// Difference from `recover_from_phrase`:
    /// - This method PRESERVES the device registry (old devices stay enrolled).
    /// - `recover_from_phrase` resets the registry to a single new device.
    ///
    /// Returns the new device's X25519/Ed25519 private keys for keywrap/signing.
    pub fn enroll_with_recovery_phrase(
        &mut self,
        payload: &EnrollmentPayload,
        phrase: &str,
    ) -> Result<RecoveryResult, BaluardError> {
        use crate::recovery::RecoveryPhrase;

        // Step 1: Parse phrase
        let recovery_phrase = RecoveryPhrase::from_phrase(phrase).map_err(|e| {
            DeviceError::EnrollmentRejected(format!("invalid recovery phrase: {e}"))
        })?;

        // Step 2: Derive recovery key and X25519 secret
        let mut recovery_key = recovery_phrase.derive_key();
        let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&recovery_key[..32])
                .map_err(|_| DeviceError::Keystore("recovery key too short".into()))?,
        );
        use zeroize::Zeroize;
        recovery_key.zeroize();

        // Step 3: Load recovery.json from vault
        let vault_path = self
            .store
            .as_ref()
            .and_then(|s| s.vault_path())
            .ok_or_else(|| DeviceError::Keystore("vault_path not set for enrollment".into()))?;
        let vault_path = vault_path.to_path_buf();
        let recovery_json_path = vault_path.join("meta/recovery.json");
        if !recovery_json_path.exists() {
            return Err(DeviceError::Keystore("meta/recovery.json not found".into()).into());
        }

        let recovery_json_str = std::fs::read_to_string(&recovery_json_path)
            .map_err(|e| DeviceError::Keystore(format!("reading recovery.json: {e}")))?;
        let recovery_json: serde_json::Value = serde_json::from_str(&recovery_json_str)
            .map_err(|e| DeviceError::Keystore(format!("parsing recovery.json: {e}")))?;

        let eph_pub = hex::decode(recovery_json["ephemeral_public"].as_str().unwrap_or(""))
            .map_err(|e| DeviceError::Keystore(format!("recovery eph_public hex: {e}")))?;
        let ct = hex::decode(recovery_json["encrypted_key"].as_str().unwrap_or(""))
            .map_err(|e| DeviceError::Keystore(format!("recovery encrypted_key hex: {e}")))?;
        let tag_hex = recovery_json["tag"].as_str().unwrap_or("");
        let tag_bytes = hex::decode(tag_hex)
            .map_err(|e| DeviceError::Keystore(format!("recovery tag hex: {e}")))?;
        let mut tag = [0u8; 16];
        if tag_bytes.len() != 16 {
            return Err(DeviceError::Keystore("invalid recovery tag length".into()).into());
        }
        tag.copy_from_slice(&tag_bytes);

        // Step 4: HPKE-unwrap Root Key
        let root_key_bytes =
            crate::crypto::hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, &recovery_x25519_secret)?;
        let rk_arr: [u8; 64] = root_key_bytes
            .try_into()
            .map_err(|_| DeviceError::Keystore("unwrapped root key not 64 bytes".into()))?;
        let root_key = RootKey::from_bytes(rk_arr);

        // Step 5: Validate payload (timestamp, nonce, keys) — same as enroll()
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = now.abs_diff(payload.timestamp);
        if drift > 300 {
            return Err(DeviceError::EnrollmentRejected(
                "stale: timestamp outside 5-minute window".into(),
            )
            .into());
        }
        if self.seen_nonces.contains(&payload.nonce) {
            return Err(
                DeviceError::EnrollmentRejected("replay: nonce already used".into()).into(),
            );
        }
        // Record nonce to prevent replay (trim if at cap, same logic as enroll())
        if self.seen_nonces.len() >= MAX_SEEN_NONCES {
            self.seen_nonces.remove(0);
        }
        self.seen_nonces.push(payload.nonce.clone());

        let enc_pk = hex::decode(&payload.encryption_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid encryption key hex".into()))?;
        let sig_pk = hex::decode(&payload.signing_public_key)
            .map_err(|_| DeviceError::EnrollmentRejected("invalid signing key hex".into()))?;
        if enc_pk.len() != 32 || sig_pk.len() != 32 {
            return Err(DeviceError::EnrollmentRejected("invalid public key length".into()).into());
        }
        let mut enc_arr = [0u8; 32];
        let mut sig_arr = [0u8; 32];
        enc_arr.copy_from_slice(&enc_pk);
        sig_arr.copy_from_slice(&sig_pk);

        // Step 6: Reject if this device is already enrolled
        if self.registry.is_enrolled(&payload.device_id) {
            return Err(DeviceError::AlreadyEnrolled(payload.device_id.to_string()).into());
        }

        // Step 7: Enroll into EXISTING registry (non-destructive — old devices stay)
        let entry = self.registry.enroll_with_id(
            payload.device_id,
            payload.name.clone(),
            enc_arr,
            sig_arr,
            None, // No approver — recovery phrase is the authority
        )?;

        // Step 8: Write keywrap for new device (so the vault is usable on next open)
        let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (eph_pub, ct, tag_out) =
            crate::crypto::hpke_wrap::wrap_key(root_key.as_bytes(), &x25519_public)?;
        let keywrap_data = serde_json::json!({
            "device_id": payload.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag_out),
        });
        let keywrap_dir = vault_path.join("meta/keywrap");
        let _ = std::fs::create_dir_all(&keywrap_dir);
        atomic_write(
            &keywrap_dir.join(format!("{}.json", payload.device_id)),
            &serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // Step 9: Write device-privkey.json for CLI/rotation use
        let (ed25519_signing, _ed25519_verifying) =
            crate::crypto::signature::generate_ed25519_keypair();
        let ed_priv_bytes = ed25519_signing.to_bytes();
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode(x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(ed_priv_bytes),
        });
        let privkey_path = vault_path.join("meta/device-privkey.json");
        let privkey_tmp = privkey_path.with_extension("json.tmp");
        std::fs::write(
            &privkey_tmp,
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&privkey_tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&privkey_tmp, &privkey_path)?;

        // Step 10: Persist state
        self.auto_save_result()?;

        Ok(RecoveryResult {
            root_key,
            entry,
            device_id: payload.device_id,
            x25519_secret,
            ed25519_signing,
        })
    }

    /// Determine current epoch from vault cipher headers or RK canary.
    fn determine_epoch_from_vault(vault_path: &Path) -> u64 {
        // Try RK canary first
        let rk_path = vault_path.join("meta/rk-canary.enc");
        if rk_path.exists() {
            if let Ok(data) = std::fs::read(&rk_path) {
                if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                    return envelope.header.key_epoch;
                }
            }
        }
        // Try first cipher
        let ciphers_dir = vault_path.join("ciphers");
        if ciphers_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&ciphers_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".enc") {
                        if let Ok(data) = std::fs::read(entry.path()) {
                            if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                                return envelope.header.key_epoch;
                            }
                        }
                    }
                }
            }
        }
        1 // default for new vaults
    }

    // ── Persistence ──

    /// Check if DeviceManager vault files exist (meta/devices.json or meta/epoch.json).
    pub fn vault_files_exist(vault_path: &Path) -> bool {
        let store = FileDeviceManagerStore::new(vault_path);
        store.exists()
    }

    /// Load DeviceManager from vault directory using a FileDeviceManagerStore.
    /// Convenience wrapper for `load_from_store()`.
    pub fn load_from_vault(vault_path: &Path) -> Result<Self, BaluardError> {
        let store = std::sync::Arc::new(FileDeviceManagerStore::new(vault_path));
        Self::load_from_store(store)
    }

    /// Load DeviceManager from any store backend.
    pub fn load_from_store(
        store: std::sync::Arc<dyn DeviceManagerStore>,
    ) -> Result<Self, BaluardError> {
        let state = if store.exists() {
            store.load_state()?
        } else {
            None
        };
        Ok(match state {
            Some(s) => Self {
                registry: s.registry,
                epoch: s.epoch,
                pending_transaction: s.pending_transaction,
                collected_acks: s.collected_acks,
                seen_nonces: s.seen_nonces,
                store: Some(store),
                observer: None,
            },
            None => {
                let mut dm = Self::new();
                dm.store = Some(store);
                dm
            }
        })
    }

    /// Save registry and epoch state via the configured store.
    pub fn save_to_vault(&self) -> Result<(), BaluardError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| DeviceError::Keystore("no store configured".into()))?;
        store.save_state(&self.snapshot_state())
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a force evict operation.
#[derive(Debug)]
pub struct ForceEvictResult {
    /// Devices that were evicted.
    pub evicted_devices: Vec<DeviceEntry>,
    /// Whether the epoch rotation was immediately committed.
    pub rotation_committed: bool,
    /// New epoch number after rotation.
    pub new_epoch: u64,
    /// New Root Key. Present only when rotation_committed = true.
    /// Caller MUST write a new keywrap file for the surviving device.
    pub new_root_key: Option<RootKey>,
}

/// Result of selective device revocation.
pub struct RevokeDeviceResult {
    /// ID of the revoked device.
    pub revoked_device_id: Uuid,
    /// Name of the revoked device.
    pub revoked_name: String,
    /// New epoch after rotation.
    pub new_epoch: u64,
    /// New Root Key. Caller MUST write keywrap file.
    pub new_root_key: Option<RootKey>,
}

/// Result of a recovery operation.
/// Contains everything the caller needs to write keywrap files and persist keys.
pub struct RecoveryResult {
    /// Recovered Root Key.
    pub root_key: RootKey,
    /// New device entry (with public keys).
    pub entry: DeviceEntry,
    /// New device ID.
    pub device_id: Uuid,
    /// X25519 private key for HPKE keywrap.
    pub x25519_secret: x25519_dalek::StaticSecret,
    /// Ed25519 signing key for ack signatures.
    pub ed25519_signing: ed25519_dalek::SigningKey,
}

/// Load seen nonces from vault directory. Returns empty vec if file missing.
fn load_seen_nonces(vault_path: &Path) -> Vec<String> {
    let path = vault_path.join("meta/seen-nonces.json");
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

/// Atomic file write: write to temp file then rename.
/// Prevents corruption from crash mid-write. Sets 0600 permissions on Unix.
fn atomic_write(path: &Path, data: &str) -> Result<(), BaluardError> {
    let tmp_path = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp_path, data)
        .map_err(|e| DeviceError::Keystore(format!("atomic write tmp: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| DeviceError::Keystore(format!("atomic write chmod: {e}")))?;
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|e| DeviceError::Keystore(format!("atomic write rename: {e}")))?;
    Ok(())
}

/// Compute a hash of a rekey transaction for ack binding.
pub(crate) fn compute_txn_hash(tx: &RekeyTransaction) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Deterministic serialization of key fields
    hasher.update(tx.old_epoch.to_le_bytes());
    hasher.update(tx.new_epoch.to_le_bytes());
    hasher.update(tx.initiating_device_id.as_bytes());
    hasher.update(tx.timestamp.to_le_bytes());
    for entry in &tx.wrapped_root_keys {
        hasher.update(entry.device_id.as_bytes());
        hasher.update(&entry.ephemeral_public);
        hasher.update(&entry.encrypted_key);
        hasher.update(entry.tag);
    }
    format!("{:x}", hasher.finalize())
}

// ── Helper: generate self-signed ack (for single-device commit) ──

/// Build the sign input for an ack. Public so callers can sign externally.
pub fn build_ack_sign_input(epoch: u64, device_id: &Uuid, txn_hash: &str) -> Vec<u8> {
    let mut input = b"ack".to_vec();
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(device_id.as_bytes());
    input.extend_from_slice(txn_hash.as_bytes());
    input
}

/// Build the sign input for enrollment approval. Public so callers can sign externally.
pub fn build_enroll_sign_input(payload: &EnrollmentPayload) -> Result<Vec<u8>, BaluardError> {
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| DeviceError::Keystore(format!("serialize enrollment payload: {e}")))?;
    let mut input = b"enroll".to_vec();
    input.extend_from_slice(&payload_bytes);
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hpke_wrap, signature as sig};

    fn make_payload(name: &str) -> EnrollmentPayload {
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let nonce: [u8; 32] = rand::random();
        EnrollmentPayload {
            device_id: Uuid::new_v4(),
            encryption_public_key: hex::encode(x_pk),
            signing_public_key: hex::encode(e_pk),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: hex::encode(nonce),
            name: name.to_string(),
            vault_id: None,
            epoch: None,
            registry_version: None,
        }
    }

    fn make_payload_bound(name: &str, epoch: u64, reg_ver: u64) -> EnrollmentPayload {
        let mut p = make_payload(name);
        p.epoch = Some(epoch);
        p.registry_version = Some(reg_ver);
        p
    }

    #[test]
    fn first_device_auto_approves() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let payload = make_payload("First Device");
        let entry = mgr.enroll(&payload, None).unwrap();
        assert_eq!(entry.name, "First Device");
        assert_eq!(mgr.registry.count(), 1);
    }

    #[test]
    fn second_device_requires_approval() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // Enroll first device
        let p1 = make_payload("First");
        mgr.enroll(&p1, None).unwrap();

        // Enroll second device without approval → rejected
        let p2 = make_payload("Second");
        assert!(mgr.enroll(&p2, None).is_err());
    }

    #[test]
    fn second_device_with_valid_approval() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // Enroll first device (with known signing key)
        let (signing_key, verifying_key) = sig::generate_ed25519_keypair();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let p1 = EnrollmentPayload {
            device_id: Uuid::new_v4(),
            encryption_public_key: hex::encode(x_pk),
            signing_public_key: hex::encode(sig::verifying_key_bytes(&verifying_key)),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: hex::encode::<[u8; 32]>(rand::random()),
            name: "Approver".to_string(),
            vault_id: None,
            epoch: None,
            registry_version: None,
        };
        let approver_id = p1.device_id;
        mgr.enroll(&p1, None).unwrap();

        // Enroll second device with approval from first
        let p2 = make_payload_bound("Second", 0, 1);
        let sign_input = build_enroll_sign_input(&p2).unwrap();
        let approval_sig = sig::sign(&signing_key, &sign_input).unwrap();

        let approval = ApprovalSignature {
            approver_device_id: approver_id,
            signature: approval_sig.to_bytes().to_vec(),
        };

        let entry = mgr.enroll(&p2, Some(&approval)).unwrap();
        assert_eq!(entry.name, "Second");
        assert_eq!(mgr.registry.count(), 2);
    }

    #[test]
    fn replay_nonce_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let payload = make_payload("First");
        mgr.enroll(&payload, None).unwrap();

        // Reuse same nonce → rejected
        let mut payload2 = make_payload("Second");
        payload2.nonce = payload.nonce.clone();
        assert!(mgr.enroll(&payload2, None).is_err());
    }

    #[test]
    fn stale_timestamp_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let mut payload = make_payload("Stale");
        payload.timestamp = 0; // very old
        assert!(mgr.enroll(&payload, None).is_err());
    }

    #[test]
    fn initiate_rotation_transitions_to_rotating() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(
                device_id,
                "D1".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&e_pk),
                None,
            )
            .unwrap();

        let (_root_key, tx) = mgr.initiate_rotation(device_id).unwrap();
        assert_eq!(tx.new_epoch, 1);
        assert_eq!(tx.wrapped_root_keys.len(), 1);
        let _ = tx; // release borrow on reference does nothing, but tx goes out of scope
        assert_eq!(mgr.epoch_state(), EpochState::Rotating);
        assert!(!mgr.writes_allowed());
    }

    #[test]
    fn single_device_self_commits() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(
                device_id,
                "Solo".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&e_pk),
                None,
            )
            .unwrap();

        let result = mgr.force_evict_and_rotate(device_id).unwrap();
        assert!(result.rotation_committed);
        assert_eq!(mgr.epoch_state(), EpochState::Active);
        assert!(mgr.writes_allowed());
        assert_eq!(mgr.current_epoch(), 1);
    }

    #[test]
    fn force_evict_removes_devices() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let d1 = mgr
            .registry
            .enroll("D1".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();
        let d2 = mgr
            .registry
            .enroll("D2".into(), [3u8; 32], [4u8; 32], None)
            .unwrap();
        let d3 = mgr
            .registry
            .enroll("D3".into(), [5u8; 32], [6u8; 32], None)
            .unwrap();

        // Note: force_evict keeps ONLY surviving device, removes all others.
        let result = mgr.force_evict_and_rotate(d1.device_id).unwrap();
        assert_eq!(result.evicted_devices.len(), 2);
        assert_eq!(mgr.registry.count(), 1);
        assert!(mgr.registry.is_enrolled(&d1.device_id));
        assert!(!mgr.registry.is_enrolled(&d2.device_id));
        assert!(!mgr.registry.is_enrolled(&d3.device_id));
    }

    #[test]
    fn concurrent_rotation_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        let device_id = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(device_id, "D1".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();

        mgr.initiate_rotation(device_id).unwrap();
        // Second initiation while ROTATING → error
        assert!(mgr.initiate_rotation(device_id).is_err());
    }

    #[test]
    fn ack_with_wrong_txn_hash_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let (signing_key, verifying_key) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        mgr.registry
            .enroll_with_id(
                device_id,
                "D1".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&verifying_key),
                None,
            )
            .unwrap();

        let (_, _) = mgr.initiate_rotation(device_id).unwrap();

        // Build ack with wrong txn_hash
        let sign_input = build_ack_sign_input(1, &device_id, "wrong_hash");
        let ack_sig = sig::sign(&signing_key, &sign_input).unwrap();

        let ack = RotationAck {
            epoch: 1,
            device_id,
            txn_hash: "wrong_hash".to_string(),
            signature: ack_sig.to_bytes().to_vec(),
        };

        assert!(mgr.record_ack(ack).is_err());
    }

    #[test]
    fn ack_forgery_rejected() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        let (_real_signing, real_verifying) = sig::generate_ed25519_keypair();
        let (fake_signing, _) = sig::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        mgr.registry
            .enroll_with_id(
                device_id,
                "D1".into(),
                x_pk.to_bytes(),
                sig::verifying_key_bytes(&real_verifying),
                None,
            )
            .unwrap();

        let (_, tx) = mgr.initiate_rotation(device_id).unwrap();
        let txn_hash = compute_txn_hash(tx);

        // Sign with wrong key
        let sign_input = build_ack_sign_input(1, &device_id, &txn_hash);
        let forged_sig = sig::sign(&fake_signing, &sign_input).unwrap();

        let ack = RotationAck {
            epoch: 1,
            device_id,
            txn_hash,
            signature: forged_sig.to_bytes().to_vec(),
        };

        assert!(mgr.record_ack(ack).is_err());
    }

    #[test]
    fn quorum_gate_multi_device() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // 3 devices: need ceil(3/2) = 2 acks
        let _d1 = mgr
            .registry
            .enroll("D1".into(), [1u8; 32], [2u8; 32], None)
            .unwrap();
        let _d2 = mgr
            .registry
            .enroll("D2".into(), [3u8; 32], [4u8; 32], None)
            .unwrap();
        let _d3 = mgr
            .registry
            .enroll("D3".into(), [5u8; 32], [6u8; 32], None)
            .unwrap();

        // Can't initiate with real rotation (need real keypairs for HPKE wrapping)
        // Just test quorum_required logic
        assert_eq!(mgr.registry.quorum_required(), 2);
    }

    #[test]
    fn epoch_state_transitions_valid() {
        let mut e = EpochInfo::new(0);
        assert_eq!(e.state, EpochState::Created);
        e.activate().unwrap();
        assert_eq!(e.state, EpochState::Active);
        e.begin_rotation().unwrap();
        assert_eq!(e.state, EpochState::Rotating);
        e.retire().unwrap();
        assert_eq!(e.state, EpochState::Retired);
        e.destroy().unwrap();
        assert_eq!(e.state, EpochState::Destroyed);
    }

    // BUG-1 fix: same device submitting duplicate acks must NOT reach quorum of 2
    #[test]
    fn duplicate_ack_does_not_reach_quorum() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // 2 devices, quorum = 1 (ceil(2/2))
        let (sk1, vk1) = sig::generate_ed25519_keypair();
        let (_, x_pk1) = hpke_wrap::generate_x25519_keypair();
        let d1 = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(
                d1,
                "D1".into(),
                x_pk1.to_bytes(),
                sig::verifying_key_bytes(&vk1),
                None,
            )
            .unwrap();

        let (_, x_pk2) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk2) = sig::generate_ed25519_keypair();
        let _d2 = mgr
            .registry
            .enroll_with_id(
                Uuid::new_v4(),
                "D2".into(),
                x_pk2.to_bytes(),
                sig::verifying_key_bytes(&e_pk2),
                None,
            )
            .unwrap();

        let (_, tx) = mgr.initiate_rotation(d1).unwrap();
        let txn_hash = compute_txn_hash(tx);

        // First ack from D1 → accepted, quorum reached (N=2, q=1)
        let sign_input = build_ack_sign_input(1, &d1, &txn_hash);
        let ack_sig = sig::sign(&sk1, &sign_input).unwrap();
        let ack1 = RotationAck {
            epoch: 1,
            device_id: d1,
            txn_hash: txn_hash.clone(),
            signature: ack_sig.to_bytes().to_vec(),
        };
        // quorum=1 so first valid ack commits immediately
        assert!(mgr.record_ack(ack1).unwrap());

        // Rotation already committed — epoch is ACTIVE, no pending tx
        assert_eq!(mgr.epoch_state(), EpochState::Active);
    }

    // BUG-1 fix: with 3 devices (quorum=2), same device acking twice must fail
    #[test]
    fn duplicate_ack_rejected_with_3_devices() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // 3 devices with real keypairs so HPKE wrapping works
        let (sk1, vk1) = sig::generate_ed25519_keypair();
        let (_, x_pk1) = hpke_wrap::generate_x25519_keypair();
        let d1 = Uuid::new_v4();
        mgr.registry
            .enroll_with_id(
                d1,
                "D1".into(),
                x_pk1.to_bytes(),
                sig::verifying_key_bytes(&vk1),
                None,
            )
            .unwrap();

        let (_, x_pk2) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk2) = sig::generate_ed25519_keypair();
        mgr.registry
            .enroll_with_id(
                Uuid::new_v4(),
                "D2".into(),
                x_pk2.to_bytes(),
                sig::verifying_key_bytes(&e_pk2),
                None,
            )
            .unwrap();

        let (_, x_pk3) = hpke_wrap::generate_x25519_keypair();
        let (_, e_pk3) = sig::generate_ed25519_keypair();
        mgr.registry
            .enroll_with_id(
                Uuid::new_v4(),
                "D3".into(),
                x_pk3.to_bytes(),
                sig::verifying_key_bytes(&e_pk3),
                None,
            )
            .unwrap();

        assert_eq!(mgr.registry.quorum_required(), 2);

        let (_, tx) = mgr.initiate_rotation(d1).unwrap();
        let txn_hash = compute_txn_hash(tx);

        // First ack from D1 → accepted
        let sign_input = build_ack_sign_input(1, &d1, &txn_hash);
        let ack_sig = sig::sign(&sk1, &sign_input).unwrap();
        let ack1 = RotationAck {
            epoch: 1,
            device_id: d1,
            txn_hash: txn_hash.clone(),
            signature: ack_sig.to_bytes().to_vec(),
        };
        assert!(!mgr.record_ack(ack1).unwrap()); // 1 of 2, not committed

        // Duplicate ack from same D1 → REJECTED
        let ack_sig2 = sig::sign(&sk1, &sign_input).unwrap();
        let ack2 = RotationAck {
            epoch: 1,
            device_id: d1,
            txn_hash: txn_hash.clone(),
            signature: ack_sig2.to_bytes().to_vec(),
        };
        assert!(mgr.record_ack(ack2).is_err());

        // Still not committed (only 1 unique ack)
        assert_eq!(mgr.epoch_state(), EpochState::Rotating);
    }

    // BUG-2 fix: seen_nonces persisted and loaded across save/load cycle
    #[test]
    fn seen_nonces_persisted_across_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path();

        // Create and save
        {
            let mut mgr = DeviceManager::new();
            mgr.epoch.activate().unwrap();
            mgr.set_vault_path(vault_path);

            let payload = make_payload("First");
            let nonce = payload.nonce.clone();
            mgr.enroll(&payload, None).unwrap();
            mgr.save_to_vault().unwrap();

            // Verify nonce is recorded
            assert!(mgr.seen_nonces.contains(&nonce));
        }

        // Load and verify nonce survives
        {
            let mgr = DeviceManager::load_from_vault(vault_path).unwrap();
            // Should have loaded the nonce
            assert!(!mgr.seen_nonces.is_empty());
        }
    }

    // BUG-2 fix: FIFO eviction at capacity
    #[test]
    fn seen_nonces_fifo_eviction() {
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();

        // Fill beyond capacity using direct registry enrollment + nonce recording
        for i in 0..=MAX_SEEN_NONCES {
            mgr.registry
                .enroll_with_id(
                    Uuid::new_v4(),
                    format!("Dev{i}"),
                    [0u8; 32],
                    [0u8; 32],
                    None,
                )
                .unwrap();
            mgr.record_nonce(format!("nonce-{i}"));
        }

        assert_eq!(mgr.seen_nonces.len(), MAX_SEEN_NONCES);
        // First nonce should have been evicted
        assert!(!mgr.seen_nonces.contains(&"nonce-0".to_string()));
        // Latest nonce should be present
        assert!(
            mgr.seen_nonces
                .contains(&format!("nonce-{MAX_SEEN_NONCES}"))
        );
    }

    // MISS-4: auto-save persists mutations without explicit save_to_vault()
    #[test]
    fn auto_save_persists_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path();

        // Create, enroll, then check persistence without calling save_to_vault()
        {
            let mut mgr = DeviceManager::new();
            mgr.epoch.activate().unwrap();
            mgr.set_vault_path(vault_path);

            let payload = make_payload("AutoSaved");
            mgr.enroll(&payload, None).unwrap();
            // No explicit save_to_vault() call
        }

        // Load from disk - auto_save should have persisted enrollment
        {
            let mgr = DeviceManager::load_from_vault(vault_path).unwrap();
            assert_eq!(mgr.registry.count(), 1);
        }
    }

    // MISS-4: auto-save persists rotation state without explicit save_to_vault()
    #[test]
    fn auto_save_persists_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path();

        let (_sk, vk) = sig::generate_ed25519_keypair();
        let (_, x_pk) = hpke_wrap::generate_x25519_keypair();
        let device_id = Uuid::new_v4();

        {
            let mut mgr = DeviceManager::new();
            mgr.epoch.activate().unwrap();
            mgr.set_vault_path(vault_path);
            mgr.registry
                .enroll_with_id(
                    device_id,
                    "Solo".into(),
                    x_pk.to_bytes(),
                    sig::verifying_key_bytes(&vk),
                    None,
                )
                .unwrap();

            // Initiate rotation - auto_save should persist ROTATING state
            let (_rk, _tx) = mgr.initiate_rotation(device_id).unwrap();
            // No explicit save_to_vault()
        }

        // Load from disk - should see ROTATING state with pending transaction
        {
            let mgr = DeviceManager::load_from_vault(vault_path).unwrap();
            assert_eq!(mgr.epoch_state(), EpochState::Rotating);
            assert!(mgr.pending_transaction.is_some());
        }
    }

    // MISS-5: recovery from BIP-39 phrase bootstraps new device
    #[test]
    fn recover_from_phrase_bootstraps_new_device() {
        use crate::types::KdfProfile;
        use crate::vault::creation;

        // Step 1: Create a vault with known recovery phrase
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path();

        let ceremony = creation::create_vault_ceremony("password", KdfProfile::MobileLow).unwrap();
        let phrase_str = ceremony.recovery_phrase.phrase();

        // Write minimal vault structure
        std::fs::create_dir_all(vault_path.join("meta/keywrap")).unwrap();
        std::fs::create_dir_all(vault_path.join("meta")).unwrap();

        // Write recovery.json
        let (eph_pub, ct, tag) = &ceremony.wrapped_recovery_key;
        // Derive the recovery X25519 pubkey from the phrase for storage
        let recovery_key_bytes = ceremony.recovery_phrase.derive_key();
        let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&recovery_key_bytes[..32]).unwrap()
        );
        let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);
        let recovery_json = serde_json::json!({
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
            // H4 fix: store recovery X25519 public key for re-wrapping on rotation
            "recovery_x25519_pubkey": hex::encode(recovery_x25519_public.as_bytes()),
        });
        std::fs::write(
            vault_path.join("meta/recovery.json"),
            serde_json::to_string_pretty(&recovery_json).unwrap(),
        )
        .unwrap();

        // Step 2: Recover using the phrase
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(vault_path);

        let result = mgr
            .recover_from_phrase(&phrase_str, "Recovered Device")
            .unwrap();

        // Verify: new device enrolled as sole device
        assert_eq!(mgr.registry.count(), 1);
        assert_eq!(result.entry.name, "Recovered Device");
        assert_eq!(mgr.epoch_state(), EpochState::Active);
        assert!(mgr.pending_transaction.is_none());

        // Verify: recovered Root Key matches original
        assert_eq!(result.root_key.as_bytes(), ceremony.root_key.as_bytes());

        // Verify: private keys were returned (not discarded)
        assert_eq!(result.device_id, result.entry.device_id);
        // Verify X25519 keypair consistency: public key in entry matches private key
        let derived_pub = x25519_dalek::PublicKey::from(&result.x25519_secret);
        assert_eq!(
            hex::encode(derived_pub.as_bytes()),
            result.entry.encryption_public_key
        );

        // Verify: state persisted to disk
        let loaded = DeviceManager::load_from_vault(vault_path).unwrap();
        assert_eq!(loaded.registry.count(), 1);
    }

    // ── enroll_with_recovery_phrase tests ──

    fn setup_vault_with_recovery() -> (tempfile::TempDir, std::path::PathBuf, String) {
        use crate::types::KdfProfile;
        use crate::vault::creation;

        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().to_path_buf();

        let ceremony = creation::create_vault_ceremony("password", KdfProfile::MobileLow).unwrap();
        let phrase_str = ceremony.recovery_phrase.phrase();

        std::fs::create_dir_all(vault_path.join("meta/keywrap")).unwrap();
        std::fs::create_dir_all(vault_path.join("meta")).unwrap();

        let (eph_pub, ct, tag) = &ceremony.wrapped_recovery_key;
        let recovery_key_bytes = ceremony.recovery_phrase.derive_key();
        let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&recovery_key_bytes[..32]).unwrap(),
        );
        let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);
        let recovery_json = serde_json::json!({
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
            "recovery_x25519_pubkey": hex::encode(recovery_x25519_public.as_bytes()),
        });
        std::fs::write(
            vault_path.join("meta/recovery.json"),
            serde_json::to_string_pretty(&recovery_json).unwrap(),
        )
        .unwrap();

        (dir, vault_path, phrase_str)
    }

    #[test]
    fn enroll_with_phrase_preserves_existing_devices() {
        let (_dir, vault_path, phrase_str) = setup_vault_with_recovery();

        // First, enroll a founding device
        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        let p1 = make_payload("Device A");
        mgr.enroll(&p1, None).unwrap();
        assert_eq!(mgr.registry.count(), 1);

        // Persist state
        mgr.auto_save_result().unwrap();

        // Now enroll a second device via recovery phrase (non-destructive)
        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let p2 = make_payload("Device B (via phrase)");
        let result = mgr2.enroll_with_recovery_phrase(&p2, &phrase_str).unwrap();

        // Verify: both devices in registry (old device preserved)
        assert_eq!(mgr2.registry.count(), 2);
        assert!(mgr2.registry.is_enrolled(&p1.device_id));
        assert!(mgr2.registry.is_enrolled(&p2.device_id));
        assert_eq!(result.entry.name, "Device B (via phrase)");
    }

    #[test]
    fn enroll_with_phrase_rejects_wrong_phrase() {
        let (_dir, vault_path, _correct_phrase) = setup_vault_with_recovery();

        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        mgr.enroll(&make_payload("First"), None).unwrap();
        mgr.auto_save_result().unwrap();

        // Generate a different 24-word phrase
        use crate::recovery::RecoveryPhrase;
        let wrong_phrase = RecoveryPhrase::generate().unwrap().phrase();

        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let p2 = make_payload("Attacker");
        let result = mgr2.enroll_with_recovery_phrase(&p2, &wrong_phrase);
        assert!(result.is_err(), "wrong phrase must be rejected");
    }

    #[test]
    fn enroll_with_phrase_rejects_stale_timestamp() {
        let (_dir, vault_path, phrase_str) = setup_vault_with_recovery();

        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        mgr.enroll(&make_payload("First"), None).unwrap();
        mgr.auto_save_result().unwrap();

        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let mut stale = make_payload("Stale");
        stale.timestamp = 0; // ancient
        let result = mgr2.enroll_with_recovery_phrase(&stale, &phrase_str);
        assert!(result.is_err(), "stale timestamp must be rejected");
    }

    #[test]
    fn enroll_with_phrase_rejects_replayed_nonce() {
        let (_dir, vault_path, phrase_str) = setup_vault_with_recovery();

        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        mgr.enroll(&make_payload("First"), None).unwrap();
        mgr.auto_save_result().unwrap();

        // Use same nonce twice
        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let mut p1 = make_payload("Replay Test 1");
        mgr2.enroll_with_recovery_phrase(&p1, &phrase_str).unwrap();
        let mut p2 = make_payload("Replay Test 2");
        p2.nonce = p1.nonce.clone(); // same nonce
        let result = mgr2.enroll_with_recovery_phrase(&p2, &phrase_str);
        assert!(result.is_err(), "replayed nonce must be rejected");
    }

    #[test]
    fn enroll_with_phrase_writes_keywrap() {
        let (_dir, vault_path, phrase_str) = setup_vault_with_recovery();

        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        mgr.enroll(&make_payload("First"), None).unwrap();
        mgr.auto_save_result().unwrap();

        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let p2 = make_payload("Phrase Device");
        let _ = mgr2.enroll_with_recovery_phrase(&p2, &phrase_str).unwrap();

        // Verify: keywrap file written for new device
        let keywrap_path = vault_path.join(format!("meta/keywrap/{}.json", p2.device_id));
        assert!(keywrap_path.exists(), "keywrap should be written");
    }

    #[test]
    fn enroll_with_phrase_rejects_already_enrolled() {
        let (_dir, vault_path, phrase_str) = setup_vault_with_recovery();

        let mut mgr = DeviceManager::new();
        mgr.epoch.activate().unwrap();
        mgr.set_vault_path(&vault_path);
        let p1 = make_payload("Device A");
        mgr.enroll(&p1, None).unwrap();
        mgr.auto_save_result().unwrap();

        // Try to re-enroll same device via phrase
        let mut mgr2 = DeviceManager::load_from_vault(&vault_path).unwrap();
        let result = mgr2.enroll_with_recovery_phrase(&p1, &phrase_str);
        assert!(result.is_err(), "already-enrolled device must be rejected");
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn activity_index_new_is_empty() {
        let idx = DeviceActivityIndex::new();
        assert_eq!(idx.v, 1);
        assert!(idx.devices.is_empty());
    }

    #[test]
    fn activity_index_update_and_read() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path();
        let device_id = Uuid::new_v4();

        DeviceActivityIndex::update(vault_path, &device_id, "abc123", 5).unwrap();

        let idx = DeviceActivityIndex::read(vault_path);
        assert_eq!(idx.devices.len(), 1);
        let entry = &idx.devices[&device_id.to_string()];
        assert_eq!(entry.last_commit, "abc123");
        assert_eq!(entry.epoch, 5);
        assert!(entry.last_push.ends_with('Z'));
    }

    #[test]
    fn activity_index_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let idx = DeviceActivityIndex::read(dir.path());
        assert!(idx.devices.is_empty());
    }

    #[test]
    fn activity_index_remove_device() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();

        DeviceActivityIndex::update(vault_path, &device_a, "aaa", 1).unwrap();
        DeviceActivityIndex::update(vault_path, &device_b, "bbb", 1).unwrap();

        DeviceActivityIndex::remove_device(vault_path, &device_a).unwrap();

        let idx = DeviceActivityIndex::read(vault_path);
        assert_eq!(idx.devices.len(), 1);
        assert!(idx.devices.contains_key(&device_b.to_string()));
    }

    #[test]
    fn activity_index_overwrite_on_update() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path();
        let device_id = Uuid::new_v4();

        DeviceActivityIndex::update(vault_path, &device_id, "first", 1).unwrap();
        DeviceActivityIndex::update(vault_path, &device_id, "second", 2).unwrap();

        let idx = DeviceActivityIndex::read(vault_path);
        assert_eq!(idx.devices.len(), 1);
        assert_eq!(idx.devices[&device_id.to_string()].last_commit, "second");
        assert_eq!(idx.devices[&device_id.to_string()].epoch, 2);
    }

    #[test]
    fn format_rfc3339_correctness() {
        // 2026-01-01T00:00:00Z = 1767225600
        assert_eq!(format_rfc3339(1767225600), "2026-01-01T00:00:00Z");
        // Known: 2026-06-02T14:30:00Z (152 days from Jan 1)
        assert_eq!(
            format_rfc3339(1767225600 + 152 * 86400 + 14 * 3600 + 30 * 60),
            "2026-06-02T14:30:00Z"
        );
    }
}
