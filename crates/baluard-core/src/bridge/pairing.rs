//! Pairing file + pairing secret.
//!
//! The pairing file lives at `<data_dir>/bridge/pairings.json` (0600) and holds
//! one entry per paired browser extension. The daemon is the SOLE writer
//! (atomic tmp+rename); the NMH reads its own entry read-only.
//!
//! A `PairingSecret` is a 256-bit random value, zeroized on drop. It is NOT a
//! key: it grants the ability to mint bridge tokens (which are themselves
//! allowlist-capped). Revocation = delete the entry.

use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Opaque pairing identifier. Stable across reauth; stored in the pairing file
/// and used as the key in the daemon's host-level bridge-token registry.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PairingId(String);

impl PairingId {
    /// Generate a fresh random pairing id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PairingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PairingId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A 256-bit pairing secret. Zeroized on drop; never logged.
///
/// Presented to the daemon at `bridge.reauth` to re-mint a bridge token after
/// every NMH spawn (and after daemon restarts). Constant-time compared by the
/// daemon. Hex-encoded on the wire + in the pairing file.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingSecret(Box<[u8; 32]>);

impl PairingSecret {
    /// Generate a fresh random secret from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut buf = Box::new([0u8; 32]);
        OsRng.fill_bytes(buf.as_mut_slice());
        Self(buf)
    }

    /// Hex-encode for storage/transit.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.0))
    }

    /// Decode from hex. Rejects malformed input.
    pub fn from_hex(s: &str) -> Result<Self, PairingError> {
        let bytes = hex::decode(s).map_err(|_| PairingError::MalformedSecret)?;
        if bytes.len() != 32 {
            return Err(PairingError::MalformedSecret);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(Box::new(arr)))
    }

    /// Raw bytes view (for constant-time comparison).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for PairingSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(**redacted**)")
    }
}

/// One row in the pairing file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingEntry {
    /// Stable id; also the key in the daemon's bridge-token registry.
    pub pairing_id: PairingId,
    /// Human label, e.g. "Chrome on laptop".
    pub name: String,
    /// "chrome" | "firefox" (free-form, for the management UI).
    pub browser: String,
    /// Hex-encoded 256-bit secret.
    pub secret: String,
    /// Unix epoch seconds when paired.
    pub created_at: u64,
}

/// The whole pairing file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PairingFile {
    #[serde(default)]
    pub pairings: Vec<PairingEntry>,
}

impl PairingFile {
    /// Path: `<data_dir>/bridge/pairings.json`.
    pub fn path() -> PathBuf {
        super::super::paths::data_dir()
            .join("bridge")
            .join("pairings.json")
    }

    /// Read + parse the file. Returns an empty `PairingFile` if absent
    /// (clean-install state; not an error).
    pub fn load() -> Result<Self, PairingError> {
        Self::load_from(&Self::path())
    }

    /// Read + parse from an explicit path (for tests).
    pub fn load_from(path: &Path) -> Result<Self, PairingError> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                if s.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_json::from_str(&s).map_err(|e| PairingError::Corrupt(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PairingError::Io(e.to_string())),
        }
    }

    /// Atomic write: tmp + rename. Creates the parent dir 0700.
    /// **Only the daemon calls this.** The NMH reads read-only.
    pub fn save_atomic(&self) -> Result<(), PairingError> {
        Self::save_atomic_to(self, &Self::path())
    }

    /// Atomic write to an explicit path (for tests).
    pub fn save_atomic_to(&self, path: &Path) -> Result<(), PairingError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| PairingError::Io(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| PairingError::Io(e.to_string()))?;
            }
        }
        let json = serde_json::to_string(self).map_err(|e| PairingError::Corrupt(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes()).map_err(|e| PairingError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| PairingError::Io(e.to_string()))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| PairingError::Io(e.to_string()))?;
        Ok(())
    }

    /// Find an entry by pairing id.
    pub fn get(&self, id: &PairingId) -> Option<&PairingEntry> {
        self.pairings.iter().find(|p| &p.pairing_id == id)
    }

    /// Remove an entry by pairing id. Returns true if it existed.
    pub fn remove(&mut self, id: &PairingId) -> bool {
        let before = self.pairings.len();
        self.pairings.retain(|p| &p.pairing_id != id);
        self.pairings.len() != before
    }
}

/// Errors raised by pairing-file operations.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("pairing file I/O error: {0}")]
    Io(String),
    #[error("pairing file corrupt: {0}")]
    Corrupt(String),
    #[error("malformed pairing secret")]
    MalformedSecret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrips_through_hex() {
        let s = PairingSecret::generate();
        let hex = s.to_hex();
        let back = PairingSecret::from_hex(&hex).expect("decode");
        assert_eq!(s.as_bytes(), back.as_bytes());
    }

    #[test]
    fn secrets_are_unique() {
        let a = PairingSecret::generate();
        let b = PairingSecret::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn malformed_secret_rejected() {
        assert!(PairingSecret::from_hex("tooshort").is_err());
        assert!(PairingSecret::from_hex(&"z".repeat(64)).is_err()); // non-hex
    }

    #[cfg(unix)]
    #[test]
    fn pairing_file_atomic_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("pairings.json");
        let mut pf = PairingFile::default();
        pf.pairings.push(PairingEntry {
            pairing_id: PairingId::new(),
            name: "test-chrome".into(),
            browser: "chrome".into(),
            secret: PairingSecret::generate().to_hex().to_string(),
            created_at: 1700000000,
        });
        pf.save_atomic_to(&path).expect("save");

        let loaded = PairingFile::load_from(&path).expect("load");
        assert_eq!(loaded.pairings.len(), 1);
        assert_eq!(loaded.pairings[0].name, "test-chrome");

        // No leftover tmp file.
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn load_missing_file_is_empty() {
        let path = PathBuf::from("/tmp/baluard-nonexistent-pairing-test-12345.json");
        let pf = PairingFile::load_from(&path).expect("missing = empty");
        assert!(pf.pairings.is_empty());
    }

    #[test]
    fn pairing_id_new_is_a_uuid() {
        let id = PairingId::new();
        let s = id.as_str();
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
        uuid::Uuid::parse_str(s).expect("valid uuid");
    }

    #[test]
    fn pairing_file_get_returns_matching_entry() {
        let mut pf = PairingFile::default();
        let id = PairingId::new();
        pf.pairings.push(PairingEntry {
            pairing_id: id.clone(),
            name: "found".into(),
            browser: "chrome".into(),
            secret: "a".repeat(64),
            created_at: 1,
        });
        pf.pairings.push(PairingEntry {
            pairing_id: PairingId::new(),
            name: "other".into(),
            browser: "firefox".into(),
            secret: "b".repeat(64),
            created_at: 2,
        });
        let got = pf.get(&id).expect("found");
        assert_eq!(got.name, "found");
        assert!(pf.get(&PairingId::new()).is_none());
    }

    #[test]
    fn pairing_file_remove_returns_true_on_existing_false_on_missing() {
        let mut pf = PairingFile::default();
        let id = PairingId::new();
        pf.pairings.push(PairingEntry {
            pairing_id: id.clone(),
            name: "x".into(),
            browser: "chrome".into(),
            secret: "c".repeat(64),
            created_at: 0,
        });
        assert!(pf.remove(&id), "remove returns true when entry exists");
        assert!(!pf.remove(&id), "second remove returns false");
        assert!(pf.pairings.is_empty());
    }

    #[test]
    fn secret_from_hex_rejects_wrong_length() {
        assert!(PairingSecret::from_hex(&"a".repeat(63)).is_err());
        assert!(PairingSecret::from_hex(&"a".repeat(65)).is_err());
        assert!(PairingSecret::from_hex("").is_err());
    }

    #[cfg(test)]
    proptest::proptest! {
        #[test]
        fn secret_hex_always_64_chars(s in ".*") {
            let _ = s;
            let secret = PairingSecret::generate();
            let hex = secret.to_hex();
            assert_eq!(hex.len(), 64);
        }
    }
}
