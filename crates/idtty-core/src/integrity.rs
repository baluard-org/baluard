//! Sequence manifest and rollback detection.
//!
//! D3/D22: Per-device sequence manifest, signed checkpoints, rollback detection.
//!
//! Each tracked object (cipher, keywrap, canary) has a monotonically-increasing
//! sequence number. On vault open, the manifest is compared against actual file
//! state. If any object's sequence has decreased, a rollback is detected.
//!
//! Fresh devices bootstrap by accepting the current state as ground truth.

use std::collections::HashMap;
use std::path::Path;

use crate::IdttyError;
use crate::error::IntegrityError;

/// Manifest file path relative to vault root.
const MANIFEST_PATH: &str = "meta/integrity.json";

/// A single tracked object's last-known sequence number and signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Object identifier (e.g. cipher UUID or "rk-canary").
    pub object_id: String,
    /// Last-seen sequence number (monotonically increasing).
    pub seq: u64,
    /// Device that recorded this checkpoint.
    pub device_id: String,
    /// Ed25519 signature over `object_id || seq || device_id`.
    pub signature: String,
}

/// Per-device sequence manifest persisted to `meta/integrity.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityManifest {
    /// Map: object_id → Checkpoint.
    pub checkpoints: HashMap<String, Checkpoint>,
    /// Device ID that last wrote this manifest.
    pub last_writer: String,
}

impl IntegrityManifest {
    /// Load manifest from vault directory. Returns empty manifest if file missing.
    pub fn load(vault_path: &Path) -> Result<Self, IdttyError> {
        let path = vault_path.join(MANIFEST_PATH);
        if !path.exists() {
            return Ok(Self {
                checkpoints: HashMap::new(),
                last_writer: String::new(),
            });
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| IntegrityError::Io(format!("read manifest: {e}")))?;
        serde_json::from_str(&data)
            .map_err(|e| IntegrityError::Corrupt(format!("parse manifest: {e}")).into())
    }

    /// Persist manifest to vault directory (atomic: write tmp + rename).
    pub fn save(&self, vault_path: &Path) -> Result<(), IdttyError> {
        let path = vault_path.join(MANIFEST_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| IntegrityError::Io(format!("create meta dir: {e}")))?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| IntegrityError::Corrupt(format!("serialize manifest: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)
            .map_err(|e| IntegrityError::Io(format!("write manifest tmp: {e}")))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| IntegrityError::Io(format!("rename manifest: {e}")))?;
        Ok(())
    }

    /// Record a checkpoint for an object. Returns previous seq if this is an update.
    ///
    /// Signs the checkpoint with the device's Ed25519 key.
    pub fn record(
        &mut self,
        object_id: &str,
        seq: u64,
        device_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Option<u64>, IdttyError> {
        // Enforce monotonicity: reject seq <= existing
        if let Some(existing) = self.checkpoints.get(object_id) {
            if seq <= existing.seq {
                return Err(IntegrityError::RollbackDetected {
                    object: object_id.to_string(),
                    old_seq: existing.seq,
                    new_seq: seq,
                }
                .into());
            }
        }

        let payload = format!("{object_id}|{seq}|{device_id}");
        let sig = crate::crypto::signature::sign(signing_key, payload.as_bytes())
            .map_err(|e| IntegrityError::Corrupt(format!("sign checkpoint: {e}")))?;

        let old_seq = self.checkpoints.get(object_id).map(|c| c.seq);
        self.checkpoints.insert(
            object_id.to_string(),
            Checkpoint {
                object_id: object_id.to_string(),
                seq,
                device_id: device_id.to_string(),
                signature: hex::encode(sig.to_bytes()),
            },
        );
        self.last_writer = device_id.to_string();
        Ok(old_seq)
    }

    /// Verify a checkpoint's signature against a device's verifying key.
    pub fn verify_checkpoint(
        &self,
        object_id: &str,
        verifying_key: &[u8; 32],
    ) -> Result<(), IdttyError> {
        let cp = self
            .checkpoints
            .get(object_id)
            .ok_or_else(|| IntegrityError::Corrupt(format!("no checkpoint for {object_id}")))?;

        let payload = format!("{}|{}|{}", cp.object_id, cp.seq, cp.device_id);
        let sig_bytes = hex::decode(&cp.signature)
            .map_err(|e| IntegrityError::Corrupt(format!("decode sig: {e}")))?;

        let vk =
            crate::crypto::signature::verifying_key_from_bytes(verifying_key).map_err(|_| {
                IntegrityError::InvalidCheckpointSignature {
                    device_id: cp.device_id.clone(),
                }
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|_| {
            IntegrityError::InvalidCheckpointSignature {
                device_id: cp.device_id.clone(),
            }
        })?;

        crate::crypto::signature::verify(&vk, payload.as_bytes(), &sig).map_err(|_| {
            IntegrityError::InvalidCheckpointSignature {
                device_id: cp.device_id.clone(),
            }
            .into()
        })
    }

    /// Check for rollback: compare manifest seq against actual seq for each object.
    ///
    /// Returns list of objects where actual seq < manifest seq (rollback detected).
    /// Returns empty if no rollback.
    pub fn detect_rollback(&self, actual_seqs: &HashMap<String, u64>) -> Vec<RollbackEntry> {
        let mut rollbacks = Vec::new();
        for (object_id, cp) in &self.checkpoints {
            if let Some(&actual_seq) = actual_seqs.get(object_id) {
                if actual_seq < cp.seq {
                    rollbacks.push(RollbackEntry {
                        object_id: object_id.clone(),
                        expected_seq: cp.seq,
                        actual_seq,
                    });
                }
            } else {
                // Object tracked in manifest but absent from filesystem (deleted)
                rollbacks.push(RollbackEntry {
                    object_id: object_id.clone(),
                    expected_seq: cp.seq,
                    actual_seq: 0,
                });
            }
        }
        rollbacks
    }

    /// Bootstrap a fresh device: accept all current state as ground truth.
    ///
    /// Creates checkpoints for all provided objects at their current seq values.
    pub fn bootstrap(
        &mut self,
        objects: &[(String, u64)],
        device_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), IdttyError> {
        for (object_id, seq) in objects {
            self.record(object_id, *seq, device_id, signing_key)?;
        }
        Ok(())
    }
}

/// A detected rollback for a single object.
#[derive(Debug, Clone)]
pub struct RollbackEntry {
    pub object_id: String,
    pub expected_seq: u64,
    pub actual_seq: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::generate_ed25519_keypair;

    fn tmp_vault() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn test_keys() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        generate_ed25519_keypair()
    }

    #[test]
    fn empty_manifest_load() {
        let dir = tmp_vault();
        let manifest = IntegrityManifest::load(dir.path()).unwrap();
        assert!(manifest.checkpoints.is_empty());
    }

    #[test]
    fn record_and_save_roundtrip() {
        let dir = tmp_vault();
        let (signing, _) = test_keys();

        let mut manifest = IntegrityManifest::load(dir.path()).unwrap();
        let old = manifest
            .record("cipher-1", 5, "device-A", &signing)
            .unwrap();
        assert_eq!(old, None);

        let old = manifest
            .record("cipher-1", 10, "device-A", &signing)
            .unwrap();
        assert_eq!(old, Some(5));

        manifest.save(dir.path()).unwrap();

        let loaded = IntegrityManifest::load(dir.path()).unwrap();
        assert_eq!(loaded.checkpoints["cipher-1"].seq, 10);
        assert_eq!(loaded.last_writer, "device-A");
    }

    #[test]
    fn verify_checkpoint_signature() {
        let (signing, _) = test_keys();
        let verifying_bytes = crate::crypto::signature::verifying_key_bytes(
            &crate::crypto::signature::verifying_key_from_bytes(
                &signing.verifying_key().to_bytes(),
            )
            .unwrap(),
        );

        let mut manifest = IntegrityManifest {
            checkpoints: HashMap::new(),
            last_writer: "device-A".into(),
        };
        manifest
            .record("cipher-1", 5, "device-A", &signing)
            .unwrap();

        manifest
            .verify_checkpoint("cipher-1", &verifying_bytes)
            .unwrap();
    }

    #[test]
    fn verify_tampered_checkpoint_fails() {
        let (signing, _) = test_keys();
        let verifying_bytes = signing.verifying_key().to_bytes();

        let mut manifest = IntegrityManifest {
            checkpoints: HashMap::new(),
            last_writer: "device-A".into(),
        };
        manifest
            .record("cipher-1", 5, "device-A", &signing)
            .unwrap();

        // Tamper with seq
        manifest.checkpoints.get_mut("cipher-1").unwrap().seq = 99;

        assert!(
            manifest
                .verify_checkpoint("cipher-1", &verifying_bytes)
                .is_err()
        );
    }

    #[test]
    fn detect_rollback() {
        let (signing, _) = test_keys();

        let mut manifest = IntegrityManifest {
            checkpoints: HashMap::new(),
            last_writer: "device-A".into(),
        };
        manifest
            .record("cipher-1", 10, "device-A", &signing)
            .unwrap();
        manifest
            .record("cipher-2", 20, "device-A", &signing)
            .unwrap();

        // cipher-1 rolled back from 10 to 5, cipher-2 advanced from 20 to 25
        let actual: HashMap<String, u64> = [("cipher-1".into(), 5), ("cipher-2".into(), 25)]
            .into_iter()
            .collect();

        let rollbacks = manifest.detect_rollback(&actual);
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].object_id, "cipher-1");
        assert_eq!(rollbacks[0].expected_seq, 10);
        assert_eq!(rollbacks[0].actual_seq, 5);
    }

    #[test]
    fn no_rollback_on_advance() {
        let (signing, _) = test_keys();

        let mut manifest = IntegrityManifest {
            checkpoints: HashMap::new(),
            last_writer: "device-A".into(),
        };
        manifest
            .record("cipher-1", 5, "device-A", &signing)
            .unwrap();

        let actual: HashMap<String, u64> = [("cipher-1".into(), 10)].into_iter().collect();
        assert!(manifest.detect_rollback(&actual).is_empty());
    }

    #[test]
    fn bootstrap_fresh_device() {
        let (signing, _) = test_keys();
        let dir = tmp_vault();

        let mut manifest = IntegrityManifest::load(dir.path()).unwrap();
        let objects = vec![
            ("cipher-1".into(), 5),
            ("cipher-2".into(), 10),
            ("rk-canary".into(), 3),
        ];
        manifest.bootstrap(&objects, "device-B", &signing).unwrap();
        manifest.save(dir.path()).unwrap();

        let loaded = IntegrityManifest::load(dir.path()).unwrap();
        assert_eq!(loaded.checkpoints.len(), 3);
        assert_eq!(loaded.checkpoints["cipher-1"].seq, 5);
        assert_eq!(loaded.checkpoints["cipher-2"].seq, 10);
        assert_eq!(loaded.checkpoints["rk-canary"].seq, 3);
    }
}
