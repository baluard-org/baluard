//! Sealed device private key file: `meta/device-privkey.json` (C1 fix).
//!
//! The keystore-less fallback used to hold raw hex X25519/Ed25519 private
//! keys: anyone with disk read access could lift them and unwrap the Root
//! Key without ever touching the master password. The file is now an
//! AES-256-GCM envelope (same envelope format as the canaries) sealed
//! under a purpose-scoped HKDF subkey of the KEK
//! ([`crate::crypto::hkdf_derive::derive_devkey_seal_key`]).
//!
//! Seal-key lifecycle:
//! - Vault creation and every master-password unlock have the KEK in hand
//!   and seal/open directly.
//! - The unlocked `VaultHandle` retains the 32-byte subkey (never the KEK)
//!   so post-unlock consumers (sync signing, password change) can open the
//!   file without keeping the KEK resident.
//! - Phrase-only flows (recovery, enroll-with-phrase) run before any
//!   master-password material exists, so they still write the legacy
//!   plaintext file; the next successful unlock re-seals it lazily
//!   ([`reseal_if_legacy`]). That window is the residual exposure, and it
//!   is strictly shorter than the previous always-plaintext state.
//!
//! File formats:
//! - sealed v1: `{"type":"baluard-devkey-seal-v1","envelope":"<base64>"}`
//! - legacy (pre-seal vaults + phrase-flow writes): the inner JSON itself,
//!   detected by the presence of `x25519_private`.

use std::path::Path;

use base64::Engine as _;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{BaluardError, VaultError};
use crate::types::EnvelopeHeader;
use crate::{ALG_AES_256_GCM, BALUARD_VERSION};

/// Marker + AAD for the sealed format. Binds the envelope to this purpose:
/// a sealed devkey blob cannot be replayed as another meta file (and vice
/// versa) because GCM authenticates the AAD.
pub const SEAL_TYPE: &str = "baluard-devkey-seal-v1";

/// Local device ID file name (gitignored).
pub const DEVICE_ID_FILE: &str = "meta/device-id";

/// Write local device ID to `meta/device-id` file.
pub fn write_device_id(vault_path: &Path, device_id: Uuid) -> Result<(), BaluardError> {
    let id_path = vault_path.join(DEVICE_ID_FILE);
    super::write_vault_file(&id_path, device_id.to_string().as_bytes())
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write device-id: {e}"))))
}

/// Read local device ID from `meta/device-id` or `meta/device-privkey.json`.
pub fn read_device_id(vault_path: &Path) -> Option<Uuid> {
    // 1. Check meta/device-id file
    let id_path = vault_path.join(DEVICE_ID_FILE);
    if id_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&id_path) {
            if let Ok(id) = Uuid::parse_str(content.trim()) {
                return Some(id);
            }
        }
    }

    // 2. Check meta/device-privkey.json outer JSON
    let privkey_path = vault_path.join("meta/device-privkey.json");
    if privkey_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&privkey_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(s) = v["device_id"].as_str() {
                    if let Ok(id) = Uuid::parse_str(s) {
                        return Some(id);
                    }
                }
            }
        }
    }

    None
}

/// How the file on disk presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivkeyFileKind {
    Sealed,
    LegacyPlaintext,
    Absent,
}

pub fn file_kind(path: &Path) -> PrivkeyFileKind {
    if !path.exists() {
        return PrivkeyFileKind::Absent;
    }
    let Ok(data) = std::fs::read_to_string(path) else {
        return PrivkeyFileKind::Absent;
    };
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(v) if v["type"].as_str() == Some(SEAL_TYPE) => PrivkeyFileKind::Sealed,
        Ok(v) if v["x25519_private"].is_string() => PrivkeyFileKind::LegacyPlaintext,
        _ => PrivkeyFileKind::Absent,
    }
}

/// Build the sealed file bytes for an inner privkey JSON payload.
pub fn seal_bytes(
    seal_key: &[u8; 32],
    inner_json: &str,
    device_id: Option<Uuid>,
) -> Result<Vec<u8>, BaluardError> {
    let nonce = crate::crypto::aead::build_random_nonce();
    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let envelope = crate::crypto::aead::encrypt(
        seal_key,
        inner_json.as_bytes(),
        SEAL_TYPE.as_bytes(),
        &nonce,
        header,
    )?;
    let serialized = crate::vault::envelope::serialize(&envelope)?;
    let mut doc = serde_json::json!({
        "type": SEAL_TYPE,
        "envelope": base64::engine::general_purpose::STANDARD.encode(serialized),
    });
    let id = device_id.or_else(|| {
        serde_json::from_str::<serde_json::Value>(inner_json)
            .ok()
            .and_then(|v| v["device_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
    });
    if let Some(id) = id {
        doc["device_id"] = serde_json::Value::String(id.to_string());
    }
    Ok(doc.to_string().into_bytes())
}

/// Open sealed file bytes back into the inner privkey JSON.
pub fn open_bytes(seal_key: &[u8; 32], file: &[u8]) -> Result<String, BaluardError> {
    let v: serde_json::Value = serde_json::from_slice(file)
        .map_err(|e| VaultError::Corrupt(format!("sealed devkey json: {e}")))?;
    if v["type"].as_str() != Some(SEAL_TYPE) {
        return Err(VaultError::Corrupt("not a sealed devkey file".into()).into());
    }
    let enc = v["envelope"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("sealed devkey missing envelope".into()))?;
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(enc)
        .map_err(|e| VaultError::Corrupt(format!("sealed devkey base64: {e}")))?;
    let envelope = crate::vault::envelope::deserialize(&serialized)?;
    let mut pt = crate::crypto::aead::decrypt(seal_key, &envelope)
        .map_err(|_| VaultError::Corrupt("devkey seal key mismatch".into()))?;
    let inner = String::from_utf8(pt.clone())
        .map_err(|e| VaultError::Corrupt(format!("devkey plaintext utf8: {e}")))?;
    pt.zeroize();
    Ok(inner)
}

/// Atomically write the sealed file (0600 via the WS1-backed writer).
pub fn seal_file(
    path: &Path,
    inner_json: &str,
    seal_key: &[u8; 32],
    device_id: Option<Uuid>,
) -> Result<(), BaluardError> {
    let bytes = seal_bytes(seal_key, inner_json, device_id)?;
    super::write_vault_file(path, &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write sealed devkey: {e}"))))?;
    if let Some(vault_dir) = path.parent().and_then(|p| p.parent()) {
        let id = device_id.or_else(|| {
            serde_json::from_str::<serde_json::Value>(inner_json)
                .ok()
                .and_then(|v| v["device_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
        });
        if let Some(id) = id {
            let _ = write_device_id(vault_dir, id);
        }
    }
    Ok(())
}

/// Read the privkey JSON from the file, sealed or legacy.
///
/// Sealed files fail closed when no seal key is supplied (a caller without
/// master-password material must not read the keys). Legacy plaintext is
/// returned as-is so phrase-flow writes keep working until the next
/// unlock re-seals them.
pub fn read_privkey_file(path: &Path, seal_key: Option<&[u8; 32]>) -> Result<String, BaluardError> {
    match file_kind(path) {
        PrivkeyFileKind::Absent => {
            Err(VaultError::NotFound("device private key not found".into()).into())
        }
        PrivkeyFileKind::Sealed => {
            let key = seal_key.ok_or_else(|| {
                BaluardError::from(VaultError::Locked) // fail closed: sealed but no key material
            })?;
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            open_bytes(key, file.as_bytes())
        }
        PrivkeyFileKind::LegacyPlaintext => std::fs::read_to_string(path)
            .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")).into()),
    }
}

/// Re-seal a legacy plaintext file under `seal_key`. No-op for sealed or
/// missing files. Returns whether a re-seal happened.
pub fn reseal_if_legacy(
    path: &Path,
    seal_key: &[u8; 32],
    device_id: Option<Uuid>,
) -> Result<bool, BaluardError> {
    if file_kind(path) != PrivkeyFileKind::LegacyPlaintext {
        return Ok(false);
    }
    let inner = std::fs::read_to_string(path)
        .map_err(|e| VaultError::Metadata(format!("reading legacy privkey: {e}")))?;
    seal_file(path, &inner, seal_key, device_id)?;
    Ok(true)
}

/// Re-key the seal: open with `old`, rewrite sealed under `new`. Also
/// converts legacy files. Returns whether the file changed. Used by master
/// password change (KEK rotates, so the seal subkey rotates with it).
pub fn rotate_seal_key(
    path: &Path,
    old_seal_key: &[u8; 32],
    new_seal_key: &[u8; 32],
    device_id: Option<Uuid>,
) -> Result<bool, BaluardError> {
    match file_kind(path) {
        PrivkeyFileKind::Absent => Ok(false),
        PrivkeyFileKind::LegacyPlaintext => {
            let inner = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading legacy privkey: {e}")))?;
            seal_file(path, &inner, new_seal_key, device_id)?;
            Ok(true)
        }
        PrivkeyFileKind::Sealed => {
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            let id = device_id.or_else(|| {
                serde_json::from_str::<serde_json::Value>(&file)
                    .ok()
                    .and_then(|v| v["device_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
            });
            let inner = open_bytes(old_seal_key, file.as_bytes())?;
            seal_file(path, &inner, new_seal_key, id)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "baluard-devkey-test-{name}-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    const INNER: &str = r#"{"x25519_private":"aa","ed25519_private":"bb"}"#;

    #[test]
    fn seal_open_roundtrip() {
        let p = tmp_path("roundtrip");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        let out = read_privkey_file(&p, Some(&[7u8; 32])).unwrap();
        assert_eq!(out, INNER);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sealed_file_holds_no_hex_keys() {
        let p = tmp_path("nohex");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("x25519_private"));
        assert!(!raw.contains("ed25519_private"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn wrong_seal_key_fails_closed() {
        let p = tmp_path("wrongkey");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        assert!(read_privkey_file(&p, Some(&[8u8; 32])).is_err());
        // No key at all: still closed.
        assert!(read_privkey_file(&p, None).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn reseal_converts_legacy_and_is_idempotent() {
        let p = tmp_path("reseal");
        super::super::write_vault_file(&p, INNER.as_bytes()).unwrap();
        assert_eq!(file_kind(&p), PrivkeyFileKind::LegacyPlaintext);
        assert!(reseal_if_legacy(&p, &[7u8; 32], None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("x25519_private"));
        // Second call: no-op.
        assert!(!reseal_if_legacy(&p, &[7u8; 32], None).unwrap());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rotate_seal_key_rekeys_sealed_file() {
        let p = tmp_path("rotate");
        seal_file(&p, INNER, &[1u8; 32], None).unwrap();
        assert!(rotate_seal_key(&p, &[1u8; 32], &[2u8; 32], None).unwrap());
        assert_eq!(read_privkey_file(&p, Some(&[2u8; 32])).unwrap(), INNER);
        assert!(read_privkey_file(&p, Some(&[1u8; 32])).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn seal_preserves_device_id_in_outer_json() {
        let p = tmp_path("device-id-test");
        let id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], Some(id)).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["device_id"].as_str(), Some(id.to_string().as_str()));
        std::fs::remove_file(&p).ok();
    }
}
