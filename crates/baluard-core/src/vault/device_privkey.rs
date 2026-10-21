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

/// Hardware-AND seal: content key = HKDF(hw_ecdh_secret || kek_subkey).
/// The file additionally carries the fresh ephemeral public key and the
/// hardware binding id; unwrap needs BOTH the master password and the
/// chip. Devices without a chip never write this kind.
pub const SEAL_TYPE_HW: &str = "baluard-devkey-seal-v2-hw";

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
    SealedHw,
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
        Ok(v) if v["type"].as_str() == Some(SEAL_TYPE_HW) => PrivkeyFileKind::SealedHw,
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
            .and_then(|v| {
                v["device_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
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
    super::write_vault_file(path, &bytes).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("write sealed devkey: {e}")))
    })?;
    if let Some(vault_dir) = path.parent().and_then(|p| p.parent()) {
        let id = device_id.or_else(|| {
            serde_json::from_str::<serde_json::Value>(inner_json)
                .ok()
                .and_then(|v| {
                    v["device_id"]
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok())
                })
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
        PrivkeyFileKind::SealedHw => {
            let key = seal_key.ok_or_else(|| BaluardError::from(VaultError::Locked))?;
            let hw = crate::hwkey::available().ok_or_else(crate::hwkey::hw_unavailable_error)?;
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            open_bytes_hw(&*hw, key, file.as_bytes())
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
        PrivkeyFileKind::SealedHw => {
            // Password change with the hardware seal: fresh ephemeral per
            // write, binding survives. Fails closed when the chip is gone
            // (the phrase path remains the rescue).
            let hw = crate::hwkey::available().ok_or_else(crate::hwkey::hw_unavailable_error)?;
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            let v: serde_json::Value = serde_json::from_str(&file)
                .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey json: {e}")))?;
            let binding = v["hw_binding"]
                .as_str()
                .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing binding".into()))?
                .to_string();
            let id = device_id.or_else(|| {
                v["device_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
            });
            let inner = open_bytes_hw(&*hw, old_seal_key, file.as_bytes())?;
            let bytes = seal_bytes_hw(&*hw, &binding, new_seal_key, &inner, id)?;
            super::write_vault_file(path, &bytes).map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!("write hw-sealed devkey: {e}")))
            })?;
            Ok(true)
        }
        PrivkeyFileKind::Sealed => {
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            let id = device_id.or_else(|| {
                serde_json::from_str::<serde_json::Value>(&file)
                    .ok()
                    .and_then(|v| {
                        v["device_id"]
                            .as_str()
                            .and_then(|s| Uuid::parse_str(s).ok())
                    })
            });
            let inner = open_bytes(old_seal_key, file.as_bytes())?;
            seal_file(path, &inner, new_seal_key, id)?;
            Ok(true)
        }
    }
}

// ---------------------------------------------------------------------------
// v2-hw: hardware-AND seal
// ---------------------------------------------------------------------------

/// Seal the inner privkey JSON under the v2-hw AND construction.
///
/// `hw` supplies the chip: a fresh ephemeral keypair is generated per
/// write, the chip performs ECDH against its public half, and the content
/// key combines that secret with the ordinary KEK subkey. Either input
/// alone cannot open the file. The file records the ephemeral public key
/// and binding id so the next open can re-run the chip side.
pub fn seal_bytes_hw(
    hw: &dyn crate::hwkey::HardwareKeyStore,
    binding: &str,
    seal_key: &[u8; 32],
    inner_json: &str,
    device_id: Option<Uuid>,
) -> Result<Vec<u8>, BaluardError> {
    // The backend mints the ephemeral in its own primitive family and
    // discards the private half - only its chip can reproduce the secret.
    let (peer, hw_secret) = hw.ecdh_ephemeral(binding)?;
    let ck = crate::hwkey::combine_seal_inputs(&hw_secret, seal_key);

    let nonce = crate::crypto::aead::build_random_nonce();
    let header = EnvelopeHeader {
        version: BALUARD_VERSION,
        alg_id: ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    // AAD binds purpose AND the stored peer bytes: an attacker editing the
    // file's ephemeral_pub fails AEAD authentication outright instead of
    // merely deriving a wrong secret.
    let aad = hw_aad(&peer.0);
    let envelope = crate::crypto::aead::encrypt(&ck, inner_json.as_bytes(), &aad, &nonce, header)?;
    let serialized = crate::vault::envelope::serialize(&envelope)?;
    let mut doc = serde_json::json!({
        "type": SEAL_TYPE_HW,
        "envelope": base64::engine::general_purpose::STANDARD.encode(serialized),
        "ephemeral_pub": base64::engine::general_purpose::STANDARD.encode(peer.0),
        "hw_binding": binding,
    });
    let id = device_id.or_else(|| outer_device_id(inner_json));
    if let Some(id) = id {
        doc["device_id"] = serde_json::Value::String(id.to_string());
    }
    Ok(doc.to_string().into_bytes())
}

/// v2-hw AAD: purpose string + the exact stored ephemeral bytes.
fn hw_aad(peer: &[u8; 65]) -> Vec<u8> {
    let mut aad = SEAL_TYPE_HW.as_bytes().to_vec();
    aad.extend_from_slice(peer);
    aad
}

fn outer_device_id(inner_json: &str) -> Option<Uuid> {
    serde_json::from_str::<serde_json::Value>(inner_json)
        .ok()
        .and_then(|v| {
            v["device_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
        })
}

/// Open a v2-hw file. `hw` must be the SAME keystore (and binding) that
/// sealed it; a missing or wrong chip fails closed - never a silent
/// downgrade. The KEK subkey is still required, so the master password
/// remains the single user-facing credential.
pub fn open_bytes_hw(
    hw: &dyn crate::hwkey::HardwareKeyStore,
    seal_key: &[u8; 32],
    file: &[u8],
) -> Result<String, BaluardError> {
    let v: serde_json::Value = serde_json::from_slice(file)
        .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey json: {e}")))?;
    if v["type"].as_str() != Some(SEAL_TYPE_HW) {
        return Err(VaultError::Corrupt("not an hw-sealed devkey file".into()).into());
    }
    let binding = v["hw_binding"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing binding".into()))?;
    let eph = v["ephemeral_pub"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing ephemeral".into()))?;
    let peer_bytes = base64::engine::general_purpose::STANDARD
        .decode(eph)
        .map_err(|e| VaultError::Corrupt(format!("hw ephemeral base64: {e}")))?;
    let peer: [u8; 65] = peer_bytes
        .try_into()
        .map_err(|_| VaultError::Corrupt("hw ephemeral wrong length".into()))?;

    let enc = v["envelope"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing envelope".into()))?;
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(enc)
        .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey base64: {e}")))?;
    let envelope = crate::vault::envelope::deserialize(&serialized)?;

    // Chip first so a hardware failure surfaces as the typed unavailable
    // error, not an opaque AEAD mismatch.
    let hw_secret = hw
        .ecdh(binding, &crate::hwkey::EphemeralPub(peer))
        .map_err(|_| crate::hwkey::hw_unavailable_error())?;
    let ck = crate::hwkey::combine_seal_inputs(&hw_secret, seal_key);
    let mut pt = crate::crypto::aead::decrypt(&ck, &envelope)
        .map_err(|_| VaultError::Corrupt("devkey seal key mismatch".into()))?;
    let inner = String::from_utf8(pt.clone())
        .map_err(|e| VaultError::Corrupt(format!("devkey plaintext utf8: {e}")))?;
    pt.zeroize();
    Ok(inner)
}

/// Enable the hardware seal on an existing sealed/legacy file (the
/// settings toggle): re-key under the AND construction. Idempotent for
/// v2-hw files. Fails closed when no usable chip is installed.
pub fn enable_hw_seal(
    path: &Path,
    seal_key: &[u8; 32],
    vault_id: Uuid,
    device_id: Option<Uuid>,
) -> Result<bool, BaluardError> {
    let Some(hw) = crate::hwkey::available() else {
        return Err(VaultError::Locked.into()); // typed unavailable; surfaces map it
    };
    match file_kind(path) {
        PrivkeyFileKind::Absent => Ok(false),
        PrivkeyFileKind::SealedHw => Ok(false),
        PrivkeyFileKind::LegacyPlaintext | PrivkeyFileKind::Sealed => {
            let inner = read_privkey_file(path, Some(seal_key))?;
            let binding = hw.create_binding(vault_id)?;
            let bytes = seal_bytes_hw(&*hw, &binding, seal_key, &inner, device_id)?;
            super::write_vault_file(path, &bytes).map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!("write hw-sealed devkey: {e}")))
            })?;
            Ok(true)
        }
    }
}

/// Disable the hardware seal (the settings toggle): downgrade to v1. The
/// chip is needed once, by design - a dead chip cannot hide the toggle's
/// consequence.
pub fn disable_hw_seal(
    path: &Path,
    hw: &dyn crate::hwkey::HardwareKeyStore,
    seal_key: &[u8; 32],
    device_id: Option<Uuid>,
) -> Result<bool, BaluardError> {
    if file_kind(path) != PrivkeyFileKind::SealedHw {
        return Ok(false);
    }
    let file = std::fs::read_to_string(path)
        .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
    let inner = open_bytes_hw(hw, seal_key, file.as_bytes())?;
    let binding = serde_json::from_str::<serde_json::Value>(&file)
        .ok()
        .and_then(|v| v["hw_binding"].as_str().map(str::to_string));
    seal_file(path, &inner, seal_key, device_id)?;
    if let Some(b) = binding {
        let _ = hw.delete_binding(&b);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

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

    // ---- v2-hw hardware-AND seal ----

    /// Software mock with deletion tracking: X25519-style agreement over
    /// the opaque peer bytes (the seal layer treats the secret as opaque).
    struct HwMock {
        deleted: std::sync::Mutex<Vec<String>>,
    }

    impl crate::hwkey::HardwareKeyStore for HwMock {
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "test-mock".into(),
            }
        }
        fn create_binding(&self, vault_id: Uuid) -> Result<String, BaluardError> {
            Ok(crate::hwkey::binding_tag(vault_id))
        }
        fn ecdh_ephemeral(
            &self,
            binding: &str,
        ) -> Result<(crate::hwkey::EphemeralPub, crate::hwkey::SharedSecret), BaluardError>
        {
            use sha2::{Digest, Sha256};
            let mut peer = [0u8; 65];
            peer[0] = 0x04;
            rand::Rng::fill(&mut rand::thread_rng(), &mut peer[1..]);
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(peer);
            Ok((
                crate::hwkey::EphemeralPub(peer),
                Zeroizing::new(h.finalize().into()),
            ))
        }
        fn ecdh(
            &self,
            binding: &str,
            peer: &crate::hwkey::EphemeralPub,
        ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(peer.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, binding: &str) -> Result<(), BaluardError> {
            self.deleted.lock().unwrap().push(binding.to_string());
            Ok(())
        }
    }

    /// The keystore registry and the kill-switch env var are
    /// process-global; every hw test holds this for its whole body.
    static HW_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The kill-switch env var may be preset for the whole `just test`
    /// process; the mock tests need it cleared for their body and the
    /// original restored after.
    fn hw_env_clear() -> Option<String> {
        // SAFETY: single-threaded under HW_LOCK.
        unsafe {
            let old = std::env::var(crate::hwkey::DISABLE_ENV).ok();
            std::env::remove_var(crate::hwkey::DISABLE_ENV);
            old
        }
    }

    /// SAFETY: single-threaded under HW_LOCK.
    fn hw_env_restore(old: Option<String>) {
        unsafe {
            match old {
                Some(v) => std::env::set_var(crate::hwkey::DISABLE_ENV, v),
                None => std::env::remove_var(crate::hwkey::DISABLE_ENV),
            }
        }
    }

    fn install_mock() -> std::sync::Arc<HwMock> {
        let m = std::sync::Arc::new(HwMock {
            deleted: std::sync::Mutex::new(Vec::new()),
        });
        crate::hwkey::install(m.clone());
        m
    }

    #[test]
    fn hw_seal_roundtrip_with_mock_keystore() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let m = install_mock();
        let p = tmp_path("hw-roundtrip");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        let vault_id = Uuid::new_v4();
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("x25519_private"));
        assert!(raw.contains("hw_binding"));
        assert!(raw.contains("ephemeral_pub"));
        let out = read_privkey_file(&p, Some(&[7u8; 32])).unwrap();
        assert_eq!(out, INNER);
        assert!(m.deleted.lock().unwrap().is_empty());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_and_property_either_input_missing_fails() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-and");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).unwrap();

        // Hardware missing: fail closed even with the right password, and
        // the error must name the chip - never read as a password failure.
        crate::hwkey::uninstall();
        let err = read_privkey_file(&p, Some(&[7u8; 32])).unwrap_err();
        assert!(
            err.to_string().contains("security chip"),
            "hw failure must be typed, got: {err}"
        );
        assert!(rotate_seal_key(&p, &[7u8; 32], &[9u8; 32], None).is_err());
        // Re-install but wrong password: still closed.
        install_mock();
        assert!(read_privkey_file(&p, Some(&[8u8; 32])).is_err());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_enable_requires_chip_and_is_idempotent() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let p = tmp_path("hw-enable-gate");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        // No chip installed: the toggle fails closed, file untouched.
        assert!(enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).is_err());
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        install_mock();
        assert!(enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).unwrap());
        // Second enable: no-op.
        assert!(!enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).unwrap());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_disable_downgrades_to_v1_and_deletes_binding() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let m = install_mock();
        let p = tmp_path("hw-disable");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], vault_id, None).unwrap();
        let binding = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["hw_binding"].as_str().unwrap().to_string()
        };
        assert!(disable_hw_seal(&p, &*m, &[7u8; 32], None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("hw_binding"));
        assert_eq!(read_privkey_file(&p, Some(&[7u8; 32])).unwrap(), INNER);
        assert_eq!(
            m.deleted.lock().unwrap().as_slice(),
            std::slice::from_ref(&binding)
        );
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_password_change_rekeys_with_fresh_ephemeral() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-rekey");
        seal_file(&p, INNER, &[1u8; 32], None).unwrap();
        enable_hw_seal(&p, &[1u8; 32], Uuid::new_v4(), None).unwrap();
        let eph_before = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["ephemeral_pub"].as_str().unwrap().to_string()
        };
        assert!(rotate_seal_key(&p, &[1u8; 32], &[2u8; 32], None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        let eph_after = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["ephemeral_pub"].as_str().unwrap().to_string()
        };
        assert_ne!(eph_before, eph_after, "fresh ephemeral per write");
        assert_eq!(read_privkey_file(&p, Some(&[2u8; 32])).unwrap(), INNER);
        assert!(read_privkey_file(&p, Some(&[1u8; 32])).is_err());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn phrase_rescue_after_simulated_hardware_death() {
        let _g = HW_LOCK.lock().unwrap();
        // A v2-hw file whose chip is gone is unwrappable forever - the
        // rescue is the phrase path, which mints a fresh identity and
        // overwrites the local devkey (legacy plaintext), after which the
        // next unlock re-seals it as v1.
        crate::hwkey::uninstall();
        install_mock();
        let _old_env = hw_env_clear();
        let p = tmp_path("hw-rescue");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).unwrap();
        crate::hwkey::uninstall();
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_err());

        // The enroll flow's write: plaintext over the dead seal.
        super::super::write_vault_file(&p, INNER.as_bytes()).unwrap();
        assert_eq!(file_kind(&p), PrivkeyFileKind::LegacyPlaintext);
        assert!(reseal_if_legacy(&p, &[7u8; 32], None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        assert_eq!(read_privkey_file(&p, Some(&[7u8; 32])).unwrap(), INNER);
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_seal_respects_the_kill_switch() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-killswitch");
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None).unwrap();
        // SAFETY: test-only env mutation in a single-threaded test; no
        // other test in this binary reads the var concurrently.
        #[allow(unsafe_op_in_unsafe_fn)]
        unsafe {
            std::env::set_var(crate::hwkey::DISABLE_ENV, "1");
        }
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_err());
        assert!(matches!(
            crate::hwkey::probe_status(),
            crate::hwkey::HwCapability::Unavailable { .. }
        ));
        // SAFETY: restore for the other tests in this binary.
        #[allow(unsafe_op_in_unsafe_fn)]
        unsafe {
            std::env::remove_var(crate::hwkey::DISABLE_ENV);
        }
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_ok());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
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
