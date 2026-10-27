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

/// This clone's committer identity: `meta/device-id` first (authoritative
/// per-clone marker), then the registry's first entry as the legacy
/// fallback for vaults predating the marker. Callers MUST NOT scan the
/// roster another way: iteration order is a HashMap artifact and on a
/// multi-device vault it credits the wrong committer, which the staging
/// admission then uses to revert admin-gated writes.
pub fn local_device_id(vault_path: &Path) -> String {
    if let Some(id) = read_device_id(vault_path) {
        return id.to_string();
    }
    let reg_path = vault_path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            if let Ok(reg) = serde_json::from_str::<
                crate::devices::DeviceRegistry,
            >(&data)
            {
                if let Some((id, _)) = reg.devices.iter().next() {
                    return id.to_string();
                }
            }
        }
    }
    String::new()
}

/// How the file on disk presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivkeyFileKind {
    Sealed,
    SealedHw,
    LegacyPlaintext,
    /// The file exists but cannot be read or parsed. Distinct from Absent:
    /// rotation must fail closed on damage instead of treating the key as
    /// missing and leaving it sealed to a dead KEK.
    Damaged,
    Absent,
}

/// Whether an hw-sealed file demands per-use confirmation. Pre-unlock
/// safe (reads only the outer JSON mode flag, never decrypts); false for
/// every other file kind or a damaged file.
pub fn file_consents(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|f| serde_json::from_str::<serde_json::Value>(&f).ok())
        .and_then(|v| {
            (v["type"].as_str() == Some(SEAL_TYPE_HW))
                .then_some(v["consent"].as_bool() == Some(true))
        })
        .unwrap_or(false)
}

pub fn file_kind(path: &Path) -> PrivkeyFileKind {
    if !path.exists() {
        return PrivkeyFileKind::Absent;
    }
    let Ok(data) = std::fs::read_to_string(path) else {
        return PrivkeyFileKind::Damaged;
    };
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(v) if v["type"].as_str() == Some(SEAL_TYPE) => PrivkeyFileKind::Sealed,
        Ok(v) if v["type"].as_str() == Some(SEAL_TYPE_HW) => PrivkeyFileKind::SealedHw,
        Ok(v) if v["x25519_private"].is_string() => PrivkeyFileKind::LegacyPlaintext,
        _ => PrivkeyFileKind::Damaged,
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
    // Purpose lives in the AEAD AAD; the outer "type" JSON is
    // unauthenticated and proves nothing on its own.
    if envelope.aad != SEAL_TYPE.as_bytes() {
        pt.zeroize();
        return Err(VaultError::Corrupt(
            "sealed devkey was sealed for a different purpose".into(),
        )
        .into());
    }
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
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            open_sealed_hw(key, file.as_bytes())
        }
        PrivkeyFileKind::LegacyPlaintext => std::fs::read_to_string(path)
            .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")).into()),
        PrivkeyFileKind::Damaged => Err(VaultError::Corrupt(
            "device private key file is damaged".into(),
        )
        .into()),
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
        PrivkeyFileKind::Damaged => Err(VaultError::Corrupt(
            "device private key file is damaged; refusing to rotate its seal key".into(),
        )
        .into()),
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
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            let backend = hw_backend_of(file.as_bytes())?;
            let hw = crate::hwkey::store_for(&backend)
                .ok_or_else(crate::hwkey::hw_unavailable_error)?;
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
            let mode = crate::hwkey::HwConsent::from_flag(v["consent"].as_bool() == Some(true));
            let inner = open_bytes_hw(&*hw, old_seal_key, file.as_bytes())?;
            let bytes = seal_bytes_hw(&*hw, &binding, new_seal_key, &inner, id, mode)?;
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
    consent: crate::hwkey::HwConsent,
) -> Result<Vec<u8>, BaluardError> {
    // The backend mints the ephemeral in its own primitive family and
    // discards the private half - only its chip can reproduce the secret.
    let (peer, hw_secret) = hw.derive_ephemeral(binding, consent)?;
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
    // AAD binds purpose, the consent mode byte, AND the stored peer
    // bytes: an attacker editing the handshake or flipping the consent
    // flag fails AEAD authentication outright instead of merely deriving
    // a wrong secret.
    let aad = hw_aad(hw.backend_id(), &peer.0, consent.is_per_use());
    let envelope = crate::crypto::aead::encrypt(&ck, inner_json.as_bytes(), &aad, &nonce, header)?;
    let serialized = crate::vault::envelope::serialize(&envelope)?;
    let mut doc = serde_json::json!({
        "type": SEAL_TYPE_HW,
        "envelope": base64::engine::general_purpose::STANDARD.encode(serialized),
        "handshake": base64::engine::general_purpose::STANDARD.encode(&peer.0),
        "hw_binding": binding,
        // The registry key of the sealing backend: an open resolves the
        // SAME backend, never whatever chip happens to be installed.
        "hw_backend": hw.backend_id(),
        // Recorded so status copy and the open path know the mode; the
        // chip's own ACL stays authoritative against tampering.
        "consent": consent.is_per_use(),
    });
    let id = device_id.or_else(|| outer_device_id(inner_json));
    if let Some(id) = id {
        doc["device_id"] = serde_json::Value::String(id.to_string());
    }
    Ok(doc.to_string().into_bytes())
}

/// v2-hw AAD: purpose string + consent mode byte + length-framed
/// backend id + length-framed handshake bytes, so flipping the flag,
/// editing the handshake, or swapping the recorded backend fails AEAD
/// outright.
fn hw_aad(backend: &str, handshake: &[u8], consent: bool) -> Vec<u8> {
    let mut aad = SEAL_TYPE_HW.as_bytes().to_vec();
    aad.push(u8::from(consent));
    aad.push(backend.len() as u8);
    aad.extend_from_slice(backend.as_bytes());
    aad.push(handshake.len() as u8);
    aad.extend_from_slice(handshake);
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
    // Pre-1.0: seals predating the backend record fail closed here; the
    // phrase path re-enrolls. Never guess the backend from the platform.
    let backend = v["hw_backend"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing backend".into()))?;
    if backend != hw.backend_id() {
        return Err(VaultError::Corrupt(
            "hw-sealed devkey was sealed by a different backend".into(),
        )
        .into());
    }
    let eph = v["handshake"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing handshake".into()))?;
    let peer_bytes = base64::engine::general_purpose::STANDARD
        .decode(eph)
        .map_err(|e| VaultError::Corrupt(format!("hw handshake base64: {e}")))?;
    let peer = crate::hwkey::Handshake::new(peer_bytes)?;

    let enc = v["envelope"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing envelope".into()))?;
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(enc)
        .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey base64: {e}")))?;
    let envelope = crate::vault::envelope::deserialize(&serialized)?;

    // The chip's ACL is authoritative, but a consent file on a backend
    // that cannot verify users must fail closed, never downgrade.
    let consent_flag = v["consent"].as_bool() == Some(true);
    let consent = crate::hwkey::HwConsent::from_flag(consent_flag);
    if consent.is_per_use() && !hw.supports_consent() {
        return Err(VaultError::HardwareConsentUnavailable.into());
    }

    // Chip first so a hardware failure surfaces as the typed unavailable
    // error, not an opaque AEAD mismatch.
    let hw_secret = hw
        .derive(binding, &peer, consent)
        .map_err(|_| crate::hwkey::hw_unavailable_error())?;
    let ck = crate::hwkey::combine_seal_inputs(&hw_secret, seal_key);
    let aad = hw_aad(backend, &peer.0, consent_flag);
    let mut pt = crate::crypto::aead::decrypt(&ck, &envelope)
        .map_err(|_| VaultError::Corrupt("devkey seal key mismatch".into()))?;
    // decrypt() authenticates the envelope's OWN stored AAD; the expected
    // AAD is a separate, caller-derived input. Compare them so a tampered
    // consent flag (or ephemeral) fails the open outright.
    if envelope.aad.as_slice() != aad.as_slice() {
        pt.zeroize();
        return Err(VaultError::Corrupt("devkey seal key mismatch".into()).into());
    }
    let inner = String::from_utf8(pt.clone())
        .map_err(|e| VaultError::Corrupt(format!("devkey plaintext utf8: {e}")))?;
    pt.zeroize();
    Ok(inner)
}

/// The backend id recorded in an hw-sealed file, for callers that need
/// the store before opening (status, disable).
pub fn hw_backend_of(file: &[u8]) -> Result<String, BaluardError> {
    let v: serde_json::Value = serde_json::from_slice(file)
        .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey json: {e}")))?;
    v["hw_backend"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing backend".into()).into())
}

/// Open an hw-sealed file, resolving the recorded backend from the
/// registry. A missing backend (chip gone, kill-switch, wrong machine)
/// is the typed unavailable error - never a silent downgrade.
pub fn open_sealed_hw(seal_key: &[u8; 32], file: &[u8]) -> Result<String, BaluardError> {
    let backend = hw_backend_of(file)?;
    let hw = crate::hwkey::store_for(&backend).ok_or_else(|| {
        // Typed distinction: a different chip installed is "wrong card";
        // nothing installed is "no card". Both fail closed.
        if crate::hwkey::installed_all().is_empty() {
            crate::hwkey::hw_unavailable_error()
        } else {
            VaultError::Metadata(format!(
                "this vault was sealed by a different backend ({backend}); connect that key"
            ))
            .into()
        }
    })?;
    open_bytes_hw(&*hw, seal_key, file)
}

/// Enable the hardware seal on an existing sealed/legacy file (the
/// settings toggle): re-key under the AND construction. Idempotent for
/// v2-hw files. `backend` None picks the default (first available)
/// store; Some(id) resolves explicitly. Fails closed when the requested
/// backend is unavailable, and refuses a silent file on a backend whose
/// every use demands a tap.
pub fn enable_hw_seal(
    path: &Path,
    seal_key: &[u8; 32],
    vault_id: Uuid,
    device_id: Option<Uuid>,
    consent: bool,
    backend: Option<&str>,
) -> Result<bool, BaluardError> {
    let hw = match backend {
        Some(id) => crate::hwkey::store_for(id)
            .ok_or_else(crate::hwkey::hw_unavailable_error)?,
        None => crate::hwkey::available()
            .ok_or_else(crate::hwkey::hw_unavailable_error)?,
    };
    let mode = crate::hwkey::HwConsent::from_flag(consent);
    if mode.is_per_use() && !hw.supports_consent() {
        return Err(VaultError::HardwareConsentUnavailable.into());
    }
    if !mode.is_per_use() && hw.interaction() == crate::hwkey::Interaction::PerUse {
        return Err(VaultError::HardwareTouchRequired.into());
    }
    match file_kind(path) {
        PrivkeyFileKind::Absent => Ok(false),
        PrivkeyFileKind::SealedHw => Ok(false),
        PrivkeyFileKind::Damaged => Err(VaultError::Corrupt(
            "device private key file is damaged; refusing to move it to the hardware seal"
                .into(),
        )
        .into()),
        PrivkeyFileKind::LegacyPlaintext | PrivkeyFileKind::Sealed => {
            let inner = read_privkey_file(path, Some(seal_key))?;
            let binding = hw.create_binding(vault_id, mode)?;
            let bytes = seal_bytes_hw(&*hw, &binding, seal_key, &inner, device_id, mode)?;
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
    seal_key: &[u8; 32],
    device_id: Option<Uuid>,
) -> Result<bool, BaluardError> {
    if file_kind(path) != PrivkeyFileKind::SealedHw {
        return Ok(false);
    }
    let file = std::fs::read_to_string(path)
        .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
    let backend = hw_backend_of(file.as_bytes())?;
    let hw = crate::hwkey::store_for(&backend)
        .ok_or_else(crate::hwkey::hw_unavailable_error)?;
    let inner = open_bytes_hw(&*hw, seal_key, file.as_bytes())?;
    let binding = serde_json::from_str::<serde_json::Value>(&file)
        .ok()
        .and_then(|v| v["hw_binding"].as_str().map(str::to_string));
    seal_file(path, &inner, seal_key, device_id)?;
    if let Some(b) = binding {
        let _ = hw.delete_binding(&b);
    }
    Ok(true)
}

/// Switch an hw-sealed file between silent and per-use-consent modes:
/// opens under the CURRENT mode, re-keys under a binding of the NEW mode,
/// and deletes the old binding. Ok(false) when not hw-sealed or already
/// in the requested mode.
pub fn set_hw_seal_consent(
    path: &Path,
    seal_key: &[u8; 32],
    device_id: Option<Uuid>,
    consent: bool,
) -> Result<bool, BaluardError> {
    if file_kind(path) != PrivkeyFileKind::SealedHw {
        return Ok(false);
    }
    let file = std::fs::read_to_string(path)
        .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
    let backend = hw_backend_of(file.as_bytes())?;
    let hw = crate::hwkey::store_for(&backend)
        .ok_or_else(crate::hwkey::hw_unavailable_error)?;
    if consent && !hw.supports_consent() {
        return Err(VaultError::HardwareConsentUnavailable.into());
    }
    if !consent && hw.interaction() == crate::hwkey::Interaction::PerUse {
        return Err(VaultError::HardwareTouchRequired.into());
    }
    let v: serde_json::Value = serde_json::from_str(&file)
        .map_err(|e| VaultError::Corrupt(format!("hw-sealed devkey json: {e}")))?;
    let old_binding = v["hw_binding"]
        .as_str()
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey missing binding".into()))?;
    if crate::hwkey::HwConsent::from_flag(v["consent"].as_bool() == Some(true)).is_per_use()
        == consent
    {
        return Ok(false);
    }
    let vault_id = crate::hwkey::binding_vault_id(old_binding)
        .ok_or_else(|| VaultError::Corrupt("hw-sealed devkey binding is not a vault tag".into()))?;
    let inner = open_bytes_hw(&*hw, seal_key, file.as_bytes())?;
    let mode = crate::hwkey::HwConsent::from_flag(consent);
    let binding = hw.create_binding(vault_id, mode)?;
    let bytes = seal_bytes_hw(&*hw, &binding, seal_key, &inner, device_id, mode)?;
    super::write_vault_file(path, &bytes).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("write hw-sealed devkey: {e}")))
    })?;
    let _ = hw.delete_binding(old_binding);
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
        fn backend_id(&self) -> &'static str {
            "test-mock"
        }
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "test-mock".into(),
            }
        }
        fn supports_consent(&self) -> bool {
            true
        }
        fn create_binding(
            &self,
            vault_id: Uuid,
            consent: crate::hwkey::HwConsent,
        ) -> Result<String, BaluardError> {
            Ok(if consent.is_per_use() {
                crate::hwkey::consent_binding_tag(vault_id)
            } else {
                crate::hwkey::binding_tag(vault_id)
            })
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _consent: crate::hwkey::HwConsent,
        ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError>
        {
            use sha2::{Digest, Sha256};
            let mut peer = vec![0x04u8];
            peer.resize(65, 0);
            rand::Rng::fill(&mut rand::thread_rng(), &mut peer[1..]);
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(&peer);
            Ok((
                crate::hwkey::Handshake(peer),
                Zeroizing::new(h.finalize().into()),
            ))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &crate::hwkey::Handshake,
            _consent: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, binding: &str) -> Result<(), BaluardError> {
            self.deleted.lock().unwrap().push(binding.to_string());
            Ok(())
        }
    }

    use crate::hwkey::TEST_STORE_LOCK as HW_LOCK;

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
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("x25519_private"));
        assert!(raw.contains("hw_binding"));
        assert!(raw.contains("handshake"));
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
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).unwrap();

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
        assert!(enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).is_err());
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        install_mock();
        assert!(enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).unwrap());
        // Second enable: no-op.
        assert!(!enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).unwrap());
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
        enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap();
        let binding = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["hw_binding"].as_str().unwrap().to_string()
        };
        assert!(disable_hw_seal(&p, &[7u8; 32], None).unwrap());
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
        enable_hw_seal(&p, &[1u8; 32], Uuid::new_v4(), None, false, None).unwrap();
        let eph_before = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["handshake"].as_str().unwrap().to_string()
        };
        assert!(rotate_seal_key(&p, &[1u8; 32], &[2u8; 32], None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        let eph_after = {
            let raw = std::fs::read_to_string(&p).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["handshake"].as_str().unwrap().to_string()
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
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).unwrap();
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
        enable_hw_seal(&p, &[7u8; 32], Uuid::new_v4(), None, false, None).unwrap();
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

    #[test]
    fn hw_consent_roundtrip_and_mode_switch() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let m = install_mock();
        let p = tmp_path("hw-consent");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();

        // Enable in consent mode: the binding is the consent tag.
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None, true, None).unwrap());
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(
            raw.contains("\"consent\":true"),
            "file records the mode: {raw}"
        );
        assert!(raw.contains("baluard-hwc:"));

        // Open works (the mock verifies users trivially); password change
        // preserves the mode.
        assert_eq!(read_privkey_file(&p, Some(&[7u8; 32])).unwrap(), INNER);
        assert!(rotate_seal_key(&p, &[7u8; 32], &[9u8; 32], None).unwrap());
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("\"consent\":true"));

        // Switch to silent: re-keys under the plain tag and deletes the
        // consent binding.
        assert!(set_hw_seal_consent(&p, &[9u8; 32], None, false).unwrap());
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("\"consent\":false"));
        assert!(raw.contains("baluard-hw:") && !raw.contains("baluard-hwc:"));
        assert_eq!(read_privkey_file(&p, Some(&[9u8; 32])).unwrap(), INNER);
        assert!(
            m.deleted
                .lock()
                .unwrap()
                .iter()
                .any(|b| b.contains("baluard-hwc:"))
        );

        // Switching again is a no-op.
        assert!(!set_hw_seal_consent(&p, &[9u8; 32], None, false).unwrap());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_consent_file_refuses_on_non_consenting_store() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-consent-refuse");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None, true, None).unwrap());

        // Swap in a store that cannot verify users: a consent-sealed file
        // must fail closed with the typed consent error, never downgrade.
        struct Consentless;
        impl crate::hwkey::HardwareKeyStore for Consentless {
            // Same id as the sealing mock: installing it replaces THAT
            // backend, modeling the chip losing its verification power.
            fn backend_id(&self) -> &'static str {
                "test-mock"
            }
            fn probe(&self) -> crate::hwkey::HwCapability {
                crate::hwkey::HwCapability::Available {
                    backend: "consentless".into(),
                }
            }
            fn create_binding(
                &self,
                _: Uuid,
                _: crate::hwkey::HwConsent,
            ) -> Result<String, BaluardError> {
                Ok(crate::hwkey::binding_tag(Uuid::new_v4()))
            }
            fn derive_ephemeral(
                &self,
                _: &str,
                _: crate::hwkey::HwConsent,
            ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError>
            {
                Err(VaultError::HardwareConsentUnavailable.into())
            }
            fn derive(
                &self,
                _: &str,
                _: &crate::hwkey::Handshake,
                _: crate::hwkey::HwConsent,
            ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
                Err(VaultError::HardwareConsentUnavailable.into())
            }
            fn delete_binding(&self, _: &str) -> Result<(), BaluardError> {
                Ok(())
            }
        }
        crate::hwkey::install(std::sync::Arc::new(Consentless));
        let err = read_privkey_file(&p, Some(&[7u8; 32])).unwrap_err();
        assert!(
            err.to_string().contains("demands confirmation"),
            "consent refusal must be typed, got: {err}"
        );
        // Enabling consent on such a store refuses too.
        let p2 = tmp_path("hw-consent-refuse2");
        seal_file(&p2, INNER, &[7u8; 32], None).unwrap();
        assert!(enable_hw_seal(&p2, &[7u8; 32], vault_id, None, true, None).is_err());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn hw_consent_flag_is_aad_bound_and_legacy_files_open() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-aad-flag");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], vault_id, None, true, None).unwrap();

        // Tampering the consent flag flips the AAD: AEAD must refuse the
        // downgrade instead of silently opening without confirmation.
        let raw = std::fs::read_to_string(&p).unwrap();
        let tampered = raw.replace("\"consent\":true", "\"consent\":false");
        assert_ne!(raw, tampered);
        super::super::write_vault_file(&p, tampered.as_bytes()).unwrap();
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_err());

        // The mirror direction: faking consent on a silent file is
        // refused too - both tamper directions are AAD-bound.
        let p2 = tmp_path("hw-aad-legacy");
        seal_file(&p2, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p2, &[7u8; 32], vault_id, None, false, None).unwrap();
        let raw2 = std::fs::read_to_string(&p2).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw2).unwrap();
        v.as_object_mut()
            .expect("hw file is an object")
            .insert("consent".into(), serde_json::Value::Bool(true));
        super::super::write_vault_file(&p2, v.to_string().as_bytes()).unwrap();
        assert!(read_privkey_file(&p2, Some(&[7u8; 32])).is_err());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&p2).ok();
    }

    /// A second backend under a different registry id, for the
    /// wrong-backend refusal test.
    struct HwMockB;
    impl crate::hwkey::HardwareKeyStore for HwMockB {
        fn backend_id(&self) -> &'static str {
            "test-mock-b"
        }
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "test-mock-b".into(),
            }
        }
        fn create_binding(
            &self,
            _: Uuid,
            _: crate::hwkey::HwConsent,
        ) -> Result<String, BaluardError> {
            Ok(crate::hwkey::binding_tag(Uuid::new_v4()))
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _: crate::hwkey::HwConsent,
        ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError>
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"b");
            h.update(binding.as_bytes());
            Ok((
                crate::hwkey::Handshake(vec![0x04, 0x01]),
                Zeroizing::new(h.finalize().into()),
            ))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &crate::hwkey::Handshake,
            _: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"b");
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    /// A backend whose every use demands a tap: silent seals refuse.
    struct TapMock;
    impl crate::hwkey::HardwareKeyStore for TapMock {
        fn backend_id(&self) -> &'static str {
            "tap-mock"
        }
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "tap-mock".into(),
            }
        }
        fn interaction(&self) -> crate::hwkey::Interaction {
            crate::hwkey::Interaction::PerUse
        }
        fn create_binding(
            &self,
            _: Uuid,
            _: crate::hwkey::HwConsent,
        ) -> Result<String, BaluardError> {
            Ok(crate::hwkey::binding_tag(Uuid::new_v4()))
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _: crate::hwkey::HwConsent,
        ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError>
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"t");
            h.update(binding.as_bytes());
            Ok((
                crate::hwkey::Handshake(vec![0x04, 0x02]),
                Zeroizing::new(h.finalize().into()),
            ))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &crate::hwkey::Handshake,
            _: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"t");
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    #[test]
    fn hw_backend_recorded_and_wrong_backend_refuses() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-backend");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("hw_backend"));
        // A different installed backend cannot open it, even with the
        // right password: the recorded backend is the only resolver.
        // Uninstall the sealer first so the id truly has no store.
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(HwMockB));
        let err = read_privkey_file(&p, Some(&[7u8; 32])).unwrap_err();
        assert!(
            err.to_string().contains("different backend"),
            "wrong-backend refusal must be typed, got: {err}"
        );
        // And the missing-backend case (chip gone) stays typed too.
        crate::hwkey::uninstall();
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_err());
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_seal_fails_closed_without_backend_record() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-nobackend");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap();
        // A pre-1.0 seal without the backend record: corrupt, phrase path.
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v.as_object_mut()
            .expect("hw file is an object")
            .remove("hw_backend");
        super::super::write_vault_file(&p, v.to_string().as_bytes()).unwrap();
        let err = read_privkey_file(&p, Some(&[7u8; 32])).unwrap_err();
        assert!(
            err.to_string().contains("missing backend"),
            "got: {err}"
        );
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_seal_refuses_oversized_handshake() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        install_mock();
        let p = tmp_path("hw-oversize");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let big = vec![0x04u8; 4096];
        v["handshake"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(big),
        );
        super::super::write_vault_file(&p, v.to_string().as_bytes()).unwrap();
        assert!(read_privkey_file(&p, Some(&[7u8; 32])).is_err());
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hw_seal_refuses_silent_on_tapping_backend() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let p = tmp_path("hw-tapsilent");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        let err = enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap_err();
        assert!(
            err.to_string().contains("requires a touch"),
            "got: {err}"
        );
        assert_eq!(file_kind(&p), PrivkeyFileKind::Sealed);
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }
}
