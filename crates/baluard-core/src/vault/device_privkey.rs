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
    read_privkey_file_with_ck(path, seal_key).map(|(inner, _)| inner)
}

/// Read the privkey JSON plus, for v2-hw files, the hw content key (see
/// `open_bytes_hw_with_ck`).
pub fn read_privkey_file_with_ck(
    path: &Path,
    seal_key: Option<&[u8; 32]>,
) -> Result<(String, Option<zeroize::Zeroizing<[u8; 32]>>), BaluardError> {
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
            open_bytes(key, file.as_bytes()).map(|inner| (inner, None))
        }
        PrivkeyFileKind::SealedHw => {
            let key = seal_key.ok_or_else(|| BaluardError::from(VaultError::Locked))?;
            let file = std::fs::read_to_string(path)
                .map_err(|e| VaultError::Metadata(format!("reading privkey: {e}")))?;
            open_sealed_hw_with_ck(key, file.as_bytes())
                .map(|(inner, ck)| (inner, Some(ck)))
        }
        PrivkeyFileKind::LegacyPlaintext => std::fs::read_to_string(path)
            .map(|inner| (inner, None))
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
            let (inner, old_ck) = open_bytes_hw_with_ck(&*hw, old_seal_key, file.as_bytes())?;
            // Rotation re-seals under the SAME binding without re-attesting;
            // the recorded verdict carries over.
            let attestation = v["hw_attestation"]
                .as_str()
                .and_then(hw_attestation_from_str);
            let out = seal_bytes_hw(&*hw, &binding, new_seal_key, &inner, id, mode, attestation)?;
            super::write_vault_file(path, &out.bytes).map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!(
                    "write hw-sealed devkey: {e}"
                )))
            })?;
            if let Some(vault) = path.parent().and_then(Path::parent) {
                rebind_identity_artifacts(vault, id, &ik_of(&old_ck), &ik_of(&out.content_key))?;
            }
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

/// A sealed v2-hw file plus the content key it was written under, so
/// the caller can rebind related artifacts (identity seed) to the same
/// chip without a second assertion.
pub struct HwSealOutput {
    pub bytes: Vec<u8>,
    pub content_key: zeroize::Zeroizing<[u8; 32]>,
}

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
    attestation: Option<crate::hwkey::HwAttestation>,
) -> Result<HwSealOutput, BaluardError> {
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
    if let Some(att) = attestation {
        doc["hw_attestation"] = serde_json::Value::String(att.as_str().to_string());
    }
    Ok(HwSealOutput {
        bytes: doc.to_string().into_bytes(),
        content_key: zeroize::Zeroizing::new(ck),
    })
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
    open_bytes_hw_with_ck(hw, seal_key, file).map(|(inner, _)| inner)
}

/// Open a v2-hw file and also return the content key, so callers can
/// derive hw-bound keys for related artifacts (identity seed, identity
/// escrow) from the SAME chip assertion instead of paying a second tap.
pub fn open_bytes_hw_with_ck(
    hw: &dyn crate::hwkey::HardwareKeyStore,
    seal_key: &[u8; 32],
    file: &[u8],
) -> Result<(String, zeroize::Zeroizing<[u8; 32]>), BaluardError> {
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
    if consent.is_per_use()
        && hw.interaction() != crate::hwkey::Interaction::PerUse
        && !hw.supports_consent()
    {
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
        .map_err(|e| VaultError::Corrupt(format!("devkey plaintext utf8: {e}")));
    pt.zeroize();
    let inner = inner?;
    Ok((inner, zeroize::Zeroizing::new(ck)))
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

pub(crate) fn hw_attestation_from_str(s: &str) -> Option<crate::hwkey::HwAttestation> {
    match s {
        "verified" => Some(crate::hwkey::HwAttestation::Verified),
        "unknown-vendor" => Some(crate::hwkey::HwAttestation::UnknownVendor),
        _ => None,
    }
}

/// The recorded enroll-time attestation verdict of an hw-sealed vault,
/// for status copy. `None` for chip backends (no ceremony) or a non-hw
/// file. Informational only.
pub fn hw_attestation_of(path: &Path) -> Option<crate::hwkey::HwAttestation> {
    if file_kind(path) != PrivkeyFileKind::SealedHw {
        return None;
    }
    let file = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&file).ok()?;
    v["hw_attestation"]
        .as_str()
        .and_then(hw_attestation_from_str)
}

/// Open an hw-sealed file, resolving the recorded backend from the
/// registry. A missing backend (chip gone, kill-switch, wrong machine)
/// is the typed unavailable error - never a silent downgrade.
pub fn open_sealed_hw(seal_key: &[u8; 32], file: &[u8]) -> Result<String, BaluardError> {
    open_sealed_hw_with_ck(seal_key, file).map(|(inner, _)| inner)
}

/// `open_sealed_hw` plus the content key (see `open_bytes_hw_with_ck`).
pub fn open_sealed_hw_with_ck(
    seal_key: &[u8; 32],
    file: &[u8],
) -> Result<(String, zeroize::Zeroizing<[u8; 32]>), BaluardError> {
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
    open_bytes_hw_with_ck(&*hw, seal_key, file)
}

/// Enable the hardware seal on an existing sealed/legacy file (the
/// settings toggle): re-key under the AND construction. Idempotent for
/// v2-hw files. `backend` None picks the default (first available)
/// store; Some(id) resolves explicitly. Fails closed when the requested
/// backend is unavailable. A backend whose every use demands a tap always
/// records per-use mode so the requirement is AAD-bound.
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
    let interaction = hw.interaction();
    let mode = if interaction == crate::hwkey::Interaction::PerUse {
        crate::hwkey::HwConsent::PerUse
    } else {
        crate::hwkey::HwConsent::from_flag(consent)
    };
    if mode.is_per_use()
        && interaction != crate::hwkey::Interaction::PerUse
        && !hw.supports_consent()
    {
        return Err(VaultError::HardwareConsentUnavailable.into());
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
            let info = hw.create_binding(vault_id, mode)?;
            let out = seal_bytes_hw(
                &*hw,
                &info.binding,
                seal_key,
                &inner,
                device_id,
                mode,
                info.attestation,
            )?;
            super::write_vault_file(path, &out.bytes).map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!(
                    "write hw-sealed devkey: {e}"
                )))
            })?;
            // Eager identity rebind where the old keys are derivable: the
            // member seed (devkey_seal) and keystore-mode identity.enc.
            // Passphrase-mode identity.enc keeps its lazy heal at the next
            // full password unlock - no passphrase key here.
            let vault = path.parent().and_then(Path::parent);
            if let Some(vault) = vault {
                let ik = ik_of(&out.content_key);
                rebind_identity_artifacts(vault, device_id, seal_key, &ik)?;
                if let Some(legacy) = identity_keystore_wrap_key(vault) {
                    rebind_identity_artifacts(vault, device_id, &legacy, &ik)?;
                }
            }
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
    let (inner, old_ck) = open_bytes_hw_with_ck(&*hw, seal_key, file.as_bytes())?;
    let binding = serde_json::from_str::<serde_json::Value>(&file)
        .ok()
        .and_then(|v| v["hw_binding"].as_str().map(str::to_string));
    let old_ik = ik_of(&old_ck);
    let vault = path.parent().and_then(Path::parent);
    // Rebind identity artifacts BEFORE the unsealed commit: a rebind
    // failure aborts with the seal still intact. The reverse (seal_file
    // first) would strand the seed under a deleted chip binding.
    if let Some(vault) = vault {
        rebind_identity_artifacts(vault, device_id, &old_ik, seal_key)?;
        if let Some(legacy) = identity_keystore_wrap_key(vault) {
            rebind_identity_artifacts(vault, device_id, &old_ik, &legacy)?;
        }
    }
    seal_file(path, &inner, seal_key, device_id)?;
    if let Some(vault) = vault {
        // Passphrase-mode identity.enc has no derivable legacy key here
        // (token-gated flow, no master password); the escrow phrase is
        // its recovery. Warn loudly instead of pretending it healed.
        let meta_identity = vault.join("meta/identity.enc");
        if let Ok(sealed) = std::fs::read(&meta_identity) {
            if crate::vault::identity::open_identity(&old_ik, &sealed).is_ok() {
                eprintln!(
                    "warning: this identity is still sealed to the security key; restore it from its recovery phrase when needed"
                );
            }
        }
    }
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
    let (inner, old_ck) = open_bytes_hw_with_ck(&*hw, seal_key, file.as_bytes())?;
    let mode = crate::hwkey::HwConsent::from_flag(consent);
    let info = hw.create_binding(vault_id, mode)?;
    // The verdict is a property of the chip key, not of the consent mode:
    // keep the fresh verdict, else carry the recorded one.
    let attestation = info.attestation.or_else(|| {
        v["hw_attestation"]
            .as_str()
            .and_then(hw_attestation_from_str)
    });
    let out = seal_bytes_hw(
        &*hw,
        &info.binding,
        seal_key,
        &inner,
        device_id,
        mode,
        attestation,
    )?;
    super::write_vault_file(path, &out.bytes).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("write hw-sealed devkey: {e}")))
    })?;
    if let Some(vault) = path.parent().and_then(Path::parent) {
        rebind_identity_artifacts(vault, device_id, &ik_of(&old_ck), &ik_of(&out.content_key))?;
    }
    let _ = hw.delete_binding(old_binding);
    Ok(true)
}

/// The identity sealing key for an hw content key. Free fn so the rebind
/// sites stay short.
fn ik_of(ck: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    crate::crypto::hkdf_derive::derive_identity_hw_key(ck).expect("identity hw key HKDF")
}

/// Rebind the identity artifacts (member unlock seed, member and legacy
/// identity.enc) from `from_key` to `to_key`. Identity files that do not
/// open under `from_key` are left untouched (not ours to heal here);
/// open/re-seal/write failures propagate - a half-rebound identity is
/// worse than a failed operation.
fn rebind_identity_artifacts(
    vault: &Path,
    device_id: Option<Uuid>,
    from_key: &[u8; 32],
    to_key: &[u8; 32],
) -> Result<(), BaluardError> {
    crate::vault::members::rebind_member_unlock_identity_seed(vault, from_key, to_key)?;
    let mut paths = vec![vault.join("meta/identity.enc")];
    if let Some(id) = device_id {
        if let Some(member) = crate::vault::members::member_id_for_device(vault, id) {
            paths.push(
                vault
                    .join(crate::vault::members::MEMBERS_DIR)
                    .join(member.to_string())
                    .join("identity.enc"),
            );
        }
    }
    for p in paths {
        if !p.exists() {
            continue;
        }
        let sealed = std::fs::read(&p)
            .map_err(|e| VaultError::Metadata(format!("read identity file: {e}")))?;
        let Ok(keys) = crate::vault::identity::open_identity(from_key, &sealed) else {
            continue;
        };
        let resealed = crate::vault::identity::seal_identity(to_key, &keys)?;
        super::write_vault_file(&p, &resealed).map_err(|e| {
            BaluardError::from(VaultError::Metadata(format!("re-seal identity file: {e}")))
        })?;
    }
    Ok(())
}

/// Best-effort legacy wrap key for identity.enc: the keystore key when the
/// identity seals in keystore mode. Passphrase mode needs the master
/// password, which token-gated flows do not have, so callers must treat
/// None as "cannot rebind; lazy-heal at the next full unlock".
fn identity_keystore_wrap_key(vault: &Path) -> Option<zeroize::Zeroizing<[u8; 32]>> {
    let meta = std::fs::read_to_string(vault.join("meta/identity-meta.json")).ok()?;
    let meta: serde_json::Value = serde_json::from_str(&meta).ok()?;
    if meta["mode"].as_str() != Some("keystore") {
        return None;
    }
    let key_name = meta["keystore_key"].as_str()?;
    let keystore = crate::vault::creation::get_global_keystore()?;
    let bytes = keystore.get_secret(key_name).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .ok()
        .map(zeroize::Zeroizing::new)
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
        ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
            Ok(crate::hwkey::BindingInfo {
                binding: if consent.is_per_use() {
                    crate::hwkey::consent_binding_tag(vault_id)
                } else {
                    crate::hwkey::binding_tag(vault_id)
                },
                attestation: None,
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
            ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
                Ok(crate::hwkey::BindingInfo {
                    binding: crate::hwkey::binding_tag(Uuid::new_v4()),
                    attestation: None,
                })
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
        ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
            Ok(crate::hwkey::BindingInfo {
                binding: crate::hwkey::binding_tag(Uuid::new_v4()),
                attestation: None,
            })
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
        ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
            Ok(crate::hwkey::BindingInfo {
                binding: crate::hwkey::binding_tag(Uuid::new_v4()),
                attestation: None,
            })
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
            h.update([0x04, 0x02]);
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
    fn hw_seal_forces_per_use_on_tapping_backend() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let p = tmp_path("hw-tap-per-use");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap());
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        assert!(file_consents(&p), "tap requirement must be AAD-bound");
        assert_eq!(read_privkey_file(&p, Some(&[7u8; 32])).unwrap(), INNER);
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    /// A tap backend that reports an attestation verdict at binding
    /// creation (the FIDO shape).
    struct AttestedTapMock;
    impl crate::hwkey::HardwareKeyStore for AttestedTapMock {
        fn backend_id(&self) -> &'static str {
            "attested-tap-mock"
        }
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "attested-tap-mock".into(),
            }
        }
        fn interaction(&self) -> crate::hwkey::Interaction {
            crate::hwkey::Interaction::PerUse
        }
        fn create_binding(
            &self,
            _: Uuid,
            _: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
            Ok(crate::hwkey::BindingInfo {
                binding: crate::hwkey::binding_tag(Uuid::new_v4()),
                attestation: Some(crate::hwkey::HwAttestation::Verified),
            })
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _: crate::hwkey::HwConsent,
        ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError> {
            let handshake = vec![0x04, 0x02];
            let mut secret = [0u8; 32];
            for (i, b) in binding.bytes().chain(handshake.iter().copied()).enumerate() {
                secret[i % 32] ^= b;
            }
            Ok((crate::hwkey::Handshake(handshake), Zeroizing::new(secret)))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &crate::hwkey::Handshake,
            _: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::SharedSecret, BaluardError> {
            let mut secret = [0u8; 32];
            for (i, b) in binding
                .bytes()
                .chain(handshake.0.iter().copied())
                .enumerate()
            {
                secret[i % 32] ^= b;
            }
            Ok(Zeroizing::new(secret))
        }
        fn delete_binding(&self, _: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    #[test]
    fn hw_seal_records_and_preserves_the_attestation_verdict() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(AttestedTapMock));
        let p = tmp_path("hw-attested");
        let vault_id = Uuid::new_v4();
        seal_file(&p, INNER, &[7u8; 32], None).unwrap();
        assert!(enable_hw_seal(&p, &[7u8; 32], vault_id, None, false, None).unwrap());
        let raw = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["hw_attestation"].as_str(), Some("verified"));
        // The verdict is informational, never an open input.
        assert_eq!(read_privkey_file(&p, Some(&[7u8; 32])).unwrap(), INNER);
        // A seal-key rotation re-seals without re-attesting; the recorded
        // verdict carries over.
        assert!(rotate_seal_key(&p, &[7u8; 32], &[9u8; 32], None).unwrap());
        let raw = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["hw_attestation"].as_str(), Some("verified"));
        assert_eq!(read_privkey_file(&p, Some(&[9u8; 32])).unwrap(), INNER);
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
        std::fs::remove_file(&p).ok();
    }

    // ── Slice-4 audit: recovery/rotation properties under a hardware seal ──

    use crate::vault::VaultHandle;

    /// A tap backend that counts every hardware operation; the heartbeat
    /// and unlock legs assert exact counts against it.
    struct CountingTapMock(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl crate::hwkey::HardwareKeyStore for CountingTapMock {
        fn backend_id(&self) -> &'static str {
            "counting-tap-mock"
        }
        fn probe(&self) -> crate::hwkey::HwCapability {
            crate::hwkey::HwCapability::Available {
                backend: "counting-tap-mock".into(),
            }
        }
        fn interaction(&self) -> crate::hwkey::Interaction {
            crate::hwkey::Interaction::PerUse
        }
        fn create_binding(
            &self,
            _: Uuid,
            _: crate::hwkey::HwConsent,
        ) -> Result<crate::hwkey::BindingInfo, BaluardError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::hwkey::BindingInfo {
                binding: crate::hwkey::binding_tag(Uuid::new_v4()),
                attestation: None,
            })
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _: crate::hwkey::HwConsent,
        ) -> Result<(crate::hwkey::Handshake, crate::hwkey::SharedSecret), BaluardError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"t");
            h.update(binding.as_bytes());
            h.update([0x04, 0x02]);
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
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"t");
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _: &str) -> Result<(), BaluardError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    fn audit_vault(dir: &std::path::Path) -> (VaultHandle, String, String) {
        let password = "audit password 123".to_string();
        let (handle, secrets) = crate::vault::creation::VaultCreator::new(dir, &password, "this-device")
            .kdf_profile(crate::types::KdfProfile::MobileLow)
            .execute()
            .unwrap();
        (handle, password, secrets.recovery_phrase.phrase())
    }

    fn seal_to_tap(handle: &mut VaultHandle) {
        let seal_key = handle.unlocked().devkey_seal;
        let p = handle.path.join("meta/device-privkey.json");
        assert!(
            enable_hw_seal(&p, &seal_key, handle.vault_id, Some(handle.device_id), false, None)
                .unwrap()
        );
        assert_eq!(file_kind(&p), PrivkeyFileKind::SealedHw);
        handle.lock();
    }

    fn kek_of(vault_path: &std::path::Path, password: &str) -> [u8; 32] {
        let kdf_json = std::fs::read_to_string(vault_path.join("meta/kdf-params.json")).unwrap();
        let params: crate::types::KdfParams = serde_json::from_str(&kdf_json).unwrap();
        crate::crypto::kdf::derive_kek(password, &params).unwrap()
    }

    fn root_from_phrase(vault_path: &std::path::Path, phrase: &str) -> crate::keys::hierarchy::RootKey {
        let parsed = crate::recovery::RecoveryPhrase::from_phrase(phrase).unwrap();
        let seed = parsed.derive_key();
        let secret = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(&seed[..32]).unwrap());
        let json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vault_path.join("meta/recovery.json")).unwrap(),
        )
        .unwrap();
        let eph = hex::decode(json["ephemeral_public"].as_str().unwrap()).unwrap();
        let ct = hex::decode(json["encrypted_key"].as_str().unwrap()).unwrap();
        let tag: [u8; 16] = hex::decode(json["tag"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let root =
            crate::crypto::hpke_wrap::unwrap_key(&eph, &ct, &tag, &secret, "recovery-keywrap")
                .unwrap();
        crate::keys::hierarchy::RootKey::from_bytes(root.try_into().unwrap())
    }

    /// The seal binds EVERY unlock tail: with the token gone, both the
    /// password tail and the KEK quick-unlock tail fail closed with the
    /// typed unavailable error; with the token back, the quick-unlock tail
    /// pays the tap and opens. No path bypasses the seal.
    #[test]
    fn hw_seal_binds_the_unlock_tail_and_quick_unlock_cannot_bypass() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, _phrase) = audit_vault(dir.path());
        seal_to_tap(&mut handle);

        crate::hwkey::uninstall();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        let err = h.unlock(&password).unwrap_err();
        assert!(err.to_string().contains("chip is unavailable"), "err: {err}");
        let kek = kek_of(dir.path(), &password);
        let err = h.unlock_with_kek(&kek).unwrap_err();
        assert!(err.to_string().contains("chip is unavailable"), "err: {err}");

        crate::hwkey::install(std::sync::Arc::new(TapMock));
        h.unlock_with_kek(&kek).unwrap();
        assert!(h.is_unlocked());
        assert!(crate::vault::handle::cached_device_signing_key(dir.path(), h.device_id).is_some());

        crate::hwkey::uninstall();
        assert!(crate::vault::handle::cached_device_signing_key(dir.path(), h.device_id).is_some());
        h.lock();
        assert!(crate::vault::handle::cached_device_signing_key(dir.path(), h.device_id).is_none());
        hw_env_restore(_old_env);
    }

    /// The phrase path is the rescue: with the token LOST and no hardware
    /// store registered, recovery enrolls a fresh device, the caller seals
    /// that key at birth, and the vault opens on the password alone. The
    /// recovered device is NOT hw-sealed: re-arming is a user decision.
    #[test]
    fn phrase_recovery_succeeds_with_the_token_gone() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, phrase) = audit_vault(dir.path());
        seal_to_tap(&mut handle);

        crate::hwkey::uninstall();
        use crate::device_manager::{DeviceManager, EnrollmentPayload};
        let (x_sk, x_pk) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (e_sk, e_vk) = crate::crypto::signature::generate_ed25519_keypair();
        let payload = EnrollmentPayload {
            device_id: Uuid::new_v4(),
            encryption_public_key: hex::encode(x_pk.to_bytes()),
            signing_public_key: hex::encode(crate::crypto::signature::verifying_key_bytes(&e_vk)),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: {
                let mut b = [0u8; 32];
                use rand_core::RngCore;
                rand_core::OsRng.fill_bytes(&mut b);
                hex::encode(b)
            },
            name: "audit recovery".into(),
            vault_id: None,
            epoch: None,
            registry_version: None,
        };
        let mut dm = DeviceManager::load_from_vault(dir.path()).unwrap();
        let enrolled = dm
            .enroll_with_recovery_phrase(&payload, &phrase, x_sk, e_sk)
            .unwrap();

        let kek = kek_of(dir.path(), &password);
        let devkey_seal = crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek).unwrap();
        let inner = serde_json::json!({
            "device_id": enrolled.device_id.to_string(),
            "x25519_private": hex::encode(enrolled.x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(enrolled.ed25519_signing.to_bytes()),
        });
        crate::vault::device_privkey::seal_file(
            &dir.path().join("meta/device-privkey.json"),
            &inner.to_string(),
            &devkey_seal,
            Some(enrolled.device_id),
        )
        .unwrap();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&password).unwrap();
        assert_eq!(
            file_kind(&dir.path().join("meta/device-privkey.json")),
            PrivkeyFileKind::Sealed
        );
        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
    }

    /// The Legacy Contact view opens the kit copy with the Root Key alone:
    /// the clone carries no device-privkey file and no hardware store is
    /// ever consulted.
    #[test]
    fn legacy_contact_view_opens_without_the_token() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, _password, phrase) = audit_vault(dir.path());
        seal_to_tap(&mut handle);

        let clone = tempfile::tempdir().unwrap();
        fn rec(src: &std::path::Path, dst: &std::path::Path) {
            std::fs::create_dir_all(dst).unwrap();
            for entry in std::fs::read_dir(src).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                let s = src.join(&name);
                let d = dst.join(&name);
                if s.is_dir() {
                    rec(&s, &d);
                } else {
                    std::fs::copy(&s, &d).unwrap();
                }
            }
        }
        rec(dir.path(), clone.path());
        std::fs::remove_file(clone.path().join("meta/device-privkey.json")).ok();
        std::fs::remove_file(clone.path().join("meta/device-id")).ok();
        let root = root_from_phrase(dir.path(), &phrase);

        crate::hwkey::uninstall();
        let contact = VaultHandle::open_with_root_key(clone.path(), &root).unwrap();
        assert!(contact.is_unlocked());

        hw_env_restore(_old_env);
    }

    /// The heartbeat side-effect never taps: it reads the in-memory Root
    /// Key only, so the unlock tap is the single hardware event of an
    /// unlock-with-heartbeat.
    #[test]
    fn heartbeat_performs_no_hardware_operations() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        crate::hwkey::install(std::sync::Arc::new(CountingTapMock(counter.clone())));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, _phrase) = audit_vault(dir.path());
        handle.unlock(&password).unwrap();
        let seal_key = handle.unlocked().devkey_seal;
        enable_hw_seal(
            &dir.path().join("meta/device-privkey.json"),
            &seal_key,
            handle.vault_id,
            Some(handle.device_id),
            false,
            None,
        )
        .unwrap();
        handle.lock();

        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&password).unwrap();
        let after_unlock = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_unlock > 0, "the unlock itself must pay the tap");

        assert!(!crate::legacy::heartbeat(dir.path(), &h).unwrap());
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            after_unlock,
            "the heartbeat must not touch the chip"
        );

        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
    }

    /// Rotation and password change re-seal through the same seam: the
    /// seal survives a Root Key rotation, a password change re-keys it
    /// under the chip, and with the token gone the change fails closed
    /// BEFORE any write (the C1 lockout guard), leaving the old password
    /// working. The phrase path stays the rescue.
    #[test]
    fn rotation_and_password_change_reseal_through_the_same_seam() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, _phrase) = audit_vault(dir.path());
        seal_to_tap(&mut handle);

        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&password).unwrap();
        h.rotate_root_key().unwrap();
        h.lock();
        let mut h2 = VaultHandle::open(dir.path()).unwrap();
        h2.unlock(&password).unwrap();
        assert_eq!(
            file_kind(&dir.path().join("meta/device-privkey.json")),
            PrivkeyFileKind::SealedHw
        );

        // Password change with the chip present re-keys the seal.
        h2.change_master_password(&password, "new password 456").unwrap();
        h2.lock();
        let mut h3 = VaultHandle::open(dir.path()).unwrap();
        h3.unlock("new password 456").unwrap();

        // Token gone mid-session: the C1 guard refuses BEFORE any write,
        // so the old password still opens the vault afterwards.
        crate::hwkey::uninstall();
        assert!(h3
            .change_master_password("new password 456", "another pass 789")
            .is_err());
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        h3.lock();
        let mut h4 = VaultHandle::open(dir.path()).unwrap();
        h4.unlock("new password 456").unwrap();

        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
    }

    /// C1 review fix: with the device file hw-sealed, the member identity
    /// seed must no longer open under the bare KEK subkey. Enable rebinds
    /// it under the hw-content-key-derived identity key; rotate re-keys it
    /// along; disable rebinds it back.
    #[test]
    fn enable_hw_seal_rebinds_the_member_identity_seed() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, _phrase) = audit_vault(dir.path());
        let vault_path = handle.path.clone();
        let device_id = handle.device_id;
        let privkey_path = vault_path.join("meta/device-privkey.json");

        // Device-local member unlock row in the pre-fix shape: the seed
        // sealed under the bare KEK subkey.
        let devkey_seal = handle.unlocked().devkey_seal;
        let identity = crate::vault::identity::IdentityKeys::generate().unwrap();
        let seed_sealed =
            hex::encode(crate::vault::identity::seal_identity(&devkey_seal, &identity).unwrap());
        let kdf_json =
            std::fs::read_to_string(vault_path.join("meta/kdf-params.json")).unwrap();
        let row = serde_json::json!({
            // A foreign device id: the row must be rebindable but never
            // match THIS device's admin unlock canary lookup.
            "device_id": uuid::Uuid::new_v4().to_string(),
            "kdf_params": serde_json::from_str::<serde_json::Value>(&kdf_json).unwrap(),
            "kek_canary": hex::encode([0u8; 16]),
            "identity_seed_sealed": seed_sealed,
        });
        crate::vault::write_vault_file(
            &vault_path.join("meta/member-unlock.json"),
            serde_json::to_string_pretty(&row).unwrap().as_bytes(),
        )
        .unwrap();

        let seed_hex = || {
            let row: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(vault_path.join("meta/member-unlock.json")).unwrap(),
            )
            .unwrap();
            row["identity_seed_sealed"].as_str().unwrap().to_string()
        };
        let opens_under = |hex_str: &str, key: &[u8; 32]| {
            crate::vault::identity::open_identity(key, &hex::decode(hex_str).unwrap()).is_ok()
        };

        assert!(opens_under(&seed_hex(), &devkey_seal));
        seal_to_tap(&mut handle);

        // The C1 property: the password-derived subkey alone cannot open
        // the seed; the hw-bound key can.
        assert!(!opens_under(&seed_hex(), &devkey_seal));
        let ik = identity_key_of_file(&privkey_path, &devkey_seal);
        assert!(opens_under(&seed_hex(), &ik));

        // Password change re-keys the seed to the new content key.
        let mut h = VaultHandle::open(&vault_path).unwrap();
        h.unlock(&password).unwrap();
        h.change_master_password(&password, "rotated pass 456").unwrap();
        h.lock();
        let new_seal = {
            let kdf_json =
                std::fs::read_to_string(vault_path.join("meta/kdf-params.json")).unwrap();
            let params: crate::types::KdfParams = serde_json::from_str(&kdf_json).unwrap();
            let kek = crate::crypto::kdf::derive_kek("rotated pass 456", &params).unwrap();
            crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek).unwrap()
        };
        assert!(!opens_under(&seed_hex(), &ik));
        let ik2 = identity_key_of_file(&privkey_path, &new_seal);
        assert!(opens_under(&seed_hex(), &ik2));
        assert_ne!(ik, ik2);

        // The rotation re-keys identity.enc along with the seed (the full
        // unlock above healed it to ik; the change moves it to ik2).
        let identity_enc = std::fs::read(vault_path.join("meta/identity.enc")).unwrap();
        assert!(crate::vault::identity::open_identity(&ik2, &identity_enc).is_ok());
        assert!(crate::vault::identity::open_identity(&ik, &identity_enc).is_err());

        // Disable rebinds the seed back under the bare KEK subkey.
        disable_hw_seal(&privkey_path, &new_seal, Some(device_id)).unwrap();
        assert!(opens_under(&seed_hex(), &new_seal));
        assert_eq!(file_kind(&privkey_path), PrivkeyFileKind::Sealed);

        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
    }

    /// C1 review fix (admin side): on an hw-sealed device the
    /// passphrase-fallback identity re-binds under the hw key at the first
    /// full unlock, so the master password alone cannot open it anymore.
    #[test]
    fn unlock_rebinds_the_passphrase_identity_under_the_hw_key() {
        let _g = HW_LOCK.lock().unwrap();
        let _old_env = hw_env_clear();
        crate::hwkey::uninstall();
        let dir = tempfile::tempdir().unwrap();
        let (mut handle, password, _phrase) = audit_vault(dir.path());
        let vault_path = handle.path.clone();
        let identity_path = vault_path.join("meta/identity.enc");

        // Keystore-less test env: passphrase-mode identity, openable with
        // the master password alone.
        let meta: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vault_path.join("meta/identity-meta.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(meta["mode"].as_str(), Some("passphrase"));
        let passphrase_key = || {
            let salt = hex::decode(meta["salt_hex"].as_str().unwrap()).unwrap();
            let params = crate::types::KdfParams {
                profile: crate::types::KdfProfile::MobileLow,
                memory_kib: meta["memory_kib"].as_u64().unwrap() as u32,
                time_cost: meta["time_cost"].as_u64().unwrap() as u32,
                parallelism: 1,
                salt,
            };
            crate::crypto::kdf::derive_kek(&password, &params).unwrap()
        };
        assert!(crate::vault::identity::open_identity(&passphrase_key(), &std::fs::read(&identity_path).unwrap()).is_ok());

        crate::hwkey::install(std::sync::Arc::new(TapMock));
        seal_to_tap(&mut handle);
        let mut h = VaultHandle::open(&vault_path).unwrap();
        h.unlock(&password).unwrap();
        assert!(h.identity().is_some());
        h.lock();

        // Healed: the password alone no longer opens the identity.
        let sealed = std::fs::read(&identity_path).unwrap();
        assert!(crate::vault::identity::open_identity(&passphrase_key(), &sealed).is_err());
        let devkey_seal = {
            let kdf_json =
                std::fs::read_to_string(vault_path.join("meta/kdf-params.json")).unwrap();
            let params: crate::types::KdfParams = serde_json::from_str(&kdf_json).unwrap();
            let kek = crate::crypto::kdf::derive_kek(&password, &params).unwrap();
            crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek).unwrap()
        };
        let ik = identity_key_of_file(&vault_path.join("meta/device-privkey.json"), &devkey_seal);
        assert!(crate::vault::identity::open_identity(&ik, &sealed).is_ok());

        // C3 follow-up: a quick unlock (no master password) still loads
        // the healed identity, because the hw key is tried first.
        let kek = {
            let kdf_json =
                std::fs::read_to_string(vault_path.join("meta/kdf-params.json")).unwrap();
            let params: crate::types::KdfParams = serde_json::from_str(&kdf_json).unwrap();
            crate::crypto::kdf::derive_kek(&password, &params).unwrap()
        };
        crate::hwkey::install(std::sync::Arc::new(TapMock));
        let mut q = VaultHandle::open(&vault_path).unwrap();
        q.unlock_with_kek(&kek).unwrap();
        assert!(q.identity().is_some(), "quick unlock must load the healed identity");

        crate::hwkey::uninstall();
        hw_env_restore(_old_env);
    }

    /// Open the device file (mock chip installed) and derive its identity
    /// sealing key.
    fn identity_key_of_file(privkey_path: &std::path::Path, seal_key: &[u8; 32]) -> [u8; 32] {
        let file = std::fs::read_to_string(privkey_path).unwrap();
        let backend = hw_backend_of(file.as_bytes()).unwrap();
        let hw = crate::hwkey::store_for(&backend).unwrap();
        let (_, ck) = open_bytes_hw_with_ck(&*hw, seal_key, file.as_bytes()).unwrap();
        *crate::crypto::hkdf_derive::derive_identity_hw_key(&ck).unwrap()
    }
}
