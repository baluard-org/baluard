//! Legacy contact: owner-silence emergency access.
//!
//! Design: docs/plan-legacy-contact.md. The contact holds an armored kit
//! (letter header + sealed body) and a read-only deploy key. The vault
//! ships a Root Key layer blob sealed under an escrow key that exists only
//! in the kit. Owner devices sign Armed/Closed records and a coarse alive
//! heartbeat; N days of observed silence lets the contact unwrap.
//! The wait is a social control: a modified client ignores it, and the
//! plan says so. Real denial is Root Key rotation, not a record.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use base64::Engine as _;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, build_random_nonce};
use crate::crypto::kdf;
use crate::crypto::signature;
use crate::error::{BaluardError, VaultError};
use crate::types::{CipherEnvelope, EnvelopeHeader, KdfParams, KdfProfile};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const RECORD_TAG: &[u8] = b"baluard/legacy/v1";
pub const ALIVE_TAG: &[u8] = b"baluard/legacy-alive/v1";
pub const LAYER_AAD_PREFIX: &[u8] = b"baluard/legacy-layer/v1";
pub const ARMOR_BEGIN: &str = "-----BEGIN BALUARD LEGACY KEY-----";
pub const ARMOR_END: &str = "-----END BALUARD LEGACY KEY-----";
pub const LAYER_FORMAT: u8 = 1;
const EK_CHECK_INFO: &[u8] = b"legacy-check";

/// Owner-held legacy state, signed with the legacy key `LK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyState {
    Armed,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    Denied,
    Replaced,
    Disarmed,
}

/// The owner-signed state record synced at `meta/legacy/<kit_id>.json`.
/// The contact verifies every field against the kit; the signing key is
/// the `LK` public from the kit, never a key from this synced file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyRecord {
    pub version: u8,
    pub vault_id: String,
    pub kit_id: String,
    pub state: LegacyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<CloseReason>,
    pub seq: u64,
    pub epoch: u64,
    pub window_days: u64,
    /// Hex of the SHA-256 over the `LK` verifying key bytes.
    pub lk_public_hash: String,
    /// Hex of HMAC(EK, "legacy-check" || kit_id); binds the record to the kit.
    pub ek_check: String,
    /// Hex of the SHA-256 over the sealed layer blob bytes.
    pub layer_hash: String,
    /// OpenSSH fingerprint of the kit's read-only deploy key.
    pub deploy_key_fingerprint: String,
    /// Hex of the SHA-256 over the repo SSH URL.
    pub repo_url_hash: String,
    pub signer_device_id: String,
    /// Day (days since epoch) the kit was armed; the silence floor when
    /// no activity signal exists yet.
    pub created_day: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<String>,
}

/// The owner-signed heartbeat synced at `meta/legacy/<kit_id>.alive`.
/// Day-rounded: a device refreshes it only when the stored day is older
/// than seven days, keeping unlock timing coarse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliveRecord {
    pub version: u8,
    pub vault_id: String,
    pub kit_id: String,
    pub seq: u64,
    pub day: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<String>,
}

/// Owner-side secrets for one armed kit, sealed into `meta/legacy.enc`
/// under the Root Key. Re-exporting a lost kit reuses `kit_letter` and
/// `kit_armor` so the resend is byte-identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyStore {
    pub kit_id: String,
    /// Hex of the `LK` private seed.
    pub lk_seed: String,
    /// Hex of the escrow key that seals the layer blob.
    pub ek: String,
    /// The plaintext letter header exactly as exported.
    pub kit_letter: String,
    /// The full armored kit exactly as exported; resend is byte-identical.
    pub kit_armor: String,
    pub deploy_key_fingerprint: String,
    /// Forge coordinates for deploy-key removal on close. Forge-local
    /// bookkeeping, so they live in the owner store, not the signed record.
    pub forge_key_id: Option<u64>,
    pub provider: crate::providers::types::Provider,
    pub owner: String,
    pub repo: String,
    pub origin_url: String,
}

/// The contact-side kit contents, recovered by `open_kit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitBody {
    pub format: u8,
    pub vault_id: String,
    pub kit_id: String,
    pub repo_ssh_url: String,
    /// OpenSSH private key PEM of the read-only deploy key.
    pub deploy_private_key: String,
    /// Hex of the escrow key that opens the layer blob.
    pub ek: String,
    /// Hex of the `LK` verifying key bytes.
    pub lk_public: String,
    pub owner_name: String,
    pub created_at: u64,
    pub window_days: u64,
}

/// The contact-visible lifecycle phase, derived by `derive_phase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyPhase {
    /// Record Armed but the observed silence is under the window.
    Quiet,
    /// Record Armed and the window has elapsed on the observed silence.
    Open,
    Closed,
}

/// Build a length-prefixed signed payload: domain tag, then each field
/// as a 4-byte big-endian length prefix plus bytes, so field boundaries
/// survive concatenation.
fn tagged_payload(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    payload.extend_from_slice(tag);
    for field in fields {
        payload.extend_from_slice(&(field.len() as u32).to_be_bytes());
        payload.extend_from_slice(field);
    }
    payload
}

fn sign_fields(
    signing_key: &SigningKey,
    tag: &[u8],
    fields: &[&[u8]],
) -> Result<String, BaluardError> {
    let sig = signature::sign(signing_key, &tagged_payload(tag, fields))
        .map_err(|e| VaultError::Metadata(format!("legacy signature: {e}")))?;
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify a signed legacy payload. The verifying key always comes from
/// the kit (`lk_public`), never from the synced record.
fn verify_fields(
    verifying_key: &VerifyingKey,
    tag: &[u8],
    fields: &[&[u8]],
    sig_hex: &str,
) -> Result<(), BaluardError> {
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| VaultError::Corrupt(format!("legacy signature hex: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| VaultError::Corrupt("invalid legacy signature".into()))?;
    signature::verify(verifying_key, &tagged_payload(tag, fields), &sig)
        .map_err(|_| VaultError::Corrupt("legacy record: invalid owner signature (tampered?)".into()))?;
    Ok(())
}

fn record_fields(record: &LegacyRecord) -> Vec<Vec<u8>> {
    vec![
        record.vault_id.as_bytes().to_vec(),
        record.kit_id.as_bytes().to_vec(),
        serde_json::to_vec(&record.state).unwrap_or_default(),
        serde_json::to_vec(&record.reason).unwrap_or_default(),
        record.seq.to_be_bytes().to_vec(),
        record.epoch.to_be_bytes().to_vec(),
        record.window_days.to_be_bytes().to_vec(),
        record.created_day.to_be_bytes().to_vec(),
        record.lk_public_hash.as_bytes().to_vec(),
        record.ek_check.as_bytes().to_vec(),
        record.layer_hash.as_bytes().to_vec(),
        record.deploy_key_fingerprint.as_bytes().to_vec(),
        record.repo_url_hash.as_bytes().to_vec(),
        record.signer_device_id.as_bytes().to_vec(),
    ]
}

/// Sign a record with the owner's legacy key. `seq` must strictly grow
/// across all writes; the verifier refuses lower-seq replays.
pub fn sign_record(record: &mut LegacyRecord, lk: &SigningKey) -> Result<(), BaluardError> {
    let fields = record_fields(record);
    let field_refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
    record.owner_signature = Some(sign_fields(lk, RECORD_TAG, &field_refs)?);
    Ok(())
}

/// Verify a record against the kit's `LK` public. Returns the parsed
/// verifying key reuse so callers can chain alive-record checks.
pub fn verify_record(
    record: &LegacyRecord,
    lk_public: &[u8; 32],
) -> Result<(), BaluardError> {
    let sig = record
        .owner_signature
        .as_deref()
        .ok_or_else(|| VaultError::Corrupt("legacy record missing owner signature".into()))?;
    let vk = signature::verifying_key_from_bytes(lk_public)
        .map_err(|e| VaultError::Corrupt(format!("legacy key: {e}")))?;
    let fields = record_fields(record);
    let field_refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
    verify_fields(&vk, RECORD_TAG, &field_refs, sig)
}

/// Sign the alive heartbeat.
pub fn sign_alive(alive: &mut AliveRecord, lk: &SigningKey) -> Result<(), BaluardError> {
    let seq_bytes = alive.seq.to_be_bytes();
    let day_bytes = alive.day.to_be_bytes();
    let fields: Vec<&[u8]> = vec![
        alive.vault_id.as_bytes(),
        alive.kit_id.as_bytes(),
        &seq_bytes,
        &day_bytes,
    ];
    alive.owner_signature = Some(sign_fields(lk, ALIVE_TAG, &fields)?);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AliveRecordPriv {
    version: u8,
    vault_id: String,
    kit_id: String,
    seq: u64,
    day: u64,
    owner_signature: Option<String>,
}

/// Verify the alive heartbeat against the kit's `LK` public and the
/// record identity, refusing cross-kit and cross-vault replays.
pub fn verify_alive(
    alive_json: &str,
    record: &LegacyRecord,
    lk_public: &[u8; 32],
) -> Result<u64, BaluardError> {
    let alive: AliveRecordPriv = serde_json::from_str(alive_json)
        .map_err(|e| VaultError::Corrupt(format!("alive record parsing: {e}")))?;
    if alive.vault_id != record.vault_id || alive.kit_id != record.kit_id {
        return Err(VaultError::Corrupt("alive record is for another kit".into()).into());
    }
    if alive.seq < record.seq {
        return Err(VaultError::Corrupt("alive record seq below the record".into()).into());
    }
    let sig = alive
        .owner_signature
        .as_deref()
        .ok_or_else(|| VaultError::Corrupt("alive record missing signature".into()))?;
    let vk = signature::verifying_key_from_bytes(lk_public)
        .map_err(|e| VaultError::Corrupt(format!("legacy key: {e}")))?;
    let seq_bytes = alive.seq.to_be_bytes();
    let day_bytes = alive.day.to_be_bytes();
    let fields: Vec<&[u8]> = vec![
        alive.vault_id.as_bytes(),
        alive.kit_id.as_bytes(),
        &seq_bytes,
        &day_bytes,
    ];
    verify_fields(&vk, ALIVE_TAG, &fields, sig)?;
    Ok(alive.day)
}

/// HMAC(EK, "legacy-check" || kit_id), hex. Proves the record was written
/// by a holder of `EK` (the owner) without shipping `EK` in the record.
pub fn ek_check(ek: &[u8; 32], kit_id: &str) -> Result<String, BaluardError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ek)
        .map_err(|e| VaultError::Metadata(format!("ek check: {e}")))?;
    mac.update(EK_CHECK_INFO);
    mac.update(kit_id.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Seal the layer blob: AES-256-GCM(EK, root_key), AAD binding vault id,
/// kit id, and epoch. Packed as fixed-order hex `v1:nonce:ct:tag`.
pub fn seal_layer(
    ek: &[u8; 32],
    root_key: &[u8; 64],
    vault_id: &str,
    kit_id: &str,
    epoch: u64,
) -> Result<String, BaluardError> {
    let mut aad = LAYER_AAD_PREFIX.to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(kit_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    let envelope = aead::encrypt(
        ek,
        root_key,
        &aad,
        &build_random_nonce(),
        EnvelopeHeader {
            version: 1,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: epoch,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
    )
    .map_err(|e| VaultError::Metadata(format!("legacy layer: {e}")))?;
    Ok(format!(
        "{LAYER_FORMAT}:{nonce}:{ct}:{tag}",
        nonce = hex::encode(envelope.nonce),
        ct = hex::encode(envelope.ciphertext),
        tag = hex::encode(envelope.tag),
    ))
}

/// Open the layer blob and zeroize the packed hex temporaries on the way
/// out. Returns the Root Key for the recorded epoch only.
pub fn open_layer(
    ek: &[u8; 32],
    packed: &str,
    vault_id: &str,
    kit_id: &str,
    epoch: u64,
) -> Result<Zeroizing<[u8; 64]>, BaluardError> {
    let mut parts = packed.split(':');
    let version: u8 = parts
        .next()
        .ok_or_else(|| VaultError::Corrupt("legacy layer missing".into()))?
        .parse()
        .map_err(|_| VaultError::Corrupt("legacy layer version".into()))?;
    if version != LAYER_FORMAT {
        return Err(VaultError::InvalidEnvelopeVersion(version).into());
    }
    let nonce_hex = parts
        .next()
        .ok_or_else(|| VaultError::Corrupt("legacy layer missing nonce".into()))?;
    let ct_hex = parts
        .next()
        .ok_or_else(|| VaultError::Corrupt("legacy layer missing ciphertext".into()))?;
    let tag_hex = parts
        .next()
        .ok_or_else(|| VaultError::Corrupt("legacy layer missing tag".into()))?;
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| VaultError::Corrupt(format!("legacy layer nonce: {e}")))?;
    let ct = hex::decode(ct_hex)
        .map_err(|e| VaultError::Corrupt(format!("legacy layer ciphertext: {e}")))?;
    let tag_bytes = hex::decode(tag_hex)
        .map_err(|e| VaultError::Corrupt(format!("legacy layer tag: {e}")))?;
    if nonce_bytes.len() != 12 || tag_bytes.len() != 16 {
        return Err(VaultError::Corrupt("legacy layer lengths".into()).into());
    }
    nonce.copy_from_slice(&nonce_bytes);
    tag.copy_from_slice(&tag_bytes);

    let mut aad = LAYER_AAD_PREFIX.to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(kit_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    let envelope = CipherEnvelope {
        header: EnvelopeHeader {
            version: 1,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: epoch,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
        nonce,
        aad,
        ciphertext: ct,
        tag,
    };
    let plaintext = aead::decrypt(ek, &envelope)
        .map_err(|_| VaultError::Corrupt("legacy layer does not open".into()))?;
    let mut root = Zeroizing::new([0u8; 64]);
    if plaintext.len() != 64 {
        return Err(VaultError::Corrupt("legacy layer key length".into()).into());
    }
    root.copy_from_slice(&plaintext);
    Ok(root)
}

/// Normalize an armored kit for parsing: strip the BOM, unify line
/// endings, and remove email quote prefixes so a forwarded-and-quoted
/// paste still matches the header AAD.
fn normalize_armor(text: &str) -> String {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = String::with_capacity(text.len());
    for line in text.replace("\r\n", "\n").replace('\r', "\n").split('\n') {
        let mut line = line;
        while let Some(stripped) = line.strip_prefix("> ") {
            line = stripped;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.pop();
    out
}

/// Seal the kit: plaintext letter header above an AES-256-GCM body keyed
/// by Argon2id over the passphrase (NFKC, never trimmed), with the exact
/// normalized header bytes as AAD so the letter cannot be altered
/// silently. Wrong passphrase and corruption are indistinguishable.
pub fn seal_kit(letter: &str, body: &KitBody, passphrase: &str) -> Result<String, BaluardError> {
    let body_json = serde_json::to_vec(body)
        .map_err(|e| VaultError::Metadata(format!("kit body: {e}")))?;
    let params = kdf::create_params(KdfProfile::DesktopStd);
    let kek = kdf::derive_kek(passphrase, &params)
        .map_err(|e| VaultError::Metadata(format!("kit kdf: {e}")))?;
    let nonce = build_random_nonce();
    // The letter is bound exactly as it appears in the armor: normalized
    // and newline-terminated. open_kit verifies against the extracted
    // armor prefix, so sealing over anything else bricks every letter
    // that does not already end in a newline.
    let mut aad_letter = normalize_armor(letter);
    if !aad_letter.ends_with('\n') {
        aad_letter.push('\n');
    }
    let envelope = aead::encrypt(&kek, &body_json, aad_letter.as_bytes(), &nonce, EnvelopeHeader {
        version: 1,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    })
    .map_err(|e| VaultError::Metadata(format!("kit seal: {e}")))?;

    let sealed = serde_json::json!({
        "format": 1,
        "kdf": {
            "memory_kib": params.memory_kib,
            "time_cost": params.time_cost,
            "parallelism": params.parallelism,
            "salt": hex::encode(&params.salt),
        },
        "nonce": hex::encode(envelope.nonce),
        "ciphertext": hex::encode(envelope.ciphertext),
        "tag": hex::encode(envelope.tag),
    });
    let sealed_json = serde_json::to_string(&sealed)
        .map_err(|e| VaultError::Metadata(format!("kit armor: {e}")))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(sealed_json.as_bytes());
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(76)
        .map(std::str::from_utf8)
        .collect::<Result<_, _>>()
        .map_err(|e| VaultError::Metadata(format!("kit armor utf8: {e}")))?;

    let mut armor = aad_letter;
    armor.push_str(ARMOR_BEGIN);
    armor.push('\n');
    for chunk in wrapped {
        armor.push_str(chunk);
        armor.push('\n');
    }
    armor.push_str(ARMOR_END);
    armor.push('\n');
    Ok(armor)
}

/// Open a kit with its passphrase. Tolerates CRLF and quoted-email paste
/// through `normalize_armor`; any other letter edit breaks the AAD and
/// surfaces as the same error as a wrong passphrase.
pub fn open_kit(armor: &str, passphrase: &str) -> Result<KitBody, BaluardError> {
    let normalized = normalize_armor(armor);
    let begin_at = normalized.find(ARMOR_BEGIN).ok_or_else(|| {
        VaultError::Corrupt("wrong passphrase or damaged file: legacy key header missing".into())
    })?;
    let end_at = normalized.find(ARMOR_END).ok_or_else(|| {
        VaultError::Corrupt("wrong passphrase or damaged file: legacy key footer missing".into())
    })?;
    if end_at < begin_at {
        return Err(VaultError::Corrupt("legacy key armor structure".into()).into());
    }
    let letter = &normalized[..begin_at];
    let body_region = &normalized[begin_at + ARMOR_BEGIN.len() + 1..end_at];
    let b64: String = body_region.chars().filter(|c| !c.is_whitespace()).collect();
    let sealed_json = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;
    let sealed: serde_json::Value = serde_json::from_slice(&sealed_json)
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;

    if sealed.get("format").and_then(|v| v.as_u64()) != Some(1) {
        return Err(VaultError::Corrupt("legacy kit format".into()).into());
    }
    let kdf_json = sealed
        .get("kdf")
        .ok_or_else(|| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;
    let salt = hex::decode(kdf_json.get("salt").and_then(|v| v.as_str()).unwrap_or(""))
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;
    let params = KdfParams {
        profile: KdfProfile::DesktopStd,
        memory_kib: kdf_json.get("memory_kib").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        time_cost: kdf_json.get("time_cost").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        parallelism: kdf_json.get("parallelism").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        salt,
    };
    let kek = kdf::derive_kek(passphrase, &params)
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;

    let decode_hex = |v: Option<&serde_json::Value>| -> Result<Vec<u8>, BaluardError> {
        hex::decode(v.and_then(|x| x.as_str()).unwrap_or(""))
            .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()).into())
    };
    let nonce_vec = decode_hex(sealed.get("nonce"))?;
    let ciphertext = decode_hex(sealed.get("ciphertext"))?;
    let tag = decode_hex(sealed.get("tag"))?;
    if nonce_vec.len() != 12 || tag.len() != 16 {
        return Err(VaultError::Corrupt("wrong passphrase or damaged file".into()).into());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(&tag);

    let envelope = CipherEnvelope {
        header: EnvelopeHeader {
            version: 1,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: 0,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
        nonce,
        aad: letter.as_bytes().to_vec(),
        ciphertext,
        tag: tag_arr,
    };
    let body_json = aead::decrypt(&kek, &envelope)
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()))?;
    serde_json::from_slice(&body_json)
        .map_err(|_| VaultError::Corrupt("wrong passphrase or damaged file".into()).into())
}

/// Derive the contact-visible phase. `last_activity_day` is the newest of
/// the alive-record day and any forge-reported deploy-key use, in days
/// since the epoch; `now_day` likewise. A Closed record always wins.
pub fn derive_phase(
    record: &LegacyRecord,
    last_activity_day: Option<u64>,
    now_day: u64,
) -> LegacyPhase {
    if record.state != LegacyState::Armed {
        return LegacyPhase::Closed;
    }
    // No activity signal: the silence counts from the arm day, so a
    // never-written heartbeat cannot shorten the wait below the window.
    let latest = last_activity_day.unwrap_or(record.created_day).max(record.created_day);
    let silence = now_day.saturating_sub(latest);
    if silence >= record.window_days {
        LegacyPhase::Open
    } else {
        LegacyPhase::Quiet
    }
}

/// Load a synced owner record from `meta/legacy/<kit_id>.json`.
pub fn load_record(vault_path: &Path, kit_id: &str) -> Result<Option<LegacyRecord>, BaluardError> {
    let path = vault_path.join("meta/legacy").join(format!("{kit_id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading legacy record: {e}")))?;
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|e| VaultError::Corrupt(format!("legacy record parsing: {e}")).into())
}

/// Save an owner record. The record itself is not secret (the wrapped
/// key lives in the layer blob), but it is owner-authoritative state, so
/// it rides the same owner-only writer.
pub fn save_record(vault_path: &Path, record: &LegacyRecord) -> Result<(), BaluardError> {
    let dir = vault_path.join("meta/legacy");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", record.kit_id));
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| VaultError::Metadata(format!("legacy record: {e}")))?;
    crate::secret_file::write_secret_file(&path, json.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("legacy record write: {e}")))?;
    Ok(())
}

/// Save the sealed layer blob at `meta/legacy/<kit_id>.layer`. The blob
/// is ciphertext, but 0600 from the first byte costs nothing.
pub fn save_layer(vault_path: &Path, kit_id: &str, packed: &str) -> Result<(), BaluardError> {
    let dir = vault_path.join("meta/legacy");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{kit_id}.layer"));
    crate::secret_file::write_secret_file(&path, packed.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("legacy layer write: {e}")))?;
    Ok(())
}

/// Load the sealed layer blob.
pub fn load_layer(vault_path: &Path, kit_id: &str) -> Result<Option<String>, BaluardError> {
    let path = vault_path.join("meta/legacy").join(format!("{kit_id}.layer"));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading legacy layer: {e}")))?;
    Ok(Some(data))
}

/// Delete the layer blob and record for a closed kit.
pub fn remove_artifacts(vault_path: &Path, kit_id: &str) -> Result<(), BaluardError> {
    for name in [format!("{kit_id}.layer"), format!("{kit_id}.alive")] {
        let path = vault_path.join("meta/legacy").join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(VaultError::Metadata(format!("legacy cleanup: {e}")).into()),
        }
    }
    Ok(())
}

const STORE_INFO: &[u8] = b"baluard-legacy-store-v1";

/// Refresh the alive heartbeat when the last one is older than this
/// many days; day-rounded to keep the cadence coarse.
const HEARTBEAT_REFRESH_DAYS: u64 = 7;

/// Derive the `meta/legacy.enc` store key from the Root Key.
pub fn derive_store_key(root_key: &[u8; 64]) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, root_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(STORE_INFO, key.as_mut())
        .map_err(|e| VaultError::Metadata(format!("legacy store key: {e}")))?;
    Ok(key)
}

fn pack_envelope(envelope: &CipherEnvelope) -> String {
    format!(
        "{LAYER_FORMAT}:{nonce}:{ct}:{tag}",
        nonce = hex::encode(envelope.nonce),
        ct = hex::encode(&envelope.ciphertext),
        tag = hex::encode(envelope.tag),
    )
}

/// Seal the owner store (LK seed, kit letter, sealed body) under the
/// Root Key for `meta/legacy.enc`.
pub fn seal_store(root_key: &[u8; 64], store: &LegacyStore) -> Result<String, BaluardError> {
    let key = derive_store_key(root_key)?;
    let json = serde_json::to_vec(store)
        .map_err(|e| VaultError::Metadata(format!("legacy store: {e}")))?;
    let envelope = aead::encrypt(
        &key,
        &json,
        STORE_INFO,
        &build_random_nonce(),
        EnvelopeHeader {
            version: 1,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: 0,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
    )
    .map_err(|e| VaultError::Metadata(format!("legacy store seal: {e}")))?;
    Ok(pack_envelope(&envelope))
}

/// Open the owner store.
pub fn open_store(root_key: &[u8; 64], packed: &str) -> Result<LegacyStore, BaluardError> {
    let key = derive_store_key(root_key)?;
    let mut parts = packed.split(':');
    let version: u8 = parts
        .next()
        .ok_or_else(|| VaultError::Corrupt("legacy store missing".into()))?
        .parse()
        .map_err(|_| VaultError::Corrupt("legacy store version".into()))?;
    if version != LAYER_FORMAT {
        return Err(VaultError::InvalidEnvelopeVersion(version).into());
    }
    let decode = |v: Option<&str>| -> Result<Vec<u8>, BaluardError> {
        let raw = match v {
            Some(raw) => raw,
            None => return Err(VaultError::Corrupt("legacy store field".into()).into()),
        };
        hex::decode(raw).map_err(|_| VaultError::Corrupt("legacy store hex".into()).into())
    };
    let nonce_vec = decode(parts.next())?;
    let ciphertext = decode(parts.next())?;
    let tag_vec = decode(parts.next())?;
    if nonce_vec.len() != 12 || tag_vec.len() != 16 {
        return Err(VaultError::Corrupt("legacy store lengths".into()).into());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_vec);
    let envelope = CipherEnvelope {
        header: EnvelopeHeader {
            version: 1,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: 0,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
        nonce,
        aad: STORE_INFO.to_vec(),
        ciphertext,
        tag,
    };
    let json = aead::decrypt(&key, &envelope)
        .map_err(|_| VaultError::Corrupt("legacy store does not open".into()))?;
    serde_json::from_slice(&json)
        .map_err(|e| VaultError::Corrupt(format!("legacy store parsing: {e}")).into())
}

/// Save the owner store at `meta/legacy.enc`.
pub fn save_store(
    vault_path: &Path,
    root_key: &[u8; 64],
    store: &LegacyStore,
) -> Result<(), BaluardError> {
    let path = vault_path.join("meta/legacy.enc");
    let packed = seal_store(root_key, store)?;
    crate::secret_file::write_secret_file(&path, packed.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("legacy store write: {e}")))?;
    Ok(())
}

/// Load the owner store; None when legacy access was never armed.
pub fn load_store(
    vault_path: &Path,
    root_key: &[u8; 64],
) -> Result<Option<LegacyStore>, BaluardError> {
    let path = vault_path.join("meta/legacy.enc");
    if !path.exists() {
        return Ok(None);
    }
    let packed = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading legacy store: {e}")))?;
    open_store(root_key, &packed).map(Some)
}

/// Rotation coverage: re-seal the owner store and every armed kit's
/// layer blob under the new Root Key, re-signing the record with the
/// store's legacy key. No-op when legacy access is not armed. Runs with
/// the outgoing Root Key so a store sealed before the swap still opens.
pub fn rewrap_after_rotation(
    vault_path: &Path,
    outgoing_root: &[u8; 64],
    new_root_key: &[u8; 64],
    new_epoch: u64,
    signer_device_id: &str,
) -> Result<(), BaluardError> {
    let Some(store) = load_store(vault_path, outgoing_root)? else {
        return Ok(());
    };
    let lk = SigningKey::from_bytes(
        &hex::decode(&store.lk_seed)
            .map_err(|e| VaultError::Corrupt(format!("legacy store seed: {e}")))?
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("legacy store seed length".into()))?,
    );
    let ek: [u8; 32] = hex::decode(&store.ek)
        .map_err(|e| VaultError::Corrupt(format!("legacy store ek: {e}")))?
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt("legacy store ek length".into()))?;

    let mut record = load_record(vault_path, &store.kit_id)?
        .ok_or_else(|| VaultError::Corrupt("legacy record missing for armed store".into()))?;
    if record.state == LegacyState::Armed {
        // The layer holds the Root Key itself, so rotation replaces its
        // plaintext: the old blob opens to a key that no longer decrypts
        // anything, and re-sealing it would brick the contact's recovery.
        let new_packed = seal_layer(&ek, new_root_key, &record.vault_id, &store.kit_id, new_epoch)?;
        save_layer(vault_path, &store.kit_id, &new_packed)?;
        record.epoch = new_epoch;
        record.seq += 1;
        record.layer_hash = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(new_packed.as_bytes()))
        };
        record.signer_device_id = signer_device_id.to_string();
        sign_record(&mut record, &lk)?;
        save_record(vault_path, &record)?;
    }
    save_store(vault_path, new_root_key, &store)
}

/// Persist the owner-signed heartbeat at `meta/legacy/<kit_id>.alive`.
pub fn save_alive(vault_path: &Path, alive: &AliveRecord) -> Result<(), BaluardError> {
    let dir = vault_path.join("meta/legacy");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.alive", alive.kit_id));
    let json = serde_json::to_string_pretty(alive)
        .map_err(|e| VaultError::Metadata(format!("legacy alive: {e}")))?;
    crate::secret_file::write_secret_file(&path, json.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("legacy alive write: {e}")))?;
    Ok(())
}

/// Load the heartbeat; None when none was ever written.
pub fn load_alive(vault_path: &Path, kit_id: &str) -> Result<Option<AliveRecord>, BaluardError> {
    let path = vault_path.join("meta/legacy").join(format!("{kit_id}.alive"));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VaultError::Metadata(format!("reading legacy alive: {e}")))?;
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|e| VaultError::Corrupt(format!("legacy alive parsing: {e}")).into())
}

/// Coarse owner clock: days since the Unix epoch. Every legacy silence
/// computation is day-rounded (T14 fingerprint discipline), so nothing
/// here looks at finer time.
pub fn today_day() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// A freshly minted read-only deploy key. The private half ships only
/// inside the kit; the public half is what the forge receives.
pub struct DeployKeyPair {
    pub public_openssh: String,
    pub private_pem: String,
    pub fingerprint: String,
}

/// Mint an Ed25519 deploy keypair. Baluard arms read-only keys only.
pub fn generate_deploy_key() -> Result<DeployKeyPair, BaluardError> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let kp = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::private::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(kp),
        String::new(),
    )
    .map_err(|e| VaultError::Metadata(format!("deploy key: {e}")))?;
    let public_openssh = private
        .public_key()
        .to_openssh()
        .map_err(|e| VaultError::Metadata(format!("deploy key public: {e}")))?;
    let fingerprint = private
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let private_pem = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| VaultError::Metadata(format!("deploy key private: {e}")))?
        .to_string();
    Ok(DeployKeyPair {
        public_openssh,
        private_pem,
        fingerprint,
    })
}

/// The forge identity of the vault's remote, extracted by the caller
/// from the origin remote and the connected provider session.
#[derive(Debug, Clone)]
pub struct RemoteIdentity {
    pub provider: crate::providers::types::Provider,
    pub owner: String,
    pub repo: String,
    /// HTTPS origin URL as configured (hashed into the owner record).
    pub origin_url: String,
    /// SSH clone URL written into the kit body.
    pub ssh_url: String,
}

#[derive(Debug, Clone)]
pub struct ArmOutcome {
    pub kit_id: String,
    /// The full armored kit. Hand off to the contact out-of-band; the
    /// passphrase travels on a separate channel.
    pub kit_armor: String,
    pub deploy_key_fingerprint: String,
}

/// Arm legacy access: mint the kit keys, seal the layer blob, sign the
/// Armed record and the first heartbeat, persist the owner store, and
/// push the read-only deploy key to the forge. A failed forge push rolls
/// the local artifacts back so nothing is left half-armed.
#[allow(clippy::too_many_arguments)]
pub async fn arm(
    vault_path: &Path,
    handle: &crate::vault::handle::VaultHandle,
    remote: &RemoteIdentity,
    provider: &dyn crate::providers::types::ForgeProvider,
    token: &crate::providers::types::ProviderToken,
    window_days: u64,
    passphrase: &str,
    letter: &str,
    owner_name: &str,
) -> Result<ArmOutcome, BaluardError> {
    if !handle.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    if window_days > 365 {
        return Err(VaultError::InvalidOperation(
            "legacy window: at most 365 days".into(),
        )
        .into());
    }
    let root: [u8; 64] = *handle.unlocked().root()?.as_bytes();
    let epoch = handle.unlocked().current_epoch;
    let vault_id = handle.vault_id.to_string();

    if let Some(store) = load_store(vault_path, &root)? {
        if let Some(record) = load_record(vault_path, &store.kit_id)? {
            if record.state == LegacyState::Armed {
                return Err(VaultError::InvalidOperation(
                    "legacy contact is already armed; close the kit first".into(),
                )
                .into());
            }
        }
    }

    let kit_id = uuid::Uuid::new_v4().to_string();
    let lk_seed = rand::random::<[u8; 32]>();
    let lk = SigningKey::from_bytes(&lk_seed);
    let lk_public = hex::encode(lk.verifying_key().as_bytes());
    let mut ek = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut ek);
    let dk = generate_deploy_key()?;

    let packed = seal_layer(&ek, &root, &vault_id, &kit_id, epoch)?;
    let today = today_day();
    let mut record = LegacyRecord {
        version: 1,
        vault_id: vault_id.clone(),
        kit_id: kit_id.clone(),
        state: LegacyState::Armed,
        reason: None,
        seq: 1,
        epoch,
        window_days,
        lk_public_hash: sha256_hex(lk.verifying_key().as_bytes()),
        ek_check: ek_check(&ek, &kit_id)?,
        layer_hash: sha256_hex(packed.as_bytes()),
        deploy_key_fingerprint: dk.fingerprint.clone(),
        repo_url_hash: sha256_hex(remote.origin_url.as_bytes()),
        signer_device_id: handle.device_id.to_string(),
        created_day: today,
        owner_signature: None,
    };
    sign_record(&mut record, &lk)?;
    let mut alive = AliveRecord {
        version: 1,
        vault_id: vault_id.clone(),
        kit_id: kit_id.clone(),
        seq: 1,
        day: today,
        owner_signature: None,
    };
    sign_alive(&mut alive, &lk)?;

    let body = KitBody {
        format: 1,
        vault_id,
        kit_id: kit_id.clone(),
        repo_ssh_url: remote.ssh_url.clone(),
        deploy_private_key: dk.private_pem.clone(),
        ek: hex::encode(ek),
        lk_public,
        owner_name: owner_name.to_string(),
        created_at: now_secs(),
        window_days,
    };
    let armor = seal_kit(letter, &body, passphrase)?;

    save_layer(vault_path, &kit_id, &packed)?;
    save_record(vault_path, &record)?;
    save_alive(vault_path, &alive)?;
    let store = LegacyStore {
        kit_id: kit_id.clone(),
        lk_seed: hex::encode(lk_seed),
        ek: hex::encode(ek),
        kit_letter: letter.to_string(),
        kit_armor: armor.clone(),
        deploy_key_fingerprint: dk.fingerprint.clone(),
        forge_key_id: None,
        provider: remote.provider,
        owner: remote.owner.clone(),
        repo: remote.repo.clone(),
        origin_url: remote.origin_url.clone(),
    };
    save_store(vault_path, &root, &store)?;

    let title = format!("Baluard legacy contact ({})", &kit_id[..8]);
    match provider
        .add_deploy_key(token, &remote.owner, &remote.repo, &title, &dk.public_openssh)
        .await
    {
        Ok(forge_key_id) => {
            let mut store = store;
            store.forge_key_id = Some(forge_key_id);
            save_store(vault_path, &root, &store)?;
        }
        Err(e) => {
            // Roll the local kit back: a kit whose key never reached the
            // forge would arm a contact into a locked-out clone attempt.
            // Unlike a closed kit, nothing may survive — the record too.
            remove_artifacts(vault_path, &kit_id)?;
            let record_path = vault_path
                .join("meta/legacy")
                .join(format!("{kit_id}.json"));
            match std::fs::remove_file(&record_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(VaultError::Metadata(format!("legacy rollback: {e}")).into())
                }
            }
            let _ = std::fs::remove_file(vault_path.join("meta/legacy.enc"));
            return Err(VaultError::Metadata(format!(
                "arming failed: the remote refused the read-only key: {e}"
            ))
            .into());
        }
    }

    Ok(ArmOutcome {
        kit_id,
        kit_armor: armor,
        deploy_key_fingerprint: dk.fingerprint,
    })
}

/// Refresh the owner heartbeat on unlock. No-op unless a kit is Armed
/// and the last heartbeat is more than 7 days old; day-rounded writes
/// keep the cadence coarse.
pub fn heartbeat(
    vault_path: &Path,
    handle: &crate::vault::handle::VaultHandle,
) -> Result<bool, BaluardError> {
    if !handle.is_unlocked() {
        return Ok(false);
    }
    let root: [u8; 64] = *handle.unlocked().root()?.as_bytes();
    let Some(store) = load_store(vault_path, &root)? else {
        return Ok(false);
    };
    let Some(record) = load_record(vault_path, &store.kit_id)? else {
        return Ok(false);
    };
    if record.state != LegacyState::Armed {
        return Ok(false);
    }
    let lk = SigningKey::from_bytes(
        &hex::decode(&store.lk_seed)
            .map_err(|e| VaultError::Corrupt(format!("legacy store seed: {e}")))?
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("legacy store seed length".into()))?,
    );
    let today = today_day();
    let last_seq = load_alive(vault_path, &store.kit_id)?.map(|a| a.seq).unwrap_or(0);
    if let Some(existing) = load_alive(vault_path, &store.kit_id)? {
        if today.saturating_sub(existing.day) <= HEARTBEAT_REFRESH_DAYS {
            return Ok(false);
        }
    }
    let mut alive = AliveRecord {
        version: 1,
        vault_id: record.vault_id,
        kit_id: store.kit_id,
        seq: record.seq.max(last_seq) + 1,
        day: today,
        owner_signature: None,
    };
    sign_alive(&mut alive, &lk)?;
    save_alive(vault_path, &alive)?;
    Ok(true)
}

/// Owner-visible summary for the settings surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyStatus {
    pub kit_id: String,
    pub state: LegacyState,
    pub reason: Option<CloseReason>,
    pub phase: LegacyPhase,
    pub window_days: u64,
    pub silence_days: u64,
    pub created_day: u64,
    pub deploy_key_fingerprint: String,
}

/// Read the kit's current phase. Returns None when legacy access was
/// never armed on this vault.
pub fn status(
    vault_path: &Path,
    handle: &crate::vault::handle::VaultHandle,
) -> Result<Option<LegacyStatus>, BaluardError> {
    if !handle.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    let root: [u8; 64] = *handle.unlocked().root()?.as_bytes();
    let Some(store) = load_store(vault_path, &root)? else {
        return Ok(None);
    };
    let Some(record) = load_record(vault_path, &store.kit_id)? else {
        return Ok(None);
    };
    let alive_day = load_alive(vault_path, &store.kit_id)?.map(|a| a.day);
    let last_activity = alive_day.or(Some(record.created_day));
    let now_day = today_day();
    let phase = derive_phase(&record, last_activity, now_day);
    let silence_days = now_day.saturating_sub(last_activity.unwrap_or(now_day));
    Ok(Some(LegacyStatus {
        kit_id: record.kit_id,
        state: record.state,
        reason: record.reason,
        phase,
        window_days: record.window_days,
        silence_days,
        created_day: record.created_day,
        deploy_key_fingerprint: record.deploy_key_fingerprint,
    }))
}

/// Close a kit: sign the terminal Closed record, remove the layer blob
/// and heartbeat, and drop the forge's deploy key. Denied and Replaced
/// also rotate the Root Key in the same change, so a contact holding a
/// downloaded blob is left with ciphertext for a dead epoch. Replaced
/// callers then arm a fresh kit (new kit id).
pub async fn close(
    vault_path: &Path,
    handle: &mut crate::vault::handle::VaultHandle,
    provider: &dyn crate::providers::types::ForgeProvider,
    token: &crate::providers::types::ProviderToken,
    reason: CloseReason,
) -> Result<(), BaluardError> {
    if !handle.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    let root: [u8; 64] = *handle.unlocked().root()?.as_bytes();
    let Some(store) = load_store(vault_path, &root)? else {
        return Err(VaultError::InvalidOperation("legacy contact is not armed".into()).into());
    };
    let Some(mut record) = load_record(vault_path, &store.kit_id)? else {
        return Err(VaultError::Corrupt("legacy record missing for armed store".into()).into());
    };
    if record.state != LegacyState::Armed {
        return Ok(());
    }
    let lk = SigningKey::from_bytes(
        &hex::decode(&store.lk_seed)
            .map_err(|e| VaultError::Corrupt(format!("legacy store seed: {e}")))?
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("legacy store seed length".into()))?,
    );
    let alive_seq = load_alive(vault_path, &store.kit_id)?
        .map(|a| a.seq)
        .unwrap_or(0);
    record.state = LegacyState::Closed;
    record.reason = Some(reason);
    record.seq = record.seq.max(alive_seq) + 1;
    record.signer_device_id = handle.device_id.to_string();
    sign_record(&mut record, &lk)?;
    save_record(vault_path, &record)?;
    remove_artifacts(vault_path, &store.kit_id)?;

    if let Some(key_id) = store.forge_key_id {
        if let Err(e) = provider
            .remove_deploy_key(token, &store.owner, &store.repo, key_id)
            .await
        {
            // Best-effort: the Closed record and (for denied/replaced)
            // the rotation below already disarm the kit cryptographically.
            // A forge outage must not wedge the terminal state.
            eprintln!("[legacy] deploy key removal deferred: {e}");
        }
    }

    if matches!(reason, CloseReason::Denied | CloseReason::Replaced) {
        handle.rotate_root_key()?;
    }
    Ok(())
}

/// Re-export the kit byte-identically. Only an Armed kit re-sends; a
/// closed kit refuses with the reason.
pub fn resend(
    vault_path: &Path,
    handle: &crate::vault::handle::VaultHandle,
) -> Result<(String, String), BaluardError> {
    if !handle.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    let root: [u8; 64] = *handle.unlocked().root()?.as_bytes();
    let Some(store) = load_store(vault_path, &root)? else {
        return Err(VaultError::InvalidOperation("legacy contact is not armed".into()).into());
    };
    let Some(record) = load_record(vault_path, &store.kit_id)? else {
        return Err(VaultError::Corrupt("legacy record missing".into()).into());
    };
    if record.state != LegacyState::Armed {
        return Err(VaultError::InvalidOperation(
            "this kit was closed; make a new one".into(),
        )
        .into());
    }
    Ok((store.kit_armor, store.kit_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::types::mock::MockProvider;
    use crate::providers::types::ProviderToken;

    /// Open a fresh vault for the owner-op tests: create, drop the
    /// ceremony handle, re-open, unlock.
    fn open_vault(dir: &tempfile::TempDir) -> crate::vault::handle::VaultHandle {
        let password = "test-password-123";
        let (handle, _secrets) = crate::vault::creation::VaultCreator::new(
            dir.path(),
            password,
            "test-device",
        )
        .kdf_profile(crate::types::KdfProfile::MobileLow)
        .initialize_git(false)
        .execute()
        .unwrap();
        drop(handle);
        let mut handle = crate::vault::handle::VaultHandle::open(dir.path()).unwrap();
        handle.unlock(password).unwrap();
        handle
    }

    fn test_remote() -> RemoteIdentity {
        RemoteIdentity {
            provider: crate::providers::types::Provider::GitHub,
            owner: "owner".into(),
            repo: "baluard-personal".into(),
            origin_url: "https://github.com/owner/baluard-personal.git".into(),
            ssh_url: "git@github.com:owner/baluard-personal.git".into(),
        }
    }

    #[tokio::test]
    async fn arm_refuses_a_locked_handle() {
        let dir = tempfile::tempdir().unwrap();
        let mut handle = open_vault(&dir);
        handle.lock();
        let mock = MockProvider::github();
        let tok = ProviderToken::new("tok", "repo");
        let err = arm(
            dir.path(),
            &handle,
            &test_remote(),
            &mock,
            &tok,
            30,
            "words",
            "letter",
            "Esteban",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("locked"), "got: {err}");
    }

    #[tokio::test]
    async fn arm_status_heartbeat_close_denied_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut handle = open_vault(&dir);
        let mock = MockProvider::github();
        let tok = ProviderToken::new("tok", "repo");
        let remote = test_remote();

        let outcome = arm(
            dir.path(),
            &handle,
            &remote,
            &mock,
            &tok,
            30,
            "four quiet words",
            "Dear Ana, the spare key is yours if I cannot speak.",
            "Esteban",
        )
        .await
        .unwrap();
        assert!(
            mock.seat_log
                .lock()
                .unwrap()
                .iter()
                .any(|l| l == "addkey:owner/baluard-personal"),
            "deploy key push missing from {:?}",
            mock.seat_log
        );

        // The kit opens with the passphrase and carries a real deploy key.
        let body = open_kit(&outcome.kit_armor, "four quiet words").unwrap();
        assert_eq!(body.vault_id, handle.vault_id.to_string());
        assert_eq!(body.repo_ssh_url, remote.ssh_url);
        assert!(
            body.deploy_private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "deploy key pem shape"
        );
        // Wrong passphrase and corruption are indistinguishable.
        assert!(open_kit(&outcome.kit_armor, "wrong words").is_err());

        // Record armed, first heartbeat written, phase Quiet.
        let record = load_record(dir.path(), &outcome.kit_id).unwrap().unwrap();
        assert_eq!(record.state, LegacyState::Armed);
        assert_eq!(record.window_days, 30);
        assert!(load_alive(dir.path(), &outcome.kit_id).unwrap().is_some());
        let st = status(dir.path(), &handle).unwrap().unwrap();
        assert_eq!(st.phase, LegacyPhase::Quiet);
        assert_eq!(st.silence_days, 0);

        // A fresh heartbeat is a no-op.
        assert!(!heartbeat(dir.path(), &handle).unwrap());

        // Denied: forge key removed, blob deleted, Root Key rotated, and
        // the store re-sealed under the NEW root by the rotation hook.
        let old_epoch = handle.unlocked().current_epoch;
        close(
            dir.path(),
            &mut handle,
            &mock,
            &tok,
            CloseReason::Denied,
        )
        .await
        .unwrap();
        assert!(
            mock.seat_log
                .lock()
                .unwrap()
                .iter()
                .any(|l| l == "delkey:owner/baluard-personal")
        );
        let record = load_record(dir.path(), &outcome.kit_id).unwrap().unwrap();
        assert_eq!(record.state, LegacyState::Closed);
        assert_eq!(record.reason, Some(CloseReason::Denied));
        assert!(load_layer(dir.path(), &outcome.kit_id).unwrap().is_none());
        assert_eq!(handle.unlocked().current_epoch, old_epoch + 1);
        let root: [u8; 64] = *handle.unlocked().root().unwrap().as_bytes();
        assert!(load_store(dir.path(), &root).unwrap().is_some());
        let st = status(dir.path(), &handle).unwrap().unwrap();
        assert_eq!(st.phase, LegacyPhase::Closed);

        // Terminal: re-close is idempotent; re-arm mints a fresh kit id.
        close(dir.path(), &mut handle, &mock, &tok, CloseReason::Denied)
            .await
            .unwrap();
        let second = arm(
            dir.path(),
            &handle,
            &remote,
            &mock,
            &tok,
            14,
            "other words",
            "again",
            "Esteban",
        )
        .await
        .unwrap();
        assert_ne!(second.kit_id, outcome.kit_id);
    }

    #[tokio::test]
    async fn arm_rolls_back_when_the_forge_refuses_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut handle = open_vault(&dir);
        let mut mock = MockProvider::github();
        mock.fail_deploy_key = true;
        let tok = ProviderToken::new("tok", "repo");

        let err = arm(
            dir.path(),
            &handle,
            &test_remote(),
            &mock,
            &tok,
            30,
            "words",
            "letter",
            "Esteban",
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("refused the read-only key"),
            "got: {err}"
        );

        // Nothing half-armed survives: no store, no legacy artifacts.
        let root: [u8; 64] = *handle.unlocked().root().unwrap().as_bytes();
        assert!(load_store(dir.path(), &root).unwrap().is_none());
        if dir.path().join("meta/legacy").exists() {
            assert!(
                std::fs::read_dir(dir.path().join("meta/legacy"))
                    .unwrap()
                    .next()
                    .is_none(),
                "legacy artifacts leaked"
            );
        }

        // A retry with a working forge arms normally.
        mock.fail_deploy_key = false;
        let outcome = arm(
            dir.path(),
            &handle,
            &test_remote(),
            &mock,
            &tok,
            30,
            "words",
            "letter",
            "Esteban",
        )
        .await
        .unwrap();
        assert!(!outcome.kit_armor.is_empty());
    }


    fn test_record() -> LegacyRecord {
        LegacyRecord {
            version: 1,
            vault_id: "11111111-1111-1111-1111-111111111111".into(),
            kit_id: "22222222-2222-2222-2222-222222222222".into(),
            state: LegacyState::Armed,
            reason: None,
            seq: 1,
            epoch: 1,
            window_days: 30,
            lk_public_hash: "ab".repeat(32),
            ek_check: "cd".repeat(32),
            layer_hash: "ef".repeat(32),
            deploy_key_fingerprint: "SHA256:abc".into(),
            repo_url_hash: "12".repeat(32),
            signer_device_id: "device-1".into(),
            created_day: 1_000,
            owner_signature: None,
        }
    }

    fn test_body() -> KitBody {
        KitBody {
            format: 1,
            vault_id: "11111111-1111-1111-1111-111111111111".into(),
            kit_id: "22222222-2222-2222-2222-222222222222".into(),
            repo_ssh_url: "git@github.com:ana/baluard-personal.git".into(),
            deploy_private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n".into(),
            ek: "33".repeat(32),
            lk_public: "44".repeat(32),
            owner_name: "Ana".into(),
            created_at: 1_760_000_000,
            window_days: 30,
        }
    }

    const LETTER: &str = "If you are reading this, Ana gave you access to her passwords.\nPassphrase hint: our trip.\nThis opens after 30 days of no use.\n";

    #[test]
    fn kit_armor_round_trip_and_letter_integrity() {
        let armor = seal_kit(LETTER, &test_body(), "correct horse battery staple").unwrap();
        assert!(armor.contains(ARMOR_BEGIN));
        assert!(armor.starts_with(LETTER));
        let opened = open_kit(&armor, "correct horse battery staple").unwrap();
        assert_eq!(opened.kit_id, test_body().kit_id);
        assert_eq!(opened.owner_name, "Ana");
        assert_eq!(opened.window_days, 30);
    }

    #[test]
    fn kit_survives_crlf_and_email_quoting() {
        let armor = seal_kit(LETTER, &test_body(), "pw").unwrap();
        let crlf = armor.replace('\n', "\r\n");
        let quoted = armor
            .lines()
            .map(|l| format!("> {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(open_kit(&crlf, "pw").is_ok());
        assert!(open_kit(&quoted, "pw").is_ok());
    }

    #[test]
    fn wrong_passphrase_and_tampered_letter_are_indistinguishable() {
        let armor = seal_kit(LETTER, &test_body(), "pw").unwrap();
        let wrong = open_kit(&armor, "other").unwrap_err().to_string();
        let mut tampered = armor.clone();
        tampered = tampered.replacen("Ana gave", "Eve gave", 1);
        let edited = open_kit(&tampered, "pw").unwrap_err().to_string();
        assert_eq!(wrong, edited);
        assert!(wrong.contains("wrong passphrase or damaged file"));
    }

    #[test]
    fn record_signature_binds_every_field() {
        let lk = SigningKey::from_bytes(&[7u8; 32]);
        let mut record = test_record();
        sign_record(&mut record, &lk).unwrap();
        let lk_public = lk.verifying_key().to_bytes();
        verify_record(&record, &lk_public).unwrap();

        let mut forged = record.clone();
        forged.window_days = 0;
        assert!(verify_record(&forged, &lk_public).is_err());

        let (other, _) = signature::generate_ed25519_keypair();
        let mut resigned = record.clone();
        resign_record_with(&mut resigned, &other);
        assert!(verify_record(&resigned, &lk_public).is_err());
    }

    // Test-only re-sign through the public surface with a foreign key.
    fn resign_record_with(record: &mut LegacyRecord, lk: &SigningKey) {
        sign_record(record, lk).unwrap();
    }

    #[test]
    fn alive_binds_kit_and_refuses_rollback() {
        let lk = SigningKey::from_bytes(&[9u8; 32]);
        let mut record = test_record();
        sign_record(&mut record, &lk).unwrap();
        let lk_public = lk.verifying_key().to_bytes();

        let mut alive = AliveRecord {
            version: 1,
            vault_id: record.vault_id.clone(),
            kit_id: record.kit_id.clone(),
            seq: 1,
            day: 20_000,
            owner_signature: None,
        };
        sign_alive(&mut alive, &lk).unwrap();
        let alive_json = serde_json::to_string(&alive).unwrap();
        assert_eq!(verify_alive(&alive_json, &record, &lk_public).unwrap(), 20_000);

        let mut other_kit = AliveRecord {
            kit_id: "other".into(),
            ..alive.clone()
        };
        sign_alive(&mut other_kit, &lk).unwrap();
        let bad = serde_json::to_string(&other_kit).unwrap();
        assert!(verify_alive(&bad, &record, &lk_public).is_err());
    }

    #[test]
    fn ek_check_binds_record_to_kit_key() {
        let ek1 = [1u8; 32];
        let ek2 = [2u8; 32];
        assert_ne!(ek_check(&ek1, "kit").unwrap(), ek_check(&ek2, "kit").unwrap());
        assert_eq!(ek_check(&ek1, "kit").unwrap(), ek_check(&ek1, "kit").unwrap());
    }

    #[test]
    fn layer_blob_round_trip_and_cross_epoch_refusal() {
        let ek = [5u8; 32];
        let root = [0xAau8; 64];
        let packed = seal_layer(&ek, &root, "vault-1", "kit-1", 3).unwrap();
        let opened = open_layer(&ek, &packed, "vault-1", "kit-1", 3).unwrap();
        assert_eq!(*opened, root);
        assert!(open_layer(&ek, &packed, "vault-1", "kit-1", 4).is_err());
        assert!(open_layer(&ek, &packed, "vault-2", "kit-1", 3).is_err());
        let other = [6u8; 32];
        assert!(open_layer(&other, &packed, "vault-1", "kit-1", 3).is_err());
    }

    #[test]
    fn phase_counts_silence_from_the_window() {
        let mut record = test_record();
        sign_record(&mut record, &SigningKey::from_bytes(&[7u8; 32])).unwrap();

        record.window_days = 30;
        assert_eq!(
            derive_phase(&record, Some(1_000), 1_010),
            LegacyPhase::Quiet
        );
        assert_eq!(
            derive_phase(&record, Some(1_000), 1_030),
            LegacyPhase::Open
        );
        // No signal at all: the silence counts from the arm day (1_000).
        assert_eq!(derive_phase(&record, None, 1_029), LegacyPhase::Quiet);
        assert_eq!(derive_phase(&record, None, 1_030), LegacyPhase::Open);

        record.state = LegacyState::Closed;
        record.reason = Some(CloseReason::Denied);
        assert_eq!(derive_phase(&record, Some(1_000), 9_999), LegacyPhase::Closed);
    }
}
