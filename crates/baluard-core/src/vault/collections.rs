//! Collections — the org-granularity data layer (plan-sharing §4.2/§4.6, S3).
//!
//! A collection is a named group inside a shared vault that members are
//! granted access to: `meta/collections/<id>.json` carries the plaintext
//! grants (`{member, access, expires_at?}` — plan rule: "plaintext = UUIDs +
//! display names + trust") plus the collection's real name encrypted under a
//! random per-collection content key, so a non-grantee sees an opaque id
//! while grantees see real names. The content key is wrapped under an
//! SGK-derived wrap key (plan: "collection key — random; wrapped under
//! SGK"), which is why rotation re-seals every collection file.
//!
//! This slice is the data + key layer only: entries stay at their personal
//! paths (`ciphers/<uuid>.enc`); collection-scoped paths and the
//! policy-table binding are the follow-up slice (the P5 remainder).
//!
//! Per-member identity wraps (`meta/collections/<c>/<m>.wrap`) arrive with
//! the Team-shape key separation (P1 Space parts); today every member holds
//! the Root Key, so the SGK wrap reaches everyone and the enforcement
//! surface is the route layer's admin gate.

use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::SpaceGroupKey;
use crate::secret_file::{open_secret_blob, seal_secret_blob};
use crate::vault::members;
use crate::vault::write_vault_file;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A decrypted collection content key keyed by its collection id — the
/// payload the rotation paths carry across the Root Key swap.
pub type CollectedKeys = Vec<(Uuid, Zeroizing<[u8; 32]>)>;

/// Cap on live collections per vault (org-shape sanity ceiling).
pub const MAX_COLLECTIONS: usize = 256;
/// Cap on grants per collection.
pub const MAX_GRANTS: usize = 256;
/// Cap on a collection display name (chars).
pub const MAX_NAME_CHARS: usize = 200;
/// Cap on one collection file on read (git-tracked files can arrive large).
pub const MAX_COLLECTION_FILE_BYTES: usize = 256 * 1024;

const FORMAT: u32 = 1;
/// HKDF info prefix for the SGK-derived key that wraps each collection key.
const CK_WRAP_INFO: &[u8] = b"baluard-ck-wrap-v1";
const KEY_PURPOSE: &str = "collection-key-v1";
const NAME_PURPOSE: &str = "collection-name-v1";

/// A member's access level on a collection. `manage` is delegated
/// administration (§4.7 ladder): the holder can grant and revoke other
/// members on that one collection without being an admin. Manage is
/// mintable to Editor+ only — a Viewer can never author a cipher or
/// meta commit, so manage access would wedge their sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionAccess {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "manage")]
    Manage,
}

/// One grant row. `expires_at` (unix seconds): the admin client executes
/// expiry at unlock (drop grant + rotate the collection key); pending and
/// expired grants surface on the notices screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionGrant {
    pub member_id: Uuid,
    pub access: CollectionAccess,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// The per-collection file. Grants are plaintext per plan; `ck_wrapped` and
/// `name_enc` are sealed-blob documents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionFile {
    pub format: u32,
    pub id: Uuid,
    pub created_at: u64,
    /// The collection content key, wrapped under the SGK-derived wrap key.
    pub ck_wrapped: serde_json::Value,
    /// The collection's display name, sealed under the CK.
    pub name_enc: serde_json::Value,
    pub grants: Vec<CollectionGrant>,
    /// Hex salt for the collection's opaque cipher directory name
    /// (plan P5: ciphers/<dir>/<uuid>.enc with a salted-hash dir so the
    /// git host sees neither the collection id nor cross-vault links).
    /// Absent on pre-S3-2 collections: their ciphers stay at the
    /// personal flat path until re-saved.
    #[serde(default)]
    pub dir_salt: Option<String>,
}

/// The opaque directory name for a collection's ciphers, or None for a
/// legacy (salt-less) collection. Deterministic given the salt so every
/// device derives the same path.
pub fn collection_dir(file: &CollectionFile) -> Option<String> {
    use sha2::{Digest, Sha256};
    let salt = file.dir_salt.as_deref()?;
    if salt.is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(file.id.to_string().as_bytes());
    Some(hex_encode(&h.finalize()[..16]))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Dir-name -> collection id map for every salted collection on disk.
/// Malformed rows are skipped inert (member-directory precedent); a
/// missing or damaged name does not matter here because only the
/// plaintext fields are read.
pub fn load_dir_map(vault_path: &Path) -> Vec<(String, Uuid)> {
    let dir = collections_dir(vault_path);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut map = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > MAX_COLLECTION_FILE_BYTES {
            continue;
        }
        let Ok(file) = serde_json::from_slice::<CollectionFile>(&bytes) else {
            continue;
        };
        if file.format != FORMAT {
            continue;
        }
        if path.file_stem().and_then(|x| x.to_str()) != Some(file.id.to_string().as_str()) {
            continue;
        }
        if let Some(d) = collection_dir(&file) {
            map.push((d, file.id));
        }
    }
    map
}

/// One row of the member-side listing (4.8): the caller's own grant,
/// with the name decrypted through their grant wrap. No SGK needed.
#[derive(Debug, Clone)]
pub struct MemberCollectionRow {
    pub collection_id: Uuid,
    pub name: String,
    pub access: CollectionAccess,
    pub expires_at: Option<u64>,
}

/// List the collections a member can actually open: walk the dir map,
/// parse each file (malformed rows skip inert, matching the admin walk),
/// keep the member's own LIVE grant, and decrypt the name through the
/// per-member grant wrap. A member with no wrap for a granted row
/// (revoked-race or pre-wrap legacy) skips inert — sync converges it.
pub fn list_member_collections(
    vault_path: &Path,
    member_id: &Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Vec<MemberCollectionRow> {
    let mut rows = Vec::new();
    let now = now_secs_pub();
    for (dir, id) in load_dir_map(vault_path) {
        let _ = dir;
        let Ok(bytes) = std::fs::read(collections_file_path(vault_path, &id)) else {
            continue;
        };
        let Ok(file) = serde_json::from_slice::<CollectionFile>(&bytes) else {
            continue;
        };
        let Some(grant) = file
            .grants
            .iter()
            .find(|g| g.member_id == *member_id && !is_grant_expired(g, now))
        else {
            continue;
        };
        let Ok(ck) = open_grant_wrap(vault_path, &id, member_id, wrapping_secret) else {
            continue;
        };
        let Ok(name_bytes) = open_secret_blob(
            &ck,
            match json_bytes(&file.name_enc) {
                Ok(b) => b,
                Err(_) => continue,
            }
            .as_slice(),
            &format!("{NAME_PURPOSE}/{}", file.id),
        ) else {
            continue;
        };
        let Ok(name) = String::from_utf8(name_bytes) else {
            continue;
        };
        rows.push(MemberCollectionRow {
            collection_id: id,
            name,
            access: grant.access,
            expires_at: grant.expires_at,
        });
    }
    rows.sort_by_key(|r| r.name.to_lowercase());
    rows
}

/// The relative path for a cipher: collection-scoped when the collection
/// is salted, personal flat otherwise (plan P5).
pub fn cipher_rel_path(file: Option<&CollectionFile>, cipher_id: Uuid) -> String {
    match file.and_then(collection_dir) {
        Some(d) => format!("ciphers/{d}/{cipher_id}.enc"),
        None => format!("ciphers/{cipher_id}.enc"),
    }
}

/// Public clock for sibling modules (the local-write expiry checks).
/// Verification stays clock-free by design; this clock gates only
/// locally-authored writes.
pub fn now_secs_pub() -> u64 {
    now_secs()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// serde_json errors map to the vault Metadata error class.
fn json_bytes(v: &serde_json::Value) -> Result<Vec<u8>, BaluardError> {
    serde_json::to_vec(v)
        .map_err(|e| VaultError::Metadata(format!("collection serialize: {e}")).into())
}

fn collections_dir(vault_path: &Path) -> PathBuf {
    vault_path.join("meta/collections")
}

/// SGK-derived wrap key for collection content keys. Epoch-bound, so a Root
/// Key rotation invalidates every wrap and the rotation paths re-seal.
fn ck_wrap_key(sgk: &SpaceGroupKey) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut info = Vec::with_capacity(CK_WRAP_INFO.len() + 8);
    info.extend_from_slice(CK_WRAP_INFO);
    info.extend_from_slice(&sgk.epoch().to_le_bytes());
    let hkdf = Hkdf::<Sha256>::new(None, sgk.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32 bytes is valid output length for HKDF-SHA256");
    key
}

fn validate_name(name: &str) -> Result<(), BaluardError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidOperation("Give the collection a name.".into()).into());
    }
    if trimmed.chars().count() > MAX_NAME_CHARS {
        return Err(VaultError::InvalidOperation(format!(
            "Collection names are limited to {MAX_NAME_CHARS} characters."
        ))
        .into());
    }
    if trimmed.chars().any(|c| c == '\n' || c == '\r') {
        return Err(VaultError::InvalidOperation(
            "Collection names cannot contain line breaks.".into(),
        )
        .into());
    }
    Ok(())
}

/// Mint a collection: random CK, SGK-wrapped, name sealed under the CK.
pub fn create_collection(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    name: &str,
) -> Result<CollectionFile, BaluardError> {
    validate_name(name)?;
    let dir = collections_dir(vault_path);
    if count_json_files(&dir)? >= MAX_COLLECTIONS {
        return Err(VaultError::InvalidOperation(
            "This vault has reached its collection limit.".into(),
        )
        .into());
    }
    let id = Uuid::new_v4();
    let mut ck = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(ck.as_mut());
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let ck_wrapped = wrap_ck(sgk, &ck, &id)?;
    let name_enc = seal_name(&ck, &id, name.trim())?;
    let file = CollectionFile {
        format: FORMAT,
        id,
        created_at: now_secs(),
        ck_wrapped,
        name_enc,
        grants: Vec::new(),
        dir_salt: Some(hex_encode(&salt)),
    };
    std::fs::create_dir_all(&dir)?;
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| VaultError::Metadata(format!("collection serialize: {e}")))?;
    write_vault_file(&collections_file_path(vault_path, &id), &bytes)?;
    Ok(file)
}

pub(crate) fn collections_file_path(vault_path: &Path, id: &Uuid) -> PathBuf {
    vault_path.join(format!("meta/collections/{id}.json"))
}

fn count_json_files(dir: &Path) -> Result<usize, BaluardError> {
    if !dir.is_dir() {
        return Ok(0);
    }
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .count())
}

fn wrap_ck(
    sgk: &SpaceGroupKey,
    ck: &[u8; 32],
    id: &Uuid,
) -> Result<serde_json::Value, BaluardError> {
    let wrap_key = ck_wrap_key(sgk);
    let sealed = seal_secret_blob(&wrap_key, ck, &format!("{KEY_PURPOSE}/{id}"))?;
    Ok(serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("collection seal: {e}")))?)
}

fn seal_name(ck: &[u8; 32], id: &Uuid, name: &str) -> Result<serde_json::Value, BaluardError> {
    let sealed = seal_secret_blob(ck, name.as_bytes(), &format!("{NAME_PURPOSE}/{id}"))?;
    Ok(serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("collection seal: {e}")))?)
}

/// Decrypt a collection's name with the SGK-derived wrap key. Fails closed
/// on a foreign wrap (wrong vault/epoch) or a tampered name.
fn decrypt_name(file: &CollectionFile, sgk: &SpaceGroupKey) -> Result<String, BaluardError> {
    let wrap_key = ck_wrap_key(sgk);
    let wrapped_bytes = json_bytes(&file.ck_wrapped)?;
    let ck_raw = open_secret_blob(
        &wrap_key,
        &wrapped_bytes,
        &format!("{KEY_PURPOSE}/{}", file.id),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection's key cannot be read.".into()))?;
    let ck: [u8; 32] = ck_raw.try_into().map_err(|_| {
        VaultError::InvalidOperation("That collection's key has the wrong length.".into())
    })?;
    let ck = Zeroizing::new(ck);
    let name_bytes = open_secret_blob(
        &ck,
        json_bytes(&file.name_enc)?.as_slice(),
        &format!("{NAME_PURPOSE}/{}", file.id),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection's name cannot be read.".into()))?;
    String::from_utf8(name_bytes).map_err(|_| {
        VaultError::InvalidOperation("That collection's name is corrupt.".into()).into()
    })
}

fn check_format(file: &CollectionFile) -> Result<(), BaluardError> {
    if file.format != FORMAT {
        return Err(VaultError::InvalidOperation("Unsupported collection format.".into()).into());
    }
    Ok(())
}

/// Open one collection and decrypt its name. Fails closed on damage.
pub fn open_collection(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    id: &Uuid,
) -> Result<(CollectionFile, String), BaluardError> {
    let path = collections_file_path(vault_path, id);
    let bytes = std::fs::read(&path)
        .map_err(|_| VaultError::InvalidOperation("That collection no longer exists.".into()))?;
    if bytes.len() > MAX_COLLECTION_FILE_BYTES {
        return Err(VaultError::InvalidOperation(
            "That collection file is too large to open.".into(),
        )
        .into());
    }
    let file: CollectionFile = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidOperation("That collection file is damaged.".into()))?;
    check_format(&file)?;
    let name = decrypt_name(&file, sgk)?;
    Ok((file, name))
}

/// Walk `meta/collections/` and decrypt every well-formed row; malformed
/// rows are skipped inert (the member-directory discipline).
pub fn list_collections(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
) -> Result<Vec<(CollectionFile, String)>, BaluardError> {
    let dir = collections_dir(vault_path);
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > MAX_COLLECTION_FILE_BYTES {
            continue;
        }
        let Ok(file) = serde_json::from_slice::<CollectionFile>(&bytes) else {
            continue;
        };
        if file.format != FORMAT {
            continue;
        }
        if path.file_stem().and_then(|x| x.to_str()) != Some(file.id.to_string().as_str()) {
            continue;
        }
        if let Ok(name) = decrypt_name(&file, sgk) {
            out.push((file, name));
        }
    }
    out.sort_by_key(|a| a.1.to_lowercase());
    Ok(out)
}

/// Persist grant/shape changes. The caller holds the decrypted name for
/// rename (which re-seals).
pub fn save_collection(vault_path: &Path, file: &CollectionFile) -> Result<(), BaluardError> {
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| VaultError::Metadata(format!("collection serialize: {e}")))?;
    write_vault_file(&collections_file_path(vault_path, &file.id), &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("collection write: {e}"))))
}

/// Rename: re-seal the name under the CK (same key, new plaintext).
pub fn rename_collection(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    id: &Uuid,
    name: &str,
) -> Result<CollectionFile, BaluardError> {
    validate_name(name)?;
    let (mut file, _) = open_collection(vault_path, sgk, id)?;
    let ck = unwrap_ck(&file, sgk)?;
    file.name_enc = seal_name(&ck, id, name.trim())?;
    save_collection(vault_path, &file)?;
    Ok(file)
}

pub(crate) fn unwrap_ck(
    file: &CollectionFile,
    sgk: &SpaceGroupKey,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let wrap_key = ck_wrap_key(sgk);
    let wrapped_bytes = json_bytes(&file.ck_wrapped)?;
    let ck_raw = open_secret_blob(
        &wrap_key,
        &wrapped_bytes,
        &format!("{KEY_PURPOSE}/{}", file.id),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection's key cannot be read.".into()))?;
    let ck: [u8; 32] = ck_raw.try_into().map_err(|_| {
        VaultError::InvalidOperation("That collection's key has the wrong length.".into())
    })?;
    Ok(Zeroizing::new(ck))
}

/// A grant target must exist and be live (no `removed` / `reset` tombstone).
fn live_member(vault_path: &Path, member_id: &Uuid) -> Result<members::MemberFile, BaluardError> {
    let member = members::member_file_by_id(vault_path, *member_id).ok_or_else(|| {
        VaultError::InvalidOperation("That person is not a member of this vault.".into())
    })?;
    if member.removed.is_some() || member.reset.is_some() {
        return Err(VaultError::InvalidOperation(
            "That person is no longer an active member.".into(),
        )
        .into());
    }
    Ok(member)
}

/// P1 (Space parts): per-member CK wraps at `meta/collections/<c>/<m>.wrap`
/// — the collection key HPKE-wrapped to the granted member's identity
/// wrap pubkey. Today every member also holds SGK, so these wraps are
/// additive groundwork: the Team-shape flip (non-admins stop receiving
/// SGK) consumes them as the only path to their granted collections.
const GRANT_WRAP_FORMAT: u32 = 1;

/// The HPKE context binds the wrap to its collection AND member, so a
/// wrap transplanted into another collection's directory (or another
/// member's filename) fails the AEAD tag instead of yielding a foreign
/// key (the outbox-entry AAD discipline).
fn grant_wrap_context(id: &Uuid, member_id: &Uuid) -> String {
    format!("collection-grant-v1/{id}/{member_id}")
}

fn grant_wraps_dir(vault_path: &Path, id: &Uuid) -> PathBuf {
    vault_path.join("meta/collections").join(id.to_string())
}

pub(crate) fn grant_wrap_path(vault_path: &Path, id: &Uuid, member_id: &Uuid) -> PathBuf {
    grant_wraps_dir(vault_path, id).join(format!("{member_id}.wrap"))
}

pub(crate) fn wrap_pubkey_bytes(wrap_pub_hex: &str) -> Result<[u8; 32], BaluardError> {
    hex::decode(wrap_pub_hex.trim())
        .map_err(|_| {
            VaultError::InvalidOperation("That contact card's share key is invalid.".into())
        })?
        .try_into()
        .map_err(|_| {
            VaultError::InvalidOperation("That contact card's share key is invalid.".into()).into()
        })
}

fn write_grant_wrap(
    vault_path: &Path,
    id: &Uuid,
    member_id: &Uuid,
    wrap_pub_hex: &str,
    ck: &[u8; 32],
) -> Result<(), BaluardError> {
    let recip = x25519_dalek::PublicKey::from(wrap_pubkey_bytes(wrap_pub_hex)?);
    let (eph, ct, tag) =
        crate::crypto::hpke_wrap::wrap_key(ck, &recip, &grant_wrap_context(id, member_id))?;
    let doc = serde_json::json!({
        "format": GRANT_WRAP_FORMAT,
        "ephemeral_public": hex::encode(eph),
        "encrypted_key": hex::encode(ct),
        "tag": hex::encode(tag),
    });
    write_vault_file(
        &grant_wrap_path(vault_path, id, member_id),
        serde_json::to_string_pretty(&doc)
            .map_err(|e| VaultError::Metadata(format!("grant wrap serialize: {e}")))?
            .as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write grant wrap: {e}"))))
}

/// Open one per-member wrap with the member's own X25519 wrapping
/// secret. Fails closed on a missing/tampered/foreign wrap.
pub fn open_grant_wrap(
    vault_path: &Path,
    id: &Uuid,
    member_id: &Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let bytes = std::fs::read(grant_wrap_path(vault_path, id, member_id)).map_err(|_| {
        VaultError::InvalidOperation("That collection key wrap does not exist.".into())
    })?;
    if bytes.len() > MAX_COLLECTION_FILE_BYTES {
        return Err(VaultError::InvalidOperation(
            "That collection key wrap is too large to open.".into(),
        )
        .into());
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidOperation("That collection key wrap is damaged.".into()))?;
    if doc["format"].as_u64() != Some(GRANT_WRAP_FORMAT as u64) {
        return Err(VaultError::InvalidOperation("Unsupported wrap format.".into()).into());
    }
    let hex_field = |k: &str| -> Result<String, BaluardError> {
        doc[k].as_str().map(|s| s.to_string()).ok_or_else(|| {
            BaluardError::from(VaultError::InvalidOperation(
                "That collection key wrap is damaged.".into(),
            ))
        })
    };
    let eph = hex::decode(hex_field("ephemeral_public")?)
        .map_err(|_| VaultError::InvalidOperation("That collection key wrap is damaged.".into()))?;
    let ct = hex::decode(hex_field("encrypted_key")?)
        .map_err(|_| VaultError::InvalidOperation("That collection key wrap is damaged.".into()))?;
    let tag: [u8; 16] = hex::decode(hex_field("tag")?)
        .map_err(|_| VaultError::InvalidOperation("That collection key wrap is damaged.".into()))?
        .try_into()
        .map_err(|_| VaultError::InvalidOperation("That collection key wrap is damaged.".into()))?;
    let pt = crate::crypto::hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        wrapping_secret,
        &grant_wrap_context(id, member_id),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection key wrap cannot be read.".into()))?;
    let ck: [u8; 32] = pt.try_into().map_err(|_| {
        VaultError::InvalidOperation("That collection key has the wrong length.".into())
    })?;
    Ok(Zeroizing::new(ck))
}

fn remove_grant_wrap(vault_path: &Path, id: &Uuid, member_id: &Uuid) -> Result<(), BaluardError> {
    match std::fs::remove_file(grant_wrap_path(vault_path, id, member_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BaluardError::from(VaultError::Metadata(format!(
            "remove collection key wrap: {e}"
        )))),
    }
}

/// True when the member holds at least one per-member wrap on disk.
pub(crate) fn has_grant_wraps(vault_path: &Path, member_id: &Uuid) -> bool {
    std::fs::read_dir(vault_path.join("meta/collections"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.path()
                .file_stem()
                .and_then(|s| s.to_str().map(String::from))
        })
        .filter_map(|stem| Uuid::parse_str(&stem).ok())
        .any(|id| grant_wrap_path(vault_path, &id, member_id).exists())
}

/// Re-write every per-member wrap of one collection under `new_ck`.
/// The wrap survives only when ALL of these hold: the member id is in
/// the collection's LIVE grant list (not expired), the member row is
/// live (no removed/reset tombstone), and the row carries a wrap
/// pubkey. Anything else loses its wrap file — a stale wrap must never
/// keep working past its grant or its membership (a repo-writable
/// leftover or a revoked-before-rotation member would otherwise be
/// handed the NEW collection key). Returns the wraps re-written.
pub fn rewrap_grant_wraps(
    vault_path: &Path,
    id: &Uuid,
    new_ck: &[u8; 32],
    grants: &[CollectionGrant],
) -> Result<usize, BaluardError> {
    let dir = grant_wraps_dir(vault_path, id);
    let mut done = 0;
    for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wrap") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(member_id) = Uuid::parse_str(stem) else {
            continue;
        };
        let granted = grants
            .iter()
            .any(|g| g.member_id == member_id && !is_grant_expired(g, now_secs()));
        let wrap_pub = if granted {
            members::member_file_by_id(vault_path, member_id)
                .filter(|row| row.removed.is_none() && row.reset.is_none())
                .and_then(|row| row.identity_wrap_pubkey)
                .filter(|w| !w.is_empty())
        } else {
            None
        };
        match wrap_pub {
            Some(wrap_pub) => {
                write_grant_wrap(vault_path, id, &member_id, &wrap_pub, new_ck)?;
                done += 1;
            }
            // Ungated, expired, tombstoned, gone, or legacy: the stale
            // wrap must die.
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(done)
}

/// P1: identity-rotation self-heal. Re-wraps the rotating member's own
/// grant wraps from the old wrap secret to the new pubkey — self-service,
/// no admin round-trip, and the old wraps die with the rotation.
pub fn rewrap_own_grant_wraps(
    vault_path: &Path,
    member_id: &Uuid,
    old_secret: &x25519_dalek::StaticSecret,
    new_wrap_pub_hex: &str,
) -> Result<usize, BaluardError> {
    // Two-phase: unwrap EVERYTHING first, write only after every unwrap
    // succeeded. A hostile/corrupt wrap aborts the rotation before any
    // wrap file changed hands; combined with the identity-swap reorder,
    // an abort here leaves zero state change.
    let mut collected: Vec<(Uuid, Zeroizing<[u8; 32]>)> = Vec::new();
    for entry in std::fs::read_dir(vault_path.join("meta/collections"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(stem) else {
            continue;
        };
        if !grant_wrap_path(vault_path, &id, member_id).exists() {
            continue;
        }
        let ck = open_grant_wrap(vault_path, &id, member_id, old_secret)?;
        collected.push((id, ck));
    }
    for (id, ck) in &collected {
        write_grant_wrap(vault_path, id, member_id, new_wrap_pub_hex, ck)?;
    }
    Ok(collected.len())
}

/// Add or update a grant. Refuses tombstoned members and cap overflow.
pub fn upsert_grant(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    collection_id: &Uuid,
    grant: CollectionGrant,
) -> Result<CollectionFile, BaluardError> {
    let (mut file, _) = open_collection(vault_path, sgk, collection_id)?;
    let member = live_member(vault_path, &grant.member_id)?;
    // Path-membership rule (S3-2): a Viewer can never author a cipher
    // or meta commit (Editor floor in the git policy), so a write or
    // manage grant to a Viewer would pass locally and wedge their sync
    // at verification.
    if matches!(
        grant.access,
        CollectionAccess::Write | CollectionAccess::Manage
    ) && member.role == crate::vault::members::MemberRole::Viewer
    {
        return Err(VaultError::InvalidOperation(
            "Viewers cannot be given write or manage access to a collection.".into(),
        )
        .into());
    }
    if is_grant_expired(&grant, now_secs()) {
        return Err(VaultError::InvalidOperation(
            "That expiry date is already in the past.".into(),
        )
        .into());
    }
    let grant_member_id = grant.member_id;
    if let Some(slot) = file
        .grants
        .iter_mut()
        .find(|g| g.member_id == grant.member_id)
    {
        *slot = grant;
    } else {
        if file.grants.len() >= MAX_GRANTS {
            return Err(VaultError::InvalidOperation(
                "This collection has reached its member limit.".into(),
            )
            .into());
        }
        file.grants.push(grant);
    }
    save_collection(vault_path, &file)?;
    // P1: mint the per-member CK wrap when the member record carries an
    // identity wrap pubkey (legacy rows stay SGK-covered until the
    // Team-shape flip).
    if let Some(wrap_pub) = member
        .identity_wrap_pubkey
        .as_deref()
        .filter(|w| !w.is_empty())
    {
        let ck = unwrap_ck(&file, sgk)?;
        write_grant_wrap(vault_path, collection_id, &grant_member_id, wrap_pub, &ck)?;
    }
    Ok(file)
}

/// Remove one member's grant. Unknown grants are a refusal (the caller
/// should know; idempotency is the route layer's call).
pub fn revoke_grant(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    collection_id: &Uuid,
    member_id: &Uuid,
) -> Result<CollectionFile, BaluardError> {
    let (mut file, _) = open_collection(vault_path, sgk, collection_id)?;
    let before = file.grants.len();
    file.grants.retain(|g| g.member_id != *member_id);
    if file.grants.len() == before {
        return Err(VaultError::InvalidOperation(
            "That person has no access to this collection.".into(),
        )
        .into());
    }
    save_collection(vault_path, &file)?;
    remove_grant_wrap(vault_path, collection_id, member_id)?;
    Ok(file)
}

/// Delete a collection: file gone. Entries stay (path binding is a later
/// slice); grants die with the file.
/// A grant is expired once `expires_at` (unix seconds) has passed.
/// Enforcement is admin-side: this wave deliberately does NOT make commit
/// verification clock-dependent (an expired-between-authoring-and-verify
/// grant would refuse commits on every peer and wedge the vault); the
/// admin's client executes the rotation on next sync instead (plan line
/// 153), so expired-but-unenforced grants converge on pull.
pub fn is_grant_expired(grant: &CollectionGrant, now: u64) -> bool {
    // 0 is the IPC convention for "no expiry" — never an expiry.
    grant.expires_at.is_some_and(|e| e != 0 && e <= now)
}

/// Admin sweep (plan line 153): drop grants whose `expires_at` has
/// passed, and rotate the collection key for any collection whose
/// grants changed. Runs on the admin client after unlock's pull; other
/// members converge on pull. Returns one row per removed grant.
pub fn sweep_expired_grants(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
) -> Result<Vec<ExpiredGrant>, BaluardError> {
    let mut removed = Vec::new();
    let now = now_secs();
    for (file, name) in list_collections(vault_path, sgk)? {
        let expired: Vec<Uuid> = file
            .grants
            .iter()
            .filter(|g| is_grant_expired(g, now))
            .map(|g| g.member_id)
            .collect();
        if expired.is_empty() {
            continue;
        }
        // One atomic save: drop the expired grants AND rotate the key
        // (the departing grantee's derived item keys must stop matching
        // anything minted later; knowledge of what they already read is
        // the accepted eventual-revocation boundary).
        let mut updated = file;
        updated.grants.retain(|g| !is_grant_expired(g, now));
        let mut new_ck = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(new_ck.as_mut());
        updated.ck_wrapped = wrap_ck(sgk, &new_ck, &updated.id)?;
        updated.name_enc = seal_name(&new_ck, &updated.id, &name)?;
        save_collection(vault_path, &updated)?;
        let collection_id = updated.id;
        for member_id in &expired {
            // The expired grantee must not keep a wrap to the NEW key.
            remove_grant_wrap(vault_path, &collection_id, member_id)?;
            removed.push(ExpiredGrant {
                collection_id,
                member_id: *member_id,
            });
        }
        rewrap_grant_wraps(vault_path, &collection_id, &new_ck, &updated.grants)?;
    }
    Ok(removed)
}

/// One removed grant from the expiry sweep.
#[derive(Debug, Clone, Serialize)]
pub struct ExpiredGrant {
    pub collection_id: Uuid,
    pub member_id: Uuid,
}

pub fn delete_collection(vault_path: &Path, id: &Uuid) -> Result<(), BaluardError> {
    let path = collections_file_path(vault_path, id);
    std::fs::remove_file(&path)
        .map_err(|_| VaultError::InvalidOperation("That collection no longer exists.".into()))?;
    let _ = std::fs::remove_dir_all(grant_wraps_dir(vault_path, id));
    Ok(())
}

/// Rotation coverage, pre-swap half: decrypt every collection's CK with the
/// outgoing SGK so the plaintext keys can cross the Root Key swap.
pub fn collect_content_keys(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
) -> Result<CollectedKeys, BaluardError> {
    let mut cks = Vec::new();
    for (file, _) in list_collections(vault_path, sgk)? {
        cks.push((file.id, unwrap_ck(&file, sgk)?));
    }
    Ok(cks)
}

/// Rotation coverage, post-swap half: re-seal the collected plaintext CKs
/// under the new SGK epoch. Called from both `rotate_root_key` and
/// `revoke_device_and_rekey` after the swap. Failures propagate (P4 rule).
pub fn rewrap_from_plaintexts(
    vault_path: &Path,
    new_sgk: &SpaceGroupKey,
    cks: &CollectedKeys,
) -> Result<usize, BaluardError> {
    let mut done = 0;
    for (id, ck) in cks {
        let mut file: CollectionFile = serde_json::from_slice(
            &std::fs::read(collections_file_path(vault_path, id)).map_err(|_| {
                VaultError::InvalidOperation("That collection no longer exists.".into())
            })?,
        )
        .map_err(|_| VaultError::InvalidOperation("That collection file is damaged.".into()))?;
        file.ck_wrapped = wrap_ck(new_sgk, ck, id)?;
        save_collection(vault_path, &file)?;
        rewrap_grant_wraps(vault_path, id, ck, &file.grants)?;
        done += 1;
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::hierarchy::SpaceGroupKey;
    use std::path::PathBuf;

    fn temp_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    fn live_member_row(id: Uuid) -> crate::vault::members::MemberFile {
        crate::vault::members::MemberFile {
            id,
            display_name: "Alicia".into(),
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Verified,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        }
    }

    fn plain_collection(id: Uuid) -> CollectionFile {
        CollectionFile {
            format: FORMAT,
            id,
            created_at: 0,
            ck_wrapped: serde_json::Value::Null,
            name_enc: serde_json::Value::Null,
            grants: Vec::new(),
            dir_salt: None,
        }
    }

    #[test]
    fn collection_dir_deterministic_and_legacy_flat() {
        let mut file = plain_collection(Uuid::new_v4());
        file.dir_salt = Some("aabbccdd00112233aabbccdd00112233".into());
        let d1 = collection_dir(&file).unwrap();
        let d2 = collection_dir(&file).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
        // A different salt yields a different (uncorrelatable) dir.
        file.dir_salt = Some("ffffffffffffffffffffffffffffffff".into());
        assert_ne!(collection_dir(&file).unwrap(), d1);
        // Legacy (no salt / empty salt) collections stay at flat paths.
        file.dir_salt = None;
        assert!(collection_dir(&file).is_none());
        file.dir_salt = Some(String::new());
        assert!(collection_dir(&file).is_none());
        assert_eq!(
            cipher_rel_path(Some(&file), file.id),
            format!("ciphers/{}.enc", file.id)
        );
    }

    #[test]
    fn create_list_roundtrip() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        create_collection(&path, &sgk, "Servers").unwrap();
        create_collection(&path, &sgk, "Finance").unwrap();
        let rows = list_collections(&path, &sgk).unwrap();
        let names: Vec<&str> = rows.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, vec!["Finance", "Servers"]);
    }

    #[test]
    fn rename_reflects() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        rename_collection(&path, &sgk, &file.id, " Infra ").unwrap();
        let rows = list_collections(&path, &sgk).unwrap();
        assert_eq!(rows[0].1, "Infra");
    }

    #[test]
    fn grant_revoke_roundtrip() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member = Uuid::new_v4();
        std::fs::create_dir_all(path.join("meta/members")).unwrap();
        members::write_member(&path, &live_member_row(member)).unwrap();
        upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: member,
                access: CollectionAccess::Read,
                expires_at: None,
            },
        )
        .unwrap();
        // Update in place.
        let updated = upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: member,
                access: CollectionAccess::Write,
                expires_at: Some(2_000_000_000),
            },
        )
        .unwrap();
        assert_eq!(updated.grants.len(), 1);
        assert_eq!(updated.grants[0].access, CollectionAccess::Write);
        let (_, name) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(name, "Servers");
        revoke_grant(&path, &sgk, &file.id, &member).unwrap();
        let (_, name) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(name, "Servers");
        let err = revoke_grant(&path, &sgk, &file.id, &member).unwrap_err();
        assert!(err.to_string().contains("no access"));
    }

    #[test]
    fn manage_grant_roundtrip_and_viewer_mint_refused() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        // S3-5: an Editor can hold delegated manage; update in place and
        // revoke all work through the normal grant machinery.
        let editor = Uuid::new_v4();
        std::fs::create_dir_all(path.join("meta/members")).unwrap();
        members::write_member(&path, &live_member_row(editor)).unwrap();
        let granted = upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: editor,
                access: CollectionAccess::Manage,
                expires_at: Some(2_000_000_000),
            },
        )
        .unwrap();
        assert_eq!(granted.grants[0].access, CollectionAccess::Manage);
        let updated = upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: editor,
                access: CollectionAccess::Manage,
                expires_at: None,
            },
        )
        .unwrap();
        assert_eq!(updated.grants.len(), 1);
        revoke_grant(&path, &sgk, &file.id, &editor).unwrap();

        // A Viewer can hold neither write nor manage: they can never
        // author the resulting meta/ciphers commits, so the grant would
        // wedge their sync at peer verification.
        let mut viewer_row = live_member_row(Uuid::new_v4());
        viewer_row.role = crate::vault::members::MemberRole::Viewer;
        std::fs::create_dir_all(path.join("meta/members")).unwrap();
        members::write_member(&path, &viewer_row).unwrap();
        for access in [CollectionAccess::Write, CollectionAccess::Manage] {
            let err = upsert_grant(
                &path,
                &sgk,
                &file.id,
                CollectionGrant {
                    member_id: viewer_row.id,
                    access,
                    expires_at: None,
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("Viewers cannot be given"), "{err}");
        }
    }

    #[test]
    fn grant_refuses_tombstoned_member() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member = Uuid::new_v4();
        std::fs::create_dir_all(path.join("meta/members")).unwrap();
        let mut row = live_member_row(member);
        row.removed = Some(1700000000);
        members::write_member(&path, &row).unwrap();
        let err = upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: member,
                access: CollectionAccess::Read,
                expires_at: None,
            },
        );
        assert!(err.is_err());
    }

    #[test]
    fn delete_collection_gone() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Temp").unwrap();
        delete_collection(&path, &file.id).unwrap();
        assert!(open_collection(&path, &sgk, &file.id).is_err());
    }

    #[test]
    fn name_tamper_refused() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let mut stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(collections_file_path(&path, &file.id)).unwrap(),
        )
        .unwrap();
        let env = stored["name_enc"]["envelope"].as_str().unwrap().to_string();
        // Flip near the END of the base64 - the tag/ciphertext region. The
        // first bytes of an envelope are the header and nonce (not covered
        // by this layer's check); the GCM tag is what catches tampering.
        let idx = env.len() - 4;
        let flipped: String = env
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == idx {
                    if c == 'A' { 'B' } else { 'A' }
                } else {
                    c
                }
            })
            .collect();
        stored["name_enc"]["envelope"] = serde_json::json!(flipped);
        std::fs::write(
            collections_file_path(&path, &file.id),
            serde_json::to_vec(&stored).unwrap(),
        )
        .unwrap();
        assert!(open_collection(&path, &sgk, &file.id).is_err());
    }

    #[test]
    fn foreign_epoch_refused() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let other = SpaceGroupKey::generate(2);
        assert!(open_collection(&path, &other, &file.id).is_err());
    }

    #[test]
    fn reseal_roundtrip() {
        let (_d, path) = temp_vault();
        let old = SpaceGroupKey::generate(1);
        let new = SpaceGroupKey::generate(2);
        let file = create_collection(&path, &old, "Servers").unwrap();
        let cks = collect_content_keys(&path, &old).unwrap();
        let n = rewrap_from_plaintexts(&path, &new, &cks).unwrap();
        assert_eq!(n, 1);
        let (_, name) = open_collection(&path, &new, &file.id).unwrap();
        assert_eq!(name, "Servers");
        assert!(open_collection(&path, &old, &file.id).is_err());
    }

    #[test]
    fn malformed_rows_skipped() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        create_collection(&path, &sgk, "Servers").unwrap();
        std::fs::create_dir_all(path.join("meta/collections")).unwrap();
        std::fs::write(path.join("meta/collections/junk.json"), b"{not json").unwrap();
        let rows = list_collections(&path, &sgk).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn sweep_expires_grants_and_rotates_key() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let now = now_secs_pub();
        let gone = Uuid::new_v4();
        let staying = Uuid::new_v4();
        std::fs::create_dir_all(path.join("meta/members")).unwrap();
        for m in [gone, staying] {
            let mut row = live_member_row(m);
            row.id = m;
            members::write_member(&path, &row).unwrap();
        }
        // Seed the past-dated grant at the file level: grants become
        // expired by time passing, not by being minted expired (the
        // mint gate refuses those).
        let (mut seeded, _) = open_collection(&path, &sgk, &file.id).unwrap();
        seeded.grants.push(CollectionGrant {
            member_id: gone,
            access: CollectionAccess::Write,
            expires_at: Some(now - 10),
        });
        save_collection(&path, &seeded).unwrap();
        upsert_grant(
            &path,
            &sgk,
            &file.id,
            CollectionGrant {
                member_id: staying,
                access: CollectionAccess::Read,
                expires_at: Some(now + 3600),
            },
        )
        .unwrap();
        let removed = sweep_expired_grants(&path, &sgk).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].member_id, gone);
        assert_eq!(removed[0].collection_id, file.id);
        // The surviving grant is intact and the name still decrypts
        // under the rotated key.
        let (updated, name) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(name, "Servers");
        assert_eq!(updated.grants.len(), 1);
        assert_eq!(updated.grants[0].member_id, staying);
        // Idempotent: a second sweep removes nothing.
        assert!(sweep_expired_grants(&path, &sgk).unwrap().is_empty());
    }

    #[test]
    fn expired_grant_does_not_authorize() {
        // is_grant_expired is the gate used by the local write check.
        let g = CollectionGrant {
            member_id: Uuid::new_v4(),
            access: CollectionAccess::Write,
            expires_at: Some(1),
        };
        assert!(is_grant_expired(&g, now_secs_pub()));
        let future = CollectionGrant {
            expires_at: Some(now_secs_pub() + 3600),
            ..g.clone()
        };
        assert!(!is_grant_expired(&future, now_secs_pub()));
        // An absent expires_at never expires.
        let none = CollectionGrant {
            expires_at: None,
            ..g
        };
        assert!(!is_grant_expired(&none, now_secs_pub()));
    }

    #[test]
    fn name_validation() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        assert!(create_collection(&path, &sgk, "   ").is_err());
        assert!(create_collection(&path, &sgk, &"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(create_collection(&path, &sgk, "bad\nname").is_err());
    }

    // ── P1: per-member grant wraps ──

    fn wrap_row(id: Uuid, wrap_hex: &str) -> members::MemberFile {
        let mut row = live_member_row(id);
        row.identity_wrap_pubkey = Some(wrap_hex.into());
        row
    }

    fn grant_to(member_id: Uuid) -> CollectionGrant {
        CollectionGrant {
            member_id,
            access: CollectionAccess::Read,
            expires_at: None,
        }
    }

    #[test]
    fn member_listing_needs_no_group_key() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let servers = create_collection(&path, &sgk, "Servers").unwrap();
        let finance = create_collection(&path, &sgk, "Finance").unwrap();
        let member_id = Uuid::new_v4();
        let stranger = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        // Read grant on Servers; a lapsed grant on Finance must not list.
        // upsert refuses past dates, so plant the lapsed row directly.
        upsert_grant(&path, &sgk, &servers.id, grant_to(member_id)).unwrap();
        let (mut fin_file, _) = open_collection(&path, &sgk, &finance.id).unwrap();
        fin_file.grants.push(CollectionGrant {
            member_id,
            access: CollectionAccess::Write,
            expires_at: Some(1),
        });
        save_collection(&path, &fin_file).unwrap();

        let rows = list_member_collections(&path, &member_id, alice.wrapping_secret());
        assert_eq!(rows.len(), 1, "only the live grant lists: {rows:?}");
        assert_eq!(rows[0].collection_id, servers.id);
        assert_eq!(rows[0].name, "Servers");
        assert_eq!(rows[0].access, CollectionAccess::Read);
        assert!(rows[0].expires_at.is_none());

        // No grant at all → empty.
        let none = list_member_collections(&path, &stranger, alice.wrapping_secret());
        assert!(none.is_empty());
    }

    #[test]
    fn grant_wrap_minted_and_opens_only_for_the_member() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        let mallory = crate::vault::identity::IdentityKeys::from_seed(&[9u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        // The wrap opens to the same CK the SGK path yields.
        let via_wrap =
            open_grant_wrap(&path, &file.id, &member_id, alice.wrapping_secret()).unwrap();
        let (on_disk, _) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(
            via_wrap.as_ref(),
            unwrap_ck(&on_disk, &sgk).unwrap().as_ref()
        );
        // A different identity is refused (HPKE unwrap fails closed).
        let err =
            open_grant_wrap(&path, &file.id, &member_id, mallory.wrapping_secret()).unwrap_err();
        assert!(err.to_string().contains("cannot be read"), "{err}");
    }

    #[test]
    fn revoke_and_delete_kill_member_wraps() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        let wrap = grant_wrap_path(&path, &file.id, &member_id);
        assert!(wrap.exists());
        revoke_grant(&path, &sgk, &file.id, &member_id).unwrap();
        assert!(!wrap.exists(), "revoke must remove the member wrap");
        // Re-grant then delete the collection: the whole wrap dir dies.
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        assert!(wrap.exists());
        delete_collection(&path, &file.id).unwrap();
        assert!(!wrap.exists(), "delete must remove the wrap dir");
    }

    #[test]
    fn transplanted_wrap_refused_by_context_binding() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let a = create_collection(&path, &sgk, "A").unwrap();
        let b = create_collection(&path, &sgk, "B").unwrap();
        let member_id = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &a.id, grant_to(member_id)).unwrap();
        upsert_grant(&path, &sgk, &b.id, grant_to(member_id)).unwrap();
        // Copy A's wrap into B's directory under the same member name:
        // the context binding must refuse it (the AEAD tag covers the
        // collection id), not yield A's key as B's.
        let a_wrap = grant_wrap_path(&path, &a.id, &member_id);
        let b_wrap = grant_wrap_path(&path, &b.id, &member_id);
        std::fs::copy(&a_wrap, &b_wrap).unwrap();
        assert!(open_grant_wrap(&path, &b.id, &member_id, alice.wrapping_secret()).is_err());
        // A's own wrap still opens.
        open_grant_wrap(&path, &a.id, &member_id, alice.wrapping_secret()).unwrap();
    }

    #[test]
    fn expired_grant_refused_at_mint() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        members::write_member(&path, &live_member_row(member_id)).unwrap();
        let mut stale = grant_to(member_id);
        stale.expires_at = Some(1);
        let err = upsert_grant(&path, &sgk, &file.id, stale).unwrap_err();
        assert!(err.to_string().contains("already in the past"), "{err}");
    }

    #[test]
    fn legacy_row_grant_skips_wrap_file() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        members::write_member(&path, &live_member_row(member_id)).unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        assert!(!grant_wrap_path(&path, &file.id, &member_id).exists());
        let rows = list_collections(&path, &sgk).unwrap();
        assert_eq!(rows[0].0.id, file.id);
    }

    #[test]
    fn key_rotation_rewraps_member_wraps() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let new_sgk = SpaceGroupKey::generate(2);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        let cks = collect_content_keys(&path, &sgk).unwrap();
        rewrap_from_plaintexts(&path, &new_sgk, &cks).unwrap();
        let via_wrap =
            open_grant_wrap(&path, &file.id, &member_id, alice.wrapping_secret()).unwrap();
        let (on_disk, _) = open_collection(&path, &new_sgk, &file.id).unwrap();
        assert_eq!(
            via_wrap.as_ref(),
            unwrap_ck(&on_disk, &new_sgk).unwrap().as_ref()
        );
    }

    #[test]
    fn sweep_strips_expired_wrap_and_rewraps_survivors() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Contractors").unwrap();
        let gone = Uuid::new_v4();
        let stays = Uuid::new_v4();
        let alice = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        let bob = crate::vault::identity::IdentityKeys::from_seed(&[11u8; 32]);
        members::write_member(
            &path,
            &wrap_row(gone, &hex::encode(alice.wrapping_pub_bytes())),
        )
        .unwrap();
        members::write_member(
            &path,
            &wrap_row(stays, &hex::encode(bob.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(stays)).unwrap();
        // Seed the expired grant + its wrap at the file level (time
        // passage): the mint gate refuses past-dated grants.
        let (mut seeded, _) = open_collection(&path, &sgk, &file.id).unwrap();
        let mut expired = grant_to(gone);
        expired.expires_at = Some(1);
        seeded.grants.push(expired);
        save_collection(&path, &seeded).unwrap();
        let ck_now = {
            let (f, _) = open_collection(&path, &sgk, &file.id).unwrap();
            unwrap_ck(&f, &sgk).unwrap()
        };
        write_grant_wrap(
            &path,
            &file.id,
            &gone,
            &hex::encode(alice.wrapping_pub_bytes()),
            &ck_now,
        )
        .unwrap();
        let removed = sweep_expired_grants(&path, &sgk).unwrap();
        assert_eq!(removed.len(), 1);
        // The expired grantee's wrap is gone; the survivor's opens to
        // the rotated CK.
        assert!(!grant_wrap_path(&path, &file.id, &gone).exists());
        let via_wrap = open_grant_wrap(&path, &file.id, &stays, bob.wrapping_secret()).unwrap();
        let (on_disk, _) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(
            via_wrap.as_ref(),
            unwrap_ck(&on_disk, &sgk).unwrap().as_ref()
        );
    }

    #[test]
    fn identity_rotation_rewraps_own_wraps() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_collection(&path, &sgk, "Servers").unwrap();
        let member_id = Uuid::new_v4();
        let old_id = crate::vault::identity::IdentityKeys::from_seed(&[7u8; 32]);
        let new_id = crate::vault::identity::IdentityKeys::from_seed(&[8u8; 32]);
        members::write_member(
            &path,
            &wrap_row(member_id, &hex::encode(old_id.wrapping_pub_bytes())),
        )
        .unwrap();
        upsert_grant(&path, &sgk, &file.id, grant_to(member_id)).unwrap();
        let done = rewrap_own_grant_wraps(
            &path,
            &member_id,
            old_id.wrapping_secret(),
            &hex::encode(new_id.wrapping_pub_bytes()),
        )
        .unwrap();
        assert_eq!(done, 1);
        // The new identity opens it; the old one is dead.
        let via_new =
            open_grant_wrap(&path, &file.id, &member_id, new_id.wrapping_secret()).unwrap();
        let (on_disk, _) = open_collection(&path, &sgk, &file.id).unwrap();
        assert_eq!(
            via_new.as_ref(),
            unwrap_ck(&on_disk, &sgk).unwrap().as_ref()
        );
        assert!(open_grant_wrap(&path, &file.id, &member_id, old_id.wrapping_secret()).is_err());
    }
}
