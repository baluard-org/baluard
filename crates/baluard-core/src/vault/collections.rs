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

/// A member's access level on a collection (§3 D: "read or write").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionAccess {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
}

/// One grant row. `expires_at` (unix seconds) is recorded this wave; the
/// expiry-that-rotates execution and notices surfacing are their own slice.
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

/// The relative path for a cipher: collection-scoped when the collection
/// is salted, personal flat otherwise (plan P5).
pub fn cipher_rel_path(file: Option<&CollectionFile>, cipher_id: Uuid) -> String {
    match file.and_then(collection_dir) {
        Some(d) => format!("ciphers/{d}/{cipher_id}.enc"),
        None => format!("ciphers/{cipher_id}.enc"),
    }
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

fn collections_file_path(vault_path: &Path, id: &Uuid) -> PathBuf {
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

fn unwrap_ck(
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

/// Add or update a grant. Refuses tombstoned members and cap overflow.
pub fn upsert_grant(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    collection_id: &Uuid,
    grant: CollectionGrant,
) -> Result<CollectionFile, BaluardError> {
    let (mut file, _) = open_collection(vault_path, sgk, collection_id)?;
    live_member(vault_path, &grant.member_id)?;
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
    Ok(file)
}

/// Delete a collection: file gone. Entries stay (path binding is a later
/// slice); grants die with the file.
pub fn delete_collection(vault_path: &Path, id: &Uuid) -> Result<(), BaluardError> {
    let path = collections_file_path(vault_path, id);
    std::fs::remove_file(&path)
        .map_err(|_| VaultError::InvalidOperation("That collection no longer exists.".into()))?;
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
    fn name_validation() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        assert!(create_collection(&path, &sgk, "   ").is_err());
        assert!(create_collection(&path, &sgk, &"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(create_collection(&path, &sgk, "bad\nname").is_err());
    }
}
