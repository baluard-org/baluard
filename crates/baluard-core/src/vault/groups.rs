//! Groups — a named membership list that collections can be granted to
//! (plan-power-pack S4-2, "grant a collection to a department instead of
//! person by person").
//!
//! `meta/groups/<id>.json` carries a plaintext member list plus the
//! group's display name sealed under a random Group Key (GK), itself
//! sealed under an SGK-derived wrap key — the collection pattern, with
//! one indirection that makes churn cheap. A collection granted to a
//! group stores its content key AGAIN under the GK
//! (`meta/groups/<g>/<c>.ckwrap`), and every group member holds the GK
//! wrapped to their identity key (`meta/groups/<g>/<m>.gkwrap`). The
//! chain is: gkwrap → GK → ckwrap → CK → names and item keys.
//!
//! The indirection is the point: REMOVING a member from a group rotates
//! only the group's GK (ckwraps re-seal under it; collection CKs and
//! every direct grantee stay untouched), where per-member CK wraps
//! would force a full re-key of every collection the group can open.
//! What the leaver memorized (an old CK) stays the accepted
//! eventual-revocation boundary priced everywhere else in this vault.
//!
//! Group files ride the `meta/**` Admin policy row; a member's own
//! `.gkwrap` carries an own-wrap structural rule so identity rotation
//! stays self-service (the collections own-wrap precedent).

use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::SpaceGroupKey;
use crate::secret_file::{open_secret_blob, seal_secret_blob};
use crate::vault::collections::{self, CollectionAccess};
use crate::vault::members;
use crate::vault::write_vault_file;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Cap on live groups per vault.
pub const MAX_GROUPS: usize = 64;
/// Cap on members per group.
pub const MAX_GROUP_MEMBERS: usize = 200;
/// Cap on one group file on read (git-tracked files can arrive large).
pub const MAX_GROUP_FILE_BYTES: usize = 256 * 1024;

const FORMAT: u32 = 1;
const GK_WRAP_FORMAT: u32 = 1;
const CKWRAP_FORMAT: u32 = 1;
/// HKDF info prefix for the SGK-derived key that seals each group key.
const GK_WRAP_INFO: &[u8] = b"baluard-group-key-wrap-v1";
const GK_PURPOSE: &str = "group-key-v1";
const NAME_PURPOSE: &str = "group-name-v1";
const CK_PURPOSE: &str = "group-ck-v1";

/// The group's file: plaintext membership, GK sealed under SGK, name
/// sealed under the GK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFile {
    pub format: u32,
    pub id: Uuid,
    pub created_at: u64,
    /// The group key, sealed under the SGK-derived wrap key.
    pub gk_wrapped: serde_json::Value,
    /// The group's display name, sealed under the GK.
    pub name_enc: serde_json::Value,
    /// Live members (no tombstones — removal deletes the row).
    pub members: Vec<Uuid>,
}

pub fn groups_dir(vault_path: &Path) -> PathBuf {
    vault_path.join("meta/groups")
}

pub fn group_file_path(vault_path: &Path, id: &Uuid) -> PathBuf {
    vault_path.join(format!("meta/groups/{id}.json"))
}

fn gkwraps_dir(vault_path: &Path, id: &Uuid) -> PathBuf {
    groups_dir(vault_path).join(id.to_string())
}

pub fn gkwrap_path(vault_path: &Path, id: &Uuid, member_id: &Uuid) -> PathBuf {
    gkwraps_dir(vault_path, id).join(format!("{member_id}.gkwrap"))
}

pub fn ckwrap_path(vault_path: &Path, id: &Uuid, collection_id: &Uuid) -> PathBuf {
    gkwraps_dir(vault_path, id).join(format!("{collection_id}.ckwrap"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// SGK-derived wrap key for group keys — same family as the collection
/// key wrap, distinct info so a GK can never be opened with a
/// collection wrap key or vice versa. Epoch-bound: rotation re-seals.
fn gk_wrap_key(sgk: &SpaceGroupKey) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut info = Vec::with_capacity(GK_WRAP_INFO.len() + 8);
    info.extend_from_slice(GK_WRAP_INFO);
    info.extend_from_slice(&sgk.epoch().to_le_bytes());
    let hkdf = Hkdf::<Sha256>::new(None, sgk.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32 bytes is valid output length for HKDF-SHA256");
    key
}

fn json_bytes(v: &serde_json::Value) -> Result<Vec<u8>, BaluardError> {
    serde_json::to_vec(v).map_err(|e| VaultError::Metadata(format!("group serialize: {e}")).into())
}

fn validate_name(name: &str) -> Result<(), BaluardError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidOperation("Give the group a name.".into()).into());
    }
    if trimmed.chars().count() > collections::MAX_NAME_CHARS {
        return Err(VaultError::InvalidOperation(format!(
            "Group names are limited to {} characters.",
            collections::MAX_NAME_CHARS
        ))
        .into());
    }
    if trimmed.chars().any(|c| c == '\n' || c == '\r') {
        return Err(
            VaultError::InvalidOperation("Group names cannot contain line breaks.".into()).into(),
        );
    }
    Ok(())
}

/// Seal the group key under the SGK-derived wrap key.
fn wrap_gk(
    sgk: &SpaceGroupKey,
    gk: &[u8; 32],
    id: &Uuid,
) -> Result<serde_json::Value, BaluardError> {
    let sealed = seal_secret_blob(&gk_wrap_key(sgk), gk, &format!("{GK_PURPOSE}/{id}"))?;
    Ok(serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("group seal: {e}")))?)
}

/// Open the group key on the admin path (SGK-held devices).
pub fn unwrap_gk(
    file: &GroupFile,
    sgk: &SpaceGroupKey,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let raw = open_secret_blob(
        &gk_wrap_key(sgk),
        &json_bytes(&file.gk_wrapped)?,
        &format!("{GK_PURPOSE}/{}", file.id),
    )
    .map_err(|_| VaultError::InvalidOperation("That group's key cannot be read.".into()))?;
    let gk: [u8; 32] = raw.try_into().map_err(|_| {
        VaultError::InvalidOperation("That group's key has the wrong length.".into())
    })?;
    Ok(Zeroizing::new(gk))
}

/// Seal the group's display name under the GK.
fn seal_name(gk: &[u8; 32], id: &Uuid, name: &str) -> Result<serde_json::Value, BaluardError> {
    let sealed = seal_secret_blob(gk, name.as_bytes(), &format!("{NAME_PURPOSE}/{id}"))?;
    Ok(serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("group seal: {e}")))?)
}

/// Open a group's display name from the GK. Fails closed on a foreign
/// or tampered blob.
fn decrypt_name(file: &GroupFile, gk: &[u8; 32]) -> Result<String, BaluardError> {
    let bytes = open_secret_blob(
        gk,
        &json_bytes(&file.name_enc)?,
        &format!("{NAME_PURPOSE}/{}", file.id),
    )
    .map_err(|_| VaultError::InvalidOperation("That group's name cannot be read.".into()))?;
    String::from_utf8(bytes)
        .map_err(|_| VaultError::InvalidOperation("That group's name is damaged.".into()).into())
}

/// Parse + format-pin one group file. Stem mismatch and wrong format
/// refuse (the collection walk discipline).
pub fn parse_group_file(vault_path: &Path, id: &Uuid) -> Result<GroupFile, BaluardError> {
    let path = group_file_path(vault_path, id);
    let bytes = std::fs::read(&path)
        .map_err(|_| VaultError::InvalidOperation("That group no longer exists.".into()))?;
    if bytes.len() > MAX_GROUP_FILE_BYTES {
        return Err(
            VaultError::InvalidOperation("That group file is too large to open.".into()).into(),
        );
    }
    let file: GroupFile = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidOperation("That group file is damaged.".into()))?;
    if file.format != FORMAT {
        return Err(VaultError::InvalidOperation("Unsupported group format.".into()).into());
    }
    if path.file_stem().and_then(|s| s.to_str()) != Some(file.id.to_string().as_str()) {
        return Err(VaultError::InvalidOperation("That group file is damaged.".into()).into());
    }
    Ok(file)
}

pub fn save_group(vault_path: &Path, file: &GroupFile) -> Result<(), BaluardError> {
    let bytes = serde_json::to_vec(file)
        .map_err(|e| VaultError::Metadata(format!("group serialize: {e}")))?;
    write_vault_file(&group_file_path(vault_path, &file.id), &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("group write: {e}"))))
}

/// Mint a group: random GK, SGK-sealed, name sealed under the GK.
pub fn create_group(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    name: &str,
) -> Result<GroupFile, BaluardError> {
    validate_name(name)?;
    let dir = groups_dir(vault_path);
    if count_group_files(&dir)? >= MAX_GROUPS {
        return Err(
            VaultError::InvalidOperation("This vault has reached its group limit.".into()).into(),
        );
    }
    // Same uniqueness invariant as collections, Unicode case-folded.
    let folded = name.trim().to_lowercase();
    for (_, existing) in list_groups(vault_path, sgk)? {
        if existing.to_lowercase() == folded {
            return Err(VaultError::InvalidOperation(
                "A group with this name already exists.".into(),
            )
            .into());
        }
    }
    let id = Uuid::new_v4();
    let mut gk = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(gk.as_mut());
    let file = GroupFile {
        format: FORMAT,
        id,
        created_at: now_secs(),
        gk_wrapped: wrap_gk(sgk, &gk, &id)?,
        name_enc: seal_name(&gk, &id, name.trim())?,
        members: Vec::new(),
    };
    std::fs::create_dir_all(&dir)?;
    save_group(vault_path, &file)?;
    Ok(file)
}

fn count_group_files(dir: &Path) -> Result<usize, BaluardError> {
    if !dir.is_dir() {
        return Ok(0);
    }
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .count())
}

/// Walk every well-formed group def; malformed rows skip inert (the
/// member-directory discipline). Sorted by decrypted name.
/// Strict file-level group enumeration for SECURITY decisions: read
/// and parse errors propagate instead of skipping, so a damaged group
/// can never silently keep a leaver's gkwrap or strand its GK across a
/// rotation. Name decryption stays out (callers may not need it).
pub fn list_group_files(vault_path: &Path) -> Result<Vec<GroupFile>, BaluardError> {
    let mut out = Vec::new();
    let dir = groups_dir(vault_path);
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| VaultError::Metadata(format!("group read: {e}")))?;
        if bytes.len() > MAX_GROUP_FILE_BYTES {
            return Err(VaultError::InvalidOperation(
                "A group file is too large to process.".into(),
            )
            .into());
        }
        let file: GroupFile = serde_json::from_slice(&bytes)
            .map_err(|_| VaultError::InvalidOperation("A group file is damaged.".into()))?;
        if file.format != FORMAT {
            return Err(VaultError::InvalidOperation(
                "A group file has an unsupported format.".into(),
            )
            .into());
        }
        if path.file_stem().and_then(|x| x.to_str()) != Some(file.id.to_string().as_str()) {
            return Err(VaultError::InvalidOperation(
                "A group file does not match its id.".into(),
            )
            .into());
        }
        out.push(file);
    }
    Ok(out)
}

pub fn list_groups(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
) -> Result<Vec<(GroupFile, String)>, BaluardError> {
    let mut out = Vec::new();
    let dir = groups_dir(vault_path);
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
        if bytes.len() > MAX_GROUP_FILE_BYTES {
            continue;
        }
        let Ok(file) = serde_json::from_slice::<GroupFile>(&bytes) else {
            continue;
        };
        if file.format != FORMAT {
            continue;
        }
        if path.file_stem().and_then(|x| x.to_str()) != Some(file.id.to_string().as_str()) {
            continue;
        }
        if let Ok(gk) = unwrap_gk(&file, sgk) {
            if let Ok(name) = decrypt_name(&file, &gk) {
                out.push((file, name));
            }
        }
    }
    out.sort_by_key(|a| a.1.to_lowercase());
    Ok(out)
}

pub fn rename_group(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    id: &Uuid,
    name: &str,
) -> Result<GroupFile, BaluardError> {
    validate_name(name)?;
    // Same uniqueness invariant as collections, Unicode case-folded.
    let folded = name.trim().to_lowercase();
    for (other, existing) in list_groups(vault_path, sgk)? {
        if other.id != *id && existing.to_lowercase() == folded {
            return Err(VaultError::InvalidOperation(
                "A group with this name already exists.".into(),
            )
            .into());
        }
    }
    let mut file = parse_group_file(vault_path, id)?;
    let gk = unwrap_gk(&file, sgk)?;
    file.name_enc = seal_name(&gk, id, name.trim())?;
    save_group(vault_path, &file)?;
    Ok(file)
}

pub fn delete_group(vault_path: &Path, sgk: &SpaceGroupKey, id: &Uuid) -> Result<(), BaluardError> {
    let path = group_file_path(vault_path, id);
    std::fs::remove_file(&path)
        .map_err(|_| VaultError::InvalidOperation("That group no longer exists.".into()))?;
    let _ = std::fs::remove_dir_all(gkwraps_dir(vault_path, id));
    // Review F4: prune the group's grant rows from every collection so
    // no def carries a dangling target (access checks already fail
    // closed on a missing group; the rows would only be dead weight in
    // the admin UI and the access review).
    for (mut file, _) in collections::list_collections(vault_path, sgk)? {
        let before = file.grants.len();
        file.grants.retain(|g| g.target.group_id() != Some(*id));
        if file.grants.len() != before {
            collections::save_collection(vault_path, &file)?;
        }
    }
    Ok(())
}

/// gkwraps mint ADMIN-side against the member's identity wrap pubkey,
/// exactly like grant wraps — the member's wrapping secret is never an
/// input here.
fn write_gkwrap(
    vault_path: &Path,
    id: &Uuid,
    member_id: &Uuid,
    wrap_pub_hex: &str,
    gk: &[u8; 32],
) -> Result<(), BaluardError> {
    let recip = x25519_dalek::PublicKey::from(collections::wrap_pubkey_bytes(wrap_pub_hex)?);
    let context = format!("{GK_PURPOSE}/{id}/{member_id}");
    let (eph, ct, tag) = crate::crypto::hpke_wrap::wrap_key(gk, &recip, &context)?;
    let doc = serde_json::json!({
        "format": GK_WRAP_FORMAT,
        "ephemeral_public": hex::encode(eph),
        "encrypted_key": hex::encode(ct),
        "tag": hex::encode(tag),
    });
    write_vault_file(
        &gkwrap_path(vault_path, id, member_id),
        serde_json::to_string_pretty(&doc)
            .map_err(|e| VaultError::Metadata(format!("gkwrap serialize: {e}")))?
            .as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write gkwrap: {e}"))))
}

/// Open one gkwrap with the member's own X25519 wrapping secret.
/// Fails closed on a missing/tampered/foreign wrap.
pub fn open_gkwrap(
    vault_path: &Path,
    id: &Uuid,
    member_id: &Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let bytes = std::fs::read(gkwrap_path(vault_path, id, member_id))
        .map_err(|_| VaultError::InvalidOperation("That group key wrap does not exist.".into()))?;
    if bytes.len() > MAX_GROUP_FILE_BYTES {
        return Err(VaultError::InvalidOperation(
            "That group key wrap is too large to open.".into(),
        )
        .into());
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?;
    if doc["format"].as_u64() != Some(GK_WRAP_FORMAT as u64) {
        return Err(VaultError::InvalidOperation("Unsupported wrap format.".into()).into());
    }
    let hex_field = |k: &str| -> Result<String, BaluardError> {
        doc[k].as_str().map(|s| s.to_string()).ok_or_else(|| {
            BaluardError::from(VaultError::InvalidOperation(
                "That group key wrap is damaged.".into(),
            ))
        })
    };
    let eph = hex::decode(hex_field("ephemeral_public")?)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?;
    let ct = hex::decode(hex_field("encrypted_key")?)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?;
    let tag: [u8; 16] = hex::decode(hex_field("tag")?)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?
        .try_into()
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?;
    let context = format!("{GK_PURPOSE}/{id}/{member_id}");
    let pt = crate::crypto::hpke_wrap::unwrap_key(&eph, &ct, &tag, wrapping_secret, &context)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap cannot be read.".into()))?;
    let gk: [u8; 32] = pt
        .try_into()
        .map_err(|_| VaultError::InvalidOperation("That group key has the wrong length.".into()))?;
    Ok(Zeroizing::new(gk))
}

/// The member's live wrap pubkey, or None (tombstoned, gone, or
/// legacy-no-pubkey — SGK covers the last case pre-flip).
fn wrap_pub_of(vault_path: &Path, member_id: &Uuid) -> Option<String> {
    members::member_file_by_id(vault_path, *member_id)
        .filter(|row| row.removed.is_none() && row.reset.is_none())
        .and_then(|row| row.identity_wrap_pubkey)
        .filter(|w| !w.is_empty())
}

/// Seal one collection's content key under the group key. The purpose
/// binds group AND collection, so a ckwrap moved between collections
/// (or groups) fails the AEAD tag.
pub fn write_ckwrap(
    vault_path: &Path,
    group_id: &Uuid,
    collection_id: &Uuid,
    gk: &[u8; 32],
    ck: &[u8; 32],
) -> Result<(), BaluardError> {
    let sealed = seal_secret_blob(gk, ck, &format!("{CK_PURPOSE}/{group_id}/{collection_id}"))?;
    let doc: serde_json::Value = serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("ckwrap seal: {e}")))?;
    let wrapped = serde_json::json!({
        "format": CKWRAP_FORMAT,
        "sealed": doc,
    });
    write_vault_file(
        &ckwrap_path(vault_path, group_id, collection_id),
        serde_json::to_string_pretty(&wrapped)
            .map_err(|e| VaultError::Metadata(format!("ckwrap serialize: {e}")))?
            .as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write ckwrap: {e}"))))
}

/// Read one ckwrap's sealed bytes back as a serde Value (the open
/// helpers share this parse).
fn read_ckwrap_sealed(
    vault_path: &Path,
    group_id: &Uuid,
    collection_id: &Uuid,
) -> Result<serde_json::Value, BaluardError> {
    let bytes = std::fs::read(ckwrap_path(vault_path, group_id, collection_id)).map_err(|_| {
        VaultError::InvalidOperation("That group's access to this collection is gone.".into())
    })?;
    if bytes.len() > MAX_GROUP_FILE_BYTES {
        return Err(VaultError::InvalidOperation(
            "That group key wrap is too large to open.".into(),
        )
        .into());
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidOperation("That group key wrap is damaged.".into()))?;
    if doc["format"].as_u64() != Some(CKWRAP_FORMAT as u64) {
        return Err(VaultError::InvalidOperation("Unsupported wrap format.".into()).into());
    }
    doc.get("sealed").cloned().ok_or_else(|| {
        BaluardError::from(VaultError::InvalidOperation(
            "That group key wrap is damaged.".into(),
        ))
    })
}

/// Member path: open the collection content key through the group —
/// gkwrap → GK → ckwrap → CK. Fails closed when any leg is missing.
pub fn open_ck_through_group(
    vault_path: &Path,
    group_id: &Uuid,
    collection_id: &Uuid,
    member_id: &Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let gk = open_gkwrap(vault_path, group_id, member_id, wrapping_secret)?;
    let sealed = read_ckwrap_sealed(vault_path, group_id, collection_id)?;
    let ck_raw = open_secret_blob(
        &gk,
        &json_bytes(&sealed)?,
        &format!("{CK_PURPOSE}/{group_id}/{collection_id}"),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection's key cannot be read.".into()))?;
    let ck: [u8; 32] = ck_raw.try_into().map_err(|_| {
        VaultError::InvalidOperation("That collection's key has the wrong length.".into())
    })?;
    Ok(Zeroizing::new(ck))
}

/// Admin path: open a ckwrap with the def's CURRENT gk_wrapped. Used by
/// the GK rotation rewrite, which unwraps the OLD GK before overwriting
/// the def.
fn open_ckwrap_with_gk(
    vault_path: &Path,
    group_id: &Uuid,
    collection_id: &Uuid,
    gk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let sealed = read_ckwrap_sealed(vault_path, group_id, collection_id)?;
    let ck_raw = open_secret_blob(
        gk,
        &json_bytes(&sealed)?,
        &format!("{CK_PURPOSE}/{group_id}/{collection_id}"),
    )
    .map_err(|_| VaultError::InvalidOperation("That collection's key cannot be read.".into()))?;
    let ck: [u8; 32] = ck_raw.try_into().map_err(|_| {
        VaultError::InvalidOperation("That collection's key has the wrong length.".into())
    })?;
    Ok(Zeroizing::new(ck))
}

/// Add a member to a group: membership row + gkwrap mint. On flipped
/// vaults a member without a usable wrap pubkey refuses — rootless
/// members could never open the GK, so membership without a wrap would
/// be silent dead weight (the flip readiness gate guarantees live rows
/// carry one, so this only fires on torn rows).
pub fn add_group_member(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    id: &Uuid,
    member_id: &Uuid,
) -> Result<GroupFile, BaluardError> {
    let mut file = parse_group_file(vault_path, id)?;
    let member = members::member_file_by_id(vault_path, *member_id).ok_or_else(|| {
        VaultError::InvalidOperation("That person is not a member of this vault.".into())
    })?;
    if member.removed.is_some() || member.reset.is_some() {
        return Err(VaultError::InvalidOperation(
            "That person is no longer an active member.".into(),
        )
        .into());
    }
    if file.members.contains(member_id) {
        return Err(
            VaultError::InvalidOperation("That person is already in this group.".into()).into(),
        );
    }
    if file.members.len() >= MAX_GROUP_MEMBERS {
        return Err(VaultError::InvalidOperation(
            "This group has reached its member limit.".into(),
        )
        .into());
    }
    let flipped = crate::vault::space_meta::shape_flipped(vault_path);
    let wrap_pub = wrap_pub_of(vault_path, member_id);
    if flipped && wrap_pub.is_none() {
        return Err(VaultError::InvalidOperation(
            "That person's record has no share key, so their device cannot hold group keys.".into(),
        )
        .into());
    }
    file.members.push(*member_id);
    save_group(vault_path, &file)?;
    if let Some(wrap_pub) = wrap_pub {
        let gk = unwrap_gk(&file, sgk)?;
        write_gkwrap(vault_path, id, member_id, &wrap_pub, &gk)?;
    }
    Ok(file)
}

/// Remove a member from a group: the row dies, their gkwrap dies, and
/// the GK rotates so the leaver cannot open any FUTURE ckwrap of this
/// group. Collection content keys and every direct grantee are
/// untouched — that is the indirection's whole point. Survivors'
/// gkwraps and every ckwrap rewrite under the new GK (the old GK is
/// unwrapped BEFORE the def changes, and only plaintext keys cross the
/// rewrite).
pub fn remove_group_member(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    id: &Uuid,
    member_id: &Uuid,
) -> Result<GroupFile, BaluardError> {
    let mut file = parse_group_file(vault_path, id)?;
    let before = file.members.len();
    file.members.retain(|m| m != member_id);
    if file.members.len() == before {
        return Err(
            VaultError::InvalidOperation("That person is not in this group.".into()).into(),
        );
    }
    let _ = std::fs::remove_file(gkwrap_path(vault_path, id, member_id));

    // Old GK first: the def still carries the old wrap. The display
    // name seals under the GK, so it decrypts now and re-seals under
    // the new key.
    let old_gk = unwrap_gk(&file, sgk)?;
    let name = decrypt_name(&file, &old_gk)?;

    // Verify phase: open every ckwrap under the old GK BEFORE any
    // persisted mutation — the def flip is the commit point, and a
    // damaged ckwrap discovered after it would be sealed under a GK
    // nobody holds.
    let dir = gkwraps_dir(vault_path, id);
    let mut ck_wraps = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ckwrap") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(cid) = Uuid::parse_str(stem) else {
                continue;
            };
            let ck = open_ckwrap_with_gk(vault_path, id, &cid, &old_gk)?;
            ck_wraps.push((cid, ck));
        }
    }

    // Rotate: fresh GK, re-seal the def (key wrap AND name).
    let mut new_gk = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(new_gk.as_mut());
    file.gk_wrapped = wrap_gk(sgk, &new_gk, id)?;
    file.name_enc = seal_name(&new_gk, id, &name)?;
    save_group(vault_path, &file)?;

    // Commit done — the old GK stays in scope until every re-wrap is
    // written; a write failure past this point surfaces as Err with the
    // group named (a retry converges: the member is already out of the
    // def, so prune skips this group).
    for (cid, ck) in &ck_wraps {
        write_ckwrap(vault_path, id, cid, &new_gk, ck)?;
    }

    // Survivor gkwraps rewrite under the new GK.
    for m in &file.members {
        if let Some(wrap_pub) = wrap_pub_of(vault_path, m) {
            write_gkwrap(vault_path, id, m, &wrap_pub, &new_gk)?;
        }
    }
    Ok(file)
}

/// The decrypted group keys keyed by group id — the payload the
/// rotation paths carry across the Root Key swap.
pub type CollectedGroupKeys = Vec<(Uuid, Zeroizing<[u8; 32]>)>;

/// Rotation coverage, pre-swap half: decrypt every group key with the
/// outgoing SGK so the plaintext GKs can cross the Root Key swap.
pub fn collect_group_keys(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
) -> Result<CollectedGroupKeys, BaluardError> {
    let mut out = Vec::new();
    // Strict walk: a group the lenient listing skips would strand its GK
    // under the dead SGK epoch — unrecoverable after the rotation.
    for file in list_group_files(vault_path)? {
        out.push((file.id, unwrap_gk(&file, sgk)?));
    }
    Ok(out)
}

/// Rotation coverage, post-swap half: re-seal the collected plaintext
/// GKs under the new SGK epoch. gkwraps and ckwraps are identity/GK-keyed
/// and need no rewrite. Called from both rotation paths after the swap;
/// failures propagate (P4 rule).
pub fn rewrap_group_keys(
    vault_path: &Path,
    new_sgk: &SpaceGroupKey,
    gks: &CollectedGroupKeys,
) -> Result<usize, BaluardError> {
    let mut done = 0;
    for (id, gk) in gks {
        let mut file = parse_group_file(vault_path, id)?;
        file.gk_wrapped = wrap_gk(new_sgk, gk, id)?;
        save_group(vault_path, &file)?;
        done += 1;
    }
    Ok(done)
}

/// Identity-rotation self-heal: re-wrap the rotating member's own
/// gkwraps to the new pubkey. Two-phase like the grant-wrap heal.
pub fn rewrap_own_gkwraps(
    vault_path: &Path,
    member_id: &Uuid,
    old_secret: &x25519_dalek::StaticSecret,
    new_wrap_pub_hex: &str,
) -> Result<usize, BaluardError> {
    let mut collected: Vec<(Uuid, Zeroizing<[u8; 32]>)> = Vec::new();
    for entry in std::fs::read_dir(groups_dir(vault_path))
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
        if !gkwrap_path(vault_path, &id, member_id).exists() {
            continue;
        }
        let gk = open_gkwrap(vault_path, &id, member_id, old_secret)?;
        collected.push((id, gk));
    }
    for (id, gk) in &collected {
        write_gkwrap(vault_path, id, member_id, new_wrap_pub_hex, gk)?;
    }
    Ok(collected.len())
}

/// Offboarding prune (review F3): a member being reset or removed from
/// the VAULT loses every group membership — the row dies, their gkwrap
/// dies, and each affected group's GK rotates so nothing future opens
/// for them through the group. Runs while the CURRENT SGK is still
/// held (before any root rotation); remove_group_member walks
/// membership directly, so the just-tombstoned row prunes fine.
pub fn prune_member(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    member_id: &Uuid,
) -> Result<usize, BaluardError> {
    let mut pruned = 0;
    // Strict walk: a damaged group must fail the removal, not leave the
    // leaver's gkwrap live on a group nobody can rotate later.
    for file in list_group_files(vault_path)? {
        if file.members.contains(member_id) {
            remove_group_member(vault_path, sgk, &file.id, member_id)?;
            pruned += 1;
        }
    }
    Ok(pruned)
}

/// Mint-side hook for collections.rs: a grant targeting this group
/// (re)mints the ckwrap and refreshes every member gkwrap (idempotent,
/// self-healing against stale pubkeys).
pub(crate) fn grant_minted_for_group(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    group_id: &Uuid,
    collection_id: &Uuid,
    ck: &[u8; 32],
) -> Result<(), BaluardError> {
    let file = parse_group_file(vault_path, group_id)?;
    let gk = unwrap_gk(&file, sgk)?;
    write_ckwrap(vault_path, group_id, collection_id, &gk, ck)?;
    for m in &file.members {
        if let Some(wrap_pub) = wrap_pub_of(vault_path, m) {
            write_gkwrap(vault_path, group_id, m, &wrap_pub, &gk)?;
        }
    }
    Ok(())
}

/// Revoke-side hook for collections.rs: a group grant dying removes
/// this group's ckwrap for that collection. gkwraps stay — membership
/// governs them, not any one grant.
pub(crate) fn grant_revoked_for_group(
    vault_path: &Path,
    group_id: &Uuid,
    collection_id: &Uuid,
) -> Result<(), BaluardError> {
    match std::fs::remove_file(ckwrap_path(vault_path, group_id, collection_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BaluardError::from(VaultError::Metadata(format!(
            "remove ckwrap: {e}"
        )))),
    }
}

/// True when the member holds at least one gkwrap (identity-rotation
/// refusal condition, mirroring collections::has_grant_wraps).
pub(crate) fn has_gkwraps(vault_path: &Path, member_id: &Uuid) -> bool {
    std::fs::read_dir(groups_dir(vault_path))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.path()
                .file_stem()
                .and_then(|s| s.to_str().map(String::from))
        })
        .filter_map(|stem| Uuid::parse_str(&stem).ok())
        .any(|id| gkwrap_path(vault_path, &id, member_id).exists())
}

/// Access level `member` holds through `grants` — direct or via a
/// group — with max access winning and expired grants ignored.
/// `group_members` resolves one group's live membership in the caller's
/// source of truth (git tree for the sync walks, disk for local
/// checks).
pub fn effective_access(
    grants: &[collections::CollectionGrant],
    member: Uuid,
    group_members: &dyn Fn(Uuid) -> Option<Vec<Uuid>>,
    now: u64,
) -> Option<CollectionAccess> {
    use CollectionAccess::{Manage, Read, Write};
    let rank = |a: &CollectionAccess| match a {
        Read => 1,
        Write => 2,
        Manage => 3,
    };
    grants
        .iter()
        .filter(|g| !collections::is_grant_expired(g, now))
        .filter_map(|g| match &g.target {
            collections::GrantTarget::Member { id } if *id == member => Some(g.access),
            collections::GrantTarget::Group { id } => group_members(*id)
                .filter(|ms| ms.contains(&member))
                .map(|_| g.access),
            _ => None,
        })
        .max_by_key(|a| rank(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    fn member_row(id: Uuid, wrap_hex: Option<&str>) -> members::MemberFile {
        crate::vault::members::MemberFile {
            id,
            display_name: "Alicia".into(),
            email: None,
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Verified,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: wrap_hex.map(String::from),
        }
    }

    fn wrap_secret(seed: u8) -> (x25519_dalek::StaticSecret, String) {
        let secret = x25519_dalek::StaticSecret::from([seed; 32]);
        let pub_hex = hex::encode(x25519_dalek::PublicKey::from(&secret).as_bytes());
        (secret, pub_hex)
    }

    #[test]
    fn rotation_fails_closed_on_damaged_group() {
        let (_dir, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let file = create_group(&path, &sgk, "Servers").unwrap();
        // A group the lenient listing silently drops would keep its GK
        // sealed under the dead SGK epoch (collect_group_keys) and its
        // leaver's gkwrap live (prune_member). The strict walk must
        // error instead of skipping.
        let p = group_file_path(&path, &file.id);
        let mut damaged: GroupFile =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        damaged.gk_wrapped = serde_json::json!({"not": "a wrap"});
        let leaver = Uuid::new_v4();
        damaged.members.push(leaver);
        std::fs::write(&p, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(collect_group_keys(&path, &sgk).is_err());
        assert!(prune_member(&path, &sgk, &leaver).is_err());
    }

    #[test]
    fn group_names_are_unique_case_insensitive() {
        let (_dir, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        create_group(&path, &sgk, "Servers").unwrap();
        let err = create_group(&path, &sgk, "SERVERS").unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn group_roundtrip_and_member_paths() {
        let (_dir, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);

        let g = create_group(&path, &sgk, "Engineering").expect("create");
        let listed = list_groups(&path, &sgk).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, "Engineering");

        // A member with a wrap pubkey joins and opens the GK.
        let (secret, pub_hex) = wrap_secret(7);
        let m = Uuid::new_v4();
        members::write_member(&path, &member_row(m, Some(&pub_hex))).unwrap();

        let file = add_group_member(&path, &sgk, &g.id, &m).expect("add member");
        assert_eq!(file.members, vec![m]);

        let gk = open_gkwrap(&path, &g.id, &m, &secret).expect("open gkwrap");
        let admin_gk = unwrap_gk(&parse_group_file(&path, &g.id).unwrap(), &sgk).unwrap();
        assert_eq!(gk.as_ref(), admin_gk.as_ref());

        // A ckwrap round-trips to the same CK the admin path unwraps.
        let cid = Uuid::new_v4();
        let mut ck = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(ck.as_mut());
        write_ckwrap(&path, &g.id, &cid, &gk, &ck).expect("write ckwrap");
        let through =
            open_ck_through_group(&path, &g.id, &cid, &m, &secret).expect("open ck through group");
        assert_eq!(through.as_ref(), ck.as_ref());
    }

    #[test]
    fn member_leave_rotates_gk_but_not_collection_keys() {
        let (_dir, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let g = create_group(&path, &sgk, "Ops").expect("create");

        let (leaver_secret, leaver_pub) = wrap_secret(3);
        let (stayer_secret, stayer_pub) = wrap_secret(9);
        let leaver = Uuid::new_v4();
        let stayer = Uuid::new_v4();
        for (id, pub_hex) in [(leaver, leaver_pub), (stayer, stayer_pub)] {
            members::write_member(&path, &member_row(id, Some(&pub_hex))).unwrap();
            add_group_member(&path, &sgk, &g.id, &id).expect("add");
        }

        // Seed a collection's CK and mint the group's ckwrap.
        let cid = Uuid::new_v4();
        let mut ck = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(ck.as_mut());
        let file = parse_group_file(&path, &g.id).unwrap();
        let gk = unwrap_gk(&file, &sgk).unwrap();
        write_ckwrap(&path, &g.id, &cid, &gk, &ck).expect("ckwrap");

        remove_group_member(&path, &sgk, &g.id, &leaver).expect("remove");

        // The leaver's gkwrap is gone and their secret opens nothing.
        assert!(!gkwrap_path(&path, &g.id, &leaver).exists());
        assert!(open_gkwrap(&path, &g.id, &leaver, &leaver_secret).is_err());

        // The stayer still reaches the SAME collection content key.
        let ck_now =
            open_ck_through_group(&path, &g.id, &cid, &stayer, &stayer_secret).expect("stayer");
        assert_eq!(ck_now.as_ref(), ck.as_ref(), "collection key invariant");

        // The def still parses and the name survives the rotation.
        let after = parse_group_file(&path, &g.id).unwrap();
        let gk_now = unwrap_gk(&after, &sgk).unwrap();
        assert_eq!(decrypt_name(&after, &gk_now).unwrap(), "Ops");
    }

    #[test]
    fn foreign_wrap_and_torn_rows_refuse() {
        let (_dir, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let g = create_group(&path, &sgk, "X").expect("create");

        let (secret, pub_hex) = wrap_secret(5);
        let m = Uuid::new_v4();
        members::write_member(&path, &member_row(m, Some(&pub_hex))).unwrap();
        add_group_member(&path, &sgk, &g.id, &m).expect("add");

        // A gkwrap from another group fails the context binding.
        let g2 = create_group(&path, &sgk, "Y").expect("create g2");
        std::fs::create_dir_all(gkwraps_dir(&path, &g2.id)).unwrap();
        std::fs::copy(
            gkwrap_path(&path, &g.id, &m),
            gkwrap_path(&path, &g2.id, &m),
        )
        .unwrap();
        assert!(open_gkwrap(&path, &g2.id, &m, &secret).is_err());

        // Duplicate add and unknown-member refusals.
        assert!(add_group_member(&path, &sgk, &g.id, &m).is_err());
        assert!(add_group_member(&path, &sgk, &g.id, &Uuid::new_v4()).is_err());

        // Effective access: group grants reach members; unknown groups
        // contribute nothing.
        let now = now_secs();
        let grants = vec![collections::CollectionGrant {
            target: collections::GrantTarget::Group { id: g.id },
            access: CollectionAccess::Write,
            expires_at: None,
        }];
        let lookup = |gid: Uuid| -> Option<Vec<Uuid>> {
            let f = parse_group_file(&path, &gid).ok()?;
            Some(f.members)
        };
        assert_eq!(
            effective_access(&grants, m, &lookup, now),
            Some(CollectionAccess::Write)
        );
        assert_eq!(
            effective_access(&grants, Uuid::new_v4(), &lookup, now),
            None
        );
    }
}
