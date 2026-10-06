//! S3-6 request-access JIT: HPKE-sealed collection-access asks plus the
//! optional plaintext collection catalog (plan §4.7 item 3, §4.2).
//!
//! A member asks for access by writing `meta/members/<own>/requests/<id>.json`.
//! The members own-subtree policy row makes that self-service at any role,
//! and another member's subtree stays admin-only, so approvals and denials
//! (which delete the file) are admin commits by construction. The ask's
//! free-text note is HPKE-sealed to the approver set (live Owner/Admin rows
//! carrying an identity wrap pubkey); the collection id and requested access
//! ride as plaintext (plan rule: plaintext is UUIDs + names + trust) but are
//! bound INSIDE the sealed payload too, so an admin decrypting a tampered
//! file sees the mismatch and counts the file inert instead of granting what
//! the plaintext claims.
//!
//! The catalog at `meta/collections/catalog.json` is the plan's explicit
//! opt-in setting: publishing it exposes display names to requesters, whose
//! only other view of a collection is an opaque id. It lives inside the
//! collections directory so the existing `meta/collections/**` Admin policy
//! row gates it and the UUID-stem walkers skip it inert.

use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::SpaceGroupKey;
use crate::vault::collections::{CollectionAccess, CollectionFile, list_collections};
use crate::vault::members;
use crate::vault::write_vault_file;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Cap on one request file on read (git-tracked files can arrive large).
pub const MAX_REQUEST_FILE_BYTES: usize = 64 * 1024;
/// Pending asks per member. A member can spam nobody but themself, but the
/// inbox walks every member's directory: bounded, not unbounded.
pub const MAX_REQUESTS_PER_MEMBER: usize = 20;
/// Cap on the free-text note (chars).
pub const MAX_NOTE_CHARS: usize = 500;
/// Cap on catalog rows (mirrors the collection-directory scale).
pub const MAX_CATALOG_ENTRIES: usize = 256;
/// Inbox rows returned before the walker stops (malformed are still counted).
pub const MAX_INBOX_ROWS: usize = 200;
/// Cap on the catalog file on read.
pub const MAX_CATALOG_FILE_BYTES: usize = 256 * 1024;

const REQUEST_FORMAT: u32 = 1;
const CATALOG_FORMAT: u32 = 1;
const REQUESTS_SUBDIR: &str = "requests";
const CATALOG_STEM: &str = "catalog";
/// HPKE context for the per-approver payload-key wraps: bound to the
/// request AND the approver, so a seal transplanted onto another request
/// (or another approver's slot) fails the unwrap.
const WRAP_CONTEXT_PREFIX: &str = "collection-request-v1";
/// AES-GCM purpose for the sealed payload blob.
const PAYLOAD_PURPOSE_PREFIX: &str = "collection-request-payload-v1";

fn deny(msg: &str) -> BaluardError {
    VaultError::InvalidOperation(msg.to_string()).into()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn requests_dir(vault_path: &Path, member_id: &Uuid) -> PathBuf {
    vault_path
        .join(members::MEMBERS_DIR)
        .join(member_id.to_string())
        .join(REQUESTS_SUBDIR)
}

fn request_path(vault_path: &Path, member_id: &Uuid, request_id: &Uuid) -> PathBuf {
    requests_dir(vault_path, member_id).join(format!("{request_id}.json"))
}

fn request_wrap_context(request_id: &Uuid, requester: &Uuid, approver_id: &Uuid) -> String {
    // The requester is bound into the HPKE context AND the sealed payload:
    // a pending file copied into another member's requests directory
    // (their own subtree is self-service) fails the unwrap instead of
    // redirecting the grant (review F2).
    format!("{WRAP_CONTEXT_PREFIX}/{request_id}/{requester}/{approver_id}")
}

fn payload_purpose(request_id: &Uuid) -> String {
    format!("{PAYLOAD_PURPOSE_PREFIX}/{request_id}")
}

/// One approver's HPKE wrap of the request's payload key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSeal {
    pub member_id: Uuid,
    pub ephemeral_public: String,
    pub encrypted_key: String,
    pub tag: String,
}

/// The git-tracked ask. `collection_id` and `access` are plaintext (UUID +
/// enum per the metadata-hygiene rule) but MUST equal their sealed copies:
/// `open_request` refuses a mismatch so a tampered file reads as inert
/// instead of granting what the plaintext claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestFile {
    pub format: u32,
    pub id: Uuid,
    pub created_at: u64,
    pub collection_id: Uuid,
    pub access: CollectionAccess,
    pub seals: Vec<RequestSeal>,
    /// Sealed `{collection_id, access, note}` blob.
    pub payload_enc: serde_json::Value,
}

/// One inbox row (admin view, payload decrypted).
#[derive(Debug, Clone, Serialize)]
pub struct AccessRequestRow {
    pub request_id: Uuid,
    pub requester_member_id: Uuid,
    pub requester_name: String,
    pub collection_id: Uuid,
    /// Decrypted display name; `None` when the collection was deleted
    /// after the ask (the ask itself stays deniable).
    pub collection_name: Option<String>,
    pub access: CollectionAccess,
    pub note: String,
    pub created_at: u64,
}

/// A member's own pending ask (plaintext fields only: the member holds no
/// seal on their own request).
#[derive(Debug, Clone, Serialize)]
pub struct OwnRequestRow {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub access: CollectionAccess,
    pub created_at: u64,
}

/// One catalog row: the plan's plaintext-id list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub collection_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogFile {
    pub format: u32,
    pub updated_at: u64,
    pub entries: Vec<CatalogEntry>,
}

fn catalog_path(vault_path: &Path) -> PathBuf {
    vault_path
        .join("meta/collections")
        .join(format!("{CATALOG_STEM}.json"))
}

/// The approver set: live (non-tombstoned) Owner/Admin rows carrying a
/// non-empty identity wrap pubkey, sorted by member id for determinism.
pub fn approver_set(vault_path: &Path) -> Vec<(Uuid, String)> {
    let mut out: Vec<(Uuid, String)> = members::list_members(vault_path)
        .unwrap_or_default()
        .into_iter()
        .filter(|row| {
            row.removed.is_none()
                && row.reset.is_none()
                && matches!(
                    row.role,
                    members::MemberRole::Owner | members::MemberRole::Admin
                )
        })
        .filter_map(|row| {
            row.identity_wrap_pubkey
                .filter(|w| !w.is_empty())
                .map(|w| (row.id, w))
        })
        .collect();
    out.sort_by_key(|(id, _)| *id);
    out
}

fn validate_note(note: &str) -> Result<String, BaluardError> {
    // Line discipline: the note renders as one inbox line (the same rule
    // as names on the People and join-queue surfaces).
    if note.contains(['\n', '\r']) {
        return Err(deny("A note cannot contain line breaks."));
    }
    let trimmed = note.trim();
    if trimmed.chars().count() > MAX_NOTE_CHARS {
        return Err(deny("That note is too long."));
    }
    Ok(trimmed.to_string())
}

/// True when `held` already covers `asked` (Read < Write < Manage).
fn covers(held: CollectionAccess, asked: CollectionAccess) -> bool {
    use CollectionAccess::{Manage, Read, Write};
    matches!(
        (held, asked),
        (Read, Read) | (Write, Read) | (Write, Write) | (Manage, _)
    )
}

/// Submit a JIT ask. The caller resolves the requester's member id and the
/// target collection (it must exist); this fn validates the rest and writes
/// the git-tracked file. Returns the request id.
pub fn submit_request(
    vault_path: &Path,
    requester: Uuid,
    collection: &CollectionFile,
    access: CollectionAccess,
    note: &str,
) -> Result<Uuid, BaluardError> {
    if access == CollectionAccess::Manage {
        // Manage is delegated-admin power; the askable set is read/write.
        // Self-service admin powers via the inbox would be a policy smell.
        return Err(deny("Manage access cannot be requested."));
    }
    // A Viewer holding a write grant can never author the commits that
    // access implies (the git policy's Editor floor), so a write ask from
    // a Viewer is unmintable at approval (review F4) and must not sit in
    // the inbox as a permanent stub.
    if access == CollectionAccess::Write {
        let requester_role = members::member_file_by_id(vault_path, requester)
            .filter(|row| row.removed.is_none() && row.reset.is_none())
            .map(|row| row.role)
            .ok_or_else(|| deny("That person is not an active member of this vault."))?;
        if requester_role == members::MemberRole::Viewer {
            return Err(deny("Viewers cannot request write access to a collection."));
        }
    }
    // Asking for access the member already holds (live, covering the
    // request) is refused: the admin inbox stays an inbox, not a mirror
    // of the grant list (review F4). An EXPIRED grant lapses and may be
    // re-asked. Group grants count as held access — a member covered
    // through their group has no ask to make.
    let held = crate::vault::groups::effective_access(
        &collection.grants,
        requester,
        &|gid| {
            crate::vault::collections::load_group_memberships(vault_path)
                .into_iter()
                .find(|(id, _)| *id == gid)
                .map(|(_, ms)| ms)
        },
        now_secs(),
    );
    if held.is_some_and(|h| covers(h, access)) {
        return Err(deny("You already have access to this collection."));
    }
    let note = validate_note(note)?;
    let request_id = Uuid::new_v4();
    let dir = requests_dir(vault_path, &requester);
    if dir.exists() && std::fs::read_dir(&dir)?.count() >= MAX_REQUESTS_PER_MEMBER {
        return Err(deny(
            "You already have too many pending requests. Withdraw one first.",
        ));
    }
    // One pending ask per collection: re-asking cannot reach anyone faster
    // than the first one.
    if list_own_requests(vault_path, requester)?
        .iter()
        .any(|r| r.collection_id == collection.id)
    {
        return Err(deny(
            "You already have a pending request for this collection.",
        ));
    }
    let approvers = approver_set(vault_path);
    if approvers.is_empty() {
        return Err(deny(
            "No administrator on this vault can receive access requests.",
        ));
    }
    let mut payload_key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, payload_key.as_mut());
    let payload = serde_json::json!({
        "collection_id": collection.id,
        "access": access,
        "note": note,
        "requester": requester,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| VaultError::Metadata(format!("request serialize: {e}")))?;
    let sealed = crate::secret_file::seal_secret_blob(
        &payload_key,
        &payload_bytes,
        &payload_purpose(&request_id),
    )?;
    let payload_enc: serde_json::Value = serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("request envelope: {e}")))?;
    let mut seals = Vec::with_capacity(approvers.len());
    for (approver_id, wrap_pub_hex) in &approvers {
        let recip = x25519_dalek::PublicKey::from(crate::vault::collections::wrap_pubkey_bytes(
            wrap_pub_hex,
        )?);
        let (eph, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            payload_key.as_slice(),
            &recip,
            &request_wrap_context(&request_id, &requester, approver_id),
        )?;
        seals.push(RequestSeal {
            member_id: *approver_id,
            ephemeral_public: hex::encode(eph),
            encrypted_key: hex::encode(ct),
            tag: hex::encode(tag),
        });
    }
    let file = AccessRequestFile {
        format: REQUEST_FORMAT,
        id: request_id,
        created_at: now_secs(),
        collection_id: collection.id,
        access,
        seals,
        payload_enc,
    };
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| VaultError::Metadata(format!("request serialize: {e}")))?;
    write_vault_file(&request_path(vault_path, &requester, &request_id), &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write request: {e}"))))?;
    Ok(request_id)
}

/// The member's own pending asks (malformed rows skipped inert). Outcome
/// visibility rides the grant list, not these rows: a consumed request
/// means "decided", and `collections.list` shows what was granted.
pub fn list_own_requests(
    vault_path: &Path,
    requester: Uuid,
) -> Result<Vec<OwnRequestRow>, BaluardError> {
    let dir = requests_dir(vault_path, &requester);
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(stem) else {
            continue;
        };
        if let Ok(file) = read_request_file(&path) {
            out.push(OwnRequestRow {
                id,
                collection_id: file.collection_id,
                access: file.access,
                created_at: file.created_at,
            });
        }
    }
    out.sort_by_key(|r| r.created_at);
    Ok(out)
}

/// Remove one of the member's own pending asks.
pub fn withdraw_request(
    vault_path: &Path,
    requester: Uuid,
    request_id: Uuid,
) -> Result<(), BaluardError> {
    remove_request_file(
        &request_path(vault_path, &requester, &request_id),
        request_id,
    )
}

fn remove_request_file(path: &Path, request_id: Uuid) -> Result<(), BaluardError> {
    std::fs::remove_file(path)
        .map_err(|_| deny(&format!("That request ({request_id}) no longer exists.")))
}

fn read_request_file(path: &Path) -> Result<AccessRequestFile, BaluardError> {
    let bytes = std::fs::read(path).map_err(|_| deny("That request no longer exists."))?;
    if bytes.len() > MAX_REQUEST_FILE_BYTES {
        return Err(deny("That request file is too large."));
    }
    let file: AccessRequestFile =
        serde_json::from_slice(&bytes).map_err(|_| deny("That request file is damaged."))?;
    if file.format != REQUEST_FORMAT {
        return Err(deny("Unsupported request format."));
    }
    Ok(file)
}

/// Decrypt one request with the approver's own identity wrapping secret and
/// verify the sealed payload against the plaintext fields. Returns the
/// requested access and note. `requester` is the member id the FILE lives
/// under (the grant target) and must equal the sealed copy: everything the
/// approval grants is pinned to the seal, never to untrusted plaintext.
fn open_request(
    file: &AccessRequestFile,
    requester: Uuid,
    approver: Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Result<(CollectionAccess, String), BaluardError> {
    // Manage is never askable (refused at submit), so a crafted file that
    // claims manage is tampering: refuse before any crypto runs. Approval
    // cannot mint delegated-admin powers from the inbox (review F1).
    if file.access == CollectionAccess::Manage {
        return Err(deny("Manage access cannot be requested."));
    }
    let seal = file
        .seals
        .iter()
        .find(|s| s.member_id == approver)
        .ok_or_else(|| deny("That request is not addressed to you."))?;
    let hex_field = |v: &str, what: &str| -> Result<Vec<u8>, BaluardError> {
        hex::decode(v).map_err(|_| deny(&format!("That request is damaged ({what}).")))
    };
    let eph = hex_field(&seal.ephemeral_public, "seal")?;
    let ct = hex_field(&seal.encrypted_key, "seal")?;
    let tag: [u8; 16] = hex_field(&seal.tag, "seal")?
        .try_into()
        .map_err(|_| deny("That request is damaged (seal)."))?;
    let key: [u8; 32] = crate::crypto::hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        wrapping_secret,
        &request_wrap_context(&file.id, &requester, &approver),
    )
    .map_err(|_| deny("That request cannot be read."))?
    .try_into()
    .map_err(|_| deny("That request cannot be read."))?;
    let key = Zeroizing::new(key);
    let envelope = serde_json::to_vec(&file.payload_enc)
        .map_err(|e| VaultError::Metadata(format!("request envelope: {e}")))?;
    let pt = crate::secret_file::open_secret_blob(&key, &envelope, &payload_purpose(&file.id))
        .map_err(|_| deny("That request cannot be read."))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&pt).map_err(|_| deny("That request is damaged."))?;
    let sealed_collection: Uuid = serde_json::from_value(payload["collection_id"].clone())
        .map_err(|_| deny("That request is damaged."))?;
    let sealed_access: CollectionAccess = serde_json::from_value(payload["access"].clone())
        .map_err(|_| deny("That request is damaged."))?;
    let sealed_requester: Uuid = serde_json::from_value(payload["requester"].clone())
        .map_err(|_| deny("That request is damaged."))?;
    // Line discipline applies to the SEALED note too: the requester seals
    // their own ask, so a crafted note must not smuggle line breaks into
    // the inbox (review F7).
    let note = validate_note(payload["note"].as_str().unwrap_or_default())?;
    // Plaintext vs sealed agreement: a repo-writer who flips the plaintext
    // access (or retargets the collection or the requester) makes the file
    // inert rather than granting the tampered claim.
    if sealed_collection != file.collection_id
        || sealed_access != file.access
        || sealed_requester != requester
    {
        return Err(deny(
            "That request file does not match its sealed contents.",
        ));
    }
    Ok((file.access, note))
}

/// The admin inbox: every decryptable pending ask across all members, plus
/// a count of files that were malformed, oversized, unaddressed to this
/// approver, or tampered (inert by design). Sorted oldest first.
pub fn list_inbox(
    vault_path: &Path,
    approver: Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
    sgk: &SpaceGroupKey,
) -> Result<(Vec<AccessRequestRow>, usize), BaluardError> {
    let members_dir = vault_path.join(members::MEMBERS_DIR);
    let names: Vec<(Uuid, String)> = list_collections(vault_path, sgk)?
        .into_iter()
        .map(|(f, name)| (f.id, name))
        .collect();
    let mut rows = Vec::new();
    let mut malformed = 0usize;
    if !members_dir.is_dir() {
        return Ok((rows, malformed));
    }
    // Deterministic order + a per-member pending cap in the WALK: commit
    // verification cannot enforce the submit-side caps (clock-free by
    // design), so a crafted flood must not reorder or starve the inbox
    // (review F3). Files beyond the per-member cap count as inert.
    let mut member_dirs: Vec<(Uuid, PathBuf)> = std::fs::read_dir(&members_dir)?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let dir = path.join(REQUESTS_SUBDIR);
            if !dir.is_dir() {
                return None;
            }
            let stem = path.file_stem()?.to_str()?;
            Uuid::parse_str(stem).ok().map(|id| (id, dir))
        })
        .collect();
    member_dirs.sort_by_key(|(id, _)| *id);
    'members: for (requester, dir) in member_dirs {
        let mut per_member = 0usize;
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        files.sort();
        for path in files {
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(request_id) = Uuid::parse_str(stem) else {
                malformed += 1;
                continue;
            };
            per_member += 1;
            if per_member > MAX_REQUESTS_PER_MEMBER {
                malformed += 1;
                continue;
            }
            let file = match read_request_file(&path) {
                Ok(f) if f.id == request_id => f,
                _ => {
                    malformed += 1;
                    continue;
                }
            };
            let (access, note) = match open_request(&file, requester, approver, wrapping_secret) {
                Ok(ok) => ok,
                Err(_) => {
                    malformed += 1;
                    continue;
                }
            };
            let requester_name = members::member_file_by_id(vault_path, requester)
                .map(|m| m.display_name)
                .unwrap_or_else(|| "unknown".into());
            let collection_name = names
                .iter()
                .find(|(id, _)| *id == file.collection_id)
                .map(|(_, n)| n.clone());
            rows.push(AccessRequestRow {
                request_id: file.id,
                requester_member_id: requester,
                requester_name,
                collection_id: file.collection_id,
                collection_name,
                access,
                note,
                created_at: file.created_at,
            });
            if rows.len() >= MAX_INBOX_ROWS {
                break 'members;
            }
        }
    }
    rows.sort_by_key(|r| r.created_at);
    Ok((rows, malformed))
}

/// Read + decrypt one request for approval. The approve path re-derives the
/// row from the sealed payload, so the grant follows the ASK, never a
/// client-supplied claim.
pub fn open_inbox_row(
    vault_path: &Path,
    requester: Uuid,
    request_id: Uuid,
    approver: Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
    sgk: &SpaceGroupKey,
) -> Result<AccessRequestRow, BaluardError> {
    let file = read_request_file(&request_path(vault_path, &requester, &request_id))?;
    if file.id != request_id {
        return Err(deny("That request file is damaged."));
    }
    let (access, note) = open_request(&file, requester, approver, wrapping_secret)?;
    let requester_name = members::member_file_by_id(vault_path, requester)
        .map(|m| m.display_name)
        .unwrap_or_else(|| "unknown".into());
    let collection_name = list_collections(vault_path, sgk).ok().and_then(|rows| {
        rows.into_iter()
            .find(|(f, _)| f.id == file.collection_id)
            .map(|(_, n)| n)
    });
    Ok(AccessRequestRow {
        request_id: file.id,
        requester_member_id: requester,
        requester_name,
        collection_id: file.collection_id,
        collection_name,
        access,
        note,
        created_at: file.created_at,
    })
}

/// Remove a decided ask (approval or denial consumes it; a missing file is
/// a refusal so a double-approve cannot look like success).
pub fn consume_request(
    vault_path: &Path,
    requester: Uuid,
    request_id: Uuid,
) -> Result<(), BaluardError> {
    remove_request_file(
        &request_path(vault_path, &requester, &request_id),
        request_id,
    )
}

fn validate_catalog_name(name: &str) -> Result<String, BaluardError> {
    if name.contains(['\n', '\r']) {
        return Err(deny("A catalog name cannot contain line breaks."));
    }
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(deny("Give every catalog row a name."));
    }
    if trimmed.chars().count() > crate::vault::collections::MAX_NAME_CHARS {
        return Err(deny("That catalog name is too long."));
    }
    Ok(trimmed.to_string())
}

/// Publish (or replace, or clear) the plaintext catalog. This IS the plan's
/// opt-in setting: an absent catalog file means requesters see opaque ids.
/// Rows referencing unknown collections are refused at publish time so a
/// typo cannot silently publish a dead row.
pub fn catalog_set(
    vault_path: &Path,
    sgk: &SpaceGroupKey,
    entries: Vec<CatalogEntry>,
) -> Result<(), BaluardError> {
    if entries.len() > MAX_CATALOG_ENTRIES {
        return Err(deny("That catalog has too many rows."));
    }
    let known: Vec<Uuid> = list_collections(vault_path, sgk)?
        .into_iter()
        .map(|(f, _)| f.id)
        .collect();
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = validate_catalog_name(&entry.name)?;
        if !known.contains(&entry.collection_id) {
            return Err(deny(
                "That catalog row names a collection that does not exist.",
            ));
        }
        if !seen.insert(entry.collection_id) {
            return Err(deny("The catalog has duplicate rows for one collection."));
        }
        cleaned.push(CatalogEntry {
            collection_id: entry.collection_id,
            name,
        });
    }
    if cleaned.is_empty() {
        // Empty publish = unpublish (the opt-out).
        match std::fs::remove_file(catalog_path(vault_path)) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(BaluardError::from(VaultError::Metadata(format!(
                    "remove catalog: {e}"
                ))));
            }
        }
    }
    let file = CatalogFile {
        format: CATALOG_FORMAT,
        updated_at: now_secs(),
        entries: cleaned,
    };
    let bytes = serde_json::to_vec_pretty(&file)
        .map_err(|e| VaultError::Metadata(format!("catalog serialize: {e}")))?;
    write_vault_file(&catalog_path(vault_path), &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write catalog: {e}"))))?;
    Ok(())
}

/// The catalog as requesters see it. Missing file = the org has not opted
/// in = empty. A damaged file is inert-empty, oversized files truncate,
/// and rows whose collection no longer exists are dropped: a stale row
/// must not invite asks the admin cannot coherently approve (review F8).
/// A tampered catalog can only mislabel asks, never grant anything.
pub fn catalog_list(vault_path: &Path) -> Vec<CatalogEntry> {
    let Ok(bytes) = std::fs::read(catalog_path(vault_path)) else {
        return Vec::new();
    };
    if bytes.len() > MAX_CATALOG_FILE_BYTES {
        return Vec::new();
    }
    let Ok(file) = serde_json::from_slice::<CatalogFile>(&bytes) else {
        return Vec::new();
    };
    if file.format != CATALOG_FORMAT {
        return Vec::new();
    }
    file.entries
        .into_iter()
        .take(MAX_CATALOG_ENTRIES)
        .filter(|e| validate_catalog_name(&e.name).is_ok())
        .filter(|e| {
            crate::vault::collections::collections_file_path(vault_path, &e.collection_id).exists()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::hierarchy::SpaceGroupKey;
    use crate::vault::collections;

    fn temp_vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    fn member_row(
        id: Uuid,
        role: members::MemberRole,
        wrap: Option<String>,
    ) -> members::MemberFile {
        members::MemberFile {
            id,
            display_name: "Alicia".into(),
            email: None,
            role,
            trust: members::TrustLevel::Verified,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: wrap,
        }
    }

    fn approver_identity(byte: u8) -> crate::vault::identity::IdentityKeys {
        crate::vault::identity::IdentityKeys::from_seed(&[byte; 32])
    }

    fn owner_with_key() -> (Uuid, String, crate::vault::identity::IdentityKeys) {
        let id = Uuid::new_v4();
        let keys = approver_identity(0x11);
        let wrap = hex::encode(keys.wrapping_pub_bytes());
        (id, wrap, keys)
    }

    fn seeded_collection(path: &Path, sgk: &SpaceGroupKey) -> CollectionFile {
        collections::create_collection(path, sgk, "Servers").unwrap()
    }

    #[test]
    fn submit_and_inbox_roundtrip() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (owner_id, wrap, keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();

        let req_id = submit_request(
            &path,
            requester,
            &collection,
            CollectionAccess::Read,
            "please add me to the servers",
        )
        .unwrap();

        // Own view: one pending row, plaintext fields only.
        let mine = list_own_requests(&path, requester).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, req_id);
        assert_eq!(mine[0].collection_id, collection.id);

        // Approver view: decrypted, with names attached.
        let (rows, malformed) = list_inbox(&path, owner_id, keys.wrapping_secret(), &sgk).unwrap();
        assert_eq!(malformed, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request_id, req_id);
        assert_eq!(rows[0].requester_name, "Alicia");
        assert_eq!(rows[0].collection_name.as_deref(), Some("Servers"));
        assert_eq!(rows[0].access, CollectionAccess::Read);
        assert_eq!(rows[0].note, "please add me to the servers");
    }

    #[test]
    fn approve_grants_and_consumes() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (owner_id, wrap, keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        // The requester carries a wrap pubkey so the grant mints a wrap.
        let (requester, rwrap, rkeys) = {
            let id = Uuid::new_v4();
            let keys = approver_identity(0x22);
            (id, hex::encode(keys.wrapping_pub_bytes()), keys)
        };
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, Some(rwrap)),
        )
        .unwrap();
        let req_id = submit_request(
            &path,
            requester,
            &collection,
            CollectionAccess::Read,
            "need in",
        )
        .unwrap();

        // The admin re-derives the row from the sealed ask, then grants.
        let row = open_inbox_row(
            &path,
            requester,
            req_id,
            owner_id,
            keys.wrapping_secret(),
            &sgk,
        )
        .unwrap();
        // Access override: asked read, granted write (the admin decides).
        collections::upsert_grant(
            &path,
            &sgk,
            &row.collection_id,
            collections::CollectionGrant {
                target: collections::GrantTarget::Member { id: requester },
                access: CollectionAccess::Write,
                expires_at: None,
            },
        )
        .unwrap();
        consume_request(&path, requester, req_id).unwrap();

        let (file, _) = collections::open_collection(&path, &sgk, &collection.id).unwrap();
        assert_eq!(file.grants.len(), 1);
        assert_eq!(file.grants[0].access, CollectionAccess::Write);
        assert!(list_own_requests(&path, requester).unwrap().is_empty());
        // The per-member CK wrap was minted and opens to the SAME key the
        // SGK path yields.
        let via_wrap = collections::open_grant_wrap(
            &path,
            &collection.id,
            &requester,
            rkeys.wrapping_secret(),
        )
        .unwrap();
        let cks = collections::collect_content_keys(&path, &sgk).unwrap();
        let (_, ck) = cks.iter().find(|(id, _)| *id == collection.id).unwrap();
        assert_eq!(via_wrap.as_ref(), ck.as_ref());
    }

    #[test]
    fn deny_and_withdraw_consume_without_grant() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let a = seeded_collection(&path, &sgk);
        let b = collections::create_collection(&path, &sgk, "Finance").unwrap();
        let (owner_id, wrap, _keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Viewer, None),
        )
        .unwrap();

        let denied = submit_request(&path, requester, &a, CollectionAccess::Read, "x").unwrap();
        let withdrawn = submit_request(&path, requester, &b, CollectionAccess::Read, "y").unwrap();

        // Admin deny: file gone, no grant.
        consume_request(&path, requester, denied).unwrap();
        // Member withdraw: same.
        withdraw_request(&path, requester, withdrawn).unwrap();
        assert!(list_own_requests(&path, requester).unwrap().is_empty());
        for col in [&a, &b] {
            let (f, _) = collections::open_collection(&path, &sgk, &col.id).unwrap();
            assert!(f.grants.is_empty());
        }
        // Double-consume is a refusal, never a silent success.
        assert!(consume_request(&path, requester, denied).is_err());
    }

    #[test]
    fn submission_refusals() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (owner_id, wrap, _keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();

        // Manage is not askable.
        assert!(
            submit_request(&path, requester, &collection, CollectionAccess::Manage, "").is_err()
        );
        // Note line discipline + length cap.
        assert!(
            submit_request(
                &path,
                requester,
                &collection,
                CollectionAccess::Read,
                "two\nlines"
            )
            .is_err()
        );
        assert!(
            submit_request(&path, requester, &collection, CollectionAccess::Read, "\r").is_err()
        );
        let long = "x".repeat(MAX_NOTE_CHARS + 1);
        assert!(
            submit_request(&path, requester, &collection, CollectionAccess::Read, &long).is_err()
        );

        // Dedupe: one pending ask per collection; a second collection is fine.
        submit_request(&path, requester, &collection, CollectionAccess::Read, "").unwrap();
        assert!(
            submit_request(
                &path,
                requester,
                &collection,
                CollectionAccess::Read,
                "again"
            )
            .is_err()
        );
        let other = collections::create_collection(&path, &sgk, "Other").unwrap();
        submit_request(&path, requester, &other, CollectionAccess::Read, "").unwrap();

        // An existing live grant that COVERS the ask refuses. This uses a
        // clean collection (no pending ask) so the refusal is the grant
        // check, not dedupe (review F4 masking).
        let held = collections::create_collection(&path, &sgk, "Held").unwrap();
        collections::upsert_grant(
            &path,
            &sgk,
            &held.id,
            collections::CollectionGrant {
                target: collections::GrantTarget::Member { id: requester },
                access: CollectionAccess::Read,
                expires_at: None,
            },
        )
        .unwrap();
        // Re-open: the grant check must see the ON-DISK grant list.
        let (held_now, _) = collections::open_collection(&path, &sgk, &held.id).unwrap();
        assert!(
            submit_request(&path, requester, &held_now, CollectionAccess::Read, "again").is_err()
        );
        // An UPGRADE ask (read held, write requested) is legitimate.
        submit_request(&path, requester, &held_now, CollectionAccess::Write, "bump").unwrap();
        // An EXPIRED grant lapses: re-asking is allowed. upsert_grant
        // refuses past-dated expiries by design, so plant the lapsed
        // grant directly in the file.
        let lapsed = collections::create_collection(&path, &sgk, "Lapsed").unwrap();
        let (mut lapsed_file, _) = collections::open_collection(&path, &sgk, &lapsed.id).unwrap();
        lapsed_file.grants.push(collections::CollectionGrant {
            target: collections::GrantTarget::Member { id: requester },
            access: CollectionAccess::Read,
            expires_at: Some(1),
        });
        collections::save_collection(&path, &lapsed_file).unwrap();
        let (lapsed_file, _) = collections::open_collection(&path, &sgk, &lapsed.id).unwrap();
        submit_request(
            &path,
            requester,
            &lapsed_file,
            CollectionAccess::Read,
            "renew",
        )
        .unwrap();

        // A Viewer cannot ask for write (unmintable at approval; review F4).
        let viewer = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(viewer, members::MemberRole::Viewer, None),
        )
        .unwrap();
        assert!(
            submit_request(
                &path,
                viewer,
                &collection,
                CollectionAccess::Write,
                "sneaky"
            )
            .is_err()
        );
        // A Viewer CAN ask for read.
        submit_request(&path, viewer, &collection, CollectionAccess::Read, "hi").unwrap();
    }

    #[test]
    fn crafted_manage_and_transplanted_files_are_inert() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (owner_id, wrap, keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let (mallory, _mwrap, _mkeys) = {
            let id = Uuid::new_v4();
            let keys = approver_identity(0x66);
            (id, hex::encode(keys.wrapping_pub_bytes()), keys)
        };
        members::write_member(
            &path,
            &member_row(mallory, members::MemberRole::Editor, None),
        )
        .unwrap();

        let req_id =
            submit_request(&path, mallory, &collection, CollectionAccess::Read, "").unwrap();
        let fpath = request_path(&path, &mallory, &req_id);

        // Transplant: copy a pending ask into another member's requests
        // directory (their own subtree is self-service at the git layer).
        // The seals bind the requester, so the copy is inert and the grant
        // can never follow the copy instead of the asker (review F2).
        let second = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(second, members::MemberRole::Editor, None),
        )
        .unwrap();
        std::fs::create_dir_all(requests_dir(&path, &second)).unwrap();
        std::fs::copy(&fpath, request_path(&path, &second, &req_id)).unwrap();
        let (rows, malformed) = list_inbox(&path, owner_id, keys.wrapping_secret(), &sgk).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requester_member_id, mallory);
        assert_eq!(malformed, 1);
        assert!(
            open_inbox_row(
                &path,
                second,
                req_id,
                owner_id,
                keys.wrapping_secret(),
                &sgk
            )
            .is_err()
        );

        // Crafted manage ask: a hostile member can seal to the approvers'
        // PUBLIC wrap keys, so the opener refuses the manage claim on the
        // plaintext field before any approval could mint it (review F1).
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fpath).unwrap()).unwrap();
        doc["access"] = serde_json::json!("manage");
        std::fs::write(&fpath, serde_json::to_vec(&doc).unwrap()).unwrap();
        let (rows, malformed) = list_inbox(&path, owner_id, keys.wrapping_secret(), &sgk).unwrap();
        assert!(rows.is_empty());
        assert_eq!(malformed, 2, "tampered manage ask + the transplant");
    }

    #[test]
    fn per_member_pending_cap() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let (owner_id, wrap, _keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();
        for i in 0..MAX_REQUESTS_PER_MEMBER {
            let c = collections::create_collection(&path, &sgk, &format!("c{i}")).unwrap();
            submit_request(&path, requester, &c, CollectionAccess::Read, "").unwrap();
        }
        let one_more = collections::create_collection(&path, &sgk, "overflow").unwrap();
        assert!(submit_request(&path, requester, &one_more, CollectionAccess::Read, "").is_err());
    }

    #[test]
    fn tampered_plaintext_is_inert() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (owner_id, wrap, keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();
        let req_id =
            submit_request(&path, requester, &collection, CollectionAccess::Read, "").unwrap();

        // Flip the plaintext access read -> write (what a repo-writer with
        // no keys could try). The sealed copy still says read.
        let fpath = request_path(&path, &requester, &req_id);
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fpath).unwrap()).unwrap();
        doc["access"] = serde_json::json!("write");
        std::fs::write(&fpath, serde_json::to_vec(&doc).unwrap()).unwrap();

        let (rows, malformed) = list_inbox(&path, owner_id, keys.wrapping_secret(), &sgk).unwrap();
        assert!(rows.is_empty());
        assert_eq!(malformed, 1);
        // Approval re-derivation refuses too (never grant the tampered claim).
        assert!(
            open_inbox_row(
                &path,
                requester,
                req_id,
                owner_id,
                keys.wrapping_secret(),
                &sgk
            )
            .is_err()
        );
    }

    #[test]
    fn unaddressed_seal_is_inert_not_fatal() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        let (a_id, a_wrap, a_keys) = owner_with_key();
        let (b_id, b_wrap, b_keys) = {
            let id = Uuid::new_v4();
            let keys = approver_identity(0x33);
            (id, hex::encode(keys.wrapping_pub_bytes()), keys)
        };
        members::write_member(
            &path,
            &member_row(a_id, members::MemberRole::Admin, Some(a_wrap)),
        )
        .unwrap();
        members::write_member(
            &path,
            &member_row(b_id, members::MemberRole::Admin, Some(b_wrap)),
        )
        .unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();
        submit_request(&path, requester, &collection, CollectionAccess::Read, "").unwrap();

        // Both approvers see it (the ask was sealed to the whole set).
        for (id, keys) in [(a_id, &a_keys), (b_id, &b_keys)] {
            let (rows, malformed) = list_inbox(&path, id, keys.wrapping_secret(), &sgk).unwrap();
            assert_eq!(rows.len(), 1, "approver {id} must see the ask");
            assert_eq!(malformed, 0);
        }

        // A non-approver identity holds no seal: their inbox counts the
        // file inert instead of erroring or revealing anything.
        let stranger = approver_identity(0x44);
        let (rows, malformed) =
            list_inbox(&path, Uuid::new_v4(), stranger.wrapping_secret(), &sgk).unwrap();
        assert!(rows.is_empty());
        assert_eq!(malformed, 1);
    }

    #[test]
    fn approver_set_skips_tombstoned_and_nonadmins() {
        let (_d, path) = temp_vault();
        let (owner_id, wrap, _keys) = owner_with_key();
        members::write_member(
            &path,
            &member_row(owner_id, members::MemberRole::Owner, Some(wrap.clone())),
        )
        .unwrap();
        let admin_removed = Uuid::new_v4();
        let mut removed = member_row(
            admin_removed,
            members::MemberRole::Admin,
            Some("aa".repeat(32)),
        );
        removed.removed = Some(0);
        members::write_member(&path, &removed).unwrap();
        let editor = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(editor, members::MemberRole::Editor, Some("bb".repeat(32))),
        )
        .unwrap();
        let admin_no_key = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(admin_no_key, members::MemberRole::Admin, None),
        )
        .unwrap();
        let set = approver_set(&path);
        assert_eq!(set, vec![(owner_id, wrap)]);
    }

    #[test]
    fn no_approvers_refuses_submit() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let collection = seeded_collection(&path, &sgk);
        // Owner row WITHOUT a wrap pubkey (pre-P1 legacy row): no reachable
        // approver, so the ask must refuse instead of writing dead mail.
        let owner = Uuid::new_v4();
        members::write_member(&path, &member_row(owner, members::MemberRole::Owner, None)).unwrap();
        let requester = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(requester, members::MemberRole::Editor, None),
        )
        .unwrap();
        assert!(submit_request(&path, requester, &collection, CollectionAccess::Read, "").is_err());
    }

    #[test]
    fn catalog_publish_clear_and_validation() {
        let (_d, path) = temp_vault();
        let sgk = SpaceGroupKey::generate(1);
        let a = seeded_collection(&path, &sgk);
        let b = collections::create_collection(&path, &sgk, "Finance").unwrap();
        let ghost = Uuid::new_v4();

        // Unknown collection refused at publish.
        assert!(
            catalog_set(
                &path,
                &sgk,
                vec![CatalogEntry {
                    collection_id: ghost,
                    name: "Ghost".into()
                }]
            )
            .is_err()
        );

        catalog_set(
            &path,
            &sgk,
            vec![
                CatalogEntry {
                    collection_id: b.id,
                    name: "  Finance  ".into(),
                },
                CatalogEntry {
                    collection_id: a.id,
                    name: "Servers".into(),
                },
            ],
        )
        .unwrap();
        let listed = catalog_list(&path);
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&CatalogEntry {
            collection_id: b.id,
            name: "Finance".into()
        }));

        // Duplicate rows refused.
        assert!(
            catalog_set(
                &path,
                &sgk,
                vec![
                    CatalogEntry {
                        collection_id: a.id,
                        name: "Servers".into()
                    },
                    CatalogEntry {
                        collection_id: a.id,
                        name: "Servers 2".into()
                    },
                ]
            )
            .is_err()
        );

        // Empty publish = the opt-out.
        catalog_set(&path, &sgk, vec![]).unwrap();
        assert!(catalog_list(&path).is_empty());
    }
}
