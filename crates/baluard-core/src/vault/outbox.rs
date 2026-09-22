//! S2 IS-4b / plan §4.6 row C: per-recipient outboxes with live mirror.
//!
//! An outbox is a small standalone git repo, one per recipient: the
//! owner re-publishes on every edit (the daemon's post-CRUD hook calls
//! the resync route), entries are sealed under a dedicated outbox
//! content key, and that key reaches the recipient HPKE-wrapped to
//! their identity wrap pubkey (Level 1 channel trust — the outbox
//! never wraps a live vault key). Reads are view-only; the recipient
//! never imports outbox entries. Revoke = unpublish + drop the
//! keywrap + forget the outbox (the next publish mints a fresh id and
//! key; a stolen old key keeps reading stale copied bytes — the
//! plan's eventual-revocation boundary).
//!
//! Repo layout:
//!   outbox.json         plaintext marker: outbox id, owner vault id, owner card
//!   share/keywrap.json  HPKE-wrapped content key + owner signature binding
//!   entries/<uuid>.enc  sealed entry blob under the content key
//!
//! Owner-side registry (meta/outbox-owner.enc) and recipient links
//! (meta/outbox-links.enc) live inside the vault, sealed under
//! `derive_outbox_key` (RootKey-derived, rotation-covered).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{hpke_wrap, signature};
use crate::error::{BaluardError, VaultError};
use crate::types::CipherInput;
use crate::vault::contacts::SignedContactCard;
use crate::vault::identity::IdentityKeys;

const OUTBOX_MARKER: &str = "outbox.json";
const KEYWRAP_FILE: &str = "share/keywrap.json";
const ENTRIES_DIR: &str = "entries";
const OWNER_REGISTRY_FILE: &str = "outbox-owner.enc";
const LINKS_FILE: &str = "outbox-links.enc";
const OWNER_REGISTRY_PURPOSE: &str = "outbox-registry-v1";
const LINKS_PURPOSE: &str = "outbox-links-v1";
const ENTRY_PURPOSE_PREFIX: &str = "outbox-entry-v1";
const OUTBOX_KEYWRAP_CONTEXT: &str = "outbox-keywrap-v1";
const ENTRY_SIGNATURE_DOMAIN: &str = "baluard-outbox-entry-v1\n";
const KEYWRAP_SIGNATURE_DOMAIN: &str = "baluard-outbox-keywrap-v1\n";
/// XL cipher tier payload plus card/JSON slack (packages parity).
const MAX_ENTRY_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

fn deny(msg: &str) -> BaluardError {
    BaluardError::from(VaultError::InvalidOperation(msg.to_string()))
}

/// Plaintext marker at the outbox root: the only artifact a recipient
/// needs before the content key (contact cards are public).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxMarker {
    pub format: u32,
    pub outbox_id: Uuid,
    pub owner_vault_id: Uuid,
    pub owner_card: SignedContactCard,
}

/// HPKE wrap of the outbox content key to the recipient's wrap pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxKeywrap {
    pub format: u32,
    pub ephemeral_public: String,
    pub encrypted_key: String,
    pub wrap_tag: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboxEntryPayload {
    format: u32,
    sender_card: SignedContactCard,
    updated_at: u64,
    item: CipherInput,
    signature: String,
}

/// Owner-side record for one outbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerOutbox {
    pub outbox_id: Uuid,
    pub path: String,
    /// Hex Ed25519 identity signing pubkey of the single recipient
    /// (stable across the recipient's wrap-key rotations).
    pub recipient_signing_pub: String,
    /// Hex X25519 wrap pubkey of the single recipient (re-wrapped when
    /// the recipient rotates their identity).
    pub recipient_wrap_pub: String,
    /// Hex content key (inside the sealed registry blob).
    pub content_key_hex: String,
    pub published: Vec<PublishedRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedRef {
    pub cipher_id: Uuid,
    /// SHA-256 over the last sealed doc, for the resync dirty check.
    pub digest: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OwnerRegistry {
    outboxes: Vec<OwnerOutbox>,
}

/// Recipient-side record for one linked outbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxLink {
    pub outbox_id: Uuid,
    pub path: String,
    /// Hex content key, unwrapped once at link time.
    pub content_key_hex: String,
    /// Hex Ed25519 signing pubkey of the owner card AS SEEN AT LINK
    /// TIME: every later open re-checks the marker against it, so a
    /// swapped-in impostor marker+keywrap set cannot hijack a link.
    pub owner_signing_pubkey: String,
    pub owner_name: String,
    pub owner_vault_id: Uuid,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LinkRegistry {
    links: Vec<OutboxLink>,
}

/// What the owner sees after a publish/unpublish/resync.
#[derive(Debug, Serialize)]
pub struct OutboxReport {
    pub outbox_id: Uuid,
    pub committed: bool,
    pub entries: usize,
}

/// One decrypted entry as the recipient sees it (view-only).
#[derive(Debug, Serialize)]
pub struct OpenedEntry {
    pub cipher_id: Uuid,
    pub sender_name: String,
    pub updated_at: u64,
    pub item: CipherInput,
}

// ── registries (contacts.rs pattern: key passed in from the handle) ──

pub fn load_owner_registry(
    vault_path: &Path,
    key: &[u8; 32],
) -> Result<Vec<OwnerOutbox>, BaluardError> {
    let path = vault_path.join("meta").join(OWNER_REGISTRY_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let sealed = std::fs::read(&path).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("read outbox registry: {e}")))
    })?;
    let data = crate::secret_file::open_secret_blob(key, &sealed, OWNER_REGISTRY_PURPOSE)?;
    let reg: OwnerRegistry = serde_json::from_slice(&data).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("parse outbox registry: {e}")))
    })?;
    Ok(reg.outboxes)
}

pub fn save_owner_registry(
    vault_path: &Path,
    key: &[u8; 32],
    outboxes: &[OwnerOutbox],
) -> Result<(), BaluardError> {
    let path = vault_path.join("meta").join(OWNER_REGISTRY_FILE);
    let data = serde_json::to_vec(&OwnerRegistry {
        outboxes: outboxes.to_vec(),
    })
    .map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("encode outbox registry: {e}")))
    })?;
    let sealed = crate::secret_file::seal_secret_blob(key, &data, OWNER_REGISTRY_PURPOSE)?;
    super::write_vault_file(&path, &sealed).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("write outbox registry: {e}")))
    })
}

pub fn load_links(vault_path: &Path, key: &[u8; 32]) -> Result<Vec<OutboxLink>, BaluardError> {
    let path = vault_path.join("meta").join(LINKS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let sealed = std::fs::read(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("read outbox links: {e}"))))?;
    let data = crate::secret_file::open_secret_blob(key, &sealed, LINKS_PURPOSE)?;
    let reg: LinkRegistry = serde_json::from_slice(&data).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("parse outbox links: {e}")))
    })?;
    Ok(reg.links)
}

pub fn save_links(
    vault_path: &Path,
    key: &[u8; 32],
    links: &[OutboxLink],
) -> Result<(), BaluardError> {
    let path = vault_path.join("meta").join(LINKS_FILE);
    let data = serde_json::to_vec(&LinkRegistry {
        links: links.to_vec(),
    })
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("encode outbox links: {e}"))))?;
    let sealed = crate::secret_file::seal_secret_blob(key, &data, LINKS_PURPOSE)?;
    super::write_vault_file(&path, &sealed)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write outbox links: {e}"))))
}

// ── git helpers (plain plumbing; the outbox repo is NOT a vault repo —
// commit-signature policy does not apply there, content signatures
// carry integrity) ──

fn git_open(outbox: &Path) -> Result<git2::Repository, BaluardError> {
    // open() NOT discover(): discover walks parent directories, so an
    // outbox folder placed inside the vault (or any git worktree) would
    // attach to THAT repo and commit mirror files into it. An outbox is
    // always its own repository, created here on first publish.
    match git2::Repository::open(outbox) {
        Ok(repo) => Ok(repo),
        Err(_) => {
            git2::Repository::init(outbox).map_err(|e| deny(&format!("outbox repo init: {e}")))
        }
    }
}

fn git_commit(outbox: &Path, message: &str) -> Result<bool, BaluardError> {
    let repo = git_open(outbox)?;
    let mut index = repo.index().map_err(|e| deny(&format!("index: {e}")))?;
    // update_all stages tracked-file DELETIONS (unpublish/revoke);
    // add_all alone only adds/updates, leaving removed files in the
    // tree for every clone.
    index
        .update_all(["*"].iter(), None)
        .map_err(|e| deny(&format!("stage removals: {e}")))?;
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .map_err(|e| deny(&format!("stage: {e}")))?;
    index
        .write()
        .map_err(|e| deny(&format!("index write: {e}")))?;
    let tree_id = index
        .write_tree()
        .map_err(|e| deny(&format!("tree: {e}")))?;
    let tree = repo
        .find_tree(tree_id)
        .map_err(|e| deny(&format!("tree: {e}")))?;
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    if let Some(p) = parents.first() {
        if p.tree_id() == tree.id() {
            return Ok(false);
        }
    }
    let sig = git2::Signature::now("Baluard", "baluard@outbox")
        .map_err(|e| deny(&format!("signature: {e}")))?;
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)
        .map_err(|e| deny(&format!("commit: {e}")))?;
    Ok(true)
}

/// Best-effort push to `origin` when it exists. Transport failures are
/// silent: the commit is durable locally, the next resync retries.
fn git_push_best_effort(outbox: &Path) {
    let Ok(repo) = git_open(outbox) else {
        return;
    };
    let Ok(mut remote) = repo.find_remote("origin") else {
        return;
    };
    let Ok(head) = repo.head() else {
        return;
    };
    let Some(branch) = head.shorthand() else {
        return;
    };
    let refspec = format!("refs/heads/{branch}");
    let _ = remote.push(&[&refspec], None);
}

/// Locate the registry record for an outbox path (or error).
fn find_record<'a>(
    outboxes: &'a [OwnerOutbox],
    outbox_path: &Path,
) -> Result<&'a OwnerOutbox, BaluardError> {
    let path_str = norm_path(outbox_path);
    outboxes
        .iter()
        .find(|o| o.path == path_str)
        .ok_or_else(|| deny("this folder is not a shared outbox you own (publish first)"))
}

fn read_marker(outbox: &Path) -> Result<OutboxMarker, BaluardError> {
    let marker: OutboxMarker = serde_json::from_str(
        &std::fs::read_to_string(outbox.join(OUTBOX_MARKER))
            .map_err(|e| deny(&format!("outbox marker unreadable: {e}")))?,
    )
    .map_err(|e| deny(&format!("outbox marker unreadable: {e}")))?;
    marker.owner_card.verify()?;
    Ok(marker)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn entry_signature(
    outbox_id: Uuid,
    cipher_id: Uuid,
    updated_at: u64,
    item: &CipherInput,
    signing: &ed25519_dalek::SigningKey,
) -> Result<String, BaluardError> {
    let item_bytes =
        serde_json::to_vec(item).map_err(|e| VaultError::Metadata(format!("encode item: {e}")))?;
    let mut input = ENTRY_SIGNATURE_DOMAIN.as_bytes().to_vec();
    input.extend_from_slice(outbox_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(cipher_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(&updated_at.to_le_bytes());
    input.push(b'\n');
    input.extend_from_slice(&item_bytes);
    let sig = signature::sign(signing, &input)?;
    Ok(hex::encode(sig.to_bytes()))
}

fn doc_digest(doc: &[u8]) -> String {
    hex::encode(Sha256::digest(doc))
}

/// Registry paths are canonicalized so trailing slashes, relative
/// forms, and symlink spellings of the same folder match one record.
fn norm_path(p: &Path) -> String {
    p.canonicalize()
        .map(|c| c.to_string_lossy().to_string())
        .unwrap_or_else(|_| p.to_string_lossy().to_string())
}

/// Seal one entry blob and return (blob, digest). Reused by publish
/// and resync so both sides never drift on the payload shape. The
/// digest is computed over a CANONICAL MIRROR DOC that excludes
/// `updated_at`: the payload signature covers the real timestamp, but
/// a digest that includes a live clock would change every second and
/// defeat the unchanged-skip (every resync would rewrite + commit
/// every entry).
fn seal_entry(
    outbox_id: Uuid,
    cipher_id: Uuid,
    item: &CipherInput,
    owner_card: &SignedContactCard,
    owner_signing: &ed25519_dalek::SigningKey,
    content_key: &[u8; 32],
) -> Result<(Vec<u8>, String), BaluardError> {
    let updated_at = now_secs();
    let signature = entry_signature(outbox_id, cipher_id, updated_at, item, owner_signing)?;
    let payload = OutboxEntryPayload {
        format: 1,
        sender_card: owner_card.clone(),
        updated_at,
        item: item.clone(),
        signature,
    };
    let doc = serde_json::to_vec(&payload)
        .map_err(|e| VaultError::Metadata(format!("encode outbox entry: {e}")))?;
    if doc.len() > MAX_ENTRY_PAYLOAD_BYTES {
        return Err(deny("this entry is too large to share"));
    }
    let purpose = format!("{ENTRY_PURPOSE_PREFIX}/{outbox_id}/{cipher_id}");
    let blob = crate::secret_file::seal_secret_blob(content_key, &doc, &purpose)?;
    // Canonical dirty-check input: item bytes + placement, no clock.
    let mirror_doc = serde_json::json!({
        "outbox_id": outbox_id,
        "cipher_id": cipher_id,
        "item": item,
    });
    let digest = doc_digest(
        &serde_json::to_vec(&mirror_doc)
            .map_err(|e| VaultError::Metadata(format!("encode outbox entry: {e}")))?,
    );
    drop(doc);
    Ok((blob, digest))
}

fn write_entry_blob(outbox_path: &Path, cipher_id: Uuid, blob: &[u8]) -> Result<(), BaluardError> {
    let entry_path = outbox_path
        .join(ENTRIES_DIR)
        .join(format!("{cipher_id}.enc"));
    crate::secret_file::write_secret_file(&entry_path, blob)
        .map_err(|e| deny(&format!("entry write: {e}")))
}

/// Publish (or re-publish) one cipher into the recipient's outbox.
/// The entry is sealed from the CURRENT cipher state, so calling this
/// after an edit IS the live mirror. Idempotent on an unchanged item:
/// the digest check skips the write + commit.
#[allow(clippy::too_many_arguments)]
pub fn publish_entry(
    vault_path: &Path,
    outbox_path: &Path,
    owner_card: &SignedContactCard,
    owner_signing: &ed25519_dalek::SigningKey,
    registry_key: &[u8; 32],
    cipher_id: Uuid,
    item: &CipherInput,
    recipient_signing_pub_hex: &str,
    recipient_wrap_pub_hex: &str,
) -> Result<OutboxReport, BaluardError> {
    // The outbox repo must live outside the vault: an outbox at or
    // inside the vault folder would commit vault files into the mirror
    // (and vice versa), corrupting both histories.
    let vault_canon = vault_path
        .canonicalize()
        .unwrap_or_else(|_| vault_path.to_path_buf());
    let outbox_canon = outbox_path
        .canonicalize()
        .unwrap_or_else(|_| outbox_path.to_path_buf());
    if outbox_canon == vault_canon
        || outbox_canon.starts_with(&vault_canon)
        || vault_canon.starts_with(&outbox_canon)
    {
        return Err(deny("the shared folder must live outside the vault"));
    }
    let wrap_hex = recipient_wrap_pub_hex;
    if wrap_hex.is_empty() || recipient_signing_pub_hex.is_empty() {
        return Err(deny(
            "this contact's card has no sharing key: ask them to share their card again",
        ));
    }
    let wrap_bytes = hex::decode(wrap_hex).map_err(|_| deny("invalid contact sharing key"))?;
    let wrap_arr: [u8; 32] = wrap_bytes
        .as_slice()
        .try_into()
        .map_err(|_| deny("invalid contact sharing key"))?;
    let recipient_pub = x25519_dalek::PublicKey::from(wrap_arr);

    std::fs::create_dir_all(outbox_path.join("share"))
        .map_err(|e| deny(&format!("outbox dir: {e}")))?;
    std::fs::create_dir_all(outbox_path.join(ENTRIES_DIR))
        .map_err(|e| deny(&format!("outbox dir: {e}")))?;

    let path_str = norm_path(outbox_path);
    let mut outboxes = load_owner_registry(vault_path, registry_key)?;
    let existing = outboxes.iter().find(|o| o.path == path_str).cloned();

    let (outbox_id, content_key) = match &existing {
        Some(o) => {
            // One repo per recipient, keyed on the recipient's STABLE
            // identity signing pubkey: a rotated wrap key re-wraps the
            // same content key below, but a different person refuses.
            if o.recipient_signing_pub != recipient_signing_pub_hex {
                return Err(deny("this outbox already belongs to a different person"));
            }
            let key: [u8; 32] = hex::decode(&o.content_key_hex)
                .ok()
                .and_then(|b| b.as_slice().try_into().ok())
                .ok_or_else(|| deny("outbox key unreadable"))?;
            (o.outbox_id, Zeroizing::new(key))
        }
        None => {
            let mut key = Zeroizing::new([0u8; 32]);
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(key.as_mut());
            (Uuid::new_v4(), key)
        }
    };

    // Marker: write on create; verify on reuse.
    let marker_path = outbox_path.join(OUTBOX_MARKER);
    if marker_path.exists() {
        let marker = read_marker(outbox_path)?;
        if marker.outbox_id != outbox_id {
            return Err(deny("outbox marker does not match this outbox"));
        }
    } else {
        let owner_vault_id = crate::vault::handle::VaultHandle::vault_id_for_path(vault_path)?;
        let marker = OutboxMarker {
            format: 1,
            outbox_id,
            owner_vault_id,
            owner_card: owner_card.clone(),
        };
        std::fs::write(
            &marker_path,
            serde_json::to_string_pretty(&marker)
                .map_err(|e| deny(&format!("marker encode: {e}")))?,
        )
        .map_err(|e| deny(&format!("marker write: {e}")))?;
    }

    // Keywrap: written once per outbox lifetime; the recipient's wrap
    // key ROTATION re-wraps the same content key to the new pubkey (the
    // stale keywrap file is replaced). A revoke mints a new outbox id
    // on the next publish, so the old keywrap is orphaned.
    let keywrap_path = outbox_path.join(KEYWRAP_FILE);
    let wrap_rotated = existing
        .as_ref()
        .map(|o| o.recipient_wrap_pub != wrap_hex)
        .unwrap_or(false);
    if !keywrap_path.exists() || wrap_rotated {
        if wrap_rotated {
            let _ = std::fs::remove_file(&keywrap_path);
        }
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&content_key[..], &recipient_pub, OUTBOX_KEYWRAP_CONTEXT)?;
        // The signature binds the WRAP BYTES too (sha256 over eph|ct|tag):
        // it only covers recipient + outbox id, a repo writer could swap
        // the ciphertext under the still-valid signature and break the
        // recipient's link.
        let mut wrap_hasher = Sha256::new();
        wrap_hasher.update(&eph);
        wrap_hasher.update(&ct);
        wrap_hasher.update(tag);
        let mut input = KEYWRAP_SIGNATURE_DOMAIN.as_bytes().to_vec();
        input.extend_from_slice(recipient_pub.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(outbox_id.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(&wrap_hasher.finalize());
        let sig = signature::sign(owner_signing, &input)?;
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let kw = OutboxKeywrap {
            format: 1,
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
            signature: hex::encode(sig.to_bytes()),
        };
        std::fs::write(
            &keywrap_path,
            serde_json::to_string_pretty(&kw).map_err(|e| deny(&format!("keywrap encode: {e}")))?,
        )
        .map_err(|e| deny(&format!("keywrap write: {e}")))?;
    }

    // Live mirror: re-seal from the current state; skip write + commit
    // when the freshly sealed doc digests to the stored value.
    let (blob, digest) = seal_entry(
        outbox_id,
        cipher_id,
        item,
        owner_card,
        owner_signing,
        &content_key,
    )?;
    let unchanged = existing
        .as_ref()
        .and_then(|o| o.published.iter().find(|p| p.cipher_id == cipher_id))
        .map(|p| p.digest == digest)
        .unwrap_or(false);
    if !unchanged {
        write_entry_blob(outbox_path, cipher_id, &blob)?;
    }
    let committed = if unchanged {
        false
    } else {
        let c = git_commit(outbox_path, "mirror entry")?;
        git_push_best_effort(outbox_path);
        c
    };

    // Registry update.
    let record = PublishedRef { cipher_id, digest };
    let mut entries = 1usize;
    if let Some(o) = outboxes.iter_mut().find(|o| o.path == path_str) {
        o.published.retain(|p| p.cipher_id != cipher_id);
        o.published.push(record);
        o.recipient_wrap_pub = wrap_hex.to_string();
        entries = o.published.len();
    } else {
        outboxes.push(OwnerOutbox {
            outbox_id,
            path: path_str,
            recipient_signing_pub: recipient_signing_pub_hex.to_string(),
            recipient_wrap_pub: wrap_hex.to_string(),
            content_key_hex: hex::encode(&content_key[..]),
            published: vec![record],
        });
    }
    save_owner_registry(vault_path, registry_key, &outboxes)?;

    Ok(OutboxReport {
        outbox_id,
        committed,
        entries,
    })
}

/// Remove one published entry from the outbox (source deleted).
pub fn unpublish_entry(
    vault_path: &Path,
    outbox_path: &Path,
    registry_key: &[u8; 32],
    cipher_id: Uuid,
) -> Result<OutboxReport, BaluardError> {
    let mut outboxes = load_owner_registry(vault_path, registry_key)?;
    let outbox_id = find_record(&outboxes, outbox_path)?.outbox_id;
    let entry_path = outbox_path
        .join(ENTRIES_DIR)
        .join(format!("{cipher_id}.enc"));
    if entry_path.exists() {
        std::fs::remove_file(&entry_path).map_err(|e| deny(&format!("entry remove: {e}")))?;
    }
    let committed = git_commit(outbox_path, "unpublish entry")?;
    git_push_best_effort(outbox_path);

    let path_str = norm_path(outbox_path);
    let mut entries = 0usize;
    if let Some(o) = outboxes.iter_mut().find(|o| o.path == path_str) {
        o.published.retain(|p| p.cipher_id != cipher_id);
        entries = o.published.len();
        // Keep the record even when nothing is published: the marker on
        // disk still carries this outbox id, and dropping the record
        // would wedge a later re-publish (fresh id vs old marker).
    }
    save_owner_registry(vault_path, registry_key, &outboxes)?;

    Ok(OutboxReport {
        outbox_id,
        committed,
        entries,
    })
}

/// Revoke the whole outbox: unpublish everything, drop the keywrap,
/// forget the registry record. The next publish to this folder mints a
/// fresh outbox id and key. (Provider seat removal is the runtime's
/// job; the P8c facade owns it.)
pub fn revoke_outbox(
    vault_path: &Path,
    outbox_path: &Path,
    registry_key: &[u8; 32],
) -> Result<(), BaluardError> {
    let mut outboxes = load_owner_registry(vault_path, registry_key)?;
    // Gate on an owned record: a typo'd path must never strip an
    // unrelated folder's entries/ directory.
    find_record(&outboxes, outbox_path)?;
    let path_str = norm_path(outbox_path);
    outboxes.retain(|o| o.path != path_str);
    save_owner_registry(vault_path, registry_key, &outboxes)?;

    let entries_dir = outbox_path.join(ENTRIES_DIR);
    if entries_dir.exists() {
        std::fs::remove_dir_all(&entries_dir).map_err(|e| deny(&format!("entries remove: {e}")))?;
    }
    let keywrap_path = outbox_path.join(KEYWRAP_FILE);
    if keywrap_path.exists() {
        std::fs::remove_file(&keywrap_path).map_err(|e| deny(&format!("keywrap remove: {e}")))?;
    }
    let marker_path = outbox_path.join(OUTBOX_MARKER);
    if marker_path.exists() {
        std::fs::remove_file(&marker_path).map_err(|e| deny(&format!("marker remove: {e}")))?;
    }
    git_commit(outbox_path, "revoke outbox")?;
    git_push_best_effort(outbox_path);
    Ok(())
}

/// Read one entry from an outbox the recipient has linked. Verifies
/// the marker card, then the entry signature (which binds the outbox
/// id, the entry id, the timestamp, and the item bytes — a captured
/// entry cannot be transplanted across outboxes or renamed).
pub fn open_entry(
    outbox_path: &Path,
    link: &OutboxLink,
    cipher_id: Uuid,
) -> Result<OpenedEntry, BaluardError> {
    let marker = read_marker(outbox_path)?;
    // The link pins the outbox id and owner identity seen at link
    // time. A swapped-in impostor set (own card, own key, keywrap
    // re-addressed to this recipient — anyone can HPKE-wrap to a
    // public key) fails the id or owner check here.
    if marker.outbox_id != link.outbox_id
        || marker.owner_card.card.identity_signing_pubkey != link.owner_signing_pubkey
    {
        return Err(deny(
            "this shared folder has changed: ask the sender to share it again",
        ));
    }
    let key: [u8; 32] = hex::decode(&link.content_key_hex)
        .ok()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or_else(|| deny("outbox link is broken: ask the sender to share again"))?;
    let entry_path = outbox_path
        .join(ENTRIES_DIR)
        .join(format!("{cipher_id}.enc"));
    // Size bound BEFORE reading: a hostile oversized file must not get
    // pulled into memory wholesale.
    let file_len = std::fs::metadata(&entry_path)
        .map(|m| m.len())
        .map_err(|e| deny(&format!("entry unreadable: {e}")))?;
    if file_len as usize > MAX_ENTRY_PAYLOAD_BYTES * 2 {
        return Err(deny("shared entry is too large"));
    }
    let blob = std::fs::read(&entry_path).map_err(|e| deny(&format!("entry unreadable: {e}")))?;
    let purpose = format!("{ENTRY_PURPOSE_PREFIX}/{}", marker.outbox_id);
    let purpose = format!("{purpose}/{cipher_id}");
    let doc = crate::secret_file::open_secret_blob(&key, &blob, &purpose)
        .map_err(|e| deny(&format!("entry does not open: {e}")))?;
    if doc.len() > MAX_ENTRY_PAYLOAD_BYTES {
        return Err(deny("shared entry is too large"));
    }
    let payload: OutboxEntryPayload =
        serde_json::from_slice(&doc).map_err(|e| deny(&format!("shared entry unreadable: {e}")))?;
    payload.sender_card.verify()?;
    // Entry attribution must be the outbox OWNER's identity — a repo
    // writer cannot inject an entry labeled as someone else.
    if payload.sender_card.card.identity_signing_pubkey
        != marker.owner_card.card.identity_signing_pubkey
    {
        return Err(deny("shared entry signature invalid"));
    }
    // Rebuild the signed input from the OUTBOX's id (from the marker),
    // the requested entry id, and the payload's own bytes, then verify
    // against the sender card's identity key. A captured entry cannot
    // be transplanted across outboxes or re-labeled.
    let item_bytes = serde_json::to_vec(&payload.item)
        .map_err(|e| VaultError::Metadata(format!("encode item: {e}")))?;
    let mut input = ENTRY_SIGNATURE_DOMAIN.as_bytes().to_vec();
    input.extend_from_slice(marker.outbox_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(cipher_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(&payload.updated_at.to_le_bytes());
    input.push(b'\n');
    input.extend_from_slice(&item_bytes);
    let vk_bytes = hex::decode(&payload.sender_card.card.identity_signing_pubkey)
        .map_err(|_| deny("shared entry has an invalid sender key"))?;
    let vk_arr: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| deny("shared entry has an invalid sender key"))?;
    let vk = signature::verifying_key_from_bytes(&vk_arr)
        .map_err(|_| deny("shared entry has an invalid sender key"))?;
    let sig_bytes =
        hex::decode(&payload.signature).map_err(|_| deny("shared entry signature invalid"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| deny("shared entry signature invalid"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    signature::verify(&vk, &input, &sig).map_err(|_| deny("shared entry signature invalid"))?;
    Ok(OpenedEntry {
        cipher_id,
        sender_name: payload.sender_card.card.display_name.clone(),
        updated_at: payload.updated_at,
        item: payload.item,
    })
}

/// Recipient side: link an outbox folder. Verifies the marker card,
/// unwraps the content key with THIS vault's identity (the keywrap is
/// addressed to the recipient's wrap pubkey and signature-bound to the
/// outbox id), and stores the link. View-only — nothing here touches
/// the recipient's entries.
pub fn link_outbox(
    vault_path: &Path,
    links_key: &[u8; 32],
    identity: &IdentityKeys,
    outbox_path: &Path,
) -> Result<OutboxLink, BaluardError> {
    let marker = read_marker(outbox_path)?;
    let kw: OutboxKeywrap = serde_json::from_str(
        &std::fs::read_to_string(outbox_path.join(KEYWRAP_FILE))
            .map_err(|e| deny(&format!("outbox keywrap unreadable: {e}")))?,
    )
    .map_err(|e| deny(&format!("outbox keywrap unreadable: {e}")))?;

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let eph = b64
        .decode(&kw.ephemeral_public)
        .map_err(|_| deny("outbox keywrap is damaged"))?;
    let ct = b64
        .decode(&kw.encrypted_key)
        .map_err(|_| deny("outbox keywrap is damaged"))?;
    let tag: [u8; 16] = b64
        .decode(&kw.wrap_tag)
        .map_err(|_| deny("outbox keywrap is damaged"))?
        .try_into()
        .map_err(|_| deny("outbox keywrap is damaged"))?;

    let content_key = Zeroizing::new(hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        identity.wrapping_secret(),
        OUTBOX_KEYWRAP_CONTEXT,
    )?);
    let key_arr: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| deny("outbox content key length invalid"))?;
    drop(content_key);

    // The keywrap signature binds the recipient wrap pubkey + outbox
    // id + the wrap bytes (sha256 over eph|ct|tag), so a wrap for
    // someone else, a transplanted keywrap, or a ciphertext swap under
    // the still-valid signature refuses here.
    let mut input = KEYWRAP_SIGNATURE_DOMAIN.as_bytes().to_vec();
    input.extend_from_slice(&identity.wrapping_pub_bytes());
    input.push(b'\n');
    input.extend_from_slice(marker.outbox_id.as_bytes());
    input.push(b'\n');
    let mut wrap_hasher = Sha256::new();
    wrap_hasher.update(&eph);
    wrap_hasher.update(&ct);
    wrap_hasher.update(tag);
    input.extend_from_slice(&wrap_hasher.finalize());
    let vk_bytes = hex::decode(&marker.owner_card.card.identity_signing_pubkey)
        .map_err(|_| deny("outbox owner card is invalid"))?;
    let vk_arr: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| deny("outbox owner card is invalid"))?;
    let vk = signature::verifying_key_from_bytes(&vk_arr)
        .map_err(|_| deny("outbox owner card is invalid"))?;
    let sig_bytes =
        hex::decode(&kw.signature).map_err(|_| deny("outbox keywrap signature invalid"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| deny("outbox keywrap signature invalid"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    signature::verify(&vk, &input, &sig).map_err(|_| deny("outbox keywrap signature invalid"))?;

    let link = OutboxLink {
        outbox_id: marker.outbox_id,
        path: norm_path(outbox_path),
        content_key_hex: hex::encode(key_arr),
        owner_signing_pubkey: marker.owner_card.card.identity_signing_pubkey.clone(),
        owner_name: marker.owner_card.card.display_name.clone(),
        owner_vault_id: marker.owner_vault_id,
    };

    let mut links = load_links(vault_path, links_key)?;
    links.retain(|l| l.outbox_id != link.outbox_id);
    links.push(link.clone());
    save_links(vault_path, links_key, &links)?;
    Ok(link)
}

pub fn forget_link(
    vault_path: &Path,
    links_key: &[u8; 32],
    outbox_id: Uuid,
) -> Result<(), BaluardError> {
    let mut links = load_links(vault_path, links_key)?;
    links.retain(|l| l.outbox_id != outbox_id);
    save_links(vault_path, links_key, &links)
}

/// List the entries of one linked outbox (view-only): decrypts each
/// blob far enough for the name + timestamp. Entry counts are small by
/// construction (one person's shared set).
pub fn list_entries(
    outbox_path: &Path,
    link: &OutboxLink,
) -> Result<Vec<OpenedEntry>, BaluardError> {
    let marker = read_marker(outbox_path)?;
    if marker.outbox_id != link.outbox_id
        || marker.owner_card.card.identity_signing_pubkey != link.owner_signing_pubkey
    {
        return Err(deny(
            "this shared folder has changed: ask the sender to share it again",
        ));
    }
    let entries_dir = outbox_path.join(ENTRIES_DIR);
    let mut out = Vec::new();
    if entries_dir.exists() {
        let mut ids: Vec<Uuid> = std::fs::read_dir(&entries_dir)
            .map_err(|e| deny(&format!("entries unreadable: {e}")))?
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| e == "enc"))
            .filter_map(|f| {
                f.file_name()
                    .to_string_lossy()
                    .strip_suffix(".enc")
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
            .collect();
        ids.sort();
        for id in ids {
            // Skip unreadable/tampered entries instead of failing the
            // whole listing: one corrupt file must not hide every valid
            // entry from the recipient.
            if let Ok(entry) = open_entry(outbox_path, link, id) {
                out.push(entry);
            }
        }
    }
    let _ = marker;
    Ok(out)
}

// ── tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::contacts::ContactCard;
    use std::path::PathBuf;

    /// A minimal fake vault: the registry layer only needs
    /// meta/kdf-params.json (vault_id derivation) and meta/.
    fn fake_vault() -> (tempfile::TempDir, [u8; 32], PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let params = crate::crypto::kdf::create_params(crate::types::KdfProfile::MobileLow);
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(
            dir.path().join("meta/kdf-params.json"),
            serde_json::to_string(&params).unwrap(),
        )
        .unwrap();
        let root: [u8; 64] = core::array::from_fn(|i| i as u8);
        let key = crate::crypto::hkdf_derive::derive_outbox_key(&root).unwrap();
        let path = dir.path().to_path_buf();
        (dir, key, path)
    }

    /// An outbox folder OUTSIDE any vault directory: the path guard
    /// refuses outboxes at/inside the vault, so tests place them in a
    /// leaked sibling tempdir (leak keeps the dir alive for the test).
    fn sibling_dir() -> &'static std::path::Path {
        let dir = tempfile::tempdir().unwrap();
        Box::leak(dir.keep().into_boxed_path())
    }

    fn owner_card(signing: &ed25519_dalek::SigningKey, wrap_pub: &[u8; 32]) -> SignedContactCard {
        SignedContactCard::sign(
            "Owner",
            &hex::encode(signing.verifying_key().as_bytes()),
            &hex::encode(wrap_pub),
            1_700_000_000,
            signing,
        )
        .unwrap()
    }

    fn recipient_card(recipient: &IdentityKeys) -> ContactCard {
        ContactCard {
            display_name: "Recip".into(),
            identity_signing_pubkey: hex::encode(
                recipient.signing_key().verifying_key().as_bytes(),
            ),
            identity_wrap_pubkey: hex::encode(recipient.wrapping_pub_bytes()),
            created_at: 1_700_000_000,
        }
    }

    fn sample_item(password: &str) -> CipherInput {
        serde_json::from_value(serde_json::json!({
            "name": "GitHub",
            "kind": {"type": "login", "data": {"username": "u", "password": password}}
        }))
        .unwrap()
    }

    #[test]
    fn publish_link_read_roundtrip() {
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-a");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());

        let report = publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("hunter2"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        assert!(report.committed);
        assert_eq!(report.entries, 1);

        let link = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap();
        assert_eq!(link.owner_name, "Owner");
        let entries = list_entries(&outbox, &link).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sender_name, "Owner");
        assert_eq!(entries[0].item.name, "GitHub");
        let cipher_id = entries[0].cipher_id;
        let opened = open_entry(&outbox, &link, cipher_id).unwrap();
        let crate::types::CipherKind::Login(login) = &opened.item.kind else {
            panic!("expected login");
        };
        assert_eq!(login.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn republish_reflects_edit_and_skips_unchanged() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-b");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();

        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("old"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        // Unchanged item → digest hit → no commit.
        let report = publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("old"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        assert!(!report.committed);
        // Edit → re-seal → commit → recipient sees the new value.
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("new-pass"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let link = link_outbox(&opath, &okey, &recipient, &outbox).unwrap();
        let opened = open_entry(&outbox, &link, cid).unwrap();
        let crate::types::CipherKind::Login(login) = &opened.item.kind else {
            panic!("expected login");
        };
        assert_eq!(login.password.as_deref(), Some("new-pass"));
    }

    #[test]
    fn unpublish_keeps_record_and_removes_entry() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-c");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let report = unpublish_entry(&opath, &outbox, &okey, cid).unwrap();
        assert_eq!(report.entries, 0);
        assert!(!outbox.join(ENTRIES_DIR).join(format!("{cid}.enc")).exists());
        // The record STAYS (the on-disk marker still carries the
        // outbox id; dropping the record would wedge a re-publish).
        let rows = load_owner_registry(&opath, &okey).unwrap();
        let kept = rows
            .iter()
            .find(|o| o.path == norm_path(&outbox))
            .expect("empty outbox keeps its record");
        assert!(kept.published.is_empty());
    }

    #[test]
    fn revoke_kills_recipient_access() {
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-d");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let link = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap();
        revoke_outbox(&opath, &outbox, &okey).unwrap();
        assert!(open_entry(&outbox, &link, cid).is_err());
        // Marker gone → a relink refuses.
        assert!(link_outbox(&rpath, &_rkey, &recipient, &outbox).is_err());
    }

    #[test]
    fn stranger_cannot_link_or_read() {
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let stranger = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-e");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        assert!(link_outbox(&rpath, &_rkey, &stranger, &outbox).is_err());
    }

    #[test]
    fn different_recipient_reuse_refused() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let a = IdentityKeys::generate().unwrap();
        let b = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-f");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&a).identity_signing_pubkey.as_str(),
            recipient_card(&a).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let err = publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&b).identity_signing_pubkey.as_str(),
            recipient_card(&b).identity_wrap_pubkey.as_str(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("different person"), "{err}");
    }

    #[test]
    fn swapped_marker_cannot_hijack_link() {
        // Attacker with write access to the outbox folder replaces the
        // whole set (own card, own key, keywrap re-addressed to the
        // victim — HPKE Base wraps need no secret). The link pins the
        // owner identity + outbox id seen at link time.
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-i");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("real"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let link = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap();

        // Impostor rebuilds the folder.
        let impostor = IdentityKeys::generate().unwrap();
        std::fs::remove_dir_all(&outbox).unwrap();
        std::fs::create_dir_all(outbox.join("share")).unwrap();
        std::fs::create_dir_all(outbox.join(ENTRIES_DIR)).unwrap();
        let i_card = owner_card(impostor.signing_key(), &impostor.wrapping_pub_bytes());
        let marker = OutboxMarker {
            format: 1,
            outbox_id: link.outbox_id,
            owner_vault_id: Uuid::new_v4(),
            owner_card: i_card,
        };
        std::fs::write(
            outbox.join(OUTBOX_MARKER),
            serde_json::to_string_pretty(&marker).unwrap(),
        )
        .unwrap();
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut key);
        let victim_wrap = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&key, &victim_wrap, OUTBOX_KEYWRAP_CONTEXT).unwrap();
        let mut input = KEYWRAP_SIGNATURE_DOMAIN.as_bytes().to_vec();
        input.extend_from_slice(victim_wrap.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(link.outbox_id.as_bytes());
        let sig = signature::sign(impostor.signing_key(), &input).unwrap();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let kw = OutboxKeywrap {
            format: 1,
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
            signature: hex::encode(sig.to_bytes()),
        };
        std::fs::write(
            outbox.join(KEYWRAP_FILE),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        let err = open_entry(&outbox, &link, cid).unwrap_err();
        assert!(err.to_string().contains("has changed"), "{err}");
    }

    #[test]
    fn unpublish_stages_deletion_into_git() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-j");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        unpublish_entry(&opath, &outbox, &okey, cid).unwrap();
        // The deletion must be in HEAD's tree, not only on disk.
        let repo = git2::Repository::open(&outbox).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let tree = head.tree().unwrap();
        assert!(
            tree.get_path(std::path::Path::new(&format!("{ENTRIES_DIR}/{cid}.enc")))
                .is_err()
        );
    }

    #[test]
    fn recipient_wrap_rotation_rewraps_content_key() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-k");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();

        // Recipient rotates their identity (new wrap key, same signing
        // pubkey is impossible with from-seed derivation, so simulate
        // the registry-level contract: same signing key, new wrap). We
        // mint a new wrap key from the same seed is not possible, so
        // rotate BOTH and re-publish with the new card — the reuse
        // check keys on the SIGNING pubkey, so pre-rotation rows built
        // by this test must carry the same signing key.
        let rotated = IdentityKeys::from_seed(&recipient.seed());
        // from_seed reproduces the SAME identity; force a wrap change by
        // publishing with a hand-mutated wrap pubkey of the same size.
        let mut new_wrap = recipient.wrapping_pub_bytes();
        new_wrap[0] ^= 0xFF;
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p2"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            &hex::encode(new_wrap),
        )
        .unwrap();
        // The old keywrap is replaced; the OLD link key still opens the
        // entries (same content key), and the registry now carries the
        // new wrap.
        let rows = load_owner_registry(&opath, &okey).unwrap();
        assert_eq!(rows[0].recipient_wrap_pub, hex::encode(new_wrap));
        let _ = rotated;
    }

    #[test]
    fn cross_outbox_transplant_refused() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox1 = sibling_dir().join("outbox-g1");
        let outbox2 = sibling_dir().join("outbox-g2");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid1 = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox1,
            &card,
            sender.signing_key(),
            &okey,
            cid1,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        publish_entry(
            &opath,
            &outbox2,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        // Copy outbox1's sealed entry into outbox2. The AAD binds the
        // outbox id, so outbox2's key cannot open it.
        let blob = std::fs::read(outbox1.join(ENTRIES_DIR).join(format!("{cid1}.enc"))).unwrap();
        std::fs::write(outbox2.join(ENTRIES_DIR).join(format!("{cid1}.enc")), &blob).unwrap();
        let link2 = link_outbox(&opath, &okey, &recipient, &outbox2).unwrap();
        assert!(open_entry(&outbox2, &link2, cid1).is_err());
    }

    #[test]
    fn keywrap_ciphertext_swap_under_captured_signature_refused() {
        // Repo writer swaps the HPKE ciphertext while keeping the
        // owner's captured signature (which pre-fix covered only
        // recipient + outbox id). The wrap-bytes hash in the signature
        // must refuse the swap.
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-swap");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let link = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap();

        let kw_path = outbox.join(KEYWRAP_FILE);
        let captured_sig: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&kw_path).unwrap()).unwrap();
        let captured_sig = captured_sig["signature"].as_str().unwrap().to_string();

        // Attacker wraps THEIR key to the victim's wrap pubkey (HPKE
        // Base needs no secret) and reuses the owner's captured
        // signature, which does not cover the wrap bytes.
        use rand::RngCore;
        let mut attacker_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(attacker_key.as_mut());
        let victim_pub = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&attacker_key[..], &victim_pub, OUTBOX_KEYWRAP_CONTEXT).unwrap();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let kw = serde_json::json!({
            "format": 1,
            "ephemeral_public": b64.encode(&eph),
            "encrypted_key": b64.encode(&ct),
            "wrap_tag": b64.encode(tag),
            "signature": captured_sig,
        });
        std::fs::write(&kw_path, serde_json::to_string_pretty(&kw).unwrap()).unwrap();

        let err = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap_err();
        assert!(
            err.to_string().contains("keywrap signature invalid"),
            "{err}"
        );
        let _ = link;
    }

    #[test]
    fn outbox_inside_vault_path_refused() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        // Same path as the vault → refuse (would commit vault files).
        let err = publish_entry(
            &opath,
            &opath,
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside the vault"), "{err}");
        // Subdirectory of the vault → refuse too.
        let err2 = publish_entry(
            &opath,
            &opath.join("entries"),
            &card,
            sender.signing_key(),
            &okey,
            Uuid::new_v4(),
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap_err();
        assert!(err2.to_string().contains("outside the vault"), "{err2}");
    }

    #[test]
    fn unpublish_then_republish_same_folder() {
        let (_owner_dir, okey, opath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-reuse");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        // Unpublish everything; the record stays (marker id preserved).
        unpublish_entry(&opath, &outbox, &okey, cid).unwrap();
        let rows = load_owner_registry(&opath, &okey).unwrap();
        assert!(
            rows.iter().any(|o| o.path == norm_path(&outbox)),
            "empty outbox must keep its registry record"
        );
        // Re-publish to the same folder works (no id/marker wedge).
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("p2"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
    }

    #[test]
    fn revoke_unregistered_path_refused() {
        let (_owner_dir, okey, opath) = fake_vault();
        let err =
            revoke_outbox(&opath, &opath.parent().unwrap().join("nowhere"), &okey).unwrap_err();
        assert!(
            err.to_string().contains("not a shared outbox you own"),
            "{err}"
        );
    }

    #[test]
    fn resealed_with_content_key_but_forged_signature_refused() {
        // Attacker model: the RECIPIENT holds the content key (they can
        // read the outbox) but not the owner's signing key. They can
        // re-seal arbitrary bytes; the entry signature still refuses.
        let (_owner_dir, okey, opath) = fake_vault();
        let (_rdir, _rkey, rpath) = fake_vault();
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let outbox = sibling_dir().join("outbox-h");
        let card = owner_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let cid = Uuid::new_v4();
        publish_entry(
            &opath,
            &outbox,
            &card,
            sender.signing_key(),
            &okey,
            cid,
            &sample_item("real"),
            recipient_card(&recipient).identity_signing_pubkey.as_str(),
            recipient_card(&recipient).identity_wrap_pubkey.as_str(),
        )
        .unwrap();
        let link = link_outbox(&rpath, &_rkey, &recipient, &outbox).unwrap();

        let legit = open_entry(&outbox, &link, cid).unwrap();
        let key: [u8; 32] = hex::decode(&link.content_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let marker = read_marker(&outbox).unwrap();
        let purpose = format!("{ENTRY_PURPOSE_PREFIX}/{}/{cid}", marker.outbox_id);

        // Capture the legit signature, then re-seal a forged item under
        // the REAL content key carrying the STALE signature.
        let old_sig = {
            let blob = std::fs::read(outbox.join(ENTRIES_DIR).join(format!("{cid}.enc"))).unwrap();
            let doc = crate::secret_file::open_secret_blob(&key, &blob, &purpose).unwrap();
            let p: OutboxEntryPayload = serde_json::from_slice(&doc).unwrap();
            p.signature
        };
        let mut forged = sample_item("phishing");
        forged.name = "Phishing Bank".into();
        let payload = OutboxEntryPayload {
            format: 1,
            sender_card: card,
            updated_at: legit.updated_at,
            item: forged,
            signature: old_sig,
        };
        let blob = crate::secret_file::seal_secret_blob(
            &key,
            &serde_json::to_vec(&payload).unwrap(),
            &purpose,
        )
        .unwrap();
        std::fs::write(outbox.join(ENTRIES_DIR).join(format!("{cid}.enc")), &blob).unwrap();
        let err = open_entry(&outbox, &link, cid).unwrap_err();
        assert!(err.to_string().contains("signature invalid"), "{err}");
    }
}
