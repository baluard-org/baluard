//! Space Meta Key (SMK) groundwork (S3-7a, plan §4.3 P1 consumption).
//!
//! The Team-shape flip (7b) stops handing the Root Key to non-admin
//! members. Everything a member must still read (folders, tags, profile,
//! settings, contacts, events) is keyed today from the Root Key, so the
//! flip needs one shared member-readable meta key: the SMK. It is a
//! random 32-byte key with two distribution paths:
//!
//! - admins open the sealed store `meta/space.enc` with a Root-Key
//!   HKDF (re-sealed by both rotation paths);
//! - members open their per-identity wrap `meta/members/<m>/space.wrap`
//!   (HPKE, context-bound to the member like the collection wraps).
//!
//! This slice is ADDITIVE: nothing derives from the SMK yet, no unlock
//! path changes, existing vaults are untouched until an admin runs
//! `space.prepare`. The 7b flip switches meta derivations and keywrap
//! distribution once `status` reports every live member wrapped.
//!
//! Git policy needs no new rows: `meta/space.enc` rides the
//! `meta/**` Admin row and `meta/members/<m>/space.wrap` rides the
//! own-subtree Any row (self-heal) plus the `meta/members/**` Admin
//! row (prepare wraps other members).

use crate::crypto::hpke_wrap;
use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::RootKey;
use crate::secret_file::{open_secret_blob, seal_secret_blob};
use crate::vault::members::{self, MemberFile};
use crate::vault::write_vault_file;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Store file. Sealed under a Root-Key HKDF; members never open it.
const SPACE_STORE_PATH: &str = "meta/space.enc";
/// HKDF info for the store-seal key. Changing this orphans every store.
const SPACE_STORE_INFO: &[u8] = b"baluard-space-store-v1";
/// Purpose string inside the sealed-blob envelope (AAD binding).
const SPACE_STORE_PURPOSE: &str = "space-meta-store-v1";
/// HPKE context binding a wrap to its member. Transplants between
/// members fail the AEAD tag.
fn space_wrap_context(member_id: &Uuid) -> String {
    format!("space-meta-v1/{member_id}")
}
const SPACE_WRAP_FORMAT: u64 = 1;
/// Wrap files are tiny; the cap only bounds a hostile synced file.
const MAX_SPACE_FILE_BYTES: usize = 64 * 1024;

/// The sealed store payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpaceStore {
    /// Hex-encoded 32-byte Space Meta Key.
    pub smk: String,
    /// Creation timestamp (informational).
    pub created_at: u64,
}

/// Report from [`prepare`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareReport {
    /// True when this call generated a fresh SMK (false: idempotent re-run).
    pub smk_fresh: bool,
    /// Members wrapped after this call.
    pub wrapped: usize,
    /// Live member ids without an identity wrap pubkey (cannot be wrapped;
    /// the 7b flip refuses until every row carries one).
    pub missing_wrap_pubkey: Vec<Uuid>,
}

/// Readiness surface for the 7b flip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceStatus {
    /// The sealed store exists (an SMK is minted).
    pub prepared: bool,
    /// Live members holding a space wrap on disk.
    pub wrapped: usize,
    /// Live members lacking an identity wrap pubkey (wrap can never exist).
    pub missing_wrap_pubkey: usize,
    /// Live members with a wrap pubkey but no wrap file yet.
    pub pending_wrap: usize,
    /// The epoch recorded at flip time; None on legacy markers.
    pub flipped_epoch: Option<u64>,
    /// Flipped and no rotation has run since (flipped_epoch == current
    /// epoch): pre-flip members still hold the old key. Computed by the
    /// handle against the live epoch, not by status().
    pub needs_rotation: bool,
}

fn space_store_path(vault_path: &Path) -> PathBuf {
    vault_path.join(SPACE_STORE_PATH)
}

pub(crate) fn space_wrap_path(vault_path: &Path, member_id: &Uuid) -> PathBuf {
    vault_path
        .join("meta/members")
        .join(member_id.to_string())
        .join("space.wrap")
}

/// Store-seal key: HKDF-SHA256 over the Root Key. Both rotation paths
/// re-seal the store because this key follows the Root Key.
fn space_store_key(root: &RootKey) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hkdf = Hkdf::<Sha256>::new(None, root.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(SPACE_STORE_INFO, key.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("space store key: {e}")))?;
    Ok(key)
}

fn live_members(vault_path: &Path) -> Result<Vec<MemberFile>, BaluardError> {
    Ok(members::list_members(vault_path)?
        .into_iter()
        .filter(|m| m.removed.is_none() && m.reset.is_none())
        .collect())
}

// ── Shape marker (S3-7b) ──────────────────────────────────────────
//
// meta/space-shape.json is a tiny PLAINTEXT, git-tracked, admin-only
// (meta/** policy row) marker. It holds no secrets: it only says the
// vault's member-visible meta derivations moved from the Root Key to
// meta_root(SMK) and member devices hold no Root Key. Every unlock
// reads it locally to pick the unlock path; writing it is the flip's
// point of no return (marker FIRST, files converge after).

const SHAPE_PATH: &str = "meta/space-shape.json";

/// Whether this vault has flipped to team shape. A damaged marker
/// reads as false: admins keep the Root Key path and can re-run the
/// flip; members get a clear unlock refusal instead of a crypto error.
pub fn shape_flipped(vault_path: &Path) -> bool {
    let path = vault_path.join(SHAPE_PATH);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["mode"].as_str().map(str::to_string))
        .as_deref()
        == Some("team")
}

/// Write the team-shape marker (the flip's commit point). Fails when
/// the file already exists with a different mode so a foreign marker
/// never gets silently overwritten.
pub fn write_shape_marker(vault_path: &Path, flipped_epoch: u64) -> Result<(), BaluardError> {
    let path = vault_path.join(SHAPE_PATH);
    if path.exists() {
        // Idempotent for an existing team marker.
        if shape_flipped(vault_path) {
            return Ok(());
        }
        return Err(VaultError::InvalidOperation(
            "a conflicting space-shape marker already exists".into(),
        )
        .into());
    }
    let doc = serde_json::json!({
        "mode": "team",
        "flipped_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        // The epoch at flip time: a rotation bumps the epoch, so
        // flipped_epoch == current epoch means the post-flip rotation
        // never happened (pre-flip members still hold the old key).
        "flipped_epoch": flipped_epoch,
    });
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(&doc)
            .map_err(|e| VaultError::Metadata(format!("marker serialization: {e}")))?
            .as_bytes(),
    )
    .map_err(|e| VaultError::Metadata(format!("writing shape marker: {e}")))?;
    Ok(())
}

/// A wrap pubkey the wrap path can actually use: present and valid
/// 32-byte hex. Invalid keys count as missing so one hostile or torn
/// row can never abort prepare (review F2) and can never pass the 7b
/// readiness gate.
fn usable_wrap_pubkey(member: &MemberFile) -> Option<[u8; 32]> {
    member
        .identity_wrap_pubkey
        .as_deref()
        .map(crate::vault::collections::wrap_pubkey_bytes)
        .transpose()
        .ok()
        .flatten()
}

/// Open the sealed store with the Root Key. Fails closed on a missing,
/// damaged, or foreign store.
pub fn open_store(vault_path: &Path, root: &RootKey) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let bytes = std::fs::read(space_store_path(vault_path))
        .map_err(|_| VaultError::NotFound("This vault has no space meta key yet.".into()))?;
    if bytes.len() > MAX_SPACE_FILE_BYTES {
        return Err(VaultError::Corrupt("space store too large".into()).into());
    }
    let store_key = space_store_key(root)?;
    let plain = open_secret_blob(&store_key, &bytes, SPACE_STORE_PURPOSE)?;
    let store: SpaceStore = serde_json::from_slice(&plain)
        .map_err(|_| VaultError::Corrupt("space store payload damaged".into()))?;
    let smk: [u8; 32] = hex::decode(store.smk.trim())
        .map_err(|_| VaultError::Corrupt("space store smk hex".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("space store smk length".into()))?;
    Ok(Zeroizing::new(smk))
}

/// Write the store under `root`'s store key. The rotation paths call
/// this after the swap with the SMK opened before it.
pub fn reseal_store(vault_path: &Path, root: &RootKey, smk: &[u8; 32]) -> Result<(), BaluardError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let store = SpaceStore {
        smk: hex::encode(smk),
        created_at: now,
    };
    let store_key = space_store_key(root)?;
    let doc = seal_secret_blob(
        &store_key,
        &serde_json::to_vec(&store)
            .map_err(|e| VaultError::Metadata(format!("space store serialize: {e}")))?,
        SPACE_STORE_PURPOSE,
    )?;
    write_vault_file(&space_store_path(vault_path), &doc)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write space store: {e}"))))
}

/// Mint (or re-wrap for) the SMK. Idempotent: an existing OPENABLE store
/// is kept and every live wrap-carrying member gets a fresh wrap. A
/// MISSING or damaged store is re-minted: the SMK is lost either way
/// (crash between a rotation commit and its reseal, hostile bytes), and
/// the fresh key re-wraps to every live member in the same pass, so the
/// system converges on `prepare` instead of wedging. Admin-gated at the
/// caller; the report names members that can never be wrapped so the
/// 7b flip gate has its readiness counts.
pub fn prepare(vault_path: &Path, root: &RootKey) -> Result<PrepareReport, BaluardError> {
    // Once the vault is team-shaped, a fresh SMK would orphan every
    // member-visible file sealed under the old key. The re-mint below
    // exists to converge the pre-flip crash window only.
    if shape_flipped(vault_path) && open_store(vault_path, root).is_err() {
        return Err(VaultError::InvalidOperation(
            "This vault's shared storage is damaged; a recovery is required before members can be managed.".into(),
        )
        .into());
    }
    let existing = open_store(vault_path, root).ok();
    let smk = match &existing {
        Some(smk) => Zeroizing::new(**smk),
        None => {
            let mut key = Zeroizing::new([0u8; 32]);
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(key.as_mut());
            reseal_store(vault_path, root, &key)?;
            key
        }
    };
    let mut wrapped = 0usize;
    let mut missing_wrap_pubkey = Vec::new();
    for member in live_members(vault_path)? {
        match usable_wrap_pubkey(&member) {
            Some(pub_bytes) => {
                write_space_wrap(vault_path, &member.id, &hex::encode(pub_bytes), &smk)?;
                wrapped += 1;
            }
            None => missing_wrap_pubkey.push(member.id),
        }
    }
    missing_wrap_pubkey.sort();
    Ok(PrepareReport {
        smk_fresh: existing.is_none(),
        wrapped,
        missing_wrap_pubkey,
    })
}

/// Readiness counts for the 7b flip gate. Admin surface.
pub fn status(vault_path: &Path, root: &RootKey) -> Result<SpaceStatus, BaluardError> {
    let smk = open_store(vault_path, root).ok();
    let mut wrapped = 0usize;
    let mut missing_wrap_pubkey = 0usize;
    let mut pending_wrap = 0usize;
    for member in live_members(vault_path)? {
        let has_file = space_wrap_path(vault_path, &member.id).exists();
        let usable = usable_wrap_pubkey(&member).is_some();
        if usable {
            if has_file {
                wrapped += 1;
            } else {
                pending_wrap += 1;
            }
        } else {
            missing_wrap_pubkey += 1;
        }
    }
    Ok(SpaceStatus {
        prepared: smk.is_some(),
        wrapped,
        missing_wrap_pubkey,
        pending_wrap,
        flipped_epoch: marker_flipped_epoch(vault_path),
        needs_rotation: false,
    })
}

/// The epoch recorded at flip time; None when unflipped or on legacy
/// markers (pre-dating the rotation reminder).
pub fn marker_flipped_epoch(vault_path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(vault_path.join(SHAPE_PATH)).ok()?;
    let v = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    if v["mode"].as_str() != Some("team") {
        return None;
    }
    v["flipped_epoch"].as_u64()
}

/// Seal the SMK to one member's identity wrap pubkey.
pub fn write_space_wrap(
    vault_path: &Path,
    member_id: &Uuid,
    wrap_pub_hex: &str,
    smk: &[u8; 32],
) -> Result<(), BaluardError> {
    let pub_bytes: [u8; 32] = hex::decode(wrap_pub_hex.trim())
        .map_err(|_| VaultError::InvalidOperation("That member's share key is invalid.".into()))?
        .try_into()
        .map_err(|_| VaultError::InvalidOperation("That member's share key is invalid.".into()))?;
    let recip = x25519_dalek::PublicKey::from(pub_bytes);
    let (eph, ct, tag) = hpke_wrap::wrap_key(smk, &recip, &space_wrap_context(member_id))?;
    let doc = serde_json::json!({
        "format": SPACE_WRAP_FORMAT,
        "ephemeral_public": hex::encode(eph),
        "encrypted_key": hex::encode(ct),
        "tag": hex::encode(tag),
    });
    write_vault_file(
        &space_wrap_path(vault_path, member_id),
        serde_json::to_string_pretty(&doc)
            .map_err(|e| VaultError::Metadata(format!("space wrap serialize: {e}")))?
            .as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write space wrap: {e}"))))
}

/// Open one member's wrap with their own X25519 wrapping secret.
/// Fails closed on a missing, tampered, or transplanted wrap.
pub fn open_space_wrap(
    vault_path: &Path,
    member_id: &Uuid,
    wrapping_secret: &x25519_dalek::StaticSecret,
) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
    let bytes = std::fs::read(space_wrap_path(vault_path, member_id))
        .map_err(|_| VaultError::NotFound("This member has no space meta key wrap.".into()))?;
    if bytes.len() > MAX_SPACE_FILE_BYTES {
        return Err(VaultError::Corrupt("space wrap too large".into()).into());
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::Corrupt("space wrap damaged".into()))?;
    if doc["format"].as_u64() != Some(SPACE_WRAP_FORMAT) {
        return Err(VaultError::Corrupt("unsupported space wrap format".into()).into());
    }
    let hex_field = |k: &str| -> Result<String, BaluardError> {
        doc[k]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::Corrupt("space wrap damaged".into()).into())
    };
    let eph = hex::decode(hex_field("ephemeral_public")?)
        .map_err(|_| VaultError::Corrupt("space wrap damaged".into()))?;
    let ct = hex::decode(hex_field("encrypted_key")?)
        .map_err(|_| VaultError::Corrupt("space wrap damaged".into()))?;
    let tag: [u8; 16] = hex::decode(hex_field("tag")?)
        .map_err(|_| VaultError::Corrupt("space wrap damaged".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("space wrap damaged".into()))?;
    let pt = hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        wrapping_secret,
        &space_wrap_context(member_id),
    )
    .map_err(|_| VaultError::InvalidOperation("This space key wrap cannot be read.".into()))?;
    let smk: [u8; 32] = pt
        .try_into()
        .map_err(|_| VaultError::Corrupt("space wrap payload length".into()))?;
    Ok(Zeroizing::new(smk))
}

/// Delete one member's wrap. Idempotent (missing = already gone).
pub fn remove_space_wrap(vault_path: &Path, member_id: &Uuid) -> Result<(), BaluardError> {
    match std::fs::remove_file(space_wrap_path(vault_path, member_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BaluardError::from(VaultError::Metadata(format!(
            "remove space wrap: {e}"
        )))),
    }
}

/// True when the member holds a space wrap on disk.
pub fn has_space_wrap(vault_path: &Path, member_id: &Uuid) -> bool {
    space_wrap_path(vault_path, member_id).exists()
}

/// Identity-rotation self-heal: unwrap the member's own wrap with the
/// old secret, seal to the new pubkey. The unwrap runs before any
/// write so a hostile wrap aborts with zero state change.
pub fn rewrap_own_space_wrap(
    vault_path: &Path,
    member_id: &Uuid,
    old_secret: &x25519_dalek::StaticSecret,
    new_wrap_pub_hex: &str,
) -> Result<usize, BaluardError> {
    if !has_space_wrap(vault_path, member_id) {
        return Ok(0);
    }
    let smk = open_space_wrap(vault_path, member_id, old_secret)?;
    write_space_wrap(vault_path, member_id, new_wrap_pub_hex, &smk)?;
    Ok(1)
}

/// Force-rotate the SMK: fresh key, re-sealed store, every live
/// wrap-carrying member re-wrapped. The offboarding primitive (review
/// F4): a removed member knew the old SMK, so removal must retire it.
/// In this additive slice nothing is SMK-encrypted yet, so the call is
/// best-effort at the caller; the 7b flip makes it authoritative.
pub fn rotate(
    vault_path: &Path,
    root: &RootKey,
) -> Result<(PrepareReport, Zeroizing<[u8; 32]>), BaluardError> {
    let mut key = Zeroizing::new([0u8; 32]);
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    reseal_store(vault_path, root, &key)?;
    let mut wrapped = 0usize;
    let mut missing_wrap_pubkey = Vec::new();
    for member in live_members(vault_path)? {
        match usable_wrap_pubkey(&member) {
            Some(pub_bytes) => {
                write_space_wrap(vault_path, &member.id, &hex::encode(pub_bytes), &key)?;
                wrapped += 1;
            }
            None => missing_wrap_pubkey.push(member.id),
        }
    }
    missing_wrap_pubkey.sort();
    let report = PrepareReport {
        smk_fresh: true,
        wrapped,
        missing_wrap_pubkey,
    };
    Ok((report, key))
}

const SMK_PENDING_PATH: &str = "meta/.smk-pending.json";

/// Record the OUTGOING SMK before a removal's rotation flips the store,
/// so a crash in the re-seal window converges at the next admin unlock.
/// Local-only (gitignored), 0600 — it carries the retired key.
pub fn write_smk_pending(
    vault_path: &Path,
    old_smk: &Zeroizing<[u8; 32]>,
) -> Result<(), BaluardError> {
    let doc = serde_json::json!({
        "format": 1,
        "smk": hex::encode(old_smk.as_ref()),
    });
    let bytes = serde_json::to_vec_pretty(&doc)
        .map_err(|e| VaultError::Metadata(format!("smk marker: {e}")))?;
    write_vault_file(&vault_path.join(SMK_PENDING_PATH), &bytes)
        .map_err(|e| VaultError::Metadata(format!("smk marker write: {e}")))?;
    Ok(())
}

/// Read the recorded outgoing SMK hex; None when absent or malformed.
pub fn read_smk_pending(vault_path: &Path) -> Option<String> {
    let bytes = std::fs::read(vault_path.join(SMK_PENDING_PATH)).ok()?;
    let doc = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    if doc["format"].as_u64() != Some(1) {
        return None;
    }
    doc["smk"].as_str().map(|s| s.to_string())
}

pub fn clear_smk_pending(vault_path: &Path) {
    let _ = std::fs::remove_file(vault_path.join(SMK_PENDING_PATH));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::hierarchy::SpaceGroupKey;
    use crate::vault::collections;
    use std::path::PathBuf;

    fn temp_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        std::fs::create_dir_all(path.join("meta")).unwrap();
        (dir, path)
    }

    fn member_row(id: Uuid, role: members::MemberRole, wrap: Option<String>) -> MemberFile {
        MemberFile {
            id,
            display_name: format!("m-{id}"),
            email: None,
            role,
            trust: members::TrustLevel::Channel,
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

    fn identity(seed: u8) -> crate::vault::identity::IdentityKeys {
        crate::vault::identity::IdentityKeys::from_seed(&[seed; 32])
    }

    #[test]
    fn prepare_store_and_wrap_roundtrip() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let alice_id = identity(0x11);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();

        let report = prepare(&path, &root).unwrap();
        assert!(report.smk_fresh);
        assert_eq!(report.wrapped, 1);
        assert!(report.missing_wrap_pubkey.is_empty());

        // Idempotent re-run: same SMK, no fresh mint.
        let again = prepare(&path, &root).unwrap();
        assert!(!again.smk_fresh);

        let via_store = open_store(&path, &root).unwrap();
        let via_wrap = open_space_wrap(&path, &alice, alice_id.wrapping_secret()).unwrap();
        assert_eq!(*via_store, *via_wrap);
    }

    #[test]
    fn store_opens_only_with_root() {
        let (_d, path) = temp_vault();
        prepare(&path, &RootKey::generate()).unwrap();
        assert!(open_store(&path, &RootKey::generate()).is_err());
    }

    #[test]
    fn wrap_transplant_between_members_fails() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let mallory = Uuid::new_v4();
        let alice_id = identity(0x21);
        let mallory_id = identity(0x22);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        members::write_member(
            &path,
            &member_row(
                mallory,
                members::MemberRole::Editor,
                Some(hex::encode(mallory_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();

        // Copy Alice's wrap into Mallory's subtree: the context binding
        // refuses it at open time.
        std::fs::copy(
            space_wrap_path(&path, &alice),
            space_wrap_path(&path, &mallory),
        )
        .unwrap();
        assert!(open_space_wrap(&path, &mallory, mallory_id.wrapping_secret()).is_err());
        // The honest wrap still opens.
        assert!(open_space_wrap(&path, &alice, alice_id.wrapping_secret()).is_ok());
    }

    #[test]
    fn status_reports_coverage_gaps() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let ready = Uuid::new_v4();
        let legacy = Uuid::new_v4();
        let ready_id = identity(0x31);
        members::write_member(
            &path,
            &member_row(
                ready,
                members::MemberRole::Editor,
                Some(hex::encode(ready_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        // Legacy row: no wrap pubkey (pre-P1 approval).
        members::write_member(
            &path,
            &member_row(legacy, members::MemberRole::Viewer, None),
        )
        .unwrap();

        let st = status(&path, &root).unwrap();
        assert!(!st.prepared);

        let report = prepare(&path, &root).unwrap();
        assert_eq!(report.wrapped, 1);
        assert_eq!(report.missing_wrap_pubkey, vec![legacy]);

        let st = status(&path, &root).unwrap();
        assert!(st.prepared);
        assert_eq!(st.wrapped, 1);
        assert_eq!(st.missing_wrap_pubkey, 1);
        assert_eq!(st.pending_wrap, 0);

        // A wrap-pubkey row without a file counts pending.
        let late = Uuid::new_v4();
        let late_id = identity(0x32);
        members::write_member(
            &path,
            &member_row(
                late,
                members::MemberRole::Viewer,
                Some(hex::encode(late_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        let st = status(&path, &root).unwrap();
        assert_eq!(st.pending_wrap, 1);
        // Prepare closes the gap.
        prepare(&path, &root).unwrap();
        let st = status(&path, &root).unwrap();
        assert_eq!(st.pending_wrap, 0);
        assert_eq!(st.wrapped, 2);
    }

    #[test]
    fn tombstoned_rows_never_count() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let gone = Uuid::new_v4();
        members::write_member(&path, &member_row(gone, members::MemberRole::Editor, None)).unwrap();
        // Tombstone.
        let mut row = members::member_file_by_id(&path, gone).unwrap();
        row.removed = Some(0);
        members::write_member(&path, &row).unwrap();

        let report = prepare(&path, &root).unwrap();
        assert_eq!(report.wrapped, 0);
        assert!(report.missing_wrap_pubkey.is_empty());
        let st = status(&path, &root).unwrap();
        assert_eq!(st.missing_wrap_pubkey, 0);
    }

    #[test]
    fn rewrap_own_survives_identity_rotation() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let old_id = identity(0x41);
        let new_id = identity(0x42);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(old_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();

        let n = rewrap_own_space_wrap(
            &path,
            &alice,
            old_id.wrapping_secret(),
            &hex::encode(new_id.wrapping_pub_bytes()),
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(open_space_wrap(&path, &alice, new_id.wrapping_secret()).is_ok());
        assert!(open_space_wrap(&path, &alice, old_id.wrapping_secret()).is_err());

        // A member without a wrap re-wraps nothing.
        let bare = Uuid::new_v4();
        members::write_member(&path, &member_row(bare, members::MemberRole::Viewer, None)).unwrap();
        let n = rewrap_own_space_wrap(
            &path,
            &bare,
            old_id.wrapping_secret(),
            &hex::encode(new_id.wrapping_pub_bytes()),
        )
        .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn tampered_wrap_and_store_fail_closed() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let alice_id = identity(0x61);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();

        // Flip one character late in the wrap (tag region): open refuses.
        let wrap_path = space_wrap_path(&path, &alice);
        let mut text = std::fs::read_to_string(&wrap_path).unwrap();
        let idx = text.rfind('"').unwrap() - 2;
        let flipped = if text.as_bytes()[idx] == b'f' {
            '0'
        } else {
            'f'
        };
        text.replace_range(idx..idx + 1, &flipped.to_string());
        std::fs::write(&wrap_path, &text).unwrap();
        assert!(open_space_wrap(&path, &alice, alice_id.wrapping_secret()).is_err());

        // A tampered store fails closed for the admin too.
        let store = path.join("meta/space.enc");
        let mut bytes = std::fs::read(&store).unwrap();
        let last = bytes.len() - 2;
        bytes[last] = bytes[last].wrapping_add(1);
        std::fs::write(&store, &bytes).unwrap();
        assert!(open_store(&path, &root).is_err());
        // And prepare converges: re-mints over the damaged store.
        let report = prepare(&path, &root).unwrap();
        assert!(report.smk_fresh, "damaged store is re-minted");
        assert!(open_store(&path, &root).is_ok());
    }

    #[test]
    fn oversized_store_and_wrap_refuse() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let alice_id = identity(0x62);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();

        let junk = vec![0u8; MAX_SPACE_FILE_BYTES + 1];
        std::fs::write(path.join("meta/space.enc"), &junk).unwrap();
        assert!(open_store(&path, &root).is_err());
        std::fs::write(space_wrap_path(&path, &alice), &junk).unwrap();
        assert!(open_space_wrap(&path, &alice, alice_id.wrapping_secret()).is_err());
    }

    #[test]
    fn malformed_wrap_pubkey_counts_missing_not_abort() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let hostile = Uuid::new_v4();
        members::write_member(
            &path,
            &member_row(
                hostile,
                members::MemberRole::Editor,
                Some("zz-not-hex".to_string()),
            ),
        )
        .unwrap();
        // Review F2: prepare must not abort on the hostile row.
        let report = prepare(&path, &root).unwrap();
        assert_eq!(report.wrapped, 0);
        assert_eq!(report.missing_wrap_pubkey, vec![hostile]);
        let st = status(&path, &root).unwrap();
        assert_eq!(st.missing_wrap_pubkey, 1);
        assert_eq!(st.pending_wrap, 0);
    }

    #[test]
    fn shape_marker_read_write_and_damaged() {
        let (_d, path) = temp_vault();
        assert!(!shape_flipped(&path));
        write_shape_marker(&path, 1).unwrap();
        assert!(shape_flipped(&path));
        // Idempotent.
        write_shape_marker(&path, 1).unwrap();
        // Damaged marker reads false (fail toward the legacy path).
        std::fs::write(path.join(SHAPE_PATH), b"{not json").unwrap();
        assert!(!shape_flipped(&path));
    }

    #[test]
    fn rotate_retires_the_smk_and_rewraps_survivors() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let alice_id = identity(0x63);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();
        let old_smk = open_store(&path, &root).unwrap();

        // Offboarding primitive: fresh SMK, survivors re-wrapped.
        let (report, rotated_smk) = rotate(&path, &root).unwrap();
        assert!(report.smk_fresh);
        assert_eq!(report.wrapped, 1);
        let new_smk = open_store(&path, &root).unwrap();
        assert_ne!(*new_smk, *old_smk);
        assert_eq!(*new_smk, *rotated_smk);
        assert_eq!(
            *open_space_wrap(&path, &alice, alice_id.wrapping_secret()).unwrap(),
            *new_smk
        );
    }

    #[test]
    fn remove_space_wrap_is_idempotent() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        let alice = Uuid::new_v4();
        let alice_id = identity(0x51);
        members::write_member(
            &path,
            &member_row(
                alice,
                members::MemberRole::Editor,
                Some(hex::encode(alice_id.wrapping_pub_bytes())),
            ),
        )
        .unwrap();
        prepare(&path, &root).unwrap();
        assert!(has_space_wrap(&path, &alice));
        remove_space_wrap(&path, &alice).unwrap();
        remove_space_wrap(&path, &alice).unwrap();
        assert!(!has_space_wrap(&path, &alice));
    }

    #[test]
    fn store_reseal_under_new_root_keeps_smk() {
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        prepare(&path, &root).unwrap();
        let smk = open_store(&path, &root).unwrap();

        // Rotation half: re-seal under the new root (mirrors what the
        // handle rotation paths do after the swap).
        let new_root = RootKey::generate();
        reseal_store(&path, &new_root, &smk).unwrap();
        assert!(open_store(&path, &root).is_err());
        let again = open_store(&path, &new_root).unwrap();
        assert_eq!(*again, *smk);
    }

    #[test]
    fn smk_is_independent_of_sgk_and_collections() {
        // Documentation-in-code: the SMK shares no derivation with the
        // SGK or any collection key, and collections keep working
        // untouched beside it.
        let (_d, path) = temp_vault();
        let root = RootKey::generate();
        prepare(&path, &root).unwrap();
        let smk = open_store(&path, &root).unwrap();
        let sgk = SpaceGroupKey::derive_from_root_key(&root, 1);
        assert_ne!(*smk, *sgk.as_bytes());
        let file = collections::create_collection(&path, &sgk, "Work").unwrap();
        assert!(collections::open_collection(&path, &sgk, &file.id).is_ok());
    }
}
