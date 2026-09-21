//! S1a slice 1: membership v2 directory (plan-sharing §4.2).
//!
//! `meta/members/<member_id>.json` — one file per member: id, display
//! name, role, trust. `meta/members/<member_id>/devices/<device_id>.json`
//! — the device-to-member binding (presence = membership). Plaintext by
//! design: the sync-visible surface is UUIDs + display names + trust
//! (plan constraint 8). All writes go through the hardened vault-file
//! writer.
//!
//! Legacy rule (engine.rs): a commit tree without a `meta/members`
//! subtree is pre-S1a and stays admin-equivalent; a tree WITH the
//! subtree is strict — an unbound device is a PendingJoiner.

use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

use crate::error::{BaluardError, VaultError};

pub const MEMBERS_DIR: &str = "meta/members";

/// Owner-side pending invites live OUTSIDE the member directory: the
/// strict member-shape validator would reject their two-segment shape,
/// and they are admin working state, not member data.
pub const INVITES_DIR: &str = "meta/invites";

/// Member role. Rank order mirrors sync::policy::CommitRole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Owner,
    Admin,
    Editor,
    Viewer,
}

/// Trust level from the graded dial (plan-sharing §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    #[serde(rename = "self")]
    SelfTrust,
    Channel,
    Verified,
    Admin,
    AdminUnverified,
}

/// One member of the vault (plan-sharing §4.2). Encrypted portions
/// (per-provider handles, optional email) arrive with later S1a slices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberFile {
    pub id: Uuid,
    pub display_name: String,
    pub role: MemberRole,
    pub trust: TrustLevel,
    /// S1a-4: the member's current identity signing pubkey (hex). `None`
    /// on records written before this field existed.
    #[serde(default)]
    pub identity_signing_pubkey: Option<String>,
    /// S1a-4: the pubkey this one replaced at the last rotation (hex).
    /// Links the rotation to its predecessor so stale-contact
    /// reconciliation can scope the trust reset to real rotations.
    #[serde(default)]
    pub identity_signing_pubkey_previous: Option<String>,
    /// S1a-4: hex Ed25519 signature by the NEW identity key over the
    /// rotation payload — proof of possession of the new key.
    #[serde(default)]
    pub identity_rotation_signature: Option<String>,
    /// S1a-4: unix timestamp of the last identity rotation, if any.
    /// Clients surface this so contact re-verification can happen
    /// (rotation is visible and contestable per §4.1).
    #[serde(default)]
    pub identity_rotated_at: Option<u64>,
    /// S1a-5: member reset marker (§5.F-8, scenario L: device gone AND
    /// phrase gone). Present = the row is tombstoned: its identity is
    /// dead (see the cleared identity fields), its bindings resolve to
    /// nothing, and `successor` is the fresh row the re-join ceremony
    /// adopts. Tombstones are admin-authored; entries are preserved.
    #[serde(default)]
    pub reset: Option<MemberReset>,
    /// S1a-6: removal marker (departure/eviction). Same tombstone
    /// semantics as `reset` but terminal — no successor exists, the
    /// member's devices are struck from the registry, their keywraps
    /// are deleted, and the Root Key rotates so their wrapped copy is
    /// dead. Value = unix seconds at removal.
    #[serde(default)]
    pub removed: Option<u64>,
}

/// S1a-5: reset provenance on a tombstoned member row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberReset {
    /// The successor member row created by the reset.
    pub successor: Uuid,
    /// Unix seconds at reset time.
    pub at: u64,
}

/// Device-to-member binding. Presence of this file = the device belongs
/// to the member (roles resolve through it in the verification walk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBinding {
    pub device_id: Uuid,
    pub member_id: Uuid,
}

/// Write (or replace) one member file.
pub fn write_member(vault_path: &Path, member: &MemberFile) -> Result<(), BaluardError> {
    let path = vault_path
        .join(MEMBERS_DIR)
        .join(format!("{}.json", member.id));
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(member).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write member: {e}"))))
}

/// Write (or replace) one device-to-member binding.
pub fn write_device_binding(
    vault_path: &Path,
    binding: &DeviceBinding,
) -> Result<(), BaluardError> {
    let dir = vault_path
        .join(MEMBERS_DIR)
        .join(binding.member_id.to_string())
        .join("devices");
    std::fs::create_dir_all(&dir).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("member devices dir: {e}")))
    })?;
    let path = dir.join(format!("{}.json", binding.device_id));
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(binding).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write binding: {e}"))))
}

/// Find the owner member id (role == Owner). `None` when the directory is
/// absent (legacy vault) or carries no owner yet.
pub fn owner_member_id(vault_path: &Path) -> Option<Uuid> {
    let dir = vault_path.join(MEMBERS_DIR);
    let entries = std::fs::read_dir(&dir).ok()?;
    // S1a-7 review: SORTED scan (an abnormal two-owner state from a
    // mid-transfer crash resolves deterministically on every device)
    // and tombstoned rows never resolve (a reset/removed row cannot
    // own).
    let mut stems: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json").map(|s| s.to_string())
        })
        .collect();
    stems.sort();
    for stem in stems {
        if let Ok(json) = std::fs::read_to_string(dir.join(format!("{stem}.json"))) {
            if let Ok(member) = serde_json::from_str::<MemberFile>(&json) {
                if member.role == MemberRole::Owner
                    && member.id.to_string() == stem
                    && member.reset.is_none()
                    && member.removed.is_none()
                {
                    return Some(member.id);
                }
            }
        }
    }
    None
}

/// Bind a device to the owner member (before member invites exist, every
/// device of the single human is the owner's). No-op when the vault has
/// no owner member: a legacy layout stays legacy, and a strict vault
/// without an owner refuses the unbound device at verification time.
pub fn bind_to_owner(vault_path: &Path, device_id: Uuid) -> Result<(), BaluardError> {
    if let Some(member_id) = owner_member_id(vault_path) {
        write_device_binding(
            vault_path,
            &DeviceBinding {
                device_id,
                member_id,
            },
        )?;
    }
    Ok(())
}

/// Canonical rotation payload: signed by the NEW identity key at
/// rotation; verified at pull by the structural member-record rule.
pub fn identity_rotation_payload(
    member_id: &Uuid,
    new_pubkey: &str,
    previous_pubkey: &str,
) -> Vec<u8> {
    let mut payload = b"baluard-identity-rotate-v1\n".to_vec();
    payload.extend_from_slice(member_id.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(new_pubkey.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(previous_pubkey.as_bytes());
    payload
}

/// S1a-5: member reset (§5.F-8, scenario L: device gone AND phrase
/// gone). Tombstones `old_member_id` (identity cleared, previous-key
/// set so contact reconciliation resets the dial, bindings dead) and
/// creates the successor row (fresh id, same display name + role,
/// trust back at Channel for re-verification). Returns the successor
/// id and a one-time reset invite bound to it: approval flows through
/// the NORMAL join ceremony but binds the successor row instead of
/// minting a new one. Entries are untouched. Actor gating (admin+,
/// not-self, not-owner) is the caller's job.
pub fn reset_member(
    vault_path: &Path,
    vault_id: Uuid,
    old_member_id: Uuid,
) -> Result<(Uuid, String), BaluardError> {
    let deny = |msg: &str| BaluardError::from(VaultError::InvalidOperation(msg.to_string()));
    let path = vault_path
        .join(MEMBERS_DIR)
        .join(format!("{old_member_id}.json"));
    let data = std::fs::read_to_string(&path).map_err(|_| deny("member not found"))?;
    let mut old: MemberFile =
        serde_json::from_str(&data).map_err(|e| deny(&format!("member record unreadable: {e}")))?;
    if old.reset.is_some() || old.removed.is_some() {
        return Err(deny("member is already tombstoned"));
    }
    if old.role == MemberRole::Owner {
        return Err(deny(
            "the owner row cannot be reset (use ownership transfer)",
        ));
    }
    let successor_id = Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Tombstone: clear the identity so no client treats the old key as
    // current; park it in `previous` so stale-contact reconciliation
    // downgrades address book entries that still carry it.
    old.identity_signing_pubkey_previous = old.identity_signing_pubkey.take();
    old.identity_rotation_signature = None;
    old.reset = Some(MemberReset {
        successor: successor_id,
        at: now,
    });
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(&old).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write tombstone: {e}"))))?;
    let successor = MemberFile {
        id: successor_id,
        display_name: old.display_name.clone(),
        role: old.role,
        trust: TrustLevel::Channel,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
    };
    write_member(vault_path, &successor)?;
    let code = create_invite(vault_path, vault_id, old.role, Some(successor_id))?;
    Ok((successor_id, code))
}

/// S1a-6: tombstone a member row for REMOVAL (departure/eviction).
/// Terminal — unlike `reset_member` there is no successor. Clears the
/// identity (dead key parked in `previous` so contact reconciliation
/// resets the dial) and returns the device ids bound to the member so
/// the caller can strike them from the registry, delete their keywraps,
/// and rotate the Root Key. Bindings stay on disk (inert: the row
/// resolves no role and no bindings). Entries are preserved. Actor
/// gating is the caller's job.
pub fn remove_member(vault_path: &Path, member_id: Uuid) -> Result<Vec<Uuid>, BaluardError> {
    let deny = |msg: &str| BaluardError::from(VaultError::InvalidOperation(msg.to_string()));
    let path = vault_path
        .join(MEMBERS_DIR)
        .join(format!("{member_id}.json"));
    let data = std::fs::read_to_string(&path).map_err(|_| deny("member not found"))?;
    let mut member: MemberFile =
        serde_json::from_str(&data).map_err(|e| deny(&format!("member record unreadable: {e}")))?;
    if member.reset.is_some() || member.removed.is_some() {
        return Err(deny("member is already tombstoned"));
    }
    if member.role == MemberRole::Owner {
        return Err(deny(
            "the owner row cannot be removed (transfer ownership first)",
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    member.identity_signing_pubkey_previous = member.identity_signing_pubkey.take();
    member.identity_rotation_signature = None;
    member.removed = Some(now);
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(&member).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write removal: {e}"))))?;
    // Collect the member's device ids (bindings stay on disk, inert).
    let mut devices = Vec::new();
    let devices_dir = vault_path
        .join(MEMBERS_DIR)
        .join(member_id.to_string())
        .join("devices");
    if let Ok(entries) = std::fs::read_dir(&devices_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if let Ok(id) = Uuid::parse_str(stem) {
                devices.push(id);
            }
        }
    }
    Ok(devices)
}

/// S1a-7: ownership transfer (§4.2, first-class action). A role change
/// on TWO member records: `old_member_id` (the current Owner row) is
/// demoted to Admin, `new_member_id` is promoted to Owner with
/// SelfTrust. Exactly one Owner row exists before and after — the two
/// writes ship in ONE git commit, so the atomic unit is the commit, not
/// the working tree. Mechanics only; actor gating (owner-only) is the
/// caller's job.
pub fn transfer_ownership(
    vault_path: &Path,
    old_member_id: Uuid,
    new_member_id: Uuid,
) -> Result<(), BaluardError> {
    let deny = |msg: &str| BaluardError::from(VaultError::InvalidOperation(msg.to_string()));
    if old_member_id == new_member_id {
        return Err(deny("the vault is already owned by this member"));
    }
    let old_path = vault_path
        .join(MEMBERS_DIR)
        .join(format!("{old_member_id}.json"));
    let data = std::fs::read_to_string(&old_path).map_err(|_| deny("owner row not found"))?;
    let mut old: MemberFile =
        serde_json::from_str(&data).map_err(|e| deny(&format!("owner record unreadable: {e}")))?;
    if old.role != MemberRole::Owner {
        return Err(deny("only the owner can transfer ownership"));
    }
    if old.reset.is_some() || old.removed.is_some() {
        return Err(deny("owner row is tombstoned"));
    }
    let new_path = vault_path
        .join(MEMBERS_DIR)
        .join(format!("{new_member_id}.json"));
    let data =
        std::fs::read_to_string(&new_path).map_err(|_| deny("successor member not found"))?;
    let mut new: MemberFile = serde_json::from_str(&data)
        .map_err(|e| deny(&format!("successor record unreadable: {e}")))?;
    if new.reset.is_some() || new.removed.is_some() {
        return Err(deny("successor row is tombstoned"));
    }
    // S1a-7 review: PROMOTE first, demote second. A crash between the
    // two writes must never leave ZERO owners (vault bricked); promote-
    // first leaves TWO owners at worst — an abnormal-but-recoverable
    // state the transfer gate tolerates (an owner-role actor can re-run,
    // which demotes the second owner). Each file write is atomic
    // (tmp+rename); the two-file window closes when the commit lands.
    new.role = MemberRole::Owner;
    new.trust = TrustLevel::SelfTrust;
    super::write_vault_file(
        &new_path,
        serde_json::to_string_pretty(&new).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("promote owner: {e}"))))?;
    old.role = MemberRole::Admin;
    // S1a-7 review: a demoted owner must not keep SelfTrust — repeated
    // transfers would otherwise accumulate SelfTrust Admin rows.
    if old.trust == TrustLevel::SelfTrust {
        old.trust = TrustLevel::Verified;
    }
    super::write_vault_file(
        &old_path,
        serde_json::to_string_pretty(&old).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("demote owner: {e}"))))?;
    Ok(())
}

/// Role of `device_id`'s member, from the on-disk directory. `None` when
/// unbound, legacy (no member directory), or bound to a TOMBSTONED row
/// (S1a-5: reset kills the member's device bindings).
pub fn member_role_for_device(vault_path: &Path, device_id: Uuid) -> Option<MemberRole> {
    let dir = vault_path.join(MEMBERS_DIR);
    let entries = std::fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Bindings live at meta/members/<member_id>/devices/<device_id>.json
        // — resolve the member DIRECTORY from the row file's stem, never
        // join under the file itself.
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let binding = dir
            .join(stem)
            .join("devices")
            .join(format!("{device_id}.json"));
        if !binding.exists() {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(entry.path()) {
            if let Ok(member) = serde_json::from_str::<MemberFile>(&json) {
                if member.id.to_string() == stem
                    && member.reset.is_none()
                    && member.removed.is_none()
                {
                    return Some(member.role);
                }
            }
        }
    }
    None
}

/// The member file for the member `device_id` is bound to, plus its
/// on-disk path. `None` when unbound, legacy (no member directory), or
/// bound to a tombstoned row.
pub(crate) fn member_file_for_device(
    vault_path: &Path,
    device_id: Uuid,
) -> Option<(std::path::PathBuf, MemberFile)> {
    let dir = vault_path.join(MEMBERS_DIR);
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        // Bindings live at meta/members/<member_id>/devices/<device_id>.json.
        let binding = vault_path
            .join(MEMBERS_DIR)
            .join(stem)
            .join("devices")
            .join(format!("{device_id}.json"));
        if !binding.exists() {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(entry.path()) {
            if let Ok(member) = serde_json::from_str::<MemberFile>(&json) {
                if member.id.to_string() == stem
                    && member.reset.is_none()
                    && member.removed.is_none()
                {
                    return Some((entry.path(), member));
                }
            }
        }
    }
    None
}

/// S1a-5: one member row by id.
pub fn member_file_by_id(vault_path: &Path, member_id: Uuid) -> Option<MemberFile> {
    let json = std::fs::read_to_string(
        vault_path
            .join(MEMBERS_DIR)
            .join(format!("{member_id}.json")),
    )
    .ok()?;
    serde_json::from_str(&json).ok()
}

/// §4.8-1: every member row for the People surface. Walks the directory
/// (row files only — the per-member `devices/` subtrees are skipped).
/// Malformed rows are skipped inert: the directory is git-synced and a
/// corrupt foreign row must not blind the whole People screen.
pub fn list_members(vault_path: &Path) -> Result<Vec<MemberFile>, BaluardError> {
    let dir = vault_path.join(MEMBERS_DIR);
    let mut members = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // No directory = legacy vault (pre-S1a): empty directory, the UI
        // shows the owner-only state.
        Err(_) => return Ok(members),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(member) = serde_json::from_str::<MemberFile>(&json) {
                members.push(member);
            }
        }
    }
    members.sort_by(|a, b| b.id.as_bytes().cmp(a.id.as_bytes()));
    Ok(members)
}

/// S1a-4: record the member's current identity signing pubkey and the
/// rotation timestamp. Self-service: any bound member updates their own
/// record (policy table row `meta/members/<own_id>/**`). The delta is
/// only admitted at verification when `rotation_signature` proves
/// possession of the NEW identity key. No-op on legacy vaults.
pub fn set_member_identity(
    vault_path: &Path,
    device_id: Uuid,
    identity_signing_pubkey: &str,
    previous_pubkey: Option<&str>,
    rotation_signature: &str,
    rotated_at: u64,
) -> Result<(), BaluardError> {
    if let Some((path, mut member)) = member_file_for_device(vault_path, device_id) {
        member.identity_signing_pubkey = Some(identity_signing_pubkey.to_string());
        member.identity_signing_pubkey_previous = previous_pubkey.map(|s| s.to_string());
        member.identity_rotation_signature = Some(rotation_signature.to_string());
        member.identity_rotated_at = Some(rotated_at);
        super::write_vault_file(
            &path,
            serde_json::to_string_pretty(&member).unwrap().as_bytes(),
        )
        .map_err(|e| {
            BaluardError::from(VaultError::Metadata(format!("update member identity: {e}")))
        })?;
    }
    Ok(())
}

/// Device-local member unlock material for `device_id`, if this device
/// is a member device (meta/member-unlock.json, gitignored).
pub fn load_member_unlock(
    vault_path: &Path,
    device_id: Uuid,
) -> Result<Option<MemberUnlock>, BaluardError> {
    let path = vault_path.join("meta/member-unlock.json");
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("read member unlock: {e}")))
    })?;
    let unlock: MemberUnlock = serde_json::from_str(&data).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("parse member unlock: {e}")))
    })?;
    if unlock.device_id != device_id {
        return Ok(None);
    }
    Ok(Some(unlock))
}

/// The identity signing pubkey recorded for `device_id`'s member.
pub fn identity_pubkey_for_device(vault_path: &Path, device_id: Uuid) -> Option<String> {
    member_file_for_device(vault_path, device_id).and_then(|(_, m)| m.identity_signing_pubkey)
}

// ── S1a-2: join ceremony (invite → introduce → approve) ──
//
// Thin offline variant of the §4.1 join queue: the owner mints a
// one-time invite code (secret travels out-of-band; only its hash is
// stored repo-side), the joiner clones + introduces (a code carrying
// their device public keys and a proof of the invite secret), and an
// admin approves asynchronously — which wraps the Root Key to the
// joiner's device and ships the member record via the normal sync
// cycle. No provider API involved; transport staging (P8c) slots in
// here later.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Owner-side one-time invite (travels out-of-band inside the code; the
/// repo-side pending file records only the secret hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    pub vault_id: Uuid,
    pub invite_id: Uuid,
    pub role: MemberRole,
    /// Random 32 bytes, hex. Proven at introduction; only its hash is
    /// stored repo-side.
    pub secret: String,
}

/// Repo-side pending invite record (admin-owned file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInviteFile {
    pub invite_id: Uuid,
    pub role: MemberRole,
    pub secret_hash: String,
    /// S1a-5: member reset invites name the successor row the approval
    /// must bind (display name + role are admin-fixed; the joiner
    /// cannot rename themselves through the introduction).
    #[serde(default)]
    pub target_member: Option<Uuid>,
}

/// Joiner-side self-introduction (§4.1 join queue, offline thin
/// variant): exported as a code and presented to an admin for async
/// approval. Carries the joiner's device public keys, a proof of the
/// invite secret, and (S1a-3) their identity-signed contact card. No
/// vault secrets exist on the joiner's device yet — the approval ships
/// the keywrap via the normal sync cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Introduction {
    pub vault_id: Uuid,
    pub invite_id: Uuid,
    pub secret: String,
    pub device_id: Uuid,
    pub encryption_public_key: String,
    pub signing_public_key: String,
    pub display_name: String,
    /// S1a-3: the joiner's identity-signed contact card (trust dial).
    #[serde(default)]
    pub contact_card: Option<crate::vault::contacts::SignedContactCard>,
    /// S1a-3: Ed25519 signature by the card's identity key over the
    /// device-key payload — binds the introduced device keys to the
    /// verified identity. Required for elevated-role approvals.
    #[serde(default)]
    pub identity_signature: Option<String>,
}

impl Introduction {
    /// Canonical payload binding the introduced device keys to the
    /// contact card's identity key (signed by the identity at
    /// introduction; verified at approval for elevated roles).
    pub fn identity_sign_payload(
        invite_id: Uuid,
        device_id: Uuid,
        encryption_public_key: &str,
        signing_public_key: &str,
        identity_signing_pubkey: &str,
    ) -> Vec<u8> {
        let mut payload = b"baluard-intro-v1\n".to_vec();
        payload.extend_from_slice(invite_id.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(device_id.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(encryption_public_key.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(signing_public_key.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(identity_signing_pubkey.as_bytes());
        payload
    }

    /// Decode an introduction code (base64url JSON).
    pub fn decode(code: &str) -> Result<Self, BaluardError> {
        let bytes = b64_decode(code)?;
        let json = std::str::from_utf8(&bytes)
            .map_err(|e| BaluardError::from(VaultError::Metadata(format!("bad code: {e}"))))?;
        serde_json::from_str(json)
            .map_err(|e| BaluardError::from(VaultError::Metadata(format!("bad code: {e}"))))
    }

    /// Re-encode an introduction as a code (base64url JSON). Round-trips
    /// with [`Introduction::decode`] — the S1a-8 join queue uses this to
    /// feed staged requests through the standard approval path.
    pub fn encode(&self) -> Result<String, BaluardError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| BaluardError::from(VaultError::Metadata(format!("encode intro: {e}"))))?;
        Ok(b64_encode(&json))
    }
}

/// Device-local member unlock material (meta/member-unlock.json,
/// gitignored): the member's own KDF params + KEK canary. The member's
/// password never touches the founding device's vault-level material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberUnlock {
    pub device_id: Uuid,
    pub kdf_params: crate::types::KdfParams,
    /// Hex-encoded KEK canary for the member's own password.
    pub kek_canary: String,
    /// S1a-3: the member's own identity seed, sealed under their
    /// kek-derived devkey seal (domain member-identity-v1). Device-local
    /// tracer substitution for the identity-rooted model.
    #[serde(default)]
    pub identity_seed_sealed: Option<String>,
}

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, BaluardError> {
    base64::engine::general_purpose::URL_SAFE
        .decode(s)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("bad code: {e}"))))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Owner: mint a one-time invite. Returns the invite code
/// (out-of-band). The repo-side pending record carries the role and the
/// secret hash; it is consumed at approval (single-use).
/// `target_member` (S1a-5) is set on reset invites: approval binds that
/// existing successor row instead of minting a new member.
pub fn create_invite(
    vault_path: &Path,
    vault_id: Uuid,
    role: MemberRole,
    target_member: Option<Uuid>,
) -> Result<String, BaluardError> {
    // S1a-7 review: an Owner invite would mint a SECOND owner row at
    // approval, violating the single-owner invariant. Ownership changes
    // go through transfer_ownership only. (Reset invites never carry
    // Owner either — the owner row cannot be reset.)
    if role == MemberRole::Owner {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "ownership cannot be invited; use transfer_ownership".into(),
        )));
    }
    let mut secret = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let invite_id = Uuid::new_v4();
    let secret_hex = hex::encode(secret);
    let pending = PendingInviteFile {
        invite_id,
        role,
        // Hash of the hex-encoded secret (the exact string carriers in
        // the code present at introduction — same domain on both sides).
        secret_hash: sha256_hex(secret_hex.as_bytes()),
        target_member,
    };
    let dir = vault_path.join(INVITES_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("pending dir: {e}"))))?;
    super::write_vault_file(
        &dir.join(format!("{invite_id}.json")),
        serde_json::to_string_pretty(&pending).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write pending invite: {e}"))))?;
    let code = InviteCode {
        vault_id,
        invite_id,
        role,
        secret: secret_hex,
    };
    Ok(b64_encode(serde_json::to_string(&code).unwrap().as_bytes()))
}

/// Read (peek) the pending invite WITHOUT consuming it. Consumption is
/// `consume_pending_invite`.
pub fn read_pending_invite(
    vault_path: &Path,
    invite_id: Uuid,
) -> Result<PendingInviteFile, BaluardError> {
    let path = vault_path
        .join(INVITES_DIR)
        .join(format!("{invite_id}.json"));
    let data = std::fs::read_to_string(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("pending invite: {e}"))))?;
    serde_json::from_str(&data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("pending invite: {e}"))))
}

/// Verify + consume the pending invite for one introduction.
/// Single-use: a wrong secret is NOT consumed (typo can retry); a
/// correct one is.
pub fn consume_pending_invite(
    vault_path: &Path,
    invite_id: Uuid,
    secret: &str,
) -> Result<PendingInviteFile, BaluardError> {
    let path = vault_path
        .join(INVITES_DIR)
        .join(format!("{invite_id}.json"));
    let data = std::fs::read_to_string(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("pending invite: {e}"))))?;
    let pending: PendingInviteFile = serde_json::from_str(&data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("pending invite: {e}"))))?;
    if pending.secret_hash != sha256_hex(secret.as_bytes()) {
        return Err(BaluardError::from(VaultError::Metadata(format!(
            "introduction secret does not match the invite (stored {}, got {}) — file: {}",
            pending.secret_hash,
            sha256_hex(secret.as_bytes()),
            path.display()
        ))));
    }
    std::fs::remove_file(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("consume invite: {e}"))))?;
    Ok(pending)
}

// ── S1a-8: repo-backed join queue ──

/// Join requests live at `meta/requests/<req_id>.json` (git-tracked):
/// staged Introduction files awaiting an async admin decision. The admin
/// stages the intro they received out-of-band; the queue makes the
/// handoff listable, deniable, and auditable (the request rides history)
/// instead of living in a command's stdout.
pub const REQUESTS_DIR: &str = "meta/requests";

/// Hard cap on one staged request file. A real Introduction is a few KB
/// (keys + card + signature); anything larger is junk or abuse.
pub const REQUEST_MAX_BYTES: usize = 64 * 1024;

/// One queued introduction, as surfaced to the admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub req_id: Uuid,
    pub invite_id: Uuid,
    pub device_id: Uuid,
    pub display_name: String,
    /// Whether the request's secret matches a live pending invite's
    /// hash. Display-only: approval re-verifies through the standard
    /// path regardless.
    pub secret_ok: bool,
}

/// Stage a received introduction into the join queue. Admin-side: the
/// caller received the intro code out-of-band. Newline names are
/// rejected (payload discipline — the canonical payloads are
/// newline-delimited, S1a-3).
pub fn submit_request(vault_path: &Path, intro: &Introduction) -> Result<Uuid, BaluardError> {
    if intro.display_name.contains(['\n', '\r']) {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "introduction display name contains newlines".into(),
        )));
    }
    let bytes = serde_json::to_vec_pretty(intro)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("encode request: {e}"))))?;
    if bytes.len() > REQUEST_MAX_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "introduction too large".into(),
        )));
    }
    let req_id = Uuid::new_v4();
    let dir = vault_path.join(REQUESTS_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("requests dir: {e}"))))?;
    super::write_vault_file(&dir.join(format!("{req_id}.json")), &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write request: {e}"))))?;
    Ok(req_id)
}

/// List queued requests (sorted by req_id — deterministic for UIs).
/// Malformed files are skipped and COUNTED, never listed: junk in the
/// requests dir is inert until an admin denies it. `secret_ok` checks
/// the request's secret against the live pending invite's hash.
pub fn list_requests(vault_path: &Path) -> Result<(Vec<JoinRequest>, usize), BaluardError> {
    let dir = vault_path.join(REQUESTS_DIR);
    if !dir.exists() {
        return Ok((Vec::new(), 0));
    }
    let mut req_ids: Vec<String> = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json").map(|s| s.to_string())
        })
        .collect();
    req_ids.sort();
    let mut out = Vec::new();
    let mut malformed = 0usize;
    for stem in req_ids {
        // S1a-8 review: non-UUID stems are malformed — parsing them to
        // Uuid::nil() would list unmanageable entries (nil.json does not
        // exist, so they could never be approved or denied).
        let Ok(req_id) = Uuid::parse_str(&stem) else {
            malformed += 1;
            continue;
        };
        let path = dir.join(format!("{stem}.json"));
        // S1a-8 review: the size cap is enforced on READ too — the file
        // is git-tracked, so an oversized blob can arrive via pull.
        if std::fs::metadata(&path)
            .map(|m| m.len())
            .unwrap_or(u64::MAX)
            > REQUEST_MAX_BYTES as u64
        {
            malformed += 1;
            continue;
        }
        let Ok(json) = std::fs::read_to_string(&path) else {
            malformed += 1;
            continue;
        };
        let Ok(intro) = serde_json::from_str::<Introduction>(&json) else {
            malformed += 1;
            continue;
        };
        let secret_ok = read_pending_invite(vault_path, intro.invite_id)
            .map(|p| p.secret_hash == sha256_hex(intro.secret.as_bytes()))
            .unwrap_or(false);
        out.push(JoinRequest {
            req_id,
            invite_id: intro.invite_id,
            device_id: intro.device_id,
            display_name: intro.display_name.clone(),
            secret_ok,
        });
    }
    Ok((out, malformed))
}

/// Read one queued request back as an Introduction (approval input).
pub fn read_request(vault_path: &Path, req_id: Uuid) -> Result<Introduction, BaluardError> {
    let path = vault_path.join(REQUESTS_DIR).join(format!("{req_id}.json"));
    // S1a-8 review: same read-side cap as listing — the file is
    // git-tracked, so an oversized blob can arrive via pull.
    if std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX)
        > REQUEST_MAX_BYTES as u64
    {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "introduction too large".into(),
        )));
    }
    let data = std::fs::read_to_string(&path).map_err(|_| {
        BaluardError::from(VaultError::InvalidOperation("request not found".into()))
    })?;
    serde_json::from_str(&data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("parse request: {e}"))))
}

/// Remove a queued request (consumed on approval, dropped on denial).
pub fn consume_request(vault_path: &Path, req_id: Uuid) -> Result<(), BaluardError> {
    let path = vault_path.join(REQUESTS_DIR).join(format!("{req_id}.json"));
    std::fs::remove_file(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("consume request: {e}"))))
}

/// The member id `device_id` is bound to (scans device bindings).
/// `None` when unbound or legacy (no member directory).
pub fn member_id_for_device(vault_path: &Path, device_id: Uuid) -> Option<Uuid> {
    let dir = vault_path.join(MEMBERS_DIR);
    let entries = std::fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let binding = entry
            .path()
            .join("devices")
            .join(format!("{device_id}.json"));
        if !binding.exists() {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(binding) {
            if let Ok(b) = serde_json::from_str::<DeviceBinding>(&json) {
                return Some(b.member_id);
            }
        }
    }
    None
}

/// Update the device-local member unlock file's sealed identity seed
/// after an identity rotation. No-op when the file is absent.
pub fn update_member_unlock_identity_seed(
    vault_path: &Path,
    sealed_hex: &str,
) -> Result<(), BaluardError> {
    let path = vault_path.join("meta/member-unlock.json");
    if !path.exists() {
        return Ok(());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("read member unlock: {e}")))
    })?;
    let mut unlock: MemberUnlock = serde_json::from_str(&data).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("parse member unlock: {e}")))
    })?;
    unlock.identity_seed_sealed = Some(sealed_hex.to_string());
    super::write_vault_file(
        &path,
        serde_json::to_string_pretty(&unlock).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write member unlock: {e}"))))
}

/// Joiner: introduce yourself to a cloned vault. Verifies the invite
/// code against the repo-side pending record, then writes DEVICE-LOCAL
/// unlock material (own password, own device keys, own KDF salt). No
/// vault secrets exist on this device yet — the owner's approval ships
/// the keywrap via the normal sync cycle. Returns the introduction code
/// for the owner to approve.
pub fn create_introduction(
    vault_path: &Path,
    code: &str,
    password: &str,
    device_name: &str,
) -> Result<String, BaluardError> {
    let code_bytes = b64_decode(code)?;
    let invite_json = std::str::from_utf8(&code_bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("bad code: {e}"))))?;
    let invite: InviteCode = serde_json::from_str(invite_json)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("bad code: {e}"))))?;
    consume_pending_invite(vault_path, invite.invite_id, &invite.secret)?;

    let vault_id = crate::vault::handle::VaultHandle::vault_id_for_path(vault_path)?;
    if vault_id != invite.vault_id {
        return Err(BaluardError::from(VaultError::Metadata(
            "invite is for a different vault".into(),
        )));
    }

    // Fresh device keys + member-local KDF material (fresh salt): the
    // member's password is independent of the founding device's. The
    // joiner also generates their own identity (S1a-3) — the card signed
    // by it is the trust-dial credential.
    let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
    let (ed25519_signing, ed25519_verifying) = crate::crypto::signature::generate_ed25519_keypair();
    let identity = crate::vault::identity::IdentityKeys::generate()?;
    let identity_vk_hex = hex::encode(identity.signing_key().verifying_key().as_bytes());
    let device_id = Uuid::new_v4();

    let mut kdf_params: crate::types::KdfParams = {
        let raw = std::fs::read_to_string(vault_path.join("meta/kdf-params.json"))
            .map_err(|e| BaluardError::from(VaultError::Metadata(format!("kdf params: {e}"))))?;
        serde_json::from_str(&raw)
            .map_err(|e| BaluardError::from(VaultError::Metadata(format!("kdf params: {e}"))))?
    };
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    kdf_params.salt = salt.to_vec();

    let kek = Zeroizing::new(crate::crypto::kdf::derive_kek(password, &kdf_params)?);
    let session_key = Zeroizing::new(crate::crypto::hkdf_derive::derive_session_key(&kek)?);
    let kek_canary = super::canary::create_kek_canary(&session_key, vault_id)?;
    let devkey_seal = Zeroizing::new(crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek)?);

    // Seal the member's identity seed under the same devkey seal so the
    // identity survives lock/unlock on this device.
    let identity_seed_sealed = hex::encode(crate::vault::identity::seal_identity(
        &devkey_seal,
        &identity,
    )?);

    // Seal the member's device private keys under their OWN kek-derived
    // seal subkey: their password never touches the founding device's
    // vault-level material.
    let mut inner = serde_json::json!({
        "device_id": device_id.to_string(),
        "x25519_private": hex::encode(x25519_secret.to_bytes()),
        "ed25519_private": hex::encode(ed25519_signing.to_bytes()),
    })
    .to_string();
    crate::vault::device_privkey::seal_file(
        &vault_path.join("meta/device-privkey.json"),
        &inner,
        &devkey_seal,
        Some(device_id),
    )?;
    inner.zeroize();
    super::device_privkey::write_device_id(vault_path, device_id)?;

    let unlock = MemberUnlock {
        device_id,
        kdf_params,
        kek_canary: hex::encode(&kek_canary),
        identity_seed_sealed: Some(identity_seed_sealed),
    };
    super::write_vault_file(
        &vault_path.join("meta/member-unlock.json"),
        serde_json::to_string_pretty(&unlock).unwrap().as_bytes(),
    )
    .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write member unlock: {e}"))))?;

    let intro = Introduction {
        vault_id: invite.vault_id,
        invite_id: invite.invite_id,
        secret: invite.secret,
        device_id,
        encryption_public_key: hex::encode(x25519_public.as_bytes()),
        signing_public_key: hex::encode(ed25519_verifying.as_bytes()),
        display_name: device_name.to_string(),
        contact_card: Some(crate::vault::contacts::SignedContactCard::sign(
            device_name,
            &identity_vk_hex,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            identity.signing_key(),
        )?),
        // S1a-3: the identity key signs the device-key payload, binding
        // the introduced device to the verified identity (the gate for
        // elevated roles).
        identity_signature: {
            use ed25519_dalek::Signer;
            let payload = crate::vault::members::Introduction::identity_sign_payload(
                invite.invite_id,
                device_id,
                &hex::encode(x25519_public.as_bytes()),
                &hex::encode(ed25519_verifying.as_bytes()),
                &identity_vk_hex,
            );
            Some(hex::encode(
                identity.signing_key().sign(&payload).to_bytes(),
            ))
        },
    };
    Ok(b64_encode(
        serde_json::to_string(&intro).unwrap().as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §4.8-1: the People listing walks row files only — device binding
    /// subtrees and junk files are skipped, rows sort deterministically,
    /// and a missing directory (legacy vault) is an empty list.
    #[test]
    fn list_members_walks_rows_only() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path();
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        let row = |id: uuid::Uuid, name: &str| {
            serde_json::json!({
                "id": id.to_string(),
                "display_name": name,
                "role": "editor",
                "trust": "channel",
            })
        };
        std::fs::create_dir_all(
            vault.join("meta/members/00000000-0000-0000-0000-00000000000/devices"),
        )
        .unwrap();
        std::fs::write(
            vault.join(format!("meta/members/{id_a}.json")),
            row(id_a, "Alice").to_string(),
        )
        .unwrap();
        std::fs::write(
            vault.join(format!("meta/members/{id_b}.json")),
            row(id_b, "Bob").to_string(),
        )
        .unwrap();
        // Device binding subtree + junk must not appear as rows.
        std::fs::write(
            vault.join(
                "meta/members/00000000-0000-0000-0000-00000000000/devices/11111111-1111-1111-1111-111111111111.json",
            ),
            "{}",
        )
        .unwrap();
        std::fs::write(vault.join("meta/members/notes.txt"), "junk").unwrap();
        // Malformed ROW (valid .json name, garbage body): skipped inert.
        std::fs::write(vault.join("meta/members/broken.json"), "{not json").unwrap();

        let members = list_members(vault).unwrap();
        assert_eq!(members.len(), 2);
        // Deterministic order (id bytes descending).
        let ids: Vec<Uuid> = members.iter().map(|m| m.id).collect();
        assert_eq!(ids, {
            let mut sorted = ids.clone();
            sorted.sort_by(|a, b| b.as_bytes().cmp(a.as_bytes()));
            sorted
        });

        // Legacy vault: no directory at all.
        let empty = tempfile::tempdir().unwrap();
        assert!(list_members(empty.path()).unwrap().is_empty());
    }
}
