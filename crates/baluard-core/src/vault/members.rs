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
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(entry.path()) {
            if let Ok(member) = serde_json::from_str::<MemberFile>(&json) {
                if member.role == MemberRole::Owner {
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
