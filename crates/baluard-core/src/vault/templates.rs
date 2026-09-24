//! S3-4: role templates — named presets bundling a vault role plus
//! collection grants, applied at invite time so an admin does not
//! hand-pick per-collection access for every member.
//!
//! Storage is ONE sealed blob at `meta/templates.enc` under a
//! RootKey-derived HKDF key (the contacts/outbox registry pattern), so
//! template names and grant structure never sit on disk in the clear
//! and the file rides the Root Key rotation read-old-then-resave list.
//! The `meta/**` policy catch-all is Admin, so template writes are
//! admin-gated at the git layer without a dedicated row.
//!
//! The invite embeds a RESOLVED copy of the template (name + grants) at
//! mint time: the invite is the contract, so what the admin picked is
//! exactly what approval applies — a template deleted between invite
//! and approval changes nothing for pending invites.

use crate::error::{BaluardError, VaultError};
use crate::vault::collections::CollectionAccess;
use crate::vault::members::MemberRole;
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const TEMPLATES_FILE: &str = "meta/templates.enc";
pub const TEMPLATES_PURPOSE: &str = "role-templates-v1";
pub const TEMPLATES_FORMAT: u32 = 1;

pub const MAX_TEMPLATES: usize = 64;
pub const MAX_TEMPLATE_NAME_CHARS: usize = 100;
pub const MAX_GRANTS_PER_TEMPLATE: usize = 64;

/// One collection access entry inside a template. `expires_in_days` is
/// relative (converted to an absolute `expires_at` at approval time, so
/// a contractor invited from a 30-day template always gets 30 days from
/// THEIR approval, not from when the template was written).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateGrant {
    pub collection_id: Uuid,
    pub access: CollectionAccess,
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

/// The template slice embedded in a pending invite (resolved at mint
/// time). `MemberFile`-style serde defaults keep old invite files
/// loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedTemplate {
    pub name: String,
    pub grants: Vec<TemplateGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTemplate {
    pub id: Uuid,
    pub name: String,
    pub role: MemberRole,
    pub grants: Vec<TemplateGrant>,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct TemplatesFile {
    format: u32,
    templates: Vec<RoleTemplate>,
}

/// Validate a template before it is stored or embedded: names are
/// non-empty and bounded, grant counts bounded, collection ids are
/// typed, expiry days are >= 1 (0 would mint an already-expired grant,
/// and the grant mint refuses past dates), and Owner is unmintable —
/// ownership changes go through transfer_ownership only (S1a-7).
pub fn validate_template(
    name: &str,
    role: MemberRole,
    grants: &[TemplateGrant],
) -> Result<(), BaluardError> {
    if name.trim().is_empty() {
        return Err(VaultError::InvalidOperation("Give the template a name.".into()).into());
    }
    if name.chars().count() > MAX_TEMPLATE_NAME_CHARS {
        return Err(VaultError::InvalidOperation("That template name is too long.".into()).into());
    }
    if role == MemberRole::Owner {
        return Err(VaultError::InvalidOperation(
            "ownership cannot be invited; use transfer_ownership".into(),
        )
        .into());
    }
    if name.contains('\n') || name.contains('\r') {
        return Err(VaultError::InvalidOperation(
            "A template name cannot contain line breaks.".into(),
        )
        .into());
    }
    // A Viewer can never author a cipher commit (the git policy floor
    // is Editor), so a template pairing Viewer with a write grant would
    // wedge that member's sync on their first commit.
    if role == MemberRole::Viewer
        && grants
            .iter()
            .any(|g| matches!(g.access, crate::vault::collections::CollectionAccess::Write))
    {
        return Err(VaultError::InvalidOperation(
            "A viewer template cannot include write access.".into(),
        )
        .into());
    }
    if grants.len() > MAX_GRANTS_PER_TEMPLATE {
        return Err(VaultError::InvalidOperation(
            "That template has too many collection entries.".into(),
        )
        .into());
    }
    if grants
        .iter()
        .any(|g| g.expires_in_days.is_some_and(|d| d == 0))
    {
        return Err(
            VaultError::InvalidOperation("An expiry must be at least one day.".into()).into(),
        );
    }
    Ok(())
}

pub fn load_templates(root: &Path, root_key: &[u8; 64]) -> Result<Vec<RoleTemplate>, BaluardError> {
    let path = root.join(TEMPLATES_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("read templates: {e}"))))?;
    if data.len() > crate::vault::collections::MAX_COLLECTION_FILE_BYTES {
        return Err(VaultError::Corrupt("template store file is too large".into()).into());
    }
    let key = Zeroizing::new(crate::crypto::hkdf_derive::derive_templates_key(root_key)?);
    let bytes = crate::secret_file::open_secret_blob(&key, &data, TEMPLATES_PURPOSE)
        .map_err(|_| VaultError::Corrupt("template store cannot be read".into()))?;
    let file: TemplatesFile = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::Corrupt("template store is malformed".into()))?;
    if file.format != TEMPLATES_FORMAT {
        return Err(VaultError::Corrupt("template store format".into()).into());
    }
    Ok(file.templates)
}

pub fn save_templates(
    root: &Path,
    root_key: &[u8; 64],
    templates: &[RoleTemplate],
) -> Result<(), BaluardError> {
    if templates.len() > MAX_TEMPLATES {
        return Err(
            VaultError::InvalidOperation("That vault has too many templates.".into()).into(),
        );
    }
    let file = TemplatesFile {
        format: TEMPLATES_FORMAT,
        templates: templates.to_vec(),
    };
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("templates: {e}"))))?;
    let key = Zeroizing::new(crate::crypto::hkdf_derive::derive_templates_key(root_key)?);
    let sealed = crate::secret_file::seal_secret_blob(&key, &bytes, TEMPLATES_PURPOSE)?;
    crate::vault::write_vault_file(&root.join(TEMPLATES_FILE), &sealed)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write templates: {e}"))))
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::collections::CollectionAccess;

    fn root_bytes() -> [u8; 64] {
        let mut b = [0u8; 64];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut b);
        b
    }

    fn grant(collection_id: Uuid) -> TemplateGrant {
        TemplateGrant {
            collection_id,
            access: CollectionAccess::Read,
            expires_in_days: Some(30),
        }
    }

    #[test]
    fn create_list_delete_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path();
        let root = root_bytes();
        let g = grant(Uuid::new_v4());
        validate_template("Contractor", MemberRole::Viewer, std::slice::from_ref(&g)).unwrap();
        let t = RoleTemplate {
            id: Uuid::new_v4(),
            name: "Contractor".into(),
            role: MemberRole::Viewer,
            grants: vec![g],
            created_at: now_secs(),
        };
        save_templates(path, &root, std::slice::from_ref(&t)).unwrap();
        let listed = load_templates(path, &root).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], t);
        save_templates(path, &root, &[]).unwrap();
        assert!(load_templates(path, &root).unwrap().is_empty());
    }

    #[test]
    fn wrong_key_or_tamper_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path();
        let root = root_bytes();
        save_templates(path, &root, &[]).unwrap();
        assert!(load_templates(path, &root_bytes()).is_err());
        // Flip a byte in the tail (tag region) of the sealed envelope.
        let file = path.join(TEMPLATES_FILE);
        let mut data = std::fs::read(&file).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x40;
        std::fs::write(&file, &data).unwrap();
        assert!(load_templates(path, &root).is_err());
    }

    #[test]
    fn validation_rules() {
        let g = grant(Uuid::new_v4());
        assert!(validate_template("", MemberRole::Editor, std::slice::from_ref(&g)).is_err());
        assert!(validate_template("x", MemberRole::Owner, std::slice::from_ref(&g)).is_err());
        assert!(
            validate_template(
                "x",
                MemberRole::Editor,
                &[TemplateGrant {
                    expires_in_days: Some(0),
                    ..g.clone()
                }]
            )
            .is_err()
        );
        let many = vec![g; MAX_GRANTS_PER_TEMPLATE + 1];
        assert!(validate_template("x", MemberRole::Editor, &many).is_err());
    }

    #[test]
    fn viewer_template_refuses_write_grant_and_newline_name() {
        let g = TemplateGrant {
            collection_id: Uuid::new_v4(),
            access: crate::vault::collections::CollectionAccess::Write,
            expires_in_days: Some(30),
        };
        // A Viewer can never author a cipher commit, so a viewer
        // template carrying write access would wedge that member's
        // sync at first verification.
        assert!(validate_template("x", MemberRole::Viewer, std::slice::from_ref(&g)).is_err());
        assert!(validate_template("x", MemberRole::Viewer, &[]).is_ok());
        assert!(validate_template("bad\nname", MemberRole::Editor, &[]).is_err());
        assert!(validate_template("bad\rname", MemberRole::Editor, &[]).is_err());
    }

    #[test]
    fn legacy_file_absent_is_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = root_bytes();
        assert!(load_templates(dir.path(), &root).unwrap().is_empty());
    }
}
