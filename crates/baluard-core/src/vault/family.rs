//! Family vaults (plan-family-spaces): the guardian-controlled minor
//! flag and the family creation transaction.
//!
//! The minor flag lives in an admin-written sealed record under the
//! member's own subtree (`meta/members/<id>/minor.enc`), never in the
//! member row: member rows are plaintext on the forge and the child's
//! status must not leak to the remote, the sync delta validator needs
//! no new pinned field, and no `MemberFile` construction site changes.
//! The sync policy table carries an Admin-only row for this exact path
//! (ordered ahead of the any-role members subtree row) so a minor can
//! never overwrite or delete the sealed flag from a validly signed
//! commit.
//!
//! Key material: the record seals under a Root-Key-derived key, so on
//! a flipped family vault only admin devices (the ones still holding
//! the Root Key) can read or write it; members see ciphertext only.
//! Existence checks are path-only and safe for guards: only an admin
//! handle can create the file locally, and only an Admin-rank commit
//! can ship it.

use std::path::Path;

use uuid::Uuid;

use crate::error::{BaluardError, VaultError};

const MINOR_RECORD_PURPOSE: &str = "baluard-minor-record-v1";

fn minor_record_path(vault_path: &Path, member_id: &Uuid) -> std::path::PathBuf {
    vault_path
        .join(crate::vault::members::MEMBERS_DIR)
        .join(member_id.to_string())
        .join("minor.enc")
}

/// Whether the sealed minor record exists for this member. Path-only:
/// the guards (swap/claim targets, invites) call this without key
/// material; a present file was written by an admin handle and can
/// only travel through an Admin-rank commit, so existence is proof.
pub(crate) fn minor_record_exists(vault_path: &Path, member_id: &Uuid) -> bool {
    minor_record_path(vault_path, member_id).exists()
}

/// Write or remove the sealed minor record. The caller gates on
/// unlocked + manage (admin) + a live member row; the record content
/// is trivial because existence IS the flag.
pub(crate) fn write_minor_record(
    vault_path: &Path,
    root_key: &RootKeyRef,
    member_id: &Uuid,
    minor: bool,
) -> Result<(), BaluardError> {
    let path = minor_record_path(vault_path, member_id);
    if !minor {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!("remove minor record: {e}")))
            })?;
        }
        return Ok(());
    }
    let key = crate::crypto::hkdf_derive::derive_minor_record_key(root_key.as_bytes())?;
    let doc =
        serde_json::json!({ "minor": true, "set_at": crate::vault::collections::now_secs_pub() });
    let blob = crate::secret_file::seal_secret_blob(
        &key,
        doc.to_string().as_bytes(),
        MINOR_RECORD_PURPOSE,
    )?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            BaluardError::from(VaultError::Metadata(format!("create member dir: {e}")))
        })?;
    }
    super::write_vault_file(&path, &blob).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("write minor record: {e}")))
    })?;
    Ok(())
}

/// Read the record back (admin surfaces). Absent = false; a
/// present-but-damaged record is an error so tampering surfaces
/// instead of silently clearing the flag.
pub(crate) fn read_minor_record(
    vault_path: &Path,
    root_key: &RootKeyRef,
    member_id: &Uuid,
) -> Result<bool, BaluardError> {
    let path = minor_record_path(vault_path, member_id);
    if !path.exists() {
        return Ok(false);
    }
    let key = crate::crypto::hkdf_derive::derive_minor_record_key(root_key.as_bytes())?;
    let blob = std::fs::read(&path)
        .map_err(|e| VaultError::Metadata(format!("read minor record: {e}")))?;
    let plain = crate::secret_file::open_secret_blob(&key, &blob, MINOR_RECORD_PURPOSE)?;
    let doc: serde_json::Value = serde_json::from_slice(&plain)
        .map_err(|_| VaultError::Corrupt("minor record payload damaged".into()))?;
    Ok(doc["minor"].as_bool().unwrap_or(false))
}

use crate::keys::hierarchy::RootKey as RootKeyRef;

/// The family creation transaction (plan-family-spaces §13 step 1/3):
/// on a freshly created vault, stamp the family purpose, create the
/// `Shared` collection plus the `Guardians` group, flip to team shape,
/// and record the Shared id as a system collection in encrypted
/// settings. Idempotent per step so a resumed wizard converges; the
/// purpose write hard-fails (a half-created family vault without its
/// purpose must never flip).
///
/// Returns the Shared collection id.
pub(crate) fn setup_family_vault(
    handle: &mut super::handle::VaultHandle,
) -> Result<Uuid, BaluardError> {
    let path = handle.path.clone();
    if crate::vault::space::read_purpose(&path) == crate::vault::space::SpacePurpose::Absent {
        crate::vault::space::set_purpose(&path, crate::vault::space::SpacePurpose::Family)
            .map_err(|e| {
                BaluardError::from(VaultError::InvalidOperation(format!(
                    "family creation failed at the purpose write: {e}"
                )))
            })?;
    }

    // Shared collection: reuse the existing one on a resumed run.
    let settings = handle.get_settings().unwrap_or_default();
    let shared_id = match settings.family_shared_collection {
        Some(id) => id,
        None => {
            let existing = handle
                .collections_list()?
                .into_iter()
                .find(|(_, name, _)| name == "Shared")
                .map(|(id, _, _)| id);
            match existing {
                Some(id) => id,
                None => handle.collection_create("Shared")?,
            }
        }
    };

    // Guardians group: the member boundary for restricted collections.
    let guardians = match handle
        .groups_list()?
        .iter()
        .find(|(_, name, _)| name == "Guardians")
    {
        Some((id, _, _)) => *id,
        None => handle.group_create("Guardians")?,
    };
    let _ = guardians;

    handle.space_flip()?;

    // Record the Shared id post-flip (settings.enc re-seals under the
    // team-shape derivation; the flip already converged tracked files).
    let mut settings = handle.get_settings().unwrap_or_default();
    if settings.family_shared_collection != Some(shared_id) {
        settings.family_shared_collection = Some(shared_id);
        handle.save_settings(&settings)?;
    }
    Ok(shared_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family_vault() -> (tempfile::TempDir, super::super::handle::VaultHandle, String) {
        let temp = tempfile::tempdir().unwrap();
        let (mut handle, _secrets) = super::super::creation::VaultCreator::new(
            temp.path().join("fam"),
            "family-pass",
            "FounderDevice",
        )
        .kdf_profile(crate::types::KdfProfile::MobileLow)
        .initialize_git(true)
        .execute()
        .unwrap();
        handle.unlock("family-pass").unwrap();
        let password = "family-pass".to_string();
        (temp, handle, password)
    }

    #[test]
    fn family_transaction_creates_shared_guardians_and_flips() {
        let (_temp, mut handle, password) = family_vault();
        let shared = setup_family_vault(&mut handle).unwrap();
        assert!(
            crate::vault::space::read_purpose(&handle.path)
                == crate::vault::space::SpacePurpose::Family
        );
        assert!(crate::vault::space_meta::shape_flipped(&handle.path));
        let names: Vec<String> = handle
            .collections_list()
            .unwrap()
            .into_iter()
            .map(|(_, n, _)| n)
            .collect();
        assert!(names.contains(&"Shared".to_string()));
        assert!(
            handle
                .groups_list()
                .unwrap()
                .iter()
                .any(|(_, n, _)| n == "Guardians")
        );
        // System id recorded.
        assert_eq!(
            handle.get_settings().unwrap().family_shared_collection,
            Some(shared)
        );
        // Resumed run converges: same Shared id, idempotent flip.
        let again = setup_family_vault(&mut handle).unwrap();
        assert_eq!(again, shared);
        drop(handle);
        let mut h2 = super::super::handle::VaultHandle::open(&_temp.path().join("fam")).unwrap();
        h2.unlock(&password).unwrap();
        assert_eq!(
            h2.get_settings().unwrap().family_shared_collection,
            Some(shared)
        );
    }

    #[test]
    fn swap_refuses_minors_and_non_admin_targets_on_family() {
        let (_temp, mut handle, _pw) = family_vault();
        setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        // A second member row (Admin, live) and a minor-flagged Admin.
        let admin = crate::vault::members::MemberFile {
            id: uuid::Uuid::new_v4(),
            display_name: "Dad".into(),
            email: None,
            role: crate::vault::members::MemberRole::Admin,
            trust: crate::vault::members::TrustLevel::Verified,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        let minor_id = uuid::Uuid::new_v4();
        let mut minor = admin.clone();
        minor.id = minor_id;
        minor.display_name = "Kid".into();
        crate::vault::members::write_member(&path, &admin).unwrap();
        crate::vault::members::write_member(&path, &minor).unwrap();
        let root = handle.unlocked().root().unwrap().clone();
        write_minor_record(&path, &root, &minor_id, true).unwrap();
        let owner = crate::vault::members::owner_member_id(&path).unwrap();

        // Minor target: refused (existence check).
        let err = crate::vault::members::commit_ownership_swap(&path, owner, minor_id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("a minor cannot receive ownership"), "{err}");

        // Non-Admin target on family: refused.
        let editor = uuid::Uuid::new_v4();
        let mut editor_row = admin.clone();
        editor_row.id = editor;
        editor_row.role = crate::vault::members::MemberRole::Editor;
        crate::vault::members::write_member(&path, &editor_row).unwrap();
        let err = crate::vault::members::commit_ownership_swap(&path, owner, editor)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ownership passes only to an admin"), "{err}");

        // Live Admin target: admitted (promote-first semantics).
        crate::vault::members::commit_ownership_swap(&path, owner, admin.id).unwrap();
    }

    #[test]
    fn shared_system_collection_deletion_refused_and_empty_rule() {
        let (_temp, mut handle, _pw) = family_vault();
        let shared = setup_family_vault(&mut handle).unwrap();
        // Shared is a system collection: deletion refused.
        let err = handle.collection_delete(shared).unwrap_err().to_string();
        assert!(err.contains("system collection"), "{err}");
        // A fresh second collection deletes fine while empty.
        let scratch = handle.collection_create("Scratch").unwrap();
        handle.collection_delete(scratch).unwrap();
        // Non-empty refusal: an entry inside blocks deletion.
        let other = handle.collection_create("Other").unwrap();
        let input = crate::types::CipherInput {
            name: "In Other".into(),
            folder_id: None,
            collection_id: Some(other),
            kind: crate::types::CipherKind::SecureNote,
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        // add_cipher files flat (collection_id ignored there); the
        // collection-scoped creation path is what marks occupancy.
        handle
            .add_cipher_in_collection(&input, Some(other))
            .unwrap();
        let err = handle.collection_delete(other).unwrap_err().to_string();
        assert!(err.contains("still has entries"), "{err}");
    }

    #[test]
    fn leave_record_files_lists_and_execution_leaves_traces() {
        let (_temp, mut handle, _pw) = family_vault();
        let shared = setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        // A live Editor member with a device binding, granted Write on
        // their own collection plus Read on Shared.
        let leaver_id = uuid::Uuid::new_v4();
        let mut leaver = crate::vault::members::MemberFile {
            id: leaver_id,
            display_name: "Uncle Rob".into(),
            email: None,
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Channel,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        crate::vault::members::write_member(&path, &leaver).unwrap();
        let device_id = uuid::Uuid::new_v4();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: leaver_id,
            },
        )
        .unwrap();
        let sgk = handle.unlocked().sgk().unwrap().clone();
        let kids_file = crate::vault::collections::create_collection(&path, &sgk, "Kids").unwrap();
        let kids = kids_file.id;
        let now = crate::vault::templates::now_secs();
        for (cid, access) in [
            (shared, crate::vault::collections::CollectionAccess::Read),
            (kids, crate::vault::collections::CollectionAccess::Write),
        ] {
            crate::vault::collections::upsert_grant(
                &path,
                &sgk,
                &cid,
                crate::vault::collections::CollectionGrant {
                    target: crate::vault::collections::GrantTarget::Member { id: leaver_id },
                    access,
                    expires_at: None,
                },
            )
            .unwrap();
        }
        let _ = now;

        // Owner file attempt: refused (transfer first).
        let owner_device = handle.device_id;
        let err = crate::vault::members::file_leave_record(&path, owner_device)
            .unwrap_err()
            .to_string();
        assert!(err.contains("transfer ownership"), "{err}");

        // The leaver files; the record surfaces once; re-file is idempotent.
        crate::vault::members::file_leave_record(&path, device_id).unwrap();
        crate::vault::members::file_leave_record(&path, device_id).unwrap();
        let pending = crate::vault::members::list_leave_records(&path).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].member_id, leaver_id);
        assert_eq!(pending[0].display_name, "Uncle Rob");

        // Execution: tombstone "left", grants rotated out, record consumed.
        crate::vault::members::remove_member(&path, leaver_id, "left").unwrap();
        let row = crate::vault::members::member_file_by_id(&path, leaver_id).unwrap();
        assert_eq!(row.removed_reason.as_deref(), Some("left"));
        assert!(row.removed.is_some());
        for cid in [shared, kids] {
            handle.collection_rotate_key(cid, Some(leaver_id)).unwrap();
            let (_, _, grants) = handle
                .collections_list()
                .unwrap()
                .into_iter()
                .find(|(id, _, _)| *id == cid)
                .unwrap();
            assert!(
                !grants.iter().any(
                    |g| matches!(g.target, crate::vault::collections::GrantTarget::Member { id } if id == leaver_id)
                ),
                "leaver grant survived rotation"
            );
        }
        crate::vault::members::consume_leave_record(&path, leaver_id);
        assert!(
            crate::vault::members::list_leave_records(&path)
                .unwrap()
                .is_empty()
        );
        assert!(!crate::vault::members::leave_record_exists(
            &path, leaver_id
        ));
    }

    #[test]
    fn minor_record_write_read_and_guard_visibility() {
        let (_temp, mut handle, password) = family_vault();
        setup_family_vault(&mut handle).unwrap();
        let member = crate::vault::members::list_members(&handle.path).unwrap()[0].id;
        assert!(!minor_record_exists(&handle.path, &member));
        let root = handle.unlocked().root().unwrap().clone();
        write_minor_record(&handle.path, &root, &member, true).unwrap();
        assert!(minor_record_exists(&handle.path, &member));
        assert!(read_minor_record(&handle.path, &root, &member).unwrap());
        // Removing the record clears the flag.
        write_minor_record(&handle.path, &root, &member, false).unwrap();
        assert!(!minor_record_exists(&handle.path, &member));
        assert!(!read_minor_record(&handle.path, &root, &member).unwrap());
        drop(handle);
        let _ = password;
    }
}
