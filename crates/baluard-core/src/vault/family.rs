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
/// Keyless filesystem check (path-only by design: only an admin
/// handle can CREATE the sealed record, so existence leaks nothing
/// that matters and guards can call it without key material).
pub fn minor_record_exists(vault_path: &Path, member_id: &Uuid) -> bool {
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
) -> Result<(Uuid, Option<String>), BaluardError> {
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

    // Kit mandatory at birth (section 7): a family vault without a kit
    // has no phrase-only escape when guardians are gone. Idempotent —
    // a resumed run keeps the existing kit and returns no phrase (the
    // founders saw it at first creation).
    let kit_phrase = if super::recovery_kit::kit_exists(&path)? {
        None
    } else {
        Some(handle.space_recovery_kit_enable()?)
    };
    Ok((shared_id, kit_phrase))
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
        let (shared, _kit) = setup_family_vault(&mut handle).unwrap();
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
        let (again, kit_again) = setup_family_vault(&mut handle).unwrap();
        assert_eq!(again, shared);
        // A resumed run keeps the existing kit (no second phrase).
        assert!(kit_again.is_none());
        drop(handle);
        let mut h2 = super::super::handle::VaultHandle::open(&_temp.path().join("fam")).unwrap();
        h2.unlock(&password).unwrap();
        assert_eq!(
            h2.get_settings().unwrap().family_shared_collection,
            Some(shared)
        );
    }

    #[test]
    fn kit_threshold_bounded_by_live_admins() {
        use crate::vault::approvals::{self, ApprovalEntry, EntryVerifier, PendingOp};
        use crate::vault::members::{MemberFile, MemberRole, TrustLevel};

        // Sole guardian: the bounded threshold is 1, so replacing and
        // disabling the kit run immediately (no ask, no deadlock).
        let (_temp, mut handle, _pw) = family_vault();
        let (_shared, first_phrase) = setup_family_vault(&mut handle).unwrap();
        assert!(first_phrase.is_some(), "creation enables the kit");
        let second = handle.space_recovery_kit_enable().unwrap();
        assert_ne!(second, first_phrase.unwrap());
        assert!(handle.space_recovery_kit_disable().unwrap());
        assert!(!handle.space_recovery_kit_disable().unwrap());
        drop(handle);

        // Two live admins: the threshold is 2. The first presentation
        // pends, a valid second-admin approval completes and consumes
        // the ask, and a re-raise starts a fresh one.
        let temp = tempfile::tempdir().unwrap();
        let (mut handle, _secrets) = crate::vault::creation::VaultCreator::new(
            temp.path().join("fam2"),
            "family-pass",
            "FounderDevice",
        )
        .kdf_profile(crate::types::KdfProfile::MobileLow)
        .initialize_git(true)
        .execute()
        .unwrap();
        let (_shared, _kit) = setup_family_vault(&mut handle).unwrap();
        // A live co-guardian with a real identity key.
        let (sk, vk) = crate::crypto::signature::generate_ed25519_keypair();
        let guard = MemberFile {
            id: uuid::Uuid::new_v4(),
            display_name: "Co-guardian".into(),
            email: None,
            role: MemberRole::Admin,
            trust: TrustLevel::Verified,
            identity_signing_pubkey: Some(hex::encode(vk.as_bytes())),
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        crate::vault::members::write_member(&handle.path, &guard).unwrap();

        let kit_created_at = crate::vault::recovery_kit::load_kit(&handle.path)
            .unwrap()
            .unwrap()
            .created_at;
        let params = serde_json::json!({ "created_at": kit_created_at });
        let err = handle.space_recovery_kit_enable().unwrap_err().to_string();
        assert!(err.contains("2 admin approvals"), "{err}");

        // The co-guardian confirms: sign the ask's own timestamp and
        // nonce exactly as the gate would, then present. Founder's
        // entry first, then the co-guardian's completes and consumes.
        let path = handle.path.clone();
        let path_for_present = path.clone();
        let vault_id = handle.vault_id;
        let pending: PendingOp = approvals::list_pending(&path)
            .into_iter()
            .find(|p| p.kind == "kit.replace")
            .expect("pending ask");
        let digest = approvals::op_digest("kit.replace", &params);
        let msg = approvals::approval_message(
            "kit.replace",
            &digest,
            vault_id,
            pending.initiated_at,
            &pending.nonce.as_deref().unwrap_or_default(),
        );
        let sig = hex::encode(
            crate::crypto::signature::sign(&sk, &msg)
                .unwrap()
                .to_bytes(),
        );
        let entry = ApprovalEntry {
            member: guard.id,
            sig,
        };
        let nonce = pending.nonce.clone().unwrap_or_default();
        // The verifier mirrors the gate: every recorded entry must
        // carry a valid signature over the ask message under its own
        // member row's key (the founder's entry included, or the
        // retain pass drops it and the count never reaches 2).
        let msg_for_verify = msg.clone();
        let verifier = EntryVerifier {
            nonce: nonce.clone(),
            verify: Box::new(move |candidate: &ApprovalEntry| {
                let Some(row) = crate::vault::members::member_file_by_id(&path, candidate.member)
                else {
                    return false;
                };
                let (Ok(pk), Ok(sig)) = (
                    hex::decode(row.identity_signing_pubkey.unwrap_or_default()),
                    hex::decode(&candidate.sig),
                ) else {
                    return false;
                };
                let (Ok(pk_arr), Ok(sig_arr)) = (
                    <[u8; 32]>::try_from(pk.as_slice()),
                    <[u8; 64]>::try_from(sig.as_slice()),
                ) else {
                    return false;
                };
                let Ok(pk) = crate::crypto::signature::verifying_key_from_bytes(&pk_arr) else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                crate::crypto::signature::verify(&pk, &msg_for_verify, &sig).is_ok()
            }),
        };
        assert_eq!(
            approvals::present(
                &path_for_present,
                "kit.replace",
                &params,
                entry,
                2,
                approvals::list_pending(&path_for_present)[0].initiated_at,
                &verifier,
            ),
            approvals::ApprovalOutcome::Approved
        );
        assert!(approvals::list_pending(&path_for_present).is_empty());

        // A consumed ask never approves twice: the founder's re-raise
        // pends again under a fresh nonce (old signatures never carry).
        let err = handle.space_recovery_kit_enable().unwrap_err().to_string();
        assert!(err.contains("2 admin approvals"), "{err}");

        // Disable runs the same fixed threshold at two admins.
        let err = handle.space_recovery_kit_disable().unwrap_err().to_string();
        assert!(err.contains("2 admin approvals"), "{err}");
    }

    #[test]
    fn minor_invites_and_flags_stay_non_admin() {
        let (_temp, mut handle, _pw) = family_vault();
        let (_shared, _kit) = setup_family_vault(&mut handle).unwrap();
        // Mint gate: a minor invite can never carry admin rank.
        let err = handle
            .invite_create_with_embedded_grants(
                crate::vault::members::MemberRole::Admin,
                None,
                crate::vault::templates::EmbeddedTemplate {
                    name: "x".into(),
                    grants: Vec::new(),
                },
                true,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("editors or viewers"), "{err}");
        // Editor rank is the wizard's child shape and works.
        handle
            .invite_create_with_embedded_grants(
                crate::vault::members::MemberRole::Editor,
                None,
                crate::vault::templates::EmbeddedTemplate {
                    name: "kid".into(),
                    grants: Vec::new(),
                },
                true,
            )
            .unwrap();
        // Flag gate: admins and owners cannot be flagged as minors.
        let owner_id =
            crate::vault::members::member_id_for_device(&handle.path, handle.device_id).unwrap();
        let err = handle
            .member_set_minor(owner_id, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be flagged as minors"), "{err}");
        // ...and a flagged editor can be unflagged (clearing stays open).
        let editor = pending_editor_row(&handle.path);
        handle.member_set_minor(editor, true).unwrap();
        handle.member_set_minor(editor, false).unwrap();
        assert!(!handle.member_minor_status(editor).unwrap());
    }

    /// A hand-written live Editor row for flag tests (no invite
    /// ceremony needed; the row is local-only until committed).
    fn pending_editor_row(path: &std::path::Path) -> uuid::Uuid {
        use crate::vault::members::{MemberFile, MemberRole, TrustLevel};
        let id = uuid::Uuid::new_v4();
        crate::vault::members::write_member(
            path,
            &MemberFile {
                id,
                display_name: "Flag Editor".into(),
                email: None,
                role: MemberRole::Editor,
                trust: TrustLevel::Channel,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                removed_reason: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        id
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
    fn ownership_claim_on_family_enters_the_contest_window() {
        let (_temp, mut handle, _pw) = family_vault();
        setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        // The acting device must be a live Admin claimant: hand-write
        // the row and bind the handle's device to it.
        let claimant = crate::vault::members::MemberFile {
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
        crate::vault::members::write_member(&path, &claimant).unwrap();
        // The founder device is already bound to the founder Owner row;
        // a device counted in two subtrees resolves to NOTHING (the
        // forgery rule), so free it before binding it to the claimant.
        let founder_id = crate::vault::members::owner_member_id(&path).unwrap();
        std::fs::remove_file(
            path.join("meta/members")
                .join(founder_id.to_string())
                .join("devices")
                .join(format!("{}.json", handle.device_id)),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id: handle.device_id,
                member_id: claimant.id,
            },
        )
        .unwrap();
        let owner = founder_id;

        // First claim: confirmed, window armed, NOT executed.
        let err = handle.ownership_claim(claimant.id).unwrap_err().to_string();
        assert!(err.contains("contest window"), "{err}");
        let pending = crate::vault::members::load_ownership_contest(&path).unwrap();
        assert_eq!(pending.new_owner_id, claimant.id);
        assert_eq!(pending.old_owner_id, owner);
        assert!(pending.window_until > crate::vault::members::unix_now_pub());
        assert_ne!(
            crate::vault::members::owner_member_id(&path),
            Some(claimant.id)
        );

        // Immediate re-touch: still inside the window.
        let err = handle.ownership_claim(claimant.id).unwrap_err().to_string();
        assert!(err.contains("more days"), "{err}");

        // The acting device is the ADMIN claimant, so its cancel is
        // refused: only the current owner may cancel.
        let err = handle.ownership_contest_cancel().unwrap_err().to_string();
        assert!(err.contains("only the current owner"), "{err}");

        // Rebind the device to the founder Owner row and cancel: the
        // record dies.
        std::fs::remove_file(
            path.join("meta/members")
                .join(claimant.id.to_string())
                .join("devices")
                .join(format!("{}.json", handle.device_id)),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id: handle.device_id,
                member_id: owner,
            },
        )
        .unwrap();
        handle.ownership_contest_cancel().unwrap();
        assert!(crate::vault::members::load_ownership_contest(&path).is_none());
        // With nothing pending, a second cancel is refused.
        let err = handle.ownership_contest_cancel().unwrap_err().to_string();
        assert!(err.contains("no ownership claim is pending"), "{err}");

        // Back to the claimant: a fresh claim re-arms a new window
        // (supersession).
        std::fs::remove_file(
            path.join("meta/members")
                .join(owner.to_string())
                .join("devices")
                .join(format!("{}.json", handle.device_id)),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id: handle.device_id,
                member_id: claimant.id,
            },
        )
        .unwrap();
        let _ = handle.ownership_claim(claimant.id).unwrap_err();
        assert!(crate::vault::members::load_ownership_contest(&path).is_some());

        // Expiry executes through the re-touch: rewind the record and
        // claim again. The elapsed record is the gate proof, so no
        // second approval is demanded.
        let mut expired = crate::vault::members::load_ownership_contest(&path).unwrap();
        expired.window_until = crate::vault::members::unix_now_pub().saturating_sub(1);
        let contest_file = path.join("meta/contests/ownership-claim.json");
        std::fs::write(&contest_file, serde_json::to_vec(&expired).unwrap()).unwrap();
        handle.ownership_claim(claimant.id).unwrap();
        assert_eq!(
            crate::vault::members::owner_member_id(&path),
            Some(claimant.id)
        );
        assert!(!contest_file.exists());
    }

    #[test]
    fn deceased_owner_claim_skips_the_window() {
        let (_temp, mut handle, _pw) = family_vault();
        setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        let claimant = crate::vault::members::MemberFile {
            id: uuid::Uuid::new_v4(),
            display_name: "Survivor".into(),
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
        crate::vault::members::write_member(&path, &claimant).unwrap();
        let founder_id = crate::vault::members::owner_member_id(&path).unwrap();
        std::fs::remove_file(
            path.join("meta/members")
                .join(founder_id.to_string())
                .join("devices")
                .join(format!("{}.json", handle.device_id)),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id: handle.device_id,
                member_id: claimant.id,
            },
        )
        .unwrap();
        // Death is not tracked: a deceased owner's row stays live on
        // disk, so the window applies and succession waits it out
        // (the honest cost the plan records). A TOMBSTONED owner row
        // is the post-succession state: ownership_claim refuses
        // outright because no owner row resolves at all.
        let owner = crate::vault::members::owner_member_id(&path).unwrap();
        let mut row = crate::vault::members::member_file_by_id(&path, owner).unwrap();
        row.removed = Some(0);
        row.removed_reason = None;
        crate::vault::members::write_member(&path, &row).unwrap();
        let err = handle.ownership_claim(claimant.id).unwrap_err().to_string();
        assert!(err.contains("no owner member row"), "{err}");
        assert!(crate::vault::members::load_ownership_contest(&path).is_none());
    }

    #[test]
    fn shared_system_collection_deletion_refused_and_empty_rule() {
        let (_temp, mut handle, _pw) = family_vault();
        let (shared, _kit) = setup_family_vault(&mut handle).unwrap();
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
    fn member_set_role_cycles_demotes_and_guards() {
        use crate::vault::members::{MemberFile, MemberRole, TrustLevel};
        let (_temp, mut handle, _pw) = family_vault();
        let (_shared, _kit) = setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        let member_id = uuid::Uuid::new_v4();
        let mk_row = |role: MemberRole| MemberFile {
            id: member_id,
            display_name: "Role Cycle".into(),
            email: None,
            role,
            trust: TrustLevel::Channel,
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
        crate::vault::members::write_member(&path, &mk_row(MemberRole::Editor)).unwrap();

        // Demote, promote, and a no-op no-change answer.
        let out = handle
            .member_set_role(member_id, MemberRole::Viewer)
            .unwrap();
        assert_eq!(out["changed"], serde_json::json!(true));
        let row = crate::vault::members::list_members(&path)
            .unwrap()
            .into_iter()
            .find(|m| m.id == member_id)
            .unwrap();
        assert_eq!(row.role, MemberRole::Viewer);
        let out = handle
            .member_set_role(member_id, MemberRole::Editor)
            .unwrap();
        assert_eq!(out["changed"], serde_json::json!(true));
        let out = handle
            .member_set_role(member_id, MemberRole::Editor)
            .unwrap();
        assert_eq!(out["changed"], serde_json::json!(false));

        // The Owner row is untouchable and Owner is not assignable.
        let owner_id = crate::vault::members::owner_member_id(&path).unwrap();
        let err = handle
            .member_set_role(owner_id, MemberRole::Viewer)
            .unwrap_err();
        assert!(err.to_string().contains("ownership moves via transfer"));
        let err = handle
            .member_set_role(member_id, MemberRole::Owner)
            .unwrap_err();
        assert!(err.to_string().contains("ownership cannot be assigned"));

        // Admin rank needs a verified contact (the flipped-vault dial);
        // an unverified member is refused.
        let err = handle
            .member_set_role(member_id, MemberRole::Admin)
            .unwrap_err();
        assert!(err.to_string().contains("verified contact"));

        // A minor cannot hold admin rank either (clearly flagged row).
        handle.member_set_minor(member_id, true).unwrap();
        let err = handle
            .member_set_role(member_id, MemberRole::Admin)
            .unwrap_err();
        assert!(err.to_string().contains("a minor cannot hold admin rank"));
        handle.member_set_minor(member_id, false).unwrap();

        // Tombstoned rows refuse.
        let mut gone = mk_row(MemberRole::Viewer);
        gone.removed = Some(crate::vault::templates::now_secs());
        crate::vault::members::write_member(&path, &gone).unwrap();
        let err = handle
            .member_set_role(member_id, MemberRole::Editor)
            .unwrap_err();
        assert!(err.to_string().contains("that member row is gone"));

        // Demotion strips keywraps: seed an admin row whose device
        // carries a keywrap, demote, the wrap dies. The acting (owner)
        // device's own wrap survives.
        let admin_id = uuid::Uuid::new_v4();
        let mut admin = mk_row(MemberRole::Admin);
        admin.id = admin_id;
        admin.identity_signing_pubkey = None;
        crate::vault::members::write_member(&path, &admin).unwrap();
        let admin_device = uuid::Uuid::new_v4();
        crate::vault::members::write_device_binding(
            &path,
            &crate::vault::members::DeviceBinding {
                device_id: admin_device,
                member_id: admin_id,
            },
        )
        .unwrap();
        super::super::write_vault_file(
            &path.join(format!("meta/keywrap/{admin_device}.json")),
            br#"{"device_id":"x"}"#,
        )
        .unwrap();
        handle
            .member_set_role(admin_id, MemberRole::Viewer)
            .unwrap();
        assert!(
            !path
                .join(format!("meta/keywrap/{admin_device}.json"))
                .exists()
        );
    }

    #[test]
    fn member_revoke_rotates_the_collection_key() {
        let (_temp, mut handle, _pw) = family_vault();
        let (shared, _kit) = setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        let sgk = handle.unlocked().sgk().unwrap().clone();

        // A live Editor whose identity carries a real wrap key, so the
        // grant mints a per-member wrap file.
        let member_id = uuid::Uuid::new_v4();
        let (wrap_secret, wrap_pub) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let _ = wrap_secret;
        let mut member = test_member_row(member_id, "Uncle Rob");
        member.identity_wrap_pubkey = Some(hex::encode(wrap_pub.as_bytes()));
        crate::vault::members::write_member(&path, &member).unwrap();

        // A second, surviving member with their own wrap key.
        let survivor_id = uuid::Uuid::new_v4();
        let (survivor_secret, survivor_pub) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let mut survivor = test_member_row(survivor_id, "Grandma");
        survivor.identity_wrap_pubkey = Some(hex::encode(survivor_pub.as_bytes()));
        crate::vault::members::write_member(&path, &survivor).unwrap();

        let roles = crate::vault::collections::create_collection(&path, &sgk, "Roles").unwrap();
        crate::vault::collections::upsert_grant(
            &path,
            &sgk,
            &roles.id,
            crate::vault::collections::CollectionGrant {
                target: crate::vault::collections::GrantTarget::Member { id: member_id },
                access: crate::vault::collections::CollectionAccess::Write,
                expires_at: None,
            },
        )
        .unwrap();
        let wrap_path = crate::vault::collections::grant_wrap_path(&path, &roles.id, &member_id);
        assert!(wrap_path.exists(), "grant must mint the member wrap");
        for mid in [member_id, survivor_id] {
            if mid != member_id {
                crate::vault::collections::upsert_grant(
                    &path,
                    &sgk,
                    &roles.id,
                    crate::vault::collections::CollectionGrant {
                        target: crate::vault::collections::GrantTarget::Member { id: mid },
                        access: crate::vault::collections::CollectionAccess::Write,
                        expires_at: None,
                    },
                )
                .unwrap();
            }
        }
        let survivor_wrap =
            crate::vault::collections::grant_wrap_path(&path, &roles.id, &survivor_id);
        assert!(survivor_wrap.exists());
        let survivor_wrap_before = std::fs::read(&survivor_wrap).unwrap();

        // One entry inside, so the rotation must re-encrypt it.
        let input = crate::types::CipherInput {
            name: "Shared Login".into(),
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("rob".into()),
                password: Some("hunter2".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cipher_id = handle
            .add_cipher_in_collection(&input, Some(roles.id))
            .unwrap();

        let (before, _) =
            crate::vault::collections::open_collection(&path, &sgk, &roles.id).unwrap();
        let old_ck = crate::vault::collections::unwrap_ck(&before, &sgk).unwrap();

        handle
            .collection_revoke(
                roles.id,
                crate::vault::collections::GrantTarget::Member { id: member_id },
            )
            .unwrap();

        // The grant row dies, the wrap file dies, and the key rotates:
        // the old wrap would be worthless even if a stale copy came back.
        let (after, _) =
            crate::vault::collections::open_collection(&path, &sgk, &roles.id).unwrap();
        assert!(
            after
                .grants
                .iter()
                .all(|g| g.target.member_id() != Some(member_id)),
            "revoked member row must be gone"
        );
        assert!(!wrap_path.exists(), "revoked member wrap must be deleted");
        let new_ck = crate::vault::collections::unwrap_ck(&after, &sgk).unwrap();
        assert_ne!(
            old_ck.as_slice(),
            new_ck.as_slice(),
            "revocation must rotate the collection key"
        );

        // The survivor's wrap was rewrapped under the new key and still
        // opens the collection with the survivor's own secret.
        let survivor_wrap_after = std::fs::read(&survivor_wrap).unwrap();
        assert_ne!(
            survivor_wrap_before, survivor_wrap_after,
            "surviving wrap must be rewrapped under the new key"
        );
        let survivor_ck = crate::vault::collections::open_grant_wrap(
            &path,
            &roles.id,
            &survivor_id,
            &survivor_secret,
        )
        .unwrap();
        assert_eq!(survivor_ck.as_slice(), new_ck.as_slice());

        // The stored entry still decrypts — under the NEW key.
        use crate::vault::handle::CipherRead;
        match handle.get_cipher(cipher_id).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "Shared Login");
            }
            CipherRead::Locked(_) => panic!("vault is unlocked; cipher must decrypt"),
        }
        let _ = shared;

        // Revoking someone who holds no grant stays a loud error.
        let stranger = uuid::Uuid::new_v4();
        let err = handle
            .collection_revoke(
                roles.id,
                crate::vault::collections::GrantTarget::Member { id: stranger },
            )
            .unwrap_err();
        assert!(err.to_string().contains("no access"), "{err}");
    }

    #[test]
    fn duplicate_collection_names_are_refused() {
        let (_temp, mut handle, _pw) = family_vault();
        setup_family_vault(&mut handle).unwrap();
        handle.collection_create("Roles").unwrap();
        let err = handle.collection_create("Roles").unwrap_err();
        assert!(err.to_string().contains("already"), "{err}");
        // Case-folded and trimmed collisions refuse too.
        assert!(handle.collection_create("roles").is_err());
        assert!(handle.collection_create("  Roles  ").is_err());
        // A distinct name still creates.
        assert!(handle.collection_create("Roles Junior").is_ok());
    }

    fn test_member_row(id: uuid::Uuid, name: &str) -> crate::vault::members::MemberFile {
        crate::vault::members::MemberFile {
            id,
            display_name: name.into(),
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
        }
    }

    fn leave_record_files_lists_and_execution_leaves_traces() {
        let (_temp, mut handle, _pw) = family_vault();
        let (shared, _kit) = setup_family_vault(&mut handle).unwrap();
        let path = handle.path.clone();
        // A live Editor member with a device binding, granted Write on
        // their own collection plus Read on Shared.
        let leaver_id = uuid::Uuid::new_v4();
        let leaver = crate::vault::members::MemberFile {
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
