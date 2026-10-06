//! S2 IS-5 pair Space (plan-sharing §4.6).
//!
//! A Space is a vault: slug `baluard-space-<name>`, shape flagged in the
//! plaintext `meta/settings-pub.json` (`"space": true`). The pair policy
//! caps a Family-shape Space at its two people — owner plus one editor
//! or viewer — enforced at invite minting AND at approval, so an invite
//! minted before the shape was set cannot breach the cap mid-ceremony.
//! Collections and richer shapes arrive in S3; the identity-rooted key
//! pivot is P1. Until then the vault model is the honest v1, and every
//! S1a primitive (join ceremony, removal, reset, transfer, seats) works
//! on a Space unchanged.

use std::path::Path;

use crate::error::{BaluardError, VaultError};
use crate::vault::members::{MEMBERS_DIR, MemberFile, MemberRole};

/// Slug prefix forced on every Space vault (plan §4.6 repo naming).
pub const SPACE_SLUG_PREFIX: &str = "baluard-space-";

/// The vault's recorded purpose (plan-family-spaces §2). Plaintext in
/// `meta/settings-pub.json` beside the legacy pair flag, because it has
/// consumers beyond merge defaults (the pair-gate split, the flip
/// refusal, family creation, G24 classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpacePurpose {
    /// No purpose recorded. With the legacy `"space": true` flag this
    /// classifies as a pair Space (every pre-purpose Space); with a
    /// flipped shape marker it is a legacy organization.
    #[default]
    Absent,
    /// Two-person Space: the pair gate caps it at its two people.
    Pair,
    /// Family vault: born team-shaped, quorum pinned to 1, minors and
    /// family kit rules available.
    Family,
    /// Organization vault: switching vaults is expected friction.
    Org,
}

impl SpacePurpose {
    /// Parse the plaintext JSON value. Unknown strings read as Absent
    /// so a corrupted file never silently changes access rules.
    fn from_json(v: Option<&str>) -> Self {
        match v {
            Some("pair") => Self::Pair,
            Some("family") => Self::Family,
            Some("org") => Self::Org,
            _ => Self::Absent,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "",
            Self::Pair => "pair",
            Self::Family => "family",
            Self::Org => "org",
        }
    }
}

fn read_pub_setting(vault_path: &Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(vault_path.join("meta/settings-pub.json"))
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

/// Read the recorded purpose. Absent file or field = [`SpacePurpose::Absent`].
pub fn read_purpose(vault_path: &Path) -> SpacePurpose {
    read_pub_setting(vault_path)
        .and_then(|v| {
            v.get("purpose")
                .and_then(|p| p.as_str().map(str::to_string))
        })
        .as_deref()
        .map(|s| SpacePurpose::from_json(Some(s)))
        .unwrap_or(SpacePurpose::Absent)
}

/// Write the purpose, merging with the existing plaintext prefs so a
/// purpose write never clobbers theme/lang/the pair flag.
pub fn set_purpose(vault_path: &Path, purpose: SpacePurpose) -> Result<(), BaluardError> {
    if purpose == SpacePurpose::Absent {
        return Err(VaultError::InvalidOperation(
            "purpose cannot be cleared; a vault keeps the purpose it was given".into(),
        )
        .into());
    }
    let path = vault_path.join("meta/settings-pub.json");
    let mut obj: serde_json::Value =
        read_pub_setting(vault_path).unwrap_or_else(|| serde_json::json!({}));
    obj["purpose"] = serde_json::json!(purpose.as_str());
    let body = serde_json::to_string_pretty(&obj)
        .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
    super::write_vault_file(&path, body.as_bytes())?;
    Ok(())
}

/// Pair classification: an explicit `purpose: "pair"` or the legacy
/// `"space": true` flag without a purpose (every pre-purpose Space).
/// A family or org vault never counts as pair, whatever flags it
/// carries.
pub fn is_pair(vault_path: &Path) -> bool {
    match read_purpose(vault_path) {
        SpacePurpose::Pair => true,
        SpacePurpose::Absent => is_space_vault(vault_path),
        SpacePurpose::Family | SpacePurpose::Org => false,
    }
}

/// Space classification, the union the merge plan records: a purpose,
/// a flipped team shape, or the legacy pair flag. Org vaults made by
/// flipping plain vaults carry neither purpose nor flag, so flag-only
/// classification would silently make every organization personal.
pub fn is_space(vault_path: &Path) -> bool {
    read_purpose(vault_path) != SpacePurpose::Absent
        || crate::vault::space_meta::shape_flipped(vault_path)
        || is_space_vault(vault_path)
}

/// Family classification: purpose only. There is no legacy family.
pub fn is_family(vault_path: &Path) -> bool {
    read_purpose(vault_path) == SpacePurpose::Family
}

/// Normalize a user-provided Space name into the forced-prefixed slug.
/// Idempotent: an existing `baluard-space-` or personal `baluard-`
/// prefix is stripped before the Space one is applied, so "Family",
/// "baluard-personal", and "baluard-space-trip" all normalize to a
/// single clean Space slug.
pub fn space_slug(name: &str) -> String {
    let base = super::slug::normalize_slug(name);
    let stripped = base
        .strip_prefix(SPACE_SLUG_PREFIX)
        .or_else(|| {
            if base == "baluard-space" {
                Some("")
            } else {
                None
            }
        })
        .or_else(|| base.strip_prefix("baluard-"))
        .unwrap_or(base.as_str());
    super::slug::normalize_slug(&format!("{SPACE_SLUG_PREFIX}{stripped}"))
}

/// Read the plaintext settings-pub shape flag. Absent file or field =
/// personal vault (the overwhelming default; every pre-S2 vault).
pub fn is_space_vault(vault_path: &Path) -> bool {
    std::fs::read_to_string(vault_path.join("meta/settings-pub.json"))
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .and_then(|v| v.get("space").and_then(|s| s.as_bool()))
        .unwrap_or(false)
}

/// Write the shape flag, merging with any existing plaintext prefs
/// (theme, lang) so a Space marking never clobbers them. New Spaces
/// also stamp `purpose: "pair"` so the pair gate reads explicitly;
/// legacy flag-only vaults keep classifying as pair via the fallback.
pub fn set_space_flag(vault_path: &Path, space: bool) -> Result<(), BaluardError> {
    let path = vault_path.join("meta/settings-pub.json");
    let mut obj: serde_json::Value =
        read_pub_setting(vault_path).unwrap_or_else(|| serde_json::json!({}));
    obj["space"] = serde_json::json!(space);
    if space && read_purpose(vault_path) == SpacePurpose::Absent {
        obj["purpose"] = serde_json::json!("pair");
    }
    let body = serde_json::to_string_pretty(&obj)
        .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
    super::write_vault_file(&path, body.as_bytes())?;
    Ok(())
}

/// Members that count against the pair cap: rows that are live (not
/// removed/reset-tombstoned) AND bound to at least one device. Unbound
/// rows are pending joiners or reset successors awaiting re-join — they
/// hold no seat yet and must not block a reset approval of the very
/// row they succeed (the same distinction the S1b-5 notices sweep
/// learned the hard way).
fn bound_live_member_count(vault_path: &Path) -> usize {
    let members_dir = vault_path.join(MEMBERS_DIR);
    let Ok(entries) = std::fs::read_dir(&members_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter(|entry| {
            entry
                .path()
                .join("devices")
                .read_dir()
                .map(|d| {
                    d.flatten()
                        .any(|f| f.path().extension().is_some_and(|e| e == "json"))
                })
                .unwrap_or(false)
        })
        // The row file sits BESIDE the binding dir: meta/members/<id>.json
        // next to meta/members/<id>/devices/.
        .filter(|entry| {
            let row_path =
                members_dir.join(format!("{}.json", entry.file_name().to_string_lossy()));
            std::fs::read_to_string(row_path)
                .ok()
                .and_then(|data| serde_json::from_str::<MemberFile>(&data).ok())
                // removed AND reset rows are both tombstones: a reset
                // predecessor keeps its device bindings on disk (inert)
                // and must not occupy a pair slot while the successor is
                // pending.
                .map(|row| row.removed.is_none() && row.reset.is_none())
                .unwrap_or(false)
        })
        .count()
}

/// The pair policy gate. Personal vaults pass everything. A Space
/// refuses admin+ roles (both editors means owner plus one editor at
/// most; viewer is the read-only grant variant) and refuses a second
/// joiner once two bound members exist.
pub fn pair_gate(vault_path: &Path, role: MemberRole) -> Result<(), BaluardError> {
    // The pair cap is a pair-Space rule only: a family vault holds the
    // whole household and an organization holds teams, so neither is
    // capped at two (plan-family-spaces §2 flag split).
    if !is_pair(vault_path) {
        return Ok(());
    }
    match role {
        MemberRole::Owner | MemberRole::Admin => {
            return Err(VaultError::InvalidOperation(
                "a two-person space shares as editor or viewer".into(),
            )
            .into());
        }
        MemberRole::Editor | MemberRole::Viewer => {}
    }
    if bound_live_member_count(vault_path) >= 2 {
        return Err(VaultError::InvalidOperation(
            "this space already has its two people; remove someone before inviting a new one"
                .into(),
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::members::{TrustLevel, write_device_binding, write_member};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn row(role: MemberRole, removed: Option<u64>) -> MemberFile {
        MemberFile {
            id: Uuid::new_v4(),
            display_name: "M".into(),
            email: None,
            role,
            trust: TrustLevel::Channel,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        }
    }

    fn bind(vault: &Path, member_id: Uuid) {
        write_device_binding(
            vault,
            &crate::vault::members::DeviceBinding {
                member_id,
                device_id: Uuid::new_v4(),
            },
        )
        .unwrap();
    }

    fn space_fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        set_space_flag(dir.path(), true).unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    #[test]
    fn space_slug_forces_prefix_and_avoids_double() {
        assert_eq!(space_slug("Family"), "baluard-space-family");
        assert_eq!(space_slug("baluard-personal"), "baluard-space-personal");
        assert_eq!(space_slug("baluard-space-trip"), "baluard-space-trip");
    }

    #[test]
    fn space_flag_round_trip_preserves_prefs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path();
        std::fs::create_dir_all(path.join("meta")).unwrap();
        std::fs::write(
            path.join("meta/settings-pub.json"),
            r#"{"theme":"dark","lang":"es"}"#,
        )
        .unwrap();
        assert!(!is_space_vault(path));
        set_space_flag(path, true).unwrap();
        assert!(is_space_vault(path));
        let data = std::fs::read_to_string(path.join("meta/settings-pub.json")).unwrap();
        assert!(data.contains("\"dark\""));
        assert!(data.contains("\"es\""));
    }

    #[test]
    fn pair_gate_personal_vault_allows_admin_and_full_roster() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        write_member(vault, &row(MemberRole::Owner, None)).unwrap();
        write_member(vault, &row(MemberRole::Editor, None)).unwrap();
        // No space flag: admin role + a third member both pass.
        pair_gate(vault, MemberRole::Admin).unwrap();
        pair_gate(vault, MemberRole::Viewer).unwrap();
    }

    #[test]
    fn pair_gate_refuses_admin_role_on_space() {
        let (_dir, vault) = space_fixture();
        let err = pair_gate(&vault, MemberRole::Admin).unwrap_err();
        assert!(err.to_string().contains("editor or viewer"), "{err}");
    }

    #[test]
    fn pair_gate_allows_editor_and_viewer_on_empty_space() {
        let (_dir, vault) = space_fixture();
        pair_gate(&vault, MemberRole::Editor).unwrap();
        pair_gate(&vault, MemberRole::Viewer).unwrap();
    }

    #[test]
    fn pair_gate_refuses_third_bound_member() {
        let (_dir, vault) = space_fixture();
        let owner = row(MemberRole::Owner, None);
        write_member(&vault, &owner).unwrap();
        bind(&vault, owner.id);
        let member = row(MemberRole::Editor, None);
        write_member(&vault, &member).unwrap();
        bind(&vault, member.id);
        let err = pair_gate(&vault, MemberRole::Viewer).unwrap_err();
        assert!(err.to_string().contains("two people"), "{err}");
    }

    #[test]
    fn pair_gate_ignores_unbound_and_removed_rows() {
        let (_dir, vault) = space_fixture();
        // Owner + a removed row + an unbound reset successor: the cap
        // counts only the bound live owner, so the slot is open.
        let owner = row(MemberRole::Owner, None);
        write_member(&vault, &owner).unwrap();
        bind(&vault, owner.id);
        write_member(&vault, &row(MemberRole::Editor, Some(123))).unwrap();
        write_member(&vault, &row(MemberRole::Editor, None)).unwrap();
        pair_gate(&vault, MemberRole::Editor).unwrap();
    }

    #[test]
    fn pair_gate_ignores_bound_reset_predecessor() {
        let (_dir, vault) = space_fixture();
        // The reset flow keeps the predecessor's device bindings on
        // disk with only reset: Some as the tombstone. The pair slot
        // belongs to the pending successor, not the dead row.
        let owner = row(MemberRole::Owner, None);
        write_member(&vault, &owner).unwrap();
        bind(&vault, owner.id);
        let mut predecessor = row(MemberRole::Editor, None);
        predecessor.reset = Some(crate::vault::members::MemberReset {
            successor: Uuid::new_v4(),
            at: 1,
        });
        write_member(&vault, &predecessor).unwrap();
        bind(&vault, predecessor.id);
        write_member(&vault, &row(MemberRole::Editor, None)).unwrap();
        pair_gate(&vault, MemberRole::Editor).unwrap();
    }

    #[test]
    fn family_purpose_exempts_the_pair_gate() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        super::set_purpose(vault, super::SpacePurpose::Family).unwrap();
        // A family vault holds the whole household: admin roles and a
        // third member both pass.
        pair_gate(&vault, MemberRole::Admin).unwrap();
        write_member(&vault, &row(MemberRole::Owner, None)).unwrap();
        write_member(&vault, &row(MemberRole::Editor, None)).unwrap();
        pair_gate(&vault, MemberRole::Viewer).unwrap();
    }

    #[test]
    fn org_purpose_exempts_the_pair_gate() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        super::set_purpose(vault, super::SpacePurpose::Org).unwrap();
        assert!(!super::is_pair(&vault));
        pair_gate(&vault, MemberRole::Admin).unwrap();
    }

    #[test]
    fn legacy_flag_without_purpose_still_classifies_pair() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        // Raw flag write, bypassing the purpose stamp a real set does.
        std::fs::create_dir_all(vault.join("meta")).unwrap();
        std::fs::write(vault.join("meta/settings-pub.json"), r#"{ "space": true }"#).unwrap();
        assert_eq!(super::read_purpose(&vault), super::SpacePurpose::Absent);
        assert!(super::is_pair(&vault));
        assert!(super::is_space(&vault));
        let err = pair_gate(&vault, MemberRole::Admin).unwrap_err();
        assert!(err.to_string().contains("editor or viewer"), "{err}");
    }

    #[test]
    fn org_purpose_classifies_as_space_without_any_flag() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        super::set_purpose(vault, super::SpacePurpose::Org).unwrap();
        assert!(super::is_space(&vault));
        assert!(!super::is_pair(&vault));
        assert!(!super::is_space_vault(&vault));
    }

    #[test]
    fn set_space_flag_stamps_pair_purpose_for_new_spaces() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        super::set_space_flag(&vault, true).unwrap();
        assert_eq!(super::read_purpose(&vault), super::SpacePurpose::Pair);
        // Clearing the flag later never invents or removes a purpose.
        super::set_space_flag(&vault, false).unwrap();
        assert_eq!(super::read_purpose(&vault), super::SpacePurpose::Pair);
    }

    #[test]
    fn purpose_cannot_be_set_to_absent() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        let err = super::set_purpose(&vault, super::SpacePurpose::Absent).unwrap_err();
        assert!(err.to_string().contains("cannot be cleared"), "{err}");
    }

    #[test]
    fn unknown_purpose_string_reads_absent() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path();
        std::fs::create_dir_all(vault.join("meta")).unwrap();
        std::fs::write(
            vault.join("meta/settings-pub.json"),
            r#"{ "purpose": "commune" }"#,
        )
        .unwrap();
        assert_eq!(super::read_purpose(&vault), super::SpacePurpose::Absent);
    }
}
