//! Field-level conflict resolution (D10).
//!
//! On push rejection (non-fast-forward):
//! 1. Pull remote version
//! 2. Verify commit signature on remote version
//! 3. Decrypt both local and remote versions
//! 4. Field-level diff: merge non-overlapping field changes automatically
//! 5. Same-field conflict: flag for user resolution (both values shown)
//! 6. Re-encrypt merged result, commit, push

use zeroize::Zeroize;

use crate::types::{CipherInput, CipherKind};

/// Result of a field-level merge attempt.
#[derive(Debug, Clone)]
pub enum MergeResult {
    /// Automatic merge succeeded.
    Merged(CipherInput),
    /// Conflict requires user resolution.
    Conflict(ConflictInfo),
}

/// Details of a merge conflict.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    /// Fields that conflicted.
    pub conflicting_fields: Vec<FieldConflict>,
    /// The auto-merged non-conflicting fields.
    pub merged_base: CipherInput,
}

impl Drop for ConflictInfo {
    fn drop(&mut self) {
        for f in self.conflicting_fields.iter_mut() {
            f.local_value.zeroize();
            f.remote_value.zeroize();
        }
        // Zeroize sensitive fields in merged_base
        self.merged_base.notes.zeroize();
        match &mut self.merged_base.kind {
            CipherKind::Login(data) => {
                data.password.zeroize();
                data.totp_uri.zeroize();
            }
            CipherKind::Card(data) => {
                data.code.zeroize();
                data.number.zeroize();
            }
            CipherKind::SshKey(data) => {
                data.private_key.zeroize();
            }
            _ => {}
        }
        for cf in &mut self.merged_base.custom_fields {
            if matches!(cf.field_type, crate::types::CustomFieldType::Hidden) {
                cf.value.zeroize();
            }
        }
    }
}

/// A single field conflict.
/// Intentionally does NOT derive Serialize/Deserialize to prevent
/// accidental serialization of plaintext passwords.
#[derive(Debug, Clone)]
pub struct FieldConflict {
    pub field_name: String,
    pub local_value: String,
    pub remote_value: String,
}

/// Black-box zeroization on drop for individual conflicts as well.
impl Drop for FieldConflict {
    fn drop(&mut self) {
        self.local_value.zeroize();
        self.remote_value.zeroize();
    }
}

/// Semantic field groups (D10: security-sensitive fields treated as atomic units).
const SEMANTIC_GROUPS: &[&[&str]] = &[&["username", "password", "totp_uri"]];

/// Perform a 3-way field-level merge between local, remote, and common ancestor (base) cipher inputs.
///
/// Non-overlapping changes merge automatically. Same-field conflicts are flagged.
/// Security-sensitive field groups (username + password + TOTP) are atomic:
/// if any field in the group conflicts, the entire group flags for user resolution.
pub fn merge_ciphers(base: &CipherInput, local: &CipherInput, remote: &CipherInput) -> MergeResult {
    let mut merged = local.clone();
    let mut conflicts = Vec::new();

    // Check each field individually using 3-way merge
    merge_3way_field(&base.name, &mut merged.name, &remote.name, "name", &mut conflicts);

        // Merge kind-specific data
    match (&base.kind, &local.kind, &remote.kind) {
        // All three are Login: merge login fields
        (
            CipherKind::Login(base_login),
            CipherKind::Login(local_login),
            CipherKind::Login(remote_login),
        ) => {
            let mut merged_login = local_login.clone();
            merge_3way_field_opt(
                &base_login.username,
                &mut merged_login.username,
                &remote_login.username,
                "username",
                &mut conflicts,
            );
            merge_3way_field_opt(
                &base_login.password,
                &mut merged_login.password,
                &remote_login.password,
                "password",
                &mut conflicts,
            );
            merge_3way_field_opt(
                &base_login.totp_uri,
                &mut merged_login.totp_uri,
                &remote_login.totp_uri,
                "totp_uri",
                &mut conflicts,
            );
            // URIs: union of unique values
            for uri in &remote_login.uris {
                if !merged_login.uris.contains(uri) {
                    merged_login.uris.push(uri.clone());
                }
            }
            merged.kind = CipherKind::Login(merged_login);
        }
        // Same non-Login type on all sides: keep local (no field-level merge for Card/Identity/SshKey yet)
        (_base, _local, _remote)
            if _local.cipher_type() == _base.cipher_type()
                && _remote.cipher_type() == _base.cipher_type() =>
        {
            // All three have the same type — keep local as-is (intentional)
        }
        // Cross-type conflict: one side changed the cipher type
        _ => {
            conflicts.push(FieldConflict {
                field_name: "type".to_string(),
                local_value: format!("{:?}", local.kind.cipher_type()),
                remote_value: format!("{:?}", remote.kind.cipher_type()),
            });
        }
    }

    // Merge notes field
    merge_3way_field_opt(&base.notes, &mut merged.notes, &remote.notes, "notes", &mut conflicts);

    // Custom fields: union by name, prefer local on name collision
    for cf in &remote.custom_fields {
        if !merged.custom_fields.iter().any(|f| f.name == cf.name) {
            merged.custom_fields.push(cf.clone());
        }
    }

    // Check semantic groups
    for group in SEMANTIC_GROUPS {
        let group_has_conflict = group
            .iter()
            .any(|f| conflicts.iter().any(|c| c.field_name == *f));
        if group_has_conflict {
            // Flag ALL fields in the group as conflicting (atomic unit)
            for field in *group {
                if !conflicts.iter().any(|c| c.field_name == *field) {
                    let local_val = get_field_value(&merged, field).unwrap_or("");
                    let remote_val = get_field_value(remote, field).unwrap_or("");
                    conflicts.push(FieldConflict {
                        field_name: field.to_string(),
                        local_value: local_val.to_string(),
                        remote_value: remote_val.to_string(),
                    });
                }
            }
        }
    }

    if conflicts.is_empty() {
        MergeResult::Merged(merged)
    } else {
        MergeResult::Conflict(ConflictInfo {
            conflicting_fields: conflicts,
            merged_base: merged,
        })
    }
}

fn merge_3way_field(
    base: &str,
    local: &mut String,
    remote: &str,
    field_name: &str,
    conflicts: &mut Vec<FieldConflict>,
) {
    if local == remote {
        return;
    }
    if local == base && remote != base {
        // Only remote changed
        *local = remote.to_string();
    } else if remote == base && local != base {
        // Only local changed
        return;
    } else {
        // Both changed to different things: conflict!
        conflicts.push(FieldConflict {
            field_name: field_name.to_string(),
            local_value: local.clone(),
            remote_value: remote.to_string(),
        });
    }
}

fn merge_3way_field_opt(
    base: &Option<String>,
    local: &mut Option<String>,
    remote: &Option<String>,
    field_name: &str,
    conflicts: &mut Vec<FieldConflict>,
) {
    if local == remote {
        return;
    }
    if local == base && remote != base {
        // Only remote changed
        *local = remote.clone();
    } else if remote == base && local != base {
        // Only local changed
        return;
    } else {
        // Both changed to different things: conflict!
        conflicts.push(FieldConflict {
            field_name: field_name.to_string(),
            local_value: local.as_deref().unwrap_or("").to_string(),
            remote_value: remote.as_deref().unwrap_or("").to_string(),
        });
    }
}

fn get_field_value<'a>(input: &'a CipherInput, field: &str) -> Option<&'a str> {
    match field {
        "name" => Some(&input.name),
        "notes" => input.notes.as_deref(),
        "username" | "password" | "totp_uri" => match &input.kind {
            CipherKind::Login(data) => match field {
                "username" => data.username.as_deref(),
                "password" => data.password.as_deref(),
                "totp_uri" => data.totp_uri.as_deref(),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CipherKind, LoginData};

    fn base_input(name: &str) -> CipherInput {
        CipherInput {
            name: name.to_string(),
            folder_id: None,
            kind: CipherKind::Login(LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
        }
    }

    #[test]
    fn identical_ciphers_merge_cleanly() {
        let base = base_input("GitHub");
        let local = base_input("GitHub");
        let remote = base_input("GitHub");
        let result = merge_ciphers(&base, &local, &remote);
        assert!(matches!(result, MergeResult::Merged(_)));
    }

    #[test]
    fn non_overlapping_fields_merge() {
        let base = base_input("GitHub");
        let mut local = base.clone();
        match &mut local.kind {
            CipherKind::Login(data) => data.username = Some("user@old.com".into()),
            _ => panic!("expected login"),
        }

        let mut remote = base.clone();
        remote.notes = Some("added a note".into());

        // Since only local changed username and only remote changed notes,
        // it should merge perfectly with NO conflicts!
        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(merged) => {
                match &merged.kind {
                    CipherKind::Login(data) => {
                        assert_eq!(data.username.as_deref(), Some("user@old.com"));
                    }
                    _ => panic!("expected login"),
                }
                assert_eq!(merged.notes.as_deref(), Some("added a note"));
            }
            MergeResult::Conflict(_) => panic!("expected clean 3-way merge"),
        }
    }

    #[test]
    fn overlapping_field_conflict() {
        let base = base_input("GitHub");
        let mut local = base.clone();
        match &mut local.kind {
            CipherKind::Login(data) => data.username = Some("local@user.com".into()),
            _ => panic!("expected login"),
        }

        let mut remote = base.clone();
        match &mut remote.kind {
            CipherKind::Login(data) => data.username = Some("remote@user.com".into()),
            _ => panic!("expected login"),
        }

        let result = merge_ciphers(&base, &local, &remote);
        assert!(matches!(result, MergeResult::Conflict(_)));
    }

    #[test]
    fn semantic_group_atomic() {
        let mut base = base_input("GitHub");
        match &mut base.kind {
            CipherKind::Login(data) => {
                data.username = Some("user".into());
                data.password = Some("old-pass".into());
                data.totp_uri = Some("otpauth://old".into());
            }
            _ => panic!("expected login"),
        }

        let mut local = base.clone();
        match &mut local.kind {
            CipherKind::Login(data) => data.password = Some("local-pass".into()),
            _ => panic!("expected login"),
        }

        let mut remote = base.clone();
        match &mut remote.kind {
            CipherKind::Login(data) => data.password = Some("remote-pass".into()),
            _ => panic!("expected login"),
        }

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Conflict(info) => {
                // All 3 fields in the semantic group should be flagged
                let names: Vec<&str> = info
                    .conflicting_fields
                    .iter()
                    .map(|c| c.field_name.as_str())
                    .collect();
                assert!(names.contains(&"username"));
                assert!(names.contains(&"password"));
                assert!(names.contains(&"totp_uri"));
            }
            MergeResult::Merged(_) => panic!("expected conflict for semantic group"),
        }
    }

    #[test]
    fn cross_type_change_conflicts() {
        // Base is Login, local stays Login, remote changed to Card
        let base = base_input("Entry");
        let local = base.clone();
        let mut remote = base.clone();
        remote.kind = CipherKind::Card(crate::types::CardData::default());

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Conflict(info) => {
                assert!(info
                    .conflicting_fields
                    .iter()
                    .any(|c| c.field_name == "type"));
            }
            MergeResult::Merged(_) => panic!("expected conflict for cross-type change"),
        }
    }

    #[test]
    fn same_non_login_type_no_conflict() {
        // All three are Card: keep local
        let mut base = CipherInput {
            name: "Card".into(),
            folder_id: None,
            kind: CipherKind::Card(crate::types::CardData {
                brand: Some("Visa".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
        };
        base.name = "Card".into();

        let local = base.clone();
        let remote = base.clone();

        let result = merge_ciphers(&base, &local, &remote);
        assert!(matches!(result, MergeResult::Merged(_)));
    }
}
