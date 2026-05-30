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

use crate::types::CipherInput;

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
        self.merged_base.password.zeroize();
        self.merged_base.totp_uri.zeroize();
        self.merged_base.notes.zeroize();
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

    merge_3way_field_opt(
        &base.username,
        &mut merged.username,
        &remote.username,
        "username",
        &mut conflicts,
    );
    merge_3way_field_opt(
        &base.password,
        &mut merged.password,
        &remote.password,
        "password",
        &mut conflicts,
    );
    merge_3way_field_opt(&base.notes, &mut merged.notes, &remote.notes, "notes", &mut conflicts);
    merge_3way_field_opt(
        &base.totp_uri,
        &mut merged.totp_uri,
        &remote.totp_uri,
        "totp_uri",
        &mut conflicts,
    );

    // URIs: simple merge (union of unique values)
    for uri in &remote.uris {
        if !merged.uris.contains(uri) {
            merged.uris.push(uri.clone());
        }
    }

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
        "username" => input.username.as_deref(),
        "password" => input.password.as_deref(),
        "totp_uri" => input.totp_uri.as_deref(),
        "name" => Some(&input.name),
        "notes" => input.notes.as_deref(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input(name: &str) -> CipherInput {
        CipherInput {
            name: name.to_string(),
            folder_id: None,
            username: None,
            password: None,
            uris: vec![],
            notes: None,
            totp_uri: None,
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
        local.username = Some("user@old.com".into());

        let mut remote = base.clone();
        remote.notes = Some("added a note".into());

        // Since only local changed username and only remote changed notes,
        // it should merge perfectly with NO conflicts!
        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(merged) => {
                assert_eq!(merged.username.as_deref(), Some("user@old.com"));
                assert_eq!(merged.notes.as_deref(), Some("added a note"));
            }
            MergeResult::Conflict(_) => panic!("expected clean 3-way merge"),
        }
    }

    #[test]
    fn overlapping_field_conflict() {
        let base = base_input("GitHub");
        let mut local = base.clone();
        local.username = Some("local@user.com".into());

        let mut remote = base.clone();
        remote.username = Some("remote@user.com".into());

        let result = merge_ciphers(&base, &local, &remote);
        assert!(matches!(result, MergeResult::Conflict(_)));
    }

    #[test]
    fn semantic_group_atomic() {
        let mut base = base_input("GitHub");
        base.username = Some("user".into());
        base.password = Some("old-pass".into());
        base.totp_uri = Some("otpauth://old".into());

        let mut local = base.clone();
        local.password = Some("local-pass".into()); // both changed password

        let mut remote = base.clone();
        remote.password = Some("remote-pass".into()); // both changed password

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
    fn uri_union_merge() {
        let base = base_input("GitHub");
        let mut local = base.clone();
        local.uris = vec!["https://github.com".into()];

        let mut remote = base.clone();
        remote.uris = vec!["https://github.com".into(), "https://api.github.com".into()];

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(merged) => {
                assert_eq!(merged.uris.len(), 2);
            }
            MergeResult::Conflict(_) => panic!("expected clean 3-way merge"),
        }
    }
}
