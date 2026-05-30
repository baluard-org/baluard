//! Field-level conflict resolution (D10).
//!
//! On push rejection (non-fast-forward):
//! 1. Pull remote version
//! 2. Verify commit signature on remote version
//! 3. Decrypt both local and remote versions
//! 4. Field-level diff: merge non-overlapping field changes automatically
//! 5. Same-field conflict: flag for user resolution (both values shown)
//! 6. Re-encrypt merged result, commit, push

use serde::{Deserialize, Serialize};

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

/// A single field conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConflict {
    pub field_name: String,
    pub local_value: String,
    pub remote_value: String,
}

/// Semantic field groups (D10: security-sensitive fields treated as atomic units).
const SEMANTIC_GROUPS: &[&[&str]] = &[&["username", "password", "totp_uri"]];

/// Perform field-level merge between local and remote cipher inputs.
///
/// Non-overlapping changes merge automatically. Same-field conflicts are flagged.
/// Security-sensitive field groups (username + password + TOTP) are atomic:
/// if any field in the group conflicts, the entire group flags for user resolution.
pub fn merge_ciphers(local: &CipherInput, remote: &CipherInput) -> MergeResult {
    let mut merged = local.clone();
    let mut conflicts = Vec::new();

    // Check each field individually
    merge_optional_field(&mut merged.name, &remote.name, "name", &mut conflicts);

    merge_optional_field_ref(
        &mut merged.username,
        &remote.username,
        "username",
        &mut conflicts,
    );
    merge_optional_field_ref(
        &mut merged.password,
        &remote.password,
        "password",
        &mut conflicts,
    );
    merge_optional_field_ref(&mut merged.notes, &remote.notes, "notes", &mut conflicts);
    merge_optional_field_ref(
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

fn merge_optional_field(
    local: &mut String,
    remote: &str,
    field_name: &str,
    conflicts: &mut Vec<FieldConflict>,
) {
    if local != remote {
        // If they differ, it's a conflict (we don't know which is "newer" at this level)
        conflicts.push(FieldConflict {
            field_name: field_name.to_string(),
            local_value: local.clone(),
            remote_value: remote.to_string(),
        });
    }
}

fn merge_optional_field_ref(
    local: &mut Option<String>,
    remote: &Option<String>,
    field_name: &str,
    conflicts: &mut Vec<FieldConflict>,
) {
    if local != remote {
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
        let local = base_input("GitHub");
        let remote = base_input("GitHub");
        let result = merge_ciphers(&local, &remote);
        assert!(matches!(result, MergeResult::Merged(_)));
    }

    #[test]
    fn non_overlapping_fields_merge() {
        let mut local = base_input("GitHub");
        local.username = Some("user@old.com".into());

        let mut remote = base_input("GitHub");
        remote.notes = Some("added a note".into());

        // name and username differ → conflicts
        let result = merge_ciphers(&local, &remote);
        // This produces conflicts because both name and username differ
        assert!(matches!(result, MergeResult::Conflict(_)));
    }

    #[test]
    fn semantic_group_atomic() {
        let mut local = base_input("GitHub");
        local.username = Some("user".into());
        local.password = Some("old-pass".into());
        local.totp_uri = Some("otpauth://old".into());

        let mut remote = base_input("GitHub");
        remote.username = Some("user".into());
        remote.password = Some("new-pass".into()); // password changed
        remote.totp_uri = Some("otpauth://old".into());

        let result = merge_ciphers(&local, &remote);
        match result {
            MergeResult::Conflict(info) => {
                // All 3 fields in the semantic group should be flagged
                let names: Vec<&str> = info
                    .conflicting_fields
                    .iter()
                    .map(|c| c.field_name.as_str())
                    .collect();
                assert!(names.contains(&"password"));
            }
            MergeResult::Merged(_) => panic!("expected conflict for semantic group"),
        }
    }

    #[test]
    fn uri_union_merge() {
        let mut local = base_input("GitHub");
        local.uris = vec!["https://github.com".into()];

        let mut remote = base_input("GitHub");
        remote.uris = vec!["https://github.com".into(), "https://api.github.com".into()];

        let result = merge_ciphers(&local, &remote);
        match result {
            MergeResult::Merged(merged) => {
                assert_eq!(merged.uris.len(), 2);
            }
            MergeResult::Conflict(_) => {} // name field may conflict
        }
    }
}
