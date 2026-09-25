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

/// Merge every `Option<String>` field of a kind struct, flagging conflicts.
/// `base`/`local`/`remote` are expressions yielding `&XxxData`; `merged` is
/// `&mut XxxData`. Each `$field` becomes the conflict label verbatim.
///
/// Why a macro, not reflection: every field is plain `Option<String>`, so the
/// per-field merge is byte-identical except the field name. A macro keeps the
/// conflict labels as readable string literals ("number", "ssn", ...) and the
/// type system still rejects a wrong field name at compile time. The previous
/// code silently dropped remote edits for 7 of 8 kinds via a no-op
/// `keep local as-is` arm; this is the surgical fix.
macro_rules! merge_kind_fields {
    ($base:expr, $local:expr, $remote:expr, $merged:expr, $conflicts:expr, [$($field:ident),* $(,)?]) => {
        $(
            merge_3way_field_opt(
                &$base.$field,
                &mut $merged.$field,
                &$remote.$field,
                stringify!($field),
                $conflicts,
            );
        )*
    };
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
    merge_3way_field(
        &base.name,
        &mut merged.name,
        &remote.name,
        "name",
        &mut conflicts,
    );

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
        // Per-field 3-way merge for every other kind. Previously this arm was
        // a no-op `keep local` that silently discarded remote edits; for a
        // sync product that is the worst-case failure (two devices edit the
        // same Card, one change is lost). All these structs are plain bags of
        // `Option<String>`, so the macro merges each field by name.
        (CipherKind::Card(base_d), CipherKind::Card(local_d), CipherKind::Card(remote_d)) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [cardholder_name, brand, number, exp_month, exp_year, code]
            );
            merged.kind = CipherKind::Card(merged_d);
        }
        (
            CipherKind::Identity(base_d),
            CipherKind::Identity(local_d),
            CipherKind::Identity(remote_d),
        ) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [
                    title,
                    first_name,
                    middle_name,
                    last_name,
                    username,
                    company,
                    email,
                    phone,
                    address1,
                    address2,
                    address3,
                    city,
                    state,
                    postal_code,
                    country,
                    ssn,
                    passport_number,
                    license_number
                ]
            );
            merged.kind = CipherKind::Identity(merged_d);
        }
        (CipherKind::SshKey(base_d), CipherKind::SshKey(local_d), CipherKind::SshKey(remote_d)) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [private_key, public_key, key_fingerprint]
            );
            merged.kind = CipherKind::SshKey(merged_d);
        }
        (
            CipherKind::BankAccount(base_d),
            CipherKind::BankAccount(local_d),
            CipherKind::BankAccount(remote_d),
        ) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [
                    bank_name,
                    name_on_account,
                    account_type,
                    account_number,
                    routing_number,
                    branch_number,
                    pin,
                    swift_code,
                    iban,
                    bank_contact_phone
                ]
            );
            merged.kind = CipherKind::BankAccount(merged_d);
        }
        (
            CipherKind::DriversLicense(base_d),
            CipherKind::DriversLicense(local_d),
            CipherKind::DriversLicense(remote_d),
        ) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [
                    first_name,
                    middle_name,
                    last_name,
                    date_of_birth,
                    license_number,
                    issuing_country,
                    issuing_state,
                    issue_date,
                    expiration_date,
                    issuing_authority,
                    license_class
                ]
            );
            merged.kind = CipherKind::DriversLicense(merged_d);
        }
        (
            CipherKind::Passport(base_d),
            CipherKind::Passport(local_d),
            CipherKind::Passport(remote_d),
        ) => {
            let mut merged_d = local_d.clone();
            merge_kind_fields!(
                base_d,
                local_d,
                remote_d,
                merged_d,
                &mut conflicts,
                [
                    surname,
                    given_name,
                    date_of_birth,
                    sex,
                    birth_place,
                    nationality,
                    issuing_country,
                    passport_number,
                    passport_type,
                    national_identification_number,
                    issuing_authority,
                    issue_date,
                    expiration_date
                ]
            );
            merged.kind = CipherKind::Passport(merged_d);
        }
        // SecureNote has no kind-specific data fields; only notes (merged
        // below) and the common fields apply.
        (CipherKind::SecureNote, CipherKind::SecureNote, CipherKind::SecureNote) => {}
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
    merge_3way_field_opt(
        &base.notes,
        &mut merged.notes,
        &remote.notes,
        "notes",
        &mut conflicts,
    );

    // Custom fields: 3-way merge per field keyed by name. Previously this
    // was union-by-name prefer-local, which ignored `base`: a remote-edited
    // field value lost to the stale local value, and a remote-DELETED field
    // silently reappeared from local (B-4 fix). The logic:
    //   - present in all three: 3-way merge value + field_type
    //   - deleted on one side, unchanged on the other: honor the delete
    //   - deleted on one side, EDITED on the other: conflict (preserve local)
    //   - added on one side only: take it
    merge_custom_fields(
        base,
        local,
        remote,
        &mut merged.custom_fields,
        &mut conflicts,
    );

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
        // Only local changed: nothing to do
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
        // Only local changed: nothing to do
    } else {
        // Both changed to different things: conflict!
        conflicts.push(FieldConflict {
            field_name: field_name.to_string(),
            local_value: local.as_deref().unwrap_or("").to_string(),
            remote_value: remote.as_deref().unwrap_or("").to_string(),
        });
    }
}

/// 3-way merge of custom fields, keyed by field name.
///
/// Produces the merged list (in `out`) and pushes conflicts for any field
/// where local and remote diverged from base incompatibly. The cases:
///
/// - present in all three: merge `value` and `field_type` via 3-way
///   (same-on-both-sides, only-one-side-changed, or both-changed = conflict).
/// - present in base + local only, deleted from remote: if local is
///   unchanged from base, honor the remote delete (drop it); if local
///   edited it, flag a conflict but preserve local (do not silently lose
///   either intent).
/// - present in base + remote only, deleted from local: mirror.
/// - added on one side only (not in base): take it as-is.
///
/// The previous code was union-by-name prefer-local, which silently kept a
/// stale local value over a remote edit and resurrected remote-deleted
/// fields from local (B-4 fix).
fn merge_custom_fields(
    base: &CipherInput,
    local: &CipherInput,
    remote: &CipherInput,
    out: &mut Vec<crate::types::CustomField>,
    conflicts: &mut Vec<FieldConflict>,
) {
    use crate::types::CustomField;

    fn find<'a>(list: &'a [CustomField], name: &str) -> Option<&'a CustomField> {
        list.iter().find(|f| f.name == name)
    }

    // Walk the union of names, deterministic order: local names first (in
    // their existing order), then any remote-only names.
    //
    // `out` starts as `merged.custom_fields` which was cloned from local in
    // the caller; we rebuild the full list here (taking deletes into
    // account), so clear it first to avoid duplicates.
    out.clear();
    let mut seen = std::collections::HashSet::new();
    let local_names = local.custom_fields.iter().map(|f| f.name.clone());
    let remote_only_names = remote
        .custom_fields
        .iter()
        .map(|f| f.name.clone())
        .filter(|n| find(&local.custom_fields, n).is_none());
    for name in local_names.chain(remote_only_names) {
        if !seen.insert(name.clone()) {
            continue;
        }
        let b = find(&base.custom_fields, &name);
        let l = find(&local.custom_fields, &name);
        let r = find(&remote.custom_fields, &name);

        let merged_field = match (b, l, r) {
            // Added on one side only (not in base): take it.
            (None, Some(l), None) => Some(l.clone()),
            (None, None, Some(r)) => Some(r.clone()),
            // In all three: 3-way merge value + field_type.
            (Some(b), Some(l), Some(r)) => {
                // value 3-way (reuses the string merge primitive, scoped to
                // the custom field name so the conflict label is useful).
                let mut value = l.value.clone();
                let mut sub_conflicts = Vec::new();
                merge_3way_field(
                    &b.value,
                    &mut value,
                    &r.value,
                    &format!("custom_field[{name}]"),
                    &mut sub_conflicts,
                );
                conflicts.extend(sub_conflicts);
                // field_type: 3-way, but field_type has no string payload, so
                // if both sides changed it differently it is a conflict too.
                let field_type = if l.field_type == r.field_type {
                    l.field_type.clone()
                } else if l.field_type == b.field_type {
                    r.field_type.clone()
                } else if r.field_type == b.field_type {
                    l.field_type.clone()
                } else {
                    conflicts.push(FieldConflict {
                        field_name: format!("custom_field[{name}].type"),
                        local_value: format!("{:?}", l.field_type),
                        remote_value: format!("{:?}", r.field_type),
                    });
                    l.field_type.clone()
                };
                Some(CustomField {
                    name,
                    value,
                    field_type,
                })
            }
            // Deleted from remote, present in base + local.
            (Some(b), Some(l), None) => {
                if l.value == b.value {
                    // Local unchanged: honor the remote delete.
                    None
                } else {
                    // Local edited while remote deleted: conflict, keep local.
                    conflicts.push(FieldConflict {
                        field_name: format!("custom_field[{name}]"),
                        local_value: l.value.clone(),
                        remote_value: "<deleted>".to_string(),
                    });
                    Some(l.clone())
                }
            }
            // Deleted from local, present in base + remote.
            (Some(b), None, Some(r)) => {
                if r.value == b.value {
                    // Remote unchanged: honor the local delete.
                    None
                } else {
                    // Remote edited while local deleted: conflict, keep
                    // remote (we are rebuilding `out`; push remote so the
                    // edit is not lost).
                    conflicts.push(FieldConflict {
                        field_name: format!("custom_field[{name}]"),
                        local_value: "<deleted>".to_string(),
                        remote_value: r.value.clone(),
                    });
                    Some(r.clone())
                }
            }
            // Present in base only: both sides deleted. Stay deleted.
            (Some(_), None, None) => None,
            // Added on both sides independently (not in base).
            (None, Some(l), Some(r)) => {
                if l.value == r.value && l.field_type == r.field_type {
                    Some(l.clone())
                } else {
                    conflicts.push(FieldConflict {
                        field_name: format!("custom_field[{name}]"),
                        local_value: l.value.clone(),
                        remote_value: r.value.clone(),
                    });
                    Some(l.clone())
                }
            }
            // Cannot happen (name came from local or remote union).
            (None, None, None) => None,
        };
        if let Some(f) = merged_field {
            out.push(f);
        }
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
            collection_id: None,
            kind: CipherKind::Login(LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
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
                assert!(
                    info.conflicting_fields
                        .iter()
                        .any(|c| c.field_name == "type")
                );
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
            collection_id: None,
            kind: CipherKind::Card(crate::types::CardData {
                brand: Some("Visa".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        };
        base.name = "Card".into();

        let local = base.clone();
        let remote = base.clone();

        let result = merge_ciphers(&base, &local, &remote);
        assert!(matches!(result, MergeResult::Merged(_)));
    }

    // B-3 regression: non-overlapping Card field edits used to silently drop
    // the remote edit (the old "keep local" no-op arm). Both changes must now
    // land via per-field 3-way merge.
    #[test]
    fn non_overlapping_card_fields_merge() {
        let base = CipherInput {
            name: "Card".into(),
            folder_id: None,
            collection_id: None,
            kind: CipherKind::Card(crate::types::CardData {
                cardholder_name: Some("Alice".into()),
                number: Some("1111".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        };

        // Local changes the cardholder name only.
        let mut local = base.clone();
        if let CipherKind::Card(d) = &mut local.kind {
            d.cardholder_name = Some("Alice Q".into());
        }

        // Remote changes the number only.
        let mut remote = base.clone();
        if let CipherKind::Card(d) = &mut remote.kind {
            d.number = Some("2222".into());
        }

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(merged) => match &merged.kind {
                CipherKind::Card(d) => {
                    assert_eq!(d.cardholder_name.as_deref(), Some("Alice Q"));
                    assert_eq!(d.number.as_deref(), Some("2222"));
                }
                _ => panic!("expected card"),
            },
            MergeResult::Conflict(_) => panic!("expected clean 3-way merge"),
        }
    }

    // B-3 regression: same Card field edited on both sides must conflict
    // (previously local silently won).
    #[test]
    fn overlapping_card_field_conflicts() {
        let base = CipherInput {
            name: "Card".into(),
            folder_id: None,
            collection_id: None,
            kind: CipherKind::Card(crate::types::CardData {
                number: Some("1111".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        };

        let mut local = base.clone();
        if let CipherKind::Card(d) = &mut local.kind {
            d.number = Some("local".into());
        }

        let mut remote = base.clone();
        if let CipherKind::Card(d) = &mut remote.kind {
            d.number = Some("remote".into());
        }

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Conflict(info) => {
                assert!(
                    info.conflicting_fields
                        .iter()
                        .any(|c| c.field_name == "number")
                );
            }
            MergeResult::Merged(_) => panic!("expected conflict on overlapping number"),
        }
    }

    // B-4 regression: remote edit to a custom field value used to lose to
    // the stale local value (union-by-name prefer-local). Must now take the
    // remote change via 3-way merge.
    #[test]
    fn custom_field_remote_edit_merges() {
        let mut base = base_input("Item");
        base.custom_fields.push(crate::types::CustomField {
            name: "pin".into(),
            value: "1111".into(),
            field_type: crate::types::CustomFieldType::Hidden,
        });

        let local = base.clone(); // local did not touch the field

        let mut remote = base.clone();
        if let Some(f) = remote.custom_fields.iter_mut().find(|f| f.name == "pin") {
            f.value = "2222".into();
        }

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(m) => {
                let f = m
                    .custom_fields
                    .iter()
                    .find(|f| f.name == "pin")
                    .expect("pin field present");
                assert_eq!(f.value, "2222", "remote edit must win when local unchanged");
            }
            MergeResult::Conflict(_) => panic!("expected clean merge"),
        }
    }

    // B-4 regression: a remote-DELETED custom field used to silently
    // reappear from local. With local unchanged, the delete must be honored.
    #[test]
    fn custom_field_remote_delete_honored() {
        let mut base = base_input("Item");
        base.custom_fields.push(crate::types::CustomField {
            name: "old".into(),
            value: "x".into(),
            field_type: crate::types::CustomFieldType::Text,
        });

        let local = base.clone(); // local did not touch it
        let remote = base_input("Item"); // remote dropped the field

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Merged(m) => {
                assert!(
                    m.custom_fields.iter().find(|f| f.name == "old").is_none(),
                    "remote-deleted field must not reappear"
                );
            }
            MergeResult::Conflict(_) => panic!("expected clean merge honoring delete"),
        }
    }

    // B-4: same custom field edited on both sides must conflict.
    #[test]
    fn custom_field_both_edit_conflicts() {
        let mut base = base_input("Item");
        base.custom_fields.push(crate::types::CustomField {
            name: "pin".into(),
            value: "1111".into(),
            field_type: crate::types::CustomFieldType::Hidden,
        });

        let mut local = base.clone();
        if let Some(f) = local.custom_fields.iter_mut().find(|f| f.name == "pin") {
            f.value = "local".into();
        }

        let mut remote = base.clone();
        if let Some(f) = remote.custom_fields.iter_mut().find(|f| f.name == "pin") {
            f.value = "remote".into();
        }

        let result = merge_ciphers(&base, &local, &remote);
        match result {
            MergeResult::Conflict(info) => {
                assert!(
                    info.conflicting_fields
                        .iter()
                        .any(|c| c.field_name == "custom_field[pin]")
                );
            }
            MergeResult::Merged(_) => panic!("expected conflict on both-edit custom field"),
        }
    }
}
