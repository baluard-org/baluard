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
            // Passkeys: keyed by credential id, same discipline as
            // attachments — a redacted copy must not clobber a live one.
            merge_passkey_sets(
                &base_login.fido2_credentials,
                &local_login.fido2_credentials,
                &remote_login.fido2_credentials,
                &mut merged_login.fido2_credentials,
                &mut conflicts,
            );
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

    // Common scalar fields: without these, a remote-only edit to any of
    // them lost to merged=local (the B-3 review's silent-drop class).
    merge_3way_value(
        &base.folder_id,
        &mut merged.folder_id,
        &remote.folder_id,
        "folder_id",
        &mut conflicts,
        |v| v.map(|u| u.to_string()).unwrap_or_default(),
    );
    merge_3way_value(
        &base.favorite,
        &mut merged.favorite,
        &remote.favorite,
        "favorite",
        &mut conflicts,
        |v| v.to_string(),
    );
    merge_3way_value(
        &base.reprompt,
        &mut merged.reprompt,
        &remote.reprompt,
        "reprompt",
        &mut conflicts,
        |v| v.to_string(),
    );
    merge_3way_value(
        &base.archived,
        &mut merged.archived,
        &remote.archived,
        "archived",
        &mut conflicts,
        |v| v.to_string(),
    );

    // Tags: set merge against base — adds from either side land, a delete
    // on one side is honored when the other kept the base set. Tag values
    // are their own identity, so delete-vs-keep cannot conflict.
    merge_tag_set(base, local, remote, &mut merged.tags);

    // Attachments: keyed by id, same discipline as custom fields.
    merge_attachment_set(base, local, remote, &mut merged.attachments, &mut conflicts);

    // Check semantic groups — Login only: the username/password/totp
    // group is meaningless for other kinds whose username field is plain
    // text (an Identity username conflict must not drag in empty password
    // conflicts).
    if matches!(local.kind, CipherKind::Login(_))
        && matches!(base.kind, CipherKind::Login(_))
        && matches!(remote.kind, CipherKind::Login(_))
    {
        for group in SEMANTIC_GROUPS {
            let group_has_conflict = group
                .iter()
                .any(|f| conflicts.iter().any(|c| c.field_name == *f));
            if group_has_conflict {
                // Flag ALL fields in the group as conflicting (atomic unit)
                for field in *group {
                    if !conflicts.iter().any(|c| c.field_name == *field) {
                        // Read from `local`, not `merged`: merged already holds
                        // auto-merged values, so the shown "local side" could be
                        // the remote value the user never had.
                        let local_val = get_field_value(local, field).unwrap_or("");
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
    }

    // Password history: union by timestamp when both sides moved (each
    // device appends on password change). The 10-entry FIFO cap is
    // re-applied by the writers; keep the most recent here. A remote-only
    // move must land too, not lose to the local snapshot.
    if remote.password_history != base.password_history {
        if merged.password_history == base.password_history {
            let mut hist = remote.password_history.clone();
            hist.sort_by_key(|e| std::cmp::Reverse(e.last_used_date));
            hist.truncate(10);
            merged.password_history = hist;
        } else if merged.password_history != remote.password_history {
            let mut hist = merged.password_history.clone();
            for entry in &remote.password_history {
                if !hist.contains(entry) {
                    hist.push(entry.clone());
                }
            }
            hist.sort_by_key(|e| std::cmp::Reverse(e.last_used_date));
            hist.truncate(10);
            merged.password_history = hist;
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

/// PasskeyData carries zeroize-on-drop so it derives no PartialEq;
/// compare the fields that define an unchanged credential.
fn passkey_equivalent(a: &crate::types::PasskeyData, b: &crate::types::PasskeyData) -> bool {
    a.credential_id == b.credential_id
        && a.counter == b.counter
        && a.key_value == b.key_value
        && a.private_key == b.private_key
        && a.prf_key == b.prf_key
        && a.name == b.name
}

/// Keyed-by-credential-id merge of passkey lists. A credential present on
/// one side only lands; a redacted (keyless) copy never clobbers a live
/// one; a genuinely divergent credential conflicts and keeps local.
fn merge_passkey_sets(
    base: &Option<Vec<crate::types::PasskeyData>>,
    local: &Option<Vec<crate::types::PasskeyData>>,
    remote: &Option<Vec<crate::types::PasskeyData>>,
    out: &mut Option<Vec<crate::types::PasskeyData>>,
    conflicts: &mut Vec<FieldConflict>,
) {
    let (Some(local_creds), Some(remote_creds)) = (local, remote) else {
        if local.is_none() && remote.is_some() {
            // Local never had (or deleted all) passkeys. Take remote's set
            // only when base had none either; otherwise the local delete
            // wins over whatever remote still holds.
            let base_had = base.as_ref().is_some_and(|b| !b.is_empty());
            if !base_had {
                *out = remote.clone();
            }
        }
        return;
    };
    let base_creds = base.as_deref().unwrap_or(&[]);
    let mut result: Vec<crate::types::PasskeyData> = Vec::new();
    let mut conflicted = false;
    for cred in local_creds {
        match remote_creds
            .iter()
            .find(|r| r.credential_id == cred.credential_id)
        {
            Some(r) => {
                // A keyless copy is a redacted mirror (the daemon strips
                // key material for IPC); it has no authority to overwrite
                // the keyed original on the side that still holds it.
                let keyed_local = cred.private_key.is_some() || cred.prf_key.is_some();
                let keyed_remote = r.private_key.is_some() || r.prf_key.is_some();
                if keyed_local != keyed_remote {
                    if keyed_local {
                        result.push(cred.clone());
                    } else {
                        result.push(r.clone());
                    }
                } else if passkey_equivalent(cred, r) {
                    result.push(cred.clone());
                } else if base_creds
                    .iter()
                    .any(|b| b.credential_id == cred.credential_id && passkey_equivalent(b, r))
                {
                    result.push(cred.clone()); // remote unchanged from base
                } else if base_creds
                    .iter()
                    .any(|b| b.credential_id == cred.credential_id && passkey_equivalent(b, cred))
                {
                    result.push(r.clone()); // local unchanged from base
                } else {
                    // Both edited: keep local (private key material lives
                    // here — a silent remote pick could destroy it) and
                    // flag for visibility.
                    conflicted = true;
                    result.push(cred.clone());
                }
            }
            None => {
                let in_base = base_creds
                    .iter()
                    .any(|b| b.credential_id == cred.credential_id && passkey_equivalent(b, cred));
                if !in_base {
                    result.push(cred.clone()); // local-only addition
                }
                // A base-identical credential absent remotely was deleted
                // there while local kept it unchanged: honor the delete.
            }
        }
    }
    for cred in remote_creds {
        if local_creds
            .iter()
            .any(|l| l.credential_id == cred.credential_id)
        {
            continue; // already handled from the local side
        }
        let unchanged_from_base = base_creds
            .iter()
            .any(|b| b.credential_id == cred.credential_id && passkey_equivalent(b, cred));
        if unchanged_from_base {
            continue; // local deleted it while remote kept the base value
        }
        result.push(cred.clone()); // remote-only addition
    }
    if conflicted {
        conflicts.push(FieldConflict {
            field_name: "fido2_credentials".to_string(),
            local_value: "passkeys edited on this device".to_string(),
            remote_value: "passkeys edited on the other device".to_string(),
        });
    }
    *out = Some(result);
}

fn merge_3way_value<T: PartialEq + Clone>(
    base: &T,
    local: &mut T,
    remote: &T,
    field_name: &str,
    conflicts: &mut Vec<FieldConflict>,
    display: impl Fn(&T) -> String,
) {
    if local == remote {
        return;
    }
    if local == base && remote != base {
        *local = remote.clone();
    } else if remote == base && local != base {
        // Only local changed: keep it.
    } else {
        conflicts.push(FieldConflict {
            field_name: field_name.to_string(),
            local_value: display(local),
            remote_value: display(remote),
        });
    }
}

/// Set merge of tag lists against base: additions from either side land,
/// one-sided deletes are honored, same-side duplicates collapse.
fn merge_tag_set(
    base: &CipherInput,
    local: &CipherInput,
    remote: &CipherInput,
    out: &mut Vec<String>,
) {
    let mut result: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for tag in local
        .tags
        .iter()
        .chain(remote.tags.iter())
        .chain(base.tags.iter())
    {
        if !seen.insert(tag.clone()) {
            continue;
        }
        let in_base = base.tags.contains(tag);
        let in_local = local.tags.contains(tag);
        let in_remote = remote.tags.contains(tag);
        if in_base && !in_local && !in_remote {
            continue; // deleted on both sides
        }
        if in_base && in_local != in_remote {
            // Deleted on one side; the other side still holds the base
            // value, so honor the delete.
            continue;
        }
        result.push(tag.clone());
    }
    *out = result;
}

/// Keyed-by-id merge of attachment metadata. Additions land, one-sided
/// deletions are honored, and a value edited on both sides conflicts —
/// the blob files live outside this merge, so a silent pick could
/// orphan the loser's blob.
fn merge_attachment_set(
    base: &CipherInput,
    local: &CipherInput,
    remote: &CipherInput,
    out: &mut Vec<crate::vault::attachment::AttachmentMeta>,
    conflicts: &mut Vec<FieldConflict>,
) {
    let mut result: Vec<crate::vault::attachment::AttachmentMeta> = Vec::new();
    for att in &local.attachments {
        match remote.attachments.iter().find(|r| r.id == att.id) {
            Some(r) => {
                if att.filename == r.filename
                    && att.size == r.size
                    && att.encrypted_size == r.encrypted_size
                {
                    result.push(att.clone());
                } else {
                    let base_att = base.attachments.iter().find(|b| b.id == att.id);
                    let base_matches_remote =
                        base_att.is_some_and(|b| b.filename == r.filename && b.size == r.size);
                    let base_matches_local =
                        base_att.is_some_and(|b| b.filename == att.filename && b.size == att.size);
                    if base_matches_remote {
                        result.push(r.clone());
                    } else if base_matches_local {
                        result.push(att.clone());
                    } else {
                        conflicts.push(FieldConflict {
                            field_name: "attachments".to_string(),
                            local_value: att.filename.clone(),
                            remote_value: r.filename.clone(),
                        });
                        result.push(att.clone());
                    }
                }
            }
            None => {
                let unchanged_from_base = base.attachments.iter().any(|b| {
                    b.id == att.id
                        && b.filename == att.filename
                        && b.size == att.size
                        && b.encrypted_size == att.encrypted_size
                });
                if unchanged_from_base {
                    continue; // remote deleted it, local kept the base value
                }
                result.push(att.clone()); // local added or edited it
            }
        }
    }
    for att in &remote.attachments {
        if local.attachments.iter().any(|l| l.id == att.id) {
            continue; // already handled from the local side
        }
        let unchanged_from_base = base.attachments.iter().any(|b| {
            b.id == att.id
                && b.filename == att.filename
                && b.size == att.size
                && b.encrypted_size == att.encrypted_size
        });
        if unchanged_from_base {
            continue; // local deleted it while remote kept the base value
        }
        result.push(att.clone()); // remote-only addition
    }
    *out = result;
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
    fn redacted_remote_copy_never_replaces_keyed_passkey() {
        // A device that only ever saw the redacted IPC copy must not
        // overwrite the keyed original through a merge.
        let base = base_input("site");
        let mut keyed = crate::types::PasskeyData::default();
        keyed.credential_id = "cred-1".into();
        keyed.private_key = Some(b"keybytes".to_vec());
        let mut redacted = crate::types::PasskeyData::default();
        redacted.credential_id = "cred-1".into();
        redacted.private_key = None;

        let mut base_c = base.clone();
        base_c.kind = CipherKind::Login(LoginData {
            fido2_credentials: Some(vec![keyed.clone()]),
            ..LoginData::default()
        });
        let mut local_c = base_c.clone();
        let mut remote_c = base.clone();
        remote_c.kind = CipherKind::Login(LoginData {
            fido2_credentials: Some(vec![redacted]),
            ..LoginData::default()
        });

        match merge_ciphers(&base_c, &local_c, &remote_c) {
            MergeResult::Merged(m) => {
                let CipherKind::Login(login) = &m.kind else {
                    panic!("login kind expected");
                };
                let creds = login.fido2_credentials.as_ref().unwrap();
                assert_eq!(creds.len(), 1);
                assert_eq!(
                    creds[0].private_key.as_deref(),
                    Some(b"keybytes".as_slice())
                );
            }
            MergeResult::Conflict(_) => panic!("redacted mirror must not conflict"),
        }
        let _ = keyed; // moved into base_c
    }

    #[test]
    fn remote_only_common_fields_survive_the_merge() {
        // The silent-drop class: a remote-only edit to a common field
        // must land, not lose to the local snapshot.
        let base = base_input("site");
        let local = base.clone();
        let mut remote = base.clone();
        remote.folder_id = Some(uuid::Uuid::new_v4());
        remote.favorite = true;
        remote.archived = true;
        remote.tags.push("urgent".into());

        match merge_ciphers(&base, &local, &remote) {
            MergeResult::Merged(m) => {
                assert_eq!(m.folder_id, remote.folder_id);
                assert!(m.favorite);
                assert!(m.archived);
                assert!(m.tags.contains(&"urgent".to_string()));
            }
            MergeResult::Conflict(_) => panic!("non-overlapping edits must auto-merge"),
        }

        // One-sided delete is honored: base had "work", remote removed
        // it, local kept the base set.
        let mut base_with_tag = base.clone();
        base_with_tag.tags.push("work".into());
        let mut remote2 = base_with_tag.clone();
        remote2.tags.clear();
        match merge_ciphers(&base_with_tag, &base_with_tag.clone(), &remote2) {
            MergeResult::Merged(m) => assert!(m.tags.is_empty()),
            MergeResult::Conflict(_) => panic!("one-sided delete must be honored"),
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
