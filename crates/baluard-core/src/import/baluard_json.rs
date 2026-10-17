//! baluard.vault v1 — Baluard's own backup format.
//!
//! A self-describing, versioned JSON backup of the whole vault: folders
//! (with hierarchy) and every entry in Baluard's real domain model. Unlike
//! the Bitwarden-shaped export, nothing is flattened into someone else's
//! type codes and no field is lost: tags, re-prompt flags, favorites,
//! archive state, password history and passkey private keys all survive a
//! backup → import roundtrip.
//!
//! v1 scope: attachment file BLOBS are not embedded (metadata only via the
//! cipher envelope on re-import is absent too) — a backup of entries is a
//! backup of secrets, not of stored files. Documented, deliberate boundary.
//!
//! Import boundary (current pipeline): the schema's folder hierarchy AND
//! empty folders are restored on import — parents are created before
//! children, same-named siblings already in the vault are reused, and a
//! hostile parent cycle in the file degrades to root folders rather than
//! dropping them. Folder icons are the one schema field not yet restored
//! (the folder-creation API takes no icon). Passkey `linked_login_id`
//! references keep their source-vault UUIDs, which do not exist in the
//! importing vault — that remains the documented boundary.

use crate::types::{Cipher, CipherInput, CipherKind, CustomField, PasswordHistoryEntry};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Format discriminator in the file header. The import auto-detect sniffs
/// for this exact string.
pub const BACKUP_FORMAT: &str = "baluard.vault";

/// Current schema version. Readers fail closed on anything they do not
/// implement, pointing the user at a newer app version.
pub const BACKUP_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaluardBackupV1 {
    pub format: String,
    pub version: u32,
    pub app_version: String,
    /// Unix seconds when the backup was taken.
    pub exported_at: u64,
    #[serde(default)]
    pub vault_name: Option<String>,
    pub manifest: BackupManifest,
    #[serde(default)]
    pub folders: Vec<BackupFolder>,
    pub ciphers: Vec<BackupCipher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub cipher_count: u32,
    pub folder_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFolder {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub icon: Option<String>,
}

/// A full-fidelity entry: Baluard's domain model, not an interchange
/// dialect. Runtime internals (key_epoch, update_seq, tier) and attachment
/// metadata are deliberately excluded — they are storage, not data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCipher {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    pub kind: CipherKind,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Build the backup JSON from decrypted entries and folders.
///
/// `now` is injected (not captured) so exports are deterministic in tests.
/// Entries must already be decrypted; the caller (runtime) skips locked
/// ones with a warning, mirroring the other export paths.
pub fn export_backup(
    ciphers: &[Cipher],
    folders: &[(Uuid, String, Option<Uuid>, Option<String>)],
    vault_name: Option<&str>,
    app_version: &str,
    now: u64,
) -> Result<String, String> {
    let backup_folders: Vec<BackupFolder> = folders
        .iter()
        .map(|(id, name, parent, icon)| BackupFolder {
            id: *id,
            name: name.clone(),
            parent_id: *parent,
            icon: icon.clone(),
        })
        .collect();

    let backup_ciphers: Vec<BackupCipher> = ciphers
        .iter()
        .map(|c| BackupCipher {
            id: c.id,
            name: c.name.clone(),
            folder_id: c.folder_id,
            kind: c.kind.clone(),
            favorite: c.favorite,
            reprompt: c.reprompt,
            notes: c.notes.clone(),
            custom_fields: c.custom_fields.clone(),
            password_history: c.password_history.clone(),
            archived: c.archived,
            tags: c.tags.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();

    let backup = BaluardBackupV1 {
        format: BACKUP_FORMAT.to_string(),
        version: BACKUP_VERSION,
        app_version: app_version.to_string(),
        exported_at: now,
        vault_name: vault_name.map(str::to_string),
        manifest: BackupManifest {
            cipher_count: backup_ciphers.len() as u32,
            folder_count: backup_folders.len() as u32,
        },
        folders: backup_folders,
        ciphers: backup_ciphers,
    };

    serde_json::to_string_pretty(&backup).map_err(|e| format!("backup serialize: {e}"))
}

/// Validate the header and integrity manifest of a backup file. Returns
/// the parsed document or a fail-closed error.
pub fn parse_backup(data: &str) -> Result<BaluardBackupV1, String> {
    let backup: BaluardBackupV1 =
        serde_json::from_str(data).map_err(|e| format!("not a valid backup file: {e}"))?;

    if backup.format != BACKUP_FORMAT {
        return Err(format!(
            "not a Baluard backup (format id {:?})",
            backup.format
        ));
    }
    if backup.version != BACKUP_VERSION {
        return Err(format!(
            "backup version {} is not supported by this app version (expected {}); update Baluard and try again",
            backup.version, BACKUP_VERSION
        ));
    }
    if backup.manifest.cipher_count as usize != backup.ciphers.len()
        || backup.manifest.folder_count as usize != backup.folders.len()
    {
        return Err(
            "backup file is corrupt: entry count does not match the file's own manifest (truncated download?)"
                .into(),
        );
    }
    Ok(backup)
}

/// Convert a validated backup into the generic import pipeline. Folder
/// assignment rides ImportResult's name-keyed folder map; duplicate folder
/// names merge into one runtime folder (same as every other format).
pub fn backup_to_import(backup: BaluardBackupV1) -> crate::import::ImportResult {
    // Emit folders parents-first so the importer can create them in one
    // pass. A hostile parent cycle cannot be rooted; those folders fall
    // back to roots rather than being dropped.
    let index: std::collections::HashMap<Uuid, usize> = backup
        .folders
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id, i))
        .collect();
    let src_parent: Vec<Option<usize>> = backup
        .folders
        .iter()
        .map(|f| f.parent_id.and_then(|p| index.get(&p).copied()))
        .collect();
    let mut order: Vec<(usize, bool)> = Vec::with_capacity(backup.folders.len()); // (src idx, keep parent)
    let mut placed = vec![false; backup.folders.len()];
    while placed.iter().any(|p| !p) {
        let mut progress = false;
        for (i, sp) in src_parent.iter().enumerate() {
            if !placed[i] && sp.is_none_or(|p| placed[p]) {
                order.push((i, true));
                placed[i] = true;
                progress = true;
            }
        }
        if !progress {
            // Only a parent cycle lands here: re-root the stragglers.
            for (i, p) in placed.iter_mut().enumerate() {
                if !*p {
                    order.push((i, false));
                    *p = true;
                }
            }
        }
    }

    let mut result = crate::import::ImportResult::new();
    let mut src_to_res: Vec<Option<usize>> = vec![None; backup.folders.len()];
    for &(i, keep_parent) in &order {
        let parent = if keep_parent {
            src_parent[i].and_then(|p| src_to_res[p])
        } else {
            None
        };
        src_to_res[i] = Some(result.folders.len());
        result.folders.push(crate::import::ImportFolder {
            name: backup.folders[i].name.clone(),
            parent,
        });
    }

    for c in backup.ciphers {
        // Result indices, not source indices: the runtime tree is indexed
        // by result.folders order, which the fixpoint pass may have moved.
        let folder_idx = c
            .folder_id
            .and_then(|id| index.get(&id).copied())
            .and_then(|src_i| src_to_res[src_i]);
        let input = CipherInput {
            name: c.name,
            folder_id: None,
            collection_id: None,
            kind: c.kind,
            favorite: c.favorite,
            reprompt: c.reprompt,
            notes: c.notes,
            custom_fields: c.custom_fields,
            created_at: Some(c.created_at),
            password_history: c.password_history,
            attachments: Vec::new(),
            archived: c.archived,
            tags: c.tags,
        };
        result.cipher_folders.push(folder_idx);
        result.ciphers.push(input);
    }
    result
}

/// Quick header sniff for import auto-detection: does this look like a
/// Baluard backup? Byte-level search over the first 512 bytes — no full
/// parse, cheap enough to run on every picked file, and no char-boundary
/// slicing so arbitrary binary-ish input can never panic it.
pub fn looks_like_backup(data: &str) -> bool {
    let bytes = data.as_bytes();
    let head = &bytes[..bytes.len().min(512)];
    let needle = BACKUP_FORMAT.as_bytes();
    head.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cipher(kind: CipherKind, name: &str) -> Cipher {
        Cipher {
            id: Uuid::new_v4(),
            name: name.to_string(),
            folder_id: None,
            kind,
            favorite: true,
            reprompt: true,
            notes: Some("note".into()),
            custom_fields: vec![
                CustomField {
                    name: "pin".into(),
                    value: "1234".into(),
                    field_type: crate::types::CustomFieldType::Hidden,
                },
                CustomField {
                    name: "checked".into(),
                    value: "true".into(),
                    field_type: crate::types::CustomFieldType::Boolean,
                },
            ],
            key_epoch: 3,
            update_seq: 9,
            tier: crate::types::Tier::M,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_500,
            password_history: vec![PasswordHistoryEntry {
                password: "old-pass".into(),
                last_used_date: 1_690_000_000,
            }],
            attachments: Vec::new(),
            archived: false,
            tags: vec!["work".into(), "devops".into()],
        }
    }

    fn all_kinds() -> Vec<Cipher> {
        let login_data = crate::types::LoginData {
            username: Some("octocat".into()),
            password: Some("hunter2".into()),
            uris: vec![crate::types::LoginUri {
                uri: "https://github.com".into(),
                match_strategy: crate::types::UriMatchStrategy::Domain,
            }],
            totp_uri: Some("otpauth://totp/x".into()),
            password_revision_date: None,
            autofill_on_page_load: false,
            favicon: None,
            fido2_credentials: Some(vec![crate::types::PasskeyData {
                credential_id: "abc".into(),
                key_type: "public-key".into(),
                key_algorithm: "ES256".into(),
                key_curve: "P-256".into(),
                key_value: "pubkey".into(),
                rp_id: "github.com".into(),
                rp_name: Some("GitHub".into()),
                user_handle: Some(vec![1, 2, 3, 4]),
                user_name: Some("octocat".into()),
                user_display_name: Some("Octo".into()),
                counter: 7,
                aaguid: Uuid::nil(),
                prf_key: None,
                private_key: Some(b"SECRET-PRIVATE-KEY".to_vec()),
                private_key_missing: false,
                linked_login_id: None,
                creation_date: 1_700_000_000,
                name: Some("YubiKey".into()),
            }]),
        };
        vec![
            sample_cipher(CipherKind::Login(login_data), "Login"),
            sample_cipher(CipherKind::SecureNote, "Note"),
            sample_cipher(CipherKind::Card(Default::default()), "Card"),
            sample_cipher(CipherKind::Identity(Default::default()), "Identity"),
            sample_cipher(CipherKind::SshKey(Default::default()), "Ssh"),
            sample_cipher(CipherKind::BankAccount(Default::default()), "Bank"),
            sample_cipher(CipherKind::DriversLicense(Default::default()), "Dl"),
            sample_cipher(CipherKind::Passport(Default::default()), "Passport"),
        ]
    }

    fn sample_folders() -> Vec<(Uuid, String, Option<Uuid>, Option<String>)> {
        let parent = Uuid::new_v4();
        vec![
            (parent, "Work".into(), None, Some("briefcase".into())),
            (Uuid::new_v4(), "Sub".into(), Some(parent), None),
        ]
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let ciphers = all_kinds();
        let folders = sample_folders();
        let json =
            export_backup(&ciphers, &folders, Some("Personal"), "0.1.0", 1_700_001_000).unwrap();

        let backup = parse_backup(&json).unwrap();
        assert_eq!(backup.ciphers.len(), 8);
        assert_eq!(backup.folders.len(), 2);
        assert_eq!(backup.manifest.cipher_count, 8);
        // Folder hierarchy survives.
        let sub = backup.folders.iter().find(|f| f.name == "Sub").unwrap();
        let parent_id = backup
            .folders
            .iter()
            .find(|f| f.name == "Work")
            .map(|f| f.id)
            .unwrap();
        assert_eq!(sub.parent_id, Some(parent_id));
        assert_eq!(sub.icon.as_deref(), None);

        let import = backup_to_import(backup);
        assert_eq!(import.ciphers.len(), 8);
        assert_eq!(import.skipped, 0);

        for (orig, parsed) in ciphers.iter().zip(import.ciphers.iter()) {
            assert_eq!(orig.name, parsed.name);
            assert_eq!(orig.favorite, parsed.favorite);
            assert_eq!(orig.reprompt, parsed.reprompt);
            assert_eq!(orig.tags, parsed.tags);
            assert_eq!(orig.custom_fields.len(), parsed.custom_fields.len());
            assert_eq!(
                serde_json::to_value(&orig.custom_fields).unwrap(),
                serde_json::to_value(&parsed.custom_fields).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&orig.password_history).unwrap(),
                serde_json::to_value(&parsed.password_history).unwrap()
            );
            assert_eq!(orig.created_at, parsed.created_at.unwrap());
            // Kind deep-equality via canonical JSON (CipherKind has no
            // PartialEq derive; serde roundtrip must be identical).
            let a = serde_json::to_value(&orig.kind).unwrap();
            let b = serde_json::to_value(&parsed.kind).unwrap();
            assert_eq!(a, b, "kind roundtrip for {}", orig.name);
        }
    }

    #[test]
    fn passkey_private_key_survives_the_backup() {
        let ciphers = all_kinds();
        let json = export_backup(&ciphers, &[], None, "0.1.0", 1).unwrap();

        let import = backup_to_import(parse_backup(&json).unwrap());
        let login = import
            .ciphers
            .iter()
            .find(|c| matches!(c.kind, CipherKind::Login(_)))
            .unwrap();
        if let CipherKind::Login(data) = &login.kind {
            let pk = data.fido2_credentials.as_ref().unwrap()[0]
                .private_key
                .as_deref();
            assert_eq!(pk, Some(b"SECRET-PRIVATE-KEY".as_slice()));
        } else {
            panic!("expected login");
        }
    }

    #[test]
    fn folder_assignment_flows_through_import() {
        let mut ciphers = all_kinds();
        let folders = sample_folders();
        ciphers[0].folder_id = Some(folders[0].0);
        let json = export_backup(&ciphers, &folders, None, "0.1.0", 1).unwrap();
        let import = backup_to_import(parse_backup(&json).unwrap());
        // The hierarchy path replaces the flat name map for this format.
        assert!(import.folder_map.is_empty());
        assert_eq!(import.folders.len(), 2);
        assert_eq!(import.folders[0].name, "Work");
        assert_eq!(import.folders[0].parent, None);
        assert_eq!(import.folders[1].name, "Sub");
        assert_eq!(import.folders[1].parent, Some(0));
        assert_eq!(import.cipher_folders[0], Some(0));
        assert!(import.cipher_folders[1..].iter().all(|o| o.is_none()));
    }

    #[test]
    fn import_orders_parents_before_children() {
        let parent = Uuid::new_v4();
        let folders = vec![
            (Uuid::new_v4(), "Sub".to_string(), Some(parent), None),
            (parent, "Work".to_string(), None, None),
        ];
        let mut ciphers = all_kinds();
        ciphers[0].folder_id = Some(folders[0].0); // filed in Sub
        let json = export_backup(&ciphers, &folders, None, "0.1.0", 1).unwrap();
        let import = backup_to_import(parse_backup(&json).unwrap());
        // The file lists the child first; the import result must not.
        assert_eq!(import.folders[0].name, "Work");
        assert_eq!(import.folders[0].parent, None);
        assert_eq!(import.folders[1].name, "Sub");
        assert_eq!(import.folders[1].parent, Some(0));
        // cipher_folders carries RESULT indices: the cipher names Sub,
        // which sits at result index 1 despite being source index 0.
        assert_eq!(import.cipher_folders[0], Some(1));
    }

    #[test]
    fn import_breaks_parent_cycles_as_roots() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let folders = vec![
            (a, "A".to_string(), Some(b), None),
            (b, "B".to_string(), Some(a), None),
        ];
        let json = export_backup(&all_kinds(), &folders, None, "0.1.0", 1).unwrap();
        let import = backup_to_import(parse_backup(&json).unwrap());
        // Neither folder can be rooted; both land as roots, none dropped.
        assert_eq!(import.folders.len(), 2);
        assert!(import.folders.iter().all(|f| f.parent.is_none()));
    }

    #[test]
    fn import_keeps_empty_folders() {
        let folders = sample_folders();
        // All ciphers unfiled: both folders are empty but must survive.
        let json = export_backup(&all_kinds(), &folders, None, "0.1.0", 1).unwrap();
        let import = backup_to_import(parse_backup(&json).unwrap());
        assert_eq!(import.folders.len(), 2);
        assert!(import.cipher_folders.iter().all(|o| o.is_none()));
    }

    #[test]
    fn rejects_wrong_format_unknown_version_and_bad_manifest() {
        let good = export_backup(&all_kinds(), &[], None, "0.1.0", 1).unwrap();

        // Not our format.
        let alien = good.replace(BACKUP_FORMAT, "bitwarden.json");
        assert!(
            parse_backup(&alien)
                .unwrap_err()
                .contains("not a Baluard backup")
        );

        // Future version fails closed with an update hint.
        let mut future: serde_json::Value = serde_json::from_str(&good).unwrap();
        future["version"] = serde_json::json!(999);
        assert!(
            parse_backup(&future.to_string())
                .unwrap_err()
                .contains("update Baluard")
        );

        // Truncated file: manifest lies about the count.
        let mut truncated: serde_json::Value = serde_json::from_str(&good).unwrap();
        truncated["manifest"]["cipher_count"] = serde_json::json!(99);
        assert!(
            parse_backup(&truncated.to_string())
                .unwrap_err()
                .contains("corrupt")
        );
    }

    #[test]
    fn sniff_detects_our_header_and_nothing_else() {
        let good = export_backup(&all_kinds(), &[], None, "0.1.0", 1).unwrap();
        assert!(looks_like_backup(&good));
        assert!(!looks_like_backup(r#"{"items": [], "folders": []}"#));
        assert!(!looks_like_backup("folder,username,password\na,b,c"));
        // Multi-byte UTF-8 must not panic the byte-window sniff
        // (regression: a naive &data[..512] slice did).
        // Needle inside the window -> detected.
        let mut wide = "\u{1F600}".repeat(100); // 4-byte emoji, 400 bytes
        wide.push_str(BACKUP_FORMAT);
        assert!(looks_like_backup(&wide));
        // Needle beyond the 512-byte heuristic window -> false, not a
        // panic (real backups carry the header in the first ~20 bytes).
        let mut late = "\u{1F600}".repeat(200); // 800 bytes
        late.push_str(BACKUP_FORMAT);
        assert!(!looks_like_backup(&late));
        assert!(!looks_like_backup(&"\u{00e9}".repeat(600)));
    }
}
