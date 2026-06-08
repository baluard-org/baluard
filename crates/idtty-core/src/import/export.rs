//! Export module.
//!
//! BW-compatible JSON export, BW-compatible CSV export, and IDtty encrypted JSON export.

use crate::types::*;

/// BW JSON export structures
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportJson {
    encrypted: bool,
    folders: Vec<BwExportFolder>,
    items: Vec<BwExportItem>,
}

#[derive(Debug, serde::Serialize)]
struct BwExportFolder {
    id: String,
    name: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportItem {
    id: String,
    name: String,
    r#type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<BwExportLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<BwExportSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<BwExportCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<BwExportIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_key: Option<BwExportSshKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bank_account: Option<crate::types::BankAccountData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    drivers_license: Option<crate::types::DriversLicenseData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport: Option<crate::types::PassportData>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<BwExportField>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    password_history: Vec<BwExportHistoryEntry>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Vec<BwExportUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_revision_date: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct BwExportUri {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_value: Option<u8>,
}

#[derive(Debug, serde::Serialize)]
struct BwExportSecureNote {
    r#type: u8,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportIdentity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    username: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    ssn: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportSshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct BwExportField {
    name: String,
    value: Option<String>,
    r#type: u8,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportHistoryEntry {
    password: String,
    last_used_date: String,
}

fn strategy_to_bw(s: UriMatchStrategy) -> u8 {
    match s {
        UriMatchStrategy::Domain => 0,
        UriMatchStrategy::Host => 1,
        UriMatchStrategy::StartsWith => 2,
        UriMatchStrategy::Exact => 3,
        UriMatchStrategy::Regex => 4,
        UriMatchStrategy::Never => 5,
    }
}

fn field_type_to_bw(ft: &CustomFieldType) -> u8 {
    match ft {
        CustomFieldType::Text => 0,
        CustomFieldType::Hidden => 1,
        CustomFieldType::Boolean => 2,
        CustomFieldType::Linked(_) => 0, // exported as text
    }
}

/// Export ciphers as BW-compatible JSON.
///
/// `folders`: slice of (id, name) pairs for folder resolution.
pub fn export_bw_json(
    ciphers: &[Cipher],
    folders: &[(uuid::Uuid, String)],
) -> Result<String, String> {
    let bw_folders: Vec<BwExportFolder> = folders
        .iter()
        .map(|(id, name)| BwExportFolder {
            id: id.to_string(),
            name: name.clone(),
        })
        .collect();

    let mut items = Vec::new();

    for cipher in ciphers {
        let bw_type = match &cipher.kind {
            CipherKind::Login(_) => 1,
            CipherKind::SecureNote => 2,
            CipherKind::Card(_) => 3,
            CipherKind::Identity(_) => 4,
            CipherKind::SshKey(_) => 5,
            CipherKind::BankAccount(_) => 6,
            CipherKind::DriversLicense(_) => 7,
            CipherKind::Passport(_) => 8,
        };

        let (login, secure_note, card, identity, ssh_key, bank_account, drivers_license, passport) =
            match &cipher.kind {
                CipherKind::Login(data) => (
                    Some(BwExportLogin {
                        username: data.username.clone(),
                        password: data.password.clone(),
                        uris: data
                            .uris
                            .iter()
                            .map(|u| BwExportUri {
                                uri: u.uri.clone(),
                                match_value: Some(strategy_to_bw(u.match_strategy)),
                            })
                            .collect(),
                        totp: data.totp_uri.clone(),
                        password_revision_date: data.password_revision_date.map(|d| d.to_string()),
                    }),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                CipherKind::SecureNote => (
                    None,
                    Some(BwExportSecureNote { r#type: 0 }),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                CipherKind::Card(data) => (
                    None,
                    None,
                    Some(BwExportCard {
                        cardholder_name: data.cardholder_name.clone(),
                        brand: data.brand.clone(),
                        number: data.number.clone(),
                        exp_month: data.exp_month.clone(),
                        exp_year: data.exp_year.clone(),
                        code: data.code.clone(),
                    }),
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                CipherKind::Identity(data) => (
                    None,
                    None,
                    None,
                    Some(BwExportIdentity {
                        title: data.title.clone(),
                        first_name: data.first_name.clone(),
                        middle_name: data.middle_name.clone(),
                        last_name: data.last_name.clone(),
                        username: data.username.clone(),
                        company: data.company.clone(),
                        email: data.email.clone(),
                        phone: data.phone.clone(),
                        address1: data.address1.clone(),
                        address2: data.address2.clone(),
                        address3: data.address3.clone(),
                        city: data.city.clone(),
                        state: data.state.clone(),
                        postal_code: data.postal_code.clone(),
                        country: data.country.clone(),
                        ssn: data.ssn.clone(),
                        passport_number: data.passport_number.clone(),
                        license_number: data.license_number.clone(),
                    }),
                    None,
                    None,
                    None,
                    None,
                ),
                CipherKind::SshKey(data) => (
                    None,
                    None,
                    None,
                    None,
                    Some(BwExportSshKey {
                        private_key: data.private_key.clone(),
                        public_key: data.public_key.clone(),
                        key_fingerprint: data.key_fingerprint.clone(),
                    }),
                    None,
                    None,
                    None,
                ),
                CipherKind::BankAccount(data) => {
                    (None, None, None, None, None, Some(data.clone()), None, None)
                }
                CipherKind::DriversLicense(data) => {
                    (None, None, None, None, None, None, Some(data.clone()), None)
                }
                CipherKind::Passport(data) => {
                    (None, None, None, None, None, None, None, Some(data.clone()))
                }
            };

        let fields: Vec<BwExportField> = cipher
            .custom_fields
            .iter()
            .map(|f| BwExportField {
                name: f.name.clone(),
                value: Some(f.value.clone()),
                r#type: field_type_to_bw(&f.field_type),
            })
            .collect();

        let history: Vec<BwExportHistoryEntry> = cipher
            .password_history
            .iter()
            .map(|h| BwExportHistoryEntry {
                password: h.password.clone(),
                last_used_date: h.last_used_date.to_string(),
            })
            .collect();

        items.push(BwExportItem {
            id: cipher.id.to_string(),
            name: cipher.name.clone(),
            r#type: bw_type,
            folder_id: cipher.folder_id.map(|id| id.to_string()),
            favorite: cipher.favorite,
            notes: cipher.notes.clone(),
            login,
            secure_note,
            card,
            identity,
            ssh_key,
            bank_account,
            drivers_license,
            passport,
            fields,
            password_history: history,
        });
    }

    let export = BwExportJson {
        encrypted: false,
        folders: bw_folders,
        items,
    };

    serde_json::to_string_pretty(&export).map_err(|e| format!("Serialization error: {e}"))
}

/// Export ciphers as BW-compatible CSV (logins only).
pub fn export_bw_csv(ciphers: &[Cipher]) -> Result<String, String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());

    // Write header
    wtr.write_record([
        "type",
        "name",
        "notes",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ])
    .map_err(|e| format!("CSV write error: {e}"))?;

    for cipher in ciphers {
        match &cipher.kind {
            CipherKind::Login(data) => {
                let uri = data.uris.first().map(|u| u.uri.as_str()).unwrap_or("");
                wtr.write_record([
                    "1",
                    &cipher.name,
                    cipher.notes.as_deref().unwrap_or(""),
                    uri,
                    data.username.as_deref().unwrap_or(""),
                    data.password.as_deref().unwrap_or(""),
                    data.totp_uri.as_deref().unwrap_or(""),
                ])
                .map_err(|e| format!("CSV write error: {e}"))?;
            }
            CipherKind::SecureNote => {
                wtr.write_record([
                    "2",
                    &cipher.name,
                    cipher.notes.as_deref().unwrap_or(""),
                    "",
                    "",
                    "",
                    "",
                ])
                .map_err(|e| format!("CSV write error: {e}"))?;
            }
            _ => {} // Skip non-login/non-note types in CSV
        }
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| format!("CSV flush error: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cipher(id: &str, name: &str, kind: CipherKind) -> Cipher {
        Cipher {
            id: uuid::Uuid::parse_str(id).unwrap(),
            name: name.to_string(),
            folder_id: None,
            kind,
            favorite: false,
            notes: None,
            custom_fields: vec![],
            key_epoch: 1,
            update_seq: 1,
            tier: Tier::Xs,
            created_at: 1000,
            updated_at: 2000,
            password_history: vec![],
            reprompt: false,
            attachments: vec![],
            archived: false,
            tags: vec![],
        }
    }

    #[test]
    fn export_bw_json_round_trip() {
        let ciphers = vec![
            make_cipher(
                "00000000-0000-0000-0000-000000000001",
                "GitHub",
                CipherKind::Login(LoginData {
                    username: Some("user@test.com".into()),
                    password: Some("s3cret!".into()),
                    uris: vec![LoginUri::new("https://github.com".into())],
                    totp_uri: None,
                    autofill_on_page_load: false,
                    password_revision_date: None,
                }),
            ),
            make_cipher(
                "00000000-0000-0000-0000-000000000002",
                "My Note",
                CipherKind::SecureNote,
            ),
        ];

        let json = export_bw_json(&ciphers, &[]).unwrap();

        // Verify it parses back
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["encrypted"], false);
        assert_eq!(parsed["items"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["items"][0]["type"], 1);
        assert_eq!(parsed["items"][0]["login"]["username"], "user@test.com");
        assert_eq!(parsed["items"][1]["type"], 2);
    }

    #[test]
    fn export_bw_csv_logins_only() {
        let ciphers = vec![
            make_cipher(
                "00000000-0000-0000-0000-000000000001",
                "GitHub",
                CipherKind::Login(LoginData {
                    username: Some("user".into()),
                    password: Some("pass".into()),
                    uris: vec![LoginUri::new("https://github.com".into())],
                    ..Default::default()
                }),
            ),
            make_cipher(
                "00000000-0000-0000-0000-000000000002",
                "Card",
                CipherKind::Card(CardData::default()),
            ),
        ];

        let csv = export_bw_csv(&ciphers).unwrap();
        // Card should be skipped in CSV
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 login
        assert!(lines[1].contains("GitHub"));
    }

    #[test]
    fn export_bw_json_with_folders_and_history() {
        let folder_id = uuid::Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();
        let mut cipher = make_cipher(
            "00000000-0000-0000-0000-000000000001",
            "Site",
            CipherKind::Login(LoginData {
                username: Some("u".into()),
                password: Some("new_pass".into()),
                uris: vec![],
                ..Default::default()
            }),
        );
        cipher.folder_id = Some(folder_id);
        cipher.password_history = vec![PasswordHistoryEntry {
            password: "old_pass".into(),
            last_used_date: 1700000000,
        }];

        let folders = vec![(folder_id, "Work".to_string())];
        let json = export_bw_json(&[cipher], &folders).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["folders"][0]["name"], "Work");
        assert_eq!(parsed["items"][0]["folderId"], folder_id.to_string());
        assert_eq!(
            parsed["items"][0]["passwordHistory"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            parsed["items"][0]["passwordHistory"][0]["password"],
            "old_pass"
        );
    }
}
