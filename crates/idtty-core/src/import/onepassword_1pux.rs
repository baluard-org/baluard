//! 1Password .1pux import parser.
//!
//! .1pux is a ZIP file containing export.data (JSON). Full-fidelity format
//! preserving multiple URIs, custom fields, tags, and all entry types.
//!
//! 1PUX format: ZIP containing `export.data` JSON with structure:
//! { accounts: [{ vaults: [{ items: [{ item: { ... } }] }] }] }

use crate::types::*;
use crate::import::ImportResult;

/// Top-level 1PUX export structure.
#[derive(Debug, serde::Deserialize)]
struct OnePuxExport {
    #[serde(default)]
    accounts: Vec<OnePuxAccount>,
}

#[derive(Debug, serde::Deserialize)]
struct OnePuxAccount {
    #[serde(default)]
    vaults: Vec<OnePuxVault>,
}

#[derive(Debug, serde::Deserialize)]
struct OnePuxVault {
    #[serde(default)]
    items: Vec<OnePuxItem>,
}

#[derive(Debug, serde::Deserialize)]
struct OnePuxItem {
    #[serde(default)]
    item: Option<OnePuxItemDetail>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnePuxItemDetail {
    title: Option<String>,
    category: Option<String>,
    #[serde(default)]
    sections: Vec<OnePuxSection>,
    #[serde(default)]
    fields: Vec<OnePuxField>,
    notes: Option<OnePuxNotes>,
}

#[derive(Debug, serde::Deserialize)]
struct OnePuxSection {
    #[serde(default)]
    fields: Vec<OnePuxField>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct OnePuxField {
    id: Option<String>,
    r#type: Option<String>,
    value: Option<serde_json::Value>,
    label: Option<String>,
    #[serde(default)]
    section: Option<OnePuxFieldSection>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct OnePuxFieldSection {
    id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OnePuxNotes(Option<String>);

/// Parse a .1pux file (ZIP) into cipher inputs.
pub fn parse(data: &[u8]) -> ImportResult {
    let mut result = ImportResult::new();

    // Extract export.data from ZIP
    let archive = match zip::ZipArchive::new(std::io::Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => {
            result.skip(format!("Invalid 1PUX ZIP: {e}"));
            return result;
        }
    };

    let json_data = extract_export_data(archive, &mut result);
    let json_str = match json_data {
        Some(d) => d,
        None => return result,
    };

    let export: OnePuxExport = match serde_json::from_str(&json_str) {
        Ok(e) => e,
        Err(e) => {
            result.skip(format!("Invalid 1PUX JSON: {e}"));
            return result;
        }
    };

    for account in &export.accounts {
        for vault in &account.vaults {
            for item in &vault.items {
                let detail = match &item.item {
                    Some(d) => d,
                    None => continue,
                };

                let name = detail.title.clone().unwrap_or_else(|| "Untitled".into());
                // Collect all fields from item-level and sections
                let mut all_fields: Vec<&OnePuxField> = detail.fields.iter().collect();
                for section in &detail.sections {
                    all_fields.extend(section.fields.iter());
                }

                let notes = detail.notes.as_ref().and_then(|n| n.0.clone())
                    .or_else(|| field_value(&all_fields, "notesPlain"));

                let kind = match detail.category.as_deref() {
                    Some("LOGIN") => parse_login(&all_fields),
                    Some("PASSWORD") | Some("SECURE_NOTE") => Some(CipherKind::SecureNote),
                    Some("CREDIT_CARD") => parse_card(&all_fields),
                    Some("IDENTITY") => parse_identity(&all_fields),
                    Some("SSH_KEY") => parse_ssh_key(&all_fields),
                    _ => {
                        // Fallback: try to detect from fields, otherwise secure note
                        Some(CipherKind::SecureNote)
                    }
                };

                let kind = match kind {
                    Some(k) => k,
                    None => {
                        result.skip(format!("Could not parse 1Password item: {name}"));
                        continue;
                    }
                };

                // Extract custom fields (non-standard ones)
                let custom_fields = extract_custom_fields(&all_fields);

                // Use first tag as folder hint
                let folder = item.tags.as_ref().and_then(|t| t.first().cloned());

                let cipher = CipherInput {
                    name,
                    folder_id: None,
                    kind,
                    favorite: false,
                    notes,
                    custom_fields,
                    created_at: None,
                    password_history: vec![],
            reprompt: false,
                };

                result.add_with_folder(cipher, folder);
            }
        }
    }

    result
}

fn extract_export_data(
    mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>>,
    result: &mut ImportResult,
) -> Option<String> {
    // Standard 1PUX: export.data in ZIP root
    if let Ok(mut file) = archive.by_name("export.data") {
        let mut contents = String::new();
        if std::io::Read::read_to_string(&mut file, &mut contents).is_ok() {
            return Some(contents);
        }
    }

    result.skip("No export.data found in 1PUX archive. Not a valid 1Password export.".into());
    None
}

fn field_value(fields: &[&OnePuxField], id: &str) -> Option<String> {
    fields.iter().find_map(|f| {
        if f.id.as_deref() == Some(id) {
            f.value.as_ref().and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Null => None,
                other => Some(other.to_string()),
            })
        } else {
            None
        }
    })
}

fn parse_login(fields: &[&OnePuxField]) -> Option<CipherKind> {
    let username = field_value(fields, "username");
    let password = field_value(fields, "password");

    // 1Password stores URLs as separate fields
    let mut uris = Vec::new();
    for f in fields {
        if let Some(ref field_id) = f.id {
            if field_id.starts_with("url") || field_id == "website" {
                if let Some(ref v) = f.value {
                    if let Some(s) = v.as_str().filter(|s| !s.is_empty()) {
                        uris.push(LoginUri::new(s.to_string()));
                    }
                }
            }
        }
    }

    // Deduplicate URIs
    uris.sort_by(|a, b| a.uri.cmp(&b.uri));
    uris.dedup_by(|a, b| a.uri == b.uri);

    Some(CipherKind::Login(LoginData {
        username,
        password,
        uris,
        totp_uri: field_value(fields, "totp"),
        autofill_on_page_load: false,
        password_revision_date: None,
    }))
}

fn parse_card(fields: &[&OnePuxField]) -> Option<CipherKind> {
    Some(CipherKind::Card(CardData {
        cardholder_name: field_value(fields, "cardholder"),
        brand: field_value(fields, "type"),
        number: field_value(fields, "number"),
        exp_month: field_value(fields, "expiry_month"),
        exp_year: field_value(fields, "expiry_year"),
        code: field_value(fields, "cvv"),
    }))
}

fn parse_identity(fields: &[&OnePuxField]) -> Option<CipherKind> {
    Some(CipherKind::Identity(IdentityData {
        title: field_value(fields, "title"),
        first_name: field_value(fields, "first_name"),
        middle_name: field_value(fields, "middle_name"),
        last_name: field_value(fields, "last_name"),
        username: field_value(fields, "username"),
        company: field_value(fields, "company"),
        email: field_value(fields, "email"),
        phone: field_value(fields, "phone"),
        address1: field_value(fields, "address1"),
        address2: field_value(fields, "address2"),
        address3: field_value(fields, "address3"),
        city: field_value(fields, "city"),
        state: field_value(fields, "state"),
        postal_code: field_value(fields, "zip"),
        country: field_value(fields, "country"),
        ssn: field_value(fields, "ssn"),
        passport_number: field_value(fields, "passport_number"),
        license_number: field_value(fields, "license_number"),
    }))
}

fn parse_ssh_key(fields: &[&OnePuxField]) -> Option<CipherKind> {
    Some(CipherKind::SshKey(SshKeyData {
        private_key: field_value(fields, "private_key"),
        public_key: field_value(fields, "public_key"),
        key_fingerprint: field_value(fields, "fingerprint"),
    }))
}

fn extract_custom_fields(fields: &[&OnePuxField]) -> Vec<CustomField> {
    let known_ids = [
        "username", "password", "url", "website", "totp",
        "cardholder", "type", "number", "expiry_month", "expiry_year", "cvv",
        "title", "first_name", "middle_name", "last_name", "company", "email",
        "phone", "address1", "address2", "address3", "city", "state", "zip",
        "country", "ssn", "passport_number", "license_number",
        "private_key", "public_key", "fingerprint",
        "notesPlain",
    ];

    fields
        .iter()
        .filter(|f| {
            let id = f.id.as_deref().unwrap_or("");
            !known_ids.contains(&id)
                && f.value.is_some()
                && f.r#type.as_deref() != Some("MENU")
        })
        .filter_map(|f| {
            let value = f.value.as_ref()?;
            let val = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if val.is_empty() {
                return None;
            }
            Some(CustomField {
                name: f.label.clone().unwrap_or_else(|| f.id.clone().unwrap_or_default()),
                value: val,
                field_type: match f.r#type.as_deref() {
                    Some("CONCEALED") | Some("PASSWORD") => CustomFieldType::Hidden,
                    Some("TOGGLE") => CustomFieldType::Boolean,
                    _ => CustomFieldType::Text,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_1pux(json: &str) -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("export.data", options).unwrap();
            zip.write_all(json.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn parse_1pux_login() {
        let json = r#"{
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "item": {
                            "title": "GitHub",
                            "category": "LOGIN",
                            "fields": [
                                {"id": "username", "type": "TEXT", "value": "user@example.com"},
                                {"id": "password", "type": "CONCEALED", "value": "s3cret!"},
                                {"id": "url", "type": "URL", "value": "https://github.com"},
                                {"id": "totp", "type": "OTP", "value": "otpauth://totp/test"}
                            ],
                            "sections": []
                        },
                        "tags": ["Work"]
                    }]
                }]
            }]
        }"#;

        let data = make_1pux(json);
        let result = parse(&data);
        assert_eq!(result.ciphers.len(), 1);
        assert_eq!(result.skipped, 0);

        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris[0].uri, "https://github.com");
                assert_eq!(data.totp_uri.as_deref(), Some("otpauth://totp/test"));
            }
            _ => panic!("expected Login"),
        }
        assert_eq!(result.ciphers[0].name, "GitHub");
        assert!(result.folder_map.contains_key("Work"));
    }

    #[test]
    fn parse_1pux_secure_note() {
        let json = r#"{
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "item": {
                            "title": "My Note",
                            "category": "SECURE_NOTE",
                            "fields": [],
                            "notes": "Secret content"
                        }
                    }]
                }]
            }]
        }"#;

        let data = make_1pux(json);
        let result = parse(&data);
        assert_eq!(result.ciphers.len(), 1);
        assert!(matches!(result.ciphers[0].kind, CipherKind::SecureNote));
    }

    #[test]
    fn parse_1pux_card() {
        let json = r#"{
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "item": {
                            "title": "My Visa",
                            "category": "CREDIT_CARD",
                            "fields": [
                                {"id": "cardholder", "type": "TEXT", "value": "John Doe"},
                                {"id": "type", "type": "MENU", "value": "visa"},
                                {"id": "number", "type": "TEXT", "value": "4111111111111111"},
                                {"id": "expiry_month", "type": "TEXT", "value": "12"},
                                {"id": "expiry_year", "type": "TEXT", "value": "2026"},
                                {"id": "cvv", "type": "CONCEALED", "value": "123"}
                            ]
                        }
                    }]
                }]
            }]
        }"#;

        let data = make_1pux(json);
        let result = parse(&data);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::Card(data) => {
                assert_eq!(data.cardholder_name.as_deref(), Some("John Doe"));
                assert_eq!(data.number.as_deref(), Some("4111111111111111"));
            }
            _ => panic!("expected Card"),
        }
    }

    #[test]
    fn invalid_zip() {
        let result = parse(b"not a zip file");
        assert_eq!(result.skipped, 1);
    }
}
