//! Bitwarden JSON import parser.
//!
//! Full-fidelity: all 5 cipher types, folders, URIs with match strategy,
//! password history, custom fields (Text/Hidden/Boolean), favorites.
//!
//! Handles BW's `encryptedString` format by using the plaintext values
//! from the JSON export (BW exports are decrypted before writing).

use crate::types::*;
use crate::import::ImportResult;

/// Top-level BW JSON export structure.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct BwExport {
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
    #[serde(default)]
    ciphers: Vec<BwItem>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct BwFolder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BwItem {
    id: Option<String>,
    name: Option<String>,
    r#type: Option<u8>,
    folder_id: Option<String>,
    favorite: Option<bool>,
    notes: Option<String>,
    login: Option<BwLogin>,
    secure_note: Option<BwSecureNote>,
    card: Option<BwCard>,
    identity: Option<BwIdentity>,
    ssh_key: Option<BwSshKey>,
    fields: Option<Vec<BwField>>,
    password_history: Option<Vec<BwHistoryEntry>>,
    #[serde(default)]
    collection_ids: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<BwLoginUri>>,
    totp: Option<String>,
    autofill_on_page_load: Option<bool>,
    #[serde(rename = "passwordRevisionDate")]
    password_revision_date: Option<String>,
    #[serde(default)]
    fido2_credentials: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct BwLoginUri {
    uri: Option<String>,
    #[serde(rename = "match")]
    match_value: Option<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct BwSecureNote {
    r#type: Option<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwIdentity {
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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwSshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    r#type: Option<u8>,
}

#[derive(Debug, serde::Deserialize)]
struct BwHistoryEntry {
    password: Option<String>,
    last_used_date: Option<String>,
}

fn bw_match_to_strategy(m: Option<u8>) -> UriMatchStrategy {
    match m {
        Some(0) => UriMatchStrategy::Domain,
        Some(1) => UriMatchStrategy::Host,
        Some(2) => UriMatchStrategy::StartsWith,
        Some(3) => UriMatchStrategy::Exact,
        Some(4) => UriMatchStrategy::Regex,
        Some(5) => UriMatchStrategy::Never,
        _ => UriMatchStrategy::Domain,
    }
}

fn bw_field_type(t: Option<u8>) -> CustomFieldType {
    match t {
        Some(0) => CustomFieldType::Text,
        Some(1) => CustomFieldType::Hidden,
        Some(2) => CustomFieldType::Boolean,
        // 3 = Linked (deferred)
        _ => CustomFieldType::Text,
    }
}

/// Parse a BW JSON export string into cipher inputs.
pub fn parse(data: &str) -> ImportResult {
    let mut result = ImportResult::new();

    let export: BwExport = match serde_json::from_str(data) {
        Ok(e) => e,
        Err(e) => {
            result.skip(format!("Invalid BW JSON: {e}"));
            return result;
        }
    };

    // Reject encrypted exports (IDtty cannot decrypt BW's encryption)
    if export.encrypted == Some(true) {
        result.skip("Encrypted BW JSON export not supported. Use plaintext export.".into());
        return result;
    }

    // Parse items (BW uses "items" in personal vault exports, "ciphers" in org exports)
    let items: Vec<&BwItem> = export
        .items
        .iter()
        .chain(export.ciphers.iter())
        .collect();

    // Build folder ID -> folder name mapping
    let folder_map: std::collections::HashMap<String, String> = export.folders.iter()
        .filter_map(|f| {
            let id = f.id.as_ref()?;
            let name = f.name.as_ref()?;
            Some((id.clone(), name.clone()))
        })
        .collect();

    for item in items {
        let name = item.name.clone().unwrap_or_else(|| "Untitled".into());

        // Resolve folder name from item's folder_id
        let folder_name = item.folder_id.as_ref()
            .and_then(|id| folder_map.get(id))
            .cloned();

        // Parse custom fields
        let custom_fields = item.fields.as_ref().map(|fields| {
            fields
                .iter()
                .filter(|f| f.r#type != Some(3)) // Skip Linked fields (deferred)
                .map(|f| CustomField {
                    name: f.name.clone().unwrap_or_default(),
                    value: f.value.clone().unwrap_or_default(),
                    field_type: bw_field_type(f.r#type),
                })
                .collect()
        }).unwrap_or_default();

        // Parse password history
        let password_history = item.password_history.as_ref().map(|hist| {
            hist.iter()
                .filter_map(|h| {
                    let password = h.password.clone()?;
                    let last_used_date = h.last_used_date.as_ref()
                        .and_then(|d| d.parse::<u64>().ok())
                        .unwrap_or(0);
                    Some(PasswordHistoryEntry { password, last_used_date })
                })
                .collect()
        }).unwrap_or_default();

        let kind = match item.r#type {
            Some(1) => {
                // Login
                let login = item.login.as_ref();
                let uris = login
                    .and_then(|l| l.uris.as_ref())
                    .map(|uris| {
                        uris.iter()
                            .filter_map(|u| {
                                u.uri.as_ref().map(|uri| LoginUri {
                                    uri: uri.clone(),
                                    match_strategy: bw_match_to_strategy(u.match_value),
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                CipherKind::Login(LoginData {
                    username: login.and_then(|l| l.username.clone()),
                    password: login.and_then(|l| l.password.clone()),
                    uris,
                    totp_uri: login.and_then(|l| l.totp.clone()),
                    autofill_on_page_load: login.and_then(|l| l.autofill_on_page_load).unwrap_or(false),
                    password_revision_date: login
                        .and_then(|l| l.password_revision_date.as_ref())
                        .and_then(|d| d.parse::<u64>().ok()),
                })
            }
            Some(2) => {
                // Secure Note. BW has a `type` field (always 0 = Generic). Ignored.
                CipherKind::SecureNote
            }
            Some(3) => {
                // Card
                let card = item.card.as_ref();
                CipherKind::Card(CardData {
                    cardholder_name: card.and_then(|c| c.cardholder_name.clone()),
                    brand: card.and_then(|c| c.brand.clone()),
                    number: card.and_then(|c| c.number.clone()),
                    exp_month: card.and_then(|c| c.exp_month.clone()),
                    exp_year: card.and_then(|c| c.exp_year.clone()),
                    code: card.and_then(|c| c.code.clone()),
                })
            }
            Some(4) => {
                // Identity
                let id = item.identity.as_ref();
                CipherKind::Identity(IdentityData {
                    title: id.and_then(|i| i.title.clone()),
                    first_name: id.and_then(|i| i.first_name.clone()),
                    middle_name: id.and_then(|i| i.middle_name.clone()),
                    last_name: id.and_then(|i| i.last_name.clone()),
                    username: id.and_then(|i| i.username.clone()),
                    company: id.and_then(|i| i.company.clone()),
                    email: id.and_then(|i| i.email.clone()),
                    phone: id.and_then(|i| i.phone.clone()),
                    address1: id.and_then(|i| i.address1.clone()),
                    address2: id.and_then(|i| i.address2.clone()),
                    address3: id.and_then(|i| i.address3.clone()),
                    city: id.and_then(|i| i.city.clone()),
                    state: id.and_then(|i| i.state.clone()),
                    postal_code: id.and_then(|i| i.postal_code.clone()),
                    country: id.and_then(|i| i.country.clone()),
                    ssn: id.and_then(|i| i.ssn.clone()),
                    passport_number: id.and_then(|i| i.passport_number.clone()),
                    license_number: id.and_then(|i| i.license_number.clone()),
                })
            }
            Some(5) => {
                // SSH Key (BW added this in 2024+)
                let ssh = item.ssh_key.as_ref();
                CipherKind::SshKey(SshKeyData {
                    private_key: ssh.and_then(|s| s.private_key.clone()),
                    public_key: ssh.and_then(|s| s.public_key.clone()),
                    key_fingerprint: ssh.and_then(|s| s.key_fingerprint.clone()),
                })
            }
            _ => {
                // Unknown type, default to SecureNote with notes
                result.skip(format!("Unknown cipher type {:?} for '{}'", item.r#type, name));
                continue;
            }
        };

        let cipher = CipherInput {
            name,
            folder_id: None, // Resolved later via folder_map
            kind,
            favorite: item.favorite.unwrap_or(false),
            notes: item.notes.clone(),
            custom_fields,
            created_at: None,
            password_history,
            reprompt: false,
            attachments: vec![],
        };

        result.add_with_folder(cipher, folder_name);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bw_json_with_all_types() {
        let json = r#"{
            "encrypted": false,
            "folders": [
                {"id": "f1", "name": "Work"},
                {"id": "f2", "name": "Personal"}
            ],
            "items": [
                {
                    "name": "GitHub",
                    "type": 1,
                    "folderId": "f1",
                    "favorite": true,
                    "notes": "My GitHub account",
                    "login": {
                        "username": "user@example.com",
                        "password": "s3cret!",
                        "uris": [
                            {"uri": "https://github.com", "match": 0},
                            {"uri": "https://api.github.com", "match": 1}
                        ],
                        "totp": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"
                    },
                    "fields": [
                        {"name": "API Key", "value": "key123", "type": 1},
                        {"name": "Active", "value": "true", "type": 2}
                    ],
                    "passwordHistory": [
                        {"password": "oldpass1", "lastUsedDate": "1700000000"},
                        {"password": "oldpass2", "lastUsedDate": "1700001000"}
                    ]
                },
                {
                    "name": "My Secret Note",
                    "type": 2,
                    "notes": "Super secret content"
                },
                {
                    "name": "Visa Card",
                    "type": 3,
                    "card": {
                        "cardholderName": "John Doe",
                        "brand": "Visa",
                        "number": "4111111111111111",
                        "expMonth": "12",
                        "expYear": "2026",
                        "code": "123"
                    }
                },
                {
                    "name": "John Doe Identity",
                    "type": 4,
                    "identity": {
                        "title": "Mr",
                        "firstName": "John",
                        "lastName": "Doe",
                        "address1": "123 Main St",
                        "address2": "Apt 4",
                        "address3": "Building B",
                        "city": "Springfield",
                        "state": "IL",
                        "postalCode": "62701",
                        "country": "US"
                    }
                }
            ]
        }"#;

        let result = parse(json);
        assert_eq!(result.ciphers.len(), 4);
        assert_eq!(result.skipped, 0);

        // Verify folder resolution: GitHub -> "Work" folder
        assert!(result.folder_map.contains_key("Work"));
        assert!(result.folder_map["Work"].contains(&0)); // cipher index 0

        // Login
        let login = &result.ciphers[0];
        assert_eq!(login.name, "GitHub");
        assert!(login.favorite);
        assert_eq!(login.notes.as_deref(), Some("My GitHub account"));
        match &login.kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris.len(), 2);
                assert_eq!(data.uris[0].uri, "https://github.com");
                assert_eq!(data.uris[0].match_strategy, UriMatchStrategy::Domain);
                assert_eq!(data.uris[1].uri, "https://api.github.com");
                assert_eq!(data.uris[1].match_strategy, UriMatchStrategy::Host);
                assert_eq!(data.totp_uri.as_deref(), Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"));
            }
            _ => panic!("expected Login"),
        }
        assert_eq!(login.custom_fields.len(), 2);
        assert_eq!(login.password_history.len(), 2);
        assert_eq!(login.password_history[0].password, "oldpass1");

        // Secure Note
        let note = &result.ciphers[1];
        assert_eq!(note.name, "My Secret Note");
        assert!(matches!(note.kind, CipherKind::SecureNote));
        assert_eq!(note.notes.as_deref(), Some("Super secret content"));

        // Card
        let card = &result.ciphers[2];
        match &card.kind {
            CipherKind::Card(data) => {
                assert_eq!(data.cardholder_name.as_deref(), Some("John Doe"));
                assert_eq!(data.brand.as_deref(), Some("Visa"));
                assert_eq!(data.number.as_deref(), Some("4111111111111111"));
            }
            _ => panic!("expected Card"),
        }

        // Identity with three address lines
        let identity = &result.ciphers[3];
        match &identity.kind {
            CipherKind::Identity(data) => {
                assert_eq!(data.first_name.as_deref(), Some("John"));
                assert_eq!(data.address1.as_deref(), Some("123 Main St"));
                assert_eq!(data.address2.as_deref(), Some("Apt 4"));
                assert_eq!(data.address3.as_deref(), Some("Building B"));
            }
            _ => panic!("expected Identity"),
        }
    }

    #[test]
    fn reject_encrypted_export() {
        let json = r#"{"encrypted": true, "items": []}"#;
        let result = parse(json);
        assert_eq!(result.skipped, 1);
        assert!(result.errors[0].contains("Encrypted"));
    }

    #[test]
    fn empty_export() {
        let json = r#"{"items": []}"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 0);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn secure_note_with_type_field() {
        // BW SecureNote exports include "type": 0 (Generic). Must not error.
        let json = r#"{
            "items": [{
                "name": "Note",
                "type": 2,
                "secureNote": {"type": 0},
                "notes": "content"
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        assert!(matches!(result.ciphers[0].kind, CipherKind::SecureNote));
    }

    #[test]
    fn strips_uri_checksum() {
        // BW exports may include uriChecksum which we ignore
        let json = r#"{
            "items": [{
                "name": "Site",
                "type": 1,
                "login": {
                    "uris": [
                        {"uri": "https://example.com", "match": null, "uriChecksum": "abc123"}
                    ]
                }
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.uris.len(), 1);
                assert_eq!(data.uris[0].uri, "https://example.com");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn linked_fields_skipped() {
        let json = r#"{
            "items": [{
                "name": "Entry",
                "type": 1,
                "login": {},
                "fields": [
                    {"name": "Normal", "value": "text", "type": 0},
                    {"name": "Linked Card Number", "value": "card.number", "type": 3}
                ]
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        // Only the Text field, Linked field (type 3) filtered out
        assert_eq!(result.ciphers[0].custom_fields.len(), 1);
        assert_eq!(result.ciphers[0].custom_fields[0].name, "Normal");
    }

    #[test]
    fn ssh_key_import() {
        let json = r#"{
            "items": [{
                "name": "My SSH Key",
                "type": 5,
                "sshKey": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                    "publicKey": "ssh-rsa AAAA test@host",
                    "keyFingerprint": "SHA256:abc123"
                }
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::SshKey(data) => {
                assert!(data.private_key.as_ref().unwrap().contains("BEGIN"));
                assert_eq!(data.public_key.as_deref(), Some("ssh-rsa AAAA test@host"));
                assert_eq!(data.key_fingerprint.as_deref(), Some("SHA256:abc123"));
            }
            _ => panic!("expected SshKey"),
        }
    }
}
