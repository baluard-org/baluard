//! Bitwarden JSON import parser.
//!
//! Full-fidelity: all 5 cipher types, folders, URIs with match strategy,
//! password history, custom fields (Text/Hidden/Boolean), favorites.
//!
//! Handles BW's `encryptedString` format by using the plaintext values
//! from the JSON export (BW exports are decrypted before writing).

use crate::import::ImportResult;
use crate::types::*;
use uuid::Uuid;

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
    // Baluard BW-export extensions (types 6/7/8): plain Bitwarden has no
    // bank-account/driver's-license/passport item classes.
    #[serde(default)]
    bank_account: Option<crate::types::BankAccountData>,
    #[serde(default)]
    drivers_license: Option<crate::types::DriversLicenseData>,
    #[serde(default)]
    passport: Option<crate::types::PassportData>,
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
    /// Typed FIDO2/WebAuthn credentials. BW stores passkeys on Login ciphers
    /// (per BW type 1 model) with this optional array. We emit one
    /// `fido2_credentials` array on the Login data. `keyValue` carries the
    /// credential's private key (PKCS#8) and decodes into
    /// `PasskeyData::private_key`; credentials whose `keyValue` is absent or
    /// undecodable stay view-only (`private_key_missing: true`).
    #[serde(default)]
    fido2_credentials: Option<Vec<BwFido2Credential>>,
}

/// Mirrors Bitwarden's Fido2Credential export shape. Field types match
/// Bitwarden's JSON exactly: `counter` and `discoverable` are strings, dates
/// are ISO 8601, `userHandle` is base64url-encoded bytes.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BwFido2Credential {
    credential_id: Option<String>,
    key_type: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    key_value: Option<String>,
    rp_id: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    counter: Option<String>,
    rp_name: Option<String>,
    user_display_name: Option<String>,
    discoverable: Option<String>,
    creation_date: Option<String>,
}

/// Convert a BW FIDO2 credential into a `PasskeyData`.
///
/// `keyValue` carries the credential's private key as base64url PKCS#8 DER
/// (Bitwarden is a software authenticator and exports the full key pair),
/// decoded into `private_key` so the credential signs like a vault-created
/// one. `private_key_missing` stays `true` only when the key is absent or
/// undecodable (metadata-only, view-only).
/// Per docs/adr/0095-passkey-support.md §4.1, `discoverable` is not stored (it's
/// an invariant, enforced via `residentKey: "required"`).
///
/// AAGUID is `Uuid::nil()` because BW does not export which authenticator
/// produced the credential — we don't know, so we mark it unknown rather
/// than fabricate one. Affects only analytics/reputation, not signing.
fn bw_fido2_to_passkey(fc: &BwFido2Credential) -> PasskeyData {
    use base64::Engine;

    let user_handle = fc.user_handle.as_deref().and_then(|s| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
            .ok()
    });

    let counter = fc
        .counter
        .as_deref()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let creation_date = fc
        .creation_date
        .as_deref()
        .and_then(parse_iso8601_to_unix)
        .unwrap_or(0);

    let key_value = fc.key_value.clone().unwrap_or_default();
    #[cfg(feature = "passkey-ceremony")]
    let (private_key, private_key_missing) = match decode_bw_private_key(&key_value) {
        Some(bytes) => (Some(bytes), false),
        None => (None, true),
    };
    #[cfg(not(feature = "passkey-ceremony"))]
    let (private_key, private_key_missing) = (None, true);

    PasskeyData {
        credential_id: fc.credential_id.clone().unwrap_or_default(),
        key_type: fc.key_type.clone().unwrap_or_else(|| "public-key".into()),
        key_algorithm: fc.key_algorithm.clone().unwrap_or_default(),
        key_curve: fc.key_curve.clone().unwrap_or_default(),
        key_value,
        rp_id: fc.rp_id.clone().unwrap_or_default(),
        rp_name: fc.rp_name.clone(),
        user_handle,
        user_name: fc.user_name.clone(),
        user_display_name: fc.user_display_name.clone(),
        counter,
        aaguid: Uuid::nil(),
        prf_key: None,
        private_key,
        private_key_missing,
        linked_login_id: None,
        creation_date,
        name: None,
    }
}

/// Decode BW's `keyValue` (base64url PKCS#8 DER) into the private COSE key
/// bytes stored in `PasskeyData::private_key`. `None` falls back to the
/// metadata-only view-only import: malformed or non-P-256 keys never block
/// the import, they just cannot sign.
#[cfg(feature = "passkey-ceremony")]
fn decode_bw_private_key(b64: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use coset::cbor::value::Value;
    use coset::iana::{Algorithm, KeyType};
    use coset::{CborSerializable, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate};
    use p256::elliptic_curve::pkcs8::DecodePrivateKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    if b64.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .ok()?;
    let secret = p256::SecretKey::from_pkcs8_der(&der).ok()?;

    let point = secret.public_key().to_encoded_point(false);
    // SEC1 uncompressed point: 0x04 || x (32) || y (32).
    let (x, y) = point.as_bytes().split_at(33);
    let key = CoseKey {
        kty: RegisteredLabel::Assigned(KeyType::EC2),
        alg: Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ES256)),
        params: vec![
            (Label::Int(-1), Value::from(1i64)),             // crv: P-256
            (Label::Int(-2), Value::Bytes(x[1..].to_vec())), // x
            (Label::Int(-3), Value::Bytes(y.to_vec())),      // y
            (Label::Int(-4), Value::Bytes(secret.to_bytes().to_vec())), // d
        ],
        ..Default::default()
    };
    key.to_vec().ok()
}

/// Minimal ISO 8601 (e.g. `"2024-06-12T10:00:00Z"` or
/// `"2024-06-12T10:00:00.000Z"`) to Unix timestamp (seconds). We avoid pulling
/// in `chrono` just for this — the format is stable for the 26 years of
/// JavaScript Date output that BW has ever produced.
fn parse_iso8601_to_unix(s: &str) -> Option<u64> {
    // Strip the trailing 'Z' (UTC indicator) if present.
    let s = s.trim_end_matches('Z');

    // Split date / time on 'T'.
    let mut parts = s.split('T');
    let date = parts.next()?;
    let time = parts.next()?;

    // Date: YYYY-MM-DD
    let mut dparts = date.split('-');
    let year: i64 = dparts.next()?.parse().ok()?;
    let month: i64 = dparts.next()?.parse().ok()?;
    let day: i64 = dparts.next()?.parse().ok()?;

    // Time: HH:MM:SS[.fff]
    let time_no_frac = time.split('.').next().unwrap_or(time);
    let mut tparts = time_no_frac.split(':');
    let hour: i64 = tparts.next()?.parse().ok()?;
    let min: i64 = tparts.next()?.parse().ok()?;
    let sec: i64 = tparts.next()?.parse().ok()?;

    if year < 1970 {
        return None;
    }

    // Howard Hinnant's `days_from_civil` algorithm, signed variant.
    // March-based year: March=0, February=11.
    let (y, m_idx) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy_i = (153 * m_idx + 2) / 5 + (day - 1);
    // doy_i is always >= 0: m_idx ∈ [0,11] gives max (153*11+2)/5 = 337,
    // and day >= 1 gives day-1 >= 0. The negative branch is unreachable
    // for valid Gregorian dates but guards against integer overflow in
    // the yoe computation below.
    let doy = doy_i as u64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + (doe as i64) - 719468;
    if days < 0 {
        return None;
    }
    let secs = (days as u64) * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64);
    Some(secs)
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
#[serde(rename_all = "camelCase")]
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

    // Reject encrypted exports (Baluard cannot decrypt BW's encryption)
    if export.encrypted == Some(true) {
        result.skip("Encrypted BW JSON export not supported. Use plaintext export.".into());
        return result;
    }

    // Parse items (BW uses "items" in personal vault exports, "ciphers" in org exports)
    let items: Vec<&BwItem> = export.items.iter().chain(export.ciphers.iter()).collect();

    // Build folder ID -> folder name mapping
    let folder_map: std::collections::HashMap<String, String> = export
        .folders
        .iter()
        .filter_map(|f| {
            let id = f.id.as_ref()?;
            let name = f.name.as_ref()?;
            Some((id.clone(), name.clone()))
        })
        .collect();

    for item in items {
        let name = item.name.clone().unwrap_or_else(|| "Untitled".into());

        // Resolve folder name from item's folder_id
        let folder_name = item
            .folder_id
            .as_ref()
            .and_then(|id| folder_map.get(id))
            .cloned();

        // Parse custom fields
        let custom_fields = item
            .fields
            .as_ref()
            .map(|fields| {
                fields
                    .iter()
                    .filter(|f| f.r#type != Some(3)) // Skip Linked fields (deferred)
                    .map(|f| CustomField {
                        name: f.name.clone().unwrap_or_default(),
                        value: f.value.clone().unwrap_or_default(),
                        field_type: bw_field_type(f.r#type),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Parse password history
        let password_history = item
            .password_history
            .as_ref()
            .map(|hist| {
                hist.iter()
                    .filter_map(|h| {
                        let password = h.password.clone()?;
                        let last_used_date = h
                            .last_used_date
                            .as_deref()
                            .and_then(|d| {
                                d.parse::<u64>().ok().or_else(|| parse_iso8601_to_unix(d))
                            })
                            .unwrap_or(0);
                        Some(PasswordHistoryEntry {
                            password,
                            last_used_date,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

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
                    autofill_on_page_load: login
                        .and_then(|l| l.autofill_on_page_load)
                        .unwrap_or(false),
                    password_revision_date: login
                        .and_then(|l| l.password_revision_date.as_ref())
                        .and_then(|d| d.parse::<u64>().ok().or_else(|| parse_iso8601_to_unix(d))),
                    fido2_credentials: login
                        .as_ref()
                        .and_then(|l| l.fido2_credentials.as_ref())
                        .map(|list| list.iter().map(bw_fido2_to_passkey).collect::<Vec<_>>()),
                    favicon: None,
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
            Some(6) => match item.bank_account.clone() {
                Some(d) => CipherKind::BankAccount(d),
                None => {
                    result.skip(format!("Bank account '{}' has no data object", name));
                    continue;
                }
            },
            Some(7) => match item.drivers_license.clone() {
                Some(d) => CipherKind::DriversLicense(d),
                None => {
                    result.skip(format!("Driver's license '{}' has no data object", name));
                    continue;
                }
            },
            Some(8) => match item.passport.clone() {
                Some(d) => CipherKind::Passport(d),
                None => {
                    result.skip(format!("Passport '{}' has no data object", name));
                    continue;
                }
            },
            _ => {
                // Unknown types are skipped (listed in the skip report).
                result.skip(format!(
                    "Unknown cipher type {:?} for '{}'",
                    item.r#type, name
                ));
                continue;
            }
        };

        let cipher = CipherInput {
            name,
            folder_id: None, // Resolved later via folder_map
            collection_id: None,
            kind,
            favorite: item.favorite.unwrap_or(false),
            notes: item.notes.clone(),
            custom_fields,
            created_at: None,
            password_history,
            reprompt: false,
            attachments: vec![],
            archived: false,
            tags: vec![],
        };

        result.add_with_folder(cipher, folder_name.clone());
    }

    // fido2_credentials now embedded inside LoginData (above).

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_dates_and_extension_types() {
        // Baluard's BW export writes ISO or integer dates and extension
        // types 6/7/8; real Bitwarden exports write ISO dates. Both must
        // import instead of silently resetting to zero/None.
        let json = r#"{
            "encrypted": false,
            "items": [
                {
                    "name": "Bank",
                    "type": 6,
                    "bankAccount": {
                        "bank_name": "First National",
                        "account_number": "1234567890",
                        "routing_number": "021000021"
                    }
                },
                {
                    "name": "Site",
                    "type": 1,
                    "login": {
                        "username": "u",
                        "password": "p",
                        "passwordRevisionDate": "2024-06-12T10:00:00Z"
                    },
                    "passwordHistory": [
                        {"password": "old", "lastUsedDate": "1700000000"}
                    ]
                }
            ]
        }"#;

        let result = parse(json);
        assert_eq!(result.ciphers.len(), 2, "skips: {:?}", result.errors);

        match &result.ciphers[0].kind {
            CipherKind::BankAccount(d) => {
                assert_eq!(d.bank_name.as_deref(), Some("First National"));
                assert_eq!(d.account_number.as_deref(), Some("1234567890"));
            }
            other => panic!("expected BankAccount, got {other:?}"),
        }

        match &result.ciphers[1].kind {
            CipherKind::Login(d) => {
                // ISO revision date must parse, not fall to None.
                assert!(d.password_revision_date.is_some(), "ISO revision date lost");
            }
            other => panic!("expected Login, got {other:?}"),
        }
        let history = &result.ciphers[1].password_history;
        assert_eq!(history.len(), 1);
        // Integer lastUsedDate must parse, not reset to 0.
        assert_eq!(history[0].last_used_date, 1700000000);
    }

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
                assert_eq!(
                    data.totp_uri.as_deref(),
                    Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP")
                );
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

    #[test]
    fn passkey_import_from_bitwarden() {
        // BW stores fido2_credentials[] inside Login items. Import embeds
        // them into LoginData::fido2_credentials. No separate cipher emitted.
        let json = r#"{
            "items": [{
                "name": "GitHub",
                "type": 1,
                "folderId": "f1",
                "login": {
                    "username": "user@example.com",
                    "password": "s3cret!",
                    "uris": [{"uri": "https://github.com", "match": 0}],
                    "fido2Credentials": [
                        {
                            "credentialId": "ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE",
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            "keyValue": "AQCAgIA",
                            "rpId": "github.com",
                            "rpName": "GitHub",
                            "userHandle": "AQIDBAUGBwgJCgsM",
                            "userName": "user@example.com",
                            "counter": "5",
                            "userDisplayName": "User",
                            "discoverable": "true",
                            "creationDate": "2024-06-12T10:00:00Z"
                        }
                    ]
                }
            }],
            "folders": [{"id": "f1", "name": "Work"}]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        assert_eq!(result.skipped, 0);

        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris.len(), 1);
                let fido2 = data.fido2_credentials.as_ref().unwrap();
                assert_eq!(fido2.len(), 1);
                assert_eq!(
                    fido2[0].credential_id,
                    "ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE"
                );
                assert_eq!(fido2[0].key_type, "public-key");
                assert_eq!(fido2[0].rp_id, "github.com");
                assert_eq!(fido2[0].rp_name.as_deref(), Some("GitHub"));
                assert_eq!(fido2[0].user_name.as_deref(), Some("user@example.com"));
                assert_eq!(fido2[0].counter, 5);
                assert!(fido2[0].private_key.is_none());
                assert!(fido2[0].private_key_missing);
                assert_eq!(fido2[0].creation_date, 1718186400);
            }
            _ => panic!("expected Login cipher with fido2_credentials"),
        }
    }

    #[test]
    fn passkey_import_with_multiple_fido2_credentials() {
        let json = r#"{
            "items": [{
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "user@example.com",
                    "fido2Credentials": [
                        {
                            "credentialId": "cred1",
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            "keyValue": "AQCAgIA",
                            "rpId": "github.com",
                            "rpName": "GitHub",
                            "userName": "user@example.com",
                            "counter": "3",
                            "discoverable": "true",
                            "creationDate": "2024-01-01T00:00:00Z"
                        },
                        {
                            "credentialId": "cred2",
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            "keyValue": "BQEBgIA",
                            "rpId": "github.com",
                            "rpName": "GitHub",
                            "userName": "user@example.com",
                            "counter": "7",
                            "discoverable": "true",
                            "creationDate": "2024-06-01T00:00:00Z"
                        }
                    ]
                }
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                let fido2 = data.fido2_credentials.as_ref().unwrap();
                assert_eq!(fido2.len(), 2);
                assert_eq!(fido2[0].credential_id, "cred1");
                assert_eq!(fido2[1].credential_id, "cred2");
                assert_ne!(fido2[0].counter, fido2[1].counter);
            }
            _ => panic!("expected Login"),
        }
    }

    // Synthetic throwaway P-256 key (generated for this fixture, not used
    // anywhere). BW stores the credential key pair as base64url PKCS#8 DER
    // in `keyValue`; the DER's scalar is the assertion target.
    const TEST_PKCS8_B64URL: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2UkAd0oqMTcegX2G7JW8NhKKiuWHaA6qAD1LOx86TN6hRANCAATyrNkx0gqTGnqyGb2wB50N03YWwu7Zf8ZavArw8-KLcXgeg7-9j_Yl1X2TR0ZARe-IEmSMGEn0X6HeIMZYR2qx";
    const TEST_SCALAR_HEX: &str =
        "d94900774a2a31371e817d86ec95bc36128a8ae587680eaa003d4b3b1f3a4cde";

    fn passkey_fixture(key_value: Option<&str>) -> String {
        let kv = match key_value {
            Some(v) => format!("\"keyValue\": \"{v}\","),
            None => String::new(),
        };
        format!(
            r#"{{
                "items": [{{
                    "name": "GitHub",
                    "type": 1,
                    "login": {{
                        "username": "user@example.com",
                        "fido2Credentials": [{{
                            "credentialId": "cred1",
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            {kv}
                            "rpId": "github.com",
                            "userName": "user@example.com",
                            "counter": "3",
                            "discoverable": "true",
                            "creationDate": "2024-01-01T00:00:00Z"
                        }}]
                    }}
                }}]
            }}"#
        )
    }

    #[test]
    #[cfg(feature = "passkey-ceremony")]
    fn passkey_import_decodes_private_key_from_key_value() {
        // BW exports carry the credential's private key in keyValue (PKCS#8).
        // It must decode into `private_key` as a private COSE key (the format
        // the ceremony path parses) with `private_key_missing` false.
        use coset::cbor::value::Value;
        use coset::{CborSerializable, Label};

        let result = parse(&passkey_fixture(Some(TEST_PKCS8_B64URL)));
        assert_eq!(result.ciphers.len(), 1, "skips: {:?}", result.errors);
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                let fido2 = data.fido2_credentials.as_ref().unwrap();
                assert_eq!(fido2.len(), 1);
                let pk = &fido2[0];
                assert!(!pk.private_key_missing);
                let cose = coset::CoseKey::from_slice(pk.private_key.as_ref().unwrap())
                    .expect("private_key must parse as a COSE key (ceremony-path format)");

                let expected_d = hex::decode(TEST_SCALAR_HEX).unwrap();
                let mut d = None;
                for (k, v) in &cose.params {
                    if *k == Label::Int(-4) {
                        d = Some(match v {
                            Value::Bytes(b) => b.clone(),
                            other => panic!("d param is not bytes: {other:?}"),
                        });
                    }
                }
                assert_eq!(d.as_deref(), Some(expected_d.as_slice()));
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn passkey_import_malformed_key_value_stays_metadata_only() {
        // Fail closed: garbage in keyValue keeps today's view-only behavior.
        let result = parse(&passkey_fixture(Some("AQCAgIA")));
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                let pk = &data.fido2_credentials.as_ref().unwrap()[0];
                assert!(pk.private_key.is_none());
                assert!(pk.private_key_missing);
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn passkey_import_absent_key_value_stays_metadata_only() {
        let result = parse(&passkey_fixture(None));
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                let pk = &data.fido2_credentials.as_ref().unwrap()[0];
                assert!(pk.private_key.is_none());
                assert!(pk.private_key_missing);
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn login_without_fido2_does_not_embed_credentials() {
        let json = r#"{
            "items": [{
                "name": "Plain Login",
                "type": 1,
                "login": {
                    "username": "user@example.com",
                    "password": "s3cret!"
                }
            }]
        }"#;
        let result = parse(json);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert!(data.fido2_credentials.is_none());
            }
            _ => panic!("expected Login"),
        }
    }
}
