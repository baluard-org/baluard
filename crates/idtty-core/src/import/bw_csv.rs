//! Bitwarden CSV import parser.
//!
//! Lossy: Login entries only. Single URI, no folders, no history, no custom fields.
//! BW CSV columns: type, name, notes, login_uri, login_username, login_password,
//! login_totp, login_uris, field_name, field_value, field_type, custom_fields, folders

use crate::import::ImportResult;
use crate::types::*;

/// Parse a BW CSV export string into cipher inputs.
pub fn parse(data: &str) -> ImportResult {
    let mut result = ImportResult::new();
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(data.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(e) => {
            result.skip(format!("Invalid CSV headers: {e}"));
            return result;
        }
    };

    // Find column indices
    let col_type = headers.iter().position(|h| h == "type");
    let col_name = headers.iter().position(|h| h == "name");
    let col_notes = headers.iter().position(|h| h == "notes");
    let col_uri = headers.iter().position(|h| h == "login_uri");
    let col_username = headers.iter().position(|h| h == "login_username");
    let col_password = headers.iter().position(|h| h == "login_password");
    let col_totp = headers.iter().position(|h| h == "login_totp");
    let col_cardholder = headers.iter().position(|h| h == "card_cardholderName");
    let col_brand = headers.iter().position(|h| h == "card_brand");
    let col_number = headers.iter().position(|h| h == "card_number");
    let col_exp_month = headers.iter().position(|h| h == "card_expMonth");
    let col_exp_year = headers.iter().position(|h| h == "card_expYear");
    let col_cvv = headers.iter().position(|h| h == "card_cvv");

    // Validate key columns exist
    if col_name.is_none() {
        result.skip("Missing 'name' column in CSV header".into());
        return result;
    }

    let get = |record: &csv::StringRecord, idx: Option<usize>| -> Option<String> {
        idx.and_then(|i| record.get(i).map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
    };

    for (row_num, record) in reader.records().enumerate() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                result.skip(format!("Row {}: parse error: {e}", row_num + 2));
                continue;
            }
        };

        let name = get(&record, col_name).unwrap_or_else(|| "Untitled".into());
        let cipher_type: u8 = get(&record, col_type)
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let kind = match cipher_type {
            1 => {
                // Login
                let uri = get(&record, col_uri);
                let uris = if let Some(u) = uri {
                    vec![LoginUri::new(u)]
                } else {
                    vec![]
                };

                CipherKind::Login(LoginData {
                    username: get(&record, col_username),
                    password: get(&record, col_password),
                    uris,
                    totp_uri: get(&record, col_totp),
                    autofill_on_page_load: false,
                    password_revision_date: None,
                })
            }
            2 => CipherKind::SecureNote,
            3 => CipherKind::Card(CardData {
                cardholder_name: get(&record, col_cardholder),
                brand: get(&record, col_brand),
                number: get(&record, col_number),
                exp_month: get(&record, col_exp_month),
                exp_year: get(&record, col_exp_year),
                code: get(&record, col_cvv),
            }),
            // BW CSV doesn't reliably support Identity/SSH Key. Skip gracefully.
            _ => {
                result.skip(format!(
                    "Row {}: unsupported type {}",
                    row_num + 2,
                    cipher_type
                ));
                continue;
            }
        };

        let cipher = CipherInput {
            name,
            folder_id: None,
            kind,
            favorite: false,
            notes: get(&record, col_notes),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            reprompt: false,
        };

        result.add(cipher);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bw_csv_logins() {
        let csv = r#"type,name,notes,login_uri,login_username,login_password,login_totp
1,GitHub,My account,https://github.com,user@example.com,s3cret!,otpauth://totp/test
1,Google,,https://google.com,user@gmail.com,pass123,
2,My Note,Secret content,,,,,"#;

        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 3);
        assert_eq!(result.skipped, 0);

        // Login with TOTP
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris.len(), 1);
                assert_eq!(data.uris[0].uri, "https://github.com");
                assert_eq!(data.totp_uri.as_deref(), Some("otpauth://totp/test"));
            }
            _ => panic!("expected Login"),
        }

        // Login without TOTP
        match &result.ciphers[1].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@gmail.com"));
                assert!(data.totp_uri.is_none());
            }
            _ => panic!("expected Login"),
        }

        // Secure Note
        assert!(matches!(result.ciphers[2].kind, CipherKind::SecureNote));
        assert_eq!(result.ciphers[2].notes.as_deref(), Some("Secret content"));
    }

    #[test]
    fn empty_csv() {
        let csv = "type,name,notes,login_uri,login_username,login_password,login_totp\n";
        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 0);
    }

    #[test]
    fn card_csv() {
        let csv = r#"type,name,notes,card_cardholderName,card_brand,card_number,card_expMonth,card_expYear,card_cvv
3,My Visa,,John Doe,Visa,4111111111111111,12,2026,123"#;
        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 1);
        match &result.ciphers[0].kind {
            CipherKind::Card(data) => {
                assert_eq!(data.cardholder_name.as_deref(), Some("John Doe"));
                assert_eq!(data.number.as_deref(), Some("4111111111111111"));
            }
            _ => panic!("expected Card"),
        }
    }
}
