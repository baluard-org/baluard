//! 1Password CSV import parser (lossy fallback).
//!
//! Columns: Title, Url, Username, Password, Notes, Type
//! Login entries only. No folders, no custom fields, no TOTP.

use crate::import::ImportResult;
use crate::types::*;

/// Parse a 1Password CSV export.
pub fn parse(data: &str) -> ImportResult {
    let mut result = ImportResult::new();
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(data.as_bytes());

    let headers: Vec<String> = match reader.headers() {
        Ok(h) => h
            .iter()
            .enumerate()
            .map(|(i, f)| {
                // Windows exports carry a UTF-8 BOM that would break
                // header matching.
                if i == 0 {
                    f.strip_prefix('\u{feff}').unwrap_or(f).to_string()
                } else {
                    f.to_string()
                }
            })
            .collect(),
        Err(e) => {
            result.skip(format!("Invalid CSV headers: {e}"));
            return result;
        }
    };

    let col_title = headers.iter().position(|h| h.eq_ignore_ascii_case("title"));
    let col_url = headers.iter().position(|h| h.eq_ignore_ascii_case("url"));
    let col_username = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("username"));
    let col_password = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("password"));
    let col_notes = headers.iter().position(|h| h.eq_ignore_ascii_case("notes"));
    let col_type = headers.iter().position(|h| h.eq_ignore_ascii_case("type"));
    if !headers.iter().any(|h| h.eq_ignore_ascii_case("url")) {
        result.skip("Not a 1Password CSV: no 'url' column".into());
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
                result.skip(format!("Row {}: {e}", row_num + 2));
                continue;
            }
        };

        let name = get(&record, col_title).unwrap_or_else(|| "Untitled".into());
        let uri = get(&record, col_url);
        let uris = if let Some(u) = uri {
            vec![LoginUri::new(u)]
        } else {
            vec![]
        };

        let entry_type = get(&record, col_type).unwrap_or_default();

        let kind = if entry_type.eq_ignore_ascii_case("login") || entry_type.is_empty() {
            CipherKind::Login(LoginData {
                username: get(&record, col_username),
                password: get(&record, col_password),
                uris,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
            })
        } else {
            // Non-login types become SecureNotes with notes preserved
            CipherKind::SecureNote
        };

        let cipher = CipherInput {
            name,
            folder_id: None,
            collection_id: None,
            kind,
            favorite: false,
            notes: get(&record, col_notes),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        };

        result.add(cipher);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_1password_csv() {
        let csv = r#"Title,Url,Username,Password,Notes,Type
GitHub,https://github.com,user@example.com,s3cret!,My account,Login
My Note,,,,Secret content,Secure Note"#;

        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 2);

        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.uris[0].uri, "https://github.com");
            }
            _ => panic!("expected Login"),
        }

        assert!(matches!(result.ciphers[1].kind, CipherKind::SecureNote));
    }
}
