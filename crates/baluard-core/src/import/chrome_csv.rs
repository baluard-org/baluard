//! Chrome CSV import parser.
//!
//! Columns: name, url, username, password, note
//! All entries become Login ciphers.

use crate::import::ImportResult;
use crate::types::*;

/// Parse a Chrome CSV export.
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

    let col_name = headers.iter().position(|h| h == "name");
    let col_url = headers.iter().position(|h| h == "url");
    let col_username = headers.iter().position(|h| h == "username");
    let col_password = headers.iter().position(|h| h == "password");
    let col_note = headers.iter().position(|h| h == "note");

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

        let name = get(&record, col_name).unwrap_or_else(|| "Untitled".into());
        let uri = get(&record, col_url);
        let uris = if let Some(u) = uri {
            vec![LoginUri::new(u)]
        } else {
            vec![]
        };

        let cipher = CipherInput {
            name,
            folder_id: None,
            kind: CipherKind::Login(LoginData {
                username: get(&record, col_username),
                password: get(&record, col_password),
                uris,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
            }),
            favorite: false,
            notes: get(&record, col_note),
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
    fn parse_chrome_csv() {
        let csv = r#"name,url,username,password,note
GitHub,https://github.com,user@example.com,s3cret!,My account
Google,https://google.com,user@gmail.com,pass123,"#;

        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 2);

        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris[0].uri, "https://github.com");
            }
            _ => panic!("expected Login"),
        }
    }
}
