//! Firefox CSV import parser.
//!
//! Columns: url, username, password, httpRealm, formActionOrigin, guid, timeCreated, timeLastUsed, timePasswordChanged
//! Same shape as Chrome: url + username + password. All entries become Login ciphers.

use crate::import::ImportResult;
use crate::types::*;

/// Parse a Firefox CSV export.
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

    // Firefox column names
    let col_url = headers.iter().position(|h| h == "url");
    let col_username = headers.iter().position(|h| h == "username");
    let col_password = headers.iter().position(|h| h == "password");
    let col_name = headers
        .iter()
        .position(|h| h == "name")
        .or_else(|| headers.iter().position(|h| h == "title")); // Fallback if title column exists
    let col_http_realm = headers.iter().position(|h| h == "httpRealm");

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

        let url = get(&record, col_url);
        // Name: use explicit name column, or derive from URL hostname
        let name = get(&record, col_name)
            .or_else(|| {
                url.as_ref().and_then(|u| {
                    u.strip_prefix("https://")
                        .or_else(|| u.strip_prefix("http://"))
                        .and_then(|s| s.split('/').next())
                        .map(|s| s.to_string())
                })
            })
            .unwrap_or_else(|| "Untitled".into());

        let uris = if let Some(ref u) = url {
            vec![LoginUri::new(u.clone())]
        } else {
            vec![]
        };

        // If no URL but has httpRealm, note it
        let notes = if url.is_none() {
            get(&record, col_http_realm).map(|r| format!("HTTP Realm: {r}"))
        } else {
            None
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
            notes,
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
    fn parse_firefox_csv() {
        let csv = r#"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
https://github.com,user@example.com,s3cret!,,,"guid-1",1700000000,1700001000,1700000500
https://google.com,user@gmail.com,pass123,,,"guid-2",1700000000,1700002000,1700000600"#;

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

        // Name derived from URL
        assert_eq!(result.ciphers[0].name, "github.com");
        assert_eq!(result.ciphers[1].name, "google.com");
    }

    #[test]
    fn firefox_http_realm_fallback() {
        let csv = r#"url,username,password,httpRealm
,admin,router-pass,Router Admin"#;

        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 1);
        assert_eq!(result.ciphers[0].name, "Untitled");
        assert_eq!(
            result.ciphers[0].notes.as_deref(),
            Some("HTTP Realm: Router Admin")
        );
    }
}
