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

    let col_name = headers.iter().position(|h| h.eq_ignore_ascii_case("name"));
    let col_url = headers.iter().position(|h| h.eq_ignore_ascii_case("url"));
    let col_username = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("username"));
    let col_password = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("password"));
    let col_note = headers.iter().position(|h| h.eq_ignore_ascii_case("note"));
    if !headers.iter().any(|h| h.eq_ignore_ascii_case("url")) {
        result.skip(format!("Not a chrome CSV: no 'url' column"));
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
            collection_id: None,
            kind: CipherKind::Login(LoginData {
                username: get(&record, col_username),
                password: get(&record, col_password),
                uris,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
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
    #[test]
    fn bom_prefixed_headers_still_match() {
        // Windows exports start the header row with a UTF-8 BOM; without
        // stripping it every name/url column missed and rows imported as
        // "Untitled" with no URL.
        let csv = "\u{feff}name,url,username,password\nGitHub,https://github.com,u,p\n";
        let result = parse(&csv);
        assert_eq!(result.ciphers.len(), 1);
        assert_eq!(result.ciphers[0].name, "GitHub");
        match &result.ciphers[0].kind {
            CipherKind::Login(d) => {
                assert_eq!(d.uris[0].uri, "https://github.com");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }
}
