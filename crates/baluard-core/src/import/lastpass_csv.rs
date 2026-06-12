//! LastPass CSV import parser.
//!
//! Columns: url, username, password, name, grouping, extra, fav, id
//! grouping -> folder, extra -> notes. All entries become Login ciphers.

use crate::import::ImportResult;
use crate::types::*;

/// Parse a LastPass CSV export.
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

    let col_url = headers.iter().position(|h| h == "url");
    let col_username = headers.iter().position(|h| h == "username");
    let col_password = headers.iter().position(|h| h == "password");
    let col_name = headers.iter().position(|h| h == "name");
    let col_grouping = headers.iter().position(|h| h == "grouping");
    let col_extra = headers.iter().position(|h| h == "extra");
    let col_fav = headers.iter().position(|h| h == "fav");

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
        let folder = get(&record, col_grouping);
        let favorite = col_fav
            .and_then(|i| record.get(i))
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

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
            favorite,
            notes: get(&record, col_extra),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        };

        result.add_with_folder(cipher, folder);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lastpass_csv() {
        let csv = r#"url,username,password,name,grouping,extra,fav
https://github.com,user@example.com,s3cret!,GitHub,Work,My GH account,1
https://google.com,user@gmail.com,pass123,Google,Personal,,"#;

        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.skipped, 0);

        // GitHub with folder
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.uris[0].uri, "https://github.com");
            }
            _ => panic!("expected Login"),
        }
        assert!(result.ciphers[0].favorite);
        assert!(result.folder_map.contains_key("Work"));

        // Google in Personal folder
        assert!(result.folder_map.contains_key("Personal"));
    }

    #[test]
    fn lastpass_no_folder() {
        let csv = r#"url,username,password,name,grouping,extra
https://example.com,user,pass,Example,,,,"#;
        let result = parse(csv);
        assert_eq!(result.ciphers.len(), 1);
        assert!(result.folder_map.is_empty());
    }
}
