//! KeePass XML import parser.
//!
//! Parses KeePass 2.x XML export format.
//! Entry fields: Title, UserName, Password, URL, Notes, custom string fields.

use crate::import::ImportResult;
use crate::types::*;

/// Parse a KeePass XML export.
pub fn parse(data: &str) -> ImportResult {
    let mut result = ImportResult::new();

    let doc = match roxmltree::Document::parse(data) {
        Ok(d) => d,
        Err(e) => {
            result.skip(format!("Invalid XML: {e}"));
            return result;
        }
    };

    // Find all Entry elements (may be under Root > Group recursively)
    for entry in doc.descendants().filter(|n| n.has_tag_name("Entry")) {
        let mut title = None;
        let mut username = None;
        let mut password = None;
        let mut url = None;
        let mut notes = None;
        let mut custom_fields: Vec<(String, String)> = Vec::new();

        // Each field is a KeyValue pair: <Key>FieldName</Key><Value protectInMemory="true">fieldValue</Value>
        for string_field in entry.children().filter(|n| n.has_tag_name("String")) {
            let key_node = string_field.children().find(|n| n.has_tag_name("Key"));
            let value_node = string_field.children().find(|n| n.has_tag_name("Value"));

            let key_text = key_node.and_then(|n| n.text()).unwrap_or("");
            let val_text = value_node.and_then(|n| n.text()).unwrap_or("");

            match key_text {
                "Title" => title = Some(val_text.to_string()),
                "UserName" => username = Some(val_text.to_string()),
                "Password" => password = Some(val_text.to_string()),
                "URL" => url = Some(val_text.to_string()),
                "Notes" => notes = Some(val_text.to_string()),
                _ => {
                    // Custom string fields
                    if !key_text.is_empty() && !val_text.is_empty() {
                        custom_fields.push((key_text.to_string(), val_text.to_string()));
                    }
                }
            }
        }

        let name = title.unwrap_or_else(|| "Untitled".into());
        let uris = if let Some(ref u) = url {
            vec![LoginUri::new(u.clone())]
        } else {
            vec![]
        };

        let has_credentials = username.is_some() || password.is_some();

        let custom = custom_fields
            .into_iter()
            .map(|(name, value)| CustomField {
                name,
                value,
                field_type: CustomFieldType::Text,
            })
            .collect();

        let kind = if has_credentials {
            CipherKind::Login(LoginData {
                username,
                password,
                uris,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            })
        } else {
            // Entries without username/password become SecureNotes
            // Move URL into notes if present
            let mut combined_notes = notes.take().unwrap_or_default();
            if let Some(ref u) = url {
                if !combined_notes.is_empty() {
                    combined_notes.push('\n');
                }
                combined_notes.push_str("URL: ");
                combined_notes.push_str(u);
            }
            notes = Some(combined_notes);
            CipherKind::SecureNote
        };

        let cipher = CipherInput {
            name,
            folder_id: None,
            kind,
            favorite: false,
            notes: if has_credentials { notes } else { None },
            custom_fields: custom,
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
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
    fn parse_keepass_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
    <Root>
        <Group>
            <Name>General</Name>
            <Entry>
                <String>
                    <Key>Title</Key>
                    <Value>GitHub</Value>
                </String>
                <String>
                    <Key>UserName</Key>
                    <Value>user@example.com</Value>
                </String>
                <String>
                    <Key>Password</Key>
                    <Value>s3cret!</Value>
                </String>
                <String>
                    <Key>URL</Key>
                    <Value>https://github.com</Value>
                </String>
                <String>
                    <Key>Notes</Key>
                    <Value>My GitHub account</Value>
                </String>
                <String>
                    <Key>API Key</Key>
                    <Value>key123</Value>
                </String>
            </Entry>
            <Entry>
                <String>
                    <Key>Title</Key>
                    <Value>No URL Entry</Value>
                </String>
                <String>
                    <Key>UserName</Key>
                    <Value>admin</Value>
                </String>
                <String>
                    <Key>Password</Key>
                    <Value>pass</Value>
                </String>
            </Entry>
        </Group>
    </Root>
</KeePassFile>"#;

        let result = parse(xml);
        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.skipped, 0);

        // Entry with all fields + custom field
        match &result.ciphers[0].kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris[0].uri, "https://github.com");
            }
            _ => panic!("expected Login"),
        }
        assert_eq!(result.ciphers[0].name, "GitHub");
        assert_eq!(
            result.ciphers[0].notes.as_deref(),
            Some("My GitHub account")
        );
        assert_eq!(result.ciphers[0].custom_fields.len(), 1);
        assert_eq!(result.ciphers[0].custom_fields[0].name, "API Key");
        assert_eq!(result.ciphers[0].custom_fields[0].value, "key123");

        // Entry without URL
        match &result.ciphers[1].kind {
            CipherKind::Login(data) => {
                assert!(data.uris.is_empty());
                assert_eq!(data.username.as_deref(), Some("admin"));
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn empty_xml() {
        let xml = r#"<?xml version="1.0"?><KeePassFile><Root><Group><Name>Empty</Name></Group></Root></KeePassFile>"#;
        let result = parse(xml);
        assert_eq!(result.ciphers.len(), 0);
    }

    #[test]
    fn invalid_xml() {
        let result = parse("not xml");
        assert_eq!(result.skipped, 1);
    }
}
