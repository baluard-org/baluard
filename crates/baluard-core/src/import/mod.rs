//! Import/Export module.
//!
//! Parsers for external password manager formats, outputting `CipherInput` for batch-create.
//! Export functions produce BW-compatible JSON/CSV and encrypted JSON.

pub mod backup_container;
pub mod baluard_json;
pub mod bw_csv;
pub mod bw_json;
pub mod chrome_csv;
pub mod export;
pub mod firefox_csv;
pub mod keepass_xml;
pub mod lastpass_csv;
pub mod onepassword_1pux;
pub mod onepassword_csv;

use crate::types::CipherInput;

/// A folder to create on import. The parent is an index into the same
/// `folders` Vec, and parents always precede children (the hierarchy-
/// carrying parser guarantees it; cycles degrade to roots). Flat parsers
/// leave `ImportResult::folders` empty and use `folder_map` instead.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportFolder {
    pub name: String,
    pub parent: Option<usize>,
}

/// Result of an import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportResult {
    /// Successfully parsed cipher inputs ready for batch-create.
    pub ciphers: Vec<CipherInput>,
    /// Number of entries skipped due to parse errors.
    pub skipped: usize,
    /// Error messages for skipped entries.
    pub errors: Vec<String>,
    /// Folder name -> list of cipher indices (for formats that support folders).
    pub folder_map: std::collections::HashMap<String, Vec<usize>>,
    /// Full folder tree for hierarchy-carrying formats (baluard.vault).
    pub folders: Vec<ImportFolder>,
    /// Source-folder index per cipher, parallel to `ciphers`.
    pub cipher_folders: Vec<Option<usize>>,
}

impl ImportResult {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a successfully parsed cipher.
    pub fn add(&mut self, cipher: CipherInput) {
        self.ciphers.push(cipher);
    }

    /// Add a cipher with an optional folder assignment.
    pub fn add_with_folder(&mut self, cipher: CipherInput, folder: Option<String>) {
        let idx = self.ciphers.len();
        self.ciphers.push(cipher);
        if let Some(folder_name) = folder {
            self.folder_map.entry(folder_name).or_default().push(idx);
        }
    }

    /// Record a skipped entry.
    pub fn skip(&mut self, error: String) {
        self.skipped += 1;
        self.errors.push(error);
    }
}

/// Supported import formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    BaluardEncrypted,
    BaluardJson,
    BwJson,
    BwCsv,
    ChromeCsv,
    FirefoxCsv,
    LastPassCsv,
    OnePassword1pux,
    OnePasswordCsv,
    KeePassXml,
}

impl ImportFormat {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "baluard-encrypted" | "bldbak" => Some(Self::BaluardEncrypted),
            "baluard" | "baluard-json" | "baluard-backup" | "baluard.vault" => {
                Some(Self::BaluardJson)
            }
            "bw-json" | "bitwarden" | "bitwarden-json" => Some(Self::BwJson),
            "bw-csv" | "bitwarden-csv" => Some(Self::BwCsv),
            "chrome-csv" | "chrome" => Some(Self::ChromeCsv),
            "firefox-csv" | "firefox" => Some(Self::FirefoxCsv),
            "lastpass-csv" | "lastpass" => Some(Self::LastPassCsv),
            "1password-1pux" | "1pux" => Some(Self::OnePassword1pux),
            "1password-csv" | "1password" => Some(Self::OnePasswordCsv),
            "keepass-xml" | "keepass" => Some(Self::KeePassXml),
            _ => None,
        }
    }

    /// All supported format names for CLI help.
    pub fn all_names() -> &'static [&'static str] {
        &[
            "baluard-encrypted",
            "baluard",
            "bw-json",
            "bw-csv",
            "chrome-csv",
            "firefox-csv",
            "lastpass-csv",
            "1password-1pux",
            "1password-csv",
            "keepass-xml",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_full_names_resolve() {
        assert_eq!(
            ImportFormat::from_name("bitwarden"),
            Some(ImportFormat::BwJson)
        );
        assert_eq!(
            ImportFormat::from_name("bitwarden-json"),
            Some(ImportFormat::BwJson)
        );
        assert_eq!(
            ImportFormat::from_name("bitwarden-csv"),
            Some(ImportFormat::BwCsv)
        );
    }
}
