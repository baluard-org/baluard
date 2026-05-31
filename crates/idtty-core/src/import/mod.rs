//! Import/Export module.
//!
//! Parsers for external password manager formats, outputting `CipherInput` for batch-create.
//! Export functions produce BW-compatible JSON/CSV and encrypted JSON.

pub mod bw_json;
pub mod bw_csv;
pub mod chrome_csv;
pub mod firefox_csv;
pub mod lastpass_csv;
pub mod onepassword_1pux;
pub mod onepassword_csv;
pub mod keepass_xml;
pub mod export;

use crate::types::CipherInput;

/// Result of an import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Successfully parsed cipher inputs ready for batch-create.
    pub ciphers: Vec<CipherInput>,
    /// Number of entries skipped due to parse errors.
    pub skipped: usize,
    /// Error messages for skipped entries.
    pub errors: Vec<String>,
    /// Folder name -> list of cipher indices (for formats that support folders).
    pub folder_map: std::collections::HashMap<String, Vec<usize>>,
}

impl ImportResult {
    pub fn new() -> Self {
        Self {
            ciphers: Vec::new(),
            skipped: 0,
            errors: Vec::new(),
            folder_map: std::collections::HashMap::new(),
        }
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
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "bw-json" => Some(Self::BwJson),
            "bw-csv" => Some(Self::BwCsv),
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
