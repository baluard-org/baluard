//! Core types shared across modules.
//!
//! Canonical type definitions for IDs, key material wrappers, and enums.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Identifiers ──

/// Unique vault identifier, set at creation.
pub type VaultId = Uuid;

/// Unique cipher identifier (random UUID).
pub type CipherId = Uuid;

/// Unique device identifier (random UUID).
pub type DeviceId = Uuid;

/// Unique org identifier.
pub type OrgId = Uuid;

// ── Size Tiers (D8) ──

/// Cipher file size tiers with uniform padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Xs,
    S,
    M,
    L,
    Xl,
}

impl Tier {
    /// Padded size in bytes for this tier.
    pub const fn padded_size(&self) -> usize {
        match self {
            Tier::Xs => 5 * 1024,        // 5 KB
            Tier::S => 30 * 1024,        // 30 KB
            Tier::M => 100 * 1024,       // 100 KB
            Tier::L => 250 * 1024,       // 250 KB
            Tier::Xl => 2 * 1024 * 1024, // 2 MB
        }
    }

    /// Tier code string (used in AAD and filenames).
    pub const fn code(&self) -> &'static str {
        match self {
            Tier::Xs => "xs",
            Tier::S => "s",
            Tier::M => "m",
            Tier::L => "l",
            Tier::Xl => "xl",
        }
    }

    /// Select the smallest tier that fits `content_size` bytes.
    pub fn fit(content_size: usize) -> Option<Self> {
        let tiers = [Tier::Xs, Tier::S, Tier::M, Tier::L, Tier::Xl];
        tiers.into_iter().find(|t| content_size <= t.padded_size())
    }
}

// ── Object Types (for AAD) ──

/// Object type discriminator used in AAD construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Cipher,
    Meta,
    Keywrap,
}

impl ObjectType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Cipher => "cipher",
            ObjectType::Meta => "meta",
            ObjectType::Keywrap => "keywrap",
        }
    }
}

// ── AEAD Envelope ──

/// AEAD envelope header fields (plaintext, outside the encrypted payload).
///
/// Per D3: `{version, alg_id, key_epoch, nonce, aad, ciphertext, tag}`.
/// Header fields are plaintext so the decryptor can select the correct key
/// before opening the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// Envelope format version (currently 1).
    pub version: u8,
    /// AEAD algorithm identifier (0x0001 = AES-256-GCM).
    pub alg_id: u16,
    /// Root Key epoch that encrypted this payload.
    pub key_epoch: u64,
    /// Per-object nonce counter.
    pub nonce_counter: u64,
    /// Monotonic update sequence number (for rollback detection).
    pub update_seq: u64,
    /// Size tier (for cipher objects) or None for non-cipher objects.
    pub tier: Option<Tier>,
}

/// Complete AEAD envelope: header + encrypted payload.
#[derive(Debug, Clone)]
pub struct CipherEnvelope {
    pub header: EnvelopeHeader,
    /// 12-byte nonce (constructed from nonce_counter + object shard).
    pub nonce: [u8; 12],
    /// AAD bytes (SHA256 hash of context-binding fields).
    pub aad: Vec<u8>,
    /// AEAD ciphertext (includes Item Key + cipher content).
    pub ciphertext: Vec<u8>,
    /// 16-byte authentication tag.
    pub tag: [u8; 16],
}

// ── KDF Profiles (D2) ──

/// Argon2id calibration profiles with hard bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfProfile {
    /// Low-end mobile devices.
    MobileLow,
    /// Standard desktop/laptop.
    DesktopStd,
    /// High-end workstation.
    DesktopHigh,
}

impl KdfProfile {
    /// Memory in KiB for this profile.
    pub const fn memory_kib(&self) -> u32 {
        match self {
            KdfProfile::MobileLow => 19 * 1024,    // 19 MB
            KdfProfile::DesktopStd => 64 * 1024,   // 64 MB
            KdfProfile::DesktopHigh => 256 * 1024, // 256 MB
        }
    }

    /// Time cost (iterations).
    pub const fn time_cost(&self) -> u32 {
        match self {
            KdfProfile::MobileLow => 2,
            KdfProfile::DesktopStd => 3,
            KdfProfile::DesktopHigh => 4,
        }
    }

    /// Parallelism (lanes).
    pub const fn parallelism(&self) -> u32 {
        match self {
            KdfProfile::MobileLow => 1,
            KdfProfile::DesktopStd => 2,
            KdfProfile::DesktopHigh => 4,
        }
    }

    /// Target latency range in milliseconds.
    pub const fn latency_range_ms(&self) -> (u32, u32) {
        match self {
            KdfProfile::MobileLow => (300, 500),
            KdfProfile::DesktopStd => (300, 500),
            KdfProfile::DesktopHigh => (500, 800),
        }
    }
}

/// Full KDF parameters (profile + calibrated values within bounds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub profile: KdfProfile,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    /// 256-bit random salt (stored in plaintext vault header).
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl KdfParams {
    /// Create params from a profile with default (lower-bound) values.
    pub fn from_profile(profile: KdfProfile) -> Self {
        Self {
            memory_kib: profile.memory_kib(),
            time_cost: profile.time_cost(),
            parallelism: profile.parallelism(),
            profile,
            salt: Vec::new(), // Caller must set salt
        }
    }
}

// ── Epoch States (doc 03, Section 2) ──
// Defined in keys::epoch::EpochState. Re-exported here for convenience.
pub use crate::keys::epoch::EpochState;

// ── Cipher Types ──

/// URI match strategy for autofill/launch detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum UriMatchStrategy {
    /// Match based on domain (default).
    #[default]
    Domain,
    /// Match exact host.
    Host,
    /// Match if URI starts with the value.
    StartsWith,
    /// Exact match.
    Exact,
    /// Regex match.
    Regex,
    /// Never match.
    Never,
}

impl UriMatchStrategy {
    /// Parse from string with hard error on unknown values.
    pub fn from_str_strict(s: &str) -> Result<Self, String> {
        match s {
            "domain" => Ok(UriMatchStrategy::Domain),
            "host" => Ok(UriMatchStrategy::Host),
            "startsWith" => Ok(UriMatchStrategy::StartsWith),
            "exact" => Ok(UriMatchStrategy::Exact),
            "regex" => Ok(UriMatchStrategy::Regex),
            "never" => Ok(UriMatchStrategy::Never),
            _ => Err(format!("unknown URI match strategy: '{s}'")),
        }
    }
}

/// A single URI with its match strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginUri {
    pub uri: String,
    #[serde(default)]
    pub match_strategy: UriMatchStrategy,
}

impl LoginUri {
    pub fn new(uri: String) -> Self {
        Self {
            uri,
            match_strategy: UriMatchStrategy::default(),
        }
    }
}

/// Cipher type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum CipherType {
    #[default]
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    BankAccount,
    DriversLicense,
    Passport,
}

/// Login-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoginData {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<LoginUri>,
    #[serde(default)]
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub autofill_on_page_load: bool,
    #[serde(default)]
    pub password_revision_date: Option<u64>,
}

/// Card-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CardData {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

/// Identity-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityData {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

/// SSH Key-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshKeyData {
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

/// Bank Account-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BankAccountData {
    #[serde(default)]
    pub bank_name: Option<String>,
    #[serde(default)]
    pub name_on_account: Option<String>,
    #[serde(default)]
    pub account_type: Option<String>,
    #[serde(default)]
    pub account_number: Option<String>,
    #[serde(default)]
    pub routing_number: Option<String>,
    #[serde(default)]
    pub branch_number: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub swift_code: Option<String>,
    #[serde(default)]
    pub iban: Option<String>,
    #[serde(default)]
    pub bank_contact_phone: Option<String>,
}

/// Driver's License-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriversLicenseData {
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub date_of_birth: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
    #[serde(default)]
    pub issuing_country: Option<String>,
    #[serde(default)]
    pub issuing_state: Option<String>,
    #[serde(default)]
    pub issue_date: Option<String>,
    #[serde(default)]
    pub expiration_date: Option<String>,
    #[serde(default)]
    pub issuing_authority: Option<String>,
    #[serde(default)]
    pub license_class: Option<String>,
}

/// Passport-specific cipher data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PassportData {
    #[serde(default)]
    pub surname: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub date_of_birth: Option<String>,
    #[serde(default)]
    pub sex: Option<String>,
    #[serde(default)]
    pub birth_place: Option<String>,
    #[serde(default)]
    pub nationality: Option<String>,
    #[serde(default)]
    pub issuing_country: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub passport_type: Option<String>,
    #[serde(default)]
    pub national_identification_number: Option<String>,
    #[serde(default)]
    pub issuing_authority: Option<String>,
    #[serde(default)]
    pub issue_date: Option<String>,
    #[serde(default)]
    pub expiration_date: Option<String>,
}

/// Country ID-specific cipher data.
/// Type-safe cipher kind. Makes invalid states unrepresentable.
/// Card(LoginData) is a compile error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum CipherKind {
    Login(LoginData),
    SecureNote,
    Card(CardData),
    Identity(IdentityData),
    SshKey(SshKeyData),
    BankAccount(BankAccountData),
    DriversLicense(DriversLicenseData),
    Passport(PassportData),
}

impl CipherKind {
    /// The cipher type discriminator.
    pub fn cipher_type(&self) -> CipherType {
        match self {
            CipherKind::Login(_) => CipherType::Login,
            CipherKind::SecureNote => CipherType::SecureNote,
            CipherKind::Card(_) => CipherType::Card,
            CipherKind::Identity(_) => CipherType::Identity,
            CipherKind::SshKey(_) => CipherType::SshKey,
            CipherKind::BankAccount(_) => CipherType::BankAccount,
            CipherKind::DriversLicense(_) => CipherType::DriversLicense,
            CipherKind::Passport(_) => CipherType::Passport,
        }
    }
}

impl Default for CipherKind {
    fn default() -> Self {
        CipherKind::Login(LoginData::default())
    }
}

// ── Cipher Input ──

/// Input for creating or updating a cipher.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CipherInput {
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub kind: CipherKind,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Preserve original creation time on updates. None = set at creation.
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Password history. Populated by update_cipher on password change.
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Existing attachments (preserved across updates).
    #[serde(default)]
    pub attachments: Vec<crate::vault::attachment::AttachmentMeta>,
    #[serde(default)]
    pub archived: bool,
}

/// Custom field on a cipher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub field_type: CustomFieldType,
}

/// Custom field type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomFieldType {
    Text,
    Hidden,
    Boolean,
    /// Linked field references a built-in field from the cipher.
    /// The value is auto-resolved from the cipher's own data at display time.
    Linked(LinkedFieldType),
}

/// Built-in fields that a linked custom field can reference.
/// Mirrors Bitwarden's linked field IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkedFieldType {
    // Login fields
    LoginUsername,
    LoginPassword,
    // Card fields
    CardCardholderName,
    CardNumber,
    CardExpMonth,
    CardExpYear,
    CardCvv,
    // Identity fields
    IdentityTitle,
    IdentityFirstName,
    IdentityMiddleName,
    IdentityLastName,
    IdentityUsername,
    IdentityCompany,
    IdentityEmail,
    IdentityPhone,
    IdentityAddress1,
    IdentityAddress2,
    IdentityAddress3,
    IdentityCity,
    IdentityState,
    IdentityPostalCode,
    IdentityCountry,

    // Bank Account fields
    BankAccountBankName,
    BankAccountNameOnAccount,
    BankAccountAccountType,
    BankAccountAccountNumber,
    BankAccountRoutingNumber,
    BankAccountBranchNumber,
    BankAccountPin,
    BankAccountSwiftCode,
    BankAccountIban,
    BankAccountBankContactPhone,

    // Driver's License fields
    DriversLicenseFirstName,
    DriversLicenseMiddleName,
    DriversLicenseLastName,
    DriversLicenseDateOfBirth,
    DriversLicenseLicenseNumber,
    DriversLicenseIssuingCountry,
    DriversLicenseIssuingState,
    DriversLicenseIssueDate,
    DriversLicenseExpirationDate,
    DriversLicenseIssuingAuthority,
    DriversLicenseLicenseClass,

    // Passport fields
    PassportSurname,
    PassportGivenName,
    PassportDateOfBirth,
    PassportSex,
    PassportBirthPlace,
    PassportNationality,
    PassportIssuingCountry,
    PassportPassportNumber,
    PassportPassportType,
    PassportNationalIdNumber,
    PassportIssuingAuthority,
    PassportIssueDate,
    PassportExpirationDate,

    // Country ID fields
    // Country ID fields merged into Passport
}

/// A single password history entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordHistoryEntry {
    pub password: String,
    /// Unix timestamp when this password was last used.
    pub last_used_date: u64,
}

/// Backward-compatible cipher data within the encrypted envelope.
///
/// Handles two formats:
/// - **Old (pre-Phase-1)**: flat fields (`username`, `password`, `uris`, etc.)
///   with no `kind` field. Deserialized as Login.
/// - **New**: `kind: CipherKind` with type-specific data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherEnvelopeData {
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub kind: CipherKind,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    // Old flat fields (used only during migration deserialization)
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<crate::vault::attachment::AttachmentMeta>,
    #[serde(default)]
    pub archived: bool,
}

impl CipherEnvelopeData {
    /// Migrate from flat format to typed CipherKind after deserialization.
    /// If `kind` is the default (Login with empty data) but flat fields are
    /// present, populate LoginData from the flat fields.
    pub fn migrate(mut self) -> Self {
        // Only migrate if kind is the default (empty Login) AND flat fields exist
        match &self.kind {
            CipherKind::Login(data)
                if data.username.is_none()
                    && data.password.is_none()
                    && data.uris.is_empty()
                    && data.totp_uri.is_none()
                    && (self.username.is_some()
                        || self.password.is_some()
                        || !self.uris.is_empty()
                        || self.totp_uri.is_some()) =>
            {
                self.kind = CipherKind::Login(LoginData {
                    username: self.username.take(),
                    password: self.password.take(),
                    uris: std::mem::take(&mut self.uris)
                        .into_iter()
                        .map(LoginUri::new)
                        .collect(),
                    totp_uri: self.totp_uri.take(),
                    autofill_on_page_load: false,
                    password_revision_date: None,
                });
            }
            _ => {
                // kind is already set to non-default or Login with data;
                // nothing to migrate.
            }
        }
        self
    }
}

/// Decrypted cipher data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub id: CipherId,
    pub name: String,
    pub folder_id: Option<Uuid>,
    pub kind: CipherKind,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub tier: Tier,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<crate::vault::attachment::AttachmentMeta>,
    #[serde(default)]
    pub archived: bool,
}

/// Cipher metadata (for listing without decryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherMeta {
    pub id: CipherId,
    pub name: String,
    pub folder_id: Option<Uuid>,
    pub cipher_type: CipherType,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    pub username: Option<String>,
    pub tier: Tier,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub archived: bool,
}

/// Resolve a linked field's value from a cipher's data.
pub fn resolve_linked_field(cipher: &Cipher, field: &LinkedFieldType) -> Option<String> {
    match (&cipher.kind, field) {
        // Login fields
        (CipherKind::Login(data), LinkedFieldType::LoginUsername) => data.username.clone(),
        (CipherKind::Login(data), LinkedFieldType::LoginPassword) => data.password.clone(),

        // Card fields
        (CipherKind::Card(data), LinkedFieldType::CardCardholderName) => {
            data.cardholder_name.clone()
        }
        (CipherKind::Card(data), LinkedFieldType::CardNumber) => data.number.clone(),
        (CipherKind::Card(data), LinkedFieldType::CardExpMonth) => data.exp_month.clone(),
        (CipherKind::Card(data), LinkedFieldType::CardExpYear) => data.exp_year.clone(),
        (CipherKind::Card(data), LinkedFieldType::CardCvv) => data.code.clone(),

        // Identity fields
        (CipherKind::Identity(data), LinkedFieldType::IdentityTitle) => data.title.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityFirstName) => data.first_name.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityMiddleName) => {
            data.middle_name.clone()
        }
        (CipherKind::Identity(data), LinkedFieldType::IdentityLastName) => data.last_name.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityUsername) => data.username.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityCompany) => data.company.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityEmail) => data.email.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityPhone) => data.phone.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityAddress1) => data.address1.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityAddress2) => data.address2.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityAddress3) => data.address3.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityCity) => data.city.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityState) => data.state.clone(),
        (CipherKind::Identity(data), LinkedFieldType::IdentityPostalCode) => {
            data.postal_code.clone()
        }
        (CipherKind::Identity(data), LinkedFieldType::IdentityCountry) => data.country.clone(),

        // Bank Account fields
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountBankName) => {
            data.bank_name.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountNameOnAccount) => {
            data.name_on_account.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountAccountType) => {
            data.account_type.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountAccountNumber) => {
            data.account_number.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountRoutingNumber) => {
            data.routing_number.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountBranchNumber) => {
            data.branch_number.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountPin) => {
            data.pin.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountSwiftCode) => {
            data.swift_code.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountIban) => {
            data.iban.clone()
        }
        (CipherKind::BankAccount(data), LinkedFieldType::BankAccountBankContactPhone) => {
            data.bank_contact_phone.clone()
        }

        // Driver's License fields
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseFirstName) => {
            data.first_name.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseMiddleName) => {
            data.middle_name.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseLastName) => {
            data.last_name.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseDateOfBirth) => {
            data.date_of_birth.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseLicenseNumber) => {
            data.license_number.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseIssuingCountry) => {
            data.issuing_country.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseIssuingState) => {
            data.issuing_state.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseIssueDate) => {
            data.issue_date.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseExpirationDate) => {
            data.expiration_date.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseIssuingAuthority) => {
            data.issuing_authority.clone()
        }
        (CipherKind::DriversLicense(data), LinkedFieldType::DriversLicenseLicenseClass) => {
            data.license_class.clone()
        }

        // Passport fields
        (CipherKind::Passport(data), LinkedFieldType::PassportSurname) => {
            data.surname.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportGivenName) => {
            data.given_name.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportDateOfBirth) => {
            data.date_of_birth.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportSex) => {
            data.sex.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportBirthPlace) => {
            data.birth_place.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportNationality) => {
            data.nationality.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportIssuingCountry) => {
            data.issuing_country.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportPassportNumber) => {
            data.passport_number.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportPassportType) => {
            data.passport_type.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportNationalIdNumber) => {
            data.national_identification_number.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportIssuingAuthority) => {
            data.issuing_authority.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportIssueDate) => {
            data.issue_date.clone()
        }
        (CipherKind::Passport(data), LinkedFieldType::PassportExpirationDate) => {
            data.expiration_date.clone()
        }

        // Country ID fields
        // Type mismatch: field doesn't match cipher kind
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_type_default_is_login() {
        assert_eq!(CipherType::default(), CipherType::Login);
    }

    #[test]
    fn cipher_kind_default_is_login() {
        assert!(matches!(CipherKind::default(), CipherKind::Login(_)));
    }

    #[test]
    fn each_cipher_type_serializes_deserializes() {
        // Login
        let login = CipherKind::Login(LoginData {
            username: Some("user@test.com".into()),
            password: Some("s3cret".into()),
            uris: vec![LoginUri::new("https://example.com".into())],
            totp_uri: None,
            autofill_on_page_load: true,
            password_revision_date: Some(1234567890),
        });
        let json = serde_json::to_string(&login).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        assert_eq!(login.cipher_type(), back.cipher_type());
        match back {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@test.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret"));
                assert_eq!(data.uris.len(), 1);
                assert_eq!(data.uris[0].uri, "https://example.com");
                assert_eq!(data.uris[0].match_strategy, UriMatchStrategy::Domain);
                assert!(data.autofill_on_page_load);
                assert_eq!(data.password_revision_date, Some(1234567890));
            }
            _ => panic!("expected Login"),
        }

        // SecureNote
        let note = CipherKind::SecureNote;
        let json = serde_json::to_string(&note).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cipher_type(), CipherType::SecureNote);

        // Card
        let card = CipherKind::Card(CardData {
            cardholder_name: Some("John Doe".into()),
            brand: Some("Visa".into()),
            number: Some("4111111111111111".into()),
            exp_month: Some("12".into()),
            exp_year: Some("2026".into()),
            code: Some("123".into()),
        });
        let json = serde_json::to_string(&card).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::Card(data) => {
                assert_eq!(data.cardholder_name.as_deref(), Some("John Doe"));
                assert_eq!(data.brand.as_deref(), Some("Visa"));
                assert_eq!(data.number.as_deref(), Some("4111111111111111"));
                assert_eq!(data.exp_month.as_deref(), Some("12"));
                assert_eq!(data.exp_year.as_deref(), Some("2026"));
                assert_eq!(data.code.as_deref(), Some("123"));
            }
            _ => panic!("expected Card"),
        }

        // Identity
        let identity = CipherKind::Identity(IdentityData {
            title: Some("Mr".into()),
            first_name: Some("John".into()),
            middle_name: None,
            last_name: Some("Doe".into()),
            username: Some("jdoe".into()),
            company: Some("Acme".into()),
            email: Some("john@acme.com".into()),
            phone: Some("555-1234".into()),
            address1: Some("123 Main St".into()),
            address2: None,
            address3: None,
            city: Some("Springfield".into()),
            state: Some("IL".into()),
            postal_code: Some("62701".into()),
            country: Some("US".into()),
            ssn: Some("123-45-6789".into()),
            passport_number: None,
            license_number: None,
        });
        let json = serde_json::to_string(&identity).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::Identity(data) => {
                assert_eq!(data.first_name.as_deref(), Some("John"));
                assert_eq!(data.last_name.as_deref(), Some("Doe"));
                assert_eq!(data.address1.as_deref(), Some("123 Main St"));
                assert_eq!(data.address2, None);
                assert_eq!(data.address3, None);
            }
            _ => panic!("expected Identity"),
        }

        // SSH Key
        let ssh = CipherKind::SshKey(SshKeyData {
            private_key: Some("-----BEGIN PRIVATE KEY-----".into()),
            public_key: Some("ssh-rsa AAAA".into()),
            key_fingerprint: Some("SHA256:abc123".into()),
        });
        let json = serde_json::to_string(&ssh).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::SshKey(data) => {
                assert_eq!(data.public_key.as_deref(), Some("ssh-rsa AAAA"));
                assert_eq!(data.key_fingerprint.as_deref(), Some("SHA256:abc123"));
            }
            _ => panic!("expected SshKey"),
        }

        // Bank Account
        let bank = CipherKind::BankAccount(BankAccountData {
            bank_name: Some("Chase".into()),
            account_number: Some("123456789".into()),
            routing_number: Some("987654321".into()),
            ..Default::default()
        });
        let json = serde_json::to_string(&bank).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::BankAccount(data) => {
                assert_eq!(data.bank_name.as_deref(), Some("Chase"));
                assert_eq!(data.account_number.as_deref(), Some("123456789"));
                assert_eq!(data.routing_number.as_deref(), Some("987654321"));
            }
            _ => panic!("expected BankAccount"),
        }

        // Driver's License
        let dl = CipherKind::DriversLicense(DriversLicenseData {
            first_name: Some("Jane".into()),
            license_number: Some("D55555".into()),
            ..Default::default()
        });
        let json = serde_json::to_string(&dl).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::DriversLicense(data) => {
                assert_eq!(data.first_name.as_deref(), Some("Jane"));
                assert_eq!(data.license_number.as_deref(), Some("D55555"));
            }
            _ => panic!("expected DriversLicense"),
        }

        // Passport
        let passport = CipherKind::Passport(PassportData {
            surname: Some("Smith".into()),
            passport_number: Some("P12345".into()),
            ..Default::default()
        });
        let json = serde_json::to_string(&passport).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::Passport(data) => {
                assert_eq!(data.surname.as_deref(), Some("Smith"));
                assert_eq!(data.passport_number.as_deref(), Some("P12345"));
            }
            _ => panic!("expected Passport"),
        }
    }

    #[test]
    fn migration_old_flat_format_to_login() {
        // Simulate old pre-Phase-1 cipher data (flat fields, no "kind")
        let old_json = r#"{
            "name": "GitHub",
            "username": "user@example.com",
            "password": "s3cret!",
            "uris": ["https://github.com", "https://api.github.com"],
            "notes": "My GitHub account",
            "totp_uri": "otpauth://totp/test",
            "custom_fields": [],
            "created_at": 1000000,
            "updated_at": 2000000
        }"#;

        let env_data: CipherEnvelopeData = serde_json::from_str(old_json).unwrap();
        let migrated = env_data.migrate();

        assert_eq!(migrated.name, "GitHub");
        match &migrated.kind {
            CipherKind::Login(data) => {
                assert_eq!(data.username.as_deref(), Some("user@example.com"));
                assert_eq!(data.password.as_deref(), Some("s3cret!"));
                assert_eq!(data.uris.len(), 2);
                assert_eq!(data.uris[0].uri, "https://github.com");
                assert_eq!(data.uris[0].match_strategy, UriMatchStrategy::Domain);
                assert_eq!(data.uris[1].uri, "https://api.github.com");
                assert_eq!(data.uris[1].match_strategy, UriMatchStrategy::Domain);
                assert_eq!(data.totp_uri.as_deref(), Some("otpauth://totp/test"));
            }
            _ => panic!("expected Login kind after migration"),
        }
        assert_eq!(migrated.notes.as_deref(), Some("My GitHub account"));
        assert_eq!(migrated.created_at, 1000000);
    }

    #[test]
    fn migration_no_op_when_kind_already_set() {
        // New format with kind already set should not be overwritten
        let new_json = r#"{
            "name": "My Card",
            "kind": {"type": "card", "data": {"brand": "Visa", "number": "4111111111111111"}},
            "notes": null,
            "totp_uri": null,
            "custom_fields": [],
            "username": null,
            "password": null,
            "uris": [],
            "created_at": 1000000,
            "updated_at": 2000000
        }"#;

        let env_data: CipherEnvelopeData = serde_json::from_str(new_json).unwrap();
        let migrated = env_data.migrate();

        assert_eq!(migrated.name, "My Card");
        match &migrated.kind {
            CipherKind::Card(data) => {
                assert_eq!(data.brand.as_deref(), Some("Visa"));
            }
            _ => panic!("expected Card kind"),
        }
        // Flat fields should remain as-is (not migrated into LoginData)
        assert!(migrated.username.is_none());
    }

    #[test]
    fn cipher_input_default_is_login() {
        let input = CipherInput {
            name: "test".into(),
            ..Default::default()
        };
        // Verify default kind is Login
        assert!(matches!(input.kind, CipherKind::Login(_)));
    }

    #[test]
    fn migration_only_totp_uri() {
        // Old cipher with ONLY totp_uri set (no username/password/uris)
        let old_json = r#"{
            "name": "GitHub",
            "username": null,
            "password": null,
            "uris": [],
            "totp_uri": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP",
            "notes": null,
            "custom_fields": [],
            "created_at": 1000000,
            "updated_at": 2000000
        }"#;

        let env_data: CipherEnvelopeData = serde_json::from_str(old_json).unwrap();
        let migrated = env_data.migrate();

        match &migrated.kind {
            CipherKind::Login(data) => {
                assert_eq!(
                    data.totp_uri.as_deref(),
                    Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP")
                );
                assert!(data.username.is_none());
                assert!(data.password.is_none());
                assert!(data.uris.is_empty());
            }
            _ => panic!("expected Login kind after migration"),
        }
    }

    #[test]
    fn multi_uri_order_preserved() {
        // 3 URIs in specific order
        let uris = vec![
            LoginUri::new("https://github.com".into()),
            LoginUri {
                uri: "https://api.github.com".into(),
                match_strategy: UriMatchStrategy::Host,
            },
            LoginUri::new("https://gist.github.com".into()),
        ];
        let login = CipherKind::Login(LoginData {
            uris: uris.clone(),
            ..Default::default()
        });
        let json = serde_json::to_string(&login).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::Login(data) => {
                assert_eq!(data.uris.len(), 3);
                assert_eq!(data.uris[0].uri, "https://github.com");
                assert_eq!(data.uris[1].uri, "https://api.github.com");
                assert_eq!(data.uris[1].match_strategy, UriMatchStrategy::Host);
                assert_eq!(data.uris[2].uri, "https://gist.github.com");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn match_strategy_round_trip() {
        let login = CipherKind::Login(LoginData {
            uris: vec![LoginUri {
                uri: "https://example.com".into(),
                match_strategy: UriMatchStrategy::Exact,
            }],
            ..Default::default()
        });
        let json = serde_json::to_string(&login).unwrap();
        let back: CipherKind = serde_json::from_str(&json).unwrap();
        match back {
            CipherKind::Login(data) => {
                assert_eq!(data.uris[0].match_strategy, UriMatchStrategy::Exact);
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn migration_flat_uris_to_login_uri() {
        let old_json = r#"{
            "name": "Test",
            "uris": ["a.com", "b.com"],
            "notes": null,
            "custom_fields": [],
            "created_at": 1,
            "updated_at": 2
        }"#;
        let env: CipherEnvelopeData = serde_json::from_str(old_json).unwrap();
        let migrated = env.migrate();
        match &migrated.kind {
            CipherKind::Login(data) => {
                assert_eq!(data.uris.len(), 2);
                assert_eq!(data.uris[0].uri, "a.com");
                assert_eq!(data.uris[0].match_strategy, UriMatchStrategy::Domain);
                assert_eq!(data.uris[1].uri, "b.com");
                assert_eq!(data.uris[1].match_strategy, UriMatchStrategy::Domain);
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn uri_match_strategy_typo_is_hard_error() {
        let json = r#"{"default_uri_match": "exakt"}"#;
        let result: Result<serde_json::Value, _> = serde_json::from_str(json);
        // The string itself parses as JSON, but from_str_strict should fail
        let val = result.unwrap();
        let s = val["default_uri_match"].as_str().unwrap();
        assert!(UriMatchStrategy::from_str_strict(s).is_err());
    }

    #[test]
    fn uri_match_strategy_all_variants_round_trip() {
        let strategies = vec![
            UriMatchStrategy::Domain,
            UriMatchStrategy::Host,
            UriMatchStrategy::StartsWith,
            UriMatchStrategy::Exact,
            UriMatchStrategy::Regex,
            UriMatchStrategy::Never,
        ];
        for strategy in strategies {
            let uri = LoginUri {
                uri: "https://test.com".into(),
                match_strategy: strategy,
            };
            let json = serde_json::to_string(&uri).unwrap();
            let back: LoginUri = serde_json::from_str(&json).unwrap();
            assert_eq!(back.match_strategy, strategy);
        }
    }

    fn make_cipher(kind: CipherKind) -> Cipher {
        Cipher {
            id: Uuid::new_v4(),
            name: "Test".into(),
            folder_id: None,
            kind,
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            key_epoch: 1,
            update_seq: 1,
            tier: Tier::Xs,
            created_at: 0,
            updated_at: 0,
            password_history: vec![],
            attachments: vec![],
            archived: false,
        }
    }

    #[test]
    fn resolve_linked_field_bank_account() {
        let cipher = make_cipher(CipherKind::BankAccount(BankAccountData {
            bank_name: Some("Chase".into()),
            account_number: Some("123456789".into()),
            pin: Some("9999".into()),
            ..Default::default()
        }));
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::BankAccountBankName),
            Some("Chase".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::BankAccountAccountNumber),
            Some("123456789".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::BankAccountPin),
            Some("9999".into())
        );
        // Empty field returns None
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::BankAccountIban),
            None
        );
        // Cross-type mismatch returns None
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::LoginUsername),
            None
        );
    }

    #[test]
    fn resolve_linked_field_drivers_license() {
        let cipher = make_cipher(CipherKind::DriversLicense(DriversLicenseData {
            first_name: Some("Jane".into()),
            license_number: Some("D55555".into()),
            issuing_state: Some("CA".into()),
            ..Default::default()
        }));
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::DriversLicenseFirstName),
            Some("Jane".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::DriversLicenseLicenseNumber),
            Some("D55555".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::DriversLicenseIssuingState),
            Some("CA".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::DriversLicenseDateOfBirth),
            None
        );
    }

    #[test]
    fn resolve_linked_field_passport() {
        let cipher = make_cipher(CipherKind::Passport(PassportData {
            surname: Some("Smith".into()),
            passport_number: Some("P12345".into()),
            nationality: Some("US".into()),
            ..Default::default()
        }));
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::PassportSurname),
            Some("Smith".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::PassportPassportNumber),
            Some("P12345".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::PassportNationality),
            Some("US".into())
        );
        assert_eq!(
            resolve_linked_field(&cipher, &LinkedFieldType::PassportSex),
            None
        );
    }
}
