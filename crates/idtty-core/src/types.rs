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

// ── Cipher Input ──

/// Input for creating or updating a cipher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInput {
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
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
}

/// Decrypted cipher data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub id: CipherId,
    pub name: String,
    pub folder_id: Option<Uuid>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub tier: Tier,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Cipher metadata (for listing without decryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherMeta {
    pub id: CipherId,
    pub name: String,
    pub folder_id: Option<Uuid>,
    pub tier: Tier,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub updated_at: u64,
}
