//! Manifest: hybrid filename-based cipher list + encrypted metadata files.
//!
//! D6: Cipher list from filenames in ciphers/. Encrypted meta files for structure.
//! Meta files: folders.json, settings.json, trash.enc, devices.enc, device-pks (plaintext).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::DeviceId;

/// Vault auto-lock policy (chosen from the desktop dropdown preset list).
///
/// A single choice from a preset list (see the desktop dropdown). The wire
/// form is a lowercase string token so the frontend deals with one scalar:
/// - `"immediately"`  -> lock the moment the app loses focus (blur/minimize)
/// - `"1m"`..`"4h"`  -> lock after N minutes of daemon inactivity
/// - `"on_app_exit"` -> no idle lock; the vault locks when the app exits
///   (the daemon is a sidecar that dies on quit, so keys are gone and the
///   vault starts locked next launch)
///
/// The wire form is a lowercase string token (e.g. `"15m"`, `"2h"`). The
/// deserializer accepts only string tokens; an unknown token falls back to
/// the default.
///
/// The OS power-event triggers from the Bitwarden reference UI (On system
/// lock / sleep / idle) require platform-specific hooks that are not yet
/// wired (see the TODO in desktop/src-tauri/src/lib.rs). They are omitted
/// from the preset list until those hooks ship; fail-closed over shipping
/// options that silently do nothing.
///
/// FUTURE NICE-TO-HAVE: a true "Never" that keeps the vault unlocked across
/// app/computer restart is NOT implemented. It would require persisting an
/// unlock secret (KEK or master password) to the OS keychain + auto-unlocking
/// on launch, plus a warning that the user is deferring security to the OS
/// (full-disk encryption + a strong login password). Tracked as a follow-up;
/// do not add a "never" option until that lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTimeout {
    /// Lock as soon as the app is backgrounded / minimized / loses focus.
    Immediately,
    /// Lock after `minutes` of daemon inactivity (no IPC requests).
    Minutes(u32),
    /// No idle timer. The vault locks only when the app exits (the daemon
    /// sidecar dies on quit, so keys never survive a restart).
    OnAppExit,
}

impl VaultTimeout {
    /// Default policy for new vaults: 15 minutes of inactivity.
    pub fn default_for_new() -> Self {
        VaultTimeout::Minutes(15)
    }

    /// Whether the daemon's idle walker should evaluate this policy.
    /// `Immediately` is driven by the desktop blur event (not the walker);
    /// `OnAppExit` never auto-locks by idle.
    pub fn is_idle_timed(&self) -> bool {
        matches!(self, VaultTimeout::Minutes(_))
    }

    /// Minutes of inactivity before an idle lock, or `None` if not idle-timed.
    /// No cap: the user's explicit choice is respected. The natural backstop
    /// is app exit (the daemon sidecar dies on quit, keys are in-memory only).
    pub fn idle_minutes(&self) -> Option<u32> {
        match self {
            VaultTimeout::Minutes(m) => Some(*m),
            _ => None,
        }
    }

    /// Stable wire token for serialization + frontend consumption.
    pub fn as_token(&self) -> String {
        match self {
            VaultTimeout::Immediately => "immediately".to_string(),
            VaultTimeout::Minutes(m) => format!("{m}m"),
            VaultTimeout::OnAppExit => "on_app_exit".to_string(),
        }
    }

    /// Parse a wire token (or a bare integer of minutes) into a policy.
    /// Unknown / empty -> default. Used by the deserializer + `settings.set`.
    pub fn from_token(raw: &str) -> Self {
        let s = raw.trim().to_ascii_lowercase();
        match s.as_str() {
            "" | "default" => VaultTimeout::default_for_new(),
            "immediately" | "instant" | "now" => VaultTimeout::Immediately,
            "on_app_exit" => VaultTimeout::OnAppExit,
            other => {
                // Duration tokens: "15m", "15", "90m", "2h", etc.
                if let Some(mins) = parse_minutes_token(other) {
                    return VaultTimeout::Minutes(mins);
                }
                VaultTimeout::default_for_new()
            }
        }
    }
}

impl Default for VaultTimeout {
    fn default() -> Self {
        VaultTimeout::default_for_new()
    }
}

/// Parse a duration token into minutes. Accepts `"15m"`, `"15"`, `"2h"`,
/// `"90"`. Returns `None` when it is not a recognizable duration.
fn parse_minutes_token(s: &str) -> Option<u32> {
    if let Some(rest) = s.strip_suffix('h') {
        return rest.parse::<u32>().ok().map(|h| h.saturating_mul(60));
    }
    let digits = s.strip_suffix('m').unwrap_or(s);
    digits.parse::<u32>().ok()
}

impl Serialize for VaultTimeout {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_token())
    }
}

impl<'de> Deserialize<'de> for VaultTimeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            // Wire form: lowercase string token.
            serde_json::Value::String(s) => Ok(VaultTimeout::from_token(&s)),
            serde_json::Value::Null => Ok(VaultTimeout::default_for_new()),
            other => Err(Error::custom(format!(
                "invalid vault_timeout: expected a string token, got {other}"
            ))),
        }
    }
}

/// Device registry entry (stored in meta/devices.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: DeviceId,
    /// Device name (user-chosen, e.g. "MacBook Pro").
    pub name: String,
    /// X25519 public key (32 bytes, hex-encoded).
    pub encryption_public_key: String,
    /// Ed25519 public key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Unix timestamp of enrollment.
    pub enrolled_at: u64,
    /// Which device approved enrollment. None for first (founding) device.
    #[serde(default)]
    pub enrolled_by: Option<DeviceId>,
    /// Last epoch this device was seen in. 0 = unknown.
    #[serde(default)]
    pub last_seen_epoch: u64,
}

/// Plaintext device public keys (stored in meta/device-pks, quorum-signed).
/// Allows commit signature verification without vault decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublicKeys {
    pub keys: Vec<DevicePublicKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublicKeyEntry {
    pub device_id: DeviceId,
    /// Ed25519 verifying key (32 bytes, hex-encoded).
    pub signing_public_key: String,
    /// Quorum signature over this entry (Ed25519, hex-encoded).
    pub quorum_signature: String,
}

/// Folder definition (stored in meta/folders.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub icon: Option<String>,
}

/// Tag index cache (stored in meta/tag_index.json).
/// Derived from decrypted cipher tags. Committed to git for cross-device sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagIndex {
    pub tags: Vec<String>,
    #[serde(default)]
    pub updated_at: u64,
}

/// Trash entry with logical timestamp (D6: per-item tombstones, delete-wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashEntry {
    pub object_id: Uuid,
    pub object_type: TrashObjectType,
    /// Monotonic sequence number (not wall-clock).
    pub delete_seq: u64,
    /// Device that performed the delete.
    pub deleted_by: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrashObjectType {
    Cipher,
    Folder,
}

/// One (package, registrable domain) pairing for app-to-web matching
/// (path B). Stored in VaultSettings trust/reject lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDomainTrust {
    pub package: String,
    pub domain: String,
}

/// Who may mint member invites (§6.5 invite_authority). Admins (default)
/// keeps the shipped assert_can_manage_members floor; Owners restricts
/// invite minting to the Owner row for high-scrutiny Spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InviteAuthority {
    #[default]
    Admins,
    Owners,
}

/// Space policy (§6.5): who may move entries to trash. Default: anyone
/// holding a live Write (or Manage) grant on the collection. `AdminsOnly`
/// restricts trashing to Owner/Admin devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TrashPolicy {
    #[default]
    WriteScopeCanTrash,
    AdminsOnly,
}

/// Space policy (§6.5): who may restore entries from trash. v1 ships
/// single-valued (the §6.5 table lists only `admins_only`; purge is
/// admin by the §4.4 row) — the persisted knob exists so surfaces can
/// display the state and a future `write_scope` value lands without a
/// migration. Enforced locally; the keyless sync walker cannot read
/// `settings.enc`, so peer admission stays grant-scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RestorePolicy {
    #[default]
    AdminsOnly,
}

/// Vault settings (stored encrypted in meta/settings.enc, last-write-wins).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultSettings {
    /// Auto-lock policy token.
    #[serde(default, deserialize_with = "VaultTimeout::deserialize")]
    pub vault_timeout: VaultTimeout,
    pub theme: Option<crate::types::ThemeMode>,
    /// Language code (e.g. "en", "es"). Persisted separately in plaintext meta/locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// URI match strategy global default. Typed enum with hard error on unknown values.
    #[serde(default, deserialize_with = "deserialize_uri_match_strategy")]
    pub default_uri_match: Option<crate::types::UriMatchStrategy>,
    /// Whether to fetch favicons from third-party sites for entries with URIs.
    /// `None` or `Some(true)` = enabled (default). `Some(false)` = disabled.
    #[serde(default)]
    pub fetch_favicons: Option<bool>,
    /// User-defined equivalent domain groups (Bitwarden parity). Each inner
    /// vec is one group of registrable domains the user declares equivalent
    /// for autofill matching (e.g. portal.acme-corp.net <-> acme.com).
    /// Synced via settings.enc; None = no custom groups defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_equivalent_domains: Option<Vec<Vec<String>>>,
    /// App-to-web suggestion toggle (path B trust-on-first-use). When true,
    /// native-app fills may surface web-saved logins whose registrable domain
    /// matches a package-name-derived candidate, after the user explicitly
    /// trusts the (package, domain) pairing. None/false = off (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggest_app_logins: Option<bool>,
    /// Trusted (package, registrable domain) pairs for app-to-web matching.
    /// A trusted pair lets web-saved entries for `domain` fill inside the
    /// native app `package`. Synced via settings.enc; auditable and per-vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_app_packages: Option<Vec<AppDomainTrust>>,
    /// Rejected pairs: the picker never suggests these (package, domain)
    /// pairings again. A later trust decision for the same pair overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_app_packages: Option<Vec<AppDomainTrust>>,
    /// Vault slug (machine-friendly identifier, e.g. "baluard-personal").
    /// Immutable after creation. Used as filesystem folder name, registry key, and git repo name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// User display name shown in sidebar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// User subtitle/role shown under display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    /// Avatar file extension (e.g. "png", "jpg"). Avatar stored at meta/avatar.{ext}.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_ext: Option<String>,
    /// Enrollment policy controls how a new device joins this vault.
    /// - `Personal` (default for new vaults): either an enrolled-device
    ///   signature OR the recovery phrase can authorize enrollment. The
    ///   recovery phrase is the root authority and can already perform
    ///   full disaster recovery; non-destructive enrollment via phrase
    ///   is a strict subset of that authority.
    /// - `Strict` (default for existing vaults, backward compat): only an
    ///   enrolled-device signature can authorize enrollment. Recovery
    ///   phrase only works via destructive `recover_from_phrase`.
    ///
    /// Migrating from Strict to Personal is a one-way door; re-read docs
    /// before doing so.
    #[serde(default = "default_enrollment_policy")]
    pub enrollment_policy: EnrollmentPolicy,
    /// Space policy (§6.5): who may mint invites. Admins by default; a
    /// Space can ratchet to Owners-only. Legacy vaults load Admins.
    #[serde(default)]
    pub space_invite_authority: InviteAuthority,
    /// Space policy (§6.5): whether Viewer-role devices may export vault
    /// data. Default false — export tightens to Editor-and-above unless a
    /// Space explicitly opts its viewers in.
    #[serde(default)]
    pub allow_viewer_export: bool,
    /// Space policy (§6.5): whether passphrase-guest reveals may be
    /// created. `None`/`Some(true)` = enabled (default); `Some(false)`
    /// blocks new guest shares (already created reveal files stay openable
    /// until expiry — they are self-contained, carried by the recipient).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_enabled: Option<bool>,
    /// Space policy (§6.5): who may move entries to trash.
    #[serde(default)]
    pub trash_policy: TrashPolicy,
    /// Space policy (§6.5): who may restore entries from trash.
    #[serde(default)]
    pub restore_policy: RestorePolicy,
}
/// These fields leak vault identity or policy if plaintext on the remote.
/// Display prefs (theme, lang) live separately in plaintext settings-pub.json
/// because the login screen needs them before unlock.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSettings {
    /// Auto-lock policy token.
    pub vault_timeout: VaultTimeout,
    /// URI match strategy global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_uri_match: Option<crate::types::UriMatchStrategy>,
    /// Whether to fetch favicons from third-party sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_favicons: Option<bool>,
    /// Vault slug (machine-friendly identifier). Post-unlock only; the
    /// authoritative runtime source is the .baluard marker + registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// Device display names, keyed by device UUID (audit C5). Names are PII
    /// ("Esteban's MacBook") and devices.json is git-tracked, so they live
    /// here, encrypted, instead. Populated by the fold-and-strip migration
    /// on unlock; entries may briefly remain in devices.json between
    /// enrollment (pre-unlock) and the first unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_names: Option<std::collections::HashMap<String, String>>,
    /// Device enrollment policy for this vault.
    #[serde(default = "default_enrollment_policy")]
    pub enrollment_policy: EnrollmentPolicy,
    /// Space policy: invite authority (mirrors VaultSettings; persisted).
    #[serde(default)]
    pub space_invite_authority: InviteAuthority,
    /// Space policy: viewer export permission (mirrors VaultSettings).
    #[serde(default)]
    pub allow_viewer_export: bool,
    /// Space policy: guest reveal creation (mirrors VaultSettings).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_enabled: Option<bool>,
    /// Space policy: trash authority (mirrors VaultSettings).
    #[serde(default)]
    pub trash_policy: TrashPolicy,
    /// Space policy: restore authority (mirrors VaultSettings).
    #[serde(default)]
    pub restore_policy: RestorePolicy,
    /// User-defined equivalent domain groups (Bitwarden parity). Each inner
    /// vec is one group of registrable domains the user declares equivalent
    /// for autofill matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_equivalent_domains: Option<Vec<Vec<String>>>,
    /// App-to-web suggestion toggle (path B trust-on-first-use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggest_app_logins: Option<bool>,
    /// Trusted (package, registrable domain) pairs for app-to-web matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_app_packages: Option<Vec<crate::vault::manifest::AppDomainTrust>>,
    /// Rejected pairs: never suggest these pairings again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_app_packages: Option<Vec<crate::vault::manifest::AppDomainTrust>>,
}

/// Vault enrollment policy for new device joins.
///
/// See `VaultSettings::enrollment_policy` for the full description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EnrollmentPolicy {
    /// New vaults: phrase OR enrolled-device signature can enroll.
    #[default]
    Personal,
    /// Existing vaults: only enrolled-device signature can enroll.
    Strict,
}

fn default_enrollment_policy() -> EnrollmentPolicy {
    // Called when the field is missing from existing settings.json.
    // Backward compat: old vaults were Strict (required device approval).
    EnrollmentPolicy::Strict
}

/// Encrypted user profile fields (stored in meta/profile.enc).
/// Separated from VaultSettings to prevent identity leakage via git sync.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub subtitle: Option<String>,
    pub avatar_ext: Option<String>,
}

fn deserialize_uri_match_strategy<'de, D>(
    deserializer: D,
) -> Result<Option<crate::types::UriMatchStrategy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            // Try typed enum first
            if let Ok(typed) = serde_json::from_value::<crate::types::UriMatchStrategy>(v.clone()) {
                return Ok(Some(typed));
            }
            // Try string with strict parsing
            if let Some(s) = v.as_str() {
                return crate::types::UriMatchStrategy::from_str_strict(s)
                    .map(Some)
                    .map_err(serde::de::Error::custom);
            }
            Err(serde::de::Error::custom("invalid URI match strategy"))
        }
    }
}

/// Sequence manifest entry (per device, stored in meta/sequences/{device_id}.enc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceManifest {
    pub vault_id: Uuid,
    pub device_id: DeviceId,
    pub epoch: u64,
    pub entries: Vec<SequenceEntry>,
    pub signed_at: u64,
    /// Ed25519 signature (hex-encoded).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceEntry {
    pub object_id: Uuid,
    pub last_seq: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The mobile + desktop apps send these wire tokens through
    // settings.set. A parse regression silently resets the user's
    // auto-lock choice to the 15-minute default.
    #[test]
    fn vault_timeout_parses_wire_tokens() {
        assert_eq!(
            VaultTimeout::from_token("immediately"),
            VaultTimeout::Immediately
        );
        assert_eq!(VaultTimeout::from_token("15m"), VaultTimeout::Minutes(15));
        assert_eq!(VaultTimeout::from_token("2h"), VaultTimeout::Minutes(120));
        assert_eq!(VaultTimeout::from_token("90"), VaultTimeout::Minutes(90));
        assert_eq!(
            VaultTimeout::from_token("on_app_exit"),
            VaultTimeout::OnAppExit
        );
        // Case-insensitive: the frontend lowercases, but belt-and-braces.
        assert_eq!(VaultTimeout::from_token("NOW"), VaultTimeout::Immediately);
    }

    #[test]
    fn vault_timeout_unknown_token_falls_back_to_default() {
        // Unknown tokens must fall back to the 15-minute default, not
        // fail the whole settings write or lock the user out instantly.
        assert_eq!(
            VaultTimeout::from_token("garbage"),
            VaultTimeout::Minutes(15)
        );
        assert_eq!(VaultTimeout::from_token(""), VaultTimeout::Minutes(15));
    }

    #[test]
    fn vault_timeout_wire_roundtrip() {
        // serde: the stored settings JSON carries the token, and
        // settings.set deserializes the same token back into the policy.
        // "4h" is accepted on input and canonicalizes to "240m" on
        // write-back; every client parses that form, so assert the
        // canonical storage token, not the input spelling.
        let cases = [
            ("immediately", "immediately"),
            ("15m", "15m"),
            ("4h", "240m"),
            ("on_app_exit", "on_app_exit"),
        ];
        for (input, stored) in cases {
            let json = format!(r#"{{"vault_timeout": "{input}"}}"#);
            let settings: VaultSettings = serde_json::from_str(&json).unwrap();
            assert_eq!(settings.vault_timeout.as_token(), stored);
            let reserialized = serde_json::to_value(settings.vault_timeout).unwrap();
            assert_eq!(reserialized, serde_json::json!(stored));
        }
    }

    #[test]
    fn vault_timeout_edge_tokens() {
        // Zero minutes: valid inactivity window
        assert_eq!(VaultTimeout::from_token("0m"), VaultTimeout::Minutes(0));
        assert_eq!(VaultTimeout::from_token("0"), VaultTimeout::Minutes(0));
        // Negative minutes: unparseable -> default fallback (15m)
        assert_eq!(VaultTimeout::from_token("-15m"), VaultTimeout::Minutes(15));
        // Hour overflow: saturating_mul to u32::MAX
        assert_eq!(
            VaultTimeout::from_token("100000000h"),
            VaultTimeout::Minutes(u32::MAX)
        );
        // Explicit default token
        assert_eq!(
            VaultTimeout::from_token("default"),
            VaultTimeout::Minutes(15)
        );
        // Surrounding whitespace trimmed
        assert_eq!(
            VaultTimeout::from_token("  30m  "),
            VaultTimeout::Minutes(30)
        );
    }

    #[test]
    fn vault_timeout_serializes_as_token() {
        assert_eq!(
            serde_json::to_value(VaultTimeout::Minutes(240)).unwrap(),
            serde_json::json!("240m")
        );
        assert_eq!(
            serde_json::to_value(VaultTimeout::Immediately).unwrap(),
            serde_json::json!("immediately")
        );
    }

    #[test]
    fn vault_settings_rejects_unknown_uri_match_strategy() {
        let json = r#"{"vault_timeout": "10m", "default_uri_match": "exakt"}"#;
        let result: Result<VaultSettings, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "expected error for unknown strategy, got: {:?}",
            result
        );
    }

    #[test]
    fn vault_settings_accepts_valid_uri_match_strategy() {
        let json = r#"{"default_uri_match": "host"}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(
            settings.default_uri_match,
            Some(crate::types::UriMatchStrategy::Host)
        );
    }

    #[test]
    fn vault_settings_null_uri_match_is_none() {
        let json = r#"{"default_uri_match": null}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert!(settings.default_uri_match.is_none());
    }

    #[test]
    fn theme_mode_serde_roundtrip() {
        use crate::types::ThemeMode;
        for theme in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
            let json = serde_json::to_string(&theme).unwrap();
            let back: ThemeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(theme, back);
        }
    }

    #[test]
    fn theme_mode_rejects_unknown() {
        let result: Result<crate::types::ThemeMode, _> = serde_json::from_str("\"neon\"");
        assert!(result.is_err());
    }

    #[test]
    fn theme_mode_case_insensitive_deserialize() {
        // Existing vaults may have capitalized theme strings
        for (input, expected) in [
            ("\"Light\"", crate::types::ThemeMode::Light),
            ("\"DARK\"", crate::types::ThemeMode::Dark),
            ("\"System\"", crate::types::ThemeMode::System),
            ("\"light\"", crate::types::ThemeMode::Light),
        ] {
            let result: crate::types::ThemeMode = serde_json::from_str(input).unwrap();
            assert_eq!(result, expected, "failed for input: {input}");
        }
    }

    #[test]
    fn vault_settings_theme_roundtrip() {
        let settings = VaultSettings {
            theme: Some(crate::types::ThemeMode::Dark),
            lang: Some("es".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: VaultSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.theme, Some(crate::types::ThemeMode::Dark));
        assert_eq!(back.lang.as_deref(), Some("es"));
    }

    #[test]
    fn vault_settings_lang_skipped_when_none() {
        let settings = VaultSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        assert!(!json.contains("lang"));
    }

    #[test]
    fn enrollment_policy_default_is_personal() {
        // New vaults default to Personal — phrase OR device approval accepted.
        // M4 product-intent: solo users should not need a second device to recover.
        assert_eq!(EnrollmentPolicy::default(), EnrollmentPolicy::Personal);
    }

    #[test]
    fn space_settings_defaults_match_plan_table() {
        // §6.5: invite_authority admins, viewer export off, guests on,
        // trash write-scope, restore admin-only.
        let settings = VaultSettings::default();
        assert_eq!(settings.space_invite_authority, InviteAuthority::Admins);
        assert!(!settings.allow_viewer_export);
        // None = enabled (the Option-toggle convention).
        assert!(settings.guest_enabled != Some(false));
        assert_eq!(settings.trash_policy, TrashPolicy::WriteScopeCanTrash);
        assert_eq!(settings.restore_policy, RestorePolicy::AdminsOnly);
    }

    #[test]
    fn space_settings_backward_compat_absent_fields_get_defaults() {
        // Pre-S3-9 settings.enc carries none of the knobs; the serde
        // defaults must fill them so legacy vaults keep today's behavior.
        let json = r#"{"vault_timeout": "10m"}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.space_invite_authority, InviteAuthority::Admins);
        assert!(!settings.allow_viewer_export);
        assert!(settings.guest_enabled != Some(false));
        assert_eq!(settings.trash_policy, TrashPolicy::WriteScopeCanTrash);
        assert_eq!(settings.restore_policy, RestorePolicy::AdminsOnly);
    }

    #[test]
    fn space_settings_roundtrip() {
        let settings = VaultSettings {
            space_invite_authority: InviteAuthority::Owners,
            allow_viewer_export: true,
            guest_enabled: Some(false),
            trash_policy: TrashPolicy::AdminsOnly,
            ..Default::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: VaultSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.space_invite_authority, InviteAuthority::Owners);
        assert!(back.allow_viewer_export);
        assert_eq!(back.guest_enabled, Some(false));
        assert_eq!(back.trash_policy, TrashPolicy::AdminsOnly);
    }

    #[test]
    fn enrollment_policy_backward_compat_existing_vaults_default_strict() {
        // When deserializing old settings.json without the field,
        // default_enrollment_policy() returns Strict (preserves old behavior).
        let json = r#"{"vault_timeout": "10m"}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.enrollment_policy, EnrollmentPolicy::Strict);
    }

    #[test]
    fn enrollment_policy_roundtrip() {
        let settings = VaultSettings {
            enrollment_policy: EnrollmentPolicy::Personal,
            ..Default::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: VaultSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.enrollment_policy, EnrollmentPolicy::Personal);

        let settings2 = VaultSettings {
            enrollment_policy: EnrollmentPolicy::Strict,
            ..Default::default()
        };
        let json2 = serde_json::to_string(&settings2).unwrap();
        let back2: VaultSettings = serde_json::from_str(&json2).unwrap();
        assert_eq!(back2.enrollment_policy, EnrollmentPolicy::Strict);
    }

    #[test]
    fn enrollment_policy_new_vault_defaults_to_personal() {
        // New VaultSettings::default() should be Personal (the product-intent default).
        let settings = VaultSettings::default();
        assert_eq!(settings.enrollment_policy, EnrollmentPolicy::Personal);
    }

    #[test]
    fn vault_timeout_default_is_15_minutes() {
        assert_eq!(VaultTimeout::default(), VaultTimeout::Minutes(15));
        assert_eq!(
            VaultSettings::default().vault_timeout,
            VaultTimeout::Minutes(15)
        );
    }

    #[test]
    fn vault_timeout_string_token_roundtrip() {
        // Deserialization: every token maps to the expected policy.
        for (token, expected) in [
            ("immediately", VaultTimeout::Immediately),
            ("1m", VaultTimeout::Minutes(1)),
            ("15m", VaultTimeout::Minutes(15)),
            ("2h", VaultTimeout::Minutes(120)),
            ("on_app_exit", VaultTimeout::OnAppExit),
        ] {
            let json = format!("{{\"vault_timeout\": \"{token}\"}}");
            let settings: VaultSettings = serde_json::from_str(&json).unwrap();
            assert_eq!(settings.vault_timeout, expected, "failed for token {token}");
        }

        // Serialization is canonical-by-minutes: Minutes(120) -> "120m",
        // not "2h". Hour tokens are convenience aliases on input only.
        assert_eq!(
            serde_json::to_string(&VaultTimeout::Minutes(120)).unwrap(),
            "\"120m\""
        );
        assert_eq!(
            serde_json::to_string(&VaultTimeout::OnAppExit).unwrap(),
            "\"on_app_exit\""
        );
        assert_eq!(
            serde_json::to_string(&VaultTimeout::Immediately).unwrap(),
            "\"immediately\""
        );
    }

    #[test]
    fn vault_timeout_respects_arbitrarily_long_window() {
        // No MAX cap: the user's explicit choice is respected. The stored
        // value is honored as-is.
        let json = r#"{"vault_timeout": "9999m"}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.vault_timeout, VaultTimeout::Minutes(9999));
        assert_eq!(settings.vault_timeout.idle_minutes(), Some(9999));
    }

    #[test]
    fn vault_timeout_idle_flags() {
        assert!(VaultTimeout::Minutes(5).is_idle_timed());
        assert!(!VaultTimeout::Immediately.is_idle_timed());
        assert!(!VaultTimeout::OnAppExit.is_idle_timed());
        assert_eq!(VaultTimeout::OnAppExit.idle_minutes(), None);
    }
}
