//! Token storage: OS keyring for secrets, providers.json for metadata.
//!
//! Keyring entry: `baluard-<provider>-<username>`
//! providers.json: `<data_dir>/providers.json` (non-sensitive state)

use std::collections::HashMap;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::types::{Provider, ProviderInfo, ProviderToken};
use crate::paths::data_dir;

/// Non-sensitive provider state file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvidersState {
    /// Schema version for forward compatibility.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Map of "provider" -> ProviderInfo.
    #[serde(flatten)]
    pub providers: HashMap<String, ProviderInfo>,
}

fn default_version() -> u32 {
    1
}

impl Default for ProvidersState {
    fn default() -> Self {
        Self {
            version: 1,
            providers: HashMap::new(),
        }
    }
}

impl ProvidersState {
    /// Path to providers.json.
    pub fn path() -> PathBuf {
        data_dir().join("providers.json")
    }

    /// Load from disk. Returns empty if file doesn't exist.
    pub fn load() -> Result<Self, std::io::Error> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let state: ProvidersState = serde_json::from_str(&data)?;
        Ok(state)
    }

    /// Save to disk atomically with 0600 permissions.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Get info for a provider.
    pub fn get(&self, provider: Provider) -> Option<&ProviderInfo> {
        self.providers.get(&provider.to_string())
    }

    /// Upsert provider info.
    pub fn set(&mut self, info: ProviderInfo) {
        self.providers.insert(info.provider.to_string(), info);
    }

    /// Remove provider info.
    pub fn remove(&mut self, provider: Provider) -> Option<ProviderInfo> {
        self.providers.remove(&provider.to_string())
    }
}

/// Keyring key format: `baluard-<provider>-<username>`
fn keyring_key(provider: Provider, username: &str) -> String {
    format!("baluard-{}-{}", provider, username)
}

/// Wrap keyring errors with headless environment hint.
fn keyring_error(e: &keyring::Error) -> super::types::ProviderError {
    super::types::ProviderError::Keyring(format!(
        "{e}. Keyring unavailable in headless/CI environments. \
         Use `baluard --direct provider connect-pat` with a PAT instead."
    ))
}

/// Path for file-based token fallback when OS keyring is unavailable.
fn token_file_path(key: &str) -> PathBuf {
    data_dir().join("tokens").join(format!("{key}.json"))
}

/// True when this build has a real, persistent OS keyring backend.
///
/// `keyring` 3.x only ships stores for macOS/iOS (apple-native), Windows
/// (windows-native) and Linux/BSD (secret-service / keyutils). On every other
/// target (**Android included**) `keyring::default` resolves to
/// `keyring::mock`, whose `set_password` returns `Ok(())` and writes into an
/// in-memory cell owned by that one `Entry`. The value is dropped with the
/// `Entry`, so a mock write is a silent black hole: the store reports success
/// and the next read returns `NoEntry`. Gate on the target instead of trusting
/// the `Ok`, so unsupported platforms go straight to the app-private file.
/// Mirrors the target list in `keyring::lib.rs` that resolves to a real store
/// (the workspace enables apple-native + windows-native + linux-native-sync-
/// persistent, so target_os alone decides).
const fn keyring_is_persistent() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
    ))
}

/// Write `secret` to the app-private token file with owner-only permissions from the
/// first byte (no world-readable window; audit C25). When a token-encryption
/// key is set (M3: Android, Keystore-wrapped via UniFFI) the content is an
/// AES-256-GCM envelope instead of plaintext. Headless/test environments run
/// without a key and keep the legacy plaintext file.
fn store_token_file(key: &str, secret: &str) -> Result<(), super::types::ProviderError> {
    store_token_file_impl(&token_file_path(key), secret.as_bytes(), token_enc_key())
}

fn store_token_file_impl(
    path: &std::path::Path,
    secret: &[u8],
    enc_key: Option<&[u8; 32]>,
) -> Result<(), super::types::ProviderError> {
    let bytes = match enc_key {
        Some(k) => crate::secret_file::seal_secret_blob(k, secret, TOKEN_BLOB_PURPOSE)
            .map_err(|e| super::types::ProviderError::Io(e.to_string()))?,
        None => secret.to_vec(),
    };
    crate::secret_file::write_secret_file(path, &bytes)
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))
}

/// Purpose marker for the sealed token-file envelope (M3).
const TOKEN_BLOB_PURPOSE: &str = "token-file-v1";

/// Process-lifetime token-file encryption key (M3). Set once by the mobile
/// app at startup; the Android side sources it from AndroidKeystore (random
/// 32-byte key, itself wrapped by a non-exportable Keystore key). Absent on
/// desktop (keyring path) and in headless tests (plaintext fallback).
static TOKEN_ENC_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

fn token_enc_key() -> Option<&'static [u8; 32]> {
    TOKEN_ENC_KEY.get()
}

/// Install the token-file encryption key. Idempotent; the first call wins
/// (a second, attacker-influenced call mid-session cannot swap the key).
pub fn set_token_encryption_key(key: [u8; 32]) {
    let _ = TOKEN_ENC_KEY.set(key);
}

/// Read the token file: sealed content requires the key (fail closed when
/// absent — an app-init bug, never a user condition); legacy plaintext is
/// returned as-is and re-sealed when a key is available (lazy migration of
/// pre-seal installs).
fn read_token_file(path: &std::path::Path) -> Result<Vec<u8>, super::types::ProviderError> {
    read_token_file_impl(path, token_enc_key())
        .and_then(|(data, migrate)| {
            if migrate {
                if let Some(k) = token_enc_key() {
                    let _ = store_token_file_impl(path, &data, Some(k));
                }
            }
            Ok(data)
        })
}

fn read_token_file_impl(
    path: &std::path::Path,
    enc_key: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, bool), super::types::ProviderError> {
    let raw = std::fs::read(path)
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
    if crate::secret_file::is_sealed_secret_blob(&raw) {
        let key = enc_key.ok_or_else(|| {
            super::types::ProviderError::Keyring(
                "token file is sealed but no encryption key is installed".into(),
            )
        })?;
        let pt = crate::secret_file::open_secret_blob(key, &raw, TOKEN_BLOB_PURPOSE)
            .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
        Ok((pt, false))
    } else {
        Ok((raw, enc_key.is_some()))
    }
}

/// Store a provider token in the OS keyring, falling back to a 0600 file if keyring is unavailable.
pub fn store_token(
    provider: Provider,
    username: &str,
    token: &ProviderToken,
) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    let secret = token
        .to_secret()
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;

    // No real keyring on this target (Android, …): the mock store would answer
    // Ok and drop the token, so go straight to the app-private file. Tests
    // (BALUARD_DISABLE_KEYRING / cfg(test)) take the same file path.
    if !keyring_is_persistent() || crate::keyring_disabled() {
        return store_token_file(&key, secret.expose_secret());
    }

    let keyring_result = keyring::Entry::new("baluard", &key)
        .map_err(|e| keyring_error(&e))
        .and_then(|entry| {
            entry
                .set_password(secret.expose_secret())
                .map_err(|e| keyring_error(&e))
        });

    if keyring_result.is_err() {
        // Keyring present but unusable (headless session, locked collection):
        // fall back to the app-private token file with 0600 permissions.
        return store_token_file(&key, secret.expose_secret());
    }
    // Keyring took it; drop any stale fallback copy so the two can't diverge.
    let _ = std::fs::remove_file(token_file_path(&key));
    Ok(())
}

/// Retrieve a provider token from the OS keyring or fallback file.
pub fn load_token(
    provider: Provider,
    username: &str,
) -> Result<ProviderToken, super::types::ProviderError> {
    let key = keyring_key(provider, username);

    // Try OS keyring first (skipped where it is a no-op mock store, and in
    // tests where unsigned binaries must not touch the real keychain).
    if keyring_is_persistent() && !crate::keyring_disabled() {
        if let Ok(entry) = keyring::Entry::new("baluard", &key) {
            if let Ok(secret_str) = entry.get_password() {
                let secret = SecretString::new(secret_str.into());
                if let Ok(tok) = ProviderToken::from_secret(&secret) {
                    return Ok(tok);
                }
            }
        }
    }

    // Fallback: load from token file (sealed under the M3 key on Android,
    // legacy plaintext elsewhere)
    let path = token_file_path(&key);
    if path.exists() {
        let secret_bytes = read_token_file(&path)?;
        let secret_str = String::from_utf8(secret_bytes)
            .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
        let secret = SecretString::new(secret_str.trim().to_string().into());
        return ProviderToken::from_secret(&secret)
            .map_err(|e| super::types::ProviderError::Keyring(e.to_string()));
    }

    Err(super::types::ProviderError::Keyring(format!(
        "Token for provider {provider} (user {username}) not found in keyring or fallback store"
    )))
}

/// Delete a provider token from the OS keyring and fallback file.
pub fn delete_token(provider: Provider, username: &str) -> Result<(), super::types::ProviderError> {
    let key = keyring_key(provider, username);
    if let Ok(entry) = keyring::Entry::new("baluard", &key) {
        let _ = entry.delete_credential();
    }
    let path = token_file_path(&key);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// Full provider disconnect: delete keyring token + remove from providers.json.
pub fn disconnect(provider: Provider) -> Result<(), super::types::ProviderError> {
    let mut state =
        ProvidersState::load().map_err(|e| super::types::ProviderError::Io(e.to_string()))?;

    if let Some(info) = state.remove(provider) {
        // Best-effort keyring / file deletion
        let _ = delete_token(provider, &info.username);
    }

    state
        .save()
        .map_err(|e| super::types::ProviderError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_state_round_trip() {
        let dir = std::env::temp_dir().join("baluard-test-providers-state");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Override data_dir for test
        let path = dir.join("providers.json");
        let mut state = ProvidersState::default();
        state.set(ProviderInfo {
            provider: Provider::GitHub,
            username: "testuser".into(),
            scopes: "repo".into(),
            connected_at: 1700000000,
            instance_url: None,
            client_id: None,
        });

        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&path, &json).unwrap();

        let loaded: ProvidersState =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.providers.len(), 1);
        assert_eq!(loaded.get(Provider::GitHub).unwrap().username, "testuser");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyring_key_format() {
        assert_eq!(
            keyring_key(Provider::GitHub, "alice"),
            "baluard-github-alice"
        );
        assert_eq!(keyring_key(Provider::GitLab, "bob"), "baluard-gitlab-bob");
    }

    #[test]
    fn token_serialization_round_trip() {
        use secrecy::ExposeSecret;
        let token = ProviderToken::new("ghp_test123", "repo");
        let secret = token.to_secret().unwrap();
        let restored = ProviderToken::from_secret(&secret).unwrap();
        assert_eq!(restored.access_token().expose_secret(), "ghp_test123");
        assert_eq!(restored.scopes, "repo");
        assert!(restored.refresh_token().is_none());
        assert!(restored.expires_at.is_none());
    }

    #[test]
    fn token_expiry_check() {
        let mut token = ProviderToken::new("test", "repo");
        assert!(!token.is_expired()); // no expiry = never expired

        token.expires_at = Some(100); // way in the past
        assert!(token.is_expired());
    }

    // ── M3: sealed token files ──
    // These call the *_impl helpers with EXPLICIT keys instead of the
    // process-global TOKEN_ENC_KEY: the global is OnceLock-set-once and tests
    // run in parallel, so going through it would make outcomes order-
    // dependent. The public store/load path delegates to the same impls.

    fn tmp_token_file(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("baluard-m3-{name}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn sealed_token_file_roundtrip_no_plaintext_at_rest() {
        let path = tmp_token_file("roundtrip");
        let key = [9u8; 32];
        let secret = b"{\"access_token\":\"ghp_x\"}";

        store_token_file_impl(&path, secret, Some(&key)).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("ghp_x"));
        assert!(crate::secret_file::is_sealed_secret_blob(&raw));

        let (pt, migrate) = read_token_file_impl(&path, Some(&key)).unwrap();
        assert_eq!(pt, secret);
        assert!(!migrate);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sealed_token_file_wrong_or_missing_key_fails_closed() {
        let path = tmp_token_file("closed");
        store_token_file_impl(&path, b"secret", Some(&[1u8; 32])).unwrap();

        // Wrong key: GCM tag mismatch.
        assert!(read_token_file_impl(&path, Some(&[2u8; 32])).is_err());
        // No key at all (app-init bug): refuses.
        assert!(read_token_file_impl(&path, None).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn legacy_plaintext_token_file_reads_and_flags_migration() {
        let path = tmp_token_file("legacy");
        crate::secret_file::write_secret_file(&path, b"legacy-secret").unwrap();

        // Without a key: readable (headless path), no migration flagged.
        let (pt, migrate) = read_token_file_impl(&path, None).unwrap();
        assert_eq!(pt, b"legacy-secret");
        assert!(!migrate);

        // With a key: readable AND flagged for lazy re-seal.
        let (pt, migrate) = read_token_file_impl(&path, Some(&[3u8; 32])).unwrap();
        assert_eq!(pt, b"legacy-secret");
        assert!(migrate);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn set_token_encryption_key_first_call_wins() {
        set_token_encryption_key([7u8; 32]);
        set_token_encryption_key([8u8; 32]);
        assert_eq!(token_enc_key(), Some(&[7u8; 32]));
    }
}
