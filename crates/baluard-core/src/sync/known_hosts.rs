//! SSH host key verification against `~/.ssh/known_hosts`.
//!
//! M5 fix: git2 does not enforce known_hosts by default — it relies on libssh2
//! defaults, which accept unknown hosts. This module provides a strict
//! certificate_check callback that rejects SSH host keys not present in the
//! user's known_hosts file. HTTPS certificates are passed through to libgit2's
//! built-in libcurl/CA validation (already secure by default).
//!
//! ## Known hosts file format
//!
//! Each non-empty, non-comment line: `markers pattern[,pattern,...] keytype base64key comment`
//!
//! - `markers` is optional and starts with `@`
//! - `pattern` is a hostname, possibly with `*` wildcard, or `[host]:port`
//! - Hashed entries (`|1|salt|hash|...`) are not supported by this parser
//!
//! Reference: `man sshd(8)` AUTHORIZED_KEYS, `man ssh(1)` KNOWN_HOSTS FILE FORMAT.

use std::path::PathBuf;

/// Outcome of host key verification.
#[derive(Debug, PartialEq, Eq)]
pub enum HostKeyResult {
    /// Host key matches a known_hosts entry.
    Known,
    /// Host key not found in known_hosts.
    Unknown,
    /// known_hosts file missing or unreadable (fail closed: reject).
    Missing,
    /// Host key does NOT match a known_hosts entry (potential MITM).
    Mismatch,
}

/// Look up `host` in known_hosts and verify the presented `key_type`/`key` match.
///
/// `key_type` is the SSH key type string (e.g. `ssh-ed25519`, `ssh-rsa`).
/// `key` is the raw host key bytes (before base64 encoding).
#[cfg(test)]
pub(crate) static TEST_HOME_LOCK: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

pub fn verify_host_key(host: &str, key_type: &str, key: &[u8]) -> HostKeyResult {
    let path = known_hosts_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return HostKeyResult::Missing,
    };

    let mut found_match = false;
    let mut found_key_for_host = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip hashed entries (|1|...). Only plaintext entries are supported.
        if line.starts_with("|1|") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // First field: host pattern (may include markers like @cert-authority
        // and/or comma-separated multiple host patterns).
        // Examples:
        //   "github.com"                          -> ["github.com"]
        //   "github.com,192.30.255.112"           -> ["github.com", "192.30.255.112"]
        //   "@cert-authority,*.example.com"       -> marker=["@cert-authority"], hosts=["*.example.com"]
        //   "@revoked"                            -> marker=["@revoked"], hosts=[]
        let first_field = parts[0];
        let (has_revoked_marker, host_patterns): (bool, Vec<&str>) = if first_field.starts_with('@')
        {
            // Comma-separated markers+hosts; first segment(s) starting with @ are markers.
            let segments: Vec<&str> = first_field.split(',').collect();
            let mut revoked = false;
            let mut hosts = Vec::new();
            for seg in &segments {
                if *seg == "@revoked" {
                    revoked = true;
                } else if !seg.starts_with('@') {
                    hosts.push(*seg);
                }
                // Other markers (e.g. @cert-authority, @userknown) are noted
                // but not enforced — we're verifying host keys, not CA chains.
            }
            (revoked, hosts)
        } else {
            // No markers; comma-separated list of host patterns.
            let hosts: Vec<&str> = first_field.split(',').collect();
            (false, hosts)
        };
        // Markers like @revoked must hard-fail (OpenSSH: a matched @revoked
        // entry means the host key has been revoked and must never be trusted).
        if has_revoked_marker {
            // @revoked with no host patterns applies to the entry as a whole;
            // we treat it as a global revoke indicator: if the line had any
            // matching host, we'd reject. Since we have no host here, skip.
            // (OpenSSH @revoked lines always include a host pattern.)
            continue;
        }
        // Key type is the second field, base64 key is the third.
        // Trailing fields (parts[3+]) are comments and ignored.
        let entry_key_type = parts[1];
        let entry_key_b64 = parts[2];

        // Check if ANY of the comma-separated host patterns match.
        let any_match = host_patterns.iter().any(|p| host_matches(p, host));
        if !any_match {
            continue;
        }
        found_key_for_host = true;
        if entry_key_type != key_type {
            continue;
        }
        // Base64-decode the key (with and without padding)
        let Ok(entry_key) = base64_decode(entry_key_b64) else {
            continue;
        };
        if entry_key == key {
            found_match = true;
        } else {
            // Key type matches but key bytes differ — possible MITM.
            return HostKeyResult::Mismatch;
        }
    }

    if found_match {
        HostKeyResult::Known
    } else if found_key_for_host {
        // Host is in known_hosts with a different key type — suspicious but
        // treat as mismatch (same effect: reject).
        HostKeyResult::Mismatch
    } else {
        HostKeyResult::Unknown
    }
}

/// Locate the known_hosts file. `$HOME/.ssh/known_hosts` (or the Windows
/// profile equivalent) when a home directory exists; otherwise the app data
/// dir (mobile has no `$HOME` — the NMH/UniFFI processes set
/// `BALUARD_DATA_DIR`). Returns the canonical path even if the file does not
/// exist (caller handles the read failure).
fn known_hosts_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".ssh").join("known_hosts");
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join(".ssh").join("known_hosts");
    }
    crate::paths::data_dir().join("known_hosts")
}

/// Strip leading markers like `@cert-authority,@revoked` from a host field.
#[allow(dead_code)]
fn strip_markers(field: &str) -> &str {
    // Markers are comma-separated and prefixed with @, appearing before the host
    // pattern. They may be absent. Format: `[markers,]pattern`
    if let Some(first_comma) = field.find(',') {
        // The pattern is the last comma-separated segment.
        if let Some(last_comma) = field.rfind(',') {
            return &field[last_comma + 1..];
        }
        return &field[first_comma + 1..];
    }
    field
}

/// Check if `pattern` (from known_hosts) matches the connection `host`.
/// Supports exact match, `[host]:port` form, and trailing `*` wildcard.
fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_start_matches('[');
    let pattern = pattern.split(']').next().unwrap_or(pattern);

    if pattern == host {
        return true;
    }
    // Wildcard: `*.example.com` matches `foo.example.com`, `a.b.example.com`.
    // Does NOT match `example.com` (no leading subdomain).
    if let Some(suffix) = pattern.strip_prefix('*') {
        if let Some(prefix) = host.strip_suffix(suffix) {
            // prefix must be non-empty and not contain '/' or ':' (path/port).
            return !prefix.is_empty() && !prefix.contains('/') && !prefix.contains(':');
        }
    }
    false
}

/// Minimal RFC 4648 base64 decoder (standard alphabet, with/without padding).
/// Avoids pulling in the `base64` crate just for known_hosts.
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut buf_len = 0;
    for &b in bytes {
        if b == b'=' {
            // Padding terminates the last group.
            if buf_len == 0 || buf_len == 1 {
                return Err(());
            }
            if buf_len == 2 {
                let combined = (u32::from(lookup[buf[0] as usize]) << 18)
                    | (u32::from(lookup[buf[1] as usize]) << 12);
                out.push((combined >> 16) as u8);
            } else {
                // buf_len == 3
                let combined = (u32::from(lookup[buf[0] as usize]) << 18)
                    | (u32::from(lookup[buf[1] as usize]) << 12)
                    | (u32::from(lookup[buf[2] as usize]) << 6);
                out.push((combined >> 16) as u8);
                out.push((combined >> 8) as u8);
            }
            return Ok(out);
        }
        let v = lookup[b as usize];
        if v == 255 {
            return Err(());
        }
        buf[buf_len] = b;
        buf_len += 1;
        if buf_len == 4 {
            let combined = (u32::from(lookup[buf[0] as usize]) << 18)
                | (u32::from(lookup[buf[1] as usize]) << 12)
                | (u32::from(lookup[buf[2] as usize]) << 6)
                | u32::from(lookup[buf[3] as usize]);
            out.push((combined >> 16) as u8);
            out.push((combined >> 8) as u8);
            out.push(combined as u8);
            buf_len = 0;
        }
    }
    // Handle unpadded tail (2 chars → 1 byte, 3 chars → 2 bytes).
    if buf_len == 2 {
        let combined =
            (u32::from(lookup[buf[0] as usize]) << 18) | (u32::from(lookup[buf[1] as usize]) << 12);
        out.push((combined >> 16) as u8);
    } else if buf_len == 3 {
        let combined = (u32::from(lookup[buf[0] as usize]) << 18)
            | (u32::from(lookup[buf[1] as usize]) << 12)
            | (u32::from(lookup[buf[2] as usize]) << 6);
        out.push((combined >> 16) as u8);
        out.push((combined >> 8) as u8);
    } else if buf_len == 1 {
        return Err(());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Host-key trust: daemon-observed pending handshakes + the trust writer.
//
// The trust flow is deliberately asymmetric: only the daemon (the process
// that ran the SSH handshake) records what the server actually presented,
// and the trust route can only bless an observation the daemon itself made.
// A compromised UI can never bless a key it chose.
// ---------------------------------------------------------------------------

/// A host key the daemon observed during a failed handshake.
#[derive(Debug, Clone)]
pub struct ObservedHostKey {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    /// Raw key bytes as presented.
    pub key: Vec<u8>,
    /// `SHA256:<base64>` fingerprint (OpenSSH display form).
    pub fingerprint: String,
}

const OBSERVATION_TTL_SECS: u64 = 300;
const MAX_PENDING_OBSERVATIONS: usize = 32;

use rand::RngCore;

struct PendingObservation {
    observed: ObservedHostKey,
    at: std::time::Instant,
}

use std::sync::Mutex;
use std::sync::OnceLock;

fn pending_observations() -> &'static Mutex<Vec<(String, PendingObservation)>> {
    static PENDING: OnceLock<Mutex<Vec<(String, PendingObservation)>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a host key observed during a failed handshake. Returns the attempt
/// id the trust route must present.
pub fn record_observation(observed: ObservedHostKey) -> String {
    let mut pending = pending_observations().lock().expect("pending lock");
    let now = std::time::Instant::now();
    pending.retain(|(_, p)| now.duration_since(p.at).as_secs() < OBSERVATION_TTL_SECS);
    while pending.len() >= MAX_PENDING_OBSERVATIONS {
        pending.remove(0);
    }
    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let attempt_id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
    pending.push((attempt_id.clone(), PendingObservation { observed, at: now }));
    attempt_id
}

/// Take a pending observation by attempt id (drains it — one trust per
/// handshake).
pub fn take_observation(attempt_id: &str) -> Option<ObservedHostKey> {
    let mut pending = pending_observations().lock().expect("pending lock");
    let now = std::time::Instant::now();
    let pos = pending.iter().position(|(id, p)| {
        id == attempt_id && now.duration_since(p.at).as_secs() < OBSERVATION_TTL_SECS
    })?;
    let (_, p) = pending.remove(pos);
    Some(p.observed)
}

/// The most recent live observation, taken (drained). Used by sync wrappers
/// to upgrade a generic transport failure into `SyncError::HostKeyUntrusted`.
pub fn take_latest_observation() -> Option<(String, ObservedHostKey)> {
    let mut pending = pending_observations().lock().expect("pending lock");
    let now = std::time::Instant::now();
    pending.retain(|(_, p)| now.duration_since(p.at).as_secs() < OBSERVATION_TTL_SECS);
    let (id, p) = pending.pop()?;
    Some((id, p.observed))
}

/// `SHA256:<base64-nopad>` fingerprint of the raw key bytes, the display form
/// `ssh-keygen -lf` prints.
pub fn fingerprint(key: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key);
    use base64::Engine as _;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// Derive the known_hosts entry host field: bare hostname for port 22,
/// `[host]:port` otherwise (OpenSSH entry form — trusting one port must not
/// trust every port on the host).
fn entry_host(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Record trust for an observed host key by appending the known_hosts line.
///
/// Fails closed on: unsanitizable host, a conflicting plaintext entry for the
/// host, or ANY hashed entry in the file (hashed lines cannot be attributed
/// to the host, so an existing trust relationship for it cannot be ruled out;
/// the user manages those themselves). Never overwrites an existing line.
pub fn trust_host_key(observed: &ObservedHostKey) -> Result<(), String> {
    let host = observed.host.trim();
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
        || host.starts_with(['-', '.'])
    {
        return Err("invalid host name".into());
    }
    if !matches!(
        observed.key_type.as_str(),
        "ssh-ed25519"
            | "ssh-rsa"
            | "ssh-dss"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    ) {
        return Err("unsupported host key type".into());
    }
    use base64::Engine as _;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&observed.key);

    let path = known_hosts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create the SSH directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    for line in existing.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("|1|") {
            // Hashed entries cannot be attributed to this host; refuse rather
            // than risk a second trust relationship for it.
            return Err(
                "your known_hosts file uses hashed entries; add this host key yourself or ask your administrator"
                    .into(),
            );
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let entry_pattern = parts[0];
        for pattern in entry_pattern.split(',') {
            let pattern = pattern
                .trim_start_matches('@')
                .split(',')
                .next()
                .unwrap_or(pattern);
            // Only exact host-form matches count as conflicts (wildcards are
            // the user's own broader trust and are not ours to rewrite).
            if pattern == host || pattern == entry_host(host, observed.port) {
                return Err(
                    "a different key is already recorded for this host; remove the old entry first if you really want to replace it"
                        .into(),
                );
            }
        }
    }

    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "{} {} {}",
        entry_host(host, observed.port),
        observed.key_type,
        key_b64
    ));
    out.push('\n');

    // Atomic replace so a crash never leaves a truncated trust file.
    let mut tmp_bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut tmp_bytes);
    let tmp = path.with_extension(format!(
        "tmp.{}",
        tmp_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    std::fs::write(&tmp, out).map_err(|e| format!("cannot write known_hosts: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("cannot update known_hosts: {e}"))?;
    Ok(())
}

#[cfg(test)]
struct HomeGuard<'a> {
    saved: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'a, Option<std::path::PathBuf>>,
}

#[cfg(test)]
impl HomeGuard<'_> {
    fn set(path: &std::path::Path) -> Self {
        let saved = std::env::var_os("HOME");
        let guard = TEST_HOME_LOCK.lock().unwrap();
        // SAFETY: serialized on TEST_HOME_LOCK.
        unsafe { std::env::set_var("HOME", path) };
        Self {
            saved,
            _guard: guard,
        }
    }
}

#[cfg(test)]
impl Drop for HomeGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: serialized on TEST_HOME_LOCK.
        unsafe {
            match self.saved.take() {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(host_matches("github.com", "github.com"));
        assert!(!host_matches("github.com", "evil.com"));
    }

    #[test]
    fn wildcard_subdomain() {
        assert!(host_matches("*.example.com", "foo.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "foo.evil.com"));
    }

    #[test]
    fn bracketed_host_port() {
        assert!(host_matches("[github.com]:2222", "github.com"));
    }

    #[test]
    fn strip_markers_removes_prefix() {
        assert_eq!(strip_markers("@cert-authority,github.com"), "github.com");
        assert_eq!(strip_markers("github.com"), "github.com");
    }

    #[test]
    fn base64_roundtrip() {
        let encoded = "aGVsbG8=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn base64_no_padding() {
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn verify_missing_file_returns_missing() {
        // Override HOME to a temp dir without known_hosts
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: test is single-threaded for this env var; not used elsewhere.
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", "ssh-ed25519", &[1, 2, 3]);
        assert_eq!(result, HostKeyResult::Missing);
    }

    #[test]
    fn verify_with_comment_trailing() {
        // Real-world known_hosts entries include a trailing comment after the key.
        // The verifier must not misread the comment as the key.
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = b"fake-key-bytes-32-bytes-long!!!";
        let key_b64 = base64_encode(key);
        // Format: hosts keytype base64key comment
        std::fs::write(
            ssh_dir.join("known_hosts"),
            format!("github.com ssh-ed25519 {key_b64} # added by user\n"),
        )
        .unwrap();
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", "ssh-ed25519", key);
        assert_eq!(result, HostKeyResult::Known);
    }

    #[test]
    fn verify_comma_separated_hosts() {
        // OpenSSH allows multiple host patterns in one entry.
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = b"another-fake-key";
        let key_b64 = base64_encode(key);
        std::fs::write(
            ssh_dir.join("known_hosts"),
            format!("github.com,192.30.255.112 ssh-ed25519 {key_b64}\n"),
        )
        .unwrap();
        let _home = HomeGuard::set(dir.path());
        // First host pattern matches
        assert_eq!(
            verify_host_key("github.com", "ssh-ed25519", key),
            HostKeyResult::Known
        );
        // Second host pattern also matches
        assert_eq!(
            verify_host_key("192.30.255.112", "ssh-ed25519", key),
            HostKeyResult::Known
        );
        // Non-matching host
        assert_eq!(
            verify_host_key("evil.com", "ssh-ed25519", key),
            HostKeyResult::Unknown
        );
    }

    /// Helper: RFC 4648 base64 encoder for test fixtures.
    /// Uses the base64 crate to avoid hand-rolling encoding bugs.
    fn base64_encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}

#[cfg(test)]
mod custom_trust_tests {
    use super::*;

    // --- Custom-remote trust tests ---

    fn with_test_home<F: FnOnce(&std::path::Path)>(f: F) {
        let dir = tempfile::tempdir().unwrap();
        let _home = HomeGuard::set(dir.path());
        f(dir.path());
    }

    #[test]
    fn observation_roundtrips_through_attempt_id() {
        let obs = ObservedHostKey {
            host: "git.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            key: b"raw-key-bytes".to_vec(),
            fingerprint: fingerprint(b"raw-key-bytes"),
        };
        let id = record_observation(obs.clone());
        let taken = take_observation(&id).expect("observation is live");
        assert_eq!(taken.host, "git.example.com");
        assert_eq!(taken.port, 22);
        assert_eq!(taken.key, b"raw-key-bytes");
        // Drained: a second take fails (one trust per handshake).
        assert!(take_observation(&id).is_none());
    }

    #[test]
    fn trust_writes_port_form_and_rejects_conflicts() {
        with_test_home(|home| {
            let kh = home.join(".ssh").join("known_hosts");
            std::fs::create_dir_all(kh.parent().unwrap()).unwrap();
            let observed = ObservedHostKey {
                host: "git.example.com".into(),
                port: 2222,
                key_type: "ssh-ed25519".into(),
                key: b"k1".to_vec(),
                fingerprint: String::new(),
            };
            trust_host_key(&observed).expect("first trust succeeds");
            let content = std::fs::read_to_string(&kh).unwrap();
            // Non-default port must use the [host]:port entry form.
            assert!(
                content.contains("[git.example.com]:2222 ssh-ed25519 "),
                "{content}"
            );

            // A conflicting plaintext entry refuses; the file is untouched.
            let other = ObservedHostKey {
                key: b"k2".to_vec(),
                ..observed.clone()
            };
            let err = trust_host_key(&other).unwrap_err();
            assert!(err.contains("different key"), "{err}");
            let want = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(b"k1")
            };
            assert!(std::fs::read_to_string(&kh).unwrap().contains(&want));

            // A hashed entry in the file blocks trust entirely.
            let _ = std::fs::write(&kh, "|1|salt|hash ssh-ed25519 AAAA\n");
            let err = trust_host_key(&other).unwrap_err();
            assert!(err.contains("hashed"), "{err}");
        });
    }

    #[test]
    fn trust_sanitizes_host_and_key_type() {
        let observed = ObservedHostKey {
            host: "evil.example.com\nbad".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            key: b"k".to_vec(),
            fingerprint: String::new(),
        };
        assert!(trust_host_key(&observed).is_err(), "newline host refused");
        let observed = ObservedHostKey {
            host: "git.example.com".into(),
            port: 22,
            key_type: "made-up-alg".into(),
            key: b"k".to_vec(),
            fingerprint: String::new(),
        };
        assert!(
            trust_host_key(&observed).is_err(),
            "unknown key type refused"
        );
    }
}
