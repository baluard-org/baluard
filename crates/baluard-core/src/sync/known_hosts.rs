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
    /// known_hosts file missing (fail closed: reject, trust-offerable).
    Missing,
    /// known_hosts exists but cannot be read or parsed (fail closed,
    /// NOT trust-offerable: first-contact framing here would let one
    /// unreadable file silently re-arm changed-key prompts).
    Unreadable,
    /// No entry for THIS key type, but the host is known under a different
    /// type. Still trust-offerable (OpenSSH keeps one line per type), and
    /// the observation carries the hint so the trust card can say so.
    UnknownOtherType,
    /// Host key does NOT match a known_hosts entry (potential MITM).
    Mismatch,
    /// The presented key is on an @revoked line for this host.
    Revoked,
}

/// Look up `host` in known_hosts and verify the presented `key_type`/`key` match.
///
/// `key_type` is the SSH key type string (e.g. `ssh-ed25519`, `ssh-rsa`).
/// `key` is the raw host key bytes (before base64 encoding).
#[cfg(test)]
pub(crate) static TEST_HOME_LOCK: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

pub fn verify_host_key(host: &str, port: u16, key_type: &str, key: &[u8]) -> HostKeyResult {
    let path = known_hosts_path();
    // Strict read: a present-but-unparseable file must fail closed
    // (Unreadable), never look missing or partially known — a lossy
    // parse could drop the pinned line and re-arm a trust offer for a
    // changed key.
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HostKeyResult::Missing,
        Err(_) => return HostKeyResult::Unreadable,
    };

    let mut found_match = false;
    let mut other_type_seen = false;
    let mut mismatch_seen = false;
    let mut revoked_presented = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // OpenSSH marker form: `@marker hostpattern keytype key` with the
        // marker as its OWN field. Older comma-joined forms (`@revoked,host`)
        // are still accepted for compatibility. Markers are scanned BEFORE
        // the hashed dispatch because ssh-keygen -H hashes marker lines too.
        let mut idx = 0usize;
        let mut marker_revoked = false;
        let mut marker_ca = false;
        while idx < parts.len() && parts[idx].starts_with('@') {
            match parts[idx] {
                "@revoked" => marker_revoked = true,
                "@cert-authority" => marker_ca = true,
                _ => {}
            }
            idx += 1;
        }
        if marker_ca {
            // CA chains are not host keys; we verify host keys only.
            continue;
        }
        // Hashed entries (|1|salt|hash): Debian/Ubuntu default to
        // HashKnownHosts yes, so skipping them would blind the verifier to
        // existing trust. Match by HMAC-SHA1 over the exact host form.
        if parts[idx].starts_with("|1|") {
            let rest = parts[idx..].join(" ");
            if let Some(verdict) = verify_hashed_entry(&rest, host, port, key_type, key) {
                match verdict {
                    HashedVerdict::Known => {
                        if marker_revoked {
                            revoked_presented = true;
                        } else {
                            found_match = true;
                        }
                    }
                    // Keep scanning: a hashed old-key line must not mask a
                    // later valid line (same rule as the plaintext arm).
                    HashedVerdict::Changed => mismatch_seen = true,
                    HashedVerdict::OtherType => {
                        if !marker_revoked {
                            other_type_seen = true;
                        }
                    }
                    HashedVerdict::OtherHost => {}
                }
            }
            continue;
        }
        if idx >= parts.len() - 2 {
            continue;
        }
        let (has_revoked_marker, host_patterns, entry_key_type, entry_key_b64) = if idx > 0 {
            (
                marker_revoked,
                parts[idx].split(',').collect::<Vec<_>>(),
                parts[idx + 1],
                parts[idx + 2],
            )
        } else {
            let first_field = parts[0];
            let mut legacy_revoked = false;
            let hosts: Vec<&str> = first_field
                .split(',')
                .filter(|seg| {
                    if *seg == "@revoked" {
                        legacy_revoked = true;
                        false
                    } else {
                        !seg.starts_with('@')
                    }
                })
                .collect();
            (legacy_revoked, hosts, parts[1], parts[2])
        };

        // Check if ANY of the comma-separated host patterns match.
        let any_match = host_patterns.iter().any(|p| host_matches(p, host, port));
        if !any_match {
            continue;
        }
        // Same host under a different key type is a NEW key, not a changed
        // one (OpenSSH keeps one line per type; libssh2 does not reorder its
        // preference from known_hosts). Only the same type with different
        // bytes is the MITM signal. A revoked line says nothing about the
        // type of a key that is not the revoked one.
        if entry_key_type != key_type {
            if !has_revoked_marker {
                other_type_seen = true;
            }
            continue;
        }
        // Base64-decode the key (with and without padding)
        let Ok(entry_key) = base64_decode(entry_key_b64) else {
            continue;
        };
        if entry_key == key {
            if has_revoked_marker {
                revoked_presented = true;
            } else {
                found_match = true;
            }
        } else if !has_revoked_marker {
            // Keep scanning: OpenSSH accepts if ANY line matches, so an
            // old-key line must not mask a later valid line. A revoked
            // line for a DIFFERENT key is not evidence of a changed key.
            mismatch_seen = true;
        }
    }

    if revoked_presented {
        HostKeyResult::Revoked
    } else if found_match {
        HostKeyResult::Known
    } else if mismatch_seen {
        HostKeyResult::Mismatch
    } else if other_type_seen {
        HostKeyResult::UnknownOtherType
    } else {
        HostKeyResult::Unknown
    }
}

/// Verdict for a hashed known_hosts line against the live handshake.
enum HashedVerdict {
    Known,
    Changed,
    OtherHost,
    /// Our host under a different key type.
    OtherType,
}

/// OpenSSH hashed-entry form: `|1|base64(salt)|base64(HMAC-SHA1(salt, host))`.
/// The hashed string is whatever host form was written (bare or `[h]:port`),
/// so both candidate forms are tried.
fn verify_hashed_entry(
    line: &str,
    host: &str,
    port: u16,
    key_type: &str,
    key: &[u8],
) -> Option<HashedVerdict> {
    use base64::Engine as _;
    use hmac::Mac;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    // fields[0] is "|1|<salt>|<hash>"; split('|') would yield a leading
    // empty piece, so strip the prefix instead.
    let rest = fields[0].strip_prefix("|1|")?;
    let mut parts = rest.split('|');
    let salt = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    let digest = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;

    type HmacSha1 = hmac::Hmac<sha1::Sha1>;
    let expected = HmacSha1::new_from_slice(&salt).ok();
    let host_matches_hash = move |candidate: &str| -> bool {
        let Some(mut mac) = expected.clone() else {
            return false;
        };
        mac.update(candidate.as_bytes());
        mac.finalize().into_bytes().as_slice() == digest.as_slice()
    };
    // The hashed string is the exact host form OpenSSH hashed at write time:
    // bare for port 22, [host]:port otherwise. Trying both forms would let a
    // bare port-22 entry false-Mismatch a port-2222 handshake.
    let bare = host.to_string();
    let ported = format!("[{host}]:{port}");
    let is_our_host = if port == 22 {
        host_matches_hash(&bare)
    } else {
        host_matches_hash(&ported)
    };
    if !is_our_host {
        return Some(HashedVerdict::OtherHost);
    }
    // Same host: the key type and bytes decide.
    let entry_key = base64::engine::general_purpose::STANDARD
        .decode(fields[2])
        .ok()?;
    if fields[1] == key_type {
        if entry_key == key {
            Some(HashedVerdict::Known)
        } else {
            Some(HashedVerdict::Changed)
        }
    } else {
        // Different type under our hashed host: a new key, not a changed one.
        Some(HashedVerdict::OtherType)
    }
}

/// Locate the known_hosts file. `$HOME/.ssh/known_hosts` (or the Windows
/// profile equivalent) when a home directory exists; otherwise the app data
/// dir (mobile has no `$HOME` — the NMH/UniFFI processes set
/// `BALUARD_DATA_DIR`). Returns the canonical path even if the file does not
/// exist (caller handles the read failure).
fn known_hosts_path() -> PathBuf {
    // Some Android contexts set HOME to / or /data; the app data dir is the
    // only writable, app-scoped location there.
    if !cfg!(target_os = "android") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".ssh").join("known_hosts");
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join(".ssh").join("known_hosts");
    }
    crate::paths::data_dir().join("known_hosts")
}

/// Check if `pattern` (from known_hosts) matches the connection `host`.
/// Supports exact match, `[host]:port` form, and trailing `*` wildcard.
/// Trusting `[h]:2222` must not trust h:22 (and vice versa), so a bare
/// pattern only ever matches the default port and bracketed forms only
/// match their exact port.
fn host_matches(pattern: &str, host: &str, port: u16) -> bool {
    if let Some(rest) = pattern.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        let pattern_host = &rest[..close];
        let pattern_port: u16 = rest[close + 1..]
            .trim_start_matches(':')
            .parse()
            .unwrap_or(22);
        return pattern_port == port && pattern_host == host;
    }
    if port != 22 {
        return false;
    }

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
    /// True when the host was already known under the same key type with
    /// DIFFERENT bytes — a possible MITM. Changed observations power the
    /// warning surface only; the trust route refuses them, so a changed key
    /// can never be blessed one-click.
    pub changed: bool,
    /// True when known_hosts already holds the host under a DIFFERENT key
    /// type. Purely informational: the trust offer is still valid, the
    /// surface just says so.
    pub known_other_type: bool,
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
    // An unreadable key cannot be fingerprinted or trusted later; recording
    // it would mint an attempt id for a bogus entry.
    if observed.key.is_empty() {
        return String::new();
    }
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
/// The most recent live observation, cloned (NOT drained): error surfaces
/// need the fingerprint + attempt id to decorate failures, but the trust
/// route consumes the observation by id afterwards.
pub fn peek_latest_observation() -> Option<(String, ObservedHostKey)> {
    let mut pending = pending_observations().lock().expect("pending lock");
    let now = std::time::Instant::now();
    pending.retain(|(_, p)| now.duration_since(p.at).as_secs() < OBSERVATION_TTL_SECS);
    let (id, p) = pending.last()?;
    Some((id.clone(), p.observed.clone()))
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
    if observed.changed {
        return Err(
            "this host key changed; if you are sure, remove the old line from your SSH known_hosts file"
                .into(),
        );
    }
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

    // A read failure here is NOT an empty file: overwriting it with a
    // one-line file would destroy every other pin and @revoked entry.
    // Strict decode too — a lossy read would write U+FFFD replacements
    // back over bytes we never verified.
    let existing = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read your known_hosts file: {e}")),
    };
    for line in existing.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("|1|") {
            // With hashed matching implemented, only a hashed entry FOR THIS
            // host blocks (its key bytes/type cannot be safely rewritten); an
            // unrelated hashed line is none of ours.
            if let Some(HashedVerdict::Known | HashedVerdict::Changed) =
                verify_hashed_entry(line, host, observed.port, &observed.key_type, &observed.key)
            {
                return Err(
                    "your known_hosts file already has a hashed entry for this host; add this host key yourself or ask your administrator"
                        .into(),
                );
            }
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let entry_pattern = parts[0];
        let entry_type = parts[1];
        for pattern in entry_pattern.split(',') {
            let pattern = pattern
                .trim_start_matches('@')
                .split(',')
                .next()
                .unwrap_or(pattern);
            // Only exact host-form matches count as conflicts, scoped to the
            // same key type (a second type is a new line, like OpenSSH).
            // Wildcards are the user's own broader trust, not ours to rewrite.
            if (pattern == host || pattern == entry_host(host, observed.port))
                && entry_type == observed.key_type
            {
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
        assert!(host_matches("github.com", "github.com", 22));
        assert!(!host_matches("github.com", "evil.com", 22));
    }

    #[test]
    fn wildcard_subdomain() {
        assert!(host_matches("*.example.com", "foo.example.com", 22));
        assert!(!host_matches("*.example.com", "example.com", 22));
        assert!(!host_matches("*.example.com", "foo.evil.com", 22));
    }

    #[test]
    fn bracketed_host_port() {
        assert!(host_matches("[github.com]:2222", "github.com", 2222));
    }

    #[test]
    fn trust_does_not_cross_ports() {
        assert!(!host_matches("github.com", "github.com", 2222));
        assert!(!host_matches("[github.com]:2222", "github.com", 22));
        assert!(!host_matches("[github.com]:2222", "github.com", 2200));
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
    fn unreadable_known_hosts_fails_closed_not_first_contact() {
        // A file that cannot be read (bad permissions, invalid encoding
        // bytes) must not look like a missing file: the Missing verdict
        // re-arms first-contact trust and silently disables changed-key
        // detection for every pinned host.
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Invalid UTF-8 byte in what used to be a comment.
        std::fs::write(ssh_dir.join("known_hosts"), b"\xff\xfe broken\n").unwrap();
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", 22, "ssh-ed25519", &[1, 2, 3]);
        assert_eq!(result, HostKeyResult::Unreadable);
    }

    #[test]
    fn revoked_key_refuses_even_when_bytes_match() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = b"revoked-key-material";
        let key_b64 = base64_encode(key);
        // OpenSSH marker form: @revoked is its own field.
        std::fs::write(
            ssh_dir.join("known_hosts"),
            format!("@revoked github.com ssh-ed25519 {key_b64}\n"),
        )
        .unwrap();
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", 22, "ssh-ed25519", key);
        assert_eq!(result, HostKeyResult::Revoked);
    }

    #[test]
    fn revoked_old_key_does_not_mask_a_valid_new_line() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let old = base64_encode(b"the-old-revoked-key");
        let new = base64_encode(b"the-new-valid-key");
        std::fs::write(
            ssh_dir.join("known_hosts"),
            format!("@revoked github.com ssh-ed25519 {old}\ngithub.com ssh-ed25519 {new}\n"),
        )
        .unwrap();
        let _home = HomeGuard::set(dir.path());
        assert_eq!(
            verify_host_key("github.com", 22, "ssh-ed25519", b"the-new-valid-key"),
            HostKeyResult::Known
        );
        assert_eq!(
            verify_host_key("github.com", 22, "ssh-ed25519", b"the-old-revoked-key"),
            HostKeyResult::Revoked
        );
    }

    #[test]
    fn revoked_hashed_entry_refuses() {
        // ssh-keygen -H hashes marker lines too; a revoked hashed entry
        // must refuse, not silently fall through as unknown.
        use base64::Engine as _;
        type HmacSha1 = hmac::Hmac<sha1::Sha1>;
        use hmac::Mac as _;
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = b"hashed-revoked-key";
        let salt = [7u8; 16];
        let mut mac = HmacSha1::new_from_slice(&salt).unwrap();
        mac.update(b"github.com");
        let digest = mac.finalize().into_bytes();
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let line = format!(
            "@revoked |1|{}|{} ssh-ed25519 {}",
            b64(&salt),
            b64(&digest),
            b64(key)
        );
        std::fs::write(ssh_dir.join("known_hosts"), format!("{line}\n")).unwrap();
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", 22, "ssh-ed25519", key);
        assert_eq!(result, HostKeyResult::Revoked);
    }

    #[test]
    fn port_scoped_plaintext_trust() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = b"port-scoped-key";
        let key_b64 = base64_encode(key);
        std::fs::write(
            ssh_dir.join("known_hosts"),
            format!("[git.example.com]:2222 ssh-ed25519 {key_b64}\n"),
        )
        .unwrap();
        let _home = HomeGuard::set(dir.path());
        assert_eq!(
            verify_host_key("git.example.com", 2222, "ssh-ed25519", key),
            HostKeyResult::Known
        );
        // Plain-port trust must not leak to the bracketed entry's port or
        // vice versa.
        assert_eq!(
            verify_host_key("git.example.com", 22, "ssh-ed25519", key),
            HostKeyResult::Unknown
        );
    }

    #[test]
    fn verify_missing_file_returns_missing() {
        // Override HOME to a temp dir without known_hosts
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: test is single-threaded for this env var; not used elsewhere.
        let _home = HomeGuard::set(dir.path());
        let result = verify_host_key("github.com", 22, "ssh-ed25519", &[1, 2, 3]);
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
        let result = verify_host_key("github.com", 22, "ssh-ed25519", key);
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
            verify_host_key("github.com", 22, "ssh-ed25519", key),
            HostKeyResult::Known
        );
        // Second host pattern also matches
        assert_eq!(
            verify_host_key("192.30.255.112", 22, "ssh-ed25519", key),
            HostKeyResult::Known
        );
        // Non-matching host
        assert_eq!(
            verify_host_key("evil.com", 22, "ssh-ed25519", key),
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
            changed: false,
            known_other_type: false,
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
                changed: false,
                known_other_type: false,
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

            // A hashed entry FOR THIS HOST blocks trust (its key bytes and
            // type cannot be safely rewritten); unrelated hashed entries are
            // none of ours.
            let salt = [7u8; 16];
            use hmac::Mac;
            type HmacSha1 = hmac::Hmac<sha1::Sha1>;
            let mut mac = HmacSha1::new_from_slice(&salt).unwrap();
            mac.update(b"[git.example.com]:2222");
            let digest = mac.finalize().into_bytes();
            use base64::Engine as _;
            let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let hashed_line = format!(
                "|1|{}|{} ssh-ed25519 {}",
                enc(&salt),
                enc(&digest),
                enc(b"k2")
            );
            let _ = std::fs::write(&kh, hashed_line + "\n");
            let err = trust_host_key(&other).unwrap_err();
            assert!(err.contains("hashed"), "{err}");
            // An unrelated hashed entry (different host) does not block.
            let mut mac2 = HmacSha1::new_from_slice(&salt).unwrap();
            mac2.update(b"other.example.com");
            let other_line = format!(
                "|1|{}|{} ssh-ed25519 {}",
                enc(&salt),
                enc(mac2.finalize().into_bytes().as_slice()),
                enc(b"k3")
            );
            let _ = std::fs::write(&kh, other_line + "\n");
            // (same key as the recorded one would conflict only on plaintext;
            // here the file has no plaintext entry, so trust appends)
            assert!(trust_host_key(&other).is_ok());
        });
    }

    #[test]
    fn hashed_entries_match_and_change_refuses() {
        with_test_home(|home| {
            let kh = home.join(".ssh").join("known_hosts");
            std::fs::create_dir_all(kh.parent().unwrap()).unwrap();
            use hmac::Mac;
            type HmacSha1 = hmac::Hmac<sha1::Sha1>;
            use base64::Engine as _;
            let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let salt = [9u8; 16];
            let mut mac = HmacSha1::new_from_slice(&salt).unwrap();
            mac.update(b"git.example.com");
            let line = format!(
                "|1|{}|{} ssh-ed25519 {}",
                enc(&salt),
                enc(mac.finalize().into_bytes().as_slice()),
                enc(b"k1")
            );
            std::fs::write(&kh, line + "\n").unwrap();
            // Same host + same type + same bytes: Known despite hashing.
            assert_eq!(
                verify_host_key("git.example.com", 22, "ssh-ed25519", b"k1"),
                HostKeyResult::Known
            );
            // Same type, different bytes: Mismatch (changed key).
            assert_eq!(
                verify_host_key("git.example.com", 22, "ssh-ed25519", b"k2"),
                HostKeyResult::Mismatch
            );
            // Different type under our hashed host: a new key, not changed.
            assert_eq!(
                verify_host_key("git.example.com", 22, "ssh-rsa", b"k1"),
                HostKeyResult::UnknownOtherType
            );
        });
    }

    #[test]
    fn different_key_type_on_plaintext_host_is_unknown_other_type() {
        with_test_home(|home| {
            let kh = home.join(".ssh").join("known_hosts");
            std::fs::create_dir_all(kh.parent().unwrap()).unwrap();
            use base64::Engine as _;
            let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let line = format!("git.example.com ssh-ed25519 {}", enc(b"k1"));
            std::fs::write(&kh, line + "\n").unwrap();
            assert_eq!(
                verify_host_key("git.example.com", 22, "ssh-ed25519", b"k2"),
                HostKeyResult::Mismatch
            );
            assert_eq!(
                verify_host_key("git.example.com", 22, "ssh-rsa", b"k1"),
                HostKeyResult::UnknownOtherType
            );
        });
    }

    #[test]
    fn hashed_bare_entry_for_port_22_never_matches_non_default_port() {
        with_test_home(|home| {
            let kh = home.join(".ssh").join("known_hosts");
            std::fs::create_dir_all(kh.parent().unwrap()).unwrap();
            use hmac::Mac;
            type HmacSha1 = hmac::Hmac<sha1::Sha1>;
            use base64::Engine as _;
            let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let salt = [5u8; 16];
            let mut mac = HmacSha1::new_from_slice(&salt).unwrap();
            // The entry hashes the BARE host (a port-22 trust).
            mac.update(b"git.example.com");
            let line = format!(
                "|1|{}|{} ssh-ed25519 {}",
                enc(&salt),
                enc(mac.finalize().into_bytes().as_slice()),
                enc(b"k1")
            );
            std::fs::write(&kh, line + "\n").unwrap();
            // A port-2222 handshake on the same host must NOT inherit it.
            assert_eq!(
                verify_host_key("git.example.com", 2222, "ssh-ed25519", b"k1"),
                HostKeyResult::Unknown
            );
        });
    }

    #[test]
    fn known_other_type_hint_signals_on_plaintext_entries() {
        with_test_home(|home| {
            // The host is known as ssh-ed25519; a handshake offering a
            // different type is trust-offerable but must carry the hint.
            let ssh = home.join(".ssh");
            std::fs::create_dir_all(&ssh).unwrap();
            use base64::Engine as _;
            let k1 = crate::crypto::signature::generate_ed25519_keypair();
            let pub1 = k1.1.as_bytes().to_vec();
            let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            std::fs::write(
                ssh.join("known_hosts"),
                format!("git.example.com ssh-ed25519 {}\n", enc(&pub1)),
            )
            .unwrap();
            assert!(matches!(
                verify_host_key("git.example.com", 22, "ssh-ed25519", &pub1),
                HostKeyResult::Known
            ));
            assert!(matches!(
                verify_host_key("git.example.com", 22, "ecdsa-sha2-nistp256", b"other-key"),
                HostKeyResult::UnknownOtherType
            ));
            // A host with no entry at all stays a plain Unknown.
            assert!(matches!(
                verify_host_key("other.example.com", 22, "ssh-ed25519", &pub1),
                HostKeyResult::Unknown
            ));
        });
    }

    #[test]
    fn known_other_type_hint_signals_on_hashed_entries() {
        with_test_home(|home| {
            let ssh = home.join(".ssh");
            std::fs::create_dir_all(&ssh).unwrap();
            use base64::Engine as _;
            use hmac::Mac;
            type HmacSha1 = hmac::Hmac<sha1::Sha1>;
            let salt = b"0123456789abcdef";
            let mac_of = |candidate: &str| -> String {
                let mut mac = HmacSha1::new_from_slice(salt).unwrap();
                mac.update(candidate.as_bytes());
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
            };
            let k1 = crate::crypto::signature::generate_ed25519_keypair();
            let pub1 = k1.1.as_bytes().to_vec();
            let enc = base64::engine::general_purpose::STANDARD.encode(&pub1);
            let hashed_host = format!(
                "|1|{}|{}",
                base64::engine::general_purpose::STANDARD.encode(salt),
                mac_of("git.example.com")
            );
            std::fs::write(
                ssh.join("known_hosts"),
                format!("{hashed_host} ssh-ed25519 {enc}\n"),
            )
            .unwrap();
            assert!(matches!(
                verify_host_key("git.example.com", 22, "ecdsa-sha2-nistp256", b"other"),
                HostKeyResult::UnknownOtherType
            ));
        });
    }

    #[test]
    fn trust_then_verify_roundtrip_is_known() {
        with_test_home(|_home| {
            let observed = ObservedHostKey {
                host: "127.0.0.1".into(),
                port: 22299,
                key_type: "ssh-ed25519".into(),
                key: b"k1".to_vec(),
                fingerprint: fingerprint(b"k1"),
                changed: false,
                known_other_type: false,
            };
            trust_host_key(&observed).expect("trust");
            assert_eq!(
                verify_host_key("127.0.0.1", 22299, "ssh-ed25519", b"k1"),
                HostKeyResult::Known
            );
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
            changed: false,
            known_other_type: false,
        };
        assert!(trust_host_key(&observed).is_err(), "newline host refused");
        let observed = ObservedHostKey {
            host: "git.example.com".into(),
            port: 22,
            key_type: "made-up-alg".into(),
            key: b"k".to_vec(),
            fingerprint: String::new(),
            changed: false,
            known_other_type: false,
        };
        assert!(
            trust_host_key(&observed).is_err(),
            "unknown key type refused"
        );
    }
}
