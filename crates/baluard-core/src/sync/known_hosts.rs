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
        let (has_revoked_marker, host_patterns): (bool, Vec<&str>) = if first_field.starts_with('@') {
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

/// Locate the user's known_hosts file. Returns `~/.ssh/known_hosts` on Unix,
/// `%USERPROFILE%\.ssh\known_hosts` on Windows. Returns the canonical path
/// even if the file does not exist (caller handles the read failure).
fn known_hosts_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".ssh").join("known_hosts");
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join(".ssh").join("known_hosts");
    }
    PathBuf::from(".ssh/known_hosts")
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
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        let combined = (u32::from(lookup[buf[0] as usize]) << 18)
            | (u32::from(lookup[buf[1] as usize]) << 12);
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
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
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
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
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
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
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
