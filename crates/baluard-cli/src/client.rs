//! Socket client for communicating with baluard-daemon.
//!
//! Serializes GatewayRequest via Protobuf, sends to Unix socket,
//! deserializes GatewayResponse. Length-delimited wire protocol
//! matching the daemon's handler.

use anyhow::{Context, Result, bail};
use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Get the default socket path for this platform.
fn default_socket_path() -> PathBuf {
    baluard_core::paths::socket_path()
}

/// Generated Protobuf types
mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

// R7-2: Session token persisted to a file so it survives across CLI invocations.
// Each `cargo run` is a separate process; thread-local storage dies with it.

// Phase 6 / M2: process-global vault slug override set by `--vault <slug>`.
// When set, every daemon request carries this slug via the proto `slug` field
// so the daemon routes to that vault WITHOUT mutating the global active
// pointer or registry `last_opened`. Read-only commands (list/get) thus stay
// side-effect-free. CLI invocations are single-process, so a OnceLock is safe.
static VAULT_SLUG_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Set the `--vault <slug>` override for this process. Called once from
/// main() before dispatching the command.
pub fn set_vault_slug_override(slug: &str) {
    let _ = VAULT_SLUG_OVERRIDE.set(slug.to_string());
}

/// The active `--vault` slug override, if any.
pub fn vault_slug_override() -> Option<&'static str> {
    VAULT_SLUG_OVERRIDE.get().map(|s| s.as_str())
}
// Token file fallback lives alongside the socket with 0600 perms.

/// Get the token file path.
///
/// NEW-3: when a `--vault <slug>` override is active, the token file is
/// slug-specific so each vault unlocked via the CLI keeps its own token.
/// Without this, `baluard --vault work list` would send whatever token
/// happened to be on file (the last-unlocked vault's), which the daemon
/// rejects per-vault. The slug-specific file sits alongside the default
/// token file with a `.<slug>` suffix.
///
/// When using default socket: uses `baluard_core::paths::token_path()` as
/// the base. When using explicit socket: derives alongside it (non-Windows)
/// or in data_dir (Windows).
fn token_file_path(socket_path: Option<&str>) -> PathBuf {
    token_file_path_for(socket_path, vault_slug_override())
}

/// Same as `token_file_path` but with an explicit slug (used internally so
/// the override is read exactly once per call).
fn token_file_path_for(socket_path: Option<&str>, slug: Option<&str>) -> PathBuf {
    let base = match socket_path {
        None => baluard_core::paths::token_path(),
        Some(p) => {
            let sock = PathBuf::from(p);
            #[cfg(windows)]
            {
                baluard_core::paths::data_dir()
                    .join(sock.file_name().unwrap_or_default())
                    .with_extension("tok")
            }
            #[cfg(not(windows))]
            {
                sock.with_extension("tok")
            }
        }
    };
    match slug.filter(|s| !s.is_empty()) {
        // Insert a `.<slug>` segment before the `.tok` extension so per-vault
        // tokens coexist with the default (active-vault) token file.
        Some(s) => {
            let with_slug = format!("{}.{}.tok", base.with_extension("").to_string_lossy(), s);
            PathBuf::from(with_slug)
        }
        None => base,
    }
}

// ── Session token storage (C2) ──
// The session token is a vault capability: whoever holds it can read the
// unlocked vault through the 0600 socket. It must NOT sit in a file any
// same-UID process can read (threat-model invariant 1). Primary store:
// OS keyring, one entry per (socket, vault slug). Fallback: the legacy
// token file, used only when the keyring is unavailable (headless/CI) or
// disabled via BALUARD_DISABLE_KEYRING=1 — in fallback mode CLI unlock is
// documented as trust-equivalent to same-user (see threat-model T2).

const TOKEN_SERVICE: &str = "baluard-cli";

/// Keyring account for a (socket, slug) pair. Human-readable on purpose:
/// `security find-generic-password -s baluard-cli` names the owner socket.
fn keyring_account(socket_path: Option<&str>, slug: Option<&str>) -> String {
    let sock = socket_path
        .map(str::to_string)
        .unwrap_or_else(|| default_socket_path().to_string_lossy().into_owned());
    match slug.filter(|s| !s.is_empty()) {
        Some(s) => format!("session:{sock}:{s}"),
        None => format!("session:{sock}"),
    }
}

fn token_keyring_entry(socket_path: Option<&str>, slug: Option<&str>) -> Option<keyring::Entry> {
    if baluard_core::keyring_disabled() {
        return None;
    }
    keyring::Entry::new(TOKEN_SERVICE, &keyring_account(socket_path, slug)).ok()
}

/// Set the session token (keyring first, file fallback).
/// The atomic 0600 file write stays as the fallback path (H6: no TOCTOU).
pub fn set_session_token(token: &str, socket_path: Option<&str>) {
    if let Some(entry) = token_keyring_entry(socket_path, vault_slug_override()) {
        if entry.set_password(token).is_ok() {
            // A stale fallback token from a previous keyring-less run must
            // not linger on disk now that the keyring holds the capability.
            let _ = std::fs::remove_file(token_file_path(socket_path));
            return;
        }
    }
    write_token_file(token, socket_path);
}

fn write_token_file(token: &str, socket_path: Option<&str>) {
    let path = token_file_path(socket_path);

    // Write atomically: tmp file with 0600, then rename
    let tmp = path.with_extension("tok.tmp");

    // Remove stale tmp from prior crash
    let _ = std::fs::remove_file(&tmp);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // create_new(true): fails if file exists (prevents symlink following)
        // mode(0o600): created with restrictive perms from the start
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
        {
            if f.write_all(token.as_bytes()).is_err() {
                let _ = std::fs::remove_file(&tmp);
                return;
            }
        } else {
            return;
        }
    }
    #[cfg(not(unix))]
    {
        if std::fs::write(&tmp, token).is_err() {
            return;
        }
    }

    let _ = std::fs::rename(&tmp, &path);
}

/// Get the current session token (keyring first, file fallback).
pub fn get_session_token(socket_path: Option<&str>) -> Option<String> {
    if let Some(entry) = token_keyring_entry(socket_path, vault_slug_override()) {
        if let Ok(token) = entry.get_password() {
            if !token.is_empty() {
                return Some(token);
            }
        }
    }
    let path = token_file_path(socket_path);
    std::fs::read_to_string(&path)
        .ok()
        .filter(|t| !t.is_empty())
}

/// Clear the session token (called after lock). Removes both stores so a
/// switch between keyring and fallback modes never leaves a stale copy.
pub fn clear_session_token(socket_path: Option<&str>) {
    if let Some(entry) = token_keyring_entry(socket_path, vault_slug_override()) {
        let _ = entry.delete_credential();
    }
    let _ = std::fs::remove_file(token_file_path(socket_path));
}

/// Send a request to the daemon at a specific socket path.
/// Zeroizes the payload and wire bytes after the response is received.
///
/// `slug` (Phase 6 / M2): target vault for this request. When set, the daemon
/// routes to that vault via `req.slug` WITHOUT mutating the global active
/// pointer — so read-only commands stay side-effect-free. Empty = active.
pub fn request_to(
    action: &str,
    payload: &str,
    socket_path: Option<&str>,
) -> Result<GatewayResponse> {
    request_to_with_slug(
        action,
        payload,
        socket_path,
        vault_slug_override().unwrap_or(""),
    )
}

fn request_to_with_slug(
    action: &str,
    payload: &str,
    socket_path: Option<&str>,
    slug: &str,
) -> Result<GatewayResponse> {
    let token = get_session_token(socket_path).unwrap_or_default();
    request_with_session(action, payload, socket_path, slug, token, true)
}

/// D80 agent calls never load or persist the user's stored session token.
/// The daemon socket is pinned to the default path for this surface.
pub fn request_agent(action: &str, payload: &str, token: &str) -> Result<GatewayResponse> {
    request_with_session(
        action,
        payload,
        None,
        vault_slug_override().unwrap_or(""),
        token.to_string(),
        false,
    )
}

fn request_with_session(
    action: &str,
    payload: &str,
    socket_path: Option<&str>,
    slug: &str,
    session_token: String,
    persist_response_token: bool,
) -> Result<GatewayResponse> {
    let socket = socket_path
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("Cannot connect to daemon at {}", socket.display()))?;

    let mut req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token,
        slug: slug.to_string(),
        ipc_version: baluard_core::IPC_PROTOCOL_VERSION,
    };
    let mut body = req.encode_to_vec();

    // Write varint-length-prefixed frame
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    stream.write_all(&header)?;
    stream.write_all(&body)?;
    stream.flush()?;

    // Shutdown write side so daemon sees EOF on its read
    stream.shutdown(std::net::Shutdown::Write)?;

    // Zeroize wire bytes and request payload (password may be in payload)
    body.zeroize();
    req.payload.zeroize();

    // Read full response
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf)?;

    if buf.is_empty() {
        bail!("Daemon closed connection without response");
    }

    // Decode varint length with bounds checking
    let (resp_len, offset) = decode_varint_checked(&buf).context("Invalid response varint")?;

    let resp_end = offset + resp_len as usize;
    if resp_end > buf.len() {
        bail!(
            "Response frame truncated: declared {} bytes but only {} available",
            resp_len,
            buf.len() - offset
        );
    }

    let resp_data = &buf[offset..resp_end];
    let response =
        GatewayResponse::decode(resp_data).context("Failed to decode daemon response")?;

    // Reverse handshake gate: a daemon whose IPC range excludes this
    // client would misparse every payload, so refuse up front with a
    // clean message. All-zero means a pre-field daemon (version 1).
    check_daemon_ipc_range(
        response.ipc_version,
        response.ipc_min_version,
        response.ipc_max_version,
    )?;

    // R7-2: Store session token from daemon if present
    if persist_response_token && !response.session_token.is_empty() {
        set_session_token(&response.session_token, socket_path);
    }

    Ok(response)
}

/// Reverse IPC gate: refuse when the daemon's supported range excludes
/// this client's protocol version. All-zero fields mean a pre-field
/// daemon, which speaks version 1.
fn check_daemon_ipc_range(cur: u32, min: u32, max: u32) -> Result<()> {
    let (cur, min, max) = if cur == 0 && min == 0 && max == 0 {
        (1, 1, 1)
    } else {
        (cur, min, max)
    };
    if !(min..=max).contains(&baluard_core::IPC_PROTOCOL_VERSION) {
        bail!(
            "daemon speaks IPC protocol {cur} (supports {min}-{max}); this client speaks {}; update Baluard",
            baluard_core::IPC_PROTOCOL_VERSION
        );
    }
    Ok(())
}

fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Decode a varint with overflow and bounds checking.
fn decode_varint_checked(data: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        value |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift >= 70 {
            bail!("Varint overflow in response");
        }
    }
    bail!("Incomplete varint in response (truncated)");
}

#[cfg(test)]
mod c2_tests {
    use super::*;

    #[test]
    fn keyring_account_names_socket_and_slug() {
        assert!(keyring_account(None, None).starts_with("session:"));
        assert_eq!(
            keyring_account(Some("/tmp/s.sock"), None),
            "session:/tmp/s.sock"
        );
        assert_eq!(
            keyring_account(Some("/tmp/s.sock"), Some("work")),
            "session:/tmp/s.sock:work"
        );
        // Empty slug collapses to the socket-only account (matches
        // token_file_path_for's filter).
        assert_eq!(
            keyring_account(Some("/tmp/s.sock"), Some("")),
            "session:/tmp/s.sock"
        );
    }

    #[test]
    fn token_file_fallback_roundtrip() {
        // Under cfg(test) keyring_disabled() is true for core; set the env var
        // so CLI test runs also skip the OS keyring in headless/CI environments.
        unsafe { std::env::set_var("BALUARD_DISABLE_KEYRING", "1") };
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("d.sock");
        let sp = sock.to_str().map(str::to_string);

        set_session_token("cap-token-123", sp.as_deref());
        assert_eq!(
            get_session_token(sp.as_deref()).as_deref(),
            Some("cap-token-123")
        );

        clear_session_token(sp.as_deref());
        assert_eq!(get_session_token(sp.as_deref()), None);
        // Fallback file must be gone after clear, not just empty.
        assert!(!token_file_path(sp.as_deref()).exists());
    }
}
