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
// Token file lives alongside the socket with 0600 perms.

/// Get the token file path.
/// When using default socket: uses `baluard_core::paths::token_path()`.
/// When using explicit socket: derives alongside it (non-Windows) or in data_dir (Windows).
fn token_file_path(socket_path: Option<&str>) -> PathBuf {
    match socket_path {
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
    }
}

/// Set the session token (persist to file alongside socket).
/// H6 fix: atomic creation with 0600 permissions (no TOCTOU race).
pub fn set_session_token(token: &str, socket_path: Option<&str>) {
    let path = token_file_path(socket_path);

    // Write atomically: tmp file with 0600, then rename
    let tmp = path.with_extension("tok.tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
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

/// Get the current session token (read from file).
pub fn get_session_token(socket_path: Option<&str>) -> Option<String> {
    let path = token_file_path(socket_path);
    std::fs::read_to_string(&path)
        .ok()
        .filter(|t| !t.is_empty())
}

/// Clear the session token (called after lock).
pub fn clear_session_token(socket_path: Option<&str>) {
    let path = token_file_path(socket_path);
    let _ = std::fs::remove_file(&path);
}

/// Send a request to the daemon at a specific socket path.
/// Zeroizes the payload and wire bytes after the response is received.
pub fn request_to(
    action: &str,
    payload: &str,
    socket_path: Option<&str>,
) -> Result<GatewayResponse> {
    let socket = socket_path
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("Cannot connect to daemon at {}", socket.display()))?;

    let mut req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: get_session_token(socket_path).unwrap_or_default(),
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

    // R7-2: Store session token from daemon if present
    if !response.session_token.is_empty() {
        set_session_token(&response.session_token, socket_path);
    }

    Ok(response)
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
