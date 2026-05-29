//! Socket client for communicating with idtty-daemon.
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

/// Default socket filename.
const SOCKET_NAME: &str = "idtty.sock";

/// Get the default socket path for this platform.
fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let dir = PathBuf::from(xdg);
            if dir.is_dir() {
                return dir.join(SOCKET_NAME);
            }
        }
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("idtty")
                .join(SOCKET_NAME);
        }
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\idtty")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/tmp").join(SOCKET_NAME)
    }
}

/// Generated Protobuf types
mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/idtty.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

// R7-2: Session token received from daemon after unlock.
// Stored in thread-local so all subsequent requests in this process
// automatically include it.
thread_local! {
    static SESSION_TOKEN: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Set the session token (called after successful unlock/create).
pub fn set_session_token(token: &str) {
    SESSION_TOKEN.with(|t| *t.borrow_mut() = Some(token.to_string()));
}

/// Get the current session token.
pub fn get_session_token() -> Option<String> {
    SESSION_TOKEN.with(|t| t.borrow().clone())
}

/// Clear the session token (called after lock).
pub fn clear_session_token() {
    SESSION_TOKEN.with(|t| *t.borrow_mut() = None);
}

/// Send a request to the daemon at a specific socket path.
/// Zeroizes the payload and wire bytes after the response is received.
pub fn request_to(action: &str, payload: &str, socket_path: Option<&str>) -> Result<GatewayResponse> {
    let socket = socket_path
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("Cannot connect to daemon at {}", socket.display()))?;

    let mut req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: get_session_token().unwrap_or_default(),
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
    let (resp_len, offset) = decode_varint_checked(&buf)
        .context("Invalid response varint")?;

    let resp_end = offset + resp_len as usize;
    if resp_end > buf.len() {
        bail!("Response frame truncated: declared {} bytes but only {} available",
              resp_len, buf.len() - offset);
    }

    let resp_data = &buf[offset..resp_end];
    let response = GatewayResponse::decode(resp_data)
        .context("Failed to decode daemon response")?;

    // R7-2: Store session token from daemon if present
    if !response.session_token.is_empty() {
        set_session_token(&response.session_token);
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
