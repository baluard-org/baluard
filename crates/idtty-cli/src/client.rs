//! Socket client for communicating with idtty-daemon.
//!
//! Serializes GatewayRequest via Protobuf, sends to Unix socket,
//! deserializes GatewayResponse. Length-delimited wire protocol
//! matching the daemon's handler.

use anyhow::{Context, Result};
use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

const DEFAULT_SOCKET_PATH: &str = "/tmp/idtty.sock";

/// Generated Protobuf types
mod proto {
    include!(concat!(env!("OUT_DIR"), "/idtty.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

/// Send a request to the daemon and return the response.
pub fn request(action: &str, payload: &str) -> Result<GatewayResponse> {
    let socket_path = discover_socket()?;
    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("Cannot connect to daemon at {}", socket_path))?;

    let req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
    };
    let body = req.encode_to_vec();

    // Write varint-length-prefixed frame
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    stream.write_all(&header)?;
    stream.write_all(&body)?;
    stream.flush()?;

    // Shutdown write side so daemon sees EOF on its read
    stream.shutdown(std::net::Shutdown::Write)?;

    // Read full response
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf)?;

    if buf.is_empty() {
        anyhow::bail!("Daemon closed connection without response");
    }

    // Decode varint length
    let (resp_len, offset) = decode_varint(&buf);
    let resp_data = &buf[offset..offset + resp_len as usize];

    let response = GatewayResponse::decode(resp_data)
        .context("Failed to decode daemon response")?;

    Ok(response)
}

/// Check if the daemon is running and reachable.
pub fn is_daemon_running() -> bool {
    let socket_path = discover_socket().unwrap_or(DEFAULT_SOCKET_PATH.to_string());
    Path::new(&socket_path).exists() && UnixStream::connect(&socket_path).is_ok()
}

fn discover_socket() -> Result<String> {
    // TODO: Check XDG_RUNTIME_DIR first, --socket flag
    Ok(DEFAULT_SOCKET_PATH.to_string())
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

fn decode_varint(data: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        value |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (value, i)
}
