//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to idtty-core,
//! serializes GatewayResponse back.
//!
//! Wire protocol: length-delimited Protobuf (varint prefix).

use anyhow::Result;
use bytes::{Buf, BytesMut};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// Generated Protobuf types
mod proto {
    pub(super) use super::super::proto::{GatewayRequest, GatewayResponse};
}

use proto::{GatewayRequest, GatewayResponse};

/// Maximum frame size: 4MB (largest bucket is 1MB, leave headroom)
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Handle a single client connection (length-delimited Protobuf frames).
pub async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    let (mut reader, mut writer) = stream.split();
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // Read varint length prefix
        let frame_len = read_varint_frame(&mut reader, &mut buf).await?;

        if frame_len == 0 {
            // Client closed connection
            return Ok(());
        }

        if frame_len > MAX_FRAME_SIZE {
            let resp = error_response(format!("Frame too large: {frame_len} bytes"));
            write_frame(&mut writer, &resp).await?;
            continue;
        }

        // Decode the frame bytes into a GatewayRequest
        let frame_data = buf.split_to(frame_len);
        let request = match GatewayRequest::decode(frame_data) {
            Ok(req) => req,
            Err(e) => {
                let resp = error_response(format!("Invalid request: {e}"));
                write_frame(&mut writer, &resp).await?;
                continue;
            }
        };

        // Route and handle
        let response = route_request(request).await;
        let resp_bytes = response.encode_to_vec();
        write_frame(&mut writer, &resp_bytes).await?;
    }
}

/// Read a varint-length-prefixed frame from the stream.
async fn read_varint_frame(
    reader: &mut tokio::io::ReadHalf<'_>,
    buf: &mut BytesMut,
) -> Result<usize> {
    // Read until we have enough bytes for the varint
    loop {
        // Try to decode varint from current buffer
        let mut tmp = buf.chunk();
        let mut varint_buf = [0u8; 10];
        let mut i = 0;

        while i < 10 && !tmp.is_empty() {
            varint_buf[i] = tmp[0];
            i += 1;
            tmp = &tmp[1..];

            // Check if this byte has the continuation bit cleared
            if varint_buf[i - 1] & 0x80 == 0 {
                // We have a complete varint
                let len = decode_varint(&varint_buf[..i]) as usize;

                // Consume the varint bytes from buf
                buf.advance(i);

                // Read the frame body
                while buf.len() < len {
                    let read = reader.read_buf(buf).await?;
                    if read == 0 {
                        return Ok(0); // Connection closed
                    }
                }

                return Ok(len);
            }
        }

        // Need more data for varint
        let read = reader.read_buf(buf).await?;
        if read == 0 {
            return Ok(0); // Connection closed
        }
    }
}

/// Decode a varint from bytes.
fn decode_varint(buf: &[u8]) -> u64 {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for &byte in buf {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    value
}

/// Write a varint-length-prefixed frame.
async fn write_frame(
    writer: &mut tokio::io::WriteHalf<'_>,
    data: &[u8],
) -> Result<()> {
    let len = data.len() as u64;
    let mut varint_buf = Vec::with_capacity(10);
    encode_varint(len, &mut varint_buf);
    writer.write_all(&varint_buf).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Encode a varint to a buffer.
fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Build an error GatewayResponse.
fn error_response(msg: String) -> Vec<u8> {
    let resp = GatewayResponse {
        success: false,
        error_message: msg,
        payload: String::new(),
    };
    resp.encode_to_vec()
}

/// Route a GatewayRequest to the appropriate idtty-core function.
async fn route_request(req: GatewayRequest) -> GatewayResponse {
    match req.action.as_str() {
        "ping" => GatewayResponse {
            success: true,
            error_message: String::new(),
            payload: "pong".into(),
        },

        // TODO: Wire these to idtty-core once vault state is held in daemon
        // "vault.init"    => { ... }
        // "vault.unlock"  => { ... }
        // "vault.lock"    => { ... }
        // "vault.list"    => { ... }
        // "vault.get"     => { ... }
        // "vault.add"     => { ... }
        // "vault.delete"  => { ... }
        // "sync.push"     => { ... }
        // "sync.pull"     => { ... }
        // "sync.status"   => { ... }

        _ => GatewayResponse {
            success: false,
            error_message: format!("Unknown action: {}", req.action),
            payload: String::new(),
        },
    }
}
