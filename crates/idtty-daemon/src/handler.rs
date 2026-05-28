//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to idtty-core,
//! serializes GatewayResponse back.
//!
//! Wire protocol: length-delimited Protobuf (varint prefix).

use anyhow::Result;
use bytes::{BytesMut, Buf};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// Re-export generated types from parent module
use crate::proto::{GatewayRequest, GatewayResponse};

/// Maximum frame size: 4MB (largest bucket is 1MB, leave headroom)
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Handle a single client connection (length-delimited Protobuf frames).
pub async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    let (mut reader, mut writer) = stream.split();
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // Read enough bytes to decode a varint
        let frame_len = match read_length(&mut reader, &mut buf).await {
            Ok(Some(len)) => len,
            Ok(None) => return Ok(()), // EOF, client disconnected
            Err(e) => {
                let resp = error_response(format!("Read error: {e}"));
                let _ = write_frame(&mut writer, &resp).await;
                return Err(e);
            }
        };

        if frame_len > MAX_FRAME_SIZE {
            let resp = error_response(format!("Frame too large: {frame_len} bytes"));
            write_frame(&mut writer, &resp).await?;
            // Discard the oversized frame data if any
            buf.clear();
            continue;
        }

        // Read the frame body
        while buf.len() < frame_len {
            let read = reader.read_buf(&mut buf).await?;
            if read == 0 {
                return Ok(()); // Connection closed mid-frame
            }
        }

        // Split off exactly the frame bytes
        let frame_data = buf.split_to(frame_len);

        // Decode into GatewayRequest
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

/// Read bytes until we can decode a varint length, returns the frame length.
/// Returns Ok(None) on clean EOF.
async fn read_length(
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut BytesMut,
) -> Result<Option<usize>> {
    loop {
        // Try to decode a varint from what we have
        let mut tmp = buf.chunk().iter();
        let mut len = 0u64;
        let mut shift = 0u32;
        let mut bytes_consumed = 0;

        while let Some(&byte) = tmp.next() {
            bytes_consumed += 1;
            len |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Complete varint
                buf.advance(bytes_consumed);
                return Ok(Some(len as usize));
            }
            if shift >= 70 {
                anyhow::bail!("Varint too long");
            }
        }

        // Need more data
        let read = reader.read_buf(buf).await?;
        if read == 0 {
            if buf.is_empty() {
                return Ok(None); // Clean EOF
            }
            anyhow::bail!("Connection closed mid-varint");
        }
    }
}

/// Write a varint-length-prefixed frame.
async fn write_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    data: &[u8],
) -> Result<()> {
    let mut header = Vec::with_capacity(10);
    encode_varint(data.len() as u64, &mut header);
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Encode a varint to a buffer.
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

/// Build an error GatewayResponse.
fn error_response(msg: impl Into<String>) -> Vec<u8> {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
    }
    .encode_to_vec()
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
