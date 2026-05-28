//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to idtty-core
//! via the shared VaultState, serializes GatewayResponse back.
//!
//! Wire protocol: length-delimited Protobuf (varint prefix).

use crate::proto::{GatewayRequest, GatewayResponse};
use crate::state::SharedVaultState;

use anyhow::Result;
use bytes::{Buf, BytesMut};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Maximum frame size: 4MB (largest bucket is 1MB, leave headroom)
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Handle a single client connection (length-delimited Protobuf frames).
pub async fn handle_connection(mut stream: UnixStream, state: SharedVaultState) -> Result<()> {
    let (mut reader, mut writer) = stream.split();
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        let frame_len = match read_length(&mut reader, &mut buf).await {
            Ok(Some(len)) => len,
            Ok(None) => return Ok(()),
            Err(e) => {
                let resp = error_response(format!("Read error: {e}"));
                let _ = write_frame(&mut writer, &resp).await;
                return Err(e);
            }
        };

        if frame_len > MAX_FRAME_SIZE {
            let resp = error_response(format!("Frame too large: {frame_len} bytes"));
            write_frame(&mut writer, &resp).await?;
            buf.clear();
            continue;
        }

        while buf.len() < frame_len {
            let read = reader.read_buf(&mut buf).await?;
            if read == 0 { return Ok(()); }
        }

        let frame_data = buf.split_to(frame_len);
        let request = match GatewayRequest::decode(frame_data) {
            Ok(req) => req,
            Err(e) => {
                let resp = error_response(format!("Invalid request: {e}"));
                write_frame(&mut writer, &resp).await?;
                continue;
            }
        };

        let response = route_request(request, &state).await;
        let resp_bytes = response.encode_to_vec();
        write_frame(&mut writer, &resp_bytes).await?;
    }
}

/// Read bytes until we can decode a varint length.
async fn read_length(
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut BytesMut,
) -> Result<Option<usize>> {
    loop {
        let mut tmp = buf.chunk().iter();
        let mut len = 0u64;
        let mut shift = 0u32;
        let mut bytes_consumed = 0;

        while let Some(&byte) = tmp.next() {
            bytes_consumed += 1;
            len |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                buf.advance(bytes_consumed);
                return Ok(Some(len as usize));
            }
            if shift >= 70 {
                anyhow::bail!("Varint too long");
            }
        }

        let read = reader.read_buf(buf).await?;
        if read == 0 {
            return if buf.is_empty() { Ok(None) } else { Err(anyhow::anyhow!("Connection closed mid-varint")) };
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

fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 { buf.push(byte); break; }
        buf.push(byte | 0x80);
    }
}

fn error_response(msg: impl Into<String>) -> Vec<u8> {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
    }
    .encode_to_vec()
}

fn ok_response(payload: impl Into<String>) -> Vec<u8> {
    GatewayResponse {
        success: true,
        error_message: String::new(),
        payload: payload.into(),
    }
    .encode_to_vec()
}

fn err_response(msg: impl Into<String>) -> GatewayResponse {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
    }
}

/// Route a GatewayRequest to the appropriate idtty-core function.
async fn route_request(req: GatewayRequest, state: &SharedVaultState) -> GatewayResponse {
    match req.action.as_str() {
        "ping" => GatewayResponse {
            success: true,
            error_message: String::new(),
            payload: "pong".into(),
        },

        // ── Vault lifecycle ──

        "vault.open" => {
            match state.open().await {
                Ok(()) => match state.info().await {
                    Ok(info) => GatewayResponse { success: true, error_message: String::new(), payload: info },
                    Err(e) => err_response(e),
                },
                Err(e) => err_response(e),
            }
        }

        "vault.unlock" => {
            if req.payload.is_empty() {
                return err_response("Missing master password in payload");
            }
            match state.unlock(&req.payload).await {
                Ok(()) => match state.info().await {
                    Ok(info) => GatewayResponse { success: true, error_message: String::new(), payload: info },
                    Err(e) => err_response(e),
                },
                Err(e) => err_response(e),
            }
        }

        "vault.lock" => {
            match state.lock().await {
                Ok(()) => GatewayResponse { success: true, error_message: String::new(), payload: "locked".into() },
                Err(e) => err_response(e),
            }
        }

        "vault.info" => {
            match state.info().await {
                Ok(info) => GatewayResponse { success: true, error_message: String::new(), payload: info },
                Err(e) => err_response(e),
            }
        }

        // ── Cipher CRUD ──

        "vault.list" => {
            match state.list_cipher_ids().await {
                Ok(ids) => {
                    let json = serde_json::json!({"cipher_ids": ids});
                    GatewayResponse { success: true, error_message: String::new(), payload: json.to_string() }
                }
                Err(e) => err_response(e),
            }
        }

        "vault.get" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            // payload = JSON {"id": "...", "decrypt": true/false}
            let (id, decrypt) = match serde_json::from_str::<serde_json::Value>(&req.payload) {
                Ok(v) => (
                    v["id"].as_str().unwrap_or("").to_string(),
                    v["decrypt"].as_bool().unwrap_or(false),
                ),
                Err(_) => (req.payload.clone(), false),
            };
            match state.get_cipher(&id, decrypt).await {
                Ok(json) => GatewayResponse { success: true, error_message: String::new(), payload: json },
                Err(e) => err_response(e),
            }
        }

        "vault.add" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher JSON in payload");
            }
            match state.add_cipher(&req.payload).await {
                Ok(id) => GatewayResponse { success: true, error_message: String::new(), payload: id },
                Err(e) => err_response(e),
            }
        }

        "vault.delete" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.delete_cipher(&req.payload).await {
                Ok(()) => GatewayResponse { success: true, error_message: String::new(), payload: "deleted".into() },
                Err(e) => err_response(e),
            }
        }

        // ── Sync ──
        // TODO: Wire sync actions through vault state once sync is daemon-integrated
        "sync.push" | "sync.pull" | "sync.status" | "sync.log" => {
            err_response(format!("{} not yet routed through daemon. Use CLI with --direct.", req.action))
        }

        _ => err_response(format!("Unknown action: {}", req.action)),
    }
}
