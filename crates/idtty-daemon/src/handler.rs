//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf requests, routes them to idtty-core,
//! and serializes responses back.

use anyhow::Result;
use idtty_core::IdttyError;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Handle a single client connection (line-delimited JSON until Protobuf is wired).
pub async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = route_request(&line).unwrap_or_else(|e| {
            format!(r#"{{"error": "{}"}}"#, e)
        });
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Route a serialized request to the appropriate idtty-core function.
///
/// TODO: Replace JSON stub with actual Protobuf deserialization
/// once proto/ schemas are compiled into Rust types.
fn route_request(payload: &str) -> Result<String, IdttyError> {
    // Stub: parse action from JSON until Protobuf is wired
    // Real implementation:
    //   let req = protobuf::parse_from_bytes(payload)?;
    //   match req.action {
    //       "vault.list" => ...,
    //       "vault.get"  => ...,
    //       "vault.add"  => ...,
    //       _ => Err(IdttyError::UnknownAction),
    //   }
    Ok(format!(r#"{{"status": "ok", "echo": "{}"}}"#, payload))
}
