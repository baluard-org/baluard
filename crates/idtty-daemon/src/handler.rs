//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to idtty-core
//! via the shared VaultState, serializes GatewayResponse back.
//!
//! Wire protocol: length-delimited Protobuf (varint prefix).

use crate::proto::{GatewayRequest, GatewayResponse};
use crate::state::SharedVaultState;

use anyhow::Result;
use base64::Engine;
use bytes::{Buf, BytesMut};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroize;

/// Maximum frame size: 4MB (largest bucket is 1MB, leave headroom)
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Handle a single client connection (length-delimited Protobuf frames).
/// Verifies peer UID matches daemon UID on Linux (SO_PEERCRED).
pub async fn handle_connection(mut stream: UnixStream, state: SharedVaultState) -> Result<()> {
    // Peer credential check: reject connections from different UIDs
    verify_peer_uid(&stream)?;

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
            // Close connection on oversized frames — draining the body
            // is complex and a legitimate client should never send >4MB.
            let resp = error_response(format!("Frame too large: {frame_len} bytes"));
            let _ = write_frame(&mut writer, &resp).await;
            return Err(anyhow::anyhow!("Frame too large: {frame_len} bytes"));
        }

        while buf.len() < frame_len {
            let read = reader.read_buf(&mut buf).await?;
            if read == 0 {
                return Ok(());
            }
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
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(anyhow::anyhow!("Connection closed mid-varint"))
            };
        }
    }
}

/// Write a varint-length-prefixed frame.
async fn write_frame(writer: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> Result<()> {
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
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn error_response(msg: impl Into<String>) -> Vec<u8> {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
        session_token: String::new(),
    }
    .encode_to_vec()
}

fn err_response(msg: impl Into<String>) -> GatewayResponse {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
        session_token: String::new(),
    }
}

/// Actions that require a valid session token (post-unlock operations).
/// vault.info is intentionally EXCLUDED: it reveals no secret data (just vault ID,
/// device ID, lock state, cipher count) and is used as a pre-flight check by
/// ensure_unlocked_daemon() which runs before the token is available.
const TOKEN_REQUIRED_ACTIONS: &[&str] = &[
    "vault.list",
    "vault.get",
    "vault.add",
    "vault.update",
    "cipher.clone",
    "cipher.totp_code",
    "folder.list",
    "folder.create",
    "folder.rename",
    "folder.delete",
    "vault.delete",
    "vault.devices",
    "vault.trash.list",
    "vault.trash.restore",
    "vault.trash.purge",
    "settings.get",
    "settings.set",
    "sync.init",
    "sync.remote",
    "sync.push",
    "sync.pull",
    "sync.status",
    "sync.log",
    "vault.import",
    "vault.export",
    "vault.reprompt_verify",
];

/// Build a success GatewayResponse. Attaches session token if available.
fn ok_resp(payload: impl Into<String>, token: Option<&str>) -> GatewayResponse {
    GatewayResponse {
        success: true,
        error_message: String::new(),
        payload: payload.into(),
        session_token: token.unwrap_or("").to_string(),
    }
}

/// Route a GatewayRequest to the appropriate idtty-core function.
///
/// R7-2: Protected actions require a valid session token obtained at unlock.
async fn route_request(mut req: GatewayRequest, state: &SharedVaultState) -> GatewayResponse {
    eprintln!(
        "[daemon] <- action={} has_token={}",
        req.action,
        !req.session_token.is_empty()
    );

    // R7-2: Enforce session token on protected actions
    if TOKEN_REQUIRED_ACTIONS.contains(&req.action.as_str()) {
        if let Err(e) = state.verify_session_token(&req.session_token).await {
            return err_response(e);
        }
    }

    let token = state.get_session_token().await;
    let token_str = token.as_deref();

    // Touch activity timer on every request (for auto-lock)
    state.touch_activity();

    let resp = match req.action.as_str() {
        "ping" => ok_resp("pong", None),

        // ── Vault lifecycle (no token required) ──
        "vault.open" => match state.open().await {
            Ok(()) => match state.info().await {
                Ok(info) => ok_resp(info, token_str),
                Err(e) => err_response(e),
            },
            Err(e) => err_response(e),
        },

        "vault.unlock" => {
            if req.payload.is_empty() {
                return err_response("Missing master password in payload");
            }
            let result = state.unlock(&req.payload).await;
            // Zeroize the password from the request immediately after use
            req.payload.zeroize();
            match result {
                Ok(()) => {
                    // Auto-purge old trash (default 30 days) on unlock
                    let _ = state.purge_old_trash(30).await;
                    // Token was just generated inside unlock(). Fetch it.
                    let token = state.get_session_token().await;
                    match state.info().await {
                        Ok(info) => ok_resp(info, token.as_deref()),
                        Err(e) => err_response(e),
                    }
                }
                Err(e) => err_response(e),
            }
        }

        "vault.lock" => match state.lock().await {
            Ok(()) => ok_resp("locked", None),
            Err(e) => err_response(e),
        },

        // vault.info: token NOT required (no secret data, used as pre-flight by CLI)
        "vault.info" => match state.info().await {
            Ok(info) => ok_resp(info, token_str),
            Err(e) => err_response(e),
        },

        // ── Cipher CRUD (token required, enforced above) ──
        "vault.list" => match state.list_cipher_meta().await {
            Ok(metas) => {
                let json = serde_json::json!({"ciphers": metas});
                ok_resp(json.to_string(), token_str)
            }
            Err(e) => err_response(e),
        },

        "vault.get" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            let (id, decrypt) = match serde_json::from_str::<serde_json::Value>(&req.payload) {
                Ok(v) => (
                    v["id"].as_str().unwrap_or("").to_string(),
                    v["decrypt"].as_bool().unwrap_or(false),
                ),
                Err(_) => (req.payload.clone(), false),
            };
            match state.get_cipher(&id, decrypt).await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.add" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher JSON in payload");
            }
            match state.add_cipher(&req.payload).await {
                Ok(id) => ok_resp(id, token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.update" => {
            if req.payload.is_empty() {
                return err_response("Missing update JSON in payload");
            }
            match state.update_cipher(&req.payload).await {
                Ok(()) => ok_resp("updated", token_str),
                Err(e) => err_response(e),
            }
        }

        "cipher.clone" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.clone_cipher(&req.payload).await {
                Ok(id) => ok_resp(id, token_str),
                Err(e) => err_response(e),
            }
        }

        "cipher.totp_code" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.totp_code(&req.payload).await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }

        "folder.list" => {
            match state.list_folders().await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }
        "folder.create" => {
            if req.payload.is_empty() {
                return err_response("Missing folder name in payload");
            }
            match state.create_folder(&req.payload).await {
                Ok(id) => ok_resp(id, token_str),
                Err(e) => err_response(e),
            }
        }
        "folder.rename" => {
            if req.payload.is_empty() {
                return err_response("Missing folder rename JSON in payload");
            }
            match state.rename_folder(&req.payload).await {
                Ok(()) => ok_resp("renamed", token_str),
                Err(e) => err_response(e),
            }
        }
        "folder.delete" => {
            if req.payload.is_empty() {
                return err_response("Missing folder UUID in payload");
            }
            match state.delete_folder(&req.payload).await {
                Ok(()) => ok_resp("deleted", token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.delete" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.delete_cipher(&req.payload).await {
                Ok(()) => ok_resp("deleted", token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.trash.list" => match state.list_trash_ids().await {
            Ok(ids) => {
                let json = serde_json::json!({"cipher_ids": ids});
                ok_resp(json.to_string(), token_str)
            }
            Err(e) => err_response(e),
        },

        "vault.trash.restore" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.restore_cipher(&req.payload).await {
                Ok(()) => ok_resp("restored", token_str),
                Err(e) => err_response(e),
            }
        },

        "vault.trash.purge" => {
            let days = match req.payload.parse::<u32>() {
                Ok(d) => d,
                Err(_) => 30, // default 30 days
            };
            match state.purge_old_trash(days).await {
                Ok(count) => {
                    let json = serde_json::json!({"purged_count": count});
                    ok_resp(json.to_string(), token_str)
                }
                Err(e) => err_response(e),
            }
        }

        "vault.devices" => match state.devices().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.create" => {
            if req.payload.is_empty() {
                return err_response("Missing vault creation JSON in payload");
            }
            match state.create_vault(&req.payload).await {
                Ok(json) => {
                    // R7-2 fix: token is embedded in response JSON by create_vault,
                    // but we also need it in the proto field for CLI extraction.
                    ok_resp(json, state.get_session_token().await.as_deref())
                }
                Err(e) => err_response(e),
            }
        }

        // ── Sync (token required, enforced above) ──
        "sync.init" => match sync_init(&state.vault_path) {
            Ok(msg) => ok_resp(msg, token_str),
            Err(e) => err_response(e),
        },
        "sync.remote" => {
            if req.payload.is_empty() {
                return err_response("Missing remote URL in payload");
            }
            match sync_remote(&state.vault_path, &req.payload) {
                Ok(msg) => ok_resp(msg, token_str),
                Err(e) => err_response(e),
            }
        }
        "sync.push" => match sync_push(&state.vault_path) {
            Ok(msg) => ok_resp(msg, token_str),
            Err(e) => err_response(e),
        },
        "sync.pull" => match sync_pull(&state.vault_path) {
            Ok(msg) => ok_resp(msg, token_str),
            Err(e) => err_response(e),
        },
        "sync.status" => match sync_status(&state.vault_path) {
            Ok(msg) => ok_resp(msg, token_str),
            Err(e) => err_response(e),
        },
        "sync.log" => {
            let limit: usize = if req.payload.is_empty() {
                10
            } else {
                req.payload.parse().unwrap_or(10)
            };
            match sync_log(&state.vault_path, limit) {
                Ok(msg) => ok_resp(msg, token_str),
                Err(e) => err_response(e),
            }
        }

        // ── Settings (token required) ──
        "settings.get" => match state.settings_get().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "settings.set" => {
            if req.payload.is_empty() {
                return err_response("Missing settings JSON in payload");
            }
            match state.settings_set(&req.payload).await {
                Ok(()) => ok_resp("settings updated", token_str),
                Err(e) => err_response(e),
            }
        }

        // ── Import (token required) ──
        "vault.import" => {
            // Payload: JSON {"format": "bw-json", "data": "..."}
            // OR for file-based: JSON {"format": "keepass-xml", "path": "/path/to/file"}
            let parsed: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(v) => v,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            let format_str = parsed["format"].as_str().unwrap_or("");
            let format = match idtty_core::import::ImportFormat::from_str(format_str) {
                Some(f) => f,
                None => return err_response(format!("Unknown import format: {format_str}. Supported: {:?}", idtty_core::import::ImportFormat::all_names())),
            };

            let import_result = match format {
                idtty_core::import::ImportFormat::BwJson => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::bw_json::parse(data)
                }
                idtty_core::import::ImportFormat::BwCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::bw_csv::parse(data)
                }
                idtty_core::import::ImportFormat::ChromeCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::chrome_csv::parse(data)
                }
                idtty_core::import::ImportFormat::FirefoxCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::firefox_csv::parse(data)
                }
                idtty_core::import::ImportFormat::LastPassCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::lastpass_csv::parse(data)
                }
                idtty_core::import::ImportFormat::OnePassword1pux => {
                    // 1PUX is binary (ZIP). Data comes as base64.
                    let b64 = parsed["data"].as_str().unwrap_or("");
                    match base64::engine::general_purpose::STANDARD.decode(b64) {
                        Ok(bytes) => idtty_core::import::onepassword_1pux::parse(&bytes),
                        Err(e) => {
                            let mut r = idtty_core::import::ImportResult::new();
                            r.skip(format!("Invalid base64: {e}"));
                            r
                        }
                    }
                }
                idtty_core::import::ImportFormat::OnePasswordCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::onepassword_csv::parse(data)
                }
                idtty_core::import::ImportFormat::KeePassXml => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    idtty_core::import::keepass_xml::parse(data)
                }
            };

            match state.import_ciphers(import_result).await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }

        // ── Export (token required) ──
        "vault.export" => {
            // Payload: "bw-json" or "bw-csv"
            let format = req.payload.trim();
            match format {
                "bw-json" => match state.export_bw_json().await {
                    Ok(json) => ok_resp(json, token_str),
                    Err(e) => err_response(e),
                },
                "bw-csv" => match state.export_bw_csv().await {
                    Ok(csv) => ok_resp(csv, token_str),
                    Err(e) => err_response(e),
                },
                _ => err_response(format!("Unknown export format: {format}. Use bw-json or bw-csv")),
            }
        }

        // ── Reprompt verify (token required) ──
        "vault.reprompt_verify" => {
            // Payload: master password (plaintext)
            if req.payload.is_empty() {
                return err_response("Missing master password");
            }
            match state.reprompt_verify(&req.payload).await {
                Ok(json) => {
                    req.payload.zeroize();
                    ok_resp(json, token_str)
                }
                Err(e) => {
                    req.payload.zeroize();
                    err_response(e)
                }
            }
        }

        _ => err_response(format!("Unknown action: {}", req.action)),
    };

    // Zeroize any remaining sensitive data in the request
    req.payload.zeroize();

    eprintln!("[daemon] -> action={} success={}", req.action, resp.success);
    resp
}

// ── Sync helpers (git2-rs, CPU-bound) ──

#[cfg(feature = "git-sync")]
fn device_name(vault_path: &std::path::Path) -> String {
    let reg_path = vault_path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            let reg: Result<idtty_core::devices::DeviceRegistry, _> = serde_json::from_str(&data);
            if let Ok(reg) = reg {
                if let Some(entry) = reg.devices.values().next() {
                    return entry.name.clone();
                }
            }
        }
    }
    "idtty-device".into()
}

#[cfg(feature = "git-sync")]
fn sync_init(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.init_repo().map_err(|e| format!("{e}"))?;
    let log = engine.log(&repo, 1).map_err(|e| format!("{e}"))?;
    let commit_info = log
        .first()
        .map(|c| format!("Initial commit: {}", &c.id[..7.min(c.id.len())]))
        .unwrap_or_else(|| "Repo initialized".into());
    Ok(format!("Git repo initialized. {}", commit_info))
}

#[cfg(feature = "git-sync")]
fn sync_remote(vault_path: &std::path::Path, url: &str) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    engine
        .add_remote(&repo, "origin", url)
        .map_err(|e| format!("{e}"))?;
    Ok(format!("Remote 'origin' set to: {url}"))
}

#[cfg(feature = "git-sync")]
fn sync_push(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    let status = engine.status(&repo).map_err(|e| format!("{e}"))?;
    let mut committed = false;
    if status.is_dirty() {
        engine.commit_all(&repo, "").map_err(|e| format!("{e}"))?;
        committed = true;
    }
    engine.push(&repo, "origin").map_err(|e| format!("{e}"))?;
    let msg = if committed {
        "Committed pending changes and pushed to origin."
    } else {
        "Pushed to origin."
    };
    Ok(msg.into())
}

#[cfg(feature = "git-sync")]
fn sync_pull(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    engine.recover_state().map_err(|e| format!("{e}"))?;
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    let result = engine.pull(&repo, "origin").map_err(|e| format!("{e}"))?;
    Ok(match result {
        idtty_core::sync::engine::PullResult::AlreadyUpToDate => "Already up to date.".into(),
        idtty_core::sync::engine::PullResult::FastForward => "Fast-forwarded to latest.".into(),
        idtty_core::sync::engine::PullResult::Merged => "Merged remote changes.".into(),
        idtty_core::sync::engine::PullResult::Conflict { files, .. } => {
            let file_list = files.join(", ");
            return Err(format!("Merge conflict in {file_list}. Resolution required."));
        }
    })
}

#[cfg(feature = "git-sync")]
fn sync_status(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    let status = engine.status(&repo).map_err(|e| format!("{e}"))?;
    let work_tree = if status.is_dirty() {
        format!(
            "dirty ({} staged, {} unstaged)",
            status.staged, status.unstaged
        )
    } else {
        "clean".into()
    };
    let log = engine.log(&repo, 5).map_err(|e| format!("{e}"))?;
    let mut result = format!("Working tree: {}", work_tree);
    if !log.is_empty() {
        result.push_str("\nRecent commits:");
        for c in &log {
            let ts = chrono::DateTime::from_timestamp(c.time, 0)
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_default();
            result.push_str(&format!(
                "\n  {} {} <{}>",
                &c.id[..7.min(c.id.len())],
                c.message.trim(),
                ts
            ));
        }
    }
    Ok(result)
}

#[cfg(feature = "git-sync")]
fn sync_log(vault_path: &std::path::Path, limit: usize) -> Result<String, String> {
    let engine = idtty_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    let log = engine.log(&repo, limit).map_err(|e| format!("{e}"))?;
    if log.is_empty() {
        return Ok("No commits.".into());
    }
    let mut result = String::new();
    for c in &log {
        let ts = chrono::DateTime::from_timestamp(c.time, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        result.push_str(&format!(
            "{} {} {}\n",
            &c.id[..7.min(c.id.len())],
            ts,
            c.message.trim()
        ));
    }
    result.push_str(&format!("\n{} commit(s)", log.len()));
    Ok(result)
}

#[cfg(not(feature = "git-sync"))]
fn sync_init(_p: &std::path::Path) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_remote(_p: &std::path::Path, _u: &str) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_push(_p: &std::path::Path) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_pull(_p: &std::path::Path) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_status(_p: &std::path::Path) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_log(_p: &std::path::Path, _n: usize) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}

// ── Peer credential verification ──

/// Verify the connecting process runs as the same UID as the daemon.
/// Prevents other local users from connecting to the Unix socket.
#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut cred_len: libc::socklen_t = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut cred_len,
        )
    };

    if ret != 0 {
        anyhow::bail!("Failed to get peer credentials: SO_PEERCRED failed");
    }

    let my_uid = unsafe { libc::geteuid() };
    if cred.uid != my_uid {
        anyhow::bail!(
            "Peer UID {} does not match daemon UID {}. Connection rejected.",
            cred.uid,
            my_uid
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_peer_uid(stream: &UnixStream) -> Result<()> {
    use libc::{geteuid, getpeereid};
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    let ret = unsafe { getpeereid(fd, &mut uid, &mut gid) };
    if ret != 0 {
        anyhow::bail!("Failed to get peer credentials");
    }

    let my_uid = unsafe { geteuid() };
    if uid != my_uid {
        anyhow::bail!(
            "Peer UID {} does not match daemon UID {}. Connection rejected.",
            uid,
            my_uid
        );
    }

    Ok(())
}

#[cfg(not(unix))]
fn verify_peer_uid(_stream: &UnixStream) -> Result<()> {
    // Windows Named Pipes have their own ACL-based security
    Ok(())
}
