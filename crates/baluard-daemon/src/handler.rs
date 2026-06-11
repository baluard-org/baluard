//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to baluard-core
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
        let mut len = 0u64;
        let mut shift = 0u32;
        let mut bytes_consumed = 0;
        for &byte in buf.chunk().iter() {
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
    "vault.list_full",
    "vault.get",
    "vault.add",
    "vault.update",
    "cipher.clone",
    "cipher.totp_code",
    "folder.list",
    "folder.create",
    "folder.rename",
    "folder.delete",
    "tag.list",
    "tag.create",
    "tag.rename",
    "tag.delete",
    "tag.rebuild_index",
    "vault.delete",
    "vault.devices",
    "vault.trash.list",
    "vault.trash.restore",
    "vault.trash.purge",
    "vault.archive",
    "vault.unarchive",
    "vault.list_archived",
    "settings.get",
    "settings.set",
    "locale.save",
    "favicon.get",
    "sync.init",
    "sync.remote",
    "sync.push",
    "sync.pull",
    "sync.status",
    "sync.log",
    "vault.import",
    "vault.export",
    "vault.reprompt_verify",
    "vault.health",
    "vault.device_activity",
    "vault.attach_upload",
    "vault.attach_download",
    "vault.attach_delete",
    "vault.biometric_enable",
    "vault.biometric_disable",
    "vault.avatar.get",
    "vault.avatar.set",
    "ssh.generate_key",
    "provider.repos",
    "provider.vault_repos",
    "provider.create_repo",
    "vault.setup_sync",
    // C4 fix: device.revoke triggers destructive rekey, must be token-gated
    "device.revoke",
    // Note: vault.biometric_unlock is intentionally NOT token-gated because
    // it's an unlock primitive (used when vault is locked, no token exists).
    // Defense against same-UID abuse relies on OS keyring/biometric prompt.
    // H1: password change requires existing session
    "vault.change_password",
];

/// Actions that mutate vault data. Schedule cover commits after these.
const COVER_MUTATION_ACTIONS: &[&str] = &[
    "vault.add",
    "vault.update",
    "vault.delete",
    "vault.archive",
    "vault.unarchive",
    "cipher.clone",
    "vault.import",
    "vault.trash.restore",
    "vault.trash.purge",
    "folder.create",
    "folder.rename",
    "folder.delete",
    "tag.create",
    "tag.rename",
    "tag.delete",
    "tag.rebuild_index",
    "settings.set",
    "vault.avatar.set",
    "device.revoke",
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

/// Dispatch to the correct ForgeProvider implementation based on Provider enum.
/// Centralizes provider routing so handler code stays provider-agnostic.
fn provider_for(p: baluard_core::providers::types::Provider) -> Box<dyn baluard_core::providers::ForgeProvider> {
    match p {
        baluard_core::providers::types::Provider::GitHub => {
            Box::new(baluard_core::providers::github::GitHubProvider::new())
        }
        // Phase 5: GitLab, Codeberg — will panic if called before impl exists
        _ => unreachable!("Provider {:?} not yet implemented", p),
    }
}

/// Helper: parse provider name from JSON payload.
fn parse_provider_name(payload: &str) -> Result<baluard_core::providers::types::Provider, GatewayResponse> {
    let val: serde_json::Value = serde_json::from_str(payload)
        .map_err(|e| err_response(format!("Invalid payload: {e}")))?;
    let name = val["provider"].as_str().unwrap_or("");
    match name {
        "github" => Ok(baluard_core::providers::types::Provider::GitHub),
        "gitlab" => Ok(baluard_core::providers::types::Provider::GitLab),
        "codeberg" => Ok(baluard_core::providers::types::Provider::Codeberg),
        _ => Err(err_response(format!("Unknown provider: {name}"))),
    }
}

/// Route a GatewayRequest to the appropriate baluard-core function.
///
/// R7-2: Protected actions require a valid session token obtained at unlock.
async fn route_request(mut req: GatewayRequest, state: &SharedVaultState) -> GatewayResponse {
    log::debug!(
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
            // M4 fix: rate-limit failed unlock attempts.
            let vault_key = state.vault_path.to_string_lossy().into_owned();
            match state.rate_limiter.check(&vault_key) {
                crate::rate_limit::RateCheck::Allowed => {}
                crate::rate_limit::RateCheck::Backoff(d) => {
                    return err_response(format!(
                        "Too many failed attempts. Wait {}s before retrying.",
                        d.as_secs()
                    ));
                }
                crate::rate_limit::RateCheck::LockedOut(d) => {
                    return err_response(format!(
                        "Vault locked due to too many failed attempts. Wait {}s.",
                        d.as_secs()
                    ));
                }
            }
            let result = state.unlock(&req.payload).await;
            // Zeroize the password from the request immediately after use
            req.payload.zeroize();
            match result {
                Ok(()) => {
                    state.rate_limiter.record_success(&vault_key);
                    // Auto-purge old trash (default 30 days) on unlock
                    let _ = state.purge_old_trash(30).await;
                    // Start cover commit scheduler
                    state.start_cover_timer().await;
                    // Token was just generated inside unlock(). Fetch it.
                    let token = state.get_session_token().await;
                    match state.info().await {
                        Ok(info) => ok_resp(info, token.as_deref()),
                        Err(e) => err_response(e),
                    }
                }
                Err(e) => {
                    state.rate_limiter.record_failure(&vault_key);
                    err_response(e)
                }
            }
        }

        "vault.lock" => match state.lock().await {
            Ok(()) => ok_resp("locked", None),
            Err(e) => err_response(e),
        },

        // H1 fix: master password change (token required)
        "vault.change_password" => {
            let payload: serde_json::Value =
                match serde_json::from_str(&req.payload) {
                    Ok(v) => v,
                    Err(e) => return err_response(format!("Invalid JSON: {e}")),
                };
            let old_pw = match payload["old_password"].as_str() {
                Some(s) => s,
                None => return err_response("missing old_password"),
            };
            let new_pw = match payload["new_password"].as_str() {
                Some(s) => s,
                None => return err_response("missing new_password"),
            };
            match state.change_master_password(old_pw, new_pw).await {
                Ok(()) => ok_resp("{}", token_str),
                Err(e) => err_response(e),
            }
        }

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

        "vault.list_full" => match state.list_all().await {
            Ok(json) => ok_resp(json, token_str),
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

        "folder.list" => match state.list_folders().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
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

        "tag.list" => match state.list_tags().await {
            Ok(resp) => ok_resp(&resp, token_str),
            Err(e) => err_response(e),
        },
        "tag.create" => {
            if req.payload.is_empty() {
                return err_response("Missing tag name in payload");
            }
            match state.create_tag(&req.payload).await {
                Ok(resp) => ok_resp(&resp, token_str),
                Err(e) => err_response(e),
            }
        }
        "tag.rename" => {
            if req.payload.is_empty() {
                return err_response("Missing tag rename JSON in payload");
            }
            match state.rename_tag(&req.payload).await {
                Ok(()) => ok_resp("renamed", token_str),
                Err(e) => err_response(e),
            }
        }
        "tag.delete" => {
            if req.payload.is_empty() {
                return err_response("Missing tag name in payload");
            }
            match state.delete_tag(&req.payload).await {
                Ok(resp) => ok_resp(&resp, token_str),
                Err(e) => err_response(e),
            }
        }
        "tag.rebuild_index" => match state.rebuild_tag_index().await {
            Ok(resp) => ok_resp(&resp, token_str),
            Err(e) => err_response(e),
        },

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
        }

        "vault.trash.purge" => {
            let days = req.payload.parse::<u32>().unwrap_or(30);
            match state.purge_old_trash(days).await {
                Ok(count) => {
                    let json = serde_json::json!({"purged_count": count});
                    ok_resp(json.to_string(), token_str)
                }
                Err(e) => err_response(e),
            }
        }

        "vault.archive" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.archive_cipher(&req.payload).await {
                Ok(()) => ok_resp("archived", token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.unarchive" => {
            if req.payload.is_empty() {
                return err_response("Missing cipher UUID in payload");
            }
            match state.unarchive_cipher(&req.payload).await {
                Ok(()) => ok_resp("unarchived", token_str),
                Err(e) => err_response(e),
            }
        }

        "vault.list_archived" => match state.list_archived_meta().await {
            Ok(metas) => {
                let json = serde_json::json!({"ciphers": metas});
                ok_resp(json.to_string(), token_str)
            }
            Err(e) => err_response(e),
        },

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
        "locale.save" => {
            if req.payload.is_empty() {
                return err_response("Missing lang in payload");
            }
            match state.locale_save(&req.payload).await {
                Ok(()) => ok_resp("locale saved", token_str),
                Err(e) => err_response(e),
            }
        }

        // ── Favicon (token required) ──
        "favicon.get" => match state.fetch_favicon(&req.payload).await {
            Ok(data) => ok_resp(data, token_str),
            Err(e) => err_response(e),
        },

        // ── Import (token required) ──
        "vault.import" => {
            // Payload: JSON {"format": "bw-json", "data": "..."}
            // OR for file-based: JSON {"format": "keepass-xml", "path": "/path/to/file"}
            let parsed: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(v) => v,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            let format_str = parsed["format"].as_str().unwrap_or("");
            let format = match baluard_core::import::ImportFormat::from_name(format_str) {
                Some(f) => f,
                None => {
                    return err_response(format!(
                        "Unknown import format: {format_str}. Supported: {:?}",
                        baluard_core::import::ImportFormat::all_names()
                    ));
                }
            };

            let import_result = match format {
                baluard_core::import::ImportFormat::BwJson => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::bw_json::parse(data)
                }
                baluard_core::import::ImportFormat::BwCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::bw_csv::parse(data)
                }
                baluard_core::import::ImportFormat::ChromeCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::chrome_csv::parse(data)
                }
                baluard_core::import::ImportFormat::FirefoxCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::firefox_csv::parse(data)
                }
                baluard_core::import::ImportFormat::LastPassCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::lastpass_csv::parse(data)
                }
                baluard_core::import::ImportFormat::OnePassword1pux => {
                    // 1PUX is binary (ZIP). Data comes as base64.
                    let b64 = parsed["data"].as_str().unwrap_or("");
                    match base64::engine::general_purpose::STANDARD.decode(b64) {
                        Ok(bytes) => baluard_core::import::onepassword_1pux::parse(&bytes),
                        Err(e) => {
                            let mut r = baluard_core::import::ImportResult::new();
                            r.skip(format!("Invalid base64: {e}"));
                            r
                        }
                    }
                }
                baluard_core::import::ImportFormat::OnePasswordCsv => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::onepassword_csv::parse(data)
                }
                baluard_core::import::ImportFormat::KeePassXml => {
                    let data = parsed["data"].as_str().unwrap_or("");
                    baluard_core::import::keepass_xml::parse(data)
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
                _ => err_response(format!(
                    "Unknown export format: {format}. Use bw-json or bw-csv"
                )),
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

        // ── Password health report (token required) ──
        "vault.health" => match state.health_report().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        // ── Device fleet activity (token required) ──
        "vault.device_activity" => match state.device_activity().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        // ── Device revocation (token required) ──
        "device.revoke" => {
            let did = req.payload.trim().to_string();
            match state.device_revoke(&did).await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }

        // ── Attachment upload (token required) ──
        "vault.attach_upload" => match state.attach_upload(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        // ── Attachment download (token required) ──
        "vault.attach_download" => match state.attach_download(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        // ── Attachment delete (token required) ──
        "vault.attach_delete" => match state.attach_delete(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        // ── Biometric unlock (token NOT required for status/unlock) ──
        "vault.biometric_status" => match state.biometric_status().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.biometric_enable" => match state.biometric_enable(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.biometric_disable" => match state.biometric_disable().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.avatar.get" => match state.avatar_get().await {
            Ok(b64) => ok_resp(b64, token_str),
            Err(e) => err_response(e),
        },
        "vault.avatar.set" => match state.avatar_set(&req.payload).await {
            Ok(()) => ok_resp("{}", token_str),
            Err(e) => err_response(e),
        },

        "ssh.generate_key" => match state.ssh_generate_key(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.biometric_unlock" => {
            // M4 fix: rate-limit failed biometric unlock attempts.
            let vault_key = state.vault_path.to_string_lossy().into_owned();
            match state.rate_limiter.check(&vault_key) {
                crate::rate_limit::RateCheck::Allowed => {}
                crate::rate_limit::RateCheck::Backoff(d) => {
                    return err_response(format!(
                        "Too many failed attempts. Wait {}s before retrying.",
                        d.as_secs()
                    ));
                }
                crate::rate_limit::RateCheck::LockedOut(d) => {
                    return err_response(format!(
                        "Vault locked due to too many failed attempts. Wait {}s.",
                        d.as_secs()
                    ));
                }
            }
            match state.biometric_unlock().await {
                Ok(json) => {
                    state.rate_limiter.record_success(&vault_key);
                    // biometric_unlock() calls self.unlock() internally,
                    // which generates a new session token. Fetch it.
                    state.start_cover_timer().await;
                    let token = state.get_session_token().await;
                    ok_resp(json, token.as_deref())
                }
                Err(e) => {
                    state.rate_limiter.record_failure(&vault_key);
                    err_response(e)
                }
            }
        }

        // Validate master password without storing to keychain.
        // Used by the Tauri biometry plugin flow: validate here, store there.

        // ── Provider auth (no token required, auth happens before vault unlock) ──
        "provider.list" => {
            use baluard_core::providers::types::Provider;
            use baluard_core::providers::token::ProvidersState;
            let state_file = ProvidersState::load().unwrap_or_default();
            let mut providers = serde_json::Map::new();
            for p in Provider::all() {
                let key = p.to_string();
                if let Some(info) = state_file.get(*p) {
                    // Uniform shape: always include connected + auth_method
                    let mut val = serde_json::to_value(info).unwrap_or_default();
                    val["connected"] = serde_json::Value::Bool(true);
                    val["auth_method"] = serde_json::Value::String(p.auth_method().to_string());
                    providers.insert(key, val);
                } else {
                    providers.insert(key.clone(), serde_json::json!({
                        "provider": key,
                        "connected": false,
                        "auth_method": p.auth_method()
                    }));
                }
            }
            ok_resp(serde_json::Value::Object(providers).to_string(), token_str)
        }

        "provider.connect_start" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match provider.auth_method() {
                "device-flow" => {
                    let prov = provider_for(provider);
                    match prov.device_flow_start().await {
                        Ok(session) => ok_resp(serde_json::to_string(&session).unwrap_or_default(), token_str),
                        Err(e) => err_response(format!("Device flow start failed: {e}")),
                    }
                }
                _ => err_response(format!("Device flow not supported for {}. Use provider.connect_pat.", provider)),
            }
        }

        "provider.connect_poll" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let session: baluard_core::providers::types::DeviceFlowSession =
                match serde_json::from_value(payload) {
                    Ok(s) => s,
                    Err(e) => return err_response(format!("Invalid session: {e}")),
                };
            let prov = provider_for(session.provider);
            match prov.device_flow_poll(&session).await {
                Ok(status) => match status {
                    baluard_core::providers::types::DeviceFlowStatus::Pending => {
                        ok_resp(serde_json::json!({"status": "pending"}).to_string(), token_str)
                    }
                    baluard_core::providers::types::DeviceFlowStatus::SlowDown { interval_secs } => {
                        // M11 fix: caller persists this back into the session
                        // and re-polls at the new (longer) interval.
                        ok_resp(serde_json::json!({"status": "slow_down", "interval_secs": interval_secs}).to_string(), token_str)
                    }
                    baluard_core::providers::types::DeviceFlowStatus::Expired => {
                        ok_resp(serde_json::json!({"status": "expired"}).to_string(), token_str)
                    }
                    baluard_core::providers::types::DeviceFlowStatus::Success(token) => {
                        // Validate token and get user info
                        match prov.validate_token(&token).await {
                            Ok(info) => {
                                // Store token in keyring
                                if let Err(e) = baluard_core::providers::token::store_token(
                                    info.provider, &info.username, &token,
                                ) {
                                    return err_response(format!("Keyring error: {e}"));
                                }
                                // Store non-sensitive state
                                let mut state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
                                state_file.set(info.clone());
                                if let Err(e) = state_file.save() {
                                    // Rollback: remove orphaned keyring entry
                                    let _ = baluard_core::providers::token::delete_token(info.provider, &info.username);
                                    return err_response(format!("Failed to save provider state: {e}"));
                                }
                                ok_resp(serde_json::json!({"status": "success", "username": info.username}).to_string(), token_str)
                            }
                            Err(e) => err_response(format!("Token validation failed: {e}")),
                        }
                    }
                },
                Err(e) => err_response(format!("Poll failed: {e}")),
            }
        }

        "provider.connect_pat" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let pat = payload["token"].as_str().unwrap_or("").to_string();
            drop(payload);
            req.payload.zeroize();
            if pat.is_empty() {
                return err_response("Missing token in payload");
            }

            let prov = provider_for(provider);
            match prov.authenticate_pat(&pat).await {
                Ok((token, info)) => {
                    if let Err(e) = baluard_core::providers::token::store_token(
                        info.provider, &info.username, &token,
                    ) {
                        return err_response(format!("Keyring error: {e}"));
                    }
                    let mut state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
                    state_file.set(info.clone());
                    if let Err(e) = state_file.save() {
                        let _ = baluard_core::providers::token::delete_token(info.provider, &info.username);
                        return err_response(format!("Failed to save provider state: {e}"));
                    }
                    ok_resp(serde_json::json!({"status": "success", "username": info.username}).to_string(), token_str)
                }
                Err(e) => err_response(format!("PAT auth failed: {e}")),
            }
        }

        "provider.status" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            match state_file.get(provider) {
                Some(info) => {
                    match baluard_core::providers::token::load_token(provider, &info.username) {
                        Ok(token) => {
                            let prov = provider_for(provider);
                            match prov.validate_token(&token).await {
                                Ok(valid_info) => ok_resp(
                                    serde_json::json!({"valid": true, "username": valid_info.username}).to_string(),
                                    token_str,
                                ),
                                Err(e) => ok_resp(
                                    serde_json::json!({"valid": false, "error": e.to_string()}).to_string(),
                                    token_str,
                                ),
                            }
                        }
                        Err(e) => ok_resp(
                            serde_json::json!({"valid": false, "error": format!("Token not found: {e}")}).to_string(),
                            token_str,
                        ),
                    }
                }
                None => ok_resp(
                    serde_json::json!({"connected": false}).to_string(),
                    token_str,
                ),
            }
        }

        "provider.disconnect" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match baluard_core::providers::token::disconnect(provider) {
                Ok(()) => ok_resp("disconnected", token_str),
                Err(e) => err_response(format!("Disconnect failed: {e}")),
            }
        }

        "provider.repos" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let page = (payload["page"].as_u64().unwrap_or(1)).min(100) as u8;
            let per_page = (payload["per_page"].as_u64().unwrap_or(30)).min(100) as u8;
            let state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match baluard_core::providers::token::load_token(provider, &info.username) {
                Ok(t) => t,
                Err(e) => return err_response(format!("Token not found: {e}")),
            };
            let prov = provider_for(provider);
            match prov.list_repos(&token, page, per_page).await {
                Ok(repos) => ok_resp(serde_json::to_string(&repos).unwrap_or_default(), token_str),
                Err(e) => err_response(format!("Failed to list repos: {e}")),
            }
        }

        "provider.vault_repos" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match baluard_core::providers::token::load_token(provider, &info.username) {
                Ok(t) => t,
                Err(e) => return err_response(format!("Token not found: {e}")),
            };
            let prov = provider_for(provider);
            match prov.detect_vault_repos(&token).await {
                Ok(repos) => ok_resp(serde_json::to_string(&repos).unwrap_or_default(), token_str),
                Err(e) => err_response(format!("Failed to detect vault repos: {e}")),
            }
        }

        "provider.create_repo" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let name = match payload["name"].as_str() {
                Some(n) => n.to_string(),
                None => return err_response("Missing repo name"),
            };
            let state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match baluard_core::providers::token::load_token(provider, &info.username) {
                Ok(t) => t,
                Err(e) => return err_response(format!("Token not found: {e}")),
            };
            let prov = provider_for(provider);
            match prov.create_private_repo(&token, &name).await {
                Ok(repo) => ok_resp(serde_json::to_string(&repo).unwrap_or_default(), token_str),
                Err(e) => err_response(format!("Failed to create repo: {e}")),
            }
        }

        "vault.setup_sync" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let provider = match payload["provider"].as_str() {
                Some(p) => p.to_string(),
                None => return err_response("Missing provider"),
            };
            let repo_name = payload["repo_name"].as_str().unwrap_or("").to_string();

            // Resolve provider
            let prov_type = match baluard_core::providers::types::Provider::all()
                .iter().find(|p| p.to_string() == provider)
            {
                Some(p) => *p,
                None => return err_response(format!("Unknown provider: {provider}")),
            };

            // Load token from keyring
            let state_file = baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(prov_type) {
                Some(i) => i,
                None => return err_response(format!("{provider} not connected")),
            };
            let token = match baluard_core::providers::token::load_token(prov_type, &info.username) {
                Ok(t) => t,
                Err(e) => return err_response(format!("Token not found: {e}")),
            };

            // Default repo name to vault slug if not provided
            let vault_path = state.vault_path.clone();
            let effective_name = if repo_name.is_empty() {
                // Try reading slug from .baluard marker
                match baluard_core::vault::registry::BaluardMarker::read_from_vault(&vault_path) {
                    Ok(Some(m)) => m.slug.clone(),
                    _ => {
                        // Fallback to directory name
                        vault_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("vault")
                            .to_string()
                    }
                }
            } else {
                repo_name
            };

            // Create private repo on provider
            let prov = provider_for(prov_type);
            let repo = match prov.create_private_repo(&token, &effective_name).await {
                Ok(r) => r,
                Err(e) => return err_response(format!("Failed to create repo: {e}")),
            };

            // Init git repo + add remote + push (blocking git ops)
            #[cfg(feature = "git-sync")]
            {
                let slug_for_reg = match baluard_core::vault::registry::BaluardMarker::read_from_vault(&vault_path) {
                    Ok(Some(m)) => m.slug.clone(),
                    _ => vault_path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
                };
                let provider_for_reg = provider.clone();
                let remote_url = repo.clone_url.clone();
                let provider_clone = provider.clone();
                let handle = tokio::task::spawn_blocking(move || -> Result<String, String> {
                    use baluard_core::sync::engine::SyncEngine;
                    let engine = SyncEngine::new(&vault_path, "baluard-daemon");

                    // Init repo if not already a git repo
                    let git_repo = match engine.open_repo() {
                        Ok(r) => r,
                        Err(_) => engine.init_repo().map_err(|e| format!("Git init failed: {e}"))?,
                    };

                    // Add origin remote (idempotent check)
                    if let Ok(existing) = engine.get_remote_url(&git_repo, "origin") {
                        if existing != remote_url {
                            return Err(format!("Remote 'origin' already set to {existing}; disconnect sync first"));
                        }
                        // Same URL, skip
                    } else {
                        engine.add_remote(&git_repo, "origin", &remote_url)
                            .map_err(|e| format!("Failed to add remote: {e}"))?;
                    }

                    // Stage + commit any pending changes, then push
                    let status = engine.status(&git_repo).map_err(|e| format!("Status check failed: {e}"))?;
                    if status.is_dirty() {
                        engine.commit_all(&git_repo, "")
                            .map_err(|e| format!("Commit failed: {e}"))?;
                    }
                    engine.push(&git_repo, "origin")
                        .map_err(|e| format!("First push failed: {e}"))?;

                    Ok(remote_url)
                });

                let remote_url = match handle.await {
                    Ok(Ok(url)) => url,
                    Ok(Err(e)) => return err_response(e),
                    Err(e) => return err_response(format!("Task join: {e}")),
                };

                // Update registry with sync info
                if !slug_for_reg.is_empty() {
                    if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
                        if let Some(entry) = reg.get_mut(&slug_for_reg) {
                            entry.provider = Some(provider_clone);
                            entry.remote_url = Some(remote_url.clone());
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            entry.last_synced = Some(now);
                        }
                        let _ = reg.save_locked();
                    }
                }

                ok_resp(serde_json::json!({
                    "status": "synced",
                    "repo": remote_url,
                    "provider": provider_for_reg
                }).to_string(), token_str)
            }

            #[cfg(not(feature = "git-sync"))]
            err_response("Git sync not available (compiled without git-sync feature)")
        }

        _ => err_response(format!("Unknown action: {}", req.action)),
    };

    // Schedule cover commit after successful vault mutations
    if resp.success && COVER_MUTATION_ACTIONS.contains(&req.action.as_str()) {
        state.schedule_cover_after_commit();
    }

    // Zeroize any remaining sensitive data in the request
    req.payload.zeroize();

    log::debug!("[daemon] -> action={} success={}", req.action, resp.success);
    resp
}

// ── Sync helpers (git2-rs, CPU-bound) ──

#[cfg(feature = "git-sync")]
fn device_name(vault_path: &std::path::Path) -> String {
    let reg_path = vault_path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            let reg: Result<baluard_core::devices::DeviceRegistry, _> = serde_json::from_str(&data);
            if let Ok(reg) = reg {
                if let Some(entry) = reg.devices.values().next() {
                    return entry.name.clone();
                }
            }
        }
    }
    "baluard-device".into()
}

#[cfg(feature = "git-sync")]
fn sync_init(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
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
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    engine
        .add_remote(&repo, "origin", url)
        .map_err(|e| format!("{e}"))?;
    Ok(format!("Remote 'origin' set to: {url}"))
}

#[cfg(feature = "git-sync")]
fn sync_push(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
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
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    engine.recover_state().map_err(|e| format!("{e}"))?;
    let repo = engine.open_repo().map_err(|e| format!("{e}"))?;
    let result = engine.pull(&repo, "origin").map_err(|e| format!("{e}"))?;
    let mut msg = match result {
        baluard_core::sync::engine::PullResult::AlreadyUpToDate => "Already up to date.".to_string(),
        baluard_core::sync::engine::PullResult::FastForward => {
            "Fast-forwarded to latest.".to_string()
        }
        baluard_core::sync::engine::PullResult::Merged => "Merged remote changes.".to_string(),
        baluard_core::sync::engine::PullResult::Conflict { files, .. } => {
            let file_list = files.join(", ");
            return Err(format!(
                "Merge conflict in {file_list}. Resolution required."
            ));
        }
    };
    // Check for abort markers from other devices
    if let Some(aborted_epoch) = engine.check_abort_marker() {
        msg.push_str(&format!(
            " WARNING: Rotation for epoch {aborted_epoch} was aborted by another device."
        ));
        // Clean up the marker so it doesn't fire on every pull
        let abort_path = vault_path.join(format!(".baluard/rekey/{aborted_epoch}.aborted"));
        let _ = std::fs::remove_file(&abort_path);
    }
    Ok(msg)
}

#[cfg(feature = "git-sync")]
fn sync_status(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
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
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
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
