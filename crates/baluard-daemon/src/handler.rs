//! Protobuf gateway handler.
//!
//! Deserializes incoming Protobuf GatewayRequest, routes to baluard-core
//! via the shared VaultState, serializes GatewayResponse back.
//!
//! Wire protocol: length-delimited Protobuf (varint prefix).

use crate::host::{SharedVaultHost, SnapshotError, VaultPresence};
use crate::proto::{GatewayRequest, GatewayResponse};
use crate::state::{SharedVaultState, VaultState};

use std::sync::Arc;

use anyhow::Result;
use base64::Engine;
use bytes::{Buf, BytesMut};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroize;

/// Maximum frame size: 4MB (largest bucket is 1MB, leave headroom)
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;
/// Hard cap on any blocking git2 operation (push/pull/remote/status). libgit2
/// has no transport timeout, so a hung SSH/HTTPS negotiation to a dead
/// remote would otherwise leak the spawn_blocking thread forever; under
/// autosync retries the pool exhausts and the whole daemon starves (the
/// EAGAIN storm). 60s is generous for a real sync yet bounds the leak.
pub(crate) const SYNC_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Handle a single client connection (length-delimited Protobuf frames).
/// Verifies peer UID matches daemon UID on Linux (SO_PEERCRED).
pub async fn handle_connection(mut stream: UnixStream, host: SharedVaultHost) -> Result<()> {
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

        let response = route_host_request(request, &host).await;
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
    // Session PIN: enable/disable require an existing unlocked session
    // (they take the master password to seed the KEK escrow). pin_unlock
    // is an unlock primitive, NOT token-gated (see TOKEN_REQUIRED_ACTIONS
    // note on biometric_unlock). pin_status is pre-unlock-safe (in-memory
    // check) so it is also not token-gated.
    "vault.pin_enable",
    "vault.pin_disable",
    "vault.avatar.get",
    "vault.avatar.set",
    "ssh.generate_key",
    // Generator history
    "generator.history_add",
    "generator.history_list",
    "generator.history_clear",
    // Phase 1: passkey ceremony routes
    "passkey.challenge_register",
    "passkey.finish_register",
    "passkey.challenge_assert",
    "passkey.finish_assert",
    "passkey.list",
    "passkey.delete",
    "passkey.rename",
    "provider.repos",
    "provider.create_repo",
    "provider.oauth_start_web",
    "provider.oauth_status_web",
    "vault.setup_sync",
    "sync.status_json",
    "sync.autosync_status",
    "sync.disconnect",
    // Focus-triggered pull: touches the on-disk repo, must be token-gated.
    "sync.autosync_nudge_pull",
    // Phase 2b: read paused-conflict metadata (file paths) and apply a
    // verdict (writes a merge commit + pushes). Both must be token-gated.
    "sync.conflict",
    "sync.conflict.resolve",
    // C4 fix: device.revoke triggers destructive rekey, must be token-gated
    "device.revoke",
    // M4/PR-2: recovery-phrase enrollment mutates the device registry and
    // unwraps the Root Key. Must be token-gated to prevent same-UID abuse.
    "vault.enroll_with_phrase",
    // Note: vault.biometric_unlock is intentionally NOT token-gated because
    // it's an unlock primitive (used when vault is locked, no token exists).
    // Defense against same-UID abuse relies on OS keyring/biometric prompt.
    // Session PIN: vault.pin_unlock is likewise an unlock primitive, NOT
    // token-gated. Its only in-process defense is the attempt cap that nukes
    // the KEK escrow after MAX_PIN_FAILURES wrong PINs.
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
    // Phase 1: passkey mutations
    "passkey.finish_register",
    "passkey.delete",
    "passkey.rename",
    "passkey.finish_assert",
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

/// Helper: parse provider name from JSON payload.
fn parse_provider_name(
    payload: &str,
) -> Result<baluard_core::providers::types::Provider, GatewayResponse> {
    let val: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| err_response(format!("Invalid payload: {e}")))?;
    let name = val["provider"].as_str().unwrap_or("");
    match name {
        "github" => Ok(baluard_core::providers::types::Provider::GitHub),
        "gitlab" => Ok(baluard_core::providers::types::Provider::GitLab),
        "codeberg" => Ok(baluard_core::providers::types::Provider::Codeberg),
        _ => Err(err_response(format!("Unknown provider: {name}"))),
    }
}

/// Helper: parse Advanced Options overrides (client_id, instance_url) from a
/// JSON payload. Both optional; absent => None => provider public default.
fn parse_provider_config(payload: &str) -> baluard_core::providers::ProviderConfig {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) else {
        return baluard_core::providers::ProviderConfig::defaults();
    };
    baluard_core::providers::ProviderConfig {
        client_id: val["client_id"].as_str().map(str::to_string),
        instance_url: val["instance_url"].as_str().map(str::to_string),
    }
}

/// Per-provider async mutex guarding token refresh. Prevents two concurrent
/// ops (e.g. sync.push + provider.status) from both refreshing a GitLab token
/// at the same instant — GitLab invalidates the old refresh_token on use, so
/// the loser of that race would disconnect spuriously. H6.
static REFRESH_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<
            baluard_core::providers::types::Provider,
            std::sync::Arc<tokio::sync::Mutex<()>>,
        >,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

async fn refresh_lock_for(
    provider: baluard_core::providers::types::Provider,
) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let mut map = REFRESH_LOCKS.lock().unwrap();
    map.entry(provider)
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Load a provider token, auto-refreshing if expired.
///
/// GitLab OAuth tokens expire every 2h and carry a refresh_token; GitHub PATs
/// and long-lived OAuth tokens never expire. When a token is expired and
/// refresh succeeds, the new token is re-stored to the keyring before return
/// so subsequent operations (including git2 credential callbacks) see the
/// fresh value. On refresh failure the stored credentials are cleared and an
/// error is returned so the desktop can transition to State D (re-auth).
///
/// H6: uses a per-provider async mutex + double-checked locking so concurrent
/// callers don't race on refresh (GitLab rolling refresh invalidates the loser).
async fn ensure_valid_token(
    provider: baluard_core::providers::types::Provider,
    info: &baluard_core::providers::ProviderInfo,
) -> Result<baluard_core::providers::ProviderToken, GatewayResponse> {
    // Fast path: not expired.
    let token = baluard_core::providers::token::load_token(provider, &info.username)
        .map_err(|e| err_response(format!("Token not found: {e}")))?;
    if !token.is_expired() {
        return Ok(token);
    }

    // Slow path: acquire per-provider refresh lock.
    let lock = refresh_lock_for(provider).await;
    let _guard = lock.lock().await;

    // Re-read after acquiring the lock (double-checked locking): a concurrent
    // caller may have already refreshed this token while we waited.
    let token = baluard_core::providers::token::load_token(provider, &info.username)
        .map_err(|e| err_response(format!("Token not found: {e}")))?;
    if !token.is_expired() {
        return Ok(token);
    }

    let prov = match baluard_core::providers::provider_for(provider, info.config()) {
        Ok(p) => p,
        Err(e) => return Err(err_response(e.to_string())),
    };

    match prov.refresh_token(&token).await {
        Ok(Some(new_token)) => {
            if let Err(e) =
                baluard_core::providers::token::store_token(provider, &info.username, &new_token)
            {
                return Err(err_response(format!(
                    "Keyring error storing refreshed token: {e}"
                )));
            }
            log::info!(
                "[daemon] refreshed expired {:?} token for @{}",
                provider,
                info.username
            );
            Ok(new_token)
        }
        Ok(None) => {
            // Token is expired but provider returned no refresh (e.g. PAT with
            // user-set expiry). Clear credentials and prompt re-auth.
            let _ = baluard_core::providers::token::disconnect(provider);
            Err(err_response(format!(
                "{:?} token expired and cannot be refreshed. Please reconnect.",
                provider
            )))
        }
        Err(e) => {
            let _ = baluard_core::providers::token::disconnect(provider);
            Err(err_response(format!(
                "{:?} token refresh failed: {e}. Please reconnect.",
                provider
            )))
        }
    }
}

/// Refresh any connected provider whose token is expired, before a sync op.
///
/// git2 credential callbacks load tokens straight from the keyring; if a
/// GitLab token lapsed between operations, the push/pull would fail with an
/// auth error. Calling this first keeps the keyring entry fresh. GitHub
/// tokens never expire (refresh is a no-op). Errors are logged but non-fatal:
/// a failed refresh surfaces on the subsequent sync attempt, not here.
async fn refresh_connected_tokens_if_needed() {
    let state = match baluard_core::providers::token::ProvidersState::load() {
        Ok(s) => s,
        Err(_) => return,
    };
    for provider in baluard_core::providers::types::Provider::all() {
        if let Some(info) = state.get(*provider) {
            if ensure_valid_token(*provider, info).await.is_err() {
                log::warn!("[daemon] pre-sync token refresh failed for {:?}", provider);
            }
        }
    }
}

// ── Web-OAuth (auth-code + PKCE) callback infrastructure ──
// Used by Codeberg/Forgejo (no device flow). The daemon starts a localhost
// TCP listener, the desktop opens the auth URL in a browser, the provider
// redirects to http://127.0.0.1:<port>/callback?code=...&state=... and the
// daemon exchanges the code for a token.

// ── Web-OAuth (auth-code + PKCE) callback infrastructure ──
// Used by Codeberg/Forgejo (no device flow). The daemon starts a localhost
// TCP listener, the desktop opens the auth URL in a browser, the provider
// redirects to http://127.0.0.1:<port>/callback?code=...&state=... and the
// daemon exchanges the code for a token.
//
// B1 fix: sessions are keyed by provider (not a single global Option) so a
// concurrent flow for a different provider cannot overwrite another. M4 fix:
// starting a new flow for the SAME provider aborts the prior listener task,
// freeing its port immediately instead of waiting for the 5-min timeout.

struct OAuthSession {
    result: Option<Result<String, String>>, // Ok(username) | Err(msg)
    /// Handle to the callback listener task. Aborted when the same provider
    /// starts a new flow, dropping the listener and closing its port.
    task: Option<tokio::task::JoinHandle<()>>,
}

static OAUTH_SESSIONS: std::sync::LazyLock<
    tokio::sync::Mutex<
        std::collections::HashMap<baluard_core::providers::types::Provider, OAuthSession>,
    >,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

/// Start a web-OAuth flow: bind a loopback listener, build the auth URL,
/// spawn the callback handler, return the URL for the desktop to open.
async fn start_web_oauth(
    provider: baluard_core::providers::types::Provider,
    config: baluard_core::providers::ProviderConfig,
) -> Result<String, String> {
    let prov = baluard_core::providers::provider_for(provider, config.clone())
        .map_err(|e| e.to_string())?;

    // Bind a random loopback port for the callback. RFC 8252 §7.3 says loopback
    // redirects allow any port, so we bind :0 (OS-assigned). Forgejo's OAuth2
    // provider is documented to honor this for public clients registered with
    // `http://127.0.0.1/` as the redirect URI.
    //
    // TODO(H1, release-gate): verify Codeberg (Forgejo) actually accepts a
    // dynamic-port redirect at runtime before shipping the automatic flow.
    // If Codeberg requires an exact registered port, register a fixed port
    // here and change the bind to `127.0.0.1:<FIXED>` to match. Test
    // end-to-end against codeberg.org. Tracked in docs/git-provider-apps-
    // and-tokens.md §9.6. Until verified, Codeberg users fall back to PAT.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get listener addr: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let oauth = prov
        .oauth_start(&redirect_uri)
        .await
        .map_err(|e| format!("oauth_start failed: {e}"))?;

    // Spawn the callback listener (accepts one connection, then exits).
    let verifier = oauth.code_verifier.clone();
    let expected_state = oauth.state.clone();
    let task = tokio::spawn(async move {
        handle_oauth_callback(
            listener,
            provider,
            config,
            verifier,
            expected_state,
            redirect_uri,
        )
        .await;
    });

    // Replace any prior session for this provider: abort its listener (M4) so
    // its port is freed immediately, then record the new one.
    {
        let mut sessions = OAUTH_SESSIONS.lock().await;
        if let Some(mut old) = sessions.insert(
            provider,
            OAuthSession {
                result: None,
                task: Some(task),
            },
        ) {
            if let Some(t) = old.task.take() {
                t.abort();
            }
        }
    }

    Ok(oauth.auth_url)
}

/// Accept one HTTP request on the callback listener, extract code+state,
/// exchange for token, store result in the session.
async fn handle_oauth_callback(
    listener: tokio::net::TcpListener,
    provider: baluard_core::providers::types::Provider,
    config: baluard_core::providers::ProviderConfig,
    verifier: String,
    expected_state: String,
    redirect_uri: String,
) {
    // Accept one connection (timeout after 5 minutes).
    let (mut sock, _) =
        match tokio::time::timeout(std::time::Duration::from_secs(300), listener.accept()).await {
            Ok(Ok(conn)) => conn,
            _ => {
                set_oauth_result(provider, Err("callback timeout".into())).await;
                return;
            }
        };

    // Read the HTTP request until the header terminator (\r\n\r\n). M3: a
    // single read() is not guaranteed to return all data; loop until the
    // terminator appears or we hit the buffer cap.
    let mut buf = vec![0u8; 8192];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            break; // header too large; proceed with what we have
        }
        let n = match sock.read(&mut buf[total..]).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(_) => break,
        };
        total += n;
        if String::from_utf8_lossy(&buf[..total]).contains("\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&buf[..total]);

    // Extract code + state from the request line: GET /callback?code=X&state=Y
    let (code, state) = match parse_callback_query(&request) {
        Some(pair) => pair,
        None => {
            let _ = respond_html(&mut sock, "Missing code or state in callback.").await;
            set_oauth_result(provider, Err("missing code/state".into())).await;
            return;
        }
    };

    if state != expected_state {
        let _ = respond_html(&mut sock, "CSRF state mismatch. Authentication aborted.").await;
        set_oauth_result(provider, Err("CSRF state mismatch".into())).await;
        return;
    }

    // Exchange code for token.
    let prov = match baluard_core::providers::provider_for(provider, config) {
        Ok(p) => p,
        Err(e) => {
            let _ = respond_html(&mut sock, &format!("Provider error: {e}")).await;
            set_oauth_result(provider, Err(e.to_string())).await;
            return;
        }
    };

    match prov.oauth_exchange(&code, &verifier, &redirect_uri).await {
        Ok((token, info)) => {
            if let Err(e) =
                baluard_core::providers::token::store_token(info.provider, &info.username, &token)
            {
                let _ = respond_html(&mut sock, &format!("Keyring error: {e}")).await;
                set_oauth_result(provider, Err(format!("Keyring: {e}"))).await;
                return;
            }
            let mut state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            state_file.set(info.clone());
            if let Err(e) = state_file.save() {
                let _ = baluard_core::providers::token::delete_token(info.provider, &info.username);
                let _ = respond_html(&mut sock, &format!("State save error: {e}")).await;
                set_oauth_result(provider, Err(format!("State: {e}"))).await;
                return;
            }
            let _ = respond_html(
                &mut sock,
                "Authentication successful! You can close this tab and return to Baluard.",
            )
            .await;
            set_oauth_result(provider, Ok(info.username)).await;
        }
        Err(e) => {
            let _ = respond_html(&mut sock, &format!("Authentication failed: {e}")).await;
            set_oauth_result(provider, Err(e.to_string())).await;
        }
    }
}

/// Escape HTML metacharacters. H2: provider API error bodies may contain
/// <, >, &, ", ' — interpolating them raw into the callback response page is
/// an XSS surface (local-only, but fail closed).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

async fn respond_html(sock: &mut tokio::net::TcpStream, msg: &str) -> std::io::Result<()> {
    let safe = html_escape(msg);
    let body = format!(
        "<html><body style='font-family:sans-serif;text-align:center;padding:40px'>\
         <h2>{safe}</h2></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    sock.write_all(response.as_bytes()).await
}

async fn set_oauth_result(
    provider: baluard_core::providers::types::Provider,
    result: Result<String, String>,
) {
    let mut sessions = OAUTH_SESSIONS.lock().await;
    if let Some(s) = sessions.get_mut(&provider) {
        s.result = Some(result);
    }
}

/// Parse code + state from a GET request line: `GET /callback?code=X&state=Y HTTP/1.1`.
fn parse_callback_query(request: &str) -> Option<(String, String)> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        match kv.next()? {
            "code" => code = kv.next().map(urldecode),
            "state" => state = kv.next().map(urldecode),
            _ => {}
        }
    }
    Some((code?, state?))
}

/// Minimal URL-decoder for %XX sequences.
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract the slug field from a JSON payload. Returns `None` when the
/// payload is not JSON, has no `slug` field, or the field is empty. Used to
/// route vault-level requests to a specific vault in the host map.
fn extract_slug(payload: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    v.get("slug")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Outcome of checking the on-disk `.baluard` marker against the
/// registry's vault_id during `vaults.detach`. The caller decides whether
/// a non-`Match` outcome is fatal or just advisory based on the `force`
/// flag — see the route's comments.
enum MarkerCheck {
    Match,
    /// Marker file does not exist (or is empty / could not be opened as
    /// a regular file). Distinct from `Unreadable` because the daemon
    /// can confidently say "no marker here" — `force` may proceed.
    Missing,
    /// Marker file exists but the daemon could not parse or read it
    /// (I/O error, partial write, garbage JSON). Distinct from `Missing`
    /// because the daemon has NOT positively verified that the file is
    /// absent — `force` still proceeds, but the audit log records the
    /// original error so forensics are not lost.
    Unreadable {
        error: String,
    },
    /// Marker file parsed cleanly but its `vault_id` does not match the
    /// registry entry. Almost always a stale registry pointing at a
    /// reused directory.
    Mismatch {
        on_disk: uuid::Uuid,
    },
}

/// Top-level Phase 6 dispatcher. Host-level routes (no target vault needed)
/// are served here; everything else resolves a target `Arc<VaultState>` and
/// delegates to `route_request`. The snapshot is taken ONCE per request so a
/// mid-request `switch` cannot re-route an in-flight operation.
pub async fn route_host_request(req: GatewayRequest, host: &SharedVaultHost) -> GatewayResponse {
    log::debug!(
        "[daemon] <- action={} has_token={} slug={} payload_slug={}",
        req.action,
        !req.session_token.is_empty(),
        req.slug,
        extract_slug(&req.payload).is_some()
    );

    // ── Host-level routes: no target vault needed ──
    match req.action.as_str() {
        "ping" => return ok_resp("pong", None),

        // `vaults.*` routes operate on the host map + registry.
        "vaults.list" => {
            let rows = host.list().await;
            return ok_resp(
                serde_json::to_string(&serde_json::json!({"vaults": rows})).unwrap_or_default(),
                None,
            );
        }
        "vaults.active" => {
            let slug = host.active_slug().await;
            return match slug {
                Some(s) => {
                    let presence = match host.get(&s).await {
                        Some(state) => {
                            if state.is_unlocked().await {
                                VaultPresence::Unlocked
                            } else {
                                VaultPresence::Locked
                            }
                        }
                        None => VaultPresence::Closed,
                    };
                    ok_resp(
                        serde_json::json!({
                            "slug": s,
                            "presence": presence.as_str(),
                        })
                        .to_string(),
                        None,
                    )
                }
                None => err_response("No active vault".to_string()),
            };
        }
        "vaults.switch" => {
            let slug = match extract_slug(&req.payload) {
                Some(s) => s,
                None => return err_response("Missing 'slug' for vaults.switch"),
            };
            // If the vault is in the registry but not in the host map (closed), load and open it.
            if host.get(&slug).await.is_none() {
                if let Ok(reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
                    if let Some(entry) = reg.get(&slug) {
                        let path = entry.path.clone();
                        let state = host
                            .get_or_insert_with(&slug, move || {
                                Arc::new(VaultState::new(path.clone()))
                            })
                            .await;
                        let _ = state.open().await;
                    }
                }
            }
            match host.switch(&slug).await {
                Ok(outcome) => {
                    // Touch registry last_opened OUTSIDE the host write lock
                    // (no I/O in the critical section — best-effort metadata).
                    if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked()
                    {
                        reg.touch(&outcome.slug);
                        let _ = reg.save_locked();
                    }
                    return ok_resp(
                        serde_json::json!({
                            "active": outcome.slug,
                            "presence": outcome.presence.as_str(),
                        })
                        .to_string(),
                        None,
                    );
                }
                Err(crate::host::SwitchError::UnknownSlug(s)) => {
                    return err_response(format!(
                        "Vault '{s}' is not open in the daemon. \
                         Run `baluard unlock --vault {s}` or switch to an open vault."
                    ));
                }
                Err(crate::host::SwitchError::Registry(e)) => {
                    return err_response(format!("Registry error: {e}"));
                }
            }
        }
        "vaults.set_active" => {
            let slug = match extract_slug(&req.payload) {
                Some(s) => s,
                None => return err_response("Missing 'slug' for vaults.set_active"),
            };
            match host.set_active_registry(&slug).await {
                Ok(()) => return ok_resp(serde_json::json!({"active": slug}).to_string(), None),
                Err(crate::host::SwitchError::UnknownSlug(s)) => {
                    return err_response(format!("Vault '{s}' not found in registry"));
                }
                Err(crate::host::SwitchError::Registry(e)) => {
                    return err_response(format!("Registry error: {e}"));
                }
            }
        }
        "vaults.close" => {
            let slug = match extract_slug(&req.payload) {
                Some(s) => s,
                None => return err_response("Missing 'slug' for vaults.close"),
            };
            let removed = host.close(&slug).await;
            return if removed {
                ok_resp(serde_json::json!({"closed": slug}).to_string(), None)
            } else {
                err_response(format!(
                    "Vault '{slug}' was not open in the daemon (already closed)"
                ))
            };
        }

        // vaults.detach: remove a vault from the registry so it no longer
        // appears in the app. Works pre-unlock on locked/closed/unlocked
        // vaults. Optionally deletes the on-disk vault directory when the
        // caller explicitly opts in (delete_from_disk: true) — used by the
        // desktop modal's "Also delete from disk (permanent)" arm and the
        // CLI's `--delete-from-disk` flag.
        //
        // Safety on the destructive arm (defense-in-depth, three layers):
        //   1. **Registry mutation happens first, then `host.close()`** —
        //      if `save_locked()` fails, the in-memory state is unchanged
        //      and the operation is a clean no-op. The previous order
        //      (close first, save second) leaked a locked-but-still-
        //      registered vault on save failure.
        //   2. **The .baluard marker gate is enforced on disk delete**.
        //      Three states:
        //        - `Match`: registry and disk agree, proceed.
        //        - `Missing` / `Unreadable`: daemon cannot verify. Refused
        //          by default, bypassed by `force=true` (typed-name modal
        //          or CLI slug retyping already established intent).
        //        - `Mismatch`: POSITIVE evidence the directory is a
        //          different vault. Refused UNCONDITIONALLY — `force` does
        //          not override this, because the typed-name gate echoes
        //          the registry's own `display_name` and proves nothing
        //          about the directory contents. The user must fix the
        //          marker, rename the directory, or `rm -rf` manually.
        //   3. **A missing directory is treated as already-deleted**
        //      (idempotent stale-registry cleanup), not an error.
        //
        // Returns { slug, deleted_from_disk, path }.
        "vaults.detach" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(v) => v,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let Some(slug) = payload["slug"].as_str() else {
                return err_response("Missing 'slug' for vaults.detach");
            };
            let delete_from_disk = payload["delete_from_disk"].as_bool().unwrap_or(false);
            // `force` opts in to overriding the `Missing` / `Unreadable`
            // marker states. It does NOT bypass `Mismatch` — see safety
            // layer 2 above. The desktop modal (typed-name match) and the
            // CLI (`--delete-from-disk` with slug retyping) always set
            // `force=true` on the destructive arm.
            let force = payload["force"].as_bool().unwrap_or(false);

            // Single load: remove + save in one lock cycle. `VaultRegistry::remove`
            // returns the removed entry, giving us the path + vault_id
            // without a second load (which would have been a TOCTOU
            // window — `save_locked`'s file lock is per-call, not per-
            // handler, so a concurrent process could mutate the registry
            // between two loads).
            let mut reg = match baluard_core::vault::registry::VaultRegistry::load_locked() {
                Ok(reg) => reg,
                Err(e) => return err_response(format!("Registry load failed: {e}")),
            };
            let entry = match reg.remove(slug) {
                Some(e) => e,
                None => {
                    return err_response(format!(
                        "Vault '{slug}' is not registered in Baluard"
                    ));
                }
            };
            // Persist BEFORE `host.close`. If `save_locked` fails, the
            // in-memory state is unchanged — the user gets an error and
            // the vault is intact. `host.close` cannot fail (in-memory
            // only), so persisting first makes the whole operation
            // fail-closed.
            if let Err(e) = reg.save_locked() {
                return err_response(format!("Registry save failed: {e}"));
            }

            let entry_path = entry.path.clone();
            let entry_vault_id = entry.vault_id;

            // Now safe to drop the vault from the in-memory map. Idempotent:
            // no-op if the slug is not in the map (closed vault). Any
            // in-flight handlers zeroize on their last Arc drop. Clearing
            // active matters because the registry removal that just
            // happened would otherwise leave the in-memory pointer
            // dangling until the next switch.
            let _ = host.close(slug).await;

            let mut deleted_from_disk = false;
            if delete_from_disk {
                let path = &entry_path;
                if path.exists() {
                    let marker_state = match baluard_core::vault::registry::BaluardMarker::read_from_vault(path) {
                        Ok(Some(m)) if m.vault_id == entry_vault_id => MarkerCheck::Match,
                        Ok(Some(m)) => MarkerCheck::Mismatch {
                            on_disk: m.vault_id,
                        },
                        Ok(None) => MarkerCheck::Missing,
                        Err(e) => MarkerCheck::Unreadable { error: e.to_string() },
                    };
                    match marker_state {
                        MarkerCheck::Match => {}
                        MarkerCheck::Mismatch { on_disk } => {
                            // UNCONDITIONAL refusal. The on-disk marker
                            // belongs to a different vault; the typed-name
                            // gate the desktop/CLI uses echoes the
                            // registry's own `display_name` and proves
                            // nothing about the directory's actual
                            // contents. Bypassing here would mean
                            // `remove_dir_all` on a directory the daemon
                            // has positive evidence is not the named
                            // vault. Manual cleanup is the only safe path.
                            log::warn!(
                                "[daemon] vaults.detach: REFUSING to delete {} — .baluard \
                                 marker vault_id mismatch (on disk: {on_disk}, registry: \
                                 {entry_vault_id}, slug={slug}). This is the one state \
                                 `force` does not override; user must fix the marker, \
                                 rename the directory, or rm -rf manually.",
                                path.display()
                            );
                            return err_response(format!(
                                "Refusing to delete {}: .baluard marker vault_id does not \
                                 match the registry (on disk: {on_disk}, registry: \
                                 {entry_vault_id}). This is the one marker state the \
                                 `force` flag does not override — the typed-name gate \
                                 proves nothing about the directory's actual contents \
                                 when the marker positively disagrees with the \
                                 registry. To clean up: rename the directory, fix the \
                                 .baluard marker inside it, or remove it manually \
                                 (e.g. `rm -rf`).",
                                path.display()
                            ));
                        }
                        MarkerCheck::Missing => {
                            if !force {
                                return err_response(format!(
                                    "Refusing to delete {}: .baluard marker is missing. \
                                     Pass force=true if the caller has already established \
                                     user intent through another gate (typed-name modal, CLI \
                                     slug retyping).",
                                    path.display()
                                ));
                            }
                            log::warn!(
                                "[daemon] vaults.detach: FORCE-deleting {} despite missing \
                                 .baluard marker (slug={slug}). Caller confirmed intent via \
                                 user-visible gate.",
                                path.display()
                            );
                        }
                        MarkerCheck::Unreadable { error } => {
                            // The marker file was not positively absent — the
                            // daemon could not read or parse it. The user has
                            // typed the vault name in the desktop modal or
                            // retyped the slug in the CLI, so we treat the
                            // intent signal as strong enough to proceed on
                            // `force`, but the original error is preserved
                            // in both the refusal message and the audit log
                            // so the deletion is traceable to a real I/O
                            // failure rather than a "missing marker" claim.
                            if !force {
                                return err_response(format!(
                                    "Refusing to delete {}: .baluard marker could not be \
                                     read ({error}). Pass force=true if the caller has \
                                     already established user intent through another gate \
                                     (typed-name modal, CLI slug retyping).",
                                    path.display()
                                ));
                            }
                            log::warn!(
                                "[daemon] vaults.detach: FORCE-deleting {} despite \
                                 unreadable .baluard marker (error: {error}, slug={slug}). \
                                 Caller confirmed intent via user-visible gate.",
                                path.display()
                            );
                        }
                    }
                    if let Err(e) = std::fs::remove_dir_all(path) {
                        return err_response(format!(
                            "Detached '{slug}' from Baluard, but disk delete failed: {e}"
                        ));
                    }
                    deleted_from_disk = true;
                    log::warn!(
                        "[daemon] vaults.detach: deleted vault directory {} (slug={slug})",
                        path.display()
                    );
                } else {
                    // Already gone: treat as success so stale-entry cleanup
                    // stays idempotent.
                    deleted_from_disk = true;
                    log::info!(
                        "[daemon] vaults.detach: directory {} already absent (slug={slug})",
                        path.display()
                    );
                }
            }

            return ok_resp(
                serde_json::json!({
                    "slug": slug,
                    "deleted_from_disk": deleted_from_disk,
                    "path": entry_path.to_string_lossy(),
                })
                .to_string(),
                None,
            );
        }

        // vaults.register_local (Phase 4): register an existing local vault
        // directory (already has a .baluard marker) into the registry without
        // copying it. Used by the "Open local vault" entry point. Pre-unlock /
        // host-level: validates the marker + path, adds the entry, sets it
        // active. Returns { slug, vault_id }.
        "vaults.register_local" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(v) => v,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let Some(path_str) = payload["path"].as_str() else {
                return err_response("Missing 'path' for vaults.register_local");
            };
            let path = std::path::PathBuf::from(path_str);
            let marker =
                match baluard_core::vault::registry::BaluardMarker::read_from_vault(&path) {
                    Ok(Some(m)) => m,
                    Ok(None) => {
                        return err_response(
                            "Not a Baluard vault: no .baluard marker found at the selected path",
                        )
                    }
                    Err(e) => return err_response(format!("Failed to read marker: {e}")),
                };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let entry = baluard_core::vault::registry::VaultEntry {
                slug: marker.slug.clone(),
                display_name: marker.slug.clone(),
                path: path.clone(),
                provider: None,
                remote_url: None,
                last_synced: None,
                last_opened: Some(now),
                vault_id: marker.vault_id,
            };
            match baluard_core::vault::registry::VaultRegistry::load_locked() {
                Ok(mut reg) => {
                    if let Err(e) = reg.add(entry.clone()) {
                        return err_response(format!("Registry add failed: {e}"));
                    }
                    let _ = reg.set_active(&entry.slug);
                    if let Err(e) = reg.save_locked() {
                        return err_response(format!("Registry save failed: {e}"));
                    }
                    return ok_resp(
                        serde_json::json!({
                            "slug": entry.slug,
                            "vault_id": entry.vault_id,
                        })
                        .to_string(),
                        None,
                    );
                }
                Err(e) => return err_response(format!("Registry load failed: {e}")),
            }
        }

        // vaults.lock_all: lock every currently-unlocked vault (zeroize all
        // key material). Fired by the desktop on screen-lock / system sleep /
        // window-blur (app resign-active) so a device becoming unattended
        // caps multi-vault exposure immediately instead of waiting for each
        // vault's idle timer. No token: this is a defensive primitive, not a
        // data-access op. Returns the count of vaults locked.
        "vaults.lock_all" => {
            let locked = host.lock_all().await;
            log::info!("[daemon] lock_all fired: locked {locked} vault(s)");
            return ok_resp(serde_json::json!({"locked": locked}).to_string(), None);
        }

        // vaults.on_app_blur: policy-driven lock on window blur / minimize.
        // Replaces the old unconditional lock_all the desktop fired on every
        // focus loss. Now each vault locks only if its timeout policy is
        // `Immediately`; `Minutes`/`OnAppExit` are left alone (the
        // idle walker + app exit already cover them). Returns the
        // count locked so the desktop can clear just those tokens.
        "vaults.on_app_blur" => {
            let locked = host.lock_blur_vaults().await;
            log::info!("[daemon] on_app_blur: locked {locked} Immediately-policy vault(s)");
            return ok_resp(serde_json::json!({"locked": locked}).to_string(), None);
        }

        // vault.active (singular): legacy alias for the active-vault lookup.
        // L1: host-level so it works pre-unlock (it only reads the plaintext
        // registry; previously it required a vault snapshot, which was odd
        // and failed when no vault was open). vaults.active (plural) is the
        // richer Phase 6 route (includes presence); this stays for back-compat
        // with the desktop's onMount pre-unlock probe.
        "vault.active" => {
            return match baluard_core::vault::registry::VaultRegistry::load() {
                Ok(reg) => {
                    let entry = reg
                        .active_vault
                        .as_ref()
                        .and_then(|slug| reg.vaults.get(slug));
                    match entry {
                        Some(e) => ok_resp(
                            serde_json::json!({
                                "slug": e.slug,
                                "display_name": e.display_name
                            })
                            .to_string(),
                            None,
                        ),
                        None => err_response("No active vault".to_string()),
                    }
                }
                Err(e) => err_response(format!("Registry error: {e}")),
            };
        }

        // Provider routes: split by whether they need a vault (NEW-1).
        //
        // The UN-GATED provider routes (list / connect_* / status / disconnect)
        // operate on the keyring + providers.json only — no vault needed. They
        // run pre-unlock (first-run sync setup) via a sentinel VaultState that
        // these arms never dereference. Without this they fell through to
        // snapshot_target and failed with "No active vault" on a fresh
        // install (H2).
        //
        // The TOKEN-GATED provider routes (oauth_start_web / oauth_status_web
        // / create_repo) DO require a vault — they're in
        // TOKEN_REQUIRED_ACTIONS, so route_request checks the session token.
        // Routing them through the tokenless sentinel would always reject
        // them (NEW-1 regression). They fall through to snapshot_target so
        // they resolve a real vault and check against ITS token.
        // (Phase 4: repos / vault_repos were moved to the un-gated arm above
        // because the clone/download flow lists repos before any unlock.)
        "provider.list"
        | "provider.connect_start"
        | "provider.connect_poll"
        | "provider.connect_pat"
        | "provider.status"
        | "provider.disconnect"
        // Phase 4: repos / vault_repos are read-only provider operations
        // (keyring token only, no vault state) and must work pre-unlock for
        // the download-from-provider flow on a fresh device.
        | "provider.repos"
        | "provider.vault_repos" => {
            let sentinel = std::sync::Arc::new(VaultState::new(std::path::PathBuf::new()));
            return route_request(req, &sentinel).await;
        }

        // provider.oauth_start_web / oauth_status_web / create_repo
        // → fall through to the vault-snapshot path below.
        _ => {}
    }

    // ── Vault lifecycle: open / unlock / create need host-level handling ──
    // because they may insert a fresh VaultState into the map.
    if req.action.as_str() == "vault.unlock" {
        return handle_vault_unlock(req, host).await;
    }
    if req.action.as_str() == "vault.create" {
        return handle_vault_create(req, host).await;
    }
    if req.action.as_str() == "vault.open" {
        return handle_vault_open(req, host).await;
    }
    // Biometric unlock is a host-level lifecycle op: it mints a session
    // token (via state.unlock internally) and the desktop files that token
    // under the vault slug. It therefore must mirror vault.unlock's
    // contract of returning {slug} in the payload, or the desktop's
    // SessionStore drops the token (handler-level routing has no slug in
    // scope). Resolved here so we know which vault to unlock.
    if req.action.as_str() == "vault.biometric_unlock" {
        return handle_vault_biometric_unlock(req, host).await;
    }
    // Session PIN unlock is a host-level lifecycle op for the same reason as
    // biometric_unlock: it mints a session token and must return {slug} so
    // the desktop can file the token under the right vault.
    if req.action.as_str() == "vault.pin_unlock" {
        return handle_vault_pin_unlock(req, host).await;
    }
    // Phase 4 remote vault clone: host-level, pre-unlock (NOT token-gated).
    if req.action.as_str() == "vault.clone_start" {
        return handle_vault_clone_start(req, host).await;
    }
    if req.action.as_str() == "vault.clone_progress" {
        return handle_vault_clone_progress(req, host).await;
    }
    if req.action.as_str() == "vault.clone_finalize" {
        return handle_vault_clone_finalize(req, host).await;
    }

    // ── Browser bridge (bridge.*) — host-level, vault-agnostic (Decision 10) ──
    if let Some(resp) = handle_bridge_host_route(req.clone(), host).await {
        return resp;
    }

    // ── Bridge-token detection (Decision 5). Branch BEFORE the per-vault ──
    // session-token gate: if the request carries a valid bridge token, we
    // enforce the bridge allowlist (NOT TOKEN_REQUIRED_ACTIONS) + the
    // vault.update field gate, then snapshot the ACTIVE vault (bridge tokens
    // are slug-agnostic). Otherwise fall through to the existing per-vault path.
    //
    // Fast path: bridge tokens are always 64-char hex. If the
    // request's token is empty or a different shape, skip the registry lock
    // entirely so the common desktop/CLI path never contends on the bridge
    // mutex. verify_token does the same length gate, but avoiding the
    // `.read().await` on the hot path matters more for latency.
    if req.session_token.len() == 64 {
        let pairing_id = host.bridge().read().await.verify_token(&req.session_token);
        if let Some(pairing_id) = pairing_id {
            return route_bridge_request(req, host, pairing_id).await;
        }
        // A bridge-shaped (64-hex) token that no longer matches a live
        // registry entry: the daemon restarted, the pairing was revoked, or
        // the token expired (the live token map is in-memory only). `bridge.*`
        // actions are served EXCLUSIVELY via bridge tokens — the desktop/CLI
        // never call them — and they aren't routed in the normal path below,
        // so letting them fall through would surface a confusing
        // `"Unknown action: bridge.match"` to the user. Reject with the
        // shared sentinel so the NMH can drop its stale cache, re-`reauth`,
        // and retry once. (Non-`bridge.*` actions legitimately use 64-hex
        // session tokens, so they keep falling through unchanged.)
        if req.action.starts_with("bridge.") {
            return err_response(baluard_core::bridge::STALE_TOKEN_ERROR);
        }
    }

    // ── Everything else: resolve target slug + snapshot, then delegate ──
    // Phase 6: target slug resolution priority: req.slug (proto field, M2) →
    // payload JSON `slug` (legacy/inline) → active pointer. req.slug is the
    // primary path now; the payload fallback covers older clients.
    let explicit_slug = if !req.slug.is_empty() {
        Some(req.slug.clone())
    } else {
        extract_slug(&req.payload)
    };
    let snapshot = match host.snapshot_target(explicit_slug.as_deref()).await {
        Ok(pair) => pair,
        Err(SnapshotError::NoActive) => {
            return err_response(
                "No active vault. Open or unlock one first, or pass a 'slug'.".to_string(),
            );
        }
        Err(SnapshotError::SlugNotOpen(slug)) => {
            return err_response(format!(
                "Vault '{slug}' is not open in the daemon. \
                 Run `baluard unlock --vault {slug}` first."
            ));
        }
    };

    // The (slug, Arc<VaultState>) snapshot is now pinned for this request.
    let _slug_for_log = snapshot.0.clone();
    let state: SharedVaultState = snapshot.1;
    route_request(req, &state).await
}

// ── Browser bridge routing ─────────────────────────────────────────────
//
// `handle_bridge_host_route`: the bridge.* routes that are NOT token-gated
//   the normal way (pair_start is desktop-token-gated; pair_complete is
//   approval-gated; reauth is secret-gated; list/revoke are desktop-token-
//   gated). Returns Some(resp) when it handled the action, None otherwise.
//
// `route_bridge_request`: the allowlisted actions a bridge token permits,
//   run AFTER bridge-token verification. Enforces BRIDGE_ALLOWED_ACTIONS +
//   the vault.update field gate (no fido2_credentials / uris) + the
//   per-pairing read-rate cap.

/// Handle the pairing/ceremony host routes. Returns None if `req.action` is
/// not a bridge.* route (caller continues to the per-vault path).
async fn handle_bridge_host_route(
    req: GatewayRequest,
    host: &SharedVaultHost,
) -> Option<GatewayResponse> {
    use crate::bridge as br;
    match req.action.as_str() {
        // Desktop-initiated pairing ceremony (Decision 4 approve-don't-type).
        // pair_start is desktop-token-gated (the "Add browser extension"
        // button). It creates a pending-approval handle; it does NOT mint
        // any token.
        "bridge.pair_start" => {
            // Require a valid desktop session token: pick the active vault
            // and check its token. This proves the caller is the desktop.
            let slug = host.active_slug().await?;
            let state = host.get(&slug).await?;
            if state
                .verify_session_token(&req.session_token)
                .await
                .is_err()
            {
                return Some(err_response("desktop session token required"));
            }
            let payload: serde_json::Value =
                serde_json::from_str(&req.payload).unwrap_or(serde_json::json!({}));
            let browser_hint = payload["browser"]
                .as_str()
                .unwrap_or("a browser")
                .to_string();
            let request_id = host.bridge().write().await.start_pair(browser_hint.clone());
            Some(ok_resp(
                serde_json::json!({
                    "request_id": request_id,
                    "browser_hint": browser_hint,
                    "ttl_seconds": br::PENDING_TTL_SECONDS,
                })
                .to_string(),
                None,
            ))
        }

        // Called by the extension/NMH. Registered as a waiter and HELD until
        // the desktop user clicks Approve (which resolves the waiter). Not
        // token-gated (the extension has no token yet). If the desktop
        // approves before the extension calls, the next pair_complete
        // proceeds immediately (fast path).
        "bridge.pair_complete" => {
            let payload: serde_json::Value = serde_json::from_str(&req.payload)
                .map_err(|e| format!("Invalid JSON: {e}"))
                .ok()?;
            let name = payload["name"].as_str().unwrap_or("Browser").to_string();
            let browser = payload["browser"].as_str().unwrap_or("unknown").to_string();

            // Fast path: desktop already approved (pending marked Approved).
            let already_approved = host
                .bridge()
                .read()
                .await
                .pending()
                .map(|p| matches!(p.approval, Some(crate::bridge::PairApproval::Approved)))
                .unwrap_or(false);
            if already_approved {
                let mut reg = host.bridge().write().await;
                return Some(finalize_pair(&mut reg, name, browser).await);
            }

            // Slow path: register a waiter and block until the desktop
            // approves or the TTL expires.
            let rx = host
                .bridge()
                .write()
                .await
                .register_waiter(name.clone(), browser.clone());
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(crate::bridge::PENDING_TTL_SECONDS),
                rx,
            )
            .await;
            match result {
                Ok(Ok(_payload)) => {
                    let mut reg = host.bridge().write().await;
                    Some(finalize_pair(&mut reg, name, browser).await)
                }
                _ => {
                    // Timeout or sender dropped (superseded). Fail closed.
                    Some(err_response("pairing timed out or was superseded"))
                }
            }
        }

        // Desktop "Approve" button consumes the pending flag. Token-gated
        // (desktop only).
        "bridge.pair_approve" => {
            let slug = host.active_slug().await?;
            let state = host.get(&slug).await?;
            if state
                .verify_session_token(&req.session_token)
                .await
                .is_err()
            {
                return Some(err_response("desktop session token required"));
            }
            let mut reg = host.bridge().write().await;
            match reg.approve_pending() {
                Ok(request_id) => Some(ok_resp(
                    serde_json::json!({
                        "request_id": request_id,
                        "approved": true,
                    })
                    .to_string(),
                    None,
                )),
                Err(msg) => Some(err_response(msg.to_string())),
            }
        }

        // NMH spawn-time re-mint (Decision 3/8). Secret-gated, idempotent.
        "bridge.reauth" => {
            let payload: serde_json::Value = serde_json::from_str(&req.payload)
                .map_err(|e| format!("Invalid JSON: {e}"))
                .ok()?;
            let secret_hex = payload["secret"].as_str()?.to_string();
            let mut reg = host.bridge().write().await;
            match reg.reauth(&secret_hex) {
                br::ReauthOutcome::Ok {
                    token_hex,
                    pairing_id,
                } => Some(ok_resp(
                    serde_json::json!({
                        "pairing_id": pairing_id.to_string(),
                        "token": token_hex,
                    })
                    .to_string(),
                    None,
                )),
                br::ReauthOutcome::NotPaired => Some(err_response("not-paired")),
            }
        }

        // Desktop UI: list paired browsers. Token-gated.
        "bridge.list" => {
            let slug = host.active_slug().await?;
            let state = host.get(&slug).await?;
            if state
                .verify_session_token(&req.session_token)
                .await
                .is_err()
            {
                return Some(err_response("desktop session token required"));
            }
            let pf = baluard_core::bridge::pairing::PairingFile::load().unwrap_or_default();
            Some(ok_resp(
                serde_json::json!({ "pairings": pf.pairings }).to_string(),
                None,
            ))
        }

        // Desktop UI: peek the pending pairing ceremony state so the UI can
        // show "extension connected" the moment pair_complete arrives. Token-
        // gated (desktop only).
        "bridge.pending" => {
            let slug = host.active_slug().await?;
            let state = host.get(&slug).await?;
            if state
                .verify_session_token(&req.session_token)
                .await
                .is_err()
            {
                return Some(err_response("desktop session token required"));
            }
            let reg = host.bridge().read().await;
            Some(ok_resp(
                serde_json::json!({
                    "pending": reg.pending().is_some(),
                    "extension_connected": reg.has_waiter(),
                    "browser_hint": reg.pending().map(|p| p.browser_hint.clone()).unwrap_or_default(),
                })
                .to_string(),
                None,
            ))
        }

        // Desktop UI: revoke a paired browser. Token-gated. Drops the
        // in-memory token AND the pairing-file entry.
        "bridge.revoke" => {
            let slug = host.active_slug().await?;
            let state = host.get(&slug).await?;
            if state
                .verify_session_token(&req.session_token)
                .await
                .is_err()
            {
                return Some(err_response("desktop session token required"));
            }
            let payload: serde_json::Value = serde_json::from_str(&req.payload)
                .map_err(|e| format!("Invalid JSON: {e}"))
                .ok()?;
            let pairing_id = payload["pairing_id"]
                .as_str()
                .map(|s| baluard_core::bridge::PairingId::from(s.to_string()))?;
            let mut reg = host.bridge().write().await;
            match reg.revoke(&pairing_id) {
                Ok(()) => Some(ok_resp(
                    serde_json::json!({ "revoked": pairing_id.to_string() }).to_string(),
                    None,
                )),
                Err(msg) => Some(err_response(msg.to_string())),
            }
        }

        _ => None,
    }
}

/// Route an allowlisted action for a verified bridge token.
///
/// Enforces: BRIDGE_ALLOWED_ACTIONS (Decision 7); vault.update field gate
/// (no fido2_credentials, no uris — Decision 13); per-pairing read-rate cap
/// on bridge.match / vault.get; active vault MUST be unlocked
/// (Decision 5 lock binding). Then snapshots the active vault and delegates
/// the actual op (bridge.match / bridge.config are NEW; the rest reuse the
/// existing vault.* semantics via route_request).
async fn route_bridge_request(
    req: GatewayRequest,
    host: &SharedVaultHost,
    pairing_id: baluard_core::bridge::PairingId,
) -> GatewayResponse {
    use crate::bridge as br;

    log::debug!(
        "[daemon] <- action={} kind=Bridge pairing_id={}",
        req.action,
        pairing_id
    );

    // 1. Allowlist.
    if !br::BridgeRegistry::action_allowed(&req.action) {
        log::warn!(
            "[daemon] bridge token denied non-allowlisted action '{}'",
            req.action
        );
        return err_response(format!(
            "action '{}' not permitted for bridge token",
            req.action
        ));
    }

    // 2. Rate-cap secret reads. Only `vault.get` returns plaintext
    //    credentials; `bridge.match` returns metadata only (no passwords),
    //    so it is NOT capped — the toolbar badge legitimately calls it on
    //    every tab activate/update, and capping it would auto-revoke the
    //    pairing under normal browsing. vault.get remains
    //    capped to bound a browser-compromise exfil.
    let is_secret_read = req.action.as_str() == "vault.get";
    if is_secret_read {
        let over_cap = !host.bridge().write().await.charge_read(&pairing_id);
        if over_cap {
            log::warn!(
                "[daemon] bridge pairing {} exceeded read cap; auto-revoking",
                pairing_id
            );
            let _ = host.bridge().write().await.revoke(&pairing_id);
            return err_response("rate-limited: pairing revoked");
        }
    }

    // 3. vault.update field gate: reject fido2_credentials / uris mutation.
    if req.action.as_str() == "vault.update" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.payload) {
            if bridge_update_touches_forbidden(&v) {
                log::warn!(
                    "[daemon] bridge token denied vault.update touching fido2_credentials/uris"
                );
                return err_response("bridge tokens may not modify fido2_credentials or uris");
            }
        }
    }

    // 4. Snapshot the ACTIVE vault (bridge tokens are slug-agnostic).
    let snapshot = match host.snapshot_target(None).await {
        Ok(pair) => pair,
        Err(_) => return err_response("locked"),
    };
    let state: SharedVaultState = snapshot.1.clone();
    let active_slug = snapshot.0.clone();

    // 5. Active vault MUST be unlocked.
    if !state.is_unlocked().await {
        return err_response("locked");
    }

    // Resolve the active vault's display name for the popup header (review I8:
    // silent cross-vault hazard; the extension must show WHERE a capture/fill
    // lands). Best-effort: registry lookup, fall back to the slug.
    let vault_name = baluard_core::vault::registry::VaultRegistry::load_locked()
        .ok()
        .and_then(|r| r.get(&active_slug).map(|e| e.display_name.clone()))
        .unwrap_or_else(|| active_slug.clone());

    // 6. Dispatch the allowlisted action. bridge.match / bridge.config are
    //    NEW routes; the rest reuse the existing per-vault handler by
    //    stamping the vault's own token (the request was already allowlisted
    //    + field-gated + rate-capped, so delegating is safe).
    let delegated = {
        let mut d = req.clone();
        let tok = state.get_session_token().await.unwrap_or_default();
        d.session_token = tok;
        d
    };
    match req.action.as_str() {
        "bridge.match" => handle_bridge_match(req, &state, &vault_name).await,
        "bridge.config" => handle_bridge_config(&state).await,
        // vault.get / vault.add / vault.update / cipher.totp_code /
        // generator.* / sync.autosync_status all reuse the normal path.
        _ => route_request(delegated, &state).await,
    }
}

/// Does a vault.update payload attempt to mutate passkey or URI fields?
/// (Decision 13: bridge tokens may edit pw/user/notes/totp but NOT these.)
/// CipherKind serializes as {"type":"login","data":{...}} (#[serde(tag="type",
/// content="data")]), so the forbidden fields live under `kind.data`, NOT
/// `kind` directly. Path verified via serde round-trip.
fn bridge_update_touches_forbidden(payload: &serde_json::Value) -> bool {
    // Resolve the inner `data` block across the layouts the update handler
    // accepts: {kind:{type,data}}, {kind:{...fields}}, or {data:{...}}.
    let data = payload
        .get("kind")
        .and_then(|k| k.get("data"))
        .or_else(|| payload.get("data"))
        .or_else(|| payload.get("kind"));
    let Some(data) = data else {
        return false;
    };
    if data.get("fido2_credentials").is_some() {
        return true;
    }
    if data.get("uris").is_some() {
        return true;
    }
    false
}

/// bridge.match: URL -> matching CipherMeta (metadata only, no passwords).
///
/// v1: reuses the vault's `list_all` batch endpoint, filters server-side by
/// hostname, and returns ONLY metadata (id/name/username/type). Passwords
/// Finalize a pairing after approval: complete_pair (write pairing file +
/// mint first token), then build the response with the secret + token.
async fn finalize_pair(
    reg: &mut crate::bridge::BridgeRegistry,
    name: String,
    browser: String,
) -> GatewayResponse {
    match reg.complete_pair(name, browser) {
        Ok((pairing_id, token_hex)) => {
            // Return BOTH the pairing secret (for future reauth) and the first
            // bridge token. The NMH persists the secret.
            let pf = baluard_core::bridge::pairing::PairingFile::load().unwrap_or_default();
            let secret_hex = pf
                .get(&pairing_id)
                .map(|e| e.secret.clone())
                .unwrap_or_default();
            ok_resp(
                serde_json::json!({
                    "pairing_id": pairing_id.to_string(),
                    "secret": secret_hex,
                    "token": token_hex,
                })
                .to_string(),
                None,
            )
        }
        Err(msg) => err_response(msg.to_string()),
    }
}

/// bridge.match: URL -> matching CipherMeta (metadata only, no passwords).
///
/// never cross this boundary — the extension calls `vault.get` for the one
/// the user picks.
async fn handle_bridge_match(
    req: GatewayRequest,
    state: &SharedVaultState,
    vault_name: &str,
) -> GatewayResponse {
    let url: String = match serde_json::from_str::<serde_json::Value>(&req.payload) {
        Ok(v) => v["url"].as_str().unwrap_or("").to_string(),
        Err(_) => return err_response("Invalid JSON"),
    };
    let want = hostname_of(&url);
    if want.is_empty() {
        return ok_resp(
            serde_json::json!({ "matches": [], "active_vault": vault_name }).to_string(),
            None,
        );
    }
    match state.list_all().await {
        Ok(blob) => {
            let v: serde_json::Value = serde_json::from_str(&blob).unwrap_or_default();
            let ciphers = v["ciphers"].as_array().cloned().unwrap_or_default();
            let matched: Vec<serde_json::Value> = ciphers
                .into_iter()
                .filter(|c| {
                    // CipherKind serializes as {"type":"login","data":{...}}
                    // (#[serde(tag="type", content="data")]). URIs live at
                    // kind.data.uris for the Login variant.
                    let uris = c["kind"]["data"]["uris"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    uris.iter().any(|u| {
                        let stored = u["uri"]
                            .as_str()
                            .or_else(|| u.as_str())
                            .map(hostname_of)
                            .unwrap_or_default();
                        !stored.is_empty() && hostname_matches(&stored, &want)
                    })
                })
                .map(|c| {
                    serde_json::json!({
                        "id": c["id"],
                        "name": c["name"],
                        "username": c.get("username").cloned().unwrap_or(serde_json::Value::Null),
                        "cipher_type": c.get("cipher_type").cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect();
            ok_resp(
                serde_json::json!({ "matches": matched, "active_vault": vault_name }).to_string(),
                None,
            )
        }
        Err(e) => err_response(e),
    }
}

/// bridge.config: returns ONLY default_uri_match (Decision 7; NOT settings.get
/// which leaks slug/enrollment_policy/profile PII).
async fn handle_bridge_config(state: &SharedVaultState) -> GatewayResponse {
    match state.settings_get().await {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
            ok_resp(
                serde_json::json!({
                    "default_uri_match": v.get("default_uri_match").cloned().unwrap_or_default(),
                })
                .to_string(),
                None,
            )
        }
        Err(e) => err_response(e),
    }
}

/// Extract the hostname from a URL (loose parser; http/https assumed).
fn hostname_of(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    stripped
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Safe hostname match with dot-boundary enforcement.
/// Exact match, or one is a proper subdomain of the other (separated by a
/// literal dot). Rejects the `evilgithub.com` matches `github.com` phishing
/// hole that a naive `ends_with` would allow. Also rejects bare-suffix
/// matches like `com` matching `github.com` (a value with no dot is only
/// allowed to match exactly).
fn hostname_matches(stored: &str, want: &str) -> bool {
    if stored == want {
        return true;
    }
    // A candidate suffix must itself contain a dot, otherwise it's a bare
    // TLD-like fragment ("com", "co") that shouldn't match any domain.
    // want is a subdomain of stored: want = "api.github.com", stored = "github.com"
    if stored.contains('.') {
        if let Some(prefix) = want.strip_suffix(stored) {
            if prefix.ends_with('.') {
                return true;
            }
        }
    }
    // stored is a subdomain of want: stored = "api.github.com", want = "github.com"
    if want.contains('.') {
        if let Some(prefix) = stored.strip_suffix(want) {
            if prefix.ends_with('.') {
                return true;
            }
        }
    }
    false
}

/// `vault.unlock` (Phase 6): takes an explicit `slug` (or falls back to
/// active). If the slug is not yet in the host map, looks up its path in
/// the registry, builds a fresh `VaultState`, and inserts it. Then runs
/// KDF + unlock on that state. Returns `{ slug, token, info }`.
async fn handle_vault_unlock(mut req: GatewayRequest, host: &SharedVaultHost) -> GatewayResponse {
    // Payload is the master password (plaintext) OR JSON {"slug":"...", "password":"..."}.
    // Support both: try JSON first, fall back to plain-string for backward compat.
    let (slug, password) = match serde_json::from_str::<serde_json::Value>(&req.payload) {
        Ok(v) if v.get("password").is_some() || v.get("slug").is_some() => {
            let s = v.get("slug").and_then(|x| x.as_str()).map(String::from);
            let p = v
                .get("password")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (s, zeroize::Zeroizing::new(p))
        }
        _ => (None, zeroize::Zeroizing::new(req.payload.clone())),
    };

    // Resolve the slug: req.slug (proto field, M2) > payload `slug` > active.
    let slug = if !req.slug.is_empty() {
        Some(req.slug.clone())
    } else {
        slug
    };
    let slug = match slug {
        Some(s) if !s.is_empty() => Some(s),
        _ => host.active_slug().await,
    };

    // Look up or atomically create the VaultState for this slug (H1: the
    // get-or-insert runs under ONE write lock so two concurrent unlocks of
    // the same not-yet-mapped slug share a single VaultState + token).
    let (slug, state) = match slug {
        Some(s) => {
            // NEW-2: resolve the vault path from the registry UNCONDITIONALLY
            // (a cheap file read). Previously this was gated on
            // `host.get(&s).is_none()`, which left a race: if get() returned
            // Some but the vault was close()'d before get_or_insert_with, the
            // closure ran with reg_path=None and fabricated a bogus
            // /tmp/baluard-{slug} path — poisoning the map. Resolving
            // unconditionally closes that window; the /tmp fallback is gone.
            let path = match baluard_core::vault::registry::VaultRegistry::load_locked() {
                Ok(reg) => match reg.get(&s) {
                    Some(entry) => entry.path.clone(),
                    None => {
                        req.payload.zeroize();
                        return err_response(format!("Vault '{s}' not found in registry"));
                    }
                },
                Err(e) => {
                    req.payload.zeroize();
                    return err_response(format!("Registry error: {e}"));
                }
            };
            let state = host
                .get_or_insert_with(&s, move || {
                    // Runs at most once, under the host write lock. `path` is
                    // always the real registry path here (no bogus fallback).
                    Arc::new(VaultState::new(path))
                })
                .await;
            (s, state)
        }
        None => {
            req.payload.zeroize();
            return err_response(
                "No active vault and no 'slug' given. Run `baluard unlock --vault <slug>`."
                    .to_string(),
            );
        }
    };

    // Rate-limit (M4) before KDF.
    let vault_key = state.vault_path.to_string_lossy().into_owned();
    let permit = match state.rate_limiter.claim_attempt(&vault_key) {
        crate::rate_limit::ClaimResult::Allowed(p) => p,
        crate::rate_limit::ClaimResult::Backoff(d) => {
            req.payload.zeroize();
            return err_response(format!(
                "Too many failed attempts. Wait {}s before retrying.",
                d.as_secs()
            ));
        }
        crate::rate_limit::ClaimResult::LockedOut(d) => {
            req.payload.zeroize();
            return err_response(format!(
                "Vault locked due to too many failed attempts. Wait {}s.",
                d.as_secs()
            ));
        }
    };

    let result = state.unlock(&password).await;
    req.payload.zeroize();

    match result {
        Ok(()) => {
            permit.commit_success();
            let _ = state.purge_old_trash(30).await;
            state.start_cover_timer().await;

            // Phase 6 / T15: log the aggregate mlock footprint now that one
            // more vault is unlocked. Best-effort diagnostic; mlock failure
            // itself stays silent per T6.
            host.log_mlock_budget().await;

            // Make this vault the active focus if there is no active yet.
            // (Switching on every unlock would surprise users mid-flow.)
            if host.active_slug().await.is_none() {
                // Best-effort: ignore errors (slug may already be in map).
                let _ = host.switch(&slug).await;
            }

            let token = state.get_session_token().await;
            let info = match state.info().await {
                Ok(i) => i,
                Err(e) => return err_response(e),
            };
            // Embed slug + token so the caller can file the per-vault token.
            let mut info_val: serde_json::Value = serde_json::from_str(&info).unwrap_or_default();
            info_val["slug"] = serde_json::json!(slug);
            ok_resp(
                serde_json::to_string(&info_val).unwrap_or(info),
                token.as_deref(),
            )
        }
        Err(e) => {
            permit.commit_failure();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            err_response(e)
        }
    }
}

/// `vault.open` (Phase 6): ensures the vault is loaded in the host map
/// (locked). Idempotent — no-op if already present. Backward-compat shim
/// for clients that call `vault.open` before `vault.unlock`.
async fn handle_vault_open(req: GatewayRequest, host: &SharedVaultHost) -> GatewayResponse {
    // M2: prefer req.slug (proto field), then payload slug, then active.
    let slug = if !req.slug.is_empty() {
        req.slug.clone()
    } else {
        match extract_slug(&req.payload) {
            Some(s) => s,
            None => match host.active_slug().await {
                Some(s) => s,
                None => {
                    // Fall back to registry active or first alphabetical whose path exists
                    if let Ok(reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
                        let mut candidates = Vec::new();
                        if let Some(active) = reg.active() {
                            if std::path::Path::new(&active.path).exists() {
                                candidates.push(active.slug.clone());
                            }
                        }
                        let mut others = Vec::new();
                        for entry in reg.vaults.values() {
                            if Some(&entry.slug) != reg.active().map(|a| &a.slug)
                                && std::path::Path::new(&entry.path).exists()
                            {
                                others.push(entry.slug.clone());
                            }
                        }
                        others.sort();
                        candidates.extend(others);

                        if !candidates.is_empty() {
                            candidates[0].clone()
                        } else {
                            return err_response(
                                "vault.open needs a 'slug' or an active vault to open.".to_string(),
                            );
                        }
                    } else {
                        return err_response(
                            "vault.open needs a 'slug' or an active vault to open.".to_string(),
                        );
                    }
                }
            },
        }
    };

    // Already in map? Done (no registry read needed).
    if let Some(state) = host.get(&slug).await {
        // Make this vault the active focus in the host if there is no active slug set.
        if host.active_slug().await.is_none() {
            let _ = host.switch(&slug).await;
        }
        return match state.info().await {
            Ok(info) => ok_resp(inject_slug(info, &slug), None),
            Err(e) => err_response(e),
        };
    }

    // Not in map: resolve path from registry, then atomic get-or-insert (H1).
    let reg = match baluard_core::vault::registry::VaultRegistry::load_locked() {
        Ok(r) => r,
        Err(e) => return err_response(format!("Registry error: {e}")),
    };
    let Some(entry) = reg.get(&slug) else {
        return err_response(format!("Vault '{slug}' not found in registry"));
    };
    let path = entry.path.clone();
    let state = host
        .get_or_insert_with(&slug, move || {
            // Runs at most once, under the host write lock.
            Arc::new(VaultState::new(path.clone()))
        })
        .await;
    // Open runs outside the closure (it's async + we don't want to hold the
    // host write lock across disk I/O). If another caller already opened it,
    // open() is a redundant no-op (sets inner = Some(handle); harmless).
    if let Err(e) = state.open().await {
        return err_response(e);
    }

    // Make this vault the active focus in the host if there is no active slug set.
    if host.active_slug().await.is_none() {
        let _ = host.switch(&slug).await;
    }
    match state.info().await {
        Ok(info) => ok_resp(inject_slug(info, &slug), None),
        Err(e) => err_response(e),
    }
}

/// `vault.biometric_unlock` (host-level): resolves the slug from req.slug /
/// payload / active, looks up the already-open `VaultState` (the frontend
/// always calls `vault.open` first), then runs biometric unlock. Returns
/// `{slug, success}` plus the session token so the desktop can file the
/// token under the slug. Mirrors `vault.unlock`'s contract: callers rely
/// on `slug` in the payload to file the per-vault session token.
///
/// Uses `host.get` (NOT `get_or_insert_with`): by the time biometric
/// unlock runs, the vault MUST already be open. Silent fabrication would
/// mask a real bug (frontend skipping `vault.open`).
async fn handle_vault_biometric_unlock(
    req: GatewayRequest,
    host: &SharedVaultHost,
) -> GatewayResponse {
    // Resolve slug: req.slug (proto field, M2) > payload `slug` > active.
    let slug = if !req.slug.is_empty() {
        req.slug.clone()
    } else {
        match extract_slug(&req.payload) {
            Some(s) => s,
            None => match host.active_slug().await {
                Some(s) => s,
                None => {
                    return err_response(
                        "No active vault and no 'slug' given. Run `baluard unlock --vault <slug>`."
                            .to_string(),
                    );
                }
            },
        }
    };

    let Some(state) = host.get(&slug).await else {
        return err_response(format!(
            "Vault '{slug}' is not open in the daemon. Run `baluard unlock --vault {slug}` first."
        ));
    };

    // M4 fix: atomically claim a rate-limit slot before running unlock.
    let vault_key = state.vault_path.to_string_lossy().into_owned();
    let permit = match state.rate_limiter.claim_attempt(&vault_key) {
        crate::rate_limit::ClaimResult::Allowed(p) => p,
        crate::rate_limit::ClaimResult::Backoff(d) => {
            return err_response(format!(
                "Too many failed attempts. Wait {}s before retrying.",
                d.as_secs()
            ));
        }
        crate::rate_limit::ClaimResult::LockedOut(d) => {
            return err_response(format!(
                "Vault locked due to too many failed attempts. Wait {}s.",
                d.as_secs()
            ));
        }
    };

    match state.biometric_unlock().await {
        Ok(json) => {
            permit.commit_success();
            // biometric_unlock() calls self.unlock() internally, which
            // generates a new session token. Fetch it.
            state.start_cover_timer().await;
            let token = state.get_session_token().await;
            ok_resp(inject_slug(json, &slug), token.as_deref())
        }
        Err(e) => {
            permit.commit_failure();
            err_response(e)
        }
    }
}

/// `vault.pin_unlock` (host-level): mirrors `vault.biometric_unlock`. Resolves
/// the slug, snapshots the already-open `VaultState`, claims a rate-limit slot,
/// then runs session-PIN unlock. On a wrong PIN the daemon's per-vault PIN
/// counter advances and (at the cap) nukes the KEK escrow, forcing the master
/// password. Returns `{slug, success}` + the freshly-minted session token.
async fn handle_vault_pin_unlock(req: GatewayRequest, host: &SharedVaultHost) -> GatewayResponse {
    // Resolve slug: req.slug (proto field, M2) > payload `slug` > active.
    let slug = if !req.slug.is_empty() {
        req.slug.clone()
    } else {
        match extract_slug(&req.payload) {
            Some(s) => s,
            None => match host.active_slug().await {
                Some(s) => s,
                None => {
                    return err_response(
                        "No active vault and no 'slug' given. Run `baluard unlock --vault <slug>`."
                            .to_string(),
                    );
                }
            },
        }
    };

    let Some(state) = host.get(&slug).await else {
        return err_response(format!(
            "Vault '{slug}' is not open in the daemon. Run `baluard unlock --vault {slug}` first."
        ));
    };

    // Rate-limit slot: a burst of wrong PINs is throttled by the same
    // per-vault limiter as password attempts. The PIN escrow's own counter
    // provides the terminal nuke-at-5 policy on top.
    let vault_key = state.vault_path.to_string_lossy().into_owned();
    let permit = match state.rate_limiter.claim_attempt(&vault_key) {
        crate::rate_limit::ClaimResult::Allowed(p) => p,
        crate::rate_limit::ClaimResult::Backoff(d) => {
            return err_response(format!(
                "Too many failed attempts. Wait {}s before retrying.",
                d.as_secs()
            ));
        }
        crate::rate_limit::ClaimResult::LockedOut(d) => {
            return err_response(format!(
                "Vault locked due to too many failed attempts. Wait {}s.",
                d.as_secs()
            ));
        }
    };

    match state.pin_unlock(&req.payload).await {
        Ok(json) => {
            permit.commit_success();
            // pin_unlock() mints a session token internally. Fetch it.
            state.start_cover_timer().await;
            let token = state.get_session_token().await;
            ok_resp(inject_slug(json, &slug), token.as_deref())
        }
        Err(e) => {
            permit.commit_failure();
            err_response(e)
        }
    }
}

/// Inject the resolved slug into a JSON response payload. The desktop's
/// `SessionStore` files a returned session token under the slug parsed
/// from the payload (`payload["slug"]`); without it the token is dropped.
/// Used by `vault.open` and `vault.biometric_unlock` to match the
/// `vault.unlock` / `vault.create` contract. Falls back to the original
/// body if it isn't valid JSON.
fn inject_slug(body: String, slug: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(mut v) => {
            v["slug"] = serde_json::json!(slug);
            serde_json::to_string(&v).unwrap_or(body)
        }
        Err(_) => body,
    }
}

/// `vault.create` (Phase 6): creates a new vault, inserts it into the map,
/// sets it active, and registers it in the registry.
async fn handle_vault_create(mut req: GatewayRequest, host: &SharedVaultHost) -> GatewayResponse {
    if req.payload.is_empty() {
        return err_response("Missing vault creation JSON in payload");
    }
    // Determine slug from payload (preferred) or marker after creation.
    let slug_hint = extract_slug(&req.payload);
    // The VaultState::create_vault() expects a vault_path to already be set
    // on the state. We need a path. Resolve from slug (registry will create
    // the entry later) or fall back to the data_dir vaults/<slug> layout.
    let slug = slug_hint.unwrap_or_else(|| {
        // Synthesize a slug from a UUID if none was provided. Caller can
        // rename later via the registry.
        format!("vault-{}", &uuid::Uuid::new_v4().to_string()[..8])
    });
    let vault_path = baluard_core::paths::vaults_dir().join(&slug);

    let state = Arc::new(VaultState::new(vault_path.clone()));
    let result = state.create_vault(&req.payload).await;
    req.payload.zeroize();
    match result {
        Ok(json) => {
            // M3: atomic try-insert — reject a slug already present in the
            // map instead of silently replacing (which would orphan the
            // existing VaultState + its token). Combined with the disk guard
            // inside create_vault (kdf-params.json exists) and the registry
            // add() below, this closes the "on disk + in map + active but
            // absent from registry" hole.
            if let Err(_existing) = host.try_insert(slug.clone(), state.clone()).await {
                // Clean up the vault we just created on disk so we don't
                // leave a stray directory. Best-effort.
                let _ = std::fs::remove_dir_all(&vault_path);
                return err_response(format!(
                    "A vault '{slug}' is already open in the daemon. \
                     Close it first or pick a different slug."
                ));
            }
            let _ = host.switch(&slug).await;

            // Register in the registry so vaults.list sees it. The marker
            // is written by create_vault; read it back for the vault_id.
            let vault_id =
                match baluard_core::vault::registry::BaluardMarker::read_from_vault(&vault_path) {
                    Ok(Some(m)) => m.vault_id,
                    _ => uuid::Uuid::new_v4(),
                };
            let display_name = serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|v| v["vault_name"].as_str().map(String::from))
                .unwrap_or_else(|| slug.clone());
            let entry = baluard_core::vault::registry::VaultEntry {
                slug: slug.clone(),
                display_name,
                path: vault_path.clone(),
                provider: None,
                remote_url: None,
                last_synced: None,
                last_opened: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                vault_id,
            };
            // M3: surface registry errors instead of swallowing them. A
            // collision here (slug already registered) means the vault was
            // created + inserted + made active, but the registry refused —
            // warn loudly so the user can reconcile.
            match baluard_core::vault::registry::VaultRegistry::load_locked() {
                Ok(mut reg) => {
                    if let Err(e) = reg.add(entry) {
                        log::warn!(
                            "[daemon] vault.create: registry add failed for '{slug}': {e}. \
                             Vault is open in the daemon but not registered."
                        );
                    }
                    let _ = reg.set_active(&slug);
                    if let Err(e) = reg.save_locked() {
                        log::warn!("[daemon] vault.create: registry save failed: {e}");
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[daemon] vault.create: registry load failed: {e}. \
                         Vault is open in the daemon but not registered."
                    );
                }
            }

            // Embed slug + token for the caller.
            let mut val: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            val["slug"] = serde_json::json!(slug);
            let body = serde_json::to_string(&val).unwrap_or_else(|_| json.clone());
            ok_resp(body, state.get_session_token().await.as_deref())
        }
        Err(e) => err_response(e),
    }
}

/// Mutable per-job state for a remote vault clone. The clone thread updates
/// `phase`/`error`/`result_*`; `progress` (a separate Arc) is updated by git2's
/// `transfer_progress` callback. Polled by `vault.clone_progress`.
#[cfg(feature = "git-sync")]
#[derive(Clone)]
struct CloneJobState {
    phase: String,
    error: Option<String>,
    result_slug: Option<String>,
    result_path: Option<String>,
}

#[cfg(feature = "git-sync")]
#[derive(Clone)]
struct CloneJob {
    state: Arc<std::sync::Mutex<CloneJobState>>,
    progress: Arc<std::sync::Mutex<baluard_core::sync::engine::CloneProgress>>,
}

/// Bundled parameters for a background clone (avoids the clippy
/// `too_many_arguments` lint and keeps the `spawn_blocking` closure tidy).
#[cfg(feature = "git-sync")]
struct CloneParams {
    state: Arc<std::sync::Mutex<CloneJobState>>,
    progress: Arc<std::sync::Mutex<baluard_core::sync::engine::CloneProgress>>,
    clone_url: String,
    target: std::path::PathBuf,
    slug: String,
    display_name: String,
    provider: baluard_core::providers::types::Provider,
    provider_str: String,
}

#[cfg(feature = "git-sync")]
static CLONE_JOBS: std::sync::LazyLock<
    tokio::sync::Mutex<std::collections::HashMap<uuid::Uuid, CloneJob>>,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

/// `vault.clone_start` (Phase 4): kick off a background clone of a remote
/// vault repo. Payload JSON: `{ clone_url, provider, slug, display_name }`.
/// Returns `{ job_id }` immediately; poll with `vault.clone_progress`.
///
/// Pre-unlock route (no vault open), so it lives at host level and is NOT in
/// `TOKEN_REQUIRED_ACTIONS`. The slug comes from `provider.vault_repos`
/// (the `.baluard` marker carries it), avoiding a temp-dir dance.
#[cfg(feature = "git-sync")]
async fn handle_vault_clone_start(req: GatewayRequest, _host: &SharedVaultHost) -> GatewayResponse {
    if req.payload.is_empty() {
        return err_response("Missing clone JSON in payload".to_string());
    }
    let v: serde_json::Value = match serde_json::from_str(&req.payload) {
        Ok(v) => v,
        Err(e) => return err_response(format!("Invalid clone JSON: {e}")),
    };
    let Some(clone_url) = v["clone_url"].as_str().map(str::to_string) else {
        return err_response("Missing 'clone_url' in clone payload".to_string());
    };
    let Some(slug) = v["slug"].as_str().map(str::to_string) else {
        return err_response("Missing 'slug' in clone payload".to_string());
    };
    let display_name = v["display_name"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| slug.clone());
    let provider_str = v["provider"].as_str().unwrap_or("");
    let provider: baluard_core::providers::types::Provider = match provider_str {
        "github" => baluard_core::providers::types::Provider::GitHub,
        "gitlab" => baluard_core::providers::types::Provider::GitLab,
        "codeberg" => baluard_core::providers::types::Provider::Codeberg,
        other => return err_response(format!("Unknown provider: {other}")),
    };

    let target = baluard_core::paths::vaults_dir().join(&slug);
    if target.exists() {
        return err_response(format!(
            "Target directory already exists: {}. Pick a different slug or remove it.",
            target.display()
        ));
    }
    if let Ok(reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
        if reg.exists(&slug) {
            return err_response(format!(
                "A vault '{slug}' is already registered. Remove it first."
            ));
        }
    }

    // Ensure the provider token is fresh before the clone thread reads it
    // from the keyring (mirrors sync.push's refresh-before-op).
    refresh_connected_tokens_if_needed().await;

    let job_id = uuid::Uuid::new_v4();
    let state = Arc::new(std::sync::Mutex::new(CloneJobState {
        phase: "cloning".to_string(),
        error: None,
        result_slug: None,
        result_path: None,
    }));
    let progress = Arc::new(std::sync::Mutex::new(
        baluard_core::sync::engine::CloneProgress::default(),
    ));
    {
        let mut jobs = CLONE_JOBS.lock().await;
        jobs.insert(
            job_id,
            CloneJob {
                state: state.clone(),
                progress: progress.clone(),
            },
        );
    }

    let state_arc = state.clone();
    let provider_str_owned = provider_str.to_string();
    tokio::task::spawn_blocking(move || {
        run_clone_to_completion(CloneParams {
            state: state_arc,
            progress,
            clone_url,
            target,
            slug,
            display_name,
            provider,
            provider_str: provider_str_owned,
        })
    });

    ok_resp(
        serde_json::json!({ "job_id": job_id.to_string() }).to_string(),
        None,
    )
}

/// Blocking worker: clone -> verify `.baluard` marker -> register in the
/// registry -> mark the job done. On any failure, cleans up the partial
/// clone directory (orphan prevention) and records the error.
#[cfg(feature = "git-sync")]
fn run_clone_to_completion(params: CloneParams) {
    let CloneParams {
        state,
        progress,
        clone_url,
        target,
        slug,
        display_name,
        provider,
        provider_str,
    } = params;
    let result = baluard_core::sync::engine::SyncEngine::clone_remote(
        &clone_url,
        &target,
        provider,
        progress.clone(),
    );
    match result {
        Ok(_repo) => {
            {
                let mut s = state.lock().unwrap();
                s.phase = "registering".to_string();
            }
            // Verify this is actually a Baluard vault (has the marker).
            let vault_id =
                match baluard_core::vault::registry::BaluardMarker::read_from_vault(&target) {
                    Ok(Some(m)) => m.vault_id,
                    _ => {
                        let _ = std::fs::remove_dir_all(&target);
                        let mut s = state.lock().unwrap();
                        s.phase = "failed".to_string();
                        s.error = Some(
                            "Cloned repository has no .baluard marker (not a Baluard vault)"
                                .to_string(),
                        );
                        return;
                    }
                };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let entry = baluard_core::vault::registry::VaultEntry {
                slug: slug.clone(),
                display_name: display_name.clone(),
                path: target.clone(),
                provider: Some(provider_str.clone()),
                remote_url: Some(clone_url.clone()),
                last_synced: Some(now),
                last_opened: Some(now),
                vault_id,
            };
            let reg_err: Option<String> =
                match baluard_core::vault::registry::VaultRegistry::load_locked() {
                    Ok(mut reg) => match reg.add(entry) {
                        Ok(()) => match reg.set_active(&slug) {
                            Ok(()) => reg
                                .save_locked()
                                .err()
                                .map(|e| format!("registry save: {e}")),
                            Err(e) => Some(format!("registry set_active: {e}")),
                        },
                        Err(e) => Some(format!("registry add: {e}")),
                    },
                    Err(e) => Some(format!("registry load: {e}")),
                };
            if let Some(msg) = reg_err {
                let _ = std::fs::remove_dir_all(&target);
                let mut s = state.lock().unwrap();
                s.phase = "failed".to_string();
                s.error = Some(format!("Registration failed: {msg}"));
                return;
            }
            let mut s = state.lock().unwrap();
            s.phase = "done".to_string();
            s.result_slug = Some(slug.clone());
            s.result_path = Some(target.to_string_lossy().to_string());
        }
        Err(e) => {
            // Orphan prevention: remove any partial clone left on disk.
            let _ = std::fs::remove_dir_all(&target);
            let mut s = state.lock().unwrap();
            s.phase = "failed".to_string();
            s.error = Some(format!("{e}"));
        }
    }
}

#[cfg(feature = "git-sync")]
fn parse_job_id(payload: &str) -> Result<uuid::Uuid, GatewayResponse> {
    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| err_response(format!("Invalid payload: {e}")))?;
    let id_str = v["job_id"]
        .as_str()
        .ok_or_else(|| err_response("Missing 'job_id' in payload".to_string()))?;
    uuid::Uuid::parse_str(id_str).map_err(|e| err_response(format!("Invalid job_id: {e}")))
}

/// `vault.clone_progress`: poll a clone job. Returns phase/objects/bytes/pct.
#[cfg(feature = "git-sync")]
async fn handle_vault_clone_progress(
    req: GatewayRequest,
    _host: &SharedVaultHost,
) -> GatewayResponse {
    let job_id = match parse_job_id(&req.payload) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let job_arc = {
        let jobs = CLONE_JOBS.lock().await;
        match jobs.get(&job_id).cloned() {
            Some(j) => j,
            None => return err_response(format!("Unknown clone job: {job_id}")),
        }
    };
    let s = job_arc
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let p = job_arc.progress.lock().unwrap_or_else(|e| e.into_inner());
    let pct = if p.total_objects > 0 {
        (p.objects_received as u64 * 100 / p.total_objects as u64) as u32
    } else {
        0
    };
    ok_resp(
        serde_json::json!({
            "phase": s.phase,
            "objects_received": p.objects_received,
            "total_objects": p.total_objects,
            "bytes_received": p.bytes_received,
            "pct": pct,
            "error": s.error,
            "done": s.phase == "done",
        })
        .to_string(),
        None,
    )
}

/// `vault.clone_finalize`: consume a finished job, return `{ slug, path }`,
/// remove it from the job map. The caller then runs `vault.unlock <slug>`
/// (which resolves the path from the registry and inserts into the host map).
#[cfg(feature = "git-sync")]
async fn handle_vault_clone_finalize(
    req: GatewayRequest,
    _host: &SharedVaultHost,
) -> GatewayResponse {
    let job_id = match parse_job_id(&req.payload) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let job_arc = {
        let mut jobs = CLONE_JOBS.lock().await;
        match jobs.remove(&job_id) {
            Some(j) => j,
            None => return err_response(format!("Unknown clone job: {job_id}")),
        }
    };
    let s = job_arc
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match s.phase.as_str() {
        "done" => {
            let p = job_arc.progress.lock().unwrap_or_else(|e| e.into_inner());
            ok_resp(
                serde_json::json!({
                    "slug": s.result_slug,
                    "path": s.result_path,
                    "objects": p.objects_received,
                    "bytes": p.bytes_received,
                })
                .to_string(),
                None,
            )
        }
        "failed" => err_response(s.error.unwrap_or_else(|| "clone failed".to_string())),
        phase => err_response(format!(
            "Clone not finished (phase: {phase}). Poll progress first."
        )),
    }
}

#[cfg(not(feature = "git-sync"))]
async fn handle_vault_clone_start(
    _req: GatewayRequest,
    _host: &SharedVaultHost,
) -> GatewayResponse {
    err_response("git-sync feature not enabled".to_string())
}
#[cfg(not(feature = "git-sync"))]
async fn handle_vault_clone_progress(
    _req: GatewayRequest,
    _host: &SharedVaultHost,
) -> GatewayResponse {
    err_response("git-sync feature not enabled".to_string())
}
#[cfg(not(feature = "git-sync"))]
async fn handle_vault_clone_finalize(
    _req: GatewayRequest,
    _host: &SharedVaultHost,
) -> GatewayResponse {
    err_response("git-sync feature not enabled".to_string())
}

/// Route a GatewayRequest to the appropriate baluard-core function.
///
/// R7-2: Protected actions require a valid session token obtained at unlock.
/// Phase 6: the caller already resolved the target `Arc<VaultState>`; the
/// token check here is per-vault (constant-time compare against THIS vault's
/// token only). A vault-A token is rejected for a vault-B operation.
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
        // L1: ping / vault.open / vault.unlock / vault.create / vault.active
        // are intercepted by route_host_request before reaching here; their
        // arms were removed to avoid confusion + a refactor hazard. Any of
        // those actions arriving here means routing is broken — fail loudly.
        "ping" | "vault.open" | "vault.unlock" | "vault.create" | "vault.active" => {
            return err_response(format!(
                "INTERNAL: action '{}' reached route_request (should be handled at host level)",
                req.action
            ));
        }

        "vault.lock" => match state.lock().await {
            Ok(()) => ok_resp("locked", None),
            Err(e) => err_response(e),
        },

        // H1 fix: master password change (token required)
        "vault.change_password" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
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

        // ── Sync (token required, enforced above) ──
        "sync.init" => match sync_init(&state.vault_path) {
            Ok(msg) => ok_resp(msg, token_str),
            Err(e) => err_response(e),
        },
        "sync.remote" => {
            if req.payload.is_empty() {
                return err_response("Missing remote URL in payload");
            }
            // git2 FFI (add_remote + network) — must not block the async
            // runtime. Without spawn_blocking a hung git2 network call
            // permanently consumes a tokio worker thread, starving every
            // other connection (root cause of the EAGAIN storm).
            let vault_path = state.vault_path.clone();
            let payload = req.payload.clone();
            let joined = tokio::time::timeout(
                SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || sync_remote(&vault_path, &payload)),
            )
            .await;
            match joined {
                Ok(Ok(Ok(msg))) => ok_resp(msg, token_str),
                Ok(Ok(Err(e))) => err_response(e),
                Ok(Err(e)) => err_response(format!("Task join: {e}")),
                Err(_) => err_response("sync.remote timed out".to_string()),
            }
        }
        "sync.push" => {
            refresh_connected_tokens_if_needed().await;
            // git2 push does real network I/O (SSH/HTTPS) with no transport
            // timeout — must run off the async worker pool, bounded by
            // SYNC_OP_TIMEOUT so a hung push can't leak the thread (see sync.remote).
            let vault_path = state.vault_path.clone();
            let joined = tokio::time::timeout(
                SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || sync_push(&vault_path)),
            )
            .await;
            match joined {
                Ok(Ok(Ok(msg))) => ok_resp(msg, token_str),
                Ok(Ok(Err(e))) => err_response(e),
                Ok(Err(e)) => err_response(format!("Task join: {e}")),
                Err(_) => err_response("sync.push timed out".to_string()),
            }
        }
        "sync.pull" => {
            refresh_connected_tokens_if_needed().await;
            // git2 pull does real network I/O — must run off the async worker
            // pool, bounded by SYNC_OP_TIMEOUT (see sync.remote).
            let vault_path = state.vault_path.clone();
            let joined = tokio::time::timeout(
                SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || sync_pull(&vault_path)),
            )
            .await;
            match joined {
                Ok(Ok(Ok(msg))) => ok_resp(msg, token_str),
                Ok(Ok(Err(e))) => err_response(e),
                Ok(Err(e)) => err_response(format!("Task join: {e}")),
                Err(_) => err_response("sync.pull timed out".to_string()),
            }
        }
        "sync.status" => {
            let vault_path = state.vault_path.clone();
            let joined = tokio::time::timeout(
                SYNC_OP_TIMEOUT,
                tokio::task::spawn_blocking(move || sync_status(&vault_path)),
            )
            .await;
            match joined {
                Ok(Ok(Ok(msg))) => ok_resp(msg, token_str),
                Ok(Ok(Err(e))) => err_response(e),
                Ok(Err(e)) => err_response(format!("Task join: {e}")),
                Err(_) => err_response("sync.status timed out".to_string()),
            }
        }
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
        "sync.status_json" => match sync_status_json(&state.vault_path) {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "sync.autosync_status" => {
            // M2 handles activation in VaultState::unlock; this route is just a
            // status reader. But as a backstop (e.g. provider connected AFTER
            // unlock via sync.setup_sync), lazily activate here too if a remote
            // is present and the coordinator is still inactive. The has_remote
            // check is blocking git I/O, so run it on the blocking pool (M1):
            // this route is polled every ~10s by every desktop client.
            #[cfg(feature = "git-sync")]
            if !state.autosync.is_active().await {
                let vault_path = state.vault_path.clone();
                let has_remote = tokio::task::spawn_blocking(move || {
                    baluard_core::sync::engine::SyncEngine::new(&vault_path, "probe")
                        .open_repo()
                        .and_then(|repo| baluard_core::sync::engine::SyncEngine::has_remote(&repo))
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                if has_remote {
                    let dn = device_name(&state.vault_path);
                    state.autosync.activate(dn).await;
                }
            }
            let status = state.autosync.status().await;
            match serde_json::to_string(&status) {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(format!("JSON error: {e}")),
            }
        }
        "sync.disconnect" => match sync_disconnect(&state.vault_path, &req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        // Focus-triggered pull. The desktop fires this on window focus /
        // visibilitychange. Server-side 10-min guard (FOCUS_PULL_MIN_GAP_SECS)
        // collapses rapid focus flicker into at most one pull per 10 min.
        "sync.autosync_nudge_pull" => {
            let dn = device_name(&state.vault_path);
            state.autosync.nudge_focus_pull(dn).await;
            ok_resp("ok".to_string(), token_str)
        }
        // Phase 2b: read the head conflict paused for user decision. Returns
        // masked details (no secret values). The frontend ConflictResolution
        // panel consumes this. 2b-2: decrypt base/local/remote, run
        // merge_ciphers. Auto-merges (Merged) with no UI prompt; surfaces
        // masked details (Conflict) or a cross_epoch flag (decrypt failure)
        // for a user verdict via sync.conflict.resolve.
        "sync.conflict" => {
            // Fast path: nothing pending → skip the decrypt entirely.
            if state.autosync.pending_conflict_count().await == 0 {
                let body = serde_json::json!({ "pending": false, "count": 0 });
                ok_resp(body.to_string(), token_str)
            } else {
                match state.conflict_decrypt_and_merge().await {
                    Ok(json) => ok_resp(json, token_str),
                    Err(e) => err_response(e),
                }
            }
        }
        // Phase 2b: apply the user's verdict to the head conflict + finalize
        // (write the 2-parent merge commit + push). Payload: {"verdict":
        // "keep_local"|"keep_remote"|"keep_both"}. 2b-1 implements
        // keep_local/keep_remote via raw blob selection (no decrypt).
        // keep_both is 2b-3 (new UUID + second entry) and errors here.
        "sync.conflict.resolve" => {
            if req.payload.is_empty() {
                return err_response("Missing verdict JSON in payload");
            }
            match handle_sync_conflict_resolve(state, &req.payload).await {
                Ok(json) => ok_resp(json, token_str),
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

        // ── Enroll this device into an existing vault via recovery phrase ──
        // Non-destructive: existing devices remain in the registry.
        // Requires the vault's `enrollment_policy` to be `Personal`.
        "vault.enroll_with_phrase" => {
            let v: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(v) => v,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            // PR-5: take ownership of the phrase so we can zeroize it
            // after use. Other sensitive routes (vault.unlock, etc.)
            // zeroize req.payload; this one handles the phrase specifically.
            let mut phrase = match v["phrase"].as_str() {
                Some(p) => p.to_string(),
                None => return err_response("missing phrase".to_string()),
            };
            let result = state.enroll_with_recovery_phrase(&phrase).await;
            // Zeroize phrase bytes before any return path.
            use zeroize::Zeroize;
            phrase.zeroize();
            match result {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }

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

        // ── Session PIN Quick Unlock ──
        // pin_status: pre-unlock-safe (in-memory escrow check), NOT token-gated.
        // pin_enable / pin_disable: token-gated (require an unlocked session).
        // pin_unlock: host-level (intercepted above), NOT token-gated.
        "vault.pin_status" => match state.pin_status().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.pin_enable" => match state.pin_enable(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },

        "vault.pin_disable" => match state.pin_disable().await {
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

        // ── Generator history ──
        "generator.history_add" => match state.generator_history_add(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "generator.history_list" => match state.generator_history_list().await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "generator.history_clear" => match state.generator_history_clear().await {
            Ok(()) => ok_resp("{}", token_str),
            Err(e) => err_response(e),
        },

        // ── Passkey ceremony (Phase 1) ──
        "passkey.list" => match state.passkey_list(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "passkey.challenge_register" => {
            match state.passkey_challenge_register(&req.payload).await {
                Ok(json) => ok_resp(json, token_str),
                Err(e) => err_response(e),
            }
        }
        "passkey.finish_register" => match state.passkey_finish_register(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "passkey.challenge_assert" => match state.passkey_challenge_assert(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "passkey.finish_assert" => match state.passkey_finish_assert(&req.payload).await {
            Ok(json) => ok_resp(json, token_str),
            Err(e) => err_response(e),
        },
        "passkey.delete" => match state.passkey_delete(&req.payload).await {
            Ok(()) => ok_resp("{}", token_str),
            Err(e) => err_response(e),
        },
        "passkey.rename" => match state.passkey_rename(&req.payload).await {
            Ok(()) => ok_resp("{}", token_str),
            Err(e) => err_response(e),
        },

        // vault.biometric_unlock is intercepted at host level
        // (handle_vault_biometric_unlock) because it needs the resolved
        // slug to satisfy the desktop's {slug} token-filing contract.

        // Validate master password without storing to keychain.
        // Used by the Tauri biometry plugin flow: validate here, store there.

        // ── Provider auth (no token required, auth happens before vault unlock) ──
        "provider.list" => {
            use baluard_core::providers::token::ProvidersState;
            use baluard_core::providers::types::Provider;
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
                    providers.insert(
                        key.clone(),
                        serde_json::json!({
                            "provider": key,
                            "connected": false,
                            "auth_method": p.auth_method()
                        }),
                    );
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
                    let config = parse_provider_config(&req.payload);
                    let prov = match baluard_core::providers::provider_for(provider, config) {
                        Ok(p) => p,
                        Err(e) => return err_response(e.to_string()),
                    };
                    match prov.device_flow_start().await {
                        Ok(session) => ok_resp(
                            serde_json::to_string(&session).unwrap_or_default(),
                            token_str,
                        ),
                        Err(e) => err_response(format!("Device flow start failed: {e}")),
                    }
                }
                _ => {
                    // H4/M6: point the caller at the right flow for the auth method.
                    let hint = match provider.auth_method() {
                        "web-oauth" => "provider.oauth_start_web",
                        _ => "provider.connect_pat",
                    };
                    err_response(format!(
                        "Device flow not supported for {}. Use {}.",
                        provider, hint
                    ))
                }
            }
        }

        "provider.connect_poll" => {
            let config = parse_provider_config(&req.payload);
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid payload: {e}")),
            };
            let session: baluard_core::providers::types::DeviceFlowSession =
                match serde_json::from_value(payload) {
                    Ok(s) => s,
                    Err(e) => return err_response(format!("Invalid session: {e}")),
                };
            let prov = match baluard_core::providers::provider_for(session.provider, config) {
                Ok(p) => p,
                Err(e) => return err_response(e.to_string()),
            };
            match prov.device_flow_poll(&session).await {
                Ok(status) => match status {
                    baluard_core::providers::types::DeviceFlowStatus::Pending => ok_resp(
                        serde_json::json!({"status": "pending"}).to_string(),
                        token_str,
                    ),
                    baluard_core::providers::types::DeviceFlowStatus::SlowDown {
                        interval_secs,
                    } => {
                        // M11 fix: caller persists this back into the session
                        // and re-polls at the new (longer) interval.
                        ok_resp(serde_json::json!({"status": "slow_down", "interval_secs": interval_secs}).to_string(), token_str)
                    }
                    baluard_core::providers::types::DeviceFlowStatus::Expired => ok_resp(
                        serde_json::json!({"status": "expired"}).to_string(),
                        token_str,
                    ),
                    baluard_core::providers::types::DeviceFlowStatus::Success(token) => {
                        // Validate token and get user info
                        match prov.validate_token(&token).await {
                            Ok(info) => {
                                // Store token in keyring
                                if let Err(e) = baluard_core::providers::token::store_token(
                                    info.provider,
                                    &info.username,
                                    &token,
                                ) {
                                    return err_response(format!("Keyring error: {e}"));
                                }
                                // Store non-sensitive state
                                let mut state_file =
                                    baluard_core::providers::token::ProvidersState::load()
                                        .unwrap_or_default();
                                state_file.set(info.clone());
                                if let Err(e) = state_file.save() {
                                    // Rollback: remove orphaned keyring entry
                                    let _ = baluard_core::providers::token::delete_token(
                                        info.provider,
                                        &info.username,
                                    );
                                    return err_response(format!(
                                        "Failed to save provider state: {e}"
                                    ));
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
            // B2: parse config BEFORE zeroizing req.payload, else Advanced
            // Options overrides (client_id, instance_url) are silently lost.
            let config = parse_provider_config(&req.payload);
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

            let prov = match baluard_core::providers::provider_for(provider, config) {
                Ok(p) => p,
                Err(e) => return err_response(e.to_string()),
            };
            match prov.authenticate_pat(&pat).await {
                Ok((token, info)) => {
                    if let Err(e) = baluard_core::providers::token::store_token(
                        info.provider,
                        &info.username,
                        &token,
                    ) {
                        return err_response(format!("Keyring error: {e}"));
                    }
                    let mut state_file =
                        baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
                    state_file.set(info.clone());
                    if let Err(e) = state_file.save() {
                        let _ = baluard_core::providers::token::delete_token(
                            info.provider,
                            &info.username,
                        );
                        return err_response(format!("Failed to save provider state: {e}"));
                    }
                    ok_resp(
                        serde_json::json!({"status": "success", "username": info.username})
                            .to_string(),
                        token_str,
                    )
                }
                Err(e) => err_response(format!("PAT auth failed: {e}")),
            }
        }

        "provider.status" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            match state_file.get(provider) {
                Some(info) => {
                    match ensure_valid_token(provider, info).await {
                        Ok(token) => {
                            let prov = match baluard_core::providers::provider_for(
                                provider,
                                info.config(),
                            ) {
                                Ok(p) => p,
                                Err(e) => return err_response(e.to_string()),
                            };
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
                        Err(_) => ok_resp(
                            serde_json::json!({"valid": false, "error": "token expired or unavailable"}).to_string(),
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
            // Best-effort server-side token revocation (Phase 4 wiring) then
            // local keyring + providers.json cleanup. Local cleanup always
            // runs even if the revoke call fails (network, PAT, no API).
            match baluard_core::providers::revoke_and_disconnect(provider).await {
                Ok(()) => ok_resp("disconnected", token_str),
                Err(e) => err_response(format!("Disconnect failed: {e}")),
            }
        }

        "provider.oauth_start_web" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            if provider.auth_method() != "web-oauth" {
                return err_response(format!(
                    "Web-OAuth not supported for {}. Use {}.",
                    provider,
                    if provider.auth_method() == "device-flow" {
                        "device flow"
                    } else {
                        "PAT"
                    }
                ));
            }
            let config = parse_provider_config(&req.payload);
            match start_web_oauth(provider, config).await {
                Ok(auth_url) => ok_resp(
                    serde_json::json!({"auth_url": auth_url}).to_string(),
                    token_str,
                ),
                Err(e) => err_response(e),
            }
        }

        "provider.oauth_status_web" => {
            let provider = match parse_provider_name(&req.payload) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let sessions = OAUTH_SESSIONS.lock().await;
            match sessions.get(&provider) {
                Some(s) => match &s.result {
                    Some(Ok(username)) => ok_resp(
                        serde_json::json!({"status": "success", "username": username}).to_string(),
                        token_str,
                    ),
                    Some(Err(msg)) => ok_resp(
                        serde_json::json!({"status": "error", "error": msg}).to_string(),
                        token_str,
                    ),
                    None => ok_resp(
                        serde_json::json!({"status": "pending"}).to_string(),
                        token_str,
                    ),
                },
                None => err_response("No web-OAuth session in progress for this provider"),
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
            let state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match ensure_valid_token(provider, info).await {
                Ok(t) => t,
                Err(e) => return e,
            };
            let prov = match baluard_core::providers::provider_for(provider, info.config()) {
                Ok(p) => p,
                Err(e) => return err_response(e.to_string()),
            };
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
            let state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match ensure_valid_token(provider, info).await {
                Ok(t) => t,
                Err(e) => return e,
            };
            let prov = match baluard_core::providers::provider_for(provider, info.config()) {
                Ok(p) => p,
                Err(e) => return err_response(e.to_string()),
            };
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
            let state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(provider) {
                Some(i) => i,
                None => return err_response(format!("{} not connected", provider)),
            };
            let token = match ensure_valid_token(provider, info).await {
                Ok(t) => t,
                Err(e) => return e,
            };
            let prov = match baluard_core::providers::provider_for(provider, info.config()) {
                Ok(p) => p,
                Err(e) => return err_response(e.to_string()),
            };
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
            // Optional: clone_url passed when the repo was already created via
            // `provider.create_repo`. If present, skip redundant creation (which
            // would 422 on the already-existing name) and use this URL directly.
            let existing_clone_url = payload["clone_url"].as_str().map(|s| s.to_string());

            // Resolve provider
            let prov_type = match baluard_core::providers::types::Provider::all()
                .iter()
                .find(|p| p.to_string() == provider)
            {
                Some(p) => *p,
                None => return err_response(format!("Unknown provider: {provider}")),
            };

            // Load token from keyring
            let state_file =
                baluard_core::providers::token::ProvidersState::load().unwrap_or_default();
            let info = match state_file.get(prov_type) {
                Some(i) => i,
                None => return err_response(format!("{provider} not connected")),
            };
            let token = match ensure_valid_token(prov_type, info).await {
                Ok(t) => t,
                Err(e) => return e,
            };

            // Default repo name to vault slug if not provided
            let vault_path = state.vault_path.clone();
            let effective_name = if repo_name.is_empty() {
                // Try reading slug from .baluard marker
                match baluard_core::vault::registry::BaluardMarker::read_from_vault(&vault_path) {
                    Ok(Some(m)) => m.slug.clone(),
                    _ => {
                        // Fallback to directory name
                        vault_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("vault")
                            .to_string()
                    }
                }
            } else {
                repo_name
            };

            // Resolve the remote URL: either reuse an already-created repo
            // (passed in the payload) or create a new private repo now.
            #[cfg(feature = "git-sync")]
            let remote_url: String = if let Some(url) = existing_clone_url {
                url
            } else {
                let prov = match baluard_core::providers::provider_for(prov_type, info.config()) {
                    Ok(p) => p,
                    Err(e) => return err_response(e.to_string()),
                };
                match prov.create_private_repo(&token, &effective_name).await {
                    Ok(r) => r.clone_url,
                    Err(e) => return err_response(format!("Failed to create repo: {e}")),
                }
            };
            #[cfg(not(feature = "git-sync"))]
            let _ = (existing_clone_url, effective_name.as_str(), info, token);

            // Init git repo + add remote + push (blocking git ops)
            #[cfg(feature = "git-sync")]
            {
                let slug_for_reg =
                    match baluard_core::vault::registry::BaluardMarker::read_from_vault(&vault_path)
                    {
                        Ok(Some(m)) => m.slug.clone(),
                        _ => vault_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_string(),
                    };
                let provider_for_reg = provider.clone();
                let provider_clone = provider.clone();
                let handle = tokio::task::spawn_blocking(move || -> Result<String, String> {
                    use baluard_core::sync::engine::SyncEngine;
                    let engine = SyncEngine::new(&vault_path, "baluard-daemon");

                    // Init repo if not already a git repo
                    let git_repo = match engine.open_repo() {
                        Ok(r) => r,
                        Err(_) => engine
                            .init_repo()
                            .map_err(|e| format!("Git init failed: {e}"))?,
                    };

                    // Add origin remote (idempotent check)
                    if let Ok(existing) = engine.get_remote_url(&git_repo, "origin") {
                        if existing != remote_url {
                            return Err(format!(
                                "Remote 'origin' already set to {existing}; disconnect sync first"
                            ));
                        }
                        // Same URL, skip
                    } else {
                        engine
                            .add_remote(&git_repo, "origin", &remote_url)
                            .map_err(|e| format!("Failed to add remote: {e}"))?;
                    }

                    // Stage + commit any pending changes, then push
                    let status = engine
                        .status(&git_repo)
                        .map_err(|e| format!("Status check failed: {e}"))?;
                    if status.is_dirty() {
                        engine
                            .commit_all(&git_repo, "")
                            .map_err(|e| format!("Commit failed: {e}"))?;
                    }
                    engine
                        .push(&git_repo, "origin")
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
                    if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked()
                    {
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

                ok_resp(
                    serde_json::json!({
                        "status": "synced",
                        "repo": remote_url,
                        "provider": provider_for_reg
                    })
                    .to_string(),
                    token_str,
                )
            }

            #[cfg(not(feature = "git-sync"))]
            err_response("Git sync not available (compiled without git-sync feature)")
        }

        _ => err_response(format!("Unknown action: {}", req.action)),
    };

    // Schedule cover commit + arm auto-sync after successful vault mutations
    if resp.success && COVER_MUTATION_ACTIONS.contains(&req.action.as_str()) {
        state.schedule_cover_after_commit();
        let dn = device_name(&state.vault_path);
        state.autosync.nudge(dn).await;
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
        baluard_core::sync::engine::PullResult::AlreadyUpToDate => {
            "Already up to date.".to_string()
        }
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
        let abort_path = vault_path.join(format!("meta/rekey/{aborted_epoch}.aborted"));
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

/// Infer the provider from a remote URL. Tries the hardcoded public
/// hostnames first, then falls back to matching against any connected
/// provider's persisted `instance_url` (self-hosted GitLab/Forgejo). H5:
/// without the fallback, self-hosted instances always return None and the
/// desktop can't show State C even though sync is active.
#[cfg(feature = "git-sync")]
fn infer_provider_from_url(url: &str) -> Option<String> {
    if url.contains("github.com") {
        return Some("github".to_string());
    }
    if url.contains("gitlab.com") {
        return Some("gitlab".to_string());
    }
    if url.contains("codeberg.org") {
        return Some("codeberg".to_string());
    }
    // Self-hosted: match against connected providers' effective instance host.
    if let Ok(state) = baluard_core::providers::token::ProvidersState::load() {
        for provider in baluard_core::providers::types::Provider::all() {
            if let Some(info) = state.get(*provider) {
                let instance = info.effective_instance_url();
                if url.contains(&instance) {
                    return Some(provider.to_string());
                }
            }
        }
    }
    None
}

#[cfg(feature = "git-sync")]
fn sync_status_json(vault_path: &std::path::Path) -> Result<String, String> {
    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = match engine.open_repo() {
        Ok(r) => r,
        Err(_) => {
            // Not a git repo
            let resp = serde_json::json!({
                "initialized": false,
                "has_remote": false,
                "remote_url": null,
                "provider": null,
                "dirty": false
            });
            return serde_json::to_string(&resp).map_err(|e| format!("JSON error: {e}"));
        }
    };

    let status = engine.status(&repo).map_err(|e| format!("{e}"))?;
    let remote_url = engine.get_remote_url(&repo, "origin").ok();
    let provider = remote_url.as_deref().and_then(infer_provider_from_url);

    let log = engine.log(&repo, 1).map_err(|e| format!("{e}"))?;
    let last_commit = log.first().map(|c| {
        serde_json::json!({
            "id": c.id.clone(),
            "message": c.message.trim().to_string(),
            "time": c.time
        })
    });

    // last_synced (Unix seconds) from the vault registry, if available.
    // Drives the user-facing "Last synced X ago" label. Best-effort: a
    // missing marker/registry yields null, not an error.
    let last_synced = baluard_core::vault::registry::BaluardMarker::read_from_vault(vault_path)
        .ok()
        .flatten()
        .and_then(|m| {
            baluard_core::vault::registry::VaultRegistry::load_locked()
                .ok()
                .and_then(|reg| reg.get(&m.slug).and_then(|e| e.last_synced))
        });

    let resp = serde_json::json!({
        "initialized": true,
        "has_remote": remote_url.is_some(),
        "remote_url": remote_url,
        "provider": provider,
        "dirty": status.is_dirty(),
        "last_commit": last_commit,
        "last_synced": last_synced
    });
    serde_json::to_string(&resp).map_err(|e| format!("JSON error: {e}"))
}

pub(crate) fn parse_repo_owner_name(url: &str) -> Option<(String, String)> {
    let cleaned = url.strip_suffix(".git").unwrap_or(url);
    let segments: Vec<&str> = cleaned.split(['/', ':']).collect();
    if segments.len() >= 2 {
        let name = segments[segments.len() - 1].to_string();
        let owner = segments[segments.len() - 2].to_string();
        Some((owner, name))
    } else {
        None
    }
}

/// Convert a git remote URL (SSH or HTTPS) to a browser URL for the repo.
/// SSH:  git@github.com:owner/name.git -> https://github.com/owner/name
/// HTTPS: https://gitlab.com/owner/name.git -> https://gitlab.com/owner/name
/// Used to offer a manual-delete link when the provider-side delete fails.
pub(crate) fn repo_web_url_from_remote(remote_url: &str) -> Option<String> {
    let cleaned = remote_url.strip_suffix(".git").unwrap_or(remote_url);
    let ssh = cleaned.strip_prefix("git@").and_then(|rest| {
        let (host, path) = rest.split_once(':')?;
        Some(format!("https://{host}/{path}"))
    });
    if let Some(url) = ssh {
        return Some(url);
    }
    if cleaned.starts_with("https://") || cleaned.starts_with("http://") {
        return Some(cleaned.to_string());
    }
    None
}

/// Phase 2b: apply the user's verdict to the head paused conflict.
///
/// `keep_local` / `keep_remote` read the raw blob from the chosen side's OID
/// and hand the bytes to [`SyncEngine::finalize_conflicts`], which writes the
/// 2-parent merge commit + pushes. No decryption happens here (2b-2 will add
/// field-level merge; 2b-3 adds `keep_both` with a new cipher UUID).
///
/// On success the head is drained via [`AutoSyncHandle::note_resolved`]; if
/// the queue is now empty the coordinator transitions to Dirty and re-arms the
/// debounce push (covers both the merge commit and any mutations queued while
/// the conflict was paused).
#[cfg(feature = "git-sync")]
async fn handle_sync_conflict_resolve(
    state: &crate::state::VaultState,
    payload_str: &str,
) -> Result<String, String> {
    use baluard_core::sync::engine::SyncEngine;

    let payload: serde_json::Value = serde_json::from_str(payload_str)
        .map_err(|e| format!("invalid conflict.resolve payload: {e}"))?;
    let verdict = payload["verdict"]
        .as_str()
        .ok_or_else(|| "missing \"verdict\" (keep_local|keep_remote|keep_both)".to_string())?;

    if verdict == "keep_both" {
        // keep_both needs decrypt + re-encrypt under a new cipher id. Delegate
        // to the state method that holds the handle (acquires cycle_lock
        // internally).
        return state.conflict_resolve_keep_both().await;
    }

    // Phase 2b review fix #2: serialize keep_local/keep_remote repo writes
    // against cycle_lock too (two overlapping sync.conflict.resolve calls
    // could race finalize_conflicts' HEAD-tip guard).
    let _cycle_guard = state.autosync.cycle_lock_guard().await;

    let pending = state
        .autosync
        .peek_pending_conflict()
        .await
        .ok_or_else(|| "no pending conflict to resolve".to_string())?;

    // Pick the source OID for each conflicting file's bytes.
    let src_oid = match verdict {
        "keep_local" => pending.local_oid,
        "keep_remote" => pending.remote_oid,
        other => return Err(format!("unknown verdict: {other}")),
    };

    let vault_path = state.vault_path.clone();
    let device = device_name(&vault_path);
    let pending_clone = pending.clone();
    let join_result = tokio::time::timeout(
        SYNC_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || -> (bool, Option<String>) {
            let engine = SyncEngine::new(&vault_path, &device);
            let repo = match engine.open_repo() {
                Ok(r) => r,
                Err(e) => return (false, Some(format!("open repo: {e}"))),
            };
            // Read each conflicting file's bytes from the chosen side.
            let mut resolved: Vec<(String, Vec<u8>)> =
                Vec::with_capacity(pending_clone.files.len());
            for f in &pending_clone.files {
                let bytes = match SyncEngine::read_blob_from_commit(&repo, src_oid, f) {
                    Ok(b) => b,
                    Err(e) => return (false, Some(format!("read {f}: {e}"))),
                };
                resolved.push((f.clone(), bytes));
            }
            match engine.finalize_conflicts(&repo, &pending_clone, &resolved) {
                Ok(_) => (true, None),
                // A push network failure still leaves the merge commit written
                // locally; the coordinator will retry the push on the next cycle.
                // Treat as success for queue-draining purposes.
                Err(e) if baluard_core::sync::engine::is_network_error(&e) => (true, None),
                Err(e) => (false, Some(format!("finalize: {e}"))),
            }
        }),
    )
    .await;
    let (merge_ok, err) = match join_result {
        Ok(Ok(inner)) => inner,
        Ok(Err(join_e)) => (false, Some(format!("finalize task join: {join_e}"))),
        Err(_) => (false, Some("conflict finalize timed out".to_string())),
    };

    if !merge_ok {
        return Err(err.unwrap_or_else(|| "finalize failed".to_string()));
    }

    // Drain the head. note_resolved transitions to Dirty (re-sync) when the
    // queue empties.
    state.autosync.note_resolved().await;
    // Phase 2b: the resolution wrote cipher files directly via SyncEngine
    // (bypassing VaultHandle's index-rebuild hooks). Rebuild so vault.list
    // reflects the change (best-effort; index self-heals on next mutation).
    state.rebuild_cipher_index().await;

    let body = serde_json::json!({ "resolved": true, "remaining": state.autosync.pending_conflict_count().await });
    serde_json::to_string(&body).map_err(|e| format!("JSON error: {e}"))
}

#[cfg(not(feature = "git-sync"))]
async fn handle_sync_conflict_resolve(
    _state: &crate::state::VaultState,
    _payload_str: &str,
) -> Result<String, String> {
    Err("git-sync feature disabled".to_string())
}

#[cfg(feature = "git-sync")]
async fn sync_disconnect(
    vault_path: &std::path::Path,
    payload_str: &str,
) -> Result<String, String> {
    let payload: serde_json::Value = if payload_str.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(payload_str).map_err(|e| format!("invalid disconnect payload: {e}"))?
    };
    let delete_remote = payload["delete_remote"].as_bool().unwrap_or(false);

    let engine = baluard_core::sync::engine::SyncEngine::new(vault_path, &device_name(vault_path));
    let repo = engine
        .open_repo()
        .map_err(|e| format!("No git repo: {e}"))?;

    // Verify origin exists
    let remote_url = engine
        .get_remote_url(&repo, "origin")
        .map_err(|e| format!("No 'origin' remote: {e}"))?;

    // Destructive: delete the repository at the provider. Best-effort: a
    // failure (403/no delete scope, network, not-owner) does NOT abort the
    // disconnect. The user is never trapped, and is told the truth via the
    // returned `remote_deleted` flag + error so the desktop can warn them
    // to delete the repo manually. Only fatal pre-conditions (no git repo,
    // no origin) abort above.
    let mut remote_deleted = false;
    let mut delete_error: Option<String> = None;
    if delete_remote {
        // Try to resolve slug/provider/owner/name. Each missing piece just
        // means we cannot delete; we still disconnect below.
        let resolved = (async {
            let slug = baluard_core::vault::registry::BaluardMarker::read_from_vault(vault_path)
                .ok()
                .flatten()
                .map(|m| m.slug)?;
            let reg = baluard_core::vault::registry::VaultRegistry::load_locked().ok()?;
            let entry = reg.get(&slug)?;
            let provider_name = entry.provider.as_ref()?;
            let reg_remote = entry.remote_url.as_ref()?;
            let url_source = if remote_url.is_empty() {
                reg_remote
            } else {
                &remote_url
            };
            let (owner, name) = parse_repo_owner_name(url_source)?;
            let provider = baluard_core::providers::types::Provider::all()
                .iter()
                .find(|p| p.to_string() == *provider_name)?;
            Some((*provider, owner, name))
        })
        .await;

        match resolved {
            Some((provider, owner, name)) => {
                // Token + provider init + delete. Each step can fail on
                // permissions; capture the message for the warning.
                let attempt = async {
                    let state_file = baluard_core::providers::token::ProvidersState::load()
                        .map_err(|e| format!("cannot load providers state: {e}"))?;
                    let info = state_file
                        .get(provider)
                        .ok_or_else(|| format!("no token for provider '{provider}'"))?;
                    let token = ensure_valid_token(provider, info)
                        .await
                        .map_err(|_e| format!("token refresh failed for provider '{provider}'"))?;
                    let prov = baluard_core::providers::provider_for(provider, info.config())
                        .map_err(|e| format!("provider init failed: {e}"))?;
                    prov.delete_repo(&token, &owner, &name)
                        .await
                        .map_err(|e| format!("failed to delete remote repo: {e}"))?;
                    Ok::<(), String>(())
                }
                .await;
                match attempt {
                    Ok(()) => remote_deleted = true,
                    Err(e) => delete_error = Some(e),
                }
            }
            None => {
                delete_error = Some("could not resolve vault provider/owner/name".to_string());
            }
        }
    }

    // Remove the remote
    engine
        .remove_remote(&repo, "origin")
        .map_err(|e| format!("Failed to remove remote: {e}"))?;

    // Clear sync fields in registry
    let slug = baluard_core::vault::registry::BaluardMarker::read_from_vault(vault_path)
        .ok()
        .flatten()
        .map(|m| m.slug);
    if let Some(ref slug_str) = slug {
        if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load_locked() {
            if let Some(entry) = reg.get_mut(slug_str) {
                entry.provider = None;
                entry.remote_url = None;
                entry.last_synced = None;
            }
            let _ = reg.save_locked();
        }
    }

    // Derive the provider web URL for the repo so the desktop can offer a
    // manual-delete link when the provider-side delete failed.
    let repo_web_url = repo_web_url_from_remote(&remote_url);

    let resp = serde_json::json!({
        "disconnected": true,
        "removed_url": remote_url,
        "remote_deleted": remote_deleted,
        "delete_error": delete_error,
        "repo_web_url": repo_web_url
    });
    serde_json::to_string(&resp).map_err(|e| format!("JSON error: {e}"))
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
#[cfg(not(feature = "git-sync"))]
fn sync_status_json(_p: &std::path::Path) -> Result<String, String> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
async fn sync_disconnect(_p: &std::path::Path, _payload: &str) -> Result<String, String> {
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

#[cfg(test)]
mod tests {
    use super::{parse_repo_owner_name, repo_web_url_from_remote};

    /// Covers the URL forms `sync_disconnect` must extract owner/name from.
    /// If this breaks, the destructive delete-remote path silently no-ops
    /// (returns Err on the now-unparseable URL instead of deleting).
    #[test]
    fn parse_repo_owner_name_handles_common_forms() {
        // SSH (git@)
        assert_eq!(
            parse_repo_owner_name("git@github.com:alice/vault.git"),
            Some(("alice".into(), "vault".into()))
        );
        // HTTPS, no .git
        assert_eq!(
            parse_repo_owner_name("https://gitlab.com/bob/secrets"),
            Some(("bob".into(), "secrets".into()))
        );
        // HTTPS with .git suffix stripped
        assert_eq!(
            parse_repo_owner_name("https://codeberg.org/carol/data.git"),
            Some(("carol".into(), "data".into()))
        );
        // Self-hosted GitLab with a port
        assert_eq!(
            parse_repo_owner_name("https://git.example.com:8443/dan/proj.git"),
            Some(("dan".into(), "proj".into()))
        );
    }

    /// Garbage in -> None out. The caller turns this into an explicit error,
    /// never a silent skip of the destructive op.
    #[test]
    fn parse_repo_owner_name_rejects_garbage() {
        assert_eq!(parse_repo_owner_name("not-a-url"), None);
        assert_eq!(parse_repo_owner_name(""), None);
    }

    /// The manual-delete link offered when provider-side delete fails must
    /// resolve to a real browser URL for both SSH and HTTPS remotes.
    #[test]
    fn repo_web_url_from_remote_handles_common_forms() {
        assert_eq!(
            repo_web_url_from_remote("git@github.com:alice/vault.git"),
            Some("https://github.com/alice/vault".into())
        );
        assert_eq!(
            repo_web_url_from_remote("https://gitlab.com/bob/secrets"),
            Some("https://gitlab.com/bob/secrets".into())
        );
        assert_eq!(
            repo_web_url_from_remote("https://codeberg.org/carol/data.git"),
            Some("https://codeberg.org/carol/data".into())
        );
        assert_eq!(repo_web_url_from_remote("not-a-url"), None);
    }

    // ── Browser bridge regression tests ──

    use super::{bridge_update_touches_forbidden, hostname_matches};

    /// C2 regression: the field-gate MUST see fido2_credentials / uris under
    /// kind.data (the real serialized CipherKind shape), not kind directly.
    /// Before the fix, this payload was allowed through.
    #[test]
    fn bridge_update_gate_catches_forbidden_fields_under_kind_data() {
        // Real shape: {"kind":{"type":"login","data":{...}}}.
        let with_fido2 = serde_json::json!({
            "kind": { "type": "login", "data": { "fido2_credentials": [{"credential_id": "x"}] } }
        });
        assert!(
            bridge_update_touches_forbidden(&with_fido2),
            "fido2_credentials under kind.data must be caught"
        );
        let with_uris = serde_json::json!({
            "kind": { "type": "login", "data": { "uris": [{"uri": "https://evil.com"}] } }
        });
        assert!(
            bridge_update_touches_forbidden(&with_uris),
            "uris under kind.data must be caught"
        );
    }

    /// C2 companion: a benign update (password only) MUST pass the gate.
    #[test]
    fn bridge_update_gate_allows_benign_password_change() {
        let benign = serde_json::json!({
            "id": "abc-123",
            "kind": { "type": "login", "data": { "password": "newpw" } }
        });
        assert!(!bridge_update_touches_forbidden(&benign));
    }

    /// C3 regression: hostname matching MUST NOT let `evilgithub.com` match
    /// `github.com`. Dot-boundary is required for subdomain matches.
    #[test]
    fn hostname_match_rejects_phishing_lookalikes() {
        // Exact match is fine.
        assert!(hostname_matches("github.com", "github.com"));
        // Legit subdomain.
        assert!(hostname_matches("github.com", "api.github.com"));
        assert!(hostname_matches("api.github.com", "github.com"));
        // Phishing: evilgithub.com must NOT match github.com (no dot boundary).
        assert!(!hostname_matches("github.com", "evilgithub.com"));
        assert!(!hostname_matches("evilgithub.com", "github.com"));
        // Phishing: github.com.evil.com must NOT match.
        assert!(!hostname_matches("github.com", "github.com.evil.com"));
        // Bare TLD must not match a domain sharing that suffix.
        assert!(!hostname_matches("com", "github.com"));
    }
}
