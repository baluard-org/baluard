//! MCP agent-access routes and the shared tool-call policy engine (ADR
//! 0116). Desktop pairing management rides `mcp.*` routes (user session);
//! both transports' tool calls funnel through the same approval stack:
//! caps -> yolo -> scoped grant -> pending human approval -> audit. All
//! policy math lives in `baluard-mcp`; this module owns vault access.

use crate::agent_audit;
use crate::agent_run::process_chain;
use crate::handler::{err_response, ok_resp};
use crate::host::SharedVaultHost;
use crate::proto::{GatewayRequest, GatewayResponse};
use baluard_mcp::{McpAction, ReadGrantKey};
use baluard_runtime::agents::{PendingOutcome, PendingPurpose};
use std::time::Duration;

/// The process-wide MCP registry (pairings persist; every volatile window
/// dies on lock or restart by construction). The runtime lock hook in
/// VaultState::lock() clears it through the same global.
pub(crate) use baluard_mcp::registry::GLOBAL as MCP_REGISTRY;

fn audit(
    event: &str,
    vault: &str,
    actor: &str,
    request_id: Option<&str>,
    item_ids: &[String],
    outcome: &str,
) -> Result<(), String> {
    let peer = baluard_runtime::agents::PeerBinding::new(0, actor.to_string(), 0);
    agent_audit::append(
        &baluard_core::paths::data_dir(),
        event,
        vault,
        &peer,
        request_id,
        None,
        item_ids,
        outcome,
    )
}

fn audit_best_effort(event: &str, vault: &str, actor: &str, outcome: &str) {
    if let Err(error) = audit(event, vault, actor, None, &[], outcome) {
        eprintln!("mcp audit: {error}");
    }
}

async fn verify_user(
    req: &GatewayRequest,
    state: &baluard_runtime::state::VaultState,
) -> Result<(), GatewayResponse> {
    state
        .verify_session_token(&req.session_token)
        .await
        .map_err(err_response)
}

async fn target_state(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    payload_slug: Option<&str>,
) -> Result<(String, crate::state::SharedVaultState), GatewayResponse> {
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        payload_slug
    };
    match host.snapshot_target(slug).await {
        Ok(pair) => Ok(pair),
        Err(_) => Err(err_response("No active vault")),
    }
}

fn session_actor(peer: Option<&baluard_runtime::agents::PeerBinding>) -> String {
    match peer {
        Some(p) if p.pid != 0 => format!("desktop session pid {}", p.pid),
        _ => "desktop session".to_string(),
    }
}

/// Resolves a process's executable path. Linux reads /proc, macOS uses
/// libproc; other platforms have no stdio transport (ADR 0116), so None
/// fails closed at the session bootstrap.
pub(crate) fn exe_path_for_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buf holds PROC_PIDPATHINFO_MAXSIZE bytes; proc_pidpath writes at most bufsize bytes and returns the length written.
        let len = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if len <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..len as usize]).into_owned())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

// ── Desktop management routes ────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PairPayload {
    name: String,
}

#[derive(serde::Deserialize)]
struct YoloSetPayload {
    pairing_id: String,
    enabled: bool,
    #[serde(default)]
    duration_secs: Option<u64>,
    #[serde(default)]
    master_password: Option<zeroize::Zeroizing<String>>,
}

#[derive(serde::Deserialize)]
struct IdPayload {
    pairing_id: String,
}

/// Handles every `mcp.*` management action (desktop-only, user session).
pub async fn handle_mcp_route(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&baluard_runtime::agents::PeerBinding>,
) -> GatewayResponse {
    match req.action.as_str() {
        "mcp.status" => {
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let server = crate::mcp_http::server_status_json();
            let pairings: Vec<serde_json::Value> = MCP_REGISTRY
                .pairing_views()
                .into_iter()
                .filter(|p| p.vault_slug == slug)
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "name": p.name,
                        "vault_slug": p.vault_slug,
                        "created_at_ms": p.created_at_ms,
                        "yolo_expires_in_secs": p.yolo_expires_in_secs,
                    })
                })
                .collect();
            ok_resp(
                serde_json::json!({ "server": server, "pairings": pairings }).to_string(),
                None,
            )
        }
        "mcp.pair" => {
            let payload: PairPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            let name = payload.name.trim();
            if name.is_empty() || name.chars().count() > 80 {
                return err_response("agent name must be 1-80 characters");
            }
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let actor = session_actor(peer);
            audit_best_effort("mcp_paired", &slug, &actor, "requested");
            // Bind slug -> path so the runtime lock hook can clear this
            // pairing's volatile state on lock.
            MCP_REGISTRY.bind_vault(&slug, &state.vault_path);
            match MCP_REGISTRY.create_pairing(name, &slug, &baluard_core::paths::data_dir()) {
                Ok((pairing, token)) => {
                    audit_best_effort("mcp_paired", &slug, &actor, "saved");
                    ok_resp(
                        serde_json::json!({
                            "pairing": {
                                "id": pairing.id,
                                "name": pairing.name,
                                "vault_slug": pairing.vault_slug,
                                "created_at_ms": pairing.created_at_ms,
                            },
                            // Shown once; only the hash is stored.
                            "token": token,
                        })
                        .to_string(),
                        None,
                    )
                }
                Err(e) => {
                    let _ = audit("mcp_paired", &slug, &actor, None, &[], "failed");
                    err_response(e)
                }
            }
        }
        "mcp.revoke" => {
            let payload: IdPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let actor = session_actor(peer);
            audit_best_effort("mcp_revoked", &slug, &actor, "requested");
            match MCP_REGISTRY.revoke_pairing(&payload.pairing_id, &baluard_core::paths::data_dir())
            {
                Ok(removed) => {
                    audit_best_effort("mcp_revoked", &slug, &actor, "saved");
                    ok_resp(serde_json::json!({ "revoked": removed }).to_string(), None)
                }
                Err(e) => {
                    let _ = audit("mcp_revoked", &slug, &actor, None, &[], "failed");
                    err_response(e)
                }
            }
        }
        "mcp.yolo_set" => {
            let payload: YoloSetPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid JSON: {e}")),
            };
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let known = MCP_REGISTRY
                .pairing_views()
                .iter()
                .any(|p| p.id == payload.pairing_id && p.vault_slug == slug);
            if !known {
                return err_response("unknown pairing for this vault");
            }
            let actor = session_actor(peer);
            let event = if payload.enabled {
                "mcp_yolo_enabled"
            } else {
                "mcp_yolo_killed"
            };
            if let Err(error) = audit(event, &slug, &actor, None, &[], "requested") {
                return err_response(format!("agent audit failed: {error}"));
            }
            if payload.enabled {
                let Some(password) = payload.master_password.as_deref() else {
                    return err_response(
                        "Master password required to allow this agent to read without prompts",
                    );
                };
                if let Err(e) = crate::handler::verify_seal_change_password(&state, password).await
                {
                    return err_response(e);
                }
                let ttl = payload.duration_secs.unwrap_or(300);
                if ttl == 0 || ttl > 3600 {
                    return err_response("auto-approve duration must be 1-3600 seconds");
                }
                if let Err(e) = MCP_REGISTRY.yolo_enable(&payload.pairing_id, ttl) {
                    let _ = audit(event, &slug, &actor, None, &[], "failed");
                    return err_response(e.to_string());
                }
            }
            let _ = audit(event, &slug, &actor, None, &[], "saved");
            let expires_in = MCP_REGISTRY
                .pairing_views()
                .iter()
                .find(|p| p.id == payload.pairing_id)
                .and_then(|p| p.yolo_expires_in_secs);
            ok_resp(
                serde_json::json!({
                    "enabled": payload.enabled,
                    "yolo_expires_in_secs": expires_in,
                })
                .to_string(),
                None,
            )
        }
        _ => err_response(format!("Unknown action: {}", req.action)),
    }
}

// ── Tool-call policy engine (shared by both transports) ─────────────────

pub struct ToolCallContext {
    pub vault_slug: String,
    /// Pairing id (HTTP) or session id (stdio): the cap/yolo/grant key.
    pub identity_id: String,
    pub actor: String,
}

/// Search: cap charge, query validation, lock check, metadata match, then
/// at most SEARCH_RESULT_CAP row decrypts for the URIs.
pub async fn run_search(
    state: &baluard_runtime::state::VaultState,
    ctx: &ToolCallContext,
    query: &str,
) -> GatewayResponse {
    if MCP_REGISTRY.charge_search(&ctx.identity_id) == baluard_mcp::CapOutcome::Throttled {
        audit_best_effort("mcp_search", &ctx.vault_slug, &ctx.actor, "throttled");
        return err_response("search cap reached; try again later");
    }
    if let Err(reason) = baluard_mcp::validate_search_query(query) {
        return err_response(reason);
    }
    if !state.is_unlocked().await {
        return err_response("locked");
    }
    let metas = match state.list_cipher_meta().await {
        Ok(metas) => metas,
        Err(e) => return err_response(e),
    };
    let needle = query.to_lowercase();
    let mut rows = Vec::new();
    for meta in metas {
        let name_hit = meta.name.to_lowercase().contains(&needle);
        let user_hit = meta
            .username
            .as_deref()
            .map(|u| u.to_lowercase().contains(&needle))
            .unwrap_or(false);
        if !name_hit && !user_hit {
            continue;
        }
        if rows.len() >= baluard_mcp::SEARCH_RESULT_CAP {
            break;
        }
        let uris = match state.get_cipher(&meta.id.to_string(), true).await {
            Ok(json) => serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|v| {
                    v.get("uris").and_then(|u| u.as_array()).map(|list| {
                        list.iter()
                            .filter_map(|u| {
                                u.as_str().map(str::to_string).or_else(|| {
                                    u.get("uri").and_then(|x| x.as_str()).map(str::to_string)
                                })
                            })
                            .collect::<Vec<String>>()
                    })
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        rows.push(baluard_mcp::SearchRow {
            id: meta.id.to_string(),
            name: meta.name.clone(),
            username: meta.username.clone(),
            uris,
        });
    }
    let rows = baluard_mcp::filter_rows(&needle, rows);
    audit_best_effort("mcp_search", &ctx.vault_slug, &ctx.actor, "approved");
    ok_resp(serde_json::json!({ "items": rows }).to_string(), None)
}

/// Executes a secret-read tool against the vault after approval cleared.
async fn run_secret_tool(
    state: &baluard_runtime::state::VaultState,
    tool: McpAction,
    item_id: &str,
) -> Result<String, String> {
    match tool {
        McpAction::GetLogin => {
            let json = state.get_cipher(item_id, true).await?;
            let cipher: serde_json::Value =
                serde_json::from_str(&json).map_err(|_| "item is malformed".to_string())?;
            serde_json::to_string(&baluard_mcp::project_login(&cipher)?)
                .map_err(|e| format!("item projection failed: {e}"))
        }
        McpAction::GetTotp => {
            let json = state.get_cipher(item_id, true).await?;
            let cipher: serde_json::Value =
                serde_json::from_str(&json).map_err(|_| "item is malformed".to_string())?;
            let has_totp = cipher
                .get("totp")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.is_empty());
            if !has_totp {
                return Err("this entry has no TOTP configured".to_string());
            }
            let code = state.totp_code(item_id).await?;
            let name = cipher
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            serde_json::to_string(&serde_json::json!({
                "id": item_id,
                "name": name,
                "code": code,
            }))
            .map_err(|e| format!("totp projection failed: {e}"))
        }
        McpAction::Search => Err("search is not a secret read".to_string()),
    }
}

enum ReadApprovalError {
    Denied,
    Timeout,
}

/// The full secret-read stack: caps -> yolo -> scoped grant -> pending
/// human approval (30 s server-side window; a cancelled or timed-out call
/// removes the pending request so a late click cannot orphan a grant).
pub async fn handle_secret_read(
    state: &baluard_runtime::state::VaultState,
    host: &SharedVaultHost,
    ctx: &ToolCallContext,
    item_id: &str,
    tool_name: &str,
    tool: McpAction,
) -> GatewayResponse {
    // Caps trip deterministically, in and out of yolo, before anything can
    // grant a read.
    if MCP_REGISTRY.charge_read(&ctx.identity_id) == baluard_mcp::CapOutcome::Throttled {
        let items = vec![item_id.to_string()];
        let _ = audit(
            "mcp_read",
            &ctx.vault_slug,
            &ctx.actor,
            None,
            &items,
            "throttled",
        );
        return err_response("read cap reached; try again later");
    }
    let auto = MCP_REGISTRY.yolo_active(&ctx.identity_id);
    if !auto
        && !MCP_REGISTRY.read_grant_live(&ReadGrantKey {
            pairing_id: ctx.identity_id.clone(),
            item_id: item_id.to_string(),
            tool: tool_name.to_string(),
        })
    {
        // Queue a pending request; the desktop modal shows it with the
        // duration ladder. Queue caps inside push() silently deny a flood.
        let requested = host.pending_requests().push(
            Some(ctx.vault_slug.clone()),
            baluard_runtime::agents::PeerBinding::new(0, ctx.actor.clone(), 0),
            ctx.identity_id.clone(),
            format!("wants to read an entry over MCP ({tool_name})"),
            vec![item_id.to_string()],
            PendingPurpose::McpRead,
        );
        let request_id = match requested {
            Ok(id) => id,
            Err(_) => return err_response("denied: approval queue is full"),
        };
        let items = vec![item_id.to_string()];
        let _ = audit(
            "mcp_read",
            &ctx.vault_slug,
            &ctx.actor,
            Some(&request_id),
            &items,
            "pending",
        );
        match wait_for_read_approval(host, &request_id).await {
            Ok(ttl_secs) => {
                if ttl_secs > 0 {
                    MCP_REGISTRY.grant_read(
                        ReadGrantKey {
                            pairing_id: ctx.identity_id.clone(),
                            item_id: item_id.to_string(),
                            tool: tool_name.to_string(),
                        },
                        ttl_secs,
                    );
                }
                let _ = audit(
                    "mcp_read",
                    &ctx.vault_slug,
                    &ctx.actor,
                    Some(&request_id),
                    &items,
                    "approved",
                );
            }
            Err(ReadApprovalError::Denied) => {
                let _ = audit(
                    "mcp_read",
                    &ctx.vault_slug,
                    &ctx.actor,
                    Some(&request_id),
                    &items,
                    "denied",
                );
                return err_response("denied");
            }
            Err(ReadApprovalError::Timeout) => {
                let _ = audit(
                    "mcp_read",
                    &ctx.vault_slug,
                    &ctx.actor,
                    Some(&request_id),
                    &items,
                    "timeout",
                );
                return err_response("timeout: the user did not respond in time");
            }
        }
    }
    let outcome_word = if auto { "auto-approved" } else { "approved" };
    let items = vec![item_id.to_string()];
    if let Err(error) = audit(
        "mcp_read",
        &ctx.vault_slug,
        &ctx.actor,
        None,
        &items,
        outcome_word,
    ) {
        return err_response(format!("agent audit failed: {error}"));
    }
    match run_secret_tool(state, tool, item_id).await {
        Ok(json) => ok_resp(json, None),
        Err(e) => err_response(e),
    }
}

async fn wait_for_read_approval(
    host: &SharedVaultHost,
    request_id: &str,
) -> Result<u64, ReadApprovalError> {
    let deadline = tokio::time::Instant::now() + baluard_mcp::READ_APPROVAL_WAIT;
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if let Some(outcome) = host.pending_requests().take_outcome(request_id) {
            return match outcome {
                // The approval route stores the chosen ladder duration
                // directly as the outcome payload for McpRead requests.
                PendingOutcome::Approved { token } => token
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| ReadApprovalError::Timeout),
                PendingOutcome::Denied => Err(ReadApprovalError::Denied),
                PendingOutcome::TimedOut => Err(ReadApprovalError::Timeout),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            // Remove the request so a late human click can never activate
            // an orphaned grant.
            let _ = host.pending_requests().deny(request_id);
            return Err(ReadApprovalError::Timeout);
        }
    }
}

/// One tool call on the desktop HTTP transport. The pairing token arrived
/// on the Authorization header and is already verified; `pairing` is the
/// resolved vault binding.
pub async fn http_tool_call(
    host: &SharedVaultHost,
    pairing: baluard_mcp::Pairing,
    tool_name: &str,
    args: &serde_json::Value,
) -> GatewayResponse {
    let Some(action) = baluard_mcp::mcp_action_for_tool(tool_name) else {
        return err_response("denied");
    };
    let (slug, state) = match host.snapshot_target(Some(&pairing.vault_slug)).await {
        Ok(pair) => pair,
        Err(_) => return err_response("locked"),
    };
    if slug != pairing.vault_slug {
        return err_response("pairing is bound to a different vault");
    }
    MCP_REGISTRY.bind_vault(&slug, &state.vault_path);
    let ctx = ToolCallContext {
        vault_slug: slug,
        identity_id: pairing.id.clone(),
        actor: format!("mcp:{}", pairing.name),
    };
    match action {
        McpAction::Search => {
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            run_search(&state, &ctx, &query).await
        }
        McpAction::GetLogin | McpAction::GetTotp => {
            let Some(item_id) = args.get("item_id").and_then(|v| v.as_str()) else {
                return err_response("item_id is required");
            };
            handle_secret_read(&state, host, &ctx, item_id, tool_name, action).await
        }
    }
}

/// The stdio transport's session bootstrap: resolve the serve process's
/// parent chain in-daemon, name the parent executable, and mint a volatile
/// session after the human approves.
pub async fn stdio_session_start(
    host: &SharedVaultHost,
    peer: Option<&baluard_runtime::agents::PeerBinding>,
    vault_slug: &str,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let Some(chain) = process_chain(peer.pid) else {
        return err_response("agent process tree is unavailable");
    };
    // The parent of `baluard mcp serve` is the coding agent. A missing or
    // init-parented process (ppid <= 1, double-fork) is rejected, never
    // bound to init.
    let Some(&(parent_pid, parent_start)) = chain.get(1) else {
        return err_response("the parent process could not be resolved");
    };
    if parent_pid <= 1 {
        return err_response("the parent process could not be resolved");
    }
    let parent_exe = exe_path_for_pid(parent_pid).unwrap_or_else(|| format!("pid {parent_pid}"));
    let display = std::path::Path::new(&parent_exe)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| parent_exe.clone());
    let request_id = match host.pending_requests().push(
        Some(vault_slug.to_string()),
        baluard_runtime::agents::PeerBinding::new(parent_pid, parent_exe.clone(), parent_start),
        display.clone(),
        "MCP access over stdio: entry search and per-read secret reads".to_string(),
        Vec::new(),
        PendingPurpose::McpSession,
    ) {
        Ok(id) => id,
        Err(_) => return err_response("another agent request is already waiting"),
    };
    audit_best_effort("mcp_session", vault_slug, &parent_exe, "pending");
    let deadline = tokio::time::Instant::now() + baluard_mcp::SESSION_APPROVAL_WAIT;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Some(outcome) = host.pending_requests().take_outcome(&request_id) {
            return match outcome {
                PendingOutcome::Approved { token } => {
                    // The approval route minted the session; the outcome
                    // carries "<session_token>|<display_name>".
                    let session_token = token.split('|').next().unwrap_or_default().to_string();
                    if let Err(error) = audit(
                        "mcp_session",
                        vault_slug,
                        &parent_exe,
                        Some(&request_id),
                        &[],
                        "approved",
                    ) {
                        return err_response(format!("agent audit failed: {error}"));
                    }
                    ok_resp(
                        serde_json::json!({
                            "session_token": session_token,
                            "vault_slug": vault_slug,
                            "exe_path": parent_exe,
                        })
                        .to_string(),
                        None,
                    )
                }
                PendingOutcome::Denied => {
                    audit_best_effort("mcp_session", vault_slug, &parent_exe, "denied");
                    err_response("denied")
                }
                PendingOutcome::TimedOut => {
                    audit_best_effort("mcp_session", vault_slug, &parent_exe, "timeout");
                    err_response("timeout: the user did not respond in time")
                }
            };
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = host.pending_requests().deny(&request_id);
            audit_best_effort("mcp_session", vault_slug, &parent_exe, "timeout");
            return err_response("timeout: the user did not respond in time");
        }
    }
}

/// Tool calls arriving over the CLI stdio transport: verify the volatile
/// session against the caller's process chain, then run the shared engine.
pub async fn stdio_tool_call(
    host: &SharedVaultHost,
    peer: Option<&baluard_runtime::agents::PeerBinding>,
    session_token: &str,
    tool_name: &str,
    args: &serde_json::Value,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let Some(chain) = process_chain(peer.pid) else {
        return err_response("agent process tree is unavailable");
    };
    let verdict = match MCP_REGISTRY.verify_session(session_token, &chain) {
        Ok(v) => v,
        Err(e) => return err_response(e.to_string()),
    };
    let Some(action) = baluard_mcp::mcp_action_for_tool(tool_name) else {
        return err_response("denied");
    };
    let (slug, state) = match host.snapshot_target(Some(&verdict.vault_slug)).await {
        Ok(pair) => pair,
        Err(_) => return err_response("locked"),
    };
    if slug != verdict.vault_slug {
        return err_response("pairing is bound to a different vault");
    }
    MCP_REGISTRY.bind_vault(&slug, &state.vault_path);
    let ctx = ToolCallContext {
        vault_slug: slug,
        identity_id: verdict.session_id,
        actor: format!("stdio:{}", verdict.exe_path),
    };
    match action {
        McpAction::Search => {
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            run_search(&state, &ctx, &query).await
        }
        McpAction::GetLogin | McpAction::GetTotp => {
            let Some(item_id) = args.get("item_id").and_then(|v| v.as_str()) else {
                return err_response("item_id is required");
            };
            handle_secret_read(&state, host, &ctx, item_id, tool_name, action).await
        }
    }
}

/// The desktop approval route calls here for McpRead/McpSession purposes.
/// McpRead records the chosen ladder duration as the outcome payload; the
/// waiting tool call turns it into a scoped grant. McpSession mints the
/// volatile stdio session. Neither mints a process-bound agent grant.
pub fn complete_mcp_approval(
    pending: &baluard_runtime::agents::PendingRequest,
    ttl_secs: Option<u64>,
) -> String {
    match pending.purpose {
        PendingPurpose::McpRead => ttl_secs.unwrap_or(0).to_string(),
        PendingPurpose::McpSession => {
            let peer = &pending.peer;
            let token = MCP_REGISTRY.create_session(
                pending.vault_slug.as_deref().unwrap_or(""),
                &peer.exe_path,
                baluard_mcp::SessionPeer {
                    pid: peer.pid,
                    start_ticks: peer.start_ticks,
                    exe_path: peer.exe_path.clone(),
                },
            );
            format!("{token}|{}", pending.claimed_name)
        }
        _ => String::new(),
    }
}
