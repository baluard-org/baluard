//! D80 agent approval routes. Secret delivery is deliberately not here yet:
//! this module owns requests, human decisions, grant lifecycle, and polling.

use crate::handler::{err_response, ok_resp};
use crate::host::{SharedVaultHost, SnapshotError};
use crate::proto::{GatewayRequest, GatewayResponse};
use crate::state::SharedVaultState;
use baluard_runtime::agents::{DEFAULT_TTL_SECS, PeerBinding, PendingOutcome};

#[derive(serde::Deserialize)]
struct AgentRequestPayload {
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    claimed_name: String,
    #[serde(default)]
    need: String,
    #[serde(default)]
    item_ids: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RequestIdPayload {
    request_id: String,
}

async fn target_state(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    payload_slug: Option<&str>,
) -> Result<(String, SharedVaultState), GatewayResponse> {
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        payload_slug
    };
    match host.snapshot_target(slug).await {
        Ok(pair) => Ok(pair),
        Err(SnapshotError::NoActive) => Err(err_response("No active vault")),
        Err(SnapshotError::SlugNotOpen(slug)) => {
            Err(err_response(format!("Vault '{slug}' is not open")))
        }
    }
}

async fn verify_user(
    req: &GatewayRequest,
    state: &SharedVaultState,
) -> Result<(), GatewayResponse> {
    state
        .verify_session_token(&req.session_token)
        .await
        .map_err(err_response)
}

fn audit(
    event: &str,
    vault: &str,
    peer: &PeerBinding,
    request_id: Option<&str>,
    item_ids: &[String],
    outcome: &str,
) -> Result<(), String> {
    crate::agent_audit::append(
        &baluard_core::paths::data_dir(),
        event,
        vault,
        peer,
        request_id,
        None,
        item_ids,
        outcome,
    )
}

fn audit_best_effort(
    event: &str,
    vault: &str,
    peer: &PeerBinding,
    request_id: Option<&str>,
    item_ids: &[String],
    outcome: &str,
) {
    if let Err(error) = audit(event, vault, peer, request_id, item_ids, outcome) {
        eprintln!("agent audit: {error}");
    }
}

/// Handles every `agents.*` action at host level. Returning a response for
/// unknown agent actions keeps the default-deny route from ever treating an
/// agent grant as a user session token.
pub async fn handle_agent_route(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&PeerBinding>,
) -> GatewayResponse {
    match req.action.as_str() {
        "agents.request" => {
            let Some(peer) = peer else {
                return err_response("agent peer identity is unavailable");
            };
            let payload: AgentRequestPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent request: {e}")),
            };
            if payload.item_ids.is_empty()
                || payload.item_ids.len() > 32
                || payload.claimed_name.len() > 80
                || payload.need.len() > 240
                || payload.item_ids.iter().any(|id| id.len() > 128)
            {
                return err_response("agent request exceeds its size limits");
            }
            let (slug, state) = match target_state(req, host, payload.slug.as_deref()).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if !state.is_unlocked().await {
                return err_response(format!("Vault '{slug}' is locked"));
            }
            // L4 (D81 review): refuse non-Login items at request time, so
            // the user never approves a grant whose run must fail. Items
            // that do not resolve stay request-time-legal; agents.run
            // remains the final validator.
            for item_id in &payload.item_ids {
                if let Ok(cipher_json) = state.get_cipher(item_id, true).await {
                    let kind = serde_json::from_str::<serde_json::Value>(&cipher_json)
                        .ok()
                        .and_then(|v| {
                            v.get("kind")
                                .and_then(|k| k.get("type"))
                                .and_then(|t| t.as_str())
                                .map(String::from)
                        })
                        .unwrap_or_default();
                    if kind != "login" {
                        return err_response("agents may only request logins");
                    }
                }
            }
            let yolo_audit_slug = slug.clone();
            let yolo_audit_items = payload.item_ids.clone();
            if yolo_enabled(&slug) {
                let token = state.agent_mint(peer.clone(), payload.item_ids, DEFAULT_TTL_SECS);
                if let Err(error) = audit(
                    "approved",
                    &yolo_audit_slug,
                    peer,
                    None,
                    &yolo_audit_items,
                    "permissive-mode",
                ) {
                    state.revoke_agent_token(&token);
                    return err_response(format!("agent audit failed: {error}"));
                }
                return ok_resp(
                    serde_json::json!({"status": "approved", "token": token}).to_string(),
                    None,
                );
            }
            let audit_slug = slug.clone();
            let audit_item_ids = payload.item_ids.clone();
            match host.pending_requests().push(
                Some(slug),
                peer.clone(),
                payload.claimed_name,
                payload.need,
                payload.item_ids,
            ) {
                Ok(request_id) => {
                    audit_best_effort(
                        "requested",
                        &audit_slug,
                        peer,
                        Some(&request_id),
                        &audit_item_ids,
                        "pending",
                    );
                    ok_resp(
                        serde_json::json!({"request_id": request_id, "status": "pending"})
                            .to_string(),
                        None,
                    )
                }
                Err(_) => err_response(
                    "another agent request is already waiting; approve or deny it first",
                ),
            }
        }
        "agents.poll" => {
            let payload: RequestIdPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent poll: {e}")),
            };
            if host.pending_requests().get(&payload.request_id).is_some() {
                return ok_resp(serde_json::json!({"status": "pending"}).to_string(), None);
            }
            match host.pending_requests().take_outcome(&payload.request_id) {
                Some(PendingOutcome::Approved { token }) => ok_resp(
                    serde_json::json!({"status": "approved", "token": token}).to_string(),
                    None,
                ),
                Some(PendingOutcome::Denied) => {
                    ok_resp(serde_json::json!({"status": "denied"}).to_string(), None)
                }
                Some(PendingOutcome::TimedOut) | None => {
                    ok_resp(serde_json::json!({"status": "unknown"}).to_string(), None)
                }
            }
        }
        "agents.pending" => {
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let pending: Vec<serde_json::Value> = host
                .pending_requests()
                .list()
                .into_iter()
                .filter(|p| p.vault_slug.as_deref().map_or(true, |s| s == slug))
                .map(|p| {
                    serde_json::json!({
                        "request_id": p.request_id,
                        "vault_slug": p.vault_slug,
                        "claimed_name": p.claimed_name,
                        "exe_path": p.peer.exe_path,
                        "pid": p.peer.pid,
                        "need": p.need,
                        "item_ids": p.item_ids,
                    })
                })
                .collect();
            ok_resp(serde_json::json!({"pending": pending}).to_string(), None)
        }
        "agents.approve" => {
            let payload: RequestIdPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent approval: {e}")),
            };
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            if !state.is_unlocked().await {
                return err_response(format!("Vault '{slug}' is locked"));
            }
            let Some(pending) = host.pending_requests().get(&payload.request_id) else {
                return err_response("agent request is no longer pending");
            };
            if pending.vault_slug.as_deref().is_some_and(|s| s != slug) {
                return err_response("agent request belongs to a different vault");
            }
            let Some(pending) = host.pending_requests().take(&payload.request_id) else {
                return err_response("agent request is no longer pending");
            };
            let audit_pending = pending.clone();
            let token = state.agent_mint(pending.peer, pending.item_ids, DEFAULT_TTL_SECS);
            if let Err(error) = audit(
                "approved",
                audit_pending.vault_slug.as_deref().unwrap_or(&slug),
                &audit_pending.peer,
                Some(&payload.request_id),
                &audit_pending.item_ids,
                "approved",
            ) {
                state.revoke_agent_token(&token);
                return err_response(format!("agent audit failed: {error}"));
            }
            host.pending_requests()
                .complete_approved(&payload.request_id, token);
            ok_resp(serde_json::json!({"approved": true}).to_string(), None)
        }
        "agents.deny" => {
            let payload: RequestIdPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent denial: {e}")),
            };
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let pending = host.pending_requests().get(&payload.request_id);
            // Deny must respect the same vault boundary as approve: a
            // request pinned to another vault is not deniable from here.
            if pending
                .as_ref()
                .and_then(|p| p.vault_slug.as_deref())
                .is_some_and(|s| s != slug)
            {
                return err_response("agent request belongs to a different vault");
            }
            if !host.pending_requests().deny(&payload.request_id) {
                return err_response("agent request is no longer pending");
            }
            host.pending_requests().complete_denied(&payload.request_id);
            if let Some(pending) = pending {
                audit_best_effort(
                    "denied",
                    pending.vault_slug.as_deref().unwrap_or(""),
                    &pending.peer,
                    Some(&payload.request_id),
                    &pending.item_ids,
                    "denied",
                );
            }
            ok_resp(serde_json::json!({"denied": true}).to_string(), None)
        }
        "agents.revoke" => {
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            state.revoke_agent_grants();
            let audit_peer = peer.cloned().unwrap_or_else(|| PeerBinding {
                pid: 0,
                exe_path: "<unresolved local client>".into(),
                start_ticks: 0,
            });
            audit_best_effort("revoked", &slug, &audit_peer, None, &[], "revoked-all");
            ok_resp(serde_json::json!({"revoked": true}).to_string(), None)
        }
        "agents.audit" => {
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let events = match crate::agent_audit::read_events(&baluard_core::paths::data_dir()) {
                Ok(events) => events,
                Err(e) => return err_response(format!("agent audit: {e}")),
            };
            // The audit store is global across vaults; a vault-scoped
            // viewer sees only its own history.
            let events: Vec<_> = events.into_iter().filter(|e| e.vault == slug).collect();
            let start = events.len().saturating_sub(100);
            ok_resp(
                serde_json::json!({"events": &events[start..]}).to_string(),
                None,
            )
        }
        "agents.list" => {
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let grants: Vec<serde_json::Value> = state
                .agent_live_grants()
                .into_iter()
                .map(|g| {
                    serde_json::json!({
                        "exe_path": g.peer.exe_path,
                        "pid": g.peer.pid,
                        "item_ids": g.item_ids,
                        "expires_at_ms": g.expires_at_ms,
                    })
                })
                .collect();
            ok_resp(
                serde_json::json!({"grants": grants, "yolo": yolo_enabled(&slug)}).to_string(),
                None,
            )
        }
        "agents.run" => crate::agent_run::run(req, host, peer).await,
        "agents.set_yolo" => {
            let payload: serde_json::Value = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent setting: {e}")),
            };
            let enabled = payload["enabled"].as_bool().unwrap_or(false);
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            if enabled {
                let Some(password) = payload["master_password"].as_str() else {
                    return err_response(
                        "Master password required to allow agent access without prompts",
                    );
                };
                if let Err(e) = crate::handler::verify_seal_change_password(&state, password).await
                {
                    return err_response(e);
                }
            }
            let audit_peer = peer.cloned().unwrap_or_else(|| PeerBinding {
                pid: 0,
                exe_path: "<unresolved local client>".into(),
                start_ticks: 0,
            });
            if let Err(error) = audit(
                if enabled {
                    "yolo_enabled"
                } else {
                    "yolo_disabled"
                },
                &slug,
                &audit_peer,
                None,
                &[],
                "saved",
            ) {
                return err_response(format!("agent audit failed: {error}"));
            }
            if let Err(e) = write_yolo(&slug, enabled) {
                return err_response(e);
            }
            ok_resp(serde_json::json!({"enabled": enabled}).to_string(), None)
        }
        "agents.revoke_own" => {
            let (_slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if state.verify_agent_token(&req.session_token).is_err() {
                return err_response("agent grant is missing, expired, or revoked");
            }
            state.revoke_agent_token(&req.session_token);
            ok_resp(serde_json::json!({"revoked": true}).to_string(), None)
        }
        _ => err_response(format!("Unknown action: {}", req.action)),
    }
}

// D80: permissive mode is a device-local policy file, never vault settings
// and therefore never git-synced to another machine.
fn yolo_path() -> std::path::PathBuf {
    baluard_core::paths::data_dir().join("agent-yolo.json")
}

fn yolo_enabled(slug: &str) -> bool {
    std::fs::read_to_string(yolo_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| value.get(slug).and_then(serde_json::Value::as_bool))
        == Some(true)
}

fn write_yolo(slug: &str, enabled: bool) -> Result<(), String> {
    let path = yolo_path();
    let mut value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !value.is_object() {
        value = serde_json::json!({});
    }
    value[slug] = serde_json::Value::Bool(enabled);
    let parent = path
        .parent()
        .ok_or("agent setting has no parent directory")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create agent setting directory: {e}"))?;
    let tmp = path.with_extension(format!("json.tmp.{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, value.to_string()).map_err(|e| format!("write agent setting: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("secure agent setting: {e}"))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("commit agent setting: {e}"))
}
