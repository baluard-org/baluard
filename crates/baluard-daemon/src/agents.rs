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
            match host.pending_requests().push(
                Some(slug),
                peer.clone(),
                payload.claimed_name,
                payload.need,
                payload.item_ids,
            ) {
                Ok(request_id) => ok_resp(
                    serde_json::json!({"request_id": request_id, "status": "pending"}).to_string(),
                    None,
                ),
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
            let (_slug, state) = match target_state(req, host, None).await {
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
            let token = state.agent_mint(pending.peer, pending.item_ids, DEFAULT_TTL_SECS);
            host.pending_requests()
                .complete_approved(&payload.request_id, token);
            ok_resp(serde_json::json!({"approved": true}).to_string(), None)
        }
        "agents.deny" => {
            let payload: RequestIdPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent denial: {e}")),
            };
            let (_slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            if !host.pending_requests().deny(&payload.request_id) {
                return err_response("agent request is no longer pending");
            }
            host.pending_requests().complete_denied(&payload.request_id);
            ok_resp(serde_json::json!({"denied": true}).to_string(), None)
        }
        "agents.revoke" => {
            let (_slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            state.revoke_agent_grants();
            ok_resp(serde_json::json!({"revoked": true}).to_string(), None)
        }
        "agents.list" => {
            let (_slug, state) = match target_state(req, host, None).await {
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
            ok_resp(serde_json::json!({"grants": grants}).to_string(), None)
        }
        "agents.run" => crate::agent_run::run(req, host, peer).await,
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
