//! D80 agent approval routes. Secret delivery is deliberately not here yet:
//! this module owns requests, human decisions, grant lifecycle, and polling.

use crate::agent_run::process_chain;
use crate::handler::{err_response, ok_resp};
use crate::host::{SharedVaultHost, SnapshotError};
use crate::proto::{GatewayRequest, GatewayResponse};
use crate::state::SharedVaultState;
use baluard_runtime::agents::{DEFAULT_TTL_SECS, PeerBinding, PendingOutcome, pid_in_process_tree};

/// Typed policy payloads (BL0010): the master password rides a Zeroizing
/// field so no serde_json::Value tree retains a plaintext copy.
#[derive(serde::Deserialize)]
struct YoloPayload {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    master_password: Option<zeroize::Zeroizing<String>>,
    #[serde(default)]
    duration_secs: Option<u64>,
    #[serde(default)]
    indefinite: Option<bool>,
}

#[derive(serde::Deserialize)]
struct AgentPolicyPayload {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    auto_approve: Option<bool>,
    #[serde(default)]
    master_password: Option<zeroize::Zeroizing<String>>,
}

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
    #[serde(default)]
    wait_for_unlock: bool,
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
            if !check_agent_request_rate(peer) {
                return err_response("agent request rate limit exceeded");
            }
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
                if !payload.wait_for_unlock {
                    return err_response(format!("Vault '{slug}' is locked"));
                }
                let audit_slug = slug.clone();
                let audit_item_ids = payload.item_ids.clone();
                return match host.pending_requests().push(
                    Some(slug),
                    peer.clone(),
                    payload.claimed_name,
                    payload.need,
                    payload.item_ids,
                    baluard_runtime::agents::PendingPurpose::Credential,
                ) {
                    Ok(request_id) => {
                        audit_best_effort(
                            "requested_locked",
                            &audit_slug,
                            peer,
                            Some(&request_id),
                            &audit_item_ids,
                            "locked_pending",
                        );
                        ok_resp(
                            serde_json::json!({
                                "request_id": request_id,
                                "status": "locked_pending",
                            })
                            .to_string(),
                            None,
                        )
                    }
                    Err(_) => err_response("agent approval queue is full"),
                };
            }
            // Refuse SSH/signing key items at request time so the user never
            // approves a grant whose run must fail.
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
                    if matches!(kind.as_str(), "ssh_key" | "signing_key") {
                        return err_response("agents may not read SSH or signing key items");
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
                baluard_runtime::agents::PendingPurpose::Credential,
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
            let Some(peer) = peer else {
                return err_response("agent peer identity is unavailable");
            };
            let Some(chain) = process_chain(peer.pid) else {
                return err_response("agent process tree is unavailable");
            };
            // BL0014 / BL0027: a request and its outcome belong to the process
            // tree that made the request; foreign peers see the same "unknown"
            // status as a missing id, and outcome check+take is atomic under one lock.
            if let Some(pending) = host.pending_requests().get(&payload.request_id) {
                if !pid_in_process_tree(&pending.peer, &chain) {
                    return ok_resp(serde_json::json!({"status": "unknown"}).to_string(), None);
                }
                return ok_resp(serde_json::json!({"status": "pending"}).to_string(), None);
            }
            match host
                .pending_requests()
                .take_outcome_if(&payload.request_id, |owner| {
                    pid_in_process_tree(owner, &chain)
                }) {
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
        "agents.pending_summary" => {
            let pending = host.pending_requests().list();
            let first = pending.first().map(|p| {
                serde_json::json!({
                    "claimed_name": p.claimed_name,
                    "need": p.need,
                    "vault_slug": p.vault_slug,
                })
            });
            ok_resp(
                serde_json::json!({
                    "count": pending.len(),
                    "first": first,
                })
                .to_string(),
                None,
            )
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
                .filter(|p| p.vault_slug.as_deref().is_none_or(|s| s == slug))
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
            // A credential request mints a grant token; an SSH sign
            // request only releases the sign. Minting a grant for a
            // sign would leave a live, unreachable grant behind that
            // also suppresses blur-locking for the vault.
            let token =
                if audit_pending.purpose == baluard_runtime::agents::PendingPurpose::Credential {
                    state.agent_mint(
                        audit_pending.peer.clone(),
                        audit_pending.item_ids.clone(),
                        DEFAULT_TTL_SECS,
                    )
                } else {
                    String::new()
                };
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
            host.pending_requests().complete_approved(
                &payload.request_id,
                token,
                audit_pending.peer.clone(),
            );
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
            host.pending_requests().complete_denied(
                &payload.request_id,
                pending.as_ref().map(|p| p.peer.clone()),
            );
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
        "agents.run_start" => crate::agent_run::run_start(req, host, peer).await,
        "agents.run_poll" => crate::agent_run::run_poll(req, host, peer).await,
        "agents.run_signal" => crate::agent_run::run_signal(req, host, peer).await,
        "agents.inject" => crate::agent_run::inject(req, host, peer).await,
        "agents.set_yolo" => {
            let payload: YoloPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent setting: {e}")),
            };
            let enabled = payload.enabled.unwrap_or(false);
            let indefinite = payload.indefinite.unwrap_or(false);
            if indefinite && payload.duration_secs.is_some() {
                return err_response("indefinite and duration_secs are mutually exclusive");
            }
            let expires_at = if !enabled || indefinite {
                None
            } else {
                let ttl = payload
                    .duration_secs
                    .unwrap_or(DEFAULT_AUTO_APPROVE_TTL_SECS);
                if ttl == 0 {
                    return err_response("duration_secs must be positive");
                }
                Some(now_unix_secs().saturating_add(ttl))
            };
            let (slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            if enabled {
                let Some(password) = payload.master_password.as_deref() else {
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
            // Fail-closed like the agent socket's "no audit record, no
            // request": the attempt is recorded before the write, then
            // the outcome rides best-effort so a store hiccup cannot
            // strand a live change without any audit line.
            let event = if enabled {
                "yolo_enabled"
            } else {
                "yolo_disabled"
            };
            if let Err(error) = audit(event, &slug, &audit_peer, None, &[], "requested") {
                return err_response(format!("agent audit failed: {error}"));
            }
            if let Err(e) = write_yolo(&slug, enabled, expires_at) {
                let _ = audit(event, &slug, &audit_peer, None, &[], "failed");
                return err_response(e);
            }
            let _ = audit(event, &slug, &audit_peer, None, &[], "saved");
            ok_resp(
                serde_json::json!({
                    "enabled": enabled,
                    "expires_at": expires_at,
                    "indefinite": enabled && expires_at.is_none(),
                })
                .to_string(),
                None,
            )
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
        "agent.policy.get" => {
            // Device-local policy: two booleans, no vault data.
            let policy = crate::ssh_agent_policy::load();
            ok_resp(
                serde_json::json!({
                    "enabled": policy.enabled,
                    "auto_approve": policy.auto_approve,
                })
                .to_string(),
                None,
            )
        }
        "agent.policy.set" => {
            let payload: AgentPolicyPayload = match serde_json::from_str(&req.payload) {
                Ok(p) => p,
                Err(e) => return err_response(format!("Invalid agent policy: {e}")),
            };
            let (_slug, state) = match target_state(req, host, None).await {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            if let Err(resp) = verify_user(req, &state).await {
                return resp;
            }
            let current = crate::ssh_agent_policy::load();
            let enabled = payload.enabled.unwrap_or(current.enabled);
            // Turning the agent off always turns silent signing off with
            // it: a payload that only disables the agent must not
            // inherit a live auto_approve from the current policy and
            // then die on the guard below, which would leave the agent
            // impossible to switch off while auto-approve is on.
            let auto_approve =
                payload
                    .auto_approve
                    .unwrap_or(if enabled { current.auto_approve } else { false });
            if auto_approve && !enabled {
                return err_response(
                    "The SSH agent must be on before signings can be approved automatically",
                );
            }
            // Turning the agent on, or turning silent signing on, is a
            // security downgrade: it needs the master password, the same
            // way the permissive agent mode does.
            let turns_on = (enabled && !current.enabled) || (auto_approve && !current.auto_approve);
            if turns_on {
                let Some(password) = payload.master_password.as_deref() else {
                    return err_response(
                        "Master password required to turn on the SSH agent for this device",
                    );
                };
                if let Err(e) = crate::handler::verify_seal_change_password(&state, password).await
                {
                    return err_response(e);
                }
            }
            let next = crate::ssh_agent_policy::AgentPolicy {
                enabled,
                auto_approve,
            };
            let audit_peer = peer.cloned().unwrap_or_else(|| PeerBinding {
                pid: 0,
                exe_path: "<unresolved local client>".into(),
                start_ticks: 0,
            });
            let event = if next.enabled != current.enabled {
                if next.enabled {
                    "agent_policy_enabled"
                } else {
                    "agent_policy_disabled"
                }
            } else if next.auto_approve != current.auto_approve {
                if next.auto_approve {
                    "agent_policy_auto_approve_enabled"
                } else {
                    "agent_policy_auto_approve_disabled"
                }
            } else {
                "agent_policy_saved"
            };
            // Fail-closed: the attempt is recorded before the write,
            // then the outcome rides best-effort.
            if let Err(error) = audit(event, &_slug, &audit_peer, None, &[], "requested") {
                return err_response(format!("agent audit failed: {error}"));
            }
            if let Err(e) = crate::ssh_agent_policy::save(&next) {
                let _ = audit(event, &_slug, &audit_peer, None, &[], "failed");
                return err_response(e);
            }
            let _ = audit(event, &_slug, &audit_peer, None, &[], "saved");
            ok_resp(
                serde_json::json!({
                    "enabled": next.enabled,
                    "auto_approve": next.auto_approve,
                })
                .to_string(),
                None,
            )
        }
        _ => err_response(format!("Unknown action: {}", req.action)),
    }
}

// D80: permissive mode is a device-local policy file, never vault settings
// and therefore never git-synced to another machine.
const DEFAULT_AUTO_APPROVE_TTL_SECS: u64 = 300;

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn yolo_path() -> std::path::PathBuf {
    baluard_core::paths::data_dir().join("agent-yolo.json")
}

fn yolo_entry_active(entry: &serde_json::Value, now: u64) -> bool {
    if let Some(flag) = entry.as_bool() {
        return flag;
    }
    if entry.get("enabled").and_then(serde_json::Value::as_bool) != Some(true) {
        return false;
    }
    match entry.get("expires_at").and_then(serde_json::Value::as_u64) {
        Some(expires_at) => now < expires_at,
        None => true,
    }
}

fn yolo_enabled(slug: &str) -> bool {
    let Some(raw) = std::fs::read_to_string(yolo_path()).ok() else {
        return false;
    };
    let Some(value) = serde_json::from_str::<serde_json::Value>(&raw).ok() else {
        return false;
    };
    let Some(entry) = value.get(slug) else {
        return false;
    };
    yolo_entry_active(entry, now_unix_secs())
}

static YOLO_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
type AgentRateMap = std::collections::HashMap<(u32, u64), Vec<std::time::Instant>>;
static AGENT_REQUEST_RATE: std::sync::LazyLock<std::sync::Mutex<AgentRateMap>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const AGENT_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const AGENT_RATE_MAX_PER_WINDOW: usize = 10;

fn check_agent_request_rate(peer: &PeerBinding) -> bool {
    let Ok(mut map) = AGENT_REQUEST_RATE.lock() else {
        return true;
    };
    let now = std::time::Instant::now();
    let bucket = map.entry((peer.pid, peer.start_ticks)).or_default();
    bucket.retain(|ts| now.duration_since(*ts) < AGENT_RATE_WINDOW);
    if bucket.len() >= AGENT_RATE_MAX_PER_WINDOW {
        return false;
    }
    bucket.push(now);
    true
}

fn write_yolo(slug: &str, enabled: bool, expires_at: Option<u64>) -> Result<(), String> {
    // Read-modify-write of the whole map must not lose concurrent updates.
    let _lock = YOLO_WRITE_LOCK
        .lock()
        .map_err(|_| "agent setting lock poisoned".to_string())?;
    let path = yolo_path();
    let mut value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !value.is_object() {
        value = serde_json::json!({});
    }
    value[slug] = if enabled {
        serde_json::json!({
            "enabled": true,
            "expires_at": expires_at,
        })
    } else {
        serde_json::Value::Bool(false)
    };
    baluard_core::secret_file::write_secret_file(&path, value.to_string().as_bytes())
        .map_err(|e| format!("write agent setting: {e}"))
}
