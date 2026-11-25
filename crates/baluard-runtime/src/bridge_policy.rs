//! Bridge routing policy, extracted from `baluard-daemon/src/handler.rs`
//! (ADR 0114 work item 0).
//!
//! Every gate a browser-extension request passes — allowlist membership,
//! read caps, Decision 7 write fences, slug scoping, origin binding, fill
//! shaping — lives HERE, transport-neutral: the policy routes through
//! [`BridgeDispatcher`], implemented by the daemon (socket path) and by
//! mobile (UniFFI ops). The runtime bridge registry
//! ([`crate::bridge::BridgeRegistry`]) holds the tokens and caps this
//! module charges.

use baluard_core::bridge::PairingId;
use baluard_proto::{GatewayRequest, GatewayResponse};
use zeroize::Zeroize;

use crate::host::SharedVaultHost;
use crate::state::SharedVaultState;

// ---------------------------------------------------------------------------
// Response builders (mirror the daemon's ok_resp / err_response).

fn ok_resp(payload: impl Into<String>, token: Option<&str>) -> GatewayResponse {
    GatewayResponse {
        success: true,
        error_message: String::new(),
        payload: payload.into(),
        session_token: token.unwrap_or("").to_string(),
        ipc_version: baluard_core::IPC_PROTOCOL_VERSION,
        ipc_min_version: baluard_core::IPC_PROTOCOL_MIN,
        ipc_max_version: baluard_core::IPC_PROTOCOL_MAX,
    }
}

fn err_response(msg: impl Into<String>) -> GatewayResponse {
    GatewayResponse {
        success: false,
        error_message: msg.into(),
        payload: String::new(),
        session_token: String::new(),
        ipc_version: baluard_core::IPC_PROTOCOL_VERSION,
        ipc_min_version: baluard_core::IPC_PROTOCOL_MIN,
        ipc_max_version: baluard_core::IPC_PROTOCOL_MAX,
    }
}

// ---------------------------------------------------------------------------
// Transport-neutral dispatch.

/// The per-vault dispatcher behind the bridge policy: given a request whose
/// `session_token` has already been stamped for the target vault, execute it
/// against that vault and return the IPC-shaped response.
///
/// The daemon implements this by delegating to its full action router
/// (`route_request`); mobile implements it by mapping the allowlisted
/// actions onto its in-process `VaultState` UniFFI ops. Implementers MUST
/// keep the response shape identical across transports — the browser
/// extension parses it without knowing which one answered.
pub trait BridgeDispatcher: Sync {
    fn dispatch(
        &self,
        req: GatewayRequest,
        state: &SharedVaultState,
    ) -> impl std::future::Future<Output = GatewayResponse> + Send;
}

// ---------------------------------------------------------------------------
// Merge fan-out (shared by bridge.match, passkey.list, and vault.search).

pub struct MergeFanoutRow {
    pub meta: serde_json::Value,
    pub eligible: bool,
    pub state: Option<SharedVaultState>,
}

pub async fn merge_fanout_rows(host: &SharedVaultHost) -> Vec<MergeFanoutRow> {
    let registry = baluard_core::vault::registry::VaultRegistry::load_locked().ok();
    let rows = host.list().await;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let eligible = registry
            .as_ref()
            .map(|r| r.merge_eligible(&row.slug))
            .unwrap_or(false);
        let state = if eligible && row.presence == "unlocked" {
            host.get(&row.slug).await
        } else {
            None
        };
        // Only locked Spaces can carry a removal notice - an unlocked one
        // has already been pulled past it (sync-lag boundary, plan section 5).
        let removed = row.presence != "unlocked"
            && row.space
            && registry
                .as_ref()
                .and_then(|r| r.get(&row.slug))
                .map(|entry| vault_removal_notice(&entry.path))
                .unwrap_or(false);
        out.push(MergeFanoutRow {
            meta: serde_json::json!({
                "slug": row.slug,
                "display_name": row.display_name,
                "space": row.space,
                "active": row.active,
                "presence": row.presence,
                "removed": removed,
            }),
            eligible,
            state,
        });
    }
    out
}

/// Removal notice probe: a removed member's marker file in the vault.
/// Fails open to false so a missing or damaged marker never lies.
fn vault_removal_notice(vault_path: &std::path::Path) -> bool {
    use baluard_core::vault::members::{member_file_by_id, member_id_for_device};
    let Ok(raw) = std::fs::read_to_string(vault_path.join("meta/device-id")) else {
        return false;
    };
    let Ok(device_id) = uuid::Uuid::parse_str(raw.trim()) else {
        return false;
    };
    let Some(member_id) = member_id_for_device(vault_path, device_id) else {
        return false;
    };
    member_file_by_id(vault_path, member_id)
        .map(|row| row.removed.is_some())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Policy classification + gates.

/// Where an allowlisted bridge action's `vault_slug` may target a sibling
/// vault. Reads REQUIRE the page URL for origin binding; provider passkey
/// ceremonies are exempt because the origin and the credential id are
/// validated Rust-side against the target vault's index; writes carry no
/// page URL — the C21 preservation gate re-checks the target vault after
/// the rebind (ADR 0098).
pub enum SlugScope {
    Read,
    Write,
    Passkey,
    None,
}

pub fn slug_scope_kind(action: &str) -> SlugScope {
    match action {
        "vault.get" | "cipher.totp_code" => SlugScope::Read,
        "vault.add" | "vault.update" => SlugScope::Write,
        "passkey.provider_register"
        | "passkey.provider_assert"
        | "passkey.store_registered"
        | "passkey.consume_assertion"
        | "passkey.verify" => SlugScope::Passkey,
        _ => SlugScope::None,
    }
}

/// D21: bridge actions that MUTATE vault data ride the desktop session's
/// write scope — a Viewer or half-joined member must not mint entries or
/// bump counters from the extension. Ceremony creation signs but does not
/// mutate, so it stays ungated.
pub fn bridge_write_gated(action: &str) -> bool {
    matches!(
        action,
        "vault.add" | "vault.update" | "passkey.store_registered" | "passkey.consume_assertion"
    )
}

// ---------------------------------------------------------------------------
// Bridge route.

/// Full bridge request policy + dispatch. Behavior-identical to the former
/// daemon `route_bridge_request`; the only structural change is that the
/// final per-vault execution goes through the [`BridgeDispatcher`].
pub async fn route_bridge_request<D: BridgeDispatcher>(
    req: GatewayRequest,
    host: &SharedVaultHost,
    pairing_id: PairingId,
    dispatcher: &D,
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

    // 2. Rate-cap secret reads and assertion minting. `vault.get` returns
    //    plaintext credentials and `passkey.provider_assert` mints WebAuthn
    //    signatures on demand; both are useful to a compromised browser
    //    context, so both are capped to bound the damage. `passkey.verify`
    //    turns the bridge into a master-password oracle, so it rides the
    //    same cap: guess-spam burns and revokes the pairing.
    //    `bridge.match` returns metadata only (no passwords), so it is NOT
    //    capped — the toolbar badge legitimately calls it on every tab
    //    activate/update, and capping it would auto-revoke the pairing
    //    under normal browsing.
    let is_capped = matches!(
        req.action.as_str(),
        "vault.get" | "passkey.provider_assert" | "passkey.verify"
    );
    if is_capped {
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

    // 3. vault.update/add field gate: Decision 7 allowlist. H1 (D81
    //    review): the old denylist admitted every field a future cipher
    //    type adds, so a SigningKey private key would have crossed.
    if matches!(req.action.as_str(), "vault.update" | "vault.add") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.payload) {
            let is_add = req.action.as_str() == "vault.add";
            if let Some(reason) = bridge_write_outside_decision_seven(&v, is_add) {
                log::warn!("[daemon] bridge token denied a write outside Decision 7");
                return err_response(reason);
            }
        }
    }

    // 3d. G24 §4.7 v2: the extension asks the desktop to unlock a vault.
    //     Works pre-unlock by design; the desktop polls, shows the ask, and
    //     the user's approval IS the unlock (no unlock route ever accepts a
    //     master password from the extension). Only merge-eligible vaults
    //     may be requested; a newer request supersedes.
    if req.action.as_str() == "bridge.request_unlock" {
        let slug = serde_json::from_str::<serde_json::Value>(&req.payload)
            .ok()
            .and_then(|v| v.get("slug").and_then(|x| x.as_str()).map(String::from))
            .unwrap_or_default();
        if slug.is_empty() {
            return err_response("bridge.request_unlock requires a slug");
        }
        let eligible = baluard_core::vault::registry::VaultRegistry::load_locked()
            .ok()
            .map(|r| r.merge_eligible(&slug))
            .unwrap_or(false);
        if !eligible {
            return err_response("vault not available for bridge access");
        }
        host.bridge().write().await.request_unlock(slug);
        return ok_resp("{}", None);
    }

    // 4. Snapshot the ACTIVE vault (bridge tokens are slug-agnostic).
    let snapshot = match host.snapshot_target(None).await {
        Ok(pair) => pair,
        Err(_) => return err_response("locked"),
    };
    let mut state: SharedVaultState = snapshot.1.clone();
    let active_slug = snapshot.0.clone();

    // 4b. G24 §4.4 slug-scoped targeting: some actions may name a sibling
    //     vault. The target resolves BEFORE any per-vault gate so the
    //     origin binding and the delegated token bind the right vault, not
    //     the active one. The slug must be merge-eligible and unlocked;
    //     anything else fails closed exactly like an unknown vault.
    let scope = slug_scope_kind(&req.action);
    if !matches!(scope, SlugScope::None) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.payload) {
            if let Some(slug) = v.get("vault_slug").and_then(|x| x.as_str()) {
                if !slug.is_empty() && slug != active_slug {
                    // A slug-scoped READ targets a foreign vault, so it
                    // MUST carry the page URL: without it the origin
                    // binding below would be skipped and any UUID from
                    // any enabled vault would be readable (plan §4.4).
                    // Provider passkey ceremonies pin to the vault that
                    // holds the chosen credential; the origin and the
                    // credential id are validated Rust-side against that
                    // vault's index, so no URL binding is needed.
                    let has_url = v
                        .get("url")
                        .and_then(|x| x.as_str())
                        .map(|u| !u.is_empty())
                        .unwrap_or(false);
                    if matches!(scope, SlugScope::Read) && !has_url {
                        return err_response("slug-scoped bridge reads require a page URL");
                    }
                    let eligible = baluard_core::vault::registry::VaultRegistry::load_locked()
                        .ok()
                        .map(|r| r.merge_eligible(slug))
                        .unwrap_or(false);
                    let target = if eligible { host.get(slug).await } else { None };
                    match target {
                        Some(t) if t.is_unlocked().await => state = t,
                        Some(_) => return err_response("vault is locked"),
                        None => return err_response("vault not available for bridge reads"),
                    }
                }
            }
        }
    }

    // 5. Gate. Most actions demand the ACTIVE vault unlocked. The
    //    merged read (bridge.match) passes when ANY merge-eligible
    //    vault is unlocked (G24 §4.3): a sleeping personal vault must
    //    not blank autofill while a family Space is open.
    if req.action.as_str() == "bridge.match" {
        let any_unlocked = merge_fanout_rows(host)
            .await
            .iter()
            .any(|r| r.state.is_some());
        if !any_unlocked {
            return err_response("locked");
        }
    } else if req.action.as_str() == "passkey.list" && !state.is_unlocked().await {
        // Passkey listing fans out over merge-eligible vaults like
        // bridge.match: any unlocked vault contributes rows.
        let any_unlocked = merge_fanout_rows(host)
            .await
            .iter()
            .any(|r| r.state.is_some());
        if !any_unlocked {
            return err_response("locked");
        }
    } else if !state.is_unlocked().await {
        return err_response("locked");
    }

    // Contact-view fence: the mobile dispatcher has no route_request-level
    // contact gate, so the bridge policy applies the same default-deny
    // here. On the bridge allowlist a contact view may only read.
    if state.is_contact_view() && !matches!(req.action.as_str(), "vault.get" | "cipher.totp_code") {
        return err_response("This is a read-only view of the vault.");
    }

    // 5b. D21 read scope: every browser-visible vault mutation rides the
    //     desktop session's write scope. On a shared vault a Viewer (or a
    //     half-finished join) must not mint entries — or bump passkey
    //     counters — that their own device could never push; refuse here,
    //     where the extension can show it.
    if bridge_write_gated(&req.action) {
        if let Err(reason) = state.bridge_write_allowed().await {
            log::warn!("[daemon] bridge {} refused: {reason}", req.action);
            return err_response(reason);
        }
    }

    // 3b. C21: vault.update omission gate. The generic update path replaces
    //     the whole `kind` when the payload carries one (serde defaults
    //     absorb absent fields), so a bridge payload omitting
    //     fido2_credentials/uris on a cipher that HAS them would silently
    //     delete them. Read-only internal fetch, exempt from the bridge
    //     read cap (integrity check, not a secret exfil path).
    if req.action.as_str() == "vault.update" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.payload) {
            if let Err(reason) = bridge_update_preserves_protected(&state, &v).await {
                log::warn!("[daemon] bridge vault.update denied: {reason}");
                return err_response(reason);
            }
        }
    }

    // 3c. B3: server-side origin binding for bridge secret reads that carry
    //     a page URL (the inline-fill flow includes it). The hostname
    //     matcher is the SAME one bridge.match uses, so a credential stored
    //     for one site cannot be fetched for a lookalike/downgraded page.
    //     Requests without a URL (popup, extension-owned UI) are allowed;
    //     URI-less ciphers stay fillable from the popup (user picked them)
    //     and are logged.
    if req.action.as_str() == "vault.get" || req.action.as_str() == "cipher.totp_code" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.payload) {
            if let Some(url) = v.get("url").and_then(|x| x.as_str()) {
                if !url.is_empty() {
                    let action = req.action.clone();
                    if let Err(reason) = bridge_read_matches_page(&state, &v, url).await {
                        log::warn!("[daemon] bridge {action} denied: {reason}");
                        return err_response(format!("bridge read refused: {reason}"));
                    }
                }
            }
        }
    }

    // Resolve the active vault's display name for the popup header (review I8:
    // silent cross-vault hazard; the extension must show WHERE a capture/fill
    // lands). Best-effort: registry lookup, fall back to the slug.
    let vault_name = baluard_core::vault::registry::VaultRegistry::load_locked()
        .ok()
        .and_then(|r| r.get(&active_slug).map(|e| e.display_name.clone()))
        .unwrap_or_else(|| active_slug.clone());

    // 6. Dispatch the allowlisted action. bridge.match / bridge.config are
    //    NEW routes; the rest reuse the per-vault dispatcher by stamping
    //    the vault's own token (the request was already allowlisted
    //    + field-gated + rate-capped, so delegating is safe).
    let delegated = {
        let mut d = req.clone();
        let tok = state.get_session_token().await.unwrap_or_default();
        d.session_token = tok;
        d
    };
    match req.action.as_str() {
        "bridge.match" => handle_bridge_match(req, host, &vault_name).await,
        "bridge.config" => handle_bridge_config(&state).await,
        "passkey.list" => handle_bridge_passkey_list(req, host, &active_slug).await,
        // B10 + H1 (Decision 7 minimalism): a bridge read returns only the
        // fill fields and only for Login entries; notes, history, custom
        // fields, the totp seed, passkeys, and every other cipher kind
        // stay behind the desktop.
        "vault.get" => {
            let mut resp = dispatcher.dispatch(delegated, &state).await;
            if resp.success {
                match bridge_fill_response(&resp.payload) {
                    Ok(payload) => resp.payload = payload,
                    Err(msg) => return err_response(msg),
                }
            }
            // The vault's own session token never leaves the policy; the
            // extension refreshes its BRIDGE token via reauth, not this.
            resp.session_token.clear();
            resp
        }
        // vault.add / vault.update / cipher.totp_code /
        // generator.* / sync.autosync_status all reuse the normal path.
        _ => {
            let mut resp = dispatcher.dispatch(delegated, &state).await;
            resp.session_token.clear();
            resp
        }
    }
}

// ---------------------------------------------------------------------------
// Payload unpackers for the browser WebAuthn provider routes. The state
// layer takes discrete args (UniFFI shape); the IPC surface is flat JSON.
// `new_login` accepts an object or a pre-serialized string so the
// extension never juggles double-encoded JSON.

pub type ProviderRegisterArgs = (String, String, Option<String>, Option<String>, bool);

pub fn provider_register_args(payload: &str) -> Result<ProviderRegisterArgs, String> {
    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "Invalid JSON".to_string())?;
    let request_json = v
        .get("request_json")
        .and_then(|x| x.as_str())
        .ok_or("Missing 'request_json'")?
        .to_string();
    let origin = v
        .get("origin")
        .and_then(|x| x.as_str())
        .ok_or("Missing 'origin'")?
        .to_string();
    let str_field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    Ok((
        request_json,
        origin,
        str_field("client_data_json_b64"),
        str_field("client_data_hash_b64"),
        v.get("user_verified")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
    ))
}

pub type ProviderAssertArgs = (String, String, String, Option<String>, Option<String>, bool);

pub fn provider_assert_args(payload: &str) -> Result<ProviderAssertArgs, String> {
    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "Invalid JSON".to_string())?;
    let credential_id = v
        .get("credential_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("Missing 'credential_id'")?
        .to_string();
    let (request_json, origin, cdj, cdh, uv) = provider_register_args(payload)?;
    Ok((request_json, origin, credential_id, cdj, cdh, uv))
}

pub fn store_registered_args(
    payload: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "Invalid JSON".to_string())?;
    let ceremony_id = v
        .get("ceremony_id")
        .and_then(|x| x.as_str())
        .ok_or("Missing 'ceremony_id'")?
        .to_string();
    let cipher_id = v
        .get("cipher_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let new_login = match v.get("new_login") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(x @ serde_json::Value::Object(_)) => Some(x.to_string()),
        _ => None,
    };
    Ok((ceremony_id, cipher_id, new_login))
}

// ---------------------------------------------------------------------------
// Decision 7 fill shaping + C21/C21v2/B3 gates.

/// Decision 7: a bridge vault.get returns the fill fields only, and only
/// for Login entries. Built as an allowlist: a denylist silently leaks
/// every field a future cipher type adds (the D81 review's H1 — a
/// SigningKey private key would have ridden the same path as an SshKey
/// private key already does). The extension consumes username, password,
/// and a totp presence flag; the derived code rides cipher.totp_code.
pub fn bridge_fill_response(payload: &str) -> Result<String, String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
        // An allowlist fails closed: an unparseable success payload is not
        // the fill pair, so it does not cross.
        return Err("bridge read returned an unexpected payload".into());
    };
    let kind_type = v
        .get("kind")
        .and_then(|k| k.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    if kind_type != "login" {
        return Err("bridge reads support logins only".into());
    }
    let data = v.get("kind").and_then(|k| k.get("data"));
    // Flat fields first (the daemon wire format flattens username and
    // password), then the nested kind.data copy for anything only the
    // nested shape carries.
    let field = |name: &str| {
        v.get(name)
            .or_else(|| data.and_then(|d| d.get(name)))
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let totp_present = match v.get("totp") {
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Bool(b)) => *b,
        // An empty or cleared seed is "no TOTP", not "has TOTP".
        _ => data
            .and_then(|d| d.get("totp_uri"))
            .and_then(|t| t.as_str())
            .is_some_and(|s| !s.is_empty()),
    };
    let out = serde_json::json!({
        "id": field("id"),
        "name": field("name"),
        "type": "login",
        "username": field("username"),
        "password": field("password"),
        "totp": totp_present,
    });
    Ok(out.to_string())
}

/// C21: does the incoming kind omit, shrink, or CHANGE a protected list
/// (uris, fido2_credentials) relative to the existing cipher? The update
/// path replaces the whole `kind`, so an omission deletes and a content
/// change rewrites the URI matching the browser is trusted against.
/// CipherKind serializes as {"type":"login","data":{...}}. Returns the
/// violation reason, or None when safe.
pub fn kind_omits_or_shrinks_protected(
    existing_kind: Option<&serde_json::Value>,
    incoming_kind: Option<&serde_json::Value>,
) -> Option<&'static str> {
    // No kind in the update payload: the generic PATCH path keeps the
    // existing kind — nothing protected can change.
    let incoming = incoming_kind?;
    let existing = existing_kind?;
    for field in ["fido2_credentials", "uris"] {
        let existing_list = existing
            .get("data")
            .and_then(|d| d.get(field))
            .and_then(|v| v.as_array());
        let Some(existing_list) = existing_list else {
            continue;
        };
        if existing_list.is_empty() {
            continue;
        }
        match incoming
            .get("data")
            .and_then(|d| d.get(field))
            .and_then(|v| v.as_array())
        {
            None => return Some("omission would delete it (send the full list or omit kind)"),
            Some(incoming_list) if incoming_list.len() < existing_list.len() => {
                return Some("list shrinks (deletion is not a bridge operation)");
            }
            // A resent list must be byte-equal: the fence permits resending
            // (C21 demands it on logins that have the list) but not
            // rewriting the URI matching the browser is trusted against.
            Some(incoming_list) if incoming_list != existing_list => {
                return Some("list content changed (resend it exactly as stored)");
            }
            _ => {}
        }
    }
    None
}

/// C21 async wrapper: fetch the existing cipher (read-only, does not charge
/// the bridge read cap) and compare protected lists against the payload.
pub async fn bridge_update_preserves_protected(
    state: &SharedVaultState,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let Some(id) = payload.get("id").and_then(|v| v.as_str()) else {
        // No id: the generic handler produces the proper error; nothing to
        // compare yet.
        return Ok(());
    };
    let existing_json = state.get_cipher(id, true).await?;
    let existing: serde_json::Value =
        serde_json::from_str(&existing_json).map_err(|e| format!("existing cipher parse: {e}"))?;
    let existing_kind = existing.get("kind");
    // The payload-level kind check cannot see the STORED kind: a payload
    // claiming login aimed at a card would otherwise replace the card
    // wholesale, because the update path replaces the whole kind.
    if existing_kind
        .and_then(|k| k.get("type"))
        .and_then(|t| t.as_str())
        .is_some_and(|t| t != "login")
    {
        return Err("bridge tokens may only edit logins, and that entry is not one".into());
    }
    let incoming_kind = payload.get("kind");
    match kind_omits_or_shrinks_protected(existing_kind, incoming_kind) {
        Some(reason) => Err(format!(
            "bridge tokens may not remove or change fido2_credentials or uris: {reason}"
        )),
        None => Ok(()),
    }
}

/// B3: verify the cipher requested by a bridge read matches the page URL
/// the client claims, using the same hostname matcher as bridge.match.
pub async fn bridge_read_matches_page(
    state: &SharedVaultState,
    payload: &serde_json::Value,
    url: &str,
) -> Result<(), String> {
    let Some(id) = payload.get("id").and_then(|v| v.as_str()) else {
        // Malformed id: the generic handler produces the proper error.
        return Ok(());
    };
    // G24 §4.3: ONE matcher everywhere. The read check rides the same
    // UriMatchStrategy evaluation (plus the vault's custom equivalent
    // domains) as bridge.match, so a suggested credential is exactly a
    // readable credential - never loosely accepted, never falsely
    // rejected on an equivalent domain.
    match state.cipher_matches_uri(id, url).await? {
        true => Ok(()),
        false => {
            let want = hostname_of(url);
            Err(format!("no stored URI matches {want}"))
        }
    }
}

pub fn bridge_write_outside_decision_seven(
    payload: &serde_json::Value,
    is_add: bool,
) -> Option<&'static str> {
    // An absent kind cannot prove the target is a Login, and a payload
    // that skips the kind block would skip the whole data fence with it.
    let kind_type = payload
        .get("kind")
        .and_then(|k| k.get("type"))
        .and_then(|t| t.as_str());
    if kind_type != Some("login") {
        return Some("bridge tokens may only create or edit logins");
    }
    // Root-level fields the data fence cannot see. Capture (vault.add)
    // may carry empty fixture lists but no content outside Decision 7;
    // edits (vault.update) replace whole root fields, so an update payload
    // may only name the entry identity, its scope, the kind block, and the
    // Decision 7 note field.
    let nonempty_list = |k: &str| {
        payload
            .get(k)
            .is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
    };
    if nonempty_list("custom_fields") {
        return Some("bridge tokens may not write custom fields");
    }
    if nonempty_list("password_history") {
        return Some("bridge tokens may not write password history");
    }
    if nonempty_list("attachments") {
        return Some("bridge tokens may not write attachments");
    }
    if !is_add {
        const UPDATE_ROOT: [&str; 5] = ["id", "vault_slug", "kind", "notes", "url"];
        if let Some(map) = payload.as_object() {
            for key in map.keys() {
                if !UPDATE_ROOT.contains(&key.as_str()) {
                    return Some("bridge tokens may not edit fields outside Decision 7");
                }
            }
        }
    }
    // Resolve the inner `data` block across the layouts the update handler
    // accepts: {kind:{type,data}}, {kind:{...fields}}, or {data:{...}}.
    let data = payload
        .get("kind")
        .and_then(|k| k.get("data"))
        .or_else(|| payload.get("data"))
        .or_else(|| payload.get("kind"));
    let data = data?;
    // Capture (vault.add) sends a full LoginData shape including the site
    // URI, so add admits every legitimate LoginData field. Edits
    // (vault.update) stay at Decision 7's strict set; uris and
    // fido2_credentials on an edit are not refused here but checked for
    // resend-equality against the stored lists by the C21 gate, because
    // C21 otherwise demands them be resent on logins that have them.
    // "type" is the discriminator of the bare-kind layout; its value was
    // already validated as login above.
    const ADD_WRITABLE: [&str; 8] = [
        "username",
        "password",
        "uris",
        "totp_uri",
        "autofill_on_page_load",
        "password_revision_date",
        "favicon",
        "type",
    ];
    const UPDATE_WRITABLE: [&str; 6] = [
        "username",
        "password",
        "totp_uri",
        "uris",
        "fido2_credentials",
        "type",
    ];
    let writable: &[&str] = if is_add {
        &ADD_WRITABLE
    } else {
        &UPDATE_WRITABLE
    };
    if let Some(map) = data.as_object() {
        for key in map.keys() {
            if !writable.contains(&key.as_str()) {
                return Some(
                    "bridge tokens may only modify username, password, notes, or the TOTP seed",
                );
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Post-mutation side effects (moved verbatim from the daemon's route_request
// tail so the mobile dispatcher schedules cover commits and sync nudges
// exactly like the socket path).

/// Tracked-file writes outside entries/: attachments live under
/// entries/<id>/attachments, a password change rewrites the shared
/// kek canary + keywrap, locale.save and space.set_purpose write
/// settings-pub.json. Without cover they wait for a later listed
/// mutation or a manual sync: the idle loop is pull-only, and a second
/// device would keep the old canary.
pub const COVER_MUTATION_ACTIONS: &[&str] = &[
    "vault.attach_upload",
    "vault.attach_delete",
    "vault.change_password",
    "legacy.arm",
    "legacy.close",
    "locale.save",
    "space.set_purpose",
    "space.migrate",
    "vault.add",
    "vault.update",
    "vault.delete",
    "vault.archive",
    "vault.unarchive",
    "cipher.clone",
    "packages.import",
    "vault.import",
    // Escrow swaps must reach the remote promptly: the ceremony tells the
    // user the old phrase is dead, which is only true once it syncs.
    "vault.rotate_recovery",
    "vault.trash.restore",
    "vault.trash.purge",
    "folder.create",
    "folder.rename",
    "folder.delete",
    "members.invite",
    "members.remove",
    "members.reset",
    "members.transfer",
    "members.claim",
    "members.set_email",
    "members.set_minor",
    "members.set_role",
    "members.leave",
    // members.leave_list is a read query: no cover commit, no nudge.
    "members.leave_approve",
    "members.contest_cancel",
];

/// Local device id for autosync nudges (thin wrapper over the core reader).
pub fn first_device_id(vault_path: &std::path::Path) -> String {
    baluard_core::vault::device_privkey::local_device_id(vault_path)
}

/// Schedule a cover commit + arm auto-sync after successful vault mutations.
pub async fn after_mutation(state: &SharedVaultState, action: &str, resp: &GatewayResponse) {
    if !(resp.success && COVER_MUTATION_ACTIONS.contains(&action)) {
        return;
    }
    state.schedule_cover_after_commit();
    let dn = first_device_id(&state.vault_path);
    state.autosync.nudge(dn).await;
    // S2 IS-4b live mirror: re-publish every outboxed entry from the
    // current cipher state (vault.delete/archive land as Locked and
    // unpublish). Best-effort: a mirror failure must never fail the
    // mutation the user just made.
    if let Err(e) = state.outbox_resync().await {
        log::warn!("[daemon] outbox mirror after {}: {e}", action);
    }
    // The resync writes the git-tracked outbox registry after the
    // first nudge; a second nudge guarantees a cycle commits it.
    let dn = first_device_id(&state.vault_path);
    state.autosync.nudge(dn).await;
}

// ---------------------------------------------------------------------------
// Mobile dispatcher: the second implementer of the bridge contract
// (ADR 0114 work item 0, review B1). Maps the eleven allowlisted actions that
// reach the dispatch step onto the same VaultState methods the daemon's
// socket router uses; the other four allowlisted actions (bridge.match,
// bridge.config, passkey.list, bridge.request_unlock) are intercepted by the
// policy above and never arrive here. The mobile host constructs a
// SharedVaultHost holding its VaultState and registers the vault in
// VaultRegistry as merge-eligible, so the fan-out routes resolve. Unlike the
// daemon, dispatch never refreshes the auto-lock timer (touch_activity): a
// phone that locks mid-browse is the safer default.

pub struct MobileDispatcher;

impl BridgeDispatcher for MobileDispatcher {
    async fn dispatch(&self, mut req: GatewayRequest, state: &SharedVaultState) -> GatewayResponse {
        let resp = self.dispatch_inner(&mut req, state).await;
        // Bridge payloads carry plaintext credentials (vault.add/update);
        // mirror the daemon router's exit zeroization.
        req.payload.zeroize();
        resp
    }
}

impl MobileDispatcher {
    async fn dispatch_inner(
        &self,
        req: &mut GatewayRequest,
        state: &SharedVaultState,
    ) -> GatewayResponse {
        match req.action.as_str() {
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
                    Ok(json) => ok_resp(json, None),
                    Err(e) => err_response(e),
                }
            }
            "vault.add" => {
                if req.payload.is_empty() {
                    return err_response("Missing cipher JSON in payload");
                }
                match state.add_cipher(&req.payload).await {
                    Ok(id) => ok_resp(id, None),
                    Err(e) => err_response(e),
                }
            }
            "vault.update" => {
                if req.payload.is_empty() {
                    return err_response("Missing update JSON in payload");
                }
                match state.update_cipher(&req.payload).await {
                    Ok(()) => ok_resp("updated", None),
                    Err(e) => err_response(e),
                }
            }
            "cipher.totp_code" => {
                if req.payload.is_empty() {
                    return err_response("Missing cipher UUID in payload");
                }
                // Wire shape is {id, url?, vault_slug?}; bare UUID kept for
                // parity with the daemon route.
                let id = serde_json::from_str::<serde_json::Value>(&req.payload)
                    .ok()
                    .and_then(|v| v["id"].as_str().map(str::to_string))
                    .unwrap_or_else(|| req.payload.clone());
                match state.totp_code(&id).await {
                    Ok(json) => ok_resp(json, None),
                    Err(e) => err_response(e),
                }
            }
            "generator.history_add" => match state.generator_history_add(&req.payload).await {
                Ok(json) => ok_resp(json, None),
                Err(e) => err_response(e),
            },
            "generator.history_clear" => match state.generator_history_clear().await {
                Ok(()) => ok_resp("{}", None),
                Err(e) => err_response(e),
            },
            "passkey.provider_register" => match provider_register_args(&req.payload) {
                Ok((request_json, origin, cdj, cdh, uv)) => {
                    match state
                        .passkey_provider_register(
                            &request_json,
                            &origin,
                            cdj.as_deref(),
                            cdh.as_deref(),
                            uv,
                        )
                        .await
                    {
                        Ok(json) => ok_resp(json, None),
                        Err(e) => err_response(e),
                    }
                }
                Err(e) => err_response(e),
            },
            "passkey.provider_assert" => match provider_assert_args(&req.payload) {
                Ok((request_json, origin, cred, cdj, cdh, uv)) => {
                    match state
                        .passkey_provider_assert(
                            &request_json,
                            &origin,
                            &cred,
                            cdj.as_deref(),
                            cdh.as_deref(),
                            uv,
                        )
                        .await
                    {
                        Ok(json) => ok_resp(json, None),
                        Err(e) => err_response(e),
                    }
                }
                Err(e) => err_response(e),
            },
            "passkey.store_registered" => match store_registered_args(&req.payload) {
                Ok((ceremony_id, cipher_id, new_login)) => {
                    match state
                        .passkey_store_registered(
                            &ceremony_id,
                            cipher_id.as_deref(),
                            new_login.as_deref(),
                        )
                        .await
                    {
                        Ok(json) => ok_resp(json, None),
                        Err(e) => err_response(e),
                    }
                }
                Err(e) => err_response(e),
            },
            "passkey.consume_assertion" => {
                let ceremony_id = serde_json::from_str::<serde_json::Value>(&req.payload)
                    .ok()
                    .and_then(|v| {
                        v.get("ceremony_id")
                            .and_then(|x| x.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default();
                if ceremony_id.is_empty() {
                    err_response("Missing 'ceremony_id'")
                } else {
                    match state.passkey_consume_assertion(&ceremony_id).await {
                        Ok(json) => ok_resp(json, None),
                        Err(e) => err_response(e),
                    }
                }
            }
            // Runtime equivalent of the daemon arm's lazy-activate backstop:
            // idempotent, no-ops when already active, refuses a locked vault.
            "sync.autosync_status" => {
                state.activate_autosync_after_remote().await;
                let status = state.autosync.status().await;
                match serde_json::to_string(&status) {
                    Ok(json) => ok_resp(json, None),
                    Err(e) => err_response(format!("JSON error: {e}")),
                }
            }
            other => err_response(format!("Unknown action: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// bridge.* route bodies.

/// bridge.match: URL -> matching CipherMeta (metadata only, no passwords).
///
/// v1: reuses the vault's `autofill_query` batch endpoint, filters
/// server-side by URI match, and returns ONLY metadata (id/name/username/
/// type). Passwords never cross this boundary — the extension calls
/// `vault.get` for the one the user picks.
pub async fn handle_bridge_match(
    req: GatewayRequest,
    host: &SharedVaultHost,
    vault_name: &str,
) -> GatewayResponse {
    let url: String = match serde_json::from_str::<serde_json::Value>(&req.payload) {
        Ok(v) => v["url"].as_str().unwrap_or("").to_string(),
        Err(_) => return err_response("Invalid JSON"),
    };
    if url.is_empty() {
        return ok_resp(
            serde_json::json!({ "matches": [], "vaults": [], "active_vault": vault_name })
                .to_string(),
            None,
        );
    }
    // G24 §4.3: fan out over the unlocked merge-eligible vaults using
    // VaultState::autofill_query - login-only, no passwords,
    // UriMatchStrategy with the vault's custom equivalent domains. The
    // old loose hostname matcher over list_all (which decrypted and
    // serialized every cipher including passwords on every tab event)
    // retires here: one matcher everywhere.
    let rows = merge_fanout_rows(host).await;
    let mut matches: Vec<serde_json::Value> = Vec::new();
    let mut vaults: Vec<serde_json::Value> = Vec::new();
    // (space, slug, name) per contributing vault, for cross-vault
    // ranking: the personal vault outranks Spaces so a shared favorite
    // never beats the user's own login (plan §4.11).
    let mut vault_rank: Vec<(bool, String, String)> = Vec::new();
    for row in rows {
        let slug = row.meta["slug"].as_str().unwrap_or_default().to_string();
        let name = row.meta["display_name"]
            .as_str()
            .unwrap_or(&slug)
            .to_string();
        let space = row.meta["space"].as_bool().unwrap_or(false);
        // Chips list ELIGIBLE vaults only (plan §4.3): an org Space is
        // invisible to the merged surface, locked or not.
        if row.eligible {
            vaults.push(serde_json::json!({
                "slug": slug,
                "display_name": name,
                "unlocked": row.state.is_some(),
                "removed": row.meta["removed"].as_bool().unwrap_or(false),
            }));
        }
        let Some(state) = row.state else {
            continue;
        };
        vault_rank.push((space, slug.clone(), name.clone()));
        let Ok(raw) = state.autofill_query(&url).await else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        for mut m in v["matches"].as_array().cloned().unwrap_or_default() {
            if let Some(o) = m.as_object_mut() {
                o.insert("vault_slug".into(), serde_json::json!(slug));
                o.insert("vault_name".into(), serde_json::json!(name));
            }
            matches.push(m);
        }
    }
    let rank_of = |m: &serde_json::Value| {
        let slug = m["vault_slug"].as_str().unwrap_or_default();
        let vr = vault_rank
            .iter()
            .find(|(_, s, _)| s == slug)
            .cloned()
            .unwrap_or((true, slug.to_string(), String::new()));
        (
            vr.0,
            // Ascending bool sort puts false first; favorites must
            // sort first, so invert (plan §4.11).
            !m["favorite"].as_bool().unwrap_or(false),
            m["name"].as_str().unwrap_or_default().to_string(),
            slug.to_string(),
        )
    };
    matches.sort_by_key(rank_of);
    ok_resp(
        serde_json::json!({
            "matches": matches,
            "vaults": vaults,
            "active_vault": vault_name,
        })
        .to_string(),
        None,
    )
}

/// bridge.passkey.list: merged passkey metadata over every unlocked
/// merge-eligible vault, mirroring bridge.match's fan-out contract. Rows
/// carry vault_slug so ceremonies can pin back to the right vault.
pub async fn handle_bridge_passkey_list(
    req: GatewayRequest,
    host: &SharedVaultHost,
    _active_slug: &str,
) -> GatewayResponse {
    // The browser client always narrows by the page's validated rpId; a
    // bridge caller without one would dump every passkey in every unlocked
    // vault, so fail closed instead of fanning out unfiltered.
    let requested_rp_id = serde_json::from_str::<serde_json::Value>(&req.payload)
        .ok()
        .and_then(|v| v.get("rp_id").and_then(|x| x.as_str()).map(String::from))
        .filter(|s| !s.is_empty());
    let Some(rp_id) = requested_rp_id else {
        return err_response("Missing 'rp_id'");
    };
    let mut rows = Vec::new();
    for entry in merge_fanout_rows(host).await {
        let Some(state) = entry.state else { continue };
        let payload = serde_json::json!({ "rp_id": rp_id }).to_string();
        match state.passkey_list(&payload).await {
            Ok(json) => {
                if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&json) {
                    for mut row in list {
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert(
                                "vault_slug".into(),
                                serde_json::Value::String(
                                    entry.meta["slug"].as_str().unwrap_or_default().to_string(),
                                ),
                            );
                        }
                        rows.push(row);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    ok_resp(
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()),
        None,
    )
}

/// bridge.config: returns ONLY default_uri_match (Decision 7; NOT settings.get
/// which leaks slug/enrollment_policy/profile PII).
pub async fn handle_bridge_config(state: &SharedVaultState) -> GatewayResponse {
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
pub fn hostname_of(url: &str) -> String {
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

#[cfg(test)]
mod policy_tests {
    use super::{
        SlugScope, bridge_write_gated, bridge_write_outside_decision_seven, provider_assert_args,
        provider_register_args, slug_scope_kind, store_registered_args,
    };

    /// Slug-scoped targeting (G24 §4.4 + the browser passkey fix): reads
    /// may target a sibling vault with a page URL, provider passkey
    /// ceremonies pin to the credential's vault Rust-side, and plain writes
    /// stay refused for a foreign slug.
    #[test]
    fn slug_scope_covers_passkey_and_write_actions() {
        assert!(matches!(slug_scope_kind("vault.get"), SlugScope::Read));
        assert!(matches!(
            slug_scope_kind("cipher.totp_code"),
            SlugScope::Read
        ));
        for a in [
            "passkey.provider_register",
            "passkey.provider_assert",
            "passkey.store_registered",
            "passkey.consume_assertion",
        ] {
            assert!(
                matches!(slug_scope_kind(a), SlugScope::Passkey),
                "{a} must be slug-pinnable"
            );
        }
        assert!(matches!(slug_scope_kind("vault.add"), SlugScope::Write));
        assert!(matches!(slug_scope_kind("vault.update"), SlugScope::Write));
        // The list fans out over every unlocked vault by design; no scope.
        assert!(matches!(slug_scope_kind("passkey.list"), SlugScope::None));
        assert!(matches!(slug_scope_kind("bridge.match"), SlugScope::None));
    }

    /// D21: every browser-visible vault MUTATION rides the desktop
    /// session's write scope; a Viewer must not mint entries or bump
    /// counters from the extension. Ceremony creation signs but does not
    /// mutate, so it stays ungated.
    #[test]
    fn bridge_write_gate_covers_passkey_mutations() {
        assert!(bridge_write_gated("vault.add"));
        assert!(bridge_write_gated("vault.update"));
        assert!(bridge_write_gated("passkey.store_registered"));
        assert!(bridge_write_gated("passkey.consume_assertion"));
        assert!(!bridge_write_gated("passkey.provider_register"));
        assert!(!bridge_write_gated("passkey.provider_assert"));
        assert!(!bridge_write_gated("passkey.list"));
        assert!(!bridge_write_gated("vault.get"));
    }

    // ── Browser bridge regression tests ──

    /// H1 (D81 review): the Decision 7 write fence is an ALLOWLIST. Every
    /// data field the extension may write is named; anything else —
    /// including fields a future cipher type adds — must refuse.
    #[test]
    fn bridge_write_gate_refuses_fields_outside_decision_seven() {
        // fido2_credentials/uris on an EDIT are deferred to the C21
        // resend-equality gate, not refused here.
        let with_fido2 = serde_json::json!({
            "kind": { "type": "login", "data": { "fido2_credentials": [{"credential_id": "x"}] } }
        });
        assert_eq!(
            bridge_write_outside_decision_seven(&with_fido2, false),
            None
        );
        let with_card_number = serde_json::json!({
            "kind": { "type": "login", "data": { "number": "4111111111111111" } }
        });
        assert!(bridge_write_outside_decision_seven(&with_card_number, false).is_some());
    }

    #[test]
    fn passkey_verify_rides_the_passkey_slug_scope() {
        assert!(matches!(
            slug_scope_kind("passkey.verify"),
            SlugScope::Passkey
        ));
    }

    #[test]
    fn provider_register_args_unpack_flat_payload() {
        let p = serde_json::json!({
            "request_json": "{\"rp\":{}}",
            "origin": "https://example.com",
            "client_data_json_b64": "e30",
            "user_verified": true,
        })
        .to_string();
        let (rj, origin, cdj, cdh, uv) = provider_register_args(&p).unwrap();
        assert_eq!(rj, "{\"rp\":{}}");
        assert_eq!(origin, "https://example.com");
        assert_eq!(cdj.as_deref(), Some("e30"));
        assert!(cdh.is_none());
        assert!(uv);
    }

    #[test]
    fn provider_register_args_require_request_and_origin() {
        let missing_origin = serde_json::json!({ "request_json": "{}" }).to_string();
        assert!(provider_register_args(&missing_origin).is_err());
        let missing_request = serde_json::json!({ "origin": "https://x.test" }).to_string();
        assert!(provider_register_args(&missing_request).is_err());
        // Defaults: absent UV and empty strings degrade to None/false.
        let minimal = serde_json::json!({
            "request_json": "{}",
            "origin": "https://x.test",
            "client_data_json_b64": "",
        })
        .to_string();
        let (_, _, cdj, _, uv) = provider_register_args(&minimal).unwrap();
        assert!(cdj.is_none());
        assert!(!uv);
    }

    #[test]
    fn provider_assert_args_require_credential() {
        let base = serde_json::json!({
            "request_json": "{}",
            "origin": "https://x.test",
        });
        let missing = base.to_string();
        assert!(provider_assert_args(&missing).is_err());
        let empty = serde_json::json!({
            "request_json": "{}",
            "origin": "https://x.test",
            "credential_id": "",
        })
        .to_string();
        assert!(provider_assert_args(&empty).is_err());
        let ok = serde_json::json!({
            "request_json": "{}",
            "origin": "https://x.test",
            "credential_id": "abc",
        })
        .to_string();
        let (_, _, cred, _, _, _) = provider_assert_args(&ok).unwrap();
        assert_eq!(cred, "abc");
    }

    #[test]
    fn store_registered_args_accept_object_or_string_new_login() {
        let as_object = serde_json::json!({
            "ceremony_id": "c1",
            "new_login": { "name": "GitHub", "username": "u@x.test" },
        })
        .to_string();
        let (cid, cipher, nl) = store_registered_args(&as_object).unwrap();
        assert_eq!(cid, "c1");
        assert!(cipher.is_none());
        let parsed: serde_json::Value = serde_json::from_str(&nl.unwrap()).unwrap();
        assert_eq!(parsed["name"], "GitHub");

        let as_string = serde_json::json!({
            "ceremony_id": "c2",
            "cipher_id": "0197e183-7f21-7cc8-9d0b-bca2f51b31a6",
            "new_login": "{\"name\":\"X\"}",
        })
        .to_string();
        let (_, cipher, nl) = store_registered_args(&as_string).unwrap();
        assert_eq!(nl.as_deref(), Some("{\"name\":\"X\"}"));
        assert!(cipher.is_some());
    }

    /// M-4: an update payload may only name identity, scope, the kind
    /// block, and the root note field. Everything else at the root is a
    /// whole-field replacement the data fence cannot see.
    #[test]
    fn bridge_update_gate_refuses_root_fields_outside_decision_seven() {
        let reprompt_flip = serde_json::json!({
            "id": "abc-123",
            "reprompt": false,
            "kind": {"type": "login", "data": {"password": "p"}}
        });
        assert!(bridge_write_outside_decision_seven(&reprompt_flip, false).is_some());
        let legal = serde_json::json!({
            "id": "abc-123",
            "vault_slug": "personal",
            "notes": "rotated today",
            "kind": {"type": "login", "data": {"username": "a", "password": "p"}}
        });
        assert_eq!(bridge_write_outside_decision_seven(&legal, false), None);
    }

    /// H1: a non-Login kind refuses outright.
    #[test]
    fn bridge_write_gate_refuses_non_login_kinds() {
        let card = serde_json::json!({
            "kind": { "type": "card", "data": { "number": "4111111111111111" } }
        });
        let reason = bridge_write_outside_decision_seven(&card, false).expect("card must refuse");
        assert!(reason.contains("logins"));
    }

    /// Decision 7 companion: the writable field set MUST pass the gate.
    #[test]
    fn bridge_write_gate_allows_decision_seven_fields() {
        let benign = serde_json::json!({
            "id": "abc-123",
            "notes": "n",
            "kind": { "type": "login", "data": {
                "username": "a", "password": "newpw", "totp_uri": "otpauth://x"
            } }
        });
        assert_eq!(bridge_write_outside_decision_seven(&benign, false), None);
    }

    /// H1 amendment: an absent kind cannot prove the target is a Login,
    /// and a kind-less payload would skip the data fence entirely.
    #[test]
    fn bridge_write_gate_refuses_a_missing_kind() {
        let no_kind = serde_json::json!({ "id": "abc-123", "password": "x" });
        assert!(bridge_write_outside_decision_seven(&no_kind, false).is_some());
    }

    /// H1 amendment: root-level hazard lists are smuggling the data fence
    /// cannot see. Empty fixture lists are no-ops and stay legal.
    #[test]
    fn bridge_write_gate_refuses_root_level_hazard_lists() {
        let smuggling = serde_json::json!({
            "id": "abc-123",
            "kind": {"type": "login", "data": {"username": "a", "password": "p"}},
            "custom_fields": [{"name": "api key", "value": "secret"}]
        });
        assert!(bridge_write_outside_decision_seven(&smuggling, true).is_some());
        let fixture_empty = serde_json::json!({
            "id": "abc-123",
            "kind": {"type": "login", "data": {"username": "a", "password": "p"}},
            "custom_fields": []
        });
        assert_eq!(
            bridge_write_outside_decision_seven(&fixture_empty, true),
            None
        );
    }

    /// H1 amendment: capture admits the full legitimate LoginData shape;
    /// the same shape on an edit keeps Decision 7's strict set.
    #[test]
    fn bridge_write_gate_splits_add_and_update_field_sets() {
        let capture = serde_json::json!({
            "name": "Example",
            "kind": {"type": "login", "data": {
                "username": "a", "password": "p",
                "uris": [{"uri": "https://example.com"}],
                "autofill_on_page_load": false,
                "password_revision_date": null,
                "favicon": null
            }}
        });
        assert_eq!(bridge_write_outside_decision_seven(&capture, true), None);
        assert!(bridge_write_outside_decision_seven(&capture, false).is_some());
    }

    /// H1 amendment: fill fields resolve from kind.data when the flat shape
    /// omits them, and an empty totp seed reads as absent.
    #[test]
    fn bridge_fill_response_falls_back_to_nested_data() {
        let payload = serde_json::json!({
            "id": "abc",
            "name": "Example",
            "kind": {"type": "login", "data": {
                "username": "alice",
                "password": "pw",
                "uris": [{"uri": "https://example.com"}],
                "totp_uri": ""
            }}
        })
        .to_string();
        let out: serde_json::Value =
            serde_json::from_str(&super::bridge_fill_response(&payload).unwrap()).unwrap();
        assert_eq!(out["username"], "alice");
        assert_eq!(out["password"], "pw");
        assert_eq!(out["totp"], false);
    }

    /// C21: omitting a protected list the existing cipher HAS must trip the
    /// omission gate — the generic update replaces the whole kind, so the
    /// omission would silently delete passkeys/URIs.
    #[test]
    fn c21_gate_rejects_omission_of_existing_protected_list() {
        use super::kind_omits_or_shrinks_protected;
        let existing = serde_json::json!({
            "type": "login",
            "data": {
                "username": "u", "password": "p",
                "fido2_credentials": [{ "credential_id": "c1" }],
                "uris": [{ "uri": "https://a.com" }]
            }
        });
        // Kind present, both protected lists omitted -> both rules fire
        // (fido2_credentials checked first).
        let omits_both = serde_json::json!({
            "type": "login", "data": { "username": "u", "password": "newpw" }
        });
        assert!(kind_omits_or_shrinks_protected(Some(&existing), Some(&omits_both)).is_some());

        // Full round-trip (lists preserved at same length) passes.
        let preserves = serde_json::json!({
            "type": "login",
            "data": {
                "username": "u", "password": "newpw",
                "fido2_credentials": [{ "credential_id": "c1" }],
                "uris": [{ "uri": "https://a.com" }]
            }
        });
        assert!(kind_omits_or_shrinks_protected(Some(&existing), Some(&preserves)).is_none());
    }

    /// C21: shrinking a protected list is deletion by another name.
    #[test]
    fn c21_gate_rejects_shrinking_protected_list() {
        use super::kind_omits_or_shrinks_protected;
        let existing = serde_json::json!({
            "type": "login",
            "data": { "uris": [{ "uri": "https://a.com" }, { "uri": "https://b.com" }] }
        });
        let shrunk = serde_json::json!({
            "type": "login", "data": { "uris": [{ "uri": "https://a.com" }] }
        });
        assert!(kind_omits_or_shrinks_protected(Some(&existing), Some(&shrunk)).is_some());
    }

    /// C21: no kind in the payload = generic PATCH keeps the existing kind;
    /// URI-less login + omitted uris = nothing to protect.
    #[test]
    fn c21_gate_allows_kindless_update_and_uriless_logins() {
        use super::kind_omits_or_shrinks_protected;
        let existing = serde_json::json!({
            "type": "login",
            "data": { "username": "u", "password": "p", "uris": [{ "uri": "https://a.com" }] }
        });
        // No incoming kind: allowed (PATCH keeps existing).
        assert!(kind_omits_or_shrinks_protected(Some(&existing), None).is_none());

        // Existing login with NO uris: omission is a no-op, allowed.
        let uriless = serde_json::json!({ "type": "login", "data": { "username": "u" } });
        let omits = serde_json::json!({ "type": "login", "data": { "password": "x" } });
        assert!(kind_omits_or_shrinks_protected(Some(&uriless), Some(&omits)).is_none());
    }
}

#[cfg(test)]
mod mobile_dispatcher_tests {
    use super::*;
    use crate::host::VaultHost;
    use std::sync::Arc;

    /// Records whether the policy let a request through to the dispatcher.
    struct StubDispatcher {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl StubDispatcher {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl BridgeDispatcher for StubDispatcher {
        async fn dispatch(
            &self,
            _req: GatewayRequest,
            _state: &SharedVaultState,
        ) -> GatewayResponse {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ok_resp("{}", None)
        }
    }

    /// A real unlocked vault under a temp data dir, hosted under `slug`,
    /// paired to a fresh bridge registry. Returns (host, pairing id).
    async fn paired_vault(
        sb: &crate::test_support::EnvGuard,
    ) -> (Arc<VaultHost>, baluard_core::bridge::PairingId) {
        let _ = sb;
        let dir = tempfile::tempdir().unwrap();
        let vpath = dir.path().join("v");
        let password = format!("policy-test-pass-{}", std::process::id());
        let handle = baluard_core::vault::creation::VaultCreator::new(&vpath, &password, "device")
            .execute()
            .unwrap()
            .0;
        let state = Arc::new(crate::VaultState::new(handle.path.clone()));
        state.unlock(&password).await.unwrap();
        let host = Arc::new(VaultHost::new());
        host.insert("t".to_string(), state.clone()).await;
        host.switch("t").await.unwrap();
        let reg = host.bridge();
        reg.write().await.start_pair("pol");
        reg.write().await.approve_pending(None).unwrap();
        let (id, _tok) = reg.write().await.complete_pair("t", "chrome").unwrap();
        (host, id)
    }

    // Gate order + dispatcher reach: every refused shape must end with the
    // stub untouched; an allowed action reaches it exactly once.
    #[tokio::test]
    async fn non_allowlisted_action_never_reaches_dispatcher() {
        let sb = crate::test_support::lock_env();
        let (host, id) = paired_vault(&sb).await;
        let stub = StubDispatcher::new();
        let resp = route_bridge_request(
            GatewayRequest {
                action: "vault.notes".into(),
                payload: "{}".into(),
                ..Default::default()
            },
            &host,
            id,
            &stub,
        )
        .await;
        assert!(!resp.success);
        assert_eq!(stub.count(), 0);
    }

    #[tokio::test]
    async fn write_outside_decision_seven_never_reaches_dispatcher() {
        let sb = crate::test_support::lock_env();
        let (host, id) = paired_vault(&sb).await;
        let stub = StubDispatcher::new();
        let payload = serde_json::json!({
            "kind": { "type": "login", "data": { "custom_field": "x" } }
        })
        .to_string();
        let resp = route_bridge_request(
            GatewayRequest {
                action: "vault.update".into(),
                payload,
                ..Default::default()
            },
            &host,
            id,
            &stub,
        )
        .await;
        assert!(!resp.success);
        assert_eq!(stub.count(), 0);
    }

    #[tokio::test]
    async fn vault_get_reaches_dispatcher_and_strips_session_token() {
        let sb = crate::test_support::lock_env();
        let (host, id) = paired_vault(&sb).await;
        let stub = StubDispatcher::new();
        let resp = route_bridge_request(
            GatewayRequest {
                action: "vault.get".into(),
                payload: r#"{"id":"x","decrypt":true}"#.into(),
                ..Default::default()
            },
            &host,
            id,
            &stub,
        )
        .await;
        // get_cipher on an unknown id fails, but the request REACHED the stub
        // and the response must not carry the vault session token.
        assert_eq!(stub.count(), 1);
        assert!(resp.session_token.is_empty(), "vault token must not leak");
    }

    // MobileDispatcher parity smoke: same fixtures as the daemon arms, both
    // transports agree on the response shape.
    #[tokio::test]
    async fn mobile_dispatcher_matches_daemon_error_shapes() {
        let sb = crate::test_support::lock_env();
        let (host, id) = paired_vault(&sb).await;
        let state = host.snapshot_target(None).await.unwrap().1;
        let mobile = MobileDispatcher;

        // Empty payload errors.
        for action in ["vault.get", "vault.add", "vault.update", "cipher.totp_code"] {
            let resp = mobile
                .dispatch(
                    GatewayRequest {
                        action: action.into(),
                        ..Default::default()
                    },
                    &state,
                )
                .await;
            assert!(!resp.success, "{action} empty payload must fail");
            assert!(!resp.error_message.is_empty());
        }

        // Unknown action fails closed.
        let resp = mobile
            .dispatch(
                GatewayRequest {
                    action: "vault.notes".into(),
                    ..Default::default()
                },
                &state,
            )
            .await;
        assert!(!resp.success && resp.error_message.contains("Unknown action"));

        // Allowlist completeness: every non-intercepted allowlisted action
        // must not fall into "Unknown action".
        for action in baluard_core::bridge::BRIDGE_ALLOWED_ACTIONS {
            if matches!(
                *action,
                "bridge.match" | "bridge.config" | "bridge.request_unlock" | "passkey.list"
                    // BL0036: the re-auth proof exists only at the browser
                    // bridge trust boundary; mobile's UV grant is the
                    // system credential manager, never a password stamp.
                    | "passkey.verify"
            ) {
                continue;
            }
            let resp = mobile
                .dispatch(
                    GatewayRequest {
                        action: (*action).into(),
                        payload: "{}".into(),
                        ..Default::default()
                    },
                    &state,
                )
                .await;
            assert!(
                !resp.error_message.contains("Unknown action"),
                "{action} must be mapped in MobileDispatcher"
            );
        }

        // sync.autosync_status activates-then-reads without failing.
        let resp = mobile
            .dispatch(
                GatewayRequest {
                    action: "sync.autosync_status".into(),
                    payload: "{}".into(),
                    ..Default::default()
                },
                &state,
            )
            .await;
        assert!(
            resp.success,
            "autosync_status must succeed: {:?}",
            resp.error_message
        );
        let _ = id;
    }
}
