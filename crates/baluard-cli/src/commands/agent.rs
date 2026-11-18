//! D80 `baluard run`: request a human-approved grant, then ask the daemon to
//! execute the child with approved environment injections.

use crate::client;
use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingInjection {
    name: String,
    vault: Option<String>,
    item_ref: String,
    field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedInjection {
    name: String,
    item_id: String,
    field: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EnvPlan {
    injections: BTreeMap<String, PendingInjection>,
    literals: BTreeMap<String, String>,
}

impl EnvPlan {
    fn insert_injection(&mut self, inj: PendingInjection) {
        self.literals.remove(&inj.name);
        self.injections.insert(inj.name.clone(), inj);
    }

    fn insert_literal(&mut self, name: String, value: String) {
        self.injections.remove(&name);
        self.literals.insert(name, value);
    }
}

pub fn handle_run(
    direct: bool,
    socket: Option<&str>,
    env_args: &[String],
    env_files: &[PathBuf],
    timeout: Option<&str>,
    need: &str,
    argv: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if direct {
        deny("agent run requires daemon mode; drop --direct");
    }
    if socket.is_some() {
        deny("agent run uses the default daemon socket; drop --socket");
    }
    if argv.is_empty() {
        deny("missing command after --");
    }
    let timeout_secs = match timeout {
        Some(raw) => Some(match parse_duration_secs(raw) {
            Ok(secs) => secs,
            Err(e) => deny(&e),
        }),
        None => None,
    };
    let stdin_b64 = if !std::io::stdin().is_terminal() {
        use base64::Engine;
        use std::io::Read;
        let mut buf = Vec::new();
        if let Err(e) = std::io::stdin().take(1024 * 1024 + 1).read_to_end(&mut buf) {
            deny(&format!("failed to read stdin: {e}"));
        }
        if buf.len() > 1024 * 1024 {
            deny("stdin exceeds 1 MiB limit");
        }
        if buf.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::STANDARD.encode(&buf))
        }
    } else {
        None
    };
    let inherited: Vec<(String, String)> = std::env::vars().collect();
    let plan = match build_env_plan(&inherited, env_files, env_args) {
        Ok(plan) => plan,
        Err(e) => deny(&e),
    };
    if plan.injections.is_empty() {
        deny(
            "at least one secret reference (--env, --env-file, or inherited baluard:// env) is required",
        );
    }

    let vault_slug = match single_vault_slug(plan.injections.values()) {
        Ok(slug) => slug,
        Err(e) => deny(&e),
    };
    let resolved = match resolve_injections(plan.injections.values()) {
        Ok(resolved) => resolved,
        Err(e) => deny(&e),
    };

    let item_ids: Vec<String> = resolved
        .iter()
        .map(|injection| injection.item_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let claimed_name = std::env::var("BALUARD_AGENT_NAME").unwrap_or_else(|_| "local agent".into());
    let mut req_payload = serde_json::json!({
        "claimed_name": claimed_name,
        "need": need,
        "item_ids": item_ids,
        "wait_for_unlock": true,
    });
    if let Some(slug) = vault_slug.as_deref() {
        req_payload["slug"] = serde_json::Value::String(slug.to_string());
    }
    let requested = match agent_call("agents.request", req_payload, "") {
        Ok(value) => value,
        Err(e) => deny(&e),
    };
    let mut agent_token = zeroize::Zeroizing::new(String::new());
    if requested["status"] == "approved" {
        agent_token =
            zeroize::Zeroizing::new(requested["token"].as_str().unwrap_or_default().to_string());
    } else {
        let Some(request_id) = requested["request_id"].as_str().map(str::to_string) else {
            deny("daemon returned no agent request id");
        };
        for _ in 0..120 {
            let polled = match agent_call(
                "agents.poll",
                serde_json::json!({"request_id": request_id}),
                "",
            ) {
                Ok(value) => value,
                Err(e) => deny(&e),
            };
            match polled["status"].as_str().unwrap_or("unknown") {
                "pending" => std::thread::sleep(std::time::Duration::from_secs(1)),
                "approved" => {
                    agent_token = zeroize::Zeroizing::new(
                        polled["token"].as_str().unwrap_or_default().to_string(),
                    );
                    break;
                }
                "denied" => deny("agent credential request was denied"),
                _ => deny("agent credential request expired"),
            }
        }
    }
    if agent_token.is_empty() {
        deny("agent credential request timed out waiting for approval");
    }

    let mut run_payload = serde_json::json!({
        "argv": argv,
        "cwd": std::env::current_dir()
            .ok()
            .map(|dir| dir.display().to_string()),
        "inject": resolved.iter().map(|injection| {
            serde_json::json!({
                "name": injection.name,
                "item_id": injection.item_id,
                "field": injection.field,
            })
        }).collect::<Vec<_>>(),
        "env_literals": plan.literals,
        "stdin_b64": stdin_b64,
        "timeout_secs": timeout_secs,
    });
    if let Some(slug) = vault_slug {
        run_payload["slug"] = serde_json::Value::String(slug);
    }
    let started = match agent_call("agents.run_start", run_payload, &agent_token) {
        Ok(value) => value,
        Err(e) => {
            agent_token.zeroize();
            deny(&e)
        }
    };
    let Some(run_id) = started["run_id"].as_str().map(str::to_string) else {
        agent_token.zeroize();
        deny("daemon returned no run_id");
    };
    let _signal_guard = install_signal_forwarder();
    let final_status = loop {
        if let Some(sig) = take_pending_signal() {
            let _ = agent_call(
                "agents.run_signal",
                serde_json::json!({"run_id": run_id, "signal": sig}),
                &agent_token,
            );
        }
        let polled = match agent_call(
            "agents.run_poll",
            serde_json::json!({"run_id": run_id}),
            &agent_token,
        ) {
            Ok(value) => value,
            Err(e) => {
                agent_token.zeroize();
                deny(&e)
            }
        };
        use std::io::Write;
        if let Some(out) = polled["stdout"].as_str().filter(|s| !s.is_empty()) {
            print!("{out}");
            std::io::stdout().flush().ok();
        }
        if let Some(err) = polled["stderr"].as_str().filter(|s| !s.is_empty()) {
            eprint!("{err}");
            std::io::stderr().flush().ok();
        }
        if polled["done"].as_bool().unwrap_or(false) {
            break polled["status"].as_i64().unwrap_or(1) as i32;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    if final_status != 0 {
        agent_token.zeroize();
        std::process::exit(final_status);
    }
    Ok(())
}

static PENDING_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn take_pending_signal() -> Option<i32> {
    let sig = PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
    if sig == 0 { None } else { Some(sig) }
}

#[cfg(unix)]
extern "C" fn on_unix_signal(sig: libc::c_int) {
    PENDING_SIGNAL.store(sig as i32, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
struct SignalGuard;

#[cfg(unix)]
fn install_signal_forwarder() -> SignalGuard {
    PENDING_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
    // SAFETY: `on_unix_signal` is async-signal-safe (only performs an atomic store).
    unsafe {
        libc::signal(
            libc::SIGINT,
            on_unix_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_unix_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            on_unix_signal as *const () as libc::sighandler_t,
        );
    }
    SignalGuard
}

#[cfg(not(unix))]
fn install_signal_forwarder() {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemplatePlaceholder {
    placeholder: String,
    inj: PendingInjection,
}

pub fn handle_inject(
    direct: bool,
    socket: Option<&str>,
    input: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
    force: bool,
    need: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if direct {
        deny("agent inject requires daemon mode; drop --direct");
    }
    if socket.is_some() {
        deny("agent inject uses the default daemon socket; drop --socket");
    }
    let template = match input {
        Some(path) if path != std::path::Path::new("-") => std::fs::read_to_string(path)
            .map_err(|e| format!("read template '{}': {e}", path.display()))?,
        _ => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("read stdin template: {e}"))?;
            buf
        }
    };
    let placeholders = match parse_template_placeholders(&template) {
        Ok(list) => list,
        Err(e) => deny(&e),
    };
    if placeholders.is_empty() {
        // No baluard:// placeholders: write template verbatim without asking for a grant.
        if let Some(out_path) = output.filter(|p| *p != std::path::Path::new("-")) {
            if out_path.exists() && !force {
                deny(&format!(
                    "refusing to overwrite '{}': pass --force to overwrite",
                    out_path.display()
                ));
            }
            baluard_core::secret_file::write_secret_file(out_path, template.as_bytes())
                .map_err(|e| format!("write '{}': {e}", out_path.display()))?;
        } else {
            print!("{template}");
        }
        return Ok(());
    }

    let vault_slug = match single_vault_slug(placeholders.iter().map(|p| &p.inj)) {
        Ok(slug) => slug,
        Err(e) => deny(&e),
    };
    let resolved = match resolve_injections(placeholders.iter().map(|p| &p.inj)) {
        Ok(r) => r,
        Err(e) => deny(&e),
    };
    let item_ids: Vec<String> = resolved
        .iter()
        .map(|r| r.item_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let claimed_name = std::env::var("BALUARD_AGENT_NAME").unwrap_or_else(|_| "local agent".into());
    let mut req_payload = serde_json::json!({
        "claimed_name": claimed_name,
        "need": need,
        "item_ids": item_ids,
        "wait_for_unlock": true,
    });
    if let Some(slug) = vault_slug.as_deref() {
        req_payload["slug"] = serde_json::Value::String(slug.to_string());
    }
    let requested = match agent_call("agents.request", req_payload, "") {
        Ok(value) => value,
        Err(e) => deny(&e),
    };
    let mut agent_token = zeroize::Zeroizing::new(String::new());
    if requested["status"] == "approved" {
        agent_token =
            zeroize::Zeroizing::new(requested["token"].as_str().unwrap_or_default().to_string());
    } else {
        let Some(request_id) = requested["request_id"].as_str().map(str::to_string) else {
            deny("daemon returned no agent request id");
        };
        for _ in 0..120 {
            let polled = match agent_call(
                "agents.poll",
                serde_json::json!({"request_id": request_id}),
                "",
            ) {
                Ok(value) => value,
                Err(e) => deny(&e),
            };
            match polled["status"].as_str().unwrap_or("unknown") {
                "pending" => std::thread::sleep(std::time::Duration::from_secs(1)),
                "approved" => {
                    agent_token = zeroize::Zeroizing::new(
                        polled["token"].as_str().unwrap_or_default().to_string(),
                    );
                    break;
                }
                "denied" => deny("agent credential request was denied"),
                _ => deny("agent credential request expired"),
            }
        }
    }
    if agent_token.is_empty() {
        deny("agent credential request timed out waiting for approval");
    }

    let resolved_placeholders: Vec<serde_json::Value> = placeholders
        .iter()
        .zip(resolved.iter())
        .map(|(ph, res)| {
            serde_json::json!({
                "placeholder": ph.placeholder,
                "item_id": res.item_id,
                "field": res.field,
            })
        })
        .collect();
    let abs_output = output.filter(|p| *p != std::path::Path::new("-")).map(|p| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        }
    });
    let mut inject_payload = serde_json::json!({
        "template": template,
        "placeholders": resolved_placeholders,
        "output": abs_output.as_ref().map(|p| p.display().to_string()),
        "force": force,
    });
    if let Some(slug) = vault_slug {
        inject_payload["slug"] = serde_json::Value::String(slug);
    }
    let result = match agent_call("agents.inject", inject_payload, &agent_token) {
        Ok(value) => value,
        Err(e) => {
            agent_token.zeroize();
            deny(&e)
        }
    };
    agent_token.zeroize();
    if let Some(content) = result["content"].as_str() {
        print!("{content}");
    }
    Ok(())
}

pub fn handle_read(
    mode: crate::ConnectMode,
    socket: Option<&str>,
    reference: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(mode, crate::ConnectMode::Direct) {
        return Err("read requires daemon mode; drop --direct".into());
    }
    let inj = parse_target_ref("READ_REF", reference)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    crate::commands::ensure_unlocked_daemon(socket)?;
    let resolved = resolve_injections(std::iter::once(&inj))?;
    let item_id = &resolved[0].item_id;
    let payload = serde_json::json!({"id": item_id, "decrypt": true}).to_string();
    let resp = client::request_to("vault.get", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    let cipher: serde_json::Value = serde_json::from_str(&resp.payload)?;
    let value = if inj.field == "totp" {
        let totp_resp = client::request_to(
            "vault.totp",
            &serde_json::json!({"id": item_id}).to_string(),
            socket,
        )?;
        if !totp_resp.success {
            return Err(totp_resp.error_message.into());
        }
        let totp_json: serde_json::Value = serde_json::from_str(&totp_resp.payload)?;
        totp_json["code"].as_str().map(str::to_string)
    } else if let Some(wanted) = inj.field.strip_prefix("custom:") {
        cipher["custom_fields"].as_array().and_then(|fields| {
            fields
                .iter()
                .find(|entry| entry["name"] == wanted)
                .and_then(|entry| entry["value"].as_str().map(str::to_string))
        })
    } else {
        cipher[inj.field.as_str()].as_str().map(str::to_string)
    };
    let Some(val) = value else {
        return Err(format!("field '{}' is empty on item '{}'", inj.field, item_id).into());
    };
    println!("{val}");
    Ok(())
}

fn parse_template_placeholders(template: &str) -> Result<Vec<TemplatePlaceholder>, String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after_open = &rest[start + 2..];
        let Some(end) = after_open.find("}}") else {
            break;
        };
        let full = &rest[start..start + 2 + end + 2];
        let inner = after_open[..end].trim();
        if inner.starts_with("baluard://") && seen.insert(full.to_string()) {
            let inj = parse_target_ref("TEMPLATE_REF", inner)?;
            out.push(TemplatePlaceholder {
                placeholder: full.to_string(),
                inj,
            });
        }
        rest = &after_open[end + 2..];
    }
    Ok(out)
}

fn agent_call(
    action: &str,
    payload: serde_json::Value,
    token: &str,
) -> Result<serde_json::Value, String> {
    let response = client::request_agent(action, &payload.to_string(), token)
        .map_err(|e| format!("agent daemon request failed: {e}"))?;
    if !response.success {
        return Err(response.error_message);
    }
    serde_json::from_str(&response.payload)
        .map_err(|e| format!("invalid agent daemon response: {e}"))
}

pub fn handle_agent_action(
    action: crate::AgentAction,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (route, payload) = match action {
        crate::AgentAction::Pending => ("agents.pending", serde_json::json!({})),
        crate::AgentAction::Approve { request_id } => (
            "agents.approve",
            serde_json::json!({"request_id": request_id}),
        ),
        crate::AgentAction::Deny { request_id } => {
            ("agents.deny", serde_json::json!({"request_id": request_id}))
        }
        crate::AgentAction::List => ("agents.list", serde_json::json!({})),
        crate::AgentAction::Revoke => ("agents.revoke", serde_json::json!({})),
        crate::AgentAction::AutoApprove {
            on,
            off,
            duration,
            yolo,
        } => {
            if on == off {
                return Err("pass either --on or --off".into());
            }
            if yolo && duration.is_some() {
                return Err("--yolo and --duration cannot be used together".into());
            }
            if off && (yolo || duration.is_some()) {
                return Err("--duration and --yolo apply only with --on".into());
            }
            let mut payload = serde_json::json!({
                "enabled": on,
                "indefinite": yolo,
            });
            if on {
                if let Some(dur) = duration.as_deref() {
                    let secs = parse_duration_secs(dur)?;
                    payload["duration_secs"] = serde_json::Value::Number(secs.into());
                }
                if !std::io::stdin().is_terminal() {
                    return Err(
                        "interactive prompt requires a terminal to supply master password".into(),
                    );
                }
                let password = rpassword::prompt_password(
                    "Master password (to enable agent auto-approval): ",
                )?;
                payload["master_password"] = serde_json::Value::String(password);
            }
            let response = client::request_to("agents.set_yolo", &payload.to_string(), socket)?;
            if !response.success {
                return Err(response.error_message.into());
            }
            println!("{}", response.payload);
            return Ok(());
        }
        crate::AgentAction::Policy {
            enable,
            disable,
            auto_approve,
            no_auto_approve,
        } => {
            if enable && disable {
                return Err("--enable and --disable contradict each other".into());
            }
            if auto_approve && no_auto_approve {
                return Err("--auto-approve and --no-auto-approve contradict each other".into());
            }
            let mut payload = serde_json::Map::new();
            if enable {
                payload.insert("enabled".into(), serde_json::Value::Bool(true));
            }
            if disable {
                payload.insert("enabled".into(), serde_json::Value::Bool(false));
            }
            if auto_approve {
                payload.insert("auto_approve".into(), serde_json::Value::Bool(true));
            }
            if no_auto_approve {
                payload.insert("auto_approve".into(), serde_json::Value::Bool(false));
            }
            if payload.is_empty() {
                let response = client::request_to("agent.policy.get", "{}", socket)?;
                if !response.success {
                    return Err(response.error_message.into());
                }
                println!("{}", response.payload);
                return Ok(());
            }
            let current = client::request_to("agent.policy.get", "{}", socket)?;
            if !current.success {
                return Err(current.error_message.into());
            }
            let current: serde_json::Value = serde_json::from_str(&current.payload)?;
            let turning_on = payload
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(current["enabled"].as_bool().unwrap_or(false))
                && !current["enabled"].as_bool().unwrap_or(false)
                || payload
                    .get("auto_approve")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(current["auto_approve"].as_bool().unwrap_or(false))
                    && !current["auto_approve"].as_bool().unwrap_or(false);
            let mut payload_value = serde_json::Value::Object(payload);
            if turning_on {
                if !std::io::stdin().is_terminal() {
                    return Err(
                        "interactive prompt requires a terminal to supply master password".into(),
                    );
                }
                let password = rpassword::prompt_password(
                    "Master password (to turn on the SSH agent for this device): ",
                )?;
                payload_value["master_password"] = serde_json::Value::String(password);
            }
            let response =
                client::request_to("agent.policy.set", &payload_value.to_string(), socket)?;
            if !response.success {
                return Err(response.error_message.into());
            }
            println!("{}", response.payload);
            return Ok(());
        }
    };
    let response = client::request_to(route, &payload.to_string(), socket)?;
    if !response.success {
        return Err(response.error_message.into());
    }
    println!("{}", response.payload);
    Ok(())
}

fn classify_error(reason: &str) -> (&'static str, i32) {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("is locked") || lower.contains("not open") {
        ("locked", 3)
    } else if lower.contains("denied") {
        ("denied", 4)
    } else if lower.contains("expired") || lower.contains("timed out waiting for approval") {
        ("expired", 4)
    } else if lower.contains("ambiguous") {
        ("ambiguous", 2)
    } else if lower.contains("rate limit") {
        ("rate_limited", 5)
    } else if lower.contains("not found") {
        ("not_found", 1)
    } else {
        ("error", 1)
    }
}

fn deny(reason: &str) -> ! {
    let (code, exit_code) = classify_error(reason);
    eprintln!("{}", serde_json::json!({"error": reason, "code": code}));
    std::process::exit(exit_code)
}

fn single_vault_slug<'a>(
    injections: impl Iterator<Item = &'a PendingInjection>,
) -> Result<Option<String>, String> {
    let mut chosen: Option<String> = None;
    for inj in injections {
        if let Some(vault) = &inj.vault {
            match &chosen {
                Some(prev) if prev != vault => {
                    return Err(format!(
                        "multiple vaults in one run ('{prev}' and '{vault}') are not supported"
                    ));
                }
                None => chosen = Some(vault.clone()),
                _ => {}
            }
        }
    }
    Ok(chosen)
}

fn resolve_injections<'a>(
    injections: impl Iterator<Item = &'a PendingInjection>,
) -> Result<Vec<ResolvedInjection>, String> {
    let items: Vec<&PendingInjection> = injections.collect();
    let needs_lookup = items
        .iter()
        .any(|inj| uuid::Uuid::parse_str(&inj.item_ref).is_err());
    let entries = if needs_lookup {
        fetch_vault_metadata()?
    } else {
        Vec::new()
    };
    items
        .into_iter()
        .map(|inj| {
            let item_id = if uuid::Uuid::parse_str(&inj.item_ref).is_ok() {
                inj.item_ref.clone()
            } else {
                match_item_ref(&inj.item_ref, &entries)?
            };
            Ok(ResolvedInjection {
                name: inj.name.clone(),
                item_id,
                field: inj.field.clone(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct VaultItemMeta {
    id: String,
    name: String,
    item_type: String,
}

pub(crate) fn resolve_item_id_for_cli(
    id_or_name: &str,
    socket: Option<&str>,
) -> Result<String, String> {
    if uuid::Uuid::parse_str(id_or_name).is_ok() {
        return Ok(id_or_name.to_string());
    }
    let resp = client::request_to("vault.list", "", socket)
        .map_err(|e| format!("failed to list vault items: {e}"))?;
    if !resp.success {
        return Err(resp.error_message);
    }
    let data: serde_json::Value = serde_json::from_str(&resp.payload)
        .map_err(|e| format!("invalid vault.list response: {e}"))?;
    let mut entries = Vec::new();
    if let Some(ciphers) = data["ciphers"].as_array() {
        for c in ciphers {
            let Some(id) = c["id"].as_str() else {
                continue;
            };
            entries.push(VaultItemMeta {
                id: id.to_string(),
                name: c["name"].as_str().unwrap_or_default().to_string(),
                item_type: c["type"].as_str().unwrap_or("login").to_string(),
            });
        }
    }
    match_item_ref(id_or_name, &entries)
}

fn fetch_vault_metadata() -> Result<Vec<VaultItemMeta>, String> {
    let resp = client::request_to("vault.list", "", None)
        .map_err(|e| format!("failed to list vault items for reference lookup: {e}"))?;
    if !resp.success {
        return Err(resp.error_message);
    }
    let data: serde_json::Value = serde_json::from_str(&resp.payload)
        .map_err(|e| format!("invalid vault.list response: {e}"))?;
    let mut out = Vec::new();
    if let Some(ciphers) = data["ciphers"].as_array() {
        for c in ciphers {
            let Some(id) = c["id"].as_str() else {
                continue;
            };
            let name = c["name"].as_str().unwrap_or_default().to_string();
            let item_type = c["type"].as_str().unwrap_or("login").to_string();
            out.push(VaultItemMeta {
                id: id.to_string(),
                name,
                item_type,
            });
        }
    }
    Ok(out)
}

fn match_item_ref(item_ref: &str, entries: &[VaultItemMeta]) -> Result<String, String> {
    if uuid::Uuid::parse_str(item_ref).is_ok() {
        return Ok(item_ref.to_string());
    }
    let lower = item_ref.to_ascii_lowercase();
    if item_ref.len() >= 4 && item_ref.chars().all(|c| c.is_ascii_hexdigit()) {
        let prefix_matches: Vec<&VaultItemMeta> = entries
            .iter()
            .filter(|e| e.id.to_ascii_lowercase().starts_with(&lower))
            .collect();
        if prefix_matches.len() == 1 {
            return Ok(prefix_matches[0].id.clone());
        }
        if prefix_matches.len() > 1 {
            return Err(format_ambiguous(item_ref, &prefix_matches));
        }
    }
    let title_matches: Vec<&VaultItemMeta> = entries
        .iter()
        .filter(|e| e.name.to_ascii_lowercase() == lower)
        .collect();
    match title_matches.len() {
        1 => Ok(title_matches[0].id.clone()),
        0 => Err(format!("item '{item_ref}' not found in active vault")),
        _ => Err(format_ambiguous(item_ref, &title_matches)),
    }
}

fn format_ambiguous(item_ref: &str, matches: &[&VaultItemMeta]) -> String {
    let list: Vec<String> = matches
        .iter()
        .map(|m| format!("{} ({}, {})", m.name, m.id, m.item_type))
        .collect();
    format!("item '{item_ref}' is ambiguous: {}", list.join(", "))
}

fn build_env_plan(
    inherited: &[(String, String)],
    env_files: &[PathBuf],
    env_args: &[String],
) -> Result<EnvPlan, String> {
    let mut plan = EnvPlan::default();
    for (key, value) in inherited {
        if !value.starts_with("baluard://") {
            continue;
        }
        if !valid_env_name(key) || key.to_ascii_uppercase().starts_with("BALUARD_") {
            continue;
        }
        let inj = parse_target_ref(key, value)?;
        plan.insert_injection(inj);
    }
    for path in env_files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read env file '{}': {e}", path.display()))?;
        parse_env_file_contents(&content, &mut plan)?;
    }
    for arg in env_args {
        let (name, target) = arg
            .split_once('=')
            .ok_or_else(|| format!("invalid injection '{arg}': expected NAME=REF"))?;
        let inj = parse_target_ref(name, target)?;
        plan.insert_injection(inj);
    }
    Ok(plan)
}

fn parse_env_file_contents(contents: &str, plan: &mut EnvPlan) -> Result<(), String> {
    for (idx, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let (key, raw_val) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid env-file line {}: expected KEY=VALUE", idx + 1))?;
        let key = key.trim();
        let val = unquote_env_value(raw_val.trim());
        if val.starts_with("baluard://") {
            let inj = parse_target_ref(key, &val)?;
            plan.insert_injection(inj);
        } else {
            validate_env_key(key)?;
            plan.insert_literal(key.to_string(), val);
        }
    }
    Ok(())
}

fn unquote_env_value(raw: &str) -> String {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

fn parse_target_ref(name: &str, target: &str) -> Result<PendingInjection, String> {
    validate_env_key(name)?;
    if let Some(rest) = target.strip_prefix("baluard://") {
        let parts: Vec<&str> = rest.split('/').collect();
        let (vault, item_raw, field_raw) = match parts.as_slice() {
            [item, field] => (None, *item, *field),
            [vault, item, field] => (Some(percent_decode_segment(vault)?), *item, *field),
            _ => {
                return Err(format!(
                    "invalid reference '{target}': expected baluard://[vault/]item/field"
                ));
            }
        };
        let item_ref = percent_decode_segment(item_raw)?;
        let field = percent_decode_segment(field_raw)?;
        if let Some(v) = &vault {
            if v.is_empty() {
                return Err(format!("invalid reference '{target}': empty vault"));
            }
        }
        if item_ref.is_empty() {
            return Err(format!("invalid reference '{target}': empty item"));
        }
        validate_field_name(&field)?;
        return Ok(PendingInjection {
            name: name.to_string(),
            vault,
            item_ref,
            field,
        });
    }

    let (item_id, field) = target.split_once(':').ok_or_else(|| {
        format!("invalid injection '{name}={target}': expected baluard://... or ITEM_ID:FIELD")
    })?;
    uuid::Uuid::parse_str(item_id).map_err(|_| format!("invalid item id '{item_id}'"))?;
    validate_field_name(field)?;
    Ok(PendingInjection {
        name: name.to_string(),
        vault: None,
        item_ref: item_id.to_string(),
        field: field.to_string(),
    })
}

fn percent_decode_segment(seg: &str) -> Result<String, String> {
    let mut out = String::with_capacity(seg.len());
    let bytes = seg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!("invalid percent escape in '{seg}'"));
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| format!("invalid percent escape in '{seg}'"))?;
            let val = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid percent escape in '{seg}'"))?;
            out.push(val as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

fn validate_env_key(name: &str) -> Result<(), String> {
    if !valid_env_name(name) || name.to_ascii_uppercase().starts_with("BALUARD_") {
        return Err(format!("invalid environment name '{name}'"));
    }
    Ok(())
}

fn validate_field_name(field: &str) -> Result<(), String> {
    if field.is_empty()
        || matches!(
            field,
            "fido2_credentials" | "private_key" | "totp_secret" | "id" | "type" | "custom_fields"
        )
    {
        return Err(format!("field '{field}' is not allowed"));
    }
    if let Some(custom) = field.strip_prefix("custom:") {
        if custom.is_empty() {
            return Err(format!("field '{field}' is not allowed"));
        }
    }
    Ok(())
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_duration_secs(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".into());
    }
    let mut total: u64 = 0;
    let mut num_buf = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
            continue;
        }
        if num_buf.is_empty() {
            return Err(format!("invalid duration '{raw}'"));
        }
        let n: u64 = num_buf
            .parse()
            .map_err(|_| format!("invalid duration '{raw}'"))?;
        num_buf.clear();
        let mult = match ch {
            's' | 'S' => 1,
            'm' | 'M' => 60,
            'h' | 'H' => 3600,
            'd' | 'D' => 86400,
            _ => return Err(format!("invalid duration unit '{ch}' in '{raw}'")),
        };
        total = total
            .checked_add(n.saturating_mul(mult))
            .ok_or_else(|| format!("duration overflow in '{raw}'"))?;
    }
    if !num_buf.is_empty() || total == 0 {
        return Err(format!("invalid duration '{raw}' (use e.g. 5m, 4h, 1h30m)"));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_and_uri_references() {
        let id = uuid::Uuid::new_v4();
        let legacy = parse_target_ref("LOGIN_PASS", &format!("{id}:password")).unwrap();
        assert_eq!(legacy.item_ref, id.to_string());
        assert_eq!(legacy.field, "password");
        assert_eq!(legacy.vault, None);

        let two_part = parse_target_ref("GH_TOKEN", "baluard://GitHub/password").unwrap();
        assert_eq!(two_part.vault, None);
        assert_eq!(two_part.item_ref, "GitHub");
        assert_eq!(two_part.field, "password");

        let three_part =
            parse_target_ref("API_KEY", "baluard://work/Stripe%2FProd/custom:api-key").unwrap();
        assert_eq!(three_part.vault.as_deref(), Some("work"));
        assert_eq!(three_part.item_ref, "Stripe/Prod");
        assert_eq!(three_part.field, "custom:api-key");
    }

    #[test]
    fn rejects_malformed_or_forbidden_injections() {
        let id = uuid::Uuid::new_v4();
        for bad in [
            ("MISSING", "no-delimiter"),
            ("1BAD", &format!("{id}:password")),
            ("BALUARD_TOKEN", &format!("{id}:password")),
            ("TOKEN", "not-a-uuid:password"),
            ("TOKEN", &format!("{id}:private_key")),
            ("TOKEN", "baluard://onlyone"),
            ("TOKEN", "baluard://a/b/c/d"),
        ] {
            assert!(parse_target_ref(bad.0, bad.1).is_err());
        }
        assert!(parse_target_ref("NOTE", &format!("{id}:notes")).is_ok());
    }

    #[test]
    fn parses_template_placeholders_and_leaves_others_alone() {
        let tpl = "key={{ baluard://Stripe/custom:api_key }}\nhelm={{ .Values.host }}\n";
        let parsed = parse_template_placeholders(tpl).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].placeholder,
            "{{ baluard://Stripe/custom:api_key }}"
        );
        assert_eq!(parsed[0].inj.item_ref, "Stripe");
        assert_eq!(parsed[0].inj.field, "custom:api_key");
    }

    #[test]
    fn parses_env_file_and_applies_precedence() {
        let mut plan = EnvPlan::default();
        let inherited = vec![
            ("A".to_string(), "baluard://Item1/password".to_string()),
            ("B".to_string(), "baluard://Item2/username".to_string()),
            ("PLAIN_ENV".to_string(), "ignored".to_string()),
        ];
        for (k, v) in &inherited {
            if v.starts_with("baluard://") {
                plan.insert_injection(parse_target_ref(k, v).unwrap());
            }
        }
        parse_env_file_contents(
            "# comment\nexport B=\"baluard://Item3/password\"\nPORT=8080\n",
            &mut plan,
        )
        .unwrap();
        assert_eq!(plan.injections["A"].item_ref, "Item1");
        assert_eq!(plan.injections["B"].item_ref, "Item3");
        assert_eq!(plan.literals.get("PORT").map(String::as_str), Some("8080"));
    }

    #[test]
    fn matches_item_by_prefix_and_title_and_rejects_ambiguous() {
        let entries = vec![
            VaultItemMeta {
                id: "abcd1111-0000-0000-0000-000000000000".into(),
                name: "GitHub".into(),
                item_type: "login".into(),
            },
            VaultItemMeta {
                id: "abcd2222-0000-0000-0000-000000000000".into(),
                name: "GitLab".into(),
                item_type: "login".into(),
            },
            VaultItemMeta {
                id: "ef003333-0000-0000-0000-000000000000".into(),
                name: "Duplicate".into(),
                item_type: "login".into(),
            },
            VaultItemMeta {
                id: "ef004444-0000-0000-0000-000000000000".into(),
                name: "Duplicate".into(),
                item_type: "login".into(),
            },
        ];
        assert_eq!(
            match_item_ref("github", &entries).unwrap(),
            "abcd1111-0000-0000-0000-000000000000"
        );
        assert_eq!(
            match_item_ref("abcd1", &entries).unwrap(),
            "abcd1111-0000-0000-0000-000000000000"
        );
        assert!(
            match_item_ref("abcd", &entries)
                .unwrap_err()
                .contains("ambiguous")
        );
        assert!(
            match_item_ref("Duplicate", &entries)
                .unwrap_err()
                .contains("ambiguous")
        );
        assert!(
            match_item_ref("Missing", &entries)
                .unwrap_err()
                .contains("not found")
        );
    }

    #[test]
    fn parses_durations_minutes_and_hours() {
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("4h").unwrap(), 14_400);
        assert_eq!(parse_duration_secs("1h30m").unwrap(), 5_400);
        assert_eq!(parse_duration_secs("45s").unwrap(), 45);
        assert!(parse_duration_secs("0m").is_err());
        assert!(parse_duration_secs("5").is_err());
        assert!(parse_duration_secs("5x").is_err());
    }

    #[test]
    fn classifies_structured_error_codes() {
        assert_eq!(classify_error("Vault 'personal' is locked"), ("locked", 3));
        assert_eq!(
            classify_error("agent credential request was denied"),
            ("denied", 4)
        );
        assert_eq!(
            classify_error("agent credential request expired"),
            ("expired", 4)
        );
        assert_eq!(
            classify_error("item 'gh' is ambiguous: a, b"),
            ("ambiguous", 2)
        );
        assert_eq!(
            classify_error("agent request rate limit exceeded"),
            ("rate_limited", 5)
        );
        assert_eq!(
            classify_error("item 'foo' not found in active vault"),
            ("not_found", 1)
        );
    }
}
