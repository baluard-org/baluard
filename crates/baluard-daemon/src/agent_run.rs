//! D80 `agents.run`: the daemon composes a child environment from approved
//! Login fields and returns only scrubbed output. Secret bytes never ride
//! the socket response and never appear in argv.

use crate::handler::{err_response, ok_resp};
use crate::host::SharedVaultHost;
use crate::proto::{GatewayRequest, GatewayResponse};
use baluard_runtime::agents::{PeerBinding, pid_in_process_tree};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use zeroize::{Zeroize, Zeroizing};

const MAX_AGENT_OUTPUT: usize = 1024 * 1024;
const AGENT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(serde::Deserialize)]
struct RunPayload {
    #[serde(default)]
    slug: Option<String>,
    argv: Vec<String>,
    #[serde(default)]
    inject: Vec<Injection>,
}

#[derive(serde::Deserialize)]
struct Injection {
    name: String,
    item_id: String,
    field: String,
}

pub async fn run(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&PeerBinding>,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let mut payload: RunPayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => return err_response(format!("Invalid agent run: {e}")),
    };
    if payload.argv.is_empty()
        || payload.argv.len() > 64
        || payload
            .argv
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        || payload.inject.len() > 32
    {
        return err_response("agent command exceeds its size limits");
    }
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        payload.slug.as_deref()
    };
    let (_slug, state) = match host.snapshot_target(slug).await {
        Ok(pair) => pair,
        Err(_) => return err_response("agent vault is not open"),
    };
    let verdict = match state.verify_agent_token(&req.session_token) {
        Ok(v) => v,
        Err(e) => return err_response(e.to_string()),
    };
    let Some(chain) = process_chain(peer.pid) else {
        return err_response("agent process tree is unavailable");
    };
    if !pid_in_process_tree(&verdict.peer, &chain) {
        return err_response("agent grant belongs to a different process tree");
    }
    if payload.inject.iter().any(|i| {
        !valid_env_name(&i.name)
            || i.name.to_ascii_uppercase().starts_with("BALUARD_")
            || !verdict.grant_item_ids.contains(&i.item_id)
    }) {
        return err_response("agent injection is invalid or outside the approved items");
    }

    let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
    for injection in &payload.inject {
        let json = match state.get_cipher(&injection.item_id, true).await {
            Ok(json) => json,
            Err(e) => return err_response(format!("agent item could not be read: {e}")),
        };
        let cipher: serde_json::Value = match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(_) => return err_response("agent item is malformed"),
        };
        if cipher["type"] != "login" {
            return err_response("agent grants may read Login items only");
        }
        let value = match injection.field.as_str() {
            "username" | "password" => cipher[injection.field.as_str()]
                .as_str()
                .map(|s| Zeroizing::new(s.to_string())),
            "totp" => match state.totp_code(&injection.item_id).await {
                Ok(code) => Some(Zeroizing::new(code)),
                Err(e) => return err_response(format!("agent TOTP could not be derived: {e}")),
            },
            field if field.starts_with("custom:") => {
                let wanted = &field[7..];
                cipher["custom_fields"].as_array().and_then(|fields| {
                    fields
                        .iter()
                        .find(|f| f["name"] == wanted)
                        .and_then(|f| f["value"].as_str().map(|s| Zeroizing::new(s.to_string())))
                })
            }
            _ => return err_response("agent field is not allowed"),
        };
        let Some(value) = value else {
            return err_response(format!("agent field '{}' is empty", injection.field));
        };
        values.push((injection.name.clone(), value));
    }

    let mut command = tokio::process::Command::new(&payload.argv[0]);
    command
        .args(&payload.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BALUARD_") {
            command.env_remove(key);
        }
    }
    for (name, value) in &values {
        command.env(name, value.as_str());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return err_response(format!("agent command could not start: {e}")),
    };
    let mut child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return err_response("agent command stdout is unavailable"),
    };
    let mut child_stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => return err_response("agent command stderr is unavailable"),
    };
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        child_stdout
            .take((MAX_AGENT_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map(|_| bytes)
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        child_stderr
            .take((MAX_AGENT_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map(|_| bytes)
    });
    let status = match tokio::time::timeout(AGENT_COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return err_response(format!("agent command failed: {e}")),
        Err(_) => {
            let _ = child.kill().await;
            return err_response("agent command timed out");
        }
    };
    let mut stdout = match stdout_task.await {
        Ok(Ok(bytes)) => bytes,
        _ => return err_response("agent command stdout could not be captured"),
    };
    let mut stderr = match stderr_task.await {
        Ok(Ok(bytes)) => bytes,
        _ => return err_response("agent command stderr could not be captured"),
    };
    let truncated = stdout.len() > MAX_AGENT_OUTPUT || stderr.len() > MAX_AGENT_OUTPUT;
    stdout.truncate(MAX_AGENT_OUTPUT);
    stderr.truncate(MAX_AGENT_OUTPUT);
    let secrets: Vec<Zeroizing<String>> = values.iter().map(|(_, value)| value.clone()).collect();
    let stdout = crate::scrub::scrub_output(&stdout, &secrets);
    let stderr = crate::scrub::scrub_output(&stderr, &secrets);
    payload.argv.zeroize();
    ok_resp(
        serde_json::json!({
            "status": status.code().unwrap_or(-1),
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
        })
        .to_string(),
        None,
    )
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(target_os = "linux")]
fn process_chain(pid: u32) -> Option<Vec<(u32, u64)>> {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..8 {
        let stat = std::fs::read_to_string(format!("/proc/{current}/stat")).ok()?;
        let rest = stat.rsplit_once(") ")?.1;
        let mut fields = rest.split_whitespace();
        let _state = fields.next()?;
        let parent: u32 = fields.next()?.parse().ok()?;
        let start_ticks = rest.split_whitespace().nth(19)?.parse().ok()?;
        chain.push((current, start_ticks));
        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }
    Some(chain)
}

#[cfg(target_os = "macos")]
fn process_chain(pid: u32) -> Option<Vec<(u32, u64)>> {
    let output = std::process::Command::new("ps")
        .args(["-eo", "pid=,ppid="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let parents = parse_ps_parents(&text);
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..8 {
        chain.push((current, 0));
        let Some(parent) = parents.get(&current).copied() else {
            break;
        };
        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }
    Some(chain)
}

fn parse_ps_parents(text: &str) -> std::collections::HashMap<u32, u32> {
    let mut parents = std::collections::HashMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(child) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        let Some(parent) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        parents.insert(child, parent);
    }
    parents
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_chain(_pid: u32) -> Option<Vec<(u32, u64)>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_parser_skips_blank_and_malformed_lines() {
        let parents = parse_ps_parents("1 0\n\nnot-a-process\n42 1\n");
        assert_eq!(parents.get(&42), Some(&1));
        assert_eq!(parents.get(&1), Some(&0));
        assert_eq!(parents.len(), 2);
    }
}
