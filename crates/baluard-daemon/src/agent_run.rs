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
// NEW-1: the command timeout covers only the direct child; a background
// grandchild can hold the output pipes far longer. The grace window below
// bounds capture AFTER the child exits — it must never cut off a command
// that is still running and producing output.
const AGENT_DRAIN_GRACE: Duration = Duration::from_secs(10);

#[derive(serde::Deserialize)]
struct RunPayload {
    #[serde(default)]
    slug: Option<String>,
    /// The caller's working directory. The daemon would otherwise spawn
    /// the child in its own cwd, breaking relative-path commands.
    #[serde(default)]
    cwd: Option<String>,
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

    if let Err(error) = crate::agent_audit::append(
        &baluard_core::paths::data_dir(),
        "run_started",
        &_slug,
        peer,
        None,
        payload.argv.first().map(String::as_str),
        &verdict.grant_item_ids,
        "started",
    ) {
        return err_response(format!("agent audit failed: {error}"));
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
    // NEW-1: the child leads its own process group so a timeout can sweep
    // background grandchildren that would otherwise outlive the ceiling
    // still holding injected secrets.
    #[cfg(unix)]
    command.process_group(0);
    if let Some(cwd) = &payload.cwd {
        let dir = std::path::PathBuf::from(cwd);
        if !dir.is_dir() {
            return err_response(format!("agent working directory does not exist: {cwd}"));
        }
        command.current_dir(dir);
    }
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
    let (exit_tx, exit_rx) = tokio::sync::watch::channel(false);
    let stdout_task = tokio::spawn(drain_capped(child_stdout, exit_rx.clone()));
    let stderr_task = tokio::spawn(drain_capped(child_stderr, exit_rx));
    let status = match tokio::time::timeout(AGENT_COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            let _ = exit_tx.send(true);
            status
        }
        Ok(Err(e)) => {
            let _ = exit_tx.send(true);
            return err_response(format!("agent command failed: {e}"));
        }
        Err(_) => {
            kill_process_group(&child);
            let _ = child.kill().await;
            let _ = exit_tx.send(true);
            return err_response("agent command timed out");
        }
    };
    let mut stdout = stdout_task.await.unwrap_or_default();
    let mut stderr = stderr_task.await.unwrap_or_default();
    let truncated = stdout.len() > MAX_AGENT_OUTPUT || stderr.len() > MAX_AGENT_OUTPUT;
    stdout.truncate(MAX_AGENT_OUTPUT);
    stderr.truncate(MAX_AGENT_OUTPUT);
    let secrets: Vec<Zeroizing<String>> = values.iter().map(|(_, value)| value.clone()).collect();
    let stdout = crate::scrub::scrub_output(&stdout, &secrets);
    let stderr = crate::scrub::scrub_output(&stderr, &secrets);
    payload.argv.zeroize();
    if let Err(error) = crate::agent_audit::append(
        &baluard_core::paths::data_dir(),
        "run_finished",
        &_slug,
        peer,
        None,
        None,
        &verdict.grant_item_ids,
        &format!("exit:{}", status.code().unwrap_or(-1)),
    ) {
        eprintln!("agent audit: {error}");
    }
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

/// Drain one capped output stream. While the child runs, reads have no
/// deadline (a slow command keeps its output); once the child exit signal
/// fires, a grace window ends capture so a pipe held open by a background
/// process cannot hang the run.
async fn drain_capped(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut child_exited: tokio::sync::watch::Receiver<bool>,
) -> Vec<u8> {
    let mut reader = stream.take((MAX_AGENT_OUTPUT + 1) as u64);
    let mut bytes = Vec::new();
    let mut buf = [0u8; 8192];
    let mut grace_deadline: Option<tokio::time::Instant> = None;
    loop {
        if let Some(deadline) = grace_deadline {
            match tokio::time::timeout_at(deadline, reader.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return bytes,
                Ok(Ok(n)) => bytes.extend_from_slice(&buf[..n]),
            }
            continue;
        }
        tokio::select! {
            n = reader.read(&mut buf) => match n {
                Ok(0) | Err(_) => return bytes,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            },
            _ = child_exited.changed() => {
                grace_deadline = Some(tokio::time::Instant::now() + AGENT_DRAIN_GRACE);
            }
        }
    }
}

/// NEW-1: SIGKILL the child's whole process group so background
/// grandchildren do not outlive the run holding injected secrets.
#[cfg(unix)]
fn kill_process_group(child: &tokio::process::Child) {
    // kill(-1, sig) signals every process the user owns and kill(0, sig)
    // signals our own group, so only a real child pid may be negated.
    if let Some(pid) = child.id().filter(|pid| *pid > 1) {
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_child: &tokio::process::Child) {}

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
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..8 {
        let Some((ppid, start)) = macos_proc_info(current) else {
            break;
        };
        // NEW-2: the start time rides the chain so the macOS peer binding
        // gets the same pid-reuse protection the Linux start ticks give.
        chain.push((current, start));
        if ppid == 0 || ppid == current {
            break;
        }
        current = ppid;
    }
    if chain.is_empty() {
        return None;
    }
    Some(chain)
}

/// NEW-2: (ppid, process start seconds since epoch) via proc_pidinfo.
/// The start time replaces the wildcard zero in the macOS peer binding.
#[cfg(target_os = "macos")]
pub(crate) fn macos_proc_info(pid: u32) -> Option<(u32, u64)> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if ret <= 0 {
        return None;
    }
    Some((info.pbi_ppid, info.pbi_start_tvsec))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_chain(_pid: u32) -> Option<Vec<(u32, u64)>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
}
