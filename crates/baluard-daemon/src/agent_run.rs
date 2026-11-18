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
const MAX_AGENT_COMMAND_TIMEOUT: Duration = Duration::from_secs(3600);
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
    #[serde(default)]
    env_literals: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    stdin_b64: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
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
    }) || payload.env_literals.len() > 64
        || payload.env_literals.iter().any(|(k, v)| {
            !valid_env_name(k)
                || k.to_ascii_uppercase().starts_with("BALUARD_")
                || v.len() > 4096
                || v.contains('\0')
        })
    {
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
        let value = match resolve_item_field(&state, &injection.item_id, &injection.field).await {
            Ok(v) => v,
            Err(e) => return err_response(e),
        };
        values.push((injection.name.clone(), value));
    }

    let stdin_bytes = match payload.stdin_b64.as_deref() {
        Some(encoded) => {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "invalid base64 stdin payload");
            match decoded {
                Ok(bytes) if bytes.len() <= MAX_AGENT_OUTPUT => Some(bytes),
                Ok(_) => return err_response("agent stdin exceeds 1 MiB limit"),
                Err(msg) => return err_response(msg),
            }
        }
        None => None,
    };
    let timeout_dur = match payload.timeout_secs {
        Some(0) => MAX_AGENT_COMMAND_TIMEOUT,
        Some(secs) => Duration::from_secs(secs).min(MAX_AGENT_COMMAND_TIMEOUT),
        None => AGENT_COMMAND_TIMEOUT,
    };

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
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BALUARD_") {
            command.env_remove(key);
        }
    }
    for (name, value) in &payload.env_literals {
        command.env(name, value);
    }
    for (name, value) in &values {
        command.env(name, value.as_str());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return err_response(format!("agent command could not start: {e}")),
    };
    if let Some(bytes) = stdin_bytes {
        if let Some(mut child_stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = child_stdin.write_all(&bytes).await;
            let _ = child_stdin.shutdown().await;
        }
    }
    let child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return err_response("agent command stdout is unavailable"),
    };
    let child_stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => return err_response("agent command stderr is unavailable"),
    };
    let (exit_tx, exit_rx) = tokio::sync::watch::channel(false);
    let stdout_task = tokio::spawn(drain_capped(child_stdout, exit_rx.clone()));
    let stderr_task = tokio::spawn(drain_capped(child_stderr, exit_rx));
    let status = match tokio::time::timeout(timeout_dur, child.wait()).await {
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
    #[cfg(unix)]
    let exit_signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let exit_signal: Option<i32> = None;
    let exit_code = match (status.code(), exit_signal) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        (None, None) => -1,
    };
    ok_resp(
        serde_json::json!({
            "status": exit_code,
            "signal": exit_signal,
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
        // SAFETY: pid is a live child greater than 1, so the negated pid targets only its own process group.
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
pub(crate) fn process_chain(pid: u32) -> Option<Vec<(u32, u64)>> {
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
pub(crate) fn process_chain(pid: u32) -> Option<Vec<(u32, u64)>> {
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
    // SAFETY: zeroed proc_bsdinfo is a valid all-zero value; proc_pidinfo fills the real fields.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: info is writable with buffersize sizeof(proc_bsdinfo); proc_pidinfo writes at most buffersize bytes.
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
pub(crate) fn process_chain(_pid: u32) -> Option<Vec<(u32, u64)>> {
    None
}

async fn resolve_item_field(
    state: &baluard_runtime::state::VaultState,
    item_id: &str,
    field: &str,
) -> Result<Zeroizing<String>, String> {
    let json = state
        .get_cipher(item_id, true)
        .await
        .map_err(|e| format!("agent item could not be read: {e}"))?;
    let cipher: serde_json::Value =
        serde_json::from_str(&json).map_err(|_| "agent item is malformed".to_string())?;
    let item_type = cipher["type"].as_str().unwrap_or("");
    if matches!(item_type, "ssh_key" | "signing_key") {
        return Err("agent grants may not read SSH or signing key items".into());
    }
    if !matches!(
        item_type,
        "login"
            | "secure_note"
            | "card"
            | "identity"
            | "bank_account"
            | "drivers_license"
            | "passport"
    ) {
        return Err(format!("agent grants may not read '{item_type}' items"));
    }
    if matches!(
        field,
        "fido2_credentials" | "private_key" | "totp_secret" | "id" | "type" | "custom_fields"
    ) {
        return Err("agent field is not allowed".into());
    }
    let value = match field {
        "totp" => {
            let code = state
                .totp_code(item_id)
                .await
                .map_err(|e| format!("agent TOTP could not be derived: {e}"))?;
            Some(Zeroizing::new(code))
        }
        f if f.starts_with("custom:") => {
            let wanted = &f[7..];
            cipher["custom_fields"].as_array().and_then(|fields| {
                fields
                    .iter()
                    .find(|entry| entry["name"] == wanted)
                    .and_then(|entry| {
                        entry["value"]
                            .as_str()
                            .map(|s| Zeroizing::new(s.to_string()))
                    })
            })
        }
        scalar => cipher
            .get(scalar)
            .and_then(serde_json::Value::as_str)
            .map(|s| Zeroizing::new(s.to_string())),
    };
    value.ok_or_else(|| format!("agent field '{field}' is empty"))
}

#[derive(serde::Deserialize)]
struct InjectPlaceholder {
    placeholder: String,
    item_id: String,
    field: String,
}

#[derive(serde::Deserialize)]
struct InjectPayload {
    #[serde(default)]
    slug: Option<String>,
    template: String,
    placeholders: Vec<InjectPlaceholder>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    force: bool,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct InjectedRecord {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_secs: i64,
    mtime_nanos: u32,
}

pub async fn inject(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&PeerBinding>,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let payload: InjectPayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => return err_response(format!("Invalid agent inject: {e}")),
    };
    if payload.template.len() > MAX_AGENT_OUTPUT || payload.placeholders.len() > 64 {
        return err_response("agent inject exceeds its size limits");
    }
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        payload.slug.as_deref()
    };
    let (vault_slug, state) = match host.snapshot_target(slug).await {
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
    if payload
        .placeholders
        .iter()
        .any(|p| !verdict.grant_item_ids.contains(&p.item_id))
    {
        return err_response("agent injection is outside the approved items");
    }

    let mut rendered = Zeroizing::new(payload.template.clone());
    for entry in &payload.placeholders {
        let val = match resolve_item_field(&state, &entry.item_id, &entry.field).await {
            Ok(v) => v,
            Err(e) => return err_response(e),
        };
        let next = rendered.replace(&entry.placeholder, &val);
        *rendered = next;
    }

    let target = payload.output.as_deref().filter(|p| *p != "-");
    if let Some(out_path_str) = target {
        let out_path = std::path::PathBuf::from(out_path_str);
        if let Err(e) = write_injected_file(&out_path, rendered.as_bytes(), payload.force) {
            return err_response(e);
        }
        if let Err(error) = crate::agent_audit::append(
            &baluard_core::paths::data_dir(),
            "inject_finished",
            &vault_slug,
            peer,
            None,
            Some(out_path_str),
            &verdict.grant_item_ids,
            "written",
        ) {
            eprintln!("agent audit: {error}");
        }
        return ok_resp(
            serde_json::json!({
                "written": out_path_str,
                "bytes": rendered.len(),
            })
            .to_string(),
            None,
        );
    }

    if let Err(error) = crate::agent_audit::append(
        &baluard_core::paths::data_dir(),
        "inject_finished",
        &vault_slug,
        peer,
        None,
        Some("stdout"),
        &verdict.grant_item_ids,
        "stdout",
    ) {
        eprintln!("agent audit: {error}");
    }
    ok_resp(
        serde_json::json!({
            "content": rendered.as_str(),
        })
        .to_string(),
        None,
    )
}

fn injected_ledger_path() -> std::path::PathBuf {
    baluard_core::paths::data_dir().join("injected.json")
}

fn file_record(path: &std::path::Path) -> Result<InjectedRecord, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("stat '{}': {e}", path.display()))?;
    #[cfg(unix)]
    let (dev, ino, mtime_secs, mtime_nanos) = {
        use std::os::unix::fs::MetadataExt;
        (
            meta.dev(),
            meta.ino(),
            meta.mtime(),
            meta.mtime_nsec() as u32,
        )
    };
    #[cfg(not(unix))]
    let (dev, ino, mtime_secs, mtime_nanos) = (0, 0, 0, 0);
    Ok(InjectedRecord {
        dev,
        ino,
        size: meta.len(),
        mtime_secs,
        mtime_nanos,
    })
}

fn write_injected_file(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<(), String> {
    let ledger_path = injected_ledger_path();
    let mut ledger: std::collections::BTreeMap<String, InjectedRecord> =
        std::fs::read_to_string(&ledger_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
    let key = path.to_string_lossy().to_string();
    if path.exists() && !force {
        let current = file_record(path)?;
        match ledger.get(&key) {
            Some(recorded) if *recorded == current => {}
            _ => {
                return Err(format!(
                    "refusing to overwrite '{}': file was modified outside baluard inject (pass --force to overwrite)",
                    path.display()
                ));
            }
        }
    }
    baluard_core::secret_file::write_secret_file(path, bytes)
        .map_err(|e| format!("write injected file '{}': {e}", path.display()))?;
    let updated = file_record(path)?;
    ledger.insert(key, updated);
    let ledger_json =
        serde_json::to_string_pretty(&ledger).map_err(|e| format!("serialize ledger: {e}"))?;
    baluard_core::secret_file::write_secret_file(&ledger_path, ledger_json.as_bytes())
        .map_err(|e| format!("write injected ledger: {e}"))
}

struct StreamingRunSession {
    peer: PeerBinding,
    pid: Option<u32>,
    secrets: Vec<Zeroizing<String>>,
    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,
    last_output_at: std::time::Instant,
    stdout_closed: bool,
    stderr_closed: bool,
    done: bool,
    status: Option<i32>,
    signal: Option<i32>,
    truncated: bool,
}

static STREAMING_RUNS: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<std::sync::Mutex<StreamingRunSession>>>,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[derive(serde::Deserialize)]
struct RunIdPayload {
    run_id: String,
}

#[derive(serde::Deserialize)]
struct RunSignalPayload {
    run_id: String,
    signal: i32,
}

fn drain_scrubbed_buf(buf: &mut Vec<u8>, secrets: &[Zeroizing<String>], flush_all: bool) -> String {
    if buf.is_empty() {
        return String::new();
    }
    let max_hold = if flush_all {
        0
    } else {
        secrets
            .iter()
            .filter(|s| s.len() >= 4)
            .map(|s| s.len().saturating_mul(3).saturating_add(4))
            .max()
            .unwrap_or(0)
    };
    if buf.len() <= max_hold {
        return String::new();
    }
    let mut split_at = buf.len() - max_hold;
    while split_at > 0 && (buf[split_at] & 0b1100_0000) == 0b1000_0000 {
        split_at -= 1;
    }
    if split_at == 0 {
        return String::new();
    }
    let chunk: Vec<u8> = buf.drain(..split_at).collect();
    crate::scrub::scrub_output(&chunk, secrets)
}

async fn pump_stream_to_session(
    mut stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    session: std::sync::Arc<std::sync::Mutex<StreamingRunSession>>,
    is_stderr: bool,
) {
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => {
                if let Ok(mut guard) = session.lock() {
                    if is_stderr {
                        guard.stderr_closed = true;
                    } else {
                        guard.stdout_closed = true;
                    }
                }
                return;
            }
            Ok(n) => {
                if let Ok(mut guard) = session.lock() {
                    let target = if is_stderr {
                        &mut guard.stderr_buf
                    } else {
                        &mut guard.stdout_buf
                    };
                    if target.len() < MAX_AGENT_OUTPUT {
                        let room = MAX_AGENT_OUTPUT - target.len();
                        let take = n.min(room);
                        target.extend_from_slice(&buf[..take]);
                        if take < n {
                            guard.truncated = true;
                        }
                    } else {
                        guard.truncated = true;
                    }
                    guard.last_output_at = std::time::Instant::now();
                }
            }
        }
    }
}

pub async fn run_start(
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
    let (vault_slug, state) = match host.snapshot_target(slug).await {
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
    }) || payload.env_literals.len() > 64
        || payload.env_literals.iter().any(|(k, v)| {
            !valid_env_name(k)
                || k.to_ascii_uppercase().starts_with("BALUARD_")
                || v.len() > 4096
                || v.contains('\0')
        })
    {
        return err_response("agent injection is invalid or outside the approved items");
    }

    let stdin_bytes = match payload.stdin_b64.as_deref() {
        Some(encoded) => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(bytes) if bytes.len() <= MAX_AGENT_OUTPUT => Some(bytes),
                Ok(_) => return err_response("agent stdin exceeds 1 MiB limit"),
                Err(_) => return err_response("invalid base64 stdin payload"),
            }
        }
        None => None,
    };
    let timeout_dur = match payload.timeout_secs {
        Some(0) => MAX_AGENT_COMMAND_TIMEOUT,
        Some(secs) => Duration::from_secs(secs).min(MAX_AGENT_COMMAND_TIMEOUT),
        None => AGENT_COMMAND_TIMEOUT,
    };

    if let Err(error) = crate::agent_audit::append(
        &baluard_core::paths::data_dir(),
        "run_started",
        &vault_slug,
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
        let value = match resolve_item_field(&state, &injection.item_id, &injection.field).await {
            Ok(v) => v,
            Err(e) => return err_response(e),
        };
        values.push((injection.name.clone(), value));
    }

    let mut command = tokio::process::Command::new(&payload.argv[0]);
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
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BALUARD_") {
            command.env_remove(key);
        }
    }
    for (name, value) in &payload.env_literals {
        command.env(name, value);
    }
    for (name, value) in &values {
        command.env(name, value.as_str());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return err_response(format!("agent command could not start: {e}")),
    };
    if let Some(bytes) = stdin_bytes {
        if let Some(mut child_stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = child_stdin.write_all(&bytes).await;
            let _ = child_stdin.shutdown().await;
        }
    }
    let child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return err_response("agent command stdout is unavailable"),
    };
    let child_stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => return err_response("agent command stderr is unavailable"),
    };
    let pid = child.id();
    let secrets: Vec<Zeroizing<String>> = values.iter().map(|(_, v)| v.clone()).collect();
    let session = std::sync::Arc::new(std::sync::Mutex::new(StreamingRunSession {
        peer: peer.clone(),
        pid,
        secrets,
        stdout_buf: Vec::new(),
        stderr_buf: Vec::new(),
        last_output_at: std::time::Instant::now(),
        stdout_closed: false,
        stderr_closed: false,
        done: false,
        status: None,
        signal: None,
        truncated: false,
    }));
    let run_id = uuid::Uuid::new_v4().to_string();
    if let Ok(mut map) = STREAMING_RUNS.lock() {
        map.insert(run_id.clone(), std::sync::Arc::clone(&session));
    }

    let stdout_task = tokio::spawn(pump_stream_to_session(
        child_stdout,
        std::sync::Arc::clone(&session),
        false,
    ));
    let stderr_task = tokio::spawn(pump_stream_to_session(
        child_stderr,
        std::sync::Arc::clone(&session),
        true,
    ));
    let audit_peer = peer.clone();
    let audit_items = verdict.grant_item_ids.clone();
    let session_wait = std::sync::Arc::clone(&session);
    tokio::spawn(async move {
        let (exit_code, exit_signal) = match tokio::time::timeout(timeout_dur, child.wait()).await {
            Ok(Ok(status)) => {
                #[cfg(unix)]
                let sig = {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal()
                };
                #[cfg(not(unix))]
                let sig: Option<i32> = None;
                let code = match (status.code(), sig) {
                    (Some(c), _) => c,
                    (None, Some(s)) => 128 + s,
                    (None, None) => -1,
                };
                (code, sig)
            }
            Ok(Err(_)) => (-1, None),
            Err(_) => {
                kill_process_group(&child);
                let _ = child.kill().await;
                (-1, Some(9))
            }
        };
        let _ = tokio::time::timeout(AGENT_DRAIN_GRACE, stdout_task).await;
        let _ = tokio::time::timeout(AGENT_DRAIN_GRACE, stderr_task).await;
        if let Ok(mut guard) = session_wait.lock() {
            guard.done = true;
            guard.status = Some(exit_code);
            guard.signal = exit_signal;
            guard.pid = None;
        }
        if let Err(error) = crate::agent_audit::append(
            &baluard_core::paths::data_dir(),
            "run_finished",
            &vault_slug,
            &audit_peer,
            None,
            None,
            &audit_items,
            &format!("exit:{exit_code}"),
        ) {
            eprintln!("agent audit: {error}");
        }
    });
    payload.argv.zeroize();
    ok_resp(serde_json::json!({"run_id": run_id}).to_string(), None)
}

pub async fn run_poll(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&PeerBinding>,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let payload: RunIdPayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => return err_response(format!("Invalid agent run_poll: {e}")),
    };
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        None
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
    let session = STREAMING_RUNS
        .lock()
        .ok()
        .and_then(|map| map.get(&payload.run_id).cloned());
    let Some(session) = session else {
        return err_response("agent run session not found");
    };
    let (done, status, signal, truncated, stdout, stderr, remove) = {
        let Ok(mut guard) = session.lock() else {
            return err_response("agent run session lock poisoned");
        };
        if guard.peer.pid != peer.pid && !pid_in_process_tree(&guard.peer, &chain) {
            return err_response("agent run session belongs to another process");
        }
        let idle = guard.last_output_at.elapsed() >= Duration::from_millis(100);
        let flush_out = guard.done || guard.stdout_closed || idle;
        let flush_err = guard.done || guard.stderr_closed || idle;
        let secrets = guard.secrets.clone();
        let out = drain_scrubbed_buf(&mut guard.stdout_buf, &secrets, flush_out);
        let err = drain_scrubbed_buf(&mut guard.stderr_buf, &secrets, flush_err);
        let fully_drained =
            guard.done && guard.stdout_buf.is_empty() && guard.stderr_buf.is_empty();
        (
            guard.done,
            guard.status,
            guard.signal,
            guard.truncated,
            out,
            err,
            fully_drained,
        )
    };
    if remove {
        if let Ok(mut map) = STREAMING_RUNS.lock() {
            map.remove(&payload.run_id);
        }
    }
    ok_resp(
        serde_json::json!({
            "done": done,
            "status": status,
            "signal": signal,
            "truncated": truncated,
            "stdout": stdout,
            "stderr": stderr,
        })
        .to_string(),
        None,
    )
}

pub async fn run_signal(
    req: &GatewayRequest,
    host: &SharedVaultHost,
    peer: Option<&PeerBinding>,
) -> GatewayResponse {
    let Some(peer) = peer else {
        return err_response("agent peer identity is unavailable");
    };
    let payload: RunSignalPayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => return err_response(format!("Invalid agent run_signal: {e}")),
    };
    if !matches!(payload.signal, 1 | 2 | 10 | 12 | 15) {
        return err_response("unsupported signal");
    }
    let slug = if !req.slug.is_empty() {
        Some(req.slug.as_str())
    } else {
        None
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
    let session = STREAMING_RUNS
        .lock()
        .ok()
        .and_then(|map| map.get(&payload.run_id).cloned());
    let Some(session) = session else {
        return ok_resp(serde_json::json!({"delivered": false}).to_string(), None);
    };
    let pid = session.lock().ok().and_then(|guard| guard.pid);
    #[cfg(unix)]
    if let Some(pid) = pid {
        // SAFETY: `pid` is the live process-group leader spawned with
        // `process_group(0)` above and validated against the caller's token.
        unsafe {
            libc::killpg(pid as libc::pid_t, payload.signal as libc::c_int);
        }
        return ok_resp(serde_json::json!({"delivered": true}).to_string(), None);
    }
    let _ = pid;
    ok_resp(serde_json::json!({"delivered": false}).to_string(), None)
}
