//! `baluard-nmh` — the browser-extension native messaging host.
//!
//! Stateless stdio <-> socket relay between a browser extension (MV3) and the
//! running `baluard-daemon`. The browser spawns this binary via the native
//! messaging host manifest; it reads length-prefixed JSON on stdin, forwards
//! each request to the daemon's 0600 socket (varint-prefixed protobuf), and
//! writes the response back as length-prefixed JSON on stdout.
//!
//! See `docs/plan-browser-extension.md` §8 for the full design.
//!
//! ## Defense-in-depth (review X6)
//! - Enforces the SAME allowlist as the daemon (a daemon routing bug isn't
//!   reachable via an action the NMH should never forward).
//! - Hard-caps request size at 64KB (the 64MB ext->host limit is huge).
//! - Rejects non-JSON `payload` before forwarding.
//! - stderr-only logging; NEVER logs payloads (responses contain plaintext).

use std::io::{Read, Write};

use baluard_core::bridge::is_allowed;
use baluard_core::bridge::pairing::PairingFile;

/// Optional debug log file. Chrome doesn't surface NMH stderr, so during
/// development we tee our trace to /tmp/baluard-nmh.debug.log. Always-on
/// while the browser-extension pairing flow is being stabilized.
static DEBUG_LOG: std::sync::OnceLock<std::sync::Mutex<std::fs::File>> =
    std::sync::OnceLock::new();

fn init_debug_log_file() {
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/baluard-nmh.debug.log")
    {
        let _ = DEBUG_LOG.set(std::sync::Mutex::new(f));
    }
}

fn dlog(msg: &str) {
    eprintln!("{msg}");
    if let Some(m) = DEBUG_LOG.get() {
        use std::io::Write;
        if let Ok(mut f) = m.lock() {
            let _ = writeln!(f, "{msg}");
        }
    }
}

mod proto {
    #![allow(dead_code)] // generated; DeviceIdentityEscrow unused here
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

/// Browser -> NMH stdio frame cap. Native messaging allows 64MB ext->host;
/// we cap far lower — no legitimate request is bigger than a vault entry.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// NMH -> browser cap. Browser hard-limits host->ext at 1MB.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Pairing-ceremony bootstrap routes. These are forwarded with NO bridge
/// token (none exists yet — pairing is what mints one). They are NOT vault
/// actions, so they are deliberately absent from BRIDGE_ALLOWED_ACTIONS;
/// this separate list is the NMH's defense-in-depth permit for the ceremony.
const BOOTSTRAP_ACTIONS: &[&str] = &["bridge.pair_complete"];

fn main() {
    // Initialise logging. stderr is the conventional target for NMH (stdout
    // must stay protocol-clean), but Chrome doesn't surface NMH stderr anywhere
    // visible, so during development we ALSO tee to a file for debugging.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .try_init();
    init_debug_log_file();

    if let Err(e) = run() {
        dlog(&format!("[baluard-nmh] fatal: {e:#}"));
        // On fatal error, emit one error frame so the extension sees a clean
        // code rather than a silent disconnect.
        let _ = write_message(
            &serde_json::json!({ "id": null, "ok": false, "error": e.to_string(), "code": "proto" }),
        );
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut stdin = std::io::stdin().lock();
    // stdout is shared across worker threads: each handler that blocks on the
    // daemon (e.g. bridge.pair_complete, held up to 120s for desktop approval)
    // runs on its own thread so the read loop can keep draining stdin. The
    // Mutex serializes the (length-prefix + body) write so frames never
    // interleave. Without this, a single blocking pair_complete would freeze
    // the whole extension (badge updates, other popup actions, etc.) for the
    // full ceremony TTL.
    let stdout = std::sync::Arc::new(std::sync::Mutex::new(std::io::stdout()));
    // In-flight worker handles. On stdin EOF (browser closed the port) we
    // drain these so pending responses are flushed before the process exits;
    // without this, a fast ping could lose the race against main-loop exit.
    let workers: std::sync::Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    loop {
        let msg = match read_message(&mut stdin)? {
            Some(m) => m,
            None => break, // EOF — browser closed the port; finish in-flight work.
        };
        let stdout = stdout.clone();
        let mid = msg.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();
        let maction = msg.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
        dlog(&format!("[baluard-nmh] recv id='{mid}' action='{maction}'"));
        let handle = std::thread::spawn(move || {
            let resp = handle_message(msg);
            let resp_json = match serde_json::to_vec(&resp) {
                Ok(b) => b,
                Err(e) => {
                    dlog(&format!("[baluard-nmh] response encode error: {e}"));
                    return;
                }
            };
            let mut out = stdout.lock().unwrap();
            let write_result = if resp_json.len() > MAX_RESPONSE_BYTES {
                let truncated = serde_json::json!({
                    "id": resp.get("id").cloned().unwrap_or(serde_json::Value::Null),
                    "ok": false,
                    "error": "response too large",
                    "code": "proto",
                });
                write_frame(&mut *out, &truncated)
            } else {
                write_frame_bytes(&mut *out, &resp_json)
            };
            if let Err(e) = write_result {
                dlog(&format!("[baluard-nmh] stdout write error: {e}"));
            } else {
                dlog(&format!("[baluard-nmh] wrote response for action='{maction}'"));
            }
        });
        if let Ok(mut w) = workers.lock() {
            w.push(handle);
        }
    }

    // Drain in-flight workers so pending responses reach the browser before
    // exit. Cap the wait so a wedged/long-running ceremony (e.g. pair_complete
    // held 120s) can't keep a dead NMH process alive after the browser left;
    // nobody is reading the response once the port closed anyway. JoinHandle
    // has no join_timeout, so we race each join against a deadline thread.
    let pending: Vec<_> = workers.lock().map(|mut w| std::mem::take(&mut *w)).unwrap_or_default();
    let grace = std::time::Duration::from_secs(2);
    for h in pending {
        if join_with_timeout(h, grace).is_err() {
            // Timed out: detach the worker so it doesn't block process exit;
            // its response (if any) is already unwritable — browser is gone.
        }
    }
    Ok(())
}

/// Join a thread with a deadline. JoinHandle lacks join_timeout, so we spawn a
/// helper that signals completion via a channel; if the deadline fires first we
/// return Err (the handle is consumed and dropped, detaching the thread).
fn join_with_timeout(
    handle: std::thread::JoinHandle<()>,
    timeout: std::time::Duration,
) -> Result<(), ()> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = handle.join();
        let _ = tx.send(());
    });
    match rx.recv_timeout(timeout) {
        Ok(()) => Ok(()),
        Err(_) => Err(()),
    }
}

/// Write one framed JSON value to stdout (serialize + frame).
fn write_frame(out: &mut impl Write, v: &serde_json::Value) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(v)?;
    write_frame_bytes(out, &bytes)
}

/// Write pre-serialized bytes as one length-prefixed frame.
fn write_frame_bytes(out: &mut impl Write, bytes: &[u8]) -> anyhow::Result<()> {
    out.write_all(&((bytes.len() as u32).to_ne_bytes()))?;
    out.write_all(bytes)?;
    out.flush()?;
    Ok(())
}

/// Dispatch one browser message. Returns the JSON to send back.
fn handle_message(msg: serde_json::Value) -> serde_json::Value {
    let id = msg.get("id").cloned();
    let action = match msg.get("action").and_then(|a| a.as_str()) {
        Some(a) => a.to_string(),
        None => {
            return err(id, "missing 'action'", "proto");
        }
    };

    // Special: ping carries the version handshake (review X5). Does NOT need
    // the daemon; proves the NMH is alive and reports versions.
    if action == "ping" {
        return serde_json::json!({
            "id": id,
            "ok": true,
            "payload": serde_json::json!({
                "nmh_version": env!("CARGO_PKG_VERSION"),
                "proto_version": baluard_core::BALUARD_VERSION,
            }).to_string(),
        });
    }

    // Defense-in-depth: enforce the allowlist BEFORE touching the socket.
    // Bootstrap routes (pairing ceremony) are permit-listed separately: they
    // are NOT vault actions, so they don't belong in BRIDGE_ALLOWED_ACTIONS,
    // but they must be forwardable so pairing can happen at all.
    let is_bootstrap = BOOTSTRAP_ACTIONS.contains(&action.as_str());
    if !is_allowed(&action) && !is_bootstrap {
        dlog(&format!("[baluard-nmh] denied non-allowlisted action '{action}'"));
        return err(id, &format!("action '{action}' not permitted"), "denied");
    }

    let payload = msg.get("payload").and_then(|p| p.as_str()).unwrap_or("");
    // Fail-closed payload validation.
    if !payload.is_empty() && serde_json::from_str::<serde_json::Value>(payload).is_err() {
        return err(id, "payload is not valid JSON", "proto");
    }

    // Resolve a bridge token (reauth if needed). Errors here -> not-paired /
    // no-daemon / locked codes. Bootstrap routes (pairing ceremony) skip
    // this: no pairing exists yet, so there is no token to resolve. The
    // daemon's pair_complete handler needs no token by design.
    let token = if is_bootstrap {
        String::new()
    } else {
        match resolve_token() {
            Ok(t) => t,
            Err(code) => {
                return err(id, &code.to_string(), code.as_str());
            }
        }
    };

    // Forward to the daemon.
    dlog(&format!("[baluard-nmh] forwarding action='{action}' is_bootstrap={is_bootstrap}"));
    match forward(&action, payload, &token) {
        Ok(resp) => {
            dlog(&format!("[baluard-nmh] forward ok success={} action='{action}'", resp.success));
            serde_json::json!({
                "id": id,
                "ok": resp.success,
                "payload": resp.payload,
                "error": if resp.success { "".to_string() } else { resp.error_message.clone() },
                // Map a few daemon error strings to NMH codes for friendly UI.
                "code": if resp.success {
                    "ok"
                } else if resp.error_message.contains("locked") || resp.error_message.contains("Unlock") {
                    "locked"
                } else {
                    "denied"
                },
            })
        },
        Err(e) => {
            dlog(&format!("[baluard-nmh] forward error: {e}"));
            err(id, &e.to_string(), "no-daemon")
        }
    }
}

/// Read one length-prefixed (32-bit native endian) JSON message from stdin.
/// Returns Ok(None) on clean EOF.
fn read_message<R: Read>(r: &mut R) -> anyhow::Result<Option<serde_json::Value>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(serde_json::Value::Null));
    }
    if len > MAX_REQUEST_BYTES {
        anyhow::bail!("request too large: {len} bytes (cap {MAX_REQUEST_BYTES})");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let val: serde_json::Value = serde_json::from_slice(&buf)?;
    Ok(Some(val))
}

/// Write one length-prefixed message to stdout (used only for the fatal-error
/// fallback before the worker-thread runtime is up).
fn write_message(v: &serde_json::Value) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    write_frame(&mut stdout, v)
}

fn err(id: Option<serde_json::Value>, error: &str, code: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "ok": false, "error": error, "code": code })
}

// ── Token resolution ───────────────────────────────────────────────────

/// Cached bridge token (in NMH memory only; dies with the process).
/// Static + Mutex keeps it across stdio messages within one NMH lifetime.
static TOKEN_CACHE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

enum ResolveError {
    NotPaired,
    NoDaemon,
    Locked,
}

impl ResolveError {
    fn as_str(&self) -> &'static str {
        match self {
            ResolveError::NotPaired => "not-paired",
            ResolveError::NoDaemon => "no-daemon",
            ResolveError::Locked => "locked",
        }
    }
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Get a live bridge token, reauth-ing via the daemon if we don't have one.
fn resolve_token() -> Result<String, ResolveError> {
    {
        let cached = TOKEN_CACHE.lock().unwrap();
        if let Some(t) = cached.as_ref() {
            return Ok(t.clone());
        }
    }

    // Read our pairing secret from the file (read-only — daemon is sole writer).
    let pf = PairingFile::load().map_err(|_| ResolveError::NotPaired)?;
    let entry = pf.pairings.first().ok_or(ResolveError::NotPaired)?;
    let secret = entry.secret.clone();

    // bridge.reauth: present the secret, get back a token.
    let resp = forward(
        "bridge.reauth",
        &serde_json::json!({ "secret": secret }).to_string(),
        "",
    )
    .map_err(|_| ResolveError::NoDaemon)?;
    if !resp.success {
        return Err(ResolveError::NotPaired);
    }
    let payload: serde_json::Value =
        serde_json::from_str(&resp.payload).map_err(|_| ResolveError::Locked)?;
    let token = payload["token"]
        .as_str()
        .ok_or(ResolveError::Locked)?
        .to_string();
    *TOKEN_CACHE.lock().unwrap() = Some(token.clone());
    Ok(token)
}

// ── Daemon forwarding (varint-length-prefixed protobuf) ────────────────
//
// Mirrors `crates/baluard-cli/src/client.rs` framing exactly.

fn forward(action: &str, payload: &str, token: &str) -> anyhow::Result<GatewayResponse> {
    use prost::Message;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let socket = baluard_core::paths::socket_path();
    let mut stream = UnixStream::connect(&socket).map_err(|e| anyhow::anyhow!("socket: {e}"))?;
    // Bounded I/O so a stalled daemon can't wedge this worker thread
    // forever (mirrors the desktop client's timeouts). Without this, every
    // browser-triggered forward that hits a starved daemon blocks
    // indefinitely, leaking threads.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| anyhow::anyhow!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| anyhow::anyhow!("set_write_timeout: {e}"))?;

    let req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: token.to_string(),
        slug: String::new(), // bridge tokens are slug-agnostic (Decision 10)
    };
    let body = req.encode_to_vec();

    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    stream.write_all(&header)?;
    stream.write_all(&body)?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf)?;
    if buf.is_empty() {
        anyhow::bail!("daemon closed connection without response");
    }

    let (resp_len, offset) = decode_varint(&buf)?;
    let end = offset + resp_len as usize;
    if end > buf.len() {
        anyhow::bail!("response frame truncated");
    }
    let resp = GatewayResponse::decode(&buf[offset..end])?;
    Ok(resp)
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

fn decode_varint(data: &[u8]) -> anyhow::Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        value |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift >= 70 {
            anyhow::bail!("varint overflow");
        }
    }
    anyhow::bail!("varint truncated");
}
