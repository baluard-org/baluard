//! `baluard-nmh` — the browser-extension native messaging host.
//!
//! Stateless stdio <-> socket relay between a browser extension (MV3) and the
//! running `baluard-daemon`. The browser spawns this binary via the native
//! messaging host manifest; it reads length-prefixed JSON on stdin, forwards
//! each request to the daemon's 0600 socket (varint-prefixed protobuf), and
//! writes the response back as length-prefixed JSON on stdout.
//!
//! See `docs/adr/0092-browser-extension.md` §8 for the full design.
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
/// development we can tee our trace to the platform log dir. Hard-gated
/// behind `BALUARD_DEBUG=1` (audit C9: never on in user environments),
/// located via `baluard_core::paths::log_dir()` (honors `BALUARD_LOG_DIR`),
/// never in world-writable /tmp. Creation uses create_new + 0600; append
/// fallback runs only when the existing entry is a regular file, so a
/// pre-planted symlink at the log path is never followed.
static DEBUG_LOG: std::sync::OnceLock<std::sync::Mutex<std::fs::File>> = std::sync::OnceLock::new();

fn init_debug_log_file() {
    if std::env::var("BALUARD_DEBUG").ok().as_deref() != Some("1") {
        return;
    }
    let dir = baluard_core::paths::log_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("baluard-nmh.debug.log");

    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
    };
    #[cfg(not(unix))]
    let created = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path);

    let file = match created {
        // Fresh file created owner-only; keep the handle. Single writer
        // (one Mutex), so writes append in practice.
        Ok(f) => f,
        Err(_) => {
            // Entry exists: append only if it is a regular file. A symlink
            // at the path is refused — never followed (audit C9).
            match std::fs::symlink_metadata(&path) {
                Ok(md) if md.file_type().is_file() => {}
                _ => return,
            }
            match std::fs::OpenOptions::new().append(true).open(&path) {
                Ok(f) => f,
                Err(_) => return,
            }
        }
    };
    let _ = DEBUG_LOG.set(std::sync::Mutex::new(file));
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
    #![allow(dead_code)] // generated
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
        let mid = msg
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let maction = msg
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
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
                dlog(&format!(
                    "[baluard-nmh] wrote response for action='{maction}'"
                ));
            }
        });
        if let Ok(mut w) = workers.lock() {
            // Drop completed handles so a long browser session doesn't
            // accumulate one Vec entry (and its output slot) per message.
            w.retain(|h| !h.is_finished());
            w.push(handle);
        }
    }

    // Drain in-flight workers so pending responses reach the browser before
    // exit. Cap the wait so a wedged/long-running ceremony (e.g. pair_complete
    // held 120s) can't keep a dead NMH process alive after the browser left;
    // nobody is reading the response once the port closed anyway. JoinHandle
    // has no join_timeout, so we race each join against a deadline thread.
    let pending: Vec<_> = workers
        .lock()
        .map(|mut w| std::mem::take(&mut *w))
        .unwrap_or_default();
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
        dlog(&format!(
            "[baluard-nmh] denied non-allowlisted action '{action}'"
        ));
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

    // Forward to the daemon, transparently recovering from a stale bridge
    // token (daemon restart / revoke / expiry). `forward_with_reauth` does
    // one cache-drop + reauth + retry on `STALE_TOKEN_ERROR`.
    dlog(&format!(
        "[baluard-nmh] forwarding action='{action}' is_bootstrap={is_bootstrap}"
    ));
    let (resp, code) = if is_bootstrap {
        // Bootstrap (pairing ceremony) skips the bridge token entirely — no
        // token to go stale, so no retry path applies.
        match forward(&action, payload, &token) {
            Ok(r) => {
                let c = code_for(&r);
                (r, c)
            }
            Err(e) => {
                dlog(&format!("[baluard-nmh] forward error: {e}"));
                return err(id, &e.to_string(), "no-daemon");
            }
        }
    } else {
        forward_with_reauth(&action, payload, &token)
    };
    dlog(&format!(
        "[baluard-nmh] forward ok success={} action='{action}'",
        resp.success
    ));
    serde_json::json!({
        "id": id,
        "ok": resp.success,
        "payload": resp.payload,
        "error": if resp.success { "".to_string() } else { resp.error_message.clone() },
        "code": code,
    })
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

/// Serializes the stale-token reauth path. The main loop spawns one OS
/// thread per inbound stdio message, so a popup that fires several bridge
/// actions at once (e.g. `bridge.match` + `sync.autosync_status`) would race
/// into `resolve_token()` and each trigger a redundant `bridge.reauth`
/// round-trip on a daemon restart. Server-side reauth is idempotent within
/// TTL (correctness is fine), but collapsing them to one reauth cuts the
/// redundant socket round-trips + log noise. Held only across the
/// cache-drop + reauth + cache-fill, never across the actual action forward
/// (that runs per-thread, outside the lock).
static REAUTH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    // Read the pairing secrets from the file (read-only — daemon is the
    // sole writer). One NMH binary serves every paired browser, so try
    // each secret until one reauths instead of assuming pairings[0].
    let pf = PairingFile::load().map_err(|_| ResolveError::NotPaired)?;
    if pf.pairings.is_empty() {
        return Err(ResolveError::NotPaired);
    }
    for entry in &pf.pairings {
        let secret = &entry.secret;
        let resp = match forward(
            "bridge.reauth",
            &serde_json::json!({ "secret": secret }).to_string(),
            "",
        ) {
            Ok(r) => r,
            // Daemon unreachable: no secret choice can fix that.
            Err(_) => return Err(ResolveError::NoDaemon),
        };
        if !resp.success {
            // Wrong secret (revoked or another browser's row): try the next.
            continue;
        }
        let payload: serde_json::Value =
            serde_json::from_str(&resp.payload).map_err(|_| ResolveError::Locked)?;
        let token = payload["token"]
            .as_str()
            .ok_or(ResolveError::Locked)?
            .to_string();
        *TOKEN_CACHE.lock().unwrap() = Some(token.clone());
        return Ok(token);
    }
    Err(ResolveError::NotPaired)
}

/// Drop the cached bridge token and re-resolve one (reauth via the pairing
/// file). Serialized by `REAUTH_LOCK` so a burst of bridge actions hitting a
/// stale token simultaneously collapses to a single `bridge.reauth`
/// round-trip instead of N. Returns the fresh token, or the original
/// `ResolveError` (not-paired / no-daemon / locked) if the pairing is gone or
/// the daemon is unreachable.
fn refresh_token() -> Result<String, ResolveError> {
    let _guard = REAUTH_LOCK.lock().unwrap();
    // Drop the stale cached token; resolve_token will then reauth.
    *TOKEN_CACHE.lock().unwrap() = None;
    dlog("[baluard-nmh] stale bridge token; re-authing via bridge.reauth");
    resolve_token()
}

/// True when the daemon's response means the bridge token attached to this
/// request no longer verifies. Two shapes: the `bridge.*` sentinel, and the
/// per-vault session rejection a popup action (`vault.get`,
/// `cipher.totp_code`) collects after falling through the bridge gate - a
/// LIVE bridge token delegates with the vault's current session token, so
/// that rejection can only mean the token itself is dead (daemon restart,
/// revoke, expiry). Mirrors the runtime's message at state.rs; if that text
/// changes, this predicate must change with it.
fn is_stale_bridge_failure(error: &str) -> bool {
    error == baluard_core::bridge::STALE_TOKEN_ERROR
        || error == "Invalid session token. Re-unlock the vault."
}

/// Forward an allowlisted bridge action to the daemon, transparently
/// recovering from a stale bridge token. The daemon's live token map is
/// in-memory only, so after a daemon restart (or pairing revoke / token
/// expiry) a previously-valid token comes back as `STALE_TOKEN_ERROR`. When
/// that happens exactly ONCE: clear the cache, reauth from the persisted
/// pairing file, and retry. A second stale response (or a reauth failure)
/// is surfaced as-is — no retry loop, so a wedged state can't spiral.
///
/// Returns `(response, code)`: the `GatewayResponse` (success or the final
/// failure after the retry budget) and a friendly NMH code for the popup.
fn forward_with_reauth(
    action: &str,
    payload: &str,
    token: &str,
) -> (GatewayResponse, &'static str) {
    let resp = match forward(action, payload, token) {
        Ok(r) => r,
        Err(e) => {
            dlog(&format!("[baluard-nmh] forward error: {e}"));
            // I/O failure reaching the daemon -> no-daemon for the popup.
            // Build a failure-shaped GatewayResponse so the caller is uniform.
            let resp = GatewayResponse {
                success: false,
                payload: String::new(),
                error_message: e.to_string(),
                session_token: String::new(),
            };
            return (resp, "no-daemon");
        }
    };

    // Stale-token recovery: exactly one retry.
    if !resp.success && is_stale_bridge_failure(&resp.error_message) {
        match refresh_token() {
            Ok(new_token) => {
                dlog(&format!(
                    "[baluard-nmh] reauth ok; retrying action='{action}'"
                ));
                match forward(action, payload, &new_token) {
                    Ok(retry) => {
                        let c = code_for(&retry);
                        return (retry, c);
                    }
                    Err(e) => {
                        dlog(&format!("[baluard-nmh] retry forward error: {e}"));
                        let r = GatewayResponse {
                            success: false,
                            payload: String::new(),
                            error_message: e.to_string(),
                            session_token: String::new(),
                        };
                        return (r, "no-daemon");
                    }
                }
            }
            Err(code) => {
                // Reauth itself failed (pairing gone / daemon down). Surface
                // the resolve error as the response so the popup sees
                // not-paired / no-daemon / locked.
                dlog(&format!(
                    "[baluard-nmh] reauth after stale token failed: {code}"
                ));
                let r = GatewayResponse {
                    success: false,
                    payload: String::new(),
                    error_message: code.to_string(),
                    session_token: String::new(),
                };
                return (r, code.as_str());
            }
        }
    }

    let code = code_for(&resp);
    (resp, code)
}

/// Map a daemon `GatewayResponse` to a friendly NMH code for the popup.
/// Mirrors the inline logic this replaced (locked detection + denied
/// fallback) so popup routing is unchanged on the happy path.
fn code_for(resp: &GatewayResponse) -> &'static str {
    if resp.success {
        "ok"
    } else if resp.error_message.contains("locked") || resp.error_message.contains("Unlock") {
        "locked"
    } else {
        "denied"
    }
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

#[cfg(test)]
mod tests {
    //! Unit tests for the baluard-nmh bridge. Covers:
    //! - stdio frame read/write (length-prefixed JSON over stdin/stdout)
    //! - varint encode/decode (daemon-side framing)
    //! - handle_message dispatch across all short-circuit paths
    //!
    //! The full forward-to-daemon path is exercised via the daemon's own test
    //! suite once a fake-daemon fixture lands. For now we pin every path that
    //! can be reached without a live daemon, plus the protocol primitives
    //! that the browser-ext integration tests depend on.

    use super::*;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    /// Process-wide BALUARD_DATA_DIR override so `PairingFile::load()` (called
    /// transitively by `resolve_token` for non-bootstrap actions) returns an
    /// empty PairingFile without touching the developer's real config dir.
    /// Initialized lazily on first call. TempDir lives for the whole test
    /// binary's lifetime so all parallel tests see the same override.
    fn nmh_test_env() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let tmp = tempfile::tempdir().expect("nmh test tempdir");
            let path = tmp.path().to_path_buf();
            // Leak the TempDir so it's not dropped while tests run.
            std::mem::forget(tmp);
            // SAFETY: tests run single-threaded at this init point (OnceLock
            // serializes the first call) and we never read BALUARD_DATA_DIR
            // concurrently with the set.
            unsafe {
                std::env::set_var("BALUARD_DATA_DIR", &path);
            }
            path
        })
    }

    #[test]
    fn stale_detection_covers_both_daemon_shapes() {
        assert!(is_stale_bridge_failure("stale bridge token"));
        assert!(is_stale_bridge_failure(
            "Invalid session token. Re-unlock the vault."
        ));
        assert!(!is_stale_bridge_failure(
            "Vault 'work' is not open in the daemon."
        ));
        assert!(!is_stale_bridge_failure("Incorrect master password."));
        assert!(!is_stale_bridge_failure(""));
    }

    // ── read_message ──

    #[test]
    fn read_message_happy() {
        let body = br#"{"action":"ping","id":"abc"}"#;
        let mut input = Vec::new();
        input.extend_from_slice(&(body.len() as u32).to_ne_bytes());
        input.extend_from_slice(body);
        let mut cur = Cursor::new(input);
        let msg = read_message(&mut cur).expect("read").expect("not eof");
        assert_eq!(msg["action"], "ping");
        assert_eq!(msg["id"], "abc");
    }

    #[test]
    fn read_message_clean_eof() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        let msg = read_message(&mut cur).expect("read");
        assert!(msg.is_none(), "empty stdin -> Ok(None)");
    }

    #[test]
    fn read_message_oversized_rejected() {
        // Length prefix claims 1 MiB but no body follows. read_exact on the
        // body will surface UnexpectedEof; we cap BEFORE reading the body so
        // the rejection happens at length-parse time, not at body read.
        let too_big = (MAX_REQUEST_BYTES + 1) as u32;
        let mut input = Vec::new();
        input.extend_from_slice(&too_big.to_ne_bytes());
        let mut cur = Cursor::new(input);
        let err = read_message(&mut cur).expect_err("must reject oversize");
        assert!(
            err.to_string().contains("request too large"),
            "expected oversize error, got: {err}"
        );
    }

    #[test]
    fn read_message_malformed_json_errors() {
        let body = b"{not valid json";
        let mut input = Vec::new();
        input.extend_from_slice(&(body.len() as u32).to_ne_bytes());
        input.extend_from_slice(body);
        let mut cur = Cursor::new(input);
        read_message(&mut cur).expect_err("must reject non-JSON");
    }

    // ── write_frame_bytes round-trip ──

    #[test]
    fn write_frame_bytes_round_trip() {
        let body = br#"{"hello":"world"}"#;
        let mut buf: Vec<u8> = Vec::new();
        write_frame_bytes(&mut buf, body).expect("write");
        // First 4 bytes are native-endian length
        let len = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, body.len());
        assert_eq!(&buf[4..], body);
    }

    // ── varint round-trip ──

    #[test]
    fn varint_round_trip() {
        for &value in &[
            0u64,
            1,
            127,             // 1 byte
            128,             // 2 bytes (first has continuation)
            16383,           // 2 bytes
            16384,           // 3 bytes
            u32::MAX as u64, // 5 bytes
            u64::MAX,        // 10 bytes
        ] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let (decoded, consumed) = decode_varint(&buf).expect("decode");
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, buf.len(), "consumed whole buffer for {value}");
        }
    }

    #[test]
    fn varint_truncated_rejected() {
        // First byte has continuation bit set, second byte missing.
        let truncated = [0xFFu8];
        assert!(decode_varint(&truncated).is_err());
    }

    // ── handle_message ──

    #[test]
    fn handle_message_ping_returns_version_handshake() {
        // Ping must work without a daemon, pairing, or socket.
        let resp = handle_message(serde_json::json!({
            "id": "req-1",
            "action": "ping",
        }));
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["id"], "req-1");
        let payload: serde_json::Value =
            serde_json::from_str(resp["payload"].as_str().unwrap()).expect("payload json");
        assert_eq!(payload["nmh_version"], env!("CARGO_PKG_VERSION"));
        // BALUARD_VERSION is a u8, serialized as a JSON number.
        assert_eq!(
            payload["proto_version"],
            baluard_core::BALUARD_VERSION as u64
        );
    }

    #[test]
    fn handle_message_missing_action() {
        let resp = handle_message(serde_json::json!({ "id": "x" }));
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], "proto");
        assert!(resp["error"].as_str().unwrap().contains("action"));
    }

    #[test]
    fn handle_message_unknown_action_denied() {
        // "totally.bogus" is not in BRIDGE_ALLOWED_ACTIONS nor in
        // BOOTSTRAP_ACTIONS, so the defense-in-depth allowlist rejects it
        // BEFORE touching the socket or pairing file.
        let resp = handle_message(serde_json::json!({
            "id": "x",
            "action": "totally.bogus",
            "payload": "{}",
        }));
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], "denied");
        assert!(resp["error"].as_str().unwrap().contains("not permitted"));
    }

    #[test]
    fn handle_message_malformed_payload_rejected() {
        // Pick an action that's in the allowlist so we reach payload
        // validation. `vault.get` is in BRIDGE_ALLOWED_ACTIONS.
        nmh_test_env(); // ensure no pairing file in tempdir
        let resp = handle_message(serde_json::json!({
            "id": "x",
            "action": "vault.get",
            "payload": "this is { not json",
        }));
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], "proto");
        assert!(resp["error"].as_str().unwrap().contains("valid JSON"));
    }

    #[test]
    fn handle_message_allowlisted_action_without_pairing_returns_not_paired() {
        // Allowlisted action + no pairing file in tempdir -> resolve_token
        // fails with NotPaired before any socket call.
        nmh_test_env();
        let resp = handle_message(serde_json::json!({
            "id": "x",
            "action": "vault.get",
            "payload": "{}",
        }));
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], "not-paired");
    }

    #[test]
    fn handle_message_bootstrap_action_skips_token_but_still_forwards() {
        // bridge.pair_complete is bootstrap: no pairing needed yet, but the
        // daemon still has to be reached. With no daemon running, the forward
        // path returns code "no-daemon".
        nmh_test_env();
        let resp = handle_message(serde_json::json!({
            "id": "x",
            "action": "bridge.pair_complete",
            "payload": "{}",
        }));
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["code"], "no-daemon");
    }

    // ── Constants sanity ──

    #[test]
    fn request_size_cap_smaller_than_native_messaging_max() {
        // Chrome allows 64 MiB ext->host. We cap at 64 KiB. Pin the gap so a
        // future "let's bump it" PR can't accidentally uncap it.
        const { assert!(MAX_REQUEST_BYTES < 64 * 1024 * 1024) };
        const { assert!(MAX_RESPONSE_BYTES <= 1024 * 1024) }; // Chrome's host->ext hard cap
    }

    // ── Stale-token recovery contract ──
    //
    // The full `forward_with_reauth` retry path (cache-drop + reauth + retry)
    // needs a fake-daemon socket fixture, which doesn't exist yet (see the
    // module-level test note). These tests pin the pieces that ARE reachable
    // without a live daemon:
    //   - the STALE_TOKEN_ERROR sentinel value (the NMH matches it byte-for-byte
    //     against the daemon's error_message, so a drift here silently breaks
    //     recovery)
    //   - `code_for` mapping (pure function, drives the popup's UI state)

    #[test]
    fn stale_token_sentinel_matches_daemon_constant() {
        // The NMH matches this string byte-for-byte to trigger reauth. If the
        // daemon's const changes and this doesn't, recovery breaks silently.
        assert_eq!(
            baluard_core::bridge::STALE_TOKEN_ERROR,
            "stale bridge token"
        );
    }

    #[test]
    fn code_for_success_is_ok() {
        let resp = GatewayResponse {
            success: true,
            payload: String::new(),
            error_message: String::new(),
            session_token: String::new(),
        };
        assert_eq!(code_for(&resp), "ok");
    }

    #[test]
    fn code_for_locked_detection() {
        // Daemon error strings that mention "locked" / "Unlock" map to the
        // popup's locked state (surfaces "unlock the vault" UI).
        for msg in ["locked", "Vault locked", "please Unlock first"] {
            let resp = GatewayResponse {
                success: false,
                payload: String::new(),
                error_message: msg.to_string(),
                session_token: String::new(),
            };
            assert_eq!(code_for(&resp), "locked", "msg={msg}");
        }
    }

    #[test]
    fn code_for_other_failure_is_denied() {
        // Any non-success, non-locked failure (including the stale-token
        // sentinel before forward_with_reauth intercepts it) maps to denied.
        let resp = GatewayResponse {
            success: false,
            payload: String::new(),
            error_message: baluard_core::bridge::STALE_TOKEN_ERROR.to_string(),
            session_token: String::new(),
        };
        assert_eq!(code_for(&resp), "denied");
    }
}
