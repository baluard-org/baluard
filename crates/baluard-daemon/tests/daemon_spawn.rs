//! Daemon-spawn fixture: launches a real `baluard-daemon` binary against a
//! per-test temp data dir + Unix socket path, then exercises routes over
//! the protobuf wire protocol. Exercises the full stack: CLI args -> CLI
//! flag parsing -> handler dispatch -> VaultState -> socket framing ->
//! response back to the client. Pinning this stack catches regressions
//! the unit-level state tests can't (route lookup, token gating, varint
//! framing, daemon binary smoke).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::os::unix::net::UnixStream;

use baluard_daemon::proto::{GatewayRequest, GatewayResponse};
use prost::Message;

const DAEMON_BIN: &str = env!("CARGO_BIN_EXE_baluard-daemon");

/// Handle to a running baluard-daemon test instance. Drop kills the process.
struct DaemonHandle {
    _child: Child,
    socket_path: PathBuf,
    _data_dir: tempfile::TempDir,
}

impl DaemonHandle {
    /// Send a request and read the response. Handles varint-length-prefixed
    /// protobuf framing exactly like the CLI client does.
    fn request(&self, action: &str, payload: &str) -> GatewayResponse {
        let req = GatewayRequest {
            action: action.to_string(),
            payload: payload.to_string(),
            session_token: String::new(), // no token — for token-gated tests
            slug: String::new(),
        };
        let body = req.encode_to_vec();

        let mut stream = UnixStream::connect(&self.socket_path)
            .expect("connect to daemon socket");
        let mut header = Vec::with_capacity(10);
        encode_varint(body.len() as u64, &mut header);
        use std::io::Write;
        stream.write_all(&header).expect("write header");
        stream.write_all(&body).expect("write body");
        stream.flush().expect("flush");
        stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");

        let mut buf = Vec::with_capacity(4096);
        use std::io::Read;
        stream.read_to_end(&mut buf).expect("read response");
        assert!(!buf.is_empty(), "daemon returned empty response");
        let (resp_len, offset) = decode_varint(&buf).expect("decode varint");
        let end = offset + resp_len as usize;
        assert!(end <= buf.len(), "response frame truncated");
        GatewayResponse::decode(&buf[offset..end]).expect("decode GatewayResponse")
    }
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

fn decode_varint(data: &[u8]) -> Result<(u64, usize), String> {
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
            return Err("varint overflow".into());
        }
    }
    Err("varint truncated".into())
}

/// Spawn a fresh daemon, wait for the socket to be ready, return a handle.
fn spawn_daemon() -> DaemonHandle {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let socket_path = data_dir.path().join("baluard.sock");

    let mut child = Command::new(DAEMON_BIN)
        .arg("--socket")
        .arg(&socket_path)
        // The daemon doesn't accept --data-dir; instead it honors the
        // BALUARD_DATA_DIR env var (via baluard_core::paths::data_dir).
        .env("BALUARD_DATA_DIR", data_dir.path())
        .env_remove("BALUARD_SOCKET") // don't let a parent process override --socket
        // Quiet stdout/stderr; the daemon logs to env_logger which writes
        // to stderr by default. Tests run with env_logger default so this
        // leaks some logs but doesn't fail.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn baluard-daemon");

    // Poll for the socket file to appear (daemon creates it on startup).
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon did not create socket within 5s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Also wait until the socket actually accepts connections — bind
    // happens before accept loop, so a small extra wait is needed.
    let connect_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if UnixStream::connect(&socket_path).is_ok() {
            break;
        }
        if Instant::now() > connect_deadline {
            let _ = child.kill();
            panic!("daemon socket not accepting connections within 2s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    DaemonHandle {
        _child: child,
        socket_path,
        _data_dir: data_dir,
    }
}

// ── Tests ────────────────────────────────────────────────────

#[test]
fn daemon_starts_and_accepts_connections() {
    let _h = spawn_daemon();
    // If spawn_daemon() didn't panic, the daemon is up + accepting.
}

#[test]
fn daemon_responds_to_ping() {
    let h = spawn_daemon();
    let resp = h.request("ping", "");
    assert!(resp.success, "ping must succeed; error={}", resp.error_message);
    // The ping payload shape is daemon-version-dependent; just confirm it's
    // non-empty (some early versions returned a plain "pong" string, others
    // return JSON). The contract that matters: ping succeeds with no
    // token and no active vault.
    assert!(!resp.payload.is_empty(), "ping returns a non-empty payload");
}

#[test]
fn unknown_action_returns_error_response() {
    let h = spawn_daemon();
    let resp = h.request("totally.bogus.action", "");
    assert!(
        !resp.success,
        "unknown action must return success=false; payload={}",
        resp.payload
    );
    assert!(!resp.error_message.is_empty(), "error message present");
}

#[test]
fn token_gated_route_rejects_no_token() {
    // vault.list is token-gated; sending with empty session_token should
    // be rejected with success=false. The exact error wording varies
    // (token / auth / unauthorized / "no active vault" if there's no
    // vault to even check the token against). Accept any non-success.
    let h = spawn_daemon();
    let resp = h.request("vault.list", "");
    assert!(
        !resp.success,
        "vault.list without token must be rejected; got payload={}",
        resp.payload
    );
    assert!(!resp.error_message.is_empty(), "error message present");
}

#[test]
fn vaults_list_route_does_not_require_token() {
    // vaults.list (with the 's') is a host-level call that lists registered
    // vaults — no token needed.
    let h = spawn_daemon();
    let resp = h.request("vaults.list", "");
    // The fresh data dir has no vaults; the response is still success=true
    // (an empty list is a valid result). The point is: no token-gate.
    assert!(
        resp.success,
        "vaults.list must succeed without token; error={}",
        resp.error_message
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&resp.payload).expect("vaults.list payload is JSON");
    assert!(
        parsed.get("vaults").map(|v| v.is_array()).unwrap_or(false),
        "vaults.list returns {{vaults: []}} on a fresh data dir"
    );
}