//! Daemon-spawn fixture: launches a real `baluard-daemon` binary against a
//! per-test temp data dir + Unix socket path, then exercises routes over
//! the protobuf wire protocol. Exercises the full stack: CLI args -> CLI
//! flag parsing -> handler dispatch -> VaultState -> socket framing ->
//! response back to the client. Pinning this stack catches regressions
//! the unit-level state tests can't (route lookup, token gating, varint
//! framing, daemon binary smoke).

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

        let mut stream = UnixStream::connect(&self.socket_path).expect("connect to daemon socket");
        let mut header = Vec::with_capacity(10);
        encode_varint(body.len() as u64, &mut header);
        use std::io::Write;
        stream.write_all(&header).expect("write header");
        stream.write_all(&body).expect("write body");
        stream.flush().expect("flush");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

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
    assert!(
        resp.success,
        "ping must succeed; error={}",
        resp.error_message
    );
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

// ── End-to-end: spawn daemon against a pre-created vault ──

/// A daemon handle that ships with a pre-created vault at a known path.
/// Use this for tests that need to exercise vault-scoped routes.
struct VaultedDaemon {
    daemon: DaemonHandle,
    #[allow(dead_code)]
    vault_dir: tempfile::TempDir,
    master_password: &'static str,
    /// Session token returned by the daemon after `vault.unlock`. Set
    /// automatically by `unlock_vault()` so subsequent requests carry it.
    token: Option<String>,
}

fn spawn_with_vault() -> VaultedDaemon {
    use baluard_core::vault::creation::VaultCreator;
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    let vault_path = vault_dir.path().to_path_buf();
    VaultCreator::new(&vault_path, "spawn-test-password", "spawn-fixture")
        .execute()
        .expect("vault creation");
    let data_dir = tempfile::tempdir().expect("data tempdir");
    // Redirect the registry/data dir to our temp via env var. This is
    // process-global but tests that use this helper run sequentially per
    // process (cargo test by default), and the daemon subprocess inherits
    // the env so it also reads from the same data dir.
    // SAFETY: each #[test] in this file runs single-threaded with respect
    // to the data_dir reader; the env var is set before the registry is
    // touched and unset at the end via TempDir drop.
    // Use load_from / save_to (explicit path) so the test process NEVER
    // reads the process-global BALUARD_DATA_DIR env var. That env var is
    // set only on the daemon subprocess via Command::env() below — which
    // is race-free because Command::env() sets the value in the CHILD's
    // env table at spawn time. The earlier set_var pattern raced with
    // other test threads in the same binary.
    let registry_path = data_dir.path().join("registry.json");
    {
        use baluard_core::vault::registry::{VaultEntry, VaultRegistry};
        let mut reg = VaultRegistry::load_from(&registry_path).unwrap_or_default();
        reg.add(VaultEntry {
            slug: "spawn-test".into(),
            display_name: "Spawn Test".into(),
            path: vault_path.clone(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: uuid::Uuid::new_v4(),
        })
        .expect("registry add");
        reg.save_to(&registry_path).expect("registry save");
    }
    // Now spawn the daemon pointed at the data dir.
    let socket_path = data_dir.path().join("baluard.sock");
    let mut child = Command::new(DAEMON_BIN)
        .arg("--socket")
        .arg(&socket_path)
        .env("BALUARD_DATA_DIR", data_dir.path())
        .env_remove("BALUARD_SOCKET")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn baluard-daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon did not create socket within 5s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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
    VaultedDaemon {
        daemon: DaemonHandle {
            _child: child,
            socket_path,
            _data_dir: data_dir,
        },
        vault_dir,
        master_password: "spawn-test-password",
        token: None,
    }
}

impl VaultedDaemon {
    /// Send vault.unlock and stash the returned session token for future
    /// calls in this handle.
    fn unlock_vault(&mut self) -> GatewayResponse {
        let unlock_payload = serde_json::json!({ "password": self.master_password }).to_string();
        let resp = self.request_with_token("vault.unlock", &unlock_payload);
        if resp.success && !resp.session_token.is_empty() {
            self.token = Some(resp.session_token.clone());
        }
        resp
    }
}

impl VaultedDaemon {
    fn request_with_token(&self, action: &str, payload: &str) -> GatewayResponse {
        // The token lives on the VaultedDaemon struct (set after unlock).
        // We send the stored token on every request so the daemon can
        // verify it. Initial value is empty (no unlock yet).
        let req = GatewayRequest {
            action: action.to_string(),
            payload: payload.to_string(),
            session_token: self.token.clone().unwrap_or_default(),
            slug: "spawn-test".into(),
        };
        let body = req.encode_to_vec();
        let mut stream = UnixStream::connect(&self.daemon.socket_path).expect("connect");
        let mut header = Vec::with_capacity(10);
        encode_varint(body.len() as u64, &mut header);
        use std::io::Write;
        stream.write_all(&header).unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = Vec::with_capacity(4096);
        use std::io::Read;
        stream.read_to_end(&mut buf).unwrap();
        let (resp_len, offset) = decode_varint(&buf).expect("decode varint");
        let end = offset + resp_len as usize;
        GatewayResponse::decode(&buf[offset..end]).expect("decode GatewayResponse")
    }
}

#[test]
fn end_to_end_unlock_then_list() {
    let mut v = spawn_with_vault();
    // 1. vault.unlock with the master password.
    let unlock_payload = serde_json::json!({
        "password": v.master_password,
    })
    .to_string();
    let resp = v.unlock_vault();
    assert!(
        resp.success,
        "vault.unlock must succeed; error={}",
        resp.error_message
    );
    // The daemon returns the session token in the response itself (NOT
    // via a sidecar .tok file). Verify the token is non-empty.
    assert!(
        !resp.session_token.is_empty(),
        "session token returned in response"
    );

    // 2. vault.list with the token returns the empty ciphers array.
    let resp = v.request_with_token("vault.list", "");
    assert!(
        resp.success,
        "vault.list with token must succeed; error={}",
        resp.error_message
    );
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    let ciphers = parsed["ciphers"].as_array().expect("ciphers array");
    assert!(ciphers.is_empty(), "fresh vault has zero ciphers");
}

#[test]
fn end_to_end_unlock_then_add_cipher() {
    let mut v = spawn_with_vault();
    // Unlock.
    v.unlock_vault();
    // (token stashed on the handle)
    // Add a login cipher.
    let add_payload = serde_json::json!({
        "name": "GitHub",
        "kind": {
            "type": "login",
            "data": {
                "username": "octocat",
                "password": "hunter2",
                "uris": [],
                "totp_uri": null,
                "autofill_on_page_load": false,
                "password_revision_date": null,
                "favicon": null,
                "fido2_credentials": null
            }
        },
        "folder_id": null,
        "favorite": false,
        "notes": null,
        "custom_fields": [],
        "created_at": null,
        "password_history": [],
        "attachments": [],
        "archived": false,
        "reprompt": false,
        "tags": ["work"]
    })
    .to_string();
    let resp = v.request_with_token("vault.add", &add_payload);
    assert!(
        resp.success,
        "vault.add must succeed; error={}",
        resp.error_message
    );
    // The response payload is the cipher_id (UUID) as a raw string — NOT
    // JSON-encoded. Confirm it's non-empty and looks like a UUID.
    let trimmed = resp.payload.trim().trim_matches('"');
    assert!(!trimmed.is_empty(), "vault.add payload non-empty");
    assert!(
        trimmed.len() >= 32 && trimmed.contains('-'),
        "vault.add payload looks like a UUID; got: {trimmed}"
    );

    // List confirms the cipher is there.
    let resp = v.request_with_token("vault.list", "");
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    let ciphers = parsed["ciphers"].as_array().expect("ciphers");
    assert_eq!(ciphers.len(), 1);
    assert_eq!(ciphers[0]["name"], "GitHub");
    assert_eq!(ciphers[0]["username"], "octocat");
}

#[test]
fn end_to_end_unauth_list_fails() {
    let mut v = spawn_with_vault();
    // Unlock so the daemon has a vault in the map.
    let unlock_payload = serde_json::json!({ "password": v.master_password }).to_string();
    v.request_with_token("vault.unlock", &unlock_payload);
    // Send vault.list with an explicit WRONG token.
    // (no request_with_token call here — explicit wrong-token test)
    let req = GatewayRequest {
        action: "vault.list".into(),
        payload: String::new(),
        session_token: "wrong-token-12345".into(),
        slug: "spawn-test".into(),
    };
    let body = req.encode_to_vec();
    let mut stream = UnixStream::connect(&v.daemon.socket_path).expect("connect");
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    use std::io::Write;
    stream.write_all(&header).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = Vec::with_capacity(4096);
    use std::io::Read;
    stream.read_to_end(&mut buf).unwrap();
    let (resp_len, offset) = decode_varint(&buf).expect("decode varint");
    let resp = GatewayResponse::decode(&buf[offset..offset + resp_len as usize]).expect("decode");
    assert!(
        !resp.success,
        "vault.list with wrong token must fail; got payload={}",
        resp.payload
    );
}
