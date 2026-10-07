//! Diagnostic for vault.add IO error. Spawns a daemon against a
//! pre-created vault, tries vault.add, dumps daemon stderr + vault dir
//! tree on failure. Uses `load_from`/`save_to` (not `load`/`save`) so the
//! test-process side never reads the process-global `BALUARD_DATA_DIR`
//! env var — that was the race a prior review identified.

use baluard_core::vault::creation::VaultCreator;
use baluard_core::vault::registry::{VaultEntry, VaultRegistry};
use baluard_daemon::proto::{GatewayRequest, GatewayResponse};
use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DAEMON_BIN: &str = env!("CARGO_BIN_EXE_baluard-daemon");

/// Panic-safe kill: a test panic unwinds through Drop, so the daemon
/// dies even when the inline cleanup below is skipped. (A hard-killed
/// RUNNER is covered by BALUARD_DAEMON_DIE_WITH_PARENT instead.)
struct ChildGuard(std::process::Child);

impl ChildGuard {
    fn kill_now(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }

    fn take_stderr(&mut self) -> std::process::ChildStderr {
        self.0.stderr.take().expect("daemon stderr piped")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_now();
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

fn request(
    socket: &PathBuf,
    action: &str,
    payload: &str,
    token: &str,
    slug: &str,
) -> GatewayResponse {
    let req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: token.to_string(),
        slug: slug.to_string(),
    };
    let body = req.encode_to_vec();
    let mut stream = UnixStream::connect(socket).expect("connect");
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    stream.write_all(&header).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let (resp_len, offset) = decode_varint(&buf).expect("decode varint");
    let end = offset + resp_len as usize;
    GatewayResponse::decode(&buf[offset..end]).expect("decode GatewayResponse")
}

fn dump_tree(path: &std::path::Path, prefix: &str) -> String {
    let mut out = String::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let meta = e.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            out.push_str(&format!(
                "{}{} {}\n",
                prefix,
                if is_dir { "d " } else { "f " },
                name
            ));
            if is_dir {
                out.push_str(&dump_tree(&p, &format!("{}  ", prefix)));
            }
        }
    }
    out
}

#[test]
fn diag_vault_add_with_explicit_path_registry() {
    // 1. Create a real vault via VaultCreator.
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    let vault_path = vault_dir.path().to_path_buf();
    VaultCreator::new(&vault_path, "diag-password", "diag-fixture")
        .execute()
        .expect("vault creation");

    // 2. Sandbox data dir + register the vault there. Use load_from /
    //    save_to (explicit path) so the test process NEVER reads the
    //    process-global BALUARD_DATA_DIR env var. That env var is set
    //    only on the daemon subprocess via Command::env() below.
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let registry_path = data_dir.path().join("registry.json");
    {
        let mut reg = VaultRegistry::load_from(&registry_path).unwrap_or_default();
        reg.add(VaultEntry {
            slug: "diag".into(),
            display_name: "Diag".into(),
            path: vault_path.clone(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: uuid::Uuid::new_v4(),
            merge_opt_in: None,
            merge_ceiling_seen: false,
        })
        .expect("registry add");
        reg.save_to(&registry_path).expect("registry save");
    }

    // 3. Inspect the vault dir BEFORE spawning the daemon.
    let tree_before = dump_tree(&vault_path, "");
    eprintln!("=== vault dir BEFORE daemon spawn ===\n{}", tree_before);

    // 4. Spawn the daemon with stderr captured.
    let socket = data_dir.path().join("baluard.sock");
    let mut child = ChildGuard(
        Command::new(DAEMON_BIN)
            .arg("--socket")
            .arg(&socket)
            .env("BALUARD_DATA_DIR", data_dir.path())
            .env_remove("BALUARD_SOCKET")
            // Belt in depth: the daemon exits when this runner dies.
            .env("BALUARD_DAEMON_DIE_WITH_PARENT", "1")
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon"),
    );
    // Drain stderr in a background thread from the START (review F1):
    // a piped child that fills the OS pipe buffer (~64KB Linux, ~16KB
    // macOS) blocks on write(2) and would deadlock the request() calls
    // below. The buffer is read only after the child is dead, so EOF
    // closes the reader.
    let daemon_stderr = child.take_stderr();
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_handle = {
        let stderr_buf = std::sync::Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = String::new();
            let mut daemon_stderr = daemon_stderr;
            let _ = daemon_stderr.read_to_string(&mut buf);
            *stderr_buf.lock().unwrap() = buf;
        })
    };

    // 5. Wait for socket.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if Instant::now() > deadline {
            panic!("daemon did not create socket");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let connect_deadline = Instant::now() + Duration::from_secs(2);
    while UnixStream::connect(&socket).is_err() {
        if Instant::now() > connect_deadline {
            panic!("daemon not accepting");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // 6. Unlock + get session token.
    let unlock_payload = serde_json::json!({ "password": "diag-password" }).to_string();
    let unlock = request(&socket, "vault.unlock", &unlock_payload, "", "diag");
    assert!(unlock.success, "unlock failed: {}", unlock.error_message);
    let token = unlock.session_token;

    // 7. Inspect the vault dir AFTER daemon unlock.
    let tree_after_unlock = dump_tree(&vault_path, "");
    eprintln!(
        "=== vault dir AFTER daemon unlock ===\n{}",
        tree_after_unlock
    );

    // 8. Try vault.add.
    let add_payload = serde_json::json!({
        "name": "Test",
        "kind": {
            "type": "login",
            "data": {
                "username": "u",
                "password": "p",
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
        "tags": []
    })
    .to_string();
    let resp = request(&socket, "vault.add", &add_payload, &token, "diag");
    eprintln!(
        "=== vault.add response: success={}, payload={:?}, error={:?}",
        resp.success, resp.payload, resp.error_message
    );

    // 9. Inspect the vault dir AFTER vault.add.
    let tree_after_add = dump_tree(&vault_path, "");
    eprintln!("=== vault dir AFTER vault.add ===\n{}", tree_after_add);

    // 10. Stop the daemon, then dump everything it logged.
    child.kill_now();
    stderr_handle.join().expect("stderr drain thread");
    let stderr_buf = stderr_buf.lock().unwrap();
    eprintln!(
        "=== daemon stderr ({} bytes) ===\n{}",
        stderr_buf.len(),
        stderr_buf
    );

    assert!(resp.success, "vault.add failed; see eprintln output above");
}
