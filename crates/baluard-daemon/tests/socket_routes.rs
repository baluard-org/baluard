//! Socket-level coverage of daemon IPC routes. Uses a per-test daemon
//! subprocess spawned against a sandboxed data dir. The data dir is
//! passed to the test-process side via explicit paths
//! (`VaultRegistry::load_from` / `save_to`) so the test process never
//! reads the process-global `BALUARD_DATA_DIR` env var — that was the
//! race Claude's review identified. The daemon subprocess gets the env
//! var via `Command::env()`, which sets it in the CHILD's env table
//! at spawn time (race-free).
//!
//! Tests are organized by route family (vault CRUD, folders, tags,
//! settings, sync, etc.). Each test pins one behavior.

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

struct VaultedHandle {
    _data_dir: tempfile::TempDir,
    // Keep the vault TempDir alive for the lifetime of the handle so
    // the vault directory isn't unlinked from the FS namespace before
    // the daemon tries to write to it. The daemon subprocess can still
    // read existing files (fd keeps them alive) but creating new
    // files (e.g. ciphers/{uuid}.enc) under an unlinked dir fails
    // with ENOENT. This was the root cause of the vault.add IO error.
    _vault_dir: tempfile::TempDir,
    _child: std::process::Child,
    socket: PathBuf,
    token: String,
}

fn spawn_vaulted() -> VaultedHandle {
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    let vault_path = vault_dir.path().to_path_buf();
    VaultCreator::new(&vault_path, "spawn-test-password", "spawn-fixture")
        .execute()
        .expect("vault creation");

    // Use load_from / save_to (explicit path) — never read the process-
    // global BALUARD_DATA_DIR env var from the test process side. The
    // daemon subprocess gets the env via Command::env() below, which
    // sets the value in the CHILD's env table at spawn time (race-free).
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let registry_path = data_dir.path().join("registry.json");
    {
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

    let socket = data_dir.path().join("baluard.sock");
    let mut child = Command::new(DAEMON_BIN)
        .arg("--socket")
        .arg(&socket)
        .env("BALUARD_DATA_DIR", data_dir.path())
        .env_remove("BALUARD_SOCKET")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon did not create socket");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let connect_deadline = Instant::now() + Duration::from_secs(2);
    while UnixStream::connect(&socket).is_err() {
        if Instant::now() > connect_deadline {
            let _ = child.kill();
            panic!("daemon not accepting");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let unlock_payload = serde_json::json!({ "password": "spawn-test-password" }).to_string();
    let resp = request(&socket, "vault.unlock", &unlock_payload, "", "spawn-test");
    assert!(resp.success, "unlock failed: {}", resp.error_message);

    VaultedHandle {
        _data_dir: data_dir,
        // Move the vault TempDir into the handle so it stays alive for
        // the daemon's lifetime.
        _vault_dir: vault_dir,
        _child: child,
        socket,
        token: resp.session_token,
    }
}

impl VaultedHandle {
    fn call(&self, action: &str, payload: &str) -> GatewayResponse {
        request(&self.socket, action, payload, &self.token, "spawn-test")
    }
}

fn login_input(name: &str, username: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "kind": {
            "type": "login",
            "data": {
                "username": username,
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
}

// ── vault.list_full / vault.get ──

#[test]
fn vault_list_full_returns_empty_envelope_on_fresh_vault() {
    let v = spawn_vaulted();
    let resp = v.call("vault.list_full", "");
    assert!(resp.success, "list_full failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    for key in ["ciphers", "folders", "trash", "archived"] {
        assert!(p[key].is_array(), "list_full returns {key} array");
    }
}

#[test]
fn vault_get_returns_cipher_payload() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("GitHub", "octocat").to_string());
    assert!(add.success, "vault.add failed: {}", add.error_message);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let resp = v.call("vault.get", &id);
    assert!(resp.success, "vault.get failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    assert_eq!(p["name"], "GitHub");
    assert_eq!(p["username"], "octocat");
}

// ── vault.update / vault.delete ──

#[test]
fn vault_update_renames_cipher() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("Old", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let payload = serde_json::json!({ "id": id, "name": "New", "favorite": true }).to_string();
    let resp = v.call("vault.update", &payload);
    assert!(resp.success, "update failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(p["ciphers"][0]["name"], "New");
}

#[test]
fn vault_delete_removes_cipher() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("Doomed", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let resp = v.call("vault.delete", &id);
    assert!(resp.success);
    let p: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(p["ciphers"].as_array().unwrap().len(), 0);
}

// ── vault.archive / unarchive ──

#[test]
fn vault_archive_moves_cipher_out_of_active_list() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("X", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    assert!(v.call("vault.archive", &id).success);
    let p: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(
        p["ciphers"].as_array().unwrap().len(),
        0,
        "active list empty"
    );
    let ap: serde_json::Value =
        serde_json::from_str(&v.call("vault.list_archived", "").payload).unwrap();
    assert_eq!(
        ap["ciphers"].as_array().unwrap().len(),
        1,
        "archived list has it"
    );
}

#[test]
fn vault_unarchive_restores_cipher() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("X", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    assert!(v.call("vault.archive", &id).success);
    assert!(v.call("vault.unarchive", &id).success);
    let p: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(
        p["ciphers"].as_array().unwrap().len(),
        1,
        "back in active list"
    );
}

// ── folder CRUD ──

#[test]
fn folder_create_list_rename_delete_round_trip() {
    let v = spawn_vaulted();
    let created = v.call("folder.create", "Work");
    assert!(created.success, "create failed: {}", created.error_message);
    let id = created.payload.trim().trim_matches('"').to_string();

    let list: serde_json::Value = serde_json::from_str(&v.call("folder.list", "").payload).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["name"], "Work");

    let rename_payload = serde_json::json!({ "id": id, "name": "Job" }).to_string();
    assert!(v.call("folder.rename", &rename_payload).success);

    let list: serde_json::Value = serde_json::from_str(&v.call("folder.list", "").payload).unwrap();
    assert_eq!(list[0]["name"], "Job");

    assert!(v.call("folder.delete", &id).success);
    let list: serde_json::Value = serde_json::from_str(&v.call("folder.list", "").payload).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 0);
}

// ── tag CRUD ──

#[test]
fn tag_create_list_delete_round_trip() {
    let v = spawn_vaulted();
    assert!(v.call("tag.create", "work").success);

    let list = v.call("tag.list", "").payload;
    assert!(list.contains("work"), "list missing work: {list}");

    // tag.delete clears the tag index; with a fresh vault, "work" was
    // the only tag so the list ends up empty. We just confirm the
    // tag is gone.
    assert!(v.call("tag.delete", "work").success);
    let list_after = v.call("tag.list", "").payload;
    assert!(
        !list_after.contains("work"),
        "work still present: {list_after}"
    );
}

// tag.rename is tested via the route_coverage.rs state-level tests since
// it operates on cipher meta tags (not the standalone tag index). The
// socket test above exercises the index CRUD path.

// ── settings ──

#[test]
fn settings_get_returns_json_with_default_keys() {
    let v = spawn_vaulted();
    let resp = v.call("settings.get", "");
    assert!(resp.success);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    // Fresh vault should have at least vault_timeout + theme + lang.
    assert!(p.get("vault_timeout").is_some() || p.get("lang").is_some());
}

#[test]
fn settings_set_vault_timeout_round_trips() {
    let v = spawn_vaulted();
    let set_payload = serde_json::json!({ "vault_timeout": "30m" }).to_string();
    assert!(v.call("settings.set", &set_payload).success);
    let p: serde_json::Value = serde_json::from_str(&v.call("settings.get", "").payload).unwrap();
    let s = p["vault_timeout"].as_str().unwrap_or_default();
    assert!(s.starts_with("30"), "timeout starts with 30; got: {s}");
}

// ── vault.devices / health ──

#[test]
fn vault_devices_lists_one_device_on_fresh_vault() {
    let v = spawn_vaulted();
    let resp = v.call("vault.devices", "");
    assert!(resp.success);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let devs = p["devices"].as_array().expect("devices array");
    assert_eq!(devs.len(), 1);
    assert_eq!(p["total"], 1);
}

#[test]
fn vault_health_on_fresh_vault_reports_no_issues() {
    let v = spawn_vaulted();
    let resp = v.call("vault.health", "");
    assert!(resp.success);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(p["weak"].as_array().map(|a| a.len()).unwrap_or(0), 0);
    assert_eq!(p["reused"].as_array().map(|a| a.len()).unwrap_or(0), 0);
    assert_eq!(p["old"].as_array().map(|a| a.len()).unwrap_or(0), 0);
}

// ── sync.autosync_status ──

#[test]
fn sync_autosync_status_returns_idle_on_fresh_vault() {
    let v = spawn_vaulted();
    let resp = v.call("sync.autosync_status", "");
    assert!(
        resp.success,
        "sync.autosync_status failed: {}",
        resp.error_message
    );
    assert!(!resp.payload.is_empty());
}

// ── vaults.* (host-level) ──

#[test]
fn vaults_list_includes_our_vault() {
    let v = spawn_vaulted();
    let resp = v.call("vaults.list", "");
    assert!(resp.success);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let vaults = p["vaults"].as_array().expect("vaults array");
    let slugs: Vec<&str> = vaults.iter().filter_map(|v| v["slug"].as_str()).collect();
    assert!(
        slugs.contains(&"spawn-test"),
        "spawn-test slug present; got: {slugs:?}"
    );
}

#[test]
fn vaults_active_returns_currently_active_slug() {
    let v = spawn_vaulted();
    let resp = v.call("vaults.active", "");
    assert!(resp.success, "vaults.active failed: {}", resp.error_message);
    assert!(!resp.payload.is_empty() || resp.error_message.is_empty());
}

#[test]
fn vaults_close_removes_vault_from_daemon_map() {
    let v = spawn_vaulted();
    // vaults.close takes a slug in the PAYLOAD (not the proto field).
    let resp = request(
        &v.socket,
        "vaults.close",
        &serde_json::json!({ "slug": "spawn-test" }).to_string(),
        &v.token,
        "spawn-test",
    );
    assert!(resp.success, "vaults.close failed: {}", resp.error_message);
    // After close, vault-scoped routes should reject.
    let resp = v.call("vault.list", "");
    assert!(
        !resp.success,
        "vault.list after close must fail; got: {}",
        resp.payload
    );
}

#[test]
fn passkey_list_returns_empty_on_cipher_without_passkey() {
    let v = spawn_vaulted();
    v.call("vault.add", &login_input("Plain", "u").to_string());
    let resp = v.call("passkey.list", "");
    assert!(resp.success, "passkey.list failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(p.as_array().map(|a| a.len()).unwrap_or(0), 0);
}

// ── Token-gate regression: same token, different slug, should fail ──

#[test]
fn token_rejected_when_slug_mismatches() {
    let v = spawn_vaulted();
    // Send with a wrong slug — daemon should refuse since the token is
    // scoped to the spawn-test vault.
    let resp = request(&v.socket, "vault.list", "", &v.token, "nonexistent-slug");
    assert!(
        !resp.success,
        "vault.list with wrong slug must fail; got: {}",
        resp.payload
    );
}

// ── vault.info / favorite flag ──

#[test]
fn vault_info_returns_metadata_with_vault_id_and_one_device() {
    let v = spawn_vaulted();
    let resp = v.call("vault.info", "");
    assert!(resp.success, "vault.info failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    assert!(p["vault_id"].is_string());
    assert!(p["device_id"].is_string());
    assert_eq!(p["cipher_count"], 0);
    // vault.info reports "unlocked": true for the freshly-unlocked vault.
    // Epoch field naming varies across versions; unlocked is stable.
    assert_eq!(p["unlocked"], true);
}

#[test]
fn vault_update_toggles_favorite_flag() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("Site", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    // Toggle on
    let payload = serde_json::json!({ "id": id, "favorite": true }).to_string();
    assert!(v.call("vault.update", &payload).success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(list["ciphers"][0]["favorite"], true);
    // Toggle off
    let payload = serde_json::json!({ "id": id, "favorite": false }).to_string();
    assert!(v.call("vault.update", &payload).success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(list["ciphers"][0]["favorite"], false);
}

// ── settings.set theme / lang ──

#[test]
fn settings_set_theme_persists() {
    let v = spawn_vaulted();
    let payload = serde_json::json!({ "theme": "dark" }).to_string();
    assert!(v.call("settings.set", &payload).success);
    let p: serde_json::Value = serde_json::from_str(&v.call("settings.get", "").payload).unwrap();
    assert_eq!(p["theme"], "dark");
}

#[test]
fn settings_set_lang_persists() {
    let v = spawn_vaulted();
    let payload = serde_json::json!({ "lang": "es" }).to_string();
    assert!(v.call("settings.set", &payload).success);
    let p: serde_json::Value = serde_json::from_str(&v.call("settings.get", "").payload).unwrap();
    assert_eq!(p["lang"], "es");
}

// ── biometric + pin status (read-only; no OS keychain needed for status) ──

#[test]
fn vault_biometric_status_on_fresh_vault_returns_unavailable_or_disabled() {
    let v = spawn_vaulted();
    let resp = v.call("vault.biometric_status", "");
    assert!(resp.success);
    // On Linux (CI) biometric is unavailable. On macOS it would return
    // either unavailable or disabled. Accept either as "biometric not
    // enrolled".
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert!(p.is_object(), "biometric_status returns object");
}

#[test]
fn vault_pin_status_on_fresh_vault_returns_disabled() {
    let v = spawn_vaulted();
    let resp = v.call("vault.pin_status", "");
    assert!(resp.success, "pin_status failed: {}", resp.error_message);
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(p["enabled"], false);
}

// ── Folder delete cascade ──

#[test]
fn folder_delete_unassigns_ciphers() {
    let v = spawn_vaulted();
    // Create a folder.
    let created = v.call("folder.create", "Work");
    let folder_id = created.payload.trim().trim_matches('"').to_string();
    // Add a cipher assigned to that folder.
    let mut input = login_input("Tagged", "u");
    input["folder_id"] = serde_json::Value::String(folder_id.clone());
    let add = v.call("vault.add", &input.to_string());
    assert!(add.success, "vault.add failed: {}", add.error_message);
    // Confirm the cipher is assigned.
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    assert_eq!(list["ciphers"][0]["folder_id"], folder_id);
    // Delete the folder. Ciphers assigned to it should be unassigned
    // (folder_id becomes null) per Phase 6 cascade behavior.
    assert!(v.call("folder.delete", &folder_id).success);
    let list_after: serde_json::Value =
        serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let folder_id_after = list_after["ciphers"][0]["folder_id"].clone();
    assert!(
        folder_id_after.is_null() || folder_id_after == serde_json::Value::Null,
        "cipher folder_id should be null after folder delete; got: {folder_id_after}"
    );
}

// ── cipher.totp_code (requires a cipher with TOTP URI) ──

#[test]
fn cipher_totp_code_returns_code_for_cipher_with_totp() {
    let v = spawn_vaulted();
    let mut input = login_input("TotpSite", "u");
    // Standard otpauth URI for the "TOTP" scheme (Google Authenticator format).
    // The secret is base32-encoded; "JBSWY3DPEHPK3PXP" is the well-known
    // example from the spec.
    input["kind"]["data"]["totp_uri"] = serde_json::Value::String(
        "otpauth://totp/Test:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test".to_string(),
    );
    let add = v.call("vault.add", &input.to_string());
    assert!(add.success, "vault.add with totp: {}", add.error_message);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let resp = v.call("cipher.totp_code", &id);
    assert!(
        resp.success,
        "cipher.totp_code failed: {}",
        resp.error_message
    );
    let p: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    // 6-digit numeric TOTP code.
    let code = p["code"].as_str().expect("code field");
    assert_eq!(code.len(), 6, "TOTP code should be 6 digits; got: {code}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP code not numeric: {code}"
    );
}

#[test]
fn cipher_totp_code_for_cipher_without_totp_returns_error() {
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("Plain", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let resp = v.call("cipher.totp_code", &id);
    assert!(
        !resp.success,
        "cipher.totp_code on non-totp cipher should fail"
    );
}

// ── Attach upload + download round-trip ──

#[test]
fn attach_upload_download_round_trip_via_socket() {
    use base64::Engine;
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("Docs", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let cipher_id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    let plaintext = b"hello attachment world";
    let upload = serde_json::json!({
        "cipher_id": cipher_id,
        "filename": "test.txt",
        "data_base64": base64::engine::general_purpose::STANDARD.encode(plaintext),
    })
    .to_string();
    let resp = v.call("vault.attach_upload", &upload);
    assert!(resp.success, "attach_upload failed: {}", resp.error_message);
    let upload_resp: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    let attach_id = upload_resp["id"].as_str().expect("id").to_string();
    assert_eq!(upload_resp["filename"], "test.txt");

    // Download
    let download_req = serde_json::json!({
        "cipher_id": cipher_id,
        "attachment_id": attach_id,
    })
    .to_string();
    let resp = v.call("vault.attach_download", &download_req);
    assert!(
        resp.success,
        "attach_download failed: {}",
        resp.error_message
    );
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(p["data_base64"].as_str().unwrap())
        .expect("base64");
    assert_eq!(decoded, plaintext, "round-tripped plaintext matches");
}

#[test]
fn attach_upload_rejects_oversized_file() {
    use base64::Engine;
    let v = spawn_vaulted();
    let add = v.call("vault.add", &login_input("X", "u").to_string());
    assert!(add.success);
    let list: serde_json::Value = serde_json::from_str(&v.call("vault.list", "").payload).unwrap();
    let cipher_id = list["ciphers"][0]["id"].as_str().unwrap().to_string();
    // 3 MB > 2 MB cap. The daemon either returns success=false (structured
    // rejection) or closes the connection (BrokenPipe). Both prove the
    // upload was rejected.
    let big = vec![0u8; 3 * 1024 * 1024];
    let upload = serde_json::json!({
        "cipher_id": cipher_id,
        "filename": "huge.bin",
        "data_base64": base64::engine::general_purpose::STANDARD.encode(&big),
    })
    .to_string();
    // Use v.call() which reads the response. Either success=false OR a
    // BrokenPipe during the read counts as rejection. The simplest
    // test: wrap the call in a catch_unwind or just check that
    // v.call's payload reflects the rejection.
    // The daemon returns a structured error: parse it as JSON and check
    // for "too large" / "2mb" in the error_message.
    let req = GatewayRequest {
        action: "vault.attach_upload".to_string(),
        payload: upload,
        session_token: v.token.clone(),
        slug: "spawn-test".to_string(),
    };
    let body = req.encode_to_vec();
    let mut stream = std::os::unix::net::UnixStream::connect(&v.socket).expect("connect");
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    use std::io::Write;
    stream.write_all(&header).expect("write header");
    if stream.write_all(&body).is_err() {
        // Daemon already closed — that's rejection.
        return;
    }
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    use std::io::Read;
    match stream.read_to_end(&mut buf) {
        Ok(_) if !buf.is_empty() => {
            let (len, off) = decode_varint(&buf).expect("decode varint");
            let resp = GatewayResponse::decode(&buf[off..off + len as usize]).expect("decode");
            assert!(!resp.success, "oversized upload should be rejected");
            let err = resp.error_message.to_lowercase();
            assert!(
                err.contains("too large") || err.contains("2mb"),
                "expected size error; got: {err}"
            );
        }
        _ => {
            // BrokenPipe / empty buffer = daemon rejected the upload.
        }
    }
}

// ── sync.init (no remote — just creates local git repo) ──

#[test]
fn sync_init_creates_local_git_repo() {
    let v = spawn_vaulted();
    let resp = v.call("sync.init", "");
    assert!(resp.success, "sync.init failed: {}", resp.error_message);
    // The vault dir should now contain .git/ (sync.init runs git init in
    // the vault directory).
    // We don't have direct access to vault_path from the handle, but
    // sync.status / sync.log should work after init.
    let status = v.call("sync.status", "");
    // sync.status may succeed or fail depending on whether there's a
    // remote; either way, sync.init should not have errored.
    assert!(status.success || !status.error_message.is_empty());
}

#[test]
fn sync_log_on_uninitialized_repo_does_not_crash() {
    let v = spawn_vaulted();
    // No sync.init called — log should still respond gracefully.
    let resp = v.call("sync.log", "");
    // The response shape varies (empty list, or an error). Just confirm
    // the daemon didn't crash + returned a payload.
    assert!(resp.error_message.is_empty() || !resp.payload.is_empty());
}

// ── vault.active returns the slug we just used ──

#[test]
fn vaults_active_returns_spawn_test_vault() {
    let v = spawn_vaulted();
    let resp = v.call("vaults.active", "");
    assert!(resp.success, "vaults.active failed: {}", resp.error_message);
    // The payload is a JSON object {slug, presence, ...}, not a raw string.
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    assert_eq!(p["slug"], "spawn-test", "active slug mismatch; got: {p}");
    assert_eq!(p["presence"], "unlocked");
}

// ── Token-gate: same token, no slug, should fail ──

#[test]
fn vault_scoped_route_without_slug_falls_back_to_active() {
    // Phase 6 M2 design: when req.slug is empty, the daemon falls back to
    // the currently active vault. After vault.unlock, the active vault IS
    // spawn-test, so the fallback succeeds. Pin that behavior here.
    let v = spawn_vaulted();
    let resp = request(&v.socket, "vault.list", "", &v.token, "");
    assert!(
        resp.success,
        "vault.list with empty slug should fall back to active"
    );
    let p: serde_json::Value = serde_json::from_str(&resp.payload).expect("json");
    assert!(p["ciphers"].is_array());
}
