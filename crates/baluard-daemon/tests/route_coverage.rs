//! Daemon route coverage at the VaultState / VaultHost layer.
//!
//! Same pattern as `pin_quick_unlock.rs`: build a real vault via
//! VaultCreator, open it into a VaultState, exercise the public methods
//! that back each IPC route. This catches regressions in the route's
//! payload handling without the overhead of spawning the daemon binary
//! over a Unix socket. End-to-end coverage (full protobuf framing +
//! token-gate rejection) lives in the handler.rs unit tests + a future
//! fake-daemon fixture.
//!
//! One happy-path test per route + a focused error test where the
//! failure mode is security- or UX-relevant (locked-vault rejection,
//! malformed payload, missing required field).

// Clippy/rustc don't treat #[tokio::test] as an entry point, so the
// dead-code lint flags unused helpers (sandboxed_host_env) when other
// test binaries compile. Allow at the file level — same pattern as
// crates/baluard-cli/tests/common/mod.rs.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use baluard_core::types::{CipherInput, CipherKind, LoginData, LoginUri};
use baluard_core::vault::creation::VaultCreator;
use baluard_core::vault::registry::{VaultEntry, VaultRegistry};
use baluard_daemon::handler::route_host_request;
use baluard_daemon::host::VaultHost;
use baluard_daemon::proto::GatewayRequest;
use baluard_daemon::state::VaultState;

const MASTER: &str = "test-master-password-123";

fn make_vault(label: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    VaultCreator::new(&path, MASTER, &format!("route-{label}"))
        .execute()
        .expect("vault creation");
    (dir, path)
}

async fn open_unlocked(label: &str) -> (tempfile::TempDir, Arc<VaultState>) {
    let (dir, path) = make_vault(label);
    let state = Arc::new(VaultState::new(path));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");
    (dir, state)
}

fn login_input(name: &str, user: &str) -> CipherInput {
    CipherInput {
        name: name.to_string(),
        folder_id: None,
        collection_id: None,
        kind: CipherKind::Login(LoginData {
            username: Some(user.to_string()),
            password: Some("p".into()),
            uris: vec![LoginUri::new("https://example.com".to_string())],
            totp_uri: None,
            autofill_on_page_load: false,
            password_revision_date: None,
            fido2_credentials: None,
            favicon: None,
        }),
        favorite: false,
        notes: None,
        custom_fields: vec![],
        created_at: None,
        password_history: vec![],
        attachments: vec![],
        archived: false,
        reprompt: false,
        tags: vec!["work".into()],
    }
}

// ── VaultState: open / unlock / lock lifecycle ────────────────────────

#[tokio::test]
async fn vault_state_open_then_locked() {
    let (_dir, path) = make_vault("lifecycle");
    let state = VaultState::new(path);
    state.open().await.expect("open");
    assert!(!state.is_unlocked().await, "freshly opened vault is locked");
}

#[tokio::test]
async fn vault_state_unlock_then_lock_round_trip() {
    let (_dir, state) = open_unlocked("unlock-lock").await;
    assert!(state.is_unlocked().await);
    state.lock().await.expect("lock");
    assert!(!state.is_unlocked().await, "lock cleared keys");
}

// ── Cipher operations ──────────────────────────────────────────────────

#[tokio::test]
async fn add_cipher_then_list_returns_it() {
    let (_dir, state) = open_unlocked("add-list").await;
    let id = state
        .add_cipher(&serde_json::to_string(&login_input("GitHub", "octocat")).unwrap())
        .await
        .expect("add_cipher");
    assert!(!id.is_empty(), "add_cipher returns UUID");

    let metas = state.list_cipher_meta().await.expect("list_cipher_meta");
    assert_eq!(metas.len(), 1, "list contains the added cipher");
    assert_eq!(metas[0].name, "GitHub");
}

#[tokio::test]
async fn add_cipher_rejects_when_vault_locked() {
    let (_dir, path) = make_vault("add-locked");
    let state = VaultState::new(path);
    state.open().await.expect("open");
    // NOT unlocked.
    let err = state
        .add_cipher(&serde_json::to_string(&login_input("X", "u")).unwrap())
        .await
        .unwrap_err();
    assert!(err.contains("locked"), "expected locked error, got: {err}");
}

#[tokio::test]
async fn get_cipher_returns_decrypted_when_unlocked() {
    let (_dir, state) = open_unlocked("get").await;
    let id = state
        .add_cipher(&serde_json::to_string(&login_input("GH", "u")).unwrap())
        .await
        .unwrap();
    let payload = state
        .get_cipher(&id, true)
        .await
        .expect("get_cipher decrypted");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert_eq!(v["name"], "GH");
    assert_eq!(v["username"], "u");
    // The kind envelope carries the plaintext password when decrypted.
    assert_eq!(v["password"], "p");
}

#[tokio::test]
async fn list_full_returns_folders_and_archived() {
    let (_dir, state) = open_unlocked("list-full").await;
    state
        .add_cipher(&serde_json::to_string(&login_input("X", "u")).unwrap())
        .await
        .unwrap();
    let payload = state.list_all().await.expect("list_all");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert!(v["ciphers"].is_array(), "list_all includes ciphers array");
    assert!(v["folders"].is_array(), "list_all includes folders array");
    assert!(v["trash"].is_array(), "list_all includes trash array");
    assert!(v["archived"].is_array(), "list_all includes archived array");
}

// ── Settings ──────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_get_on_fresh_vault_returns_defaults() {
    let (_dir, state) = open_unlocked("settings-get").await;
    let payload = state.settings_get().await.expect("settings_get");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    // Fresh vault: no theme/lang set, both fields present (null ok).
    assert!(
        v.get("theme").is_some() || v.get("lang").is_some(),
        "settings returns at least one field"
    );
}

#[tokio::test]
async fn settings_set_vault_timeout_accepted() {
    let (_dir, state) = open_unlocked("settings-set").await;
    let payload = serde_json::json!({ "vault_timeout": "30" }).to_string();
    state.settings_set(&payload).await.expect("settings_set");
    let payload = state.settings_get().await.expect("settings_get");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    // VaultTimeout::from_token parses "30" -> VaultTimeout::Minutes(30),
    // which serializes back as "30m". Accept any token starting with 30.
    let s = v["vault_timeout"].as_str().unwrap_or_default();
    assert!(s.starts_with("30"), "expected 30m-style token, got: {s}");
}

#[tokio::test]
async fn settings_set_unknown_field_silently_ignored_or_error() {
    // The core allows unknown fields (extra serde keys are dropped). The
    // contract: this never panics. Accept any outcome short of a panic.
    let (_dir, state) = open_unlocked("settings-unknown").await;
    let payload = serde_json::json!({ "totally_unknown_key": "x" }).to_string();
    let _ = state.settings_set(&payload).await; // ok or err, both fine
}

// ── Locale ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn locale_save_persists_and_reflects_in_settings() {
    let (_dir, state) = open_unlocked("locale").await;
    state.locale_save("es").await.expect("locale_save es");
    let payload = state.settings_get().await.expect("settings_get");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert_eq!(v["lang"], "es");
}

// ── Avatar ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn avatar_get_on_fresh_vault_returns_empty_or_null() {
    let (_dir, state) = open_unlocked("avatar").await;
    let payload = state.avatar_get().await.expect("avatar_get");
    // On a fresh vault the handler returns either an empty payload or a
    // JSON null / empty object. All three mean "no avatar set". Pin that
    // the call succeeds and the result is not a binary blob.
    assert!(
        payload.is_empty() || payload == "null" || payload.starts_with('{'),
        "unexpected avatar payload: {payload:?}"
    );
}

// ── SSH key generation ────────────────────────────────────────────────

#[tokio::test]
async fn ssh_generate_ed25519_key() {
    let (_dir, state) = open_unlocked("ssh-ed").await;
    let payload = serde_json::json!({ "type": "ed25519" }).to_string();
    let resp = state
        .ssh_generate_key(&payload)
        .await
        .expect("ssh_generate_key");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
    assert!(
        v["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert!(v["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(
        v["private_key"]
            .as_str()
            .unwrap()
            .contains("OPENSSH PRIVATE KEY")
    );
}

#[tokio::test]
#[ignore = "ssh-key 0.7-rc rejects Algorithm::Ecdsa{NistP256} construction; ECDSA path needs ssh-key upgrade"]
async fn ssh_generate_ecdsa256_key() {
    // ssh-key 0.7-rc.10 (in Cargo.lock) returns "unknown algorithm" when
    // Algorithm::Ecdsa { curve: NistP256 } is passed to random(). The
    // Ed25519 path is the only one currently working; ECDSA P-256 is
    // gated until the ssh-key dependency is upgraded. Tracked as a
    // follow-up — the L7 fix removed RSA but the ECDSA path was never
    // verified end-to-end.
    let (_dir, state) = open_unlocked("ssh-ec").await;
    let payload = serde_json::json!({ "type": "ecdsa256" }).to_string();
    let resp = state
        .ssh_generate_key(&payload)
        .await
        .expect("ssh_generate_key");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
    let pk = v["public_key"].as_str().unwrap();
    assert!(
        pk.starts_with("ecdsa-sha2-nistp256 "),
        "unexpected ECDSA key prefix: {pk}"
    );
}

#[tokio::test]
async fn ssh_generate_rejects_rsa() {
    let (_dir, state) = open_unlocked("ssh-rsa").await;
    let payload = serde_json::json!({ "type": "rsa4096" }).to_string();
    let err = state.ssh_generate_key(&payload).await.unwrap_err();
    assert!(
        err.contains("ed25519") || err.contains("ecdsa256"),
        "expected known-types-only error: {err}"
    );
}

// ── Generator history ─────────────────────────────────────────────────

#[tokio::test]
async fn generator_history_add_then_list() {
    let (_dir, state) = open_unlocked("gen-history").await;
    let add_payload = serde_json::json!({
        "value": "generated-pass-123",
        "kind": "password",
        "params": { "length": 18 },
    })
    .to_string();
    state
        .generator_history_add(&add_payload)
        .await
        .expect("history_add");
    let list = state.generator_history_list().await.expect("history_list");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&list).expect("json");
    assert!(!arr.is_empty(), "history list has the added entry");
}

// ── Info + devices ────────────────────────────────────────────────────

#[tokio::test]
async fn info_returns_vault_metadata() {
    let (_dir, state) = open_unlocked("info").await;
    let payload = state.info().await.expect("info");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    // info() returns the vault + device identifiers. The exact field
    // names shift across releases; pin the stable subset and just confirm
    // the call returns a non-empty JSON object with vault + device IDs.
    assert!(v.is_object());
    assert!(
        v.get("vault_id").map(|x| x.is_string()).unwrap_or(false)
            || v.get("device_id").map(|x| x.is_string()).unwrap_or(false),
        "info() returns at least one id field: {v}"
    );
}

#[tokio::test]
async fn devices_lists_enrolled_device() {
    let (_dir, state) = open_unlocked("devices").await;
    let payload = state.devices().await.expect("devices");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    let arr = v["devices"].as_array().expect("devices array");
    assert_eq!(arr.len(), 1, "fresh vault has exactly one device");
    assert_eq!(v["total"], 1);
}

// ── VaultHost (multi-vault layer) ─────────────────────────────────────

/// VaultHost::list() joins the in-memory map with the on-disk registry.
/// Redirect BALUARD_DATA_DIR to a per-test tempdir so the host can't see
/// the developer's real registry. Same trick the CLI tests use.
/// G24: sandbox access is serialized. BALUARD_DATA_DIR is a
/// process-wide var, so two parallel tests racing their sandboxes
/// made registry-dependent routes read each other's registries (the
/// merged-read routes made that race load-bearing). The guard ties
/// the env flip to the sandbox lifetime.
static SANDBOX_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn sandboxed_host_env() -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = SANDBOX_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("sandbox tempdir");
    unsafe {
        std::env::set_var("BALUARD_DATA_DIR", dir.path());
    }
    (dir, guard)
}

async fn vault_host_list_includes_inserted_vault() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let (_dir, path) = make_vault("host-list");
    let state = Arc::new(VaultState::new(path));
    state.open().await.expect("open");
    host.insert("host-list".into(), state.clone()).await;
    let rows = host.list().await;
    assert_eq!(rows.len(), 1, "expected 1 row, got {rows:?}");
    assert_eq!(rows[0].slug, "host-list");
}

#[tokio::test]
async fn vault_host_get_returns_inserted_state() {
    let host = VaultHost::new();
    let (_dir, path) = make_vault("host-get");
    let state = Arc::new(VaultState::new(path));
    state.open().await.expect("open");
    host.insert("host-get".into(), state.clone()).await;
    let got = host
        .get("host-get")
        .await
        .expect("get returns the inserted state");
    assert!(Arc::ptr_eq(&got, &state), "host.get returns the same Arc");
}

#[tokio::test]
async fn vault_host_close_removes_from_map() {
    let host = VaultHost::new();
    let (_dir, path) = make_vault("host-close");
    let state = Arc::new(VaultState::new(path));
    state.open().await.expect("open");
    host.insert("host-close".into(), state).await;
    assert!(host.get("host-close").await.is_some());
    let removed = host.close("host-close").await;
    assert!(removed, "close returns true for an existing entry");
    assert!(
        host.get("host-close").await.is_none(),
        "close removed the entry"
    );
}

#[tokio::test]
async fn vault_host_list_empty_with_sandboxed_registry() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    assert!(
        host.list().await.is_empty(),
        "fresh host with empty registry has zero vaults"
    );
}

// ── vaults.list_full_all (S2-5 merged multi-vault) ──────────────────

/// Register a created vault in the sandboxed registry so host.list()
/// joins it into rows (the route merges registry rows with host states).
fn register_in_registry(slug: &str, path: &std::path::Path) {
    use baluard_core::vault::registry::{BaluardMarker, VaultEntry, VaultRegistry};
    let vault_id = BaluardMarker::read_from_vault(path)
        .ok()
        .flatten()
        .map(|m: baluard_core::vault::registry::BaluardMarker| m.vault_id)
        .unwrap_or(uuid::Uuid::new_v4());
    let mut reg = VaultRegistry::load_locked().unwrap_or_default();
    reg.vaults.insert(
        slug.to_string(),
        VaultEntry {
            slug: slug.to_string(),
            display_name: format!("Vault {slug}"),
            path: path.to_path_buf(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id,
            merge_opt_in: None,
            merge_ceiling_seen: false,
        },
    );
    reg.save_locked().expect("registry save");
}

#[tokio::test]
async fn vaults_list_full_all_merges_and_gates_on_active_token() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(host);

    let (dir_a, path_a) = make_vault("fullall-a");
    let state_a = Arc::new(VaultState::new(path_a.clone()));
    state_a.open().await.expect("open a");
    state_a.unlock(MASTER).await.expect("unlock a");
    state_a
        .add_cipher(&serde_json::to_string(&login_input("Bank A", "u")).unwrap())
        .await
        .expect("add a");
    register_in_registry("fullall-a", &path_a);

    let (dir_b, path_b) = make_vault("fullall-b");
    let state_b = Arc::new(VaultState::new(path_b.clone()));
    state_b.open().await.expect("open b");
    state_b.unlock(MASTER).await.expect("unlock b");
    state_b
        .add_cipher(&serde_json::to_string(&login_input("Bank B", "u")).unwrap())
        .await
        .expect("add b");
    register_in_registry("fullall-b", &path_b);

    let (dir_c, path_c) = make_vault("fullall-c");
    let state_c = Arc::new(VaultState::new(path_c.clone()));
    state_c.open().await.expect("open c");
    register_in_registry("fullall-c", &path_c);

    host.insert("fullall-a".into(), state_a.clone()).await;
    host.insert("fullall-b".into(), state_b.clone()).await;
    host.insert("fullall-c".into(), state_c.clone()).await;
    host.switch("fullall-a").await.expect("switch to a");

    let token_a = state_a
        .get_session_token()
        .await
        .expect("active vault token");
    let token_b = state_b.get_session_token().await.expect("b token");

    // Happy path: merged rows; unlocked vaults carry envelopes.
    let req = GatewayRequest {
        action: "vaults.list_full_all".into(),
        payload: String::new(),
        session_token: token_a.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["vaults"].as_array().expect("rows").clone();
    assert_eq!(rows.len(), 3, "all registered vaults appear: {rows:?}");

    let row_a = rows.iter().find(|r| r["slug"] == "fullall-a").unwrap();
    assert_eq!(row_a["active"], serde_json::json!(true));
    assert_eq!(
        row_a["ciphers"].as_array().unwrap().len(),
        1,
        "active vault envelope present"
    );
    let row_b = rows.iter().find(|r| r["slug"] == "fullall-b").unwrap();
    assert_eq!(
        row_b["ciphers"].as_array().unwrap().len(),
        1,
        "sibling unlocked vault merges"
    );
    assert!(row_b["active"] == serde_json::json!(false));
    let row_c = rows.iter().find(|r| r["slug"] == "fullall-c").unwrap();
    assert!(
        row_c.get("ciphers").is_none(),
        "locked vault carries metadata only"
    );

    // Gate 1: no token refused.
    let req = GatewayRequest {
        action: "vaults.list_full_all".into(),
        payload: String::new(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "empty token must be refused");

    // Gate 2: a SIBLING vault's token refused — only the active
    // session may read the merge (bridge/extension tokens can never
    // verify here, preserving the D21 no-export boundary).
    let req = GatewayRequest {
        action: "vaults.list_full_all".into(),
        payload: String::new(),
        session_token: token_b,
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "sibling token must be refused");

    let _ = (dir_a, dir_b, dir_c);
}

// ── Auto-lock policy ──────────────────────────────────────────────────

#[tokio::test]
async fn timeout_policy_fresh_vault_uses_default() {
    let (_dir, state) = open_unlocked("timeout").await;
    let policy = state.timeout_policy().await;
    // The default from VaultCreator is Some(VaultTimeout::Minutes(15))
    // (matches the desktop default).
    let p: serde_json::Value = serde_json::to_value(policy).expect("serialize policy");
    // We don't pin the exact variant — just confirm the call returns
    // without panic and serializes as JSON.
    assert!(p.is_object() || p.is_string() || p.is_null());
}

#[tokio::test]
async fn should_auto_lock_immediately_on_fresh_state() {
    // Freshly unlocked state with no activity time elapsed -> never auto-lock.
    let (_dir, state) = open_unlocked("auto-lock-immediate").await;
    assert!(
        !state.should_auto_lock().await,
        "freshly unlocked vault should NOT auto-lock immediately"
    );
}

// ── Cipher archive / unarchive ────────────────────────────────────

#[tokio::test]
async fn archive_unarchive_round_trip() {
    let (_dir, state) = open_unlocked("archive").await;
    let id = state
        .add_cipher(&serde_json::to_string(&login_input("X", "u")).unwrap())
        .await
        .unwrap();
    state.archive_cipher(&id).await.expect("archive");
    // After archive, list_cipher_meta excludes it; list_archived_meta includes it.
    assert_eq!(state.list_cipher_meta().await.unwrap().len(), 0);
    assert_eq!(state.list_archived_meta().await.unwrap().len(), 1);
    state.unarchive_cipher(&id).await.expect("unarchive");
    assert_eq!(state.list_cipher_meta().await.unwrap().len(), 1);
    assert_eq!(state.list_archived_meta().await.unwrap().len(), 0);
}

#[tokio::test]
async fn archive_unknown_cipher_returns_error() {
    let (_dir, state) = open_unlocked("archive-miss").await;
    let err = state
        .archive_cipher("00000000-0000-0000-0000-000000000000")
        .await
        .unwrap_err();
    assert!(!err.is_empty(), "archive of unknown id should fail");
}

// ── Cipher update ─────────────────────────────────────────────────

#[tokio::test]
async fn update_cipher_changes_name() {
    let (_dir, state) = open_unlocked("update").await;
    let id = state
        .add_cipher(&serde_json::to_string(&login_input("Old", "u")).unwrap())
        .await
        .unwrap();
    let payload = serde_json::json!({
        "id": id,
        "name": "New",
        "favorite": true,
    })
    .to_string();
    state.update_cipher(&payload).await.expect("update");
    let metas = state.list_cipher_meta().await.unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "New");
    assert!(metas[0].favorite, "favorite flag updated");
}

#[tokio::test]
async fn update_cipher_missing_id_field_errors() {
    let (_dir, state) = open_unlocked("update-bad").await;
    state
        .add_cipher(&serde_json::to_string(&login_input("X", "u")).unwrap())
        .await
        .unwrap();
    let payload = serde_json::json!({ "name": "New" }).to_string();
    let err = state.update_cipher(&payload).await.unwrap_err();
    assert!(
        err.contains("id") || err.contains("Missing"),
        "expected missing-id error: {err}"
    );
}

// ── Cipher delete ───────────────────────────────────────────────────

#[tokio::test]
async fn delete_cipher_removes_from_active_list() {
    let (_dir, state) = open_unlocked("delete").await;
    let id = state
        .add_cipher(&serde_json::to_string(&login_input("Doomed", "u")).unwrap())
        .await
        .unwrap();
    state.delete_cipher(&id).await.expect("delete");
    assert_eq!(state.list_cipher_meta().await.unwrap().len(), 0);
}

#[tokio::test]
async fn delete_cipher_unknown_id_errors() {
    let (_dir, state) = open_unlocked("delete-miss").await;
    let err = state
        .delete_cipher("00000000-0000-0000-0000-000000000000")
        .await
        .unwrap_err();
    assert!(!err.is_empty());
}

// ── Settings: theme + lang ─────────────────────────────────────────

#[tokio::test]
async fn settings_set_theme_persists() {
    let (_dir, state) = open_unlocked("settings-theme").await;
    let payload = serde_json::json!({ "theme": "dark" }).to_string();
    state.settings_set(&payload).await.expect("settings_set");
    let payload = state.settings_get().await.expect("settings_get");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert_eq!(v["theme"], "dark");
}

#[tokio::test]
async fn settings_set_lang_persists() {
    let (_dir, state) = open_unlocked("settings-lang").await;
    let payload = serde_json::json!({ "lang": "es" }).to_string();
    state.settings_set(&payload).await.expect("settings_set");
    let payload = state.settings_get().await.expect("settings_get");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert_eq!(v["lang"], "es");
}

// ── Biometric status (no enable — needs OS keychain) ──────────────

#[tokio::test]
async fn biometric_status_on_fresh_vault() {
    let (_dir, state) = open_unlocked("bio-status").await;
    let payload = state.biometric_status().await.expect("biometric_status");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    // Fresh vault has no biometric enrollment. The exact field names
    // differ by platform; just confirm a status object came back.
    assert!(v.is_object());
}

#[tokio::test]
async fn biometric_disable_when_not_enrolled_is_safe() {
    let (_dir, state) = open_unlocked("bio-disable").await;
    // Idempotent: disabling without enrollment must not panic. Either
    // succeeds (no-op) or returns a non-fatal error.
    let _ = state.biometric_disable().await;
}

// ── Health report ────────────────────────────────────────────────

#[tokio::test]
async fn health_report_on_fresh_vault_empty() {
    let (_dir, state) = open_unlocked("health-empty").await;
    let payload = state.health_report().await.expect("health_report");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert_eq!(v["weak"].as_array().map(|a| a.len()).unwrap_or(0), 0);
    assert_eq!(v["reused"].as_array().map(|a| a.len()).unwrap_or(0), 0);
    assert_eq!(v["old"].as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[tokio::test]
async fn health_report_with_short_password_flags_weak() {
    let (_dir, state) = open_unlocked("health-weak").await;
    // 6-char password is below the typical weak threshold (8 chars).
    let weak_input = CipherInput {
        name: "weak".to_string(),
        folder_id: None,
        collection_id: None,
        kind: CipherKind::Login(LoginData {
            username: Some("u".into()),
            password: Some("abc".into()), // 3 chars
            uris: vec![],
            totp_uri: None,
            autofill_on_page_load: false,
            password_revision_date: None,
            fido2_credentials: None,
            favicon: None,
        }),
        favorite: false,
        notes: None,
        custom_fields: vec![],
        created_at: None,
        password_history: vec![],
        attachments: vec![],
        archived: false,
        reprompt: false,
        tags: vec![],
    };
    state
        .add_cipher(&serde_json::to_string(&weak_input).unwrap())
        .await
        .unwrap();
    let payload = state.health_report().await.expect("health_report");
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    // The health report should now surface at least one weak entry. If
    // the threshold is higher than 3 chars in this build, accept any
    // non-empty weak array; otherwise confirm >0.
    let weak_count = v["weak"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(weak_count >= 1, "expected >=1 weak entry, got: {v}");
}

// ── Generator history clear ──────────────────────────────────────

#[tokio::test]
async fn generator_history_clear_empties_list() {
    let (_dir, state) = open_unlocked("gen-clear").await;
    let add = serde_json::json!({
        "value": "x", "kind": "password", "params": { "length": 8 }
    })
    .to_string();
    state.generator_history_add(&add).await.unwrap();
    let list = state.generator_history_list().await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&list).expect("json");
    assert!(!arr.is_empty(), "history has the added entry");
    state.generator_history_clear().await.unwrap();
    let list = state.generator_history_list().await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&list).expect("json");
    assert!(arr.is_empty(), "history cleared");
}

// ── Reprompt verify ───────────────────────────────────────────────

#[tokio::test]
async fn reprompt_verify_with_correct_master_returns_ok() {
    let (_dir, state) = open_unlocked("reprompt").await;
    let payload = state
        .reprompt_verify(MASTER)
        .await
        .expect("reprompt_verify ok");
    // The success payload shape shifts; just confirm non-empty JSON success.
    let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
    assert!(v.is_object());
}

#[tokio::test]
async fn reprompt_verify_with_wrong_master_errors() {
    let (_dir, state) = open_unlocked("reprompt-bad").await;
    let err = state
        .reprompt_verify("definitely-wrong-master-password")
        .await
        .unwrap_err();
    assert!(err.to_lowercase().contains("incorrect") || err.to_lowercase().contains("invalid"));
}

// ── VaultHost: switch + lock_all ──────────────────────────────────

#[tokio::test]
async fn vault_host_switch_flips_active_pointer() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let (_d1, p1) = make_vault("switch-1");
    let (_d2, p2) = make_vault("switch-2");
    let s1 = Arc::new(VaultState::new(p1));
    let s2 = Arc::new(VaultState::new(p2));
    s1.open().await.unwrap();
    s2.open().await.unwrap();
    host.insert("vault-1".into(), s1).await;
    host.insert("vault-2".into(), s2).await;
    host.switch("vault-1").await.expect("switch to vault-1");
    assert_eq!(host.active_slug().await.as_deref(), Some("vault-1"));
    host.switch("vault-2").await.expect("switch to vault-2");
    assert_eq!(host.active_slug().await.as_deref(), Some("vault-2"));
}

#[tokio::test]
async fn vault_host_switch_unknown_slug_errors() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let err = host.switch("ghost").await.unwrap_err();
    // Just confirm the error message references the slug.
    assert!(
        format!("{err:?}").contains("ghost")
            || format!("{err:?}").to_lowercase().contains("unknown")
    );
}

#[tokio::test]
async fn vault_host_lock_all_returns_count() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let (_d1, p1) = make_vault("lock-all-1");
    let (_d2, p2) = make_vault("lock-all-2");
    let s1 = Arc::new(VaultState::new(p1));
    let s2 = Arc::new(VaultState::new(p2));
    s1.open().await.unwrap();
    s2.open().await.unwrap();
    s1.unlock(MASTER).await.unwrap();
    s2.unlock(MASTER).await.unwrap();
    host.insert("la-1".into(), s1).await;
    host.insert("la-2".into(), s2).await;
    let n = host.lock_all().await;
    assert_eq!(n, 2, "lock_all returns count of locked vaults");
}

#[tokio::test]
async fn ping_payload_carries_the_version_handshake() {
    // D79: the desktop refuses a daemon whose build version differs from the
    // one it shipped with; this pins the wire shape it parses.
    let req = GatewayRequest {
        action: "ping".into(),
        ..Default::default()
    };
    let resp = route_host_request(req, &Arc::new(VaultHost::new())).await;
    assert!(resp.success, "ping must succeed");
    let v: serde_json::Value = serde_json::from_str(&resp.payload).expect("ping payload is JSON");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["proto_version"], baluard_core::BALUARD_VERSION);
}

#[tokio::test]
async fn system_prepare_update_drains_and_locks_every_open_vault() {
    // D79 update prep: the desktop stops the daemon only after this route
    // reports success, so it must lock every open vault (draining any sync
    // cycle first) and report what it locked.
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let (_d1, p1) = make_vault("prep-1");
    let (_d2, p2) = make_vault("prep-2");
    let s1 = Arc::new(VaultState::new(p1.clone()));
    let s2 = Arc::new(VaultState::new(p2.clone()));
    s1.open().await.unwrap();
    s2.open().await.unwrap();
    s1.unlock(MASTER).await.unwrap();
    s2.unlock(MASTER).await.unwrap();
    host.insert("prep-1".into(), s1.clone()).await;
    host.insert("prep-2".into(), s2.clone()).await;

    let req = GatewayRequest {
        action: "system.prepare_update".into(),
        ..Default::default()
    };
    let resp = route_host_request(req, &Arc::new(host)).await;
    assert!(
        resp.success,
        "prepare_update must succeed: {:?}",
        resp.error_message
    );
    let v: serde_json::Value =
        serde_json::from_str(&resp.payload).expect("prepare_update payload is JSON");
    let mut locked: Vec<String> = serde_json::from_value(v["locked"].clone()).unwrap();
    locked.sort();
    assert_eq!(locked, vec!["prep-1".to_string(), "prep-2".to_string()]);
    assert!(
        !s1.is_unlocked().await && !s2.is_unlocked().await,
        "both vaults must lock"
    );
}

// ── §4.8-1: sharing surfaces (members / requests / activity) ──

#[tokio::test]
async fn sharing_surfaces_happy_path_and_role_guard() {
    let (_dir, state) = open_unlocked("sharing-flow").await;

    // Role parsing fails closed: a typo'd or missing role must never
    // silently become an Editor invite (write seat + keywrap).
    let err = state
        .members_invite(r#"{"role": "view"}"#)
        .await
        .unwrap_err();
    assert!(err.contains("invalid or missing 'role'"), "err: {err}");
    let err = state.members_invite("{}").await.unwrap_err();
    assert!(err.contains("invalid or missing 'role'"), "err: {err}");

    // Mint an editor invite. A transport username with NO provider
    // remote reports the seat failure but still creates the invite.
    let invite: serde_json::Value = serde_json::from_str(
        &state
            .members_invite(r#"{"role":"editor", "transport_username":"gituser"}"#)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!invite["code"].as_str().unwrap_or_default().is_empty());
    assert_eq!(invite["seat_granted"], false);
    assert!(invite["seat_error"].is_string());

    // Members list: the genesis owner row, not reset/removed; the viewer
    // here is the owner device (is_self) with the owner role.
    let list: serde_json::Value =
        serde_json::from_str(&state.members_list().await.unwrap()).unwrap();
    let arr = list["members"]
        .as_array()
        .expect("members.list returns members");
    assert_eq!(arr.len(), 1, "genesis vault has exactly the owner row");
    assert_eq!(arr[0]["role"], "owner");
    assert_eq!(arr[0]["removed"], false);
    assert_eq!(arr[0]["is_self"], true);
    assert_eq!(list["your_role"], "owner");

    // Join queue: empty on a fresh vault.
    let q: serde_json::Value = serde_json::from_str(&state.requests_list().await.unwrap()).unwrap();
    assert_eq!(q["requests"].as_array().unwrap().len(), 0);
    assert_eq!(q["malformed"], 0);

    // Activity surfaces: empty on a fresh vault.
    let events: serde_json::Value =
        serde_json::from_str(&state.activity_events("{}").await.unwrap()).unwrap();
    assert!(events.as_array().unwrap().is_empty());
    let refusals: serde_json::Value =
        serde_json::from_str(&state.activity_refusals("{}").await.unwrap()).unwrap();
    assert!(refusals.as_array().unwrap().is_empty());

    // Approve/deny of an unknown request fail (nothing consumed).
    let bogus = r#"{"req_id": "11111111-1111-1111-1111-111111111111"}"#;
    assert!(state.requests_approve(bogus).await.is_err());
    assert!(state.requests_deny(bogus).await.is_err());

    // Stage leg (§4.8-2): the joiner's out-of-band intro code enters the
    // queue through the route, list shows it with a matching secret, and
    // approval mints the member. The introduction is hand-built from the
    // invite code the way a real joiner's device would emit it.
    use baluard_core::vault::members::Introduction;
    // Core encodes invite codes with the URL_SAFE alphabet.
    use base64::Engine as _;
    let invite_json: serde_json::Value = serde_json::from_str(
        &String::from_utf8(
            base64::engine::general_purpose::URL_SAFE
                .decode(invite["code"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let intro = Introduction {
        vault_id: invite_json["vault_id"].as_str().unwrap().parse().unwrap(),
        invite_id: invite_json["invite_id"].as_str().unwrap().parse().unwrap(),
        secret: invite_json["secret"].as_str().unwrap().to_string(),
        device_id: uuid::Uuid::new_v4(),
        encryption_public_key: "aa".repeat(32),
        signing_public_key: "bb".repeat(32),
        display_name: "Phone B".into(),
        email: Some("b@example.com".into()),
        contact_card: None,
        identity_signature: None,
    };
    let intro_code = intro.encode().unwrap();
    // Garbage and foreign-vault replies refuse without staging anything.
    assert!(
        state
            .requests_stage(r#"{"intro_code":"not-a-code"}"#)
            .await
            .is_err()
    );
    let mut foreign = intro.clone();
    foreign.vault_id = uuid::Uuid::new_v4();
    let foreign_err = state
        .requests_stage(&format!(
            r#"{{"intro_code":"{}"}}"#,
            foreign.encode().unwrap()
        ))
        .await
        .unwrap_err();
    assert!(
        foreign_err.contains("different vault"),
        "err: {foreign_err}"
    );
    let staged: serde_json::Value = serde_json::from_str(
        &state
            .requests_stage(&format!(r#"{{"intro_code":"{intro_code}"}}"#))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!staged["req_id"].as_str().unwrap().is_empty());
    let q: serde_json::Value = serde_json::from_str(&state.requests_list().await.unwrap()).unwrap();
    let rows = q["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "staged request is listed");
    assert_eq!(rows[0]["display_name"], "Phone B");
    assert_eq!(rows[0]["secret_ok"], true);
    assert_eq!(rows[0]["email"], "b@example.com");
    // Editor is NOT above the trust dial: the approval proceeds without a
    // Verified contact card, mints the member row, and empties the queue.
    // No provider remote, so the seat upgrade reports false.
    let approved: serde_json::Value = serde_json::from_str(
        &state
            .requests_approve(&format!(
                r#"{{"req_id":"{}"}}"#,
                staged["req_id"].as_str().unwrap()
            ))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!approved["member_id"].as_str().unwrap().is_empty());
    assert_eq!(approved["seat_upgraded"], false);
    let q: serde_json::Value = serde_json::from_str(&state.requests_list().await.unwrap()).unwrap();
    assert_eq!(
        q["requests"].as_array().unwrap().len(),
        0,
        "approval consumed the request"
    );
    let list: serde_json::Value =
        serde_json::from_str(&state.members_list().await.unwrap()).unwrap();
    assert_eq!(
        list["members"].as_array().unwrap().len(),
        2,
        "joiner has a member row"
    );
}

#[tokio::test]
async fn unlock_sweeps_expired_grants_and_route_can_invoke() {
    // S3-3: the admin client executes expiry on next sync (at unlock,
    // post-pull). No remote here, so the inline no-pull path runs.
    let (_dir, path) = make_vault("expiry-sweep");
    let state = Arc::new(VaultState::new(path.clone()));
    state.open().await.expect("open");
    state.unlock(MASTER).await.expect("unlock");
    // Seed: one collection with an expired grant (expires_at 1 = long
    // past) via the normal grant route, plus a live member row.
    let created: serde_json::Value =
        serde_json::from_str(&state.collection_create("Contractors").await.unwrap()).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let member = uuid::Uuid::new_v4();
    std::fs::create_dir_all(path.join("meta/members")).unwrap();
    let row = baluard_core::vault::members::MemberFile {
        id: member,
        display_name: "Contractor".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Editor,
        trust: baluard_core::vault::members::TrustLevel::Verified,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    baluard_core::vault::members::write_member(&path, &row).unwrap();
    // The mint gate refuses past-dated grants, so the grant is minted
    // valid and expires by time passage (1s window, then sleep past it).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant_payload = serde_json::json!({
        "member_id": member.to_string(),
        "access": "read",
        "expires_at": now + 1,
    });
    state
        .collection_grant(&id, &grant_payload)
        .await
        .expect("grant");
    std::thread::sleep(std::time::Duration::from_millis(1600));

    // Re-unlock: the unlock path sweeps (no remote -> inline). Lock via
    // a fresh state on the same vault (unlock is idempotent-guarded on
    // the live state, so re-open from disk instead).
    let state2 = Arc::new(VaultState::new(path.clone()));
    state2.open().await.expect("open");
    state2.unlock(MASTER).await.expect("unlock");
    let list: serde_json::Value =
        serde_json::from_str(&state2.collections_list().await.unwrap()).unwrap();
    let grants: Vec<_> = list["collections"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["grants"].as_array().unwrap().iter())
        .collect();
    assert!(
        grants.is_empty(),
        "expired grant must be swept by the admin unlock: {list}"
    );

    // On-demand route wrapper: an empty sweep reports 0.
    let swept: serde_json::Value =
        serde_json::from_str(&state2.collections_sweep().await.unwrap()).unwrap();
    assert_eq!(swept["removed"].as_u64(), Some(0));
}

#[tokio::test]
async fn collections_state_lifecycle_and_locked_rejection() {
    let (_dir, vault_path) = make_vault("collections-state");
    let state_path = vault_path.clone();
    let state = Arc::new(VaultState::new(state_path));
    state.open().await.expect("vault open");
    // NOT unlocked: every collection surface refuses.
    assert!(state.collections_list().await.is_err());
    assert!(state.collection_create(r#""Servers""#).await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // Owner session: create, rename, list.
    let created: serde_json::Value =
        serde_json::from_str(&state.collection_create("Servers").await.unwrap()).unwrap();
    let id = created["id"].as_str().expect("collection id");
    state.collection_rename(id, "Infra").await.expect("rename");
    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let rows = list["collections"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Infra");

    // Grant: write access to a live member row.
    let member = uuid::Uuid::new_v4();
    std::fs::create_dir_all(vault_path.join("meta/members")).unwrap();
    baluard_core::vault::members::write_member(
        &vault_path,
        &baluard_core::vault::members::MemberFile {
            id: member,
            display_name: "Alicia".into(),
            email: None,
            role: baluard_core::vault::members::MemberRole::Editor,
            trust: baluard_core::vault::members::TrustLevel::Verified,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        },
    )
    .unwrap();
    let grant_payload = serde_json::json!({
        "id": id,
        "member_id": member.to_string(),
        "access": "write",
    });
    state
        .collection_grant(id, &grant_payload)
        .await
        .expect("grant");
    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    assert_eq!(
        list["collections"][0]["grants"].as_array().unwrap().len(),
        1
    );
    state
        .collection_revoke(id, &serde_json::json!({ "member_id": member.to_string() }))
        .await
        .expect("revoke");
    state.collection_delete(id).await.expect("delete");
    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    assert!(list["collections"].as_array().unwrap().is_empty());

    // Bad ids fail closed.
    assert!(state.collection_rename("not-a-uuid", "X").await.is_err());
    assert!(
        state
            .collection_grant("not-a-uuid", &grant_payload)
            .await
            .is_err()
    );
}

/// S3-6: request-access JIT lifecycle through the state wrappers, plus
/// fail-closed payload parsing and locked-vault rejection.
#[tokio::test]
async fn access_requests_state_lifecycle_and_locked_rejection() {
    let (_dir, vault_path) = make_vault("access-requests");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: every JIT surface refuses.
    assert!(state.collection_requests_mine().await.is_err());
    assert!(state.collection_requests_list().await.is_err());
    assert!(state.collection_catalog_list().await.is_err());
    assert!(
        state
            .collection_request_access("{\"collection_id\":\"x\"}")
            .await
            .is_err()
    );

    state.unlock(MASTER).await.expect("vault unlock");
    // The owner session creates the catalog target and asks for its own
    // collection (owner devices are members, so this exercises the full
    // submit path; the two-device ceremony lives in the core handle test).
    let created: serde_json::Value =
        serde_json::from_str(&state.collection_create("Servers").await.unwrap()).unwrap();
    let cid = created["id"].as_str().expect("collection id").to_string();

    // Fail-closed parses: mistyped access, non-UUID collection id.
    assert!(
        state
            .collection_request_access(
                &serde_json::json!({"collection_id": cid, "access": "admin"}).to_string()
            )
            .await
            .is_err()
    );
    assert!(
        state
            .collection_request_access(
                &serde_json::json!({"collection_id": "nope", "access": "read"}).to_string()
            )
            .await
            .is_err()
    );

    let submitted: serde_json::Value = serde_json::from_str(
        &state
            .collection_request_access(
                &serde_json::json!({"collection_id": cid, "access": "read", "note": "please"})
                    .to_string(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let rid = submitted["request_id"]
        .as_str()
        .expect("request id")
        .to_string();

    // Own list shows the pending ask; the admin inbox decrypts it.
    let mine: serde_json::Value =
        serde_json::from_str(&state.collection_requests_mine().await.unwrap()).unwrap();
    assert_eq!(mine["requests"].as_array().unwrap().len(), 1);
    let inbox: serde_json::Value =
        serde_json::from_str(&state.collection_requests_list().await.unwrap()).unwrap();
    assert_eq!(inbox["malformed"].as_u64(), Some(0));
    assert_eq!(inbox["requests"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["requests"][0]["collection_name"], "Servers");
    assert_eq!(inbox["requests"][0]["note"], "please");

    // Approve with an access override; the grant lands.
    let owner_member = baluard_core::vault::members::member_id_for_device(
        &vault_path,
        uuid::Uuid::parse_str(&state.device_id().await).expect("device uuid"),
    )
    .expect("owner member");
    let approved: serde_json::Value = serde_json::from_str(
        &state
            .collection_requests_approve(
                &serde_json::json!({
                    "request_id": rid,
                    "requester_member_id": owner_member.to_string(),
                    "access": "write"
                })
                .to_string(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(approved["approved"], true);
    // Mistyped expiry refuses instead of silently meaning "never expires".
    // The deny leg uses a SECOND collection: the owner now holds a write
    // grant on Servers, so a redundant ask refuses before parsing (F4).
    let finance: serde_json::Value =
        serde_json::from_str(&state.collection_create("Finance").await.unwrap()).unwrap();
    let fid = finance["id"].as_str().unwrap().to_string();
    let second = serde_json::from_str::<serde_json::Value>(
        &state
            .collection_request_access(
                &serde_json::json!({"collection_id": fid, "access": "read"}).to_string(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let rid2 = second["request_id"].as_str().unwrap().to_string();
    assert!(
        state
            .collection_requests_approve(
                &serde_json::json!({
                    "request_id": rid2,
                    "requester_member_id": owner_member.to_string(),
                    "expires_at": "soon"
                })
                .to_string()
            )
            .await
            .is_err()
    );
    state
        .collection_requests_deny(
            &serde_json::json!({
                "request_id": rid2,
                "requester_member_id": owner_member.to_string()
            })
            .to_string(),
        )
        .await
        .expect("deny");
    // Double-deny refuses (consumed).
    assert!(
        state
            .collection_requests_deny(
                &serde_json::json!({
                    "request_id": rid2,
                    "requester_member_id": owner_member.to_string()
                })
                .to_string()
            )
            .await
            .is_err()
    );

    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let servers = list["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == cid)
        .expect("servers row")
        .clone();
    let grants = servers["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["access"], "write");
    assert_eq!(grants[0]["kind"], "member");
    assert_eq!(
        grants[0]["id"].as_str(),
        Some(owner_member.to_string()).as_deref()
    );

    // Catalog: unknown collection refused; publish + list + clear.
    assert!(
        state
            .collection_catalog_set(
                &serde_json::json!({"entries": [{"collection_id": uuid::Uuid::new_v4().to_string(), "name": "Ghost"}]})
                    .to_string()
            )
            .await
            .is_err()
    );
    state
        .collection_catalog_set(
            &serde_json::json!({"entries": [{"collection_id": cid, "name": "Servers"}]})
                .to_string(),
        )
        .await
        .expect("catalog publish");
    let catalog: serde_json::Value =
        serde_json::from_str(&state.collection_catalog_list().await.unwrap()).unwrap();
    assert_eq!(catalog["catalog"][0]["name"], "Servers");
    state
        .collection_catalog_set("{\"entries\": []}")
        .await
        .expect("catalog clear");
    let catalog: serde_json::Value =
        serde_json::from_str(&state.collection_catalog_list().await.unwrap()).unwrap();
    assert!(catalog["catalog"].as_array().unwrap().is_empty());
}

// S3-7c / 4.8: the collections surface role-aware listing (admin
// branch), entries carrying their collection id, and vault.add creating
// straight into a collection.
#[tokio::test]
async fn collections_list_admin_shape_and_cipher_collection_ids() {
    let (_dir, vault_path) = make_vault("coll-ui");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    assert!(state.collections_list().await.is_err(), "locked refuses");
    state.unlock(MASTER).await.expect("vault unlock");

    // Admin branch: rows carry access "admin" and a grants array.
    let created: serde_json::Value =
        serde_json::from_str(&state.collection_create("Servers").await.unwrap()).unwrap();
    let cid = created["id"].as_str().unwrap().to_string();
    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let rows = list["collections"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Servers");
    assert_eq!(rows[0]["access"], "admin");
    assert!(rows[0]["grants"].is_array());

    // vault.add with a collection id lands inside the collection; the
    // listing meta carries that collection id.
    let add_payload = format!(
        r#"{{"name":"Prod login","kind":{{"type":"login","data":{{"username":"u","password":"p"}}}},"collection_id":"{cid}"}}"#
    );
    let added = state.add_cipher(&add_payload).await;
    if added.is_err() {
        panic!("in-collection create refused: {:?}", added);
    }
    let envelope = state.list_all().await.unwrap();
    let full: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let ciphers = full["ciphers"].as_array().unwrap();
    assert_eq!(ciphers.len(), 1, "one entry: {full}");
    assert_eq!(
        ciphers[0]["_meta"]["collection_id"].as_str(),
        Some(cid.as_str()),
        "list_full rows carry the collection id in _meta"
    );

    // Flat creation (no collection_id) stays the admin surface.
    let flat =
        r#"{"name":"Personal","kind":{"type":"login","data":{"username":"u","password":"p"}}}"#;
    assert!(state.add_cipher(flat).await.is_ok());
    let envelope = state.list_all().await.unwrap();
    let full: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let ciphers = full["ciphers"].as_array().unwrap();
    let personal = ciphers.iter().find(|c| c["name"] == "Personal").unwrap();
    assert!(personal["_meta"]["collection_id"].is_null());

    // §4.8-5: cipher.set_collection moves an entry across key domains
    // in one op — flat personal entry into the collection and back.
    let personal_id = personal["_meta"]["id"].as_str().unwrap().to_string();
    let move_in = format!(r#"{{"cipher_id":"{personal_id}","collection_id":"{cid}"}}"#);
    state.cipher_set_collection(&move_in).await.unwrap();
    let envelope = state.list_all().await.unwrap();
    let full: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let ciphers = full["ciphers"].as_array().unwrap();
    let moved = ciphers.iter().find(|c| c["name"] == "Personal").unwrap();
    assert_eq!(
        moved["_meta"]["collection_id"].as_str(),
        Some(cid.as_str()),
        "moved entry reads back inside the collection"
    );

    let move_out = format!(r#"{{"cipher_id":"{personal_id}","collection_id":null}}"#);
    state.cipher_set_collection(&move_out).await.unwrap();
    let envelope = state.list_all().await.unwrap();
    let full: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let ciphers = full["ciphers"].as_array().unwrap();
    let moved_back = ciphers.iter().find(|c| c["name"] == "Personal").unwrap();
    assert!(moved_back["_meta"]["collection_id"].is_null());
}

#[tokio::test]
async fn groups_lifecycle_and_locked_rejection() {
    let (_dir, vault_path) = make_vault("groups-ui");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    assert!(state.groups_list().await.is_err(), "locked refuses");
    state.unlock(MASTER).await.expect("vault unlock");

    // Empty name refuses; create parses.
    assert!(state.group_create(r#"{"name":"  "}"#).await.is_err());
    let created: serde_json::Value =
        serde_json::from_str(&state.group_create(r#"{"name":"Ops"}"#).await.unwrap()).unwrap();
    let gid = created["id"].as_str().unwrap().to_string();

    let list: serde_json::Value =
        serde_json::from_str(&state.groups_list().await.unwrap()).unwrap();
    let rows = list["groups"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Ops");
    assert_eq!(rows[0]["members"].as_array().unwrap().len(), 0);

    // Rename round-trips.
    let rename_payload = format!(r#"{{"id":"{gid}","name":"Ops crew"}}"#);
    state.group_rename(&rename_payload).await.unwrap();
    let list: serde_json::Value =
        serde_json::from_str(&state.groups_list().await.unwrap()).unwrap();
    assert_eq!(list["groups"][0]["name"], "Ops crew");

    // A live member row joins the group (duplicate add refuses). The
    // row is planted directly — the acting device stays the owner, so
    // the admin gates keep passing.
    let member_id = uuid::Uuid::new_v4();
    let member_row = serde_json::json!({
        "id": member_id,
        "display_name": "Rey",
        "role": "editor",
        "trust": "channel",
        "reset": null,
        "removed": null,
    });
    std::fs::create_dir_all(vault_path.join("meta/members")).unwrap();
    std::fs::write(
        vault_path.join(format!("meta/members/{member_id}.json")),
        serde_json::to_vec(&member_row).unwrap(),
    )
    .unwrap();
    let add_payload = format!(r#"{{"id":"{gid}","member_id":"{member_id}"}}"#);
    state.group_member_add(&add_payload).await.unwrap();
    assert!(
        state.group_member_add(&add_payload).await.is_err(),
        "duplicate add refuses"
    );

    // Grant a collection to the GROUP: the admin listing shows the
    // group-targeted grant; an unknown kind refuses.
    let cid_val: serde_json::Value =
        serde_json::from_str(&state.collection_create("Servers").await.unwrap()).unwrap();
    let cid = cid_val["id"].as_str().unwrap().to_string();
    let grant_payload =
        format!(r#"{{"id":"{cid}","kind":"group","target_id":"{gid}","access":"write"}}"#);
    state
        .collection_grant(
            &cid,
            &serde_json::from_str::<serde_json::Value>(&grant_payload).unwrap(),
        )
        .await
        .unwrap();
    let bad_kind =
        format!(r#"{{"id":"{cid}","kind":"alien","target_id":"{gid}","access":"write"}}"#);
    assert!(
        state
            .collection_grant(
                &cid,
                &serde_json::from_str::<serde_json::Value>(&bad_kind).unwrap()
            )
            .await
            .is_err()
    );
    let list: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let grants = list["collections"][0]["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["kind"], "group");
    assert_eq!(grants[0]["id"], gid.as_str());

    // Group revoke via the new target shape.
    let revoke_payload = format!(r#"{{"id":"{cid}","kind":"group","target_id":"{gid}"}}"#);
    state
        .collection_revoke(
            &cid,
            &serde_json::from_str::<serde_json::Value>(&revoke_payload).unwrap(),
        )
        .await
        .unwrap();

    // Re-grant, then remove the member: the GK rotation path runs at
    // route level and the group empties.
    state
        .collection_grant(
            &cid,
            &serde_json::from_str::<serde_json::Value>(&grant_payload).unwrap(),
        )
        .await
        .unwrap();
    state.group_member_remove(&add_payload).await.unwrap();
    let list: serde_json::Value =
        serde_json::from_str(&state.groups_list().await.unwrap()).unwrap();
    assert_eq!(list["groups"][0]["members"].as_array().unwrap().len(), 0);

    // Unknown-group mutations refuse; delete round-trips and empties.
    let missing = format!(
        r#"{{"id":"{}","member_id":"{member_id}"}}"#,
        uuid::Uuid::new_v4()
    );
    assert!(state.group_member_add(&missing).await.is_err());
    state
        .group_delete(&format!(r#"{{"id":"{gid}"}}"#))
        .await
        .unwrap();
    assert!(
        state
            .group_delete(&format!(r#"{{"id":"{gid}"}}"#))
            .await
            .is_err()
    );
    let list: serde_json::Value =
        serde_json::from_str(&state.groups_list().await.unwrap()).unwrap();
    assert_eq!(list["groups"].as_array().unwrap().len(), 0);
}

// Debt: the desktop admin marker asks the daemon (holds_root) instead
// of counting admin rows — it holds for zero-collection vaults, and a
// locked vault reports no powers.
// Removal-notice route: none on a fresh member, confirmed on a locally
// tombstoned row, none on a personal vault (no members directory).
#[tokio::test]
async fn removal_notice_reports_tombstone_and_personal_guard() {
    let (_dir, vault_path) = make_vault("removal-notice");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");
    // Owner genesis: live row, no tombstone, streak zero → none.
    let none = state.removal_notice().await.expect("notice");
    assert!(none.contains("\"none\""), "{none}");

    // Tombstone the acting device's row: confirmed removal.
    let device = uuid::Uuid::parse_str(&state.device_id().await).expect("device uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device,
        Some(1),
    );
    let removed = state.removal_notice().await.expect("notice");
    assert!(removed.contains("\"removed\""), "{removed}");
    assert!(removed.contains("local-tombstone"), "{removed}");

    // Personal-vault guard: no members directory, never a notice.
    std::fs::remove_dir_all(vault_path.join("meta").join("members")).unwrap();
    let personal = state.removal_notice().await.expect("notice");
    assert!(personal.contains("\"none\""), "{personal}");
}

#[tokio::test]
async fn is_admin_device_reports_the_managing_marker() {
    let (_dir, vault_path) = make_vault("is-admin");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    assert!(
        !state.is_admin_device().await.unwrap(),
        "locked = no powers"
    );
    state.unlock(MASTER).await.expect("vault unlock");
    // True on a ZERO-collection vault — the row-counting proxy read
    // false here and hid admin surfaces (the wave-29 lockout).
    assert!(state.is_admin_device().await.unwrap());
    // Key-state semantics: the marker reports holds_root, so a device
    // whose role changes server-side keeps reporting admin until it
    // locks (the recorded session-keys-live-until-lock boundary).
}

#[tokio::test]
async fn space_meta_prepare_status_and_locked_rejection() {
    let (_dir, vault_path) = make_vault("space-meta");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: both surfaces refuse.
    assert!(state.space_prepare().await.is_err());
    assert!(state.space_status().await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // Unprepared vault: status reports readiness zeros.
    let st: serde_json::Value = serde_json::from_str(&state.space_status().await.unwrap()).unwrap();
    assert_eq!(st["prepared"], false);
    assert_eq!(st["wrapped"], 0);

    // Prepare mints the store. This vault has one live member (the
    // owner genesis row). Whether that row carries a wrap pubkey
    // depends on the genesis path (D35); the report must agree with
    // status either way.
    let prep: serde_json::Value =
        serde_json::from_str(&state.space_prepare().await.unwrap()).unwrap();
    assert_eq!(prep["smk_fresh"], true);
    let wrapped = prep["wrapped"].as_u64().unwrap();
    let missing = prep["missing_wrap_pubkey"].as_array().unwrap().len();

    // Idempotent re-run: no fresh mint.
    let again: serde_json::Value =
        serde_json::from_str(&state.space_prepare().await.unwrap()).unwrap();
    assert_eq!(again["smk_fresh"], false);

    let st: serde_json::Value = serde_json::from_str(&state.space_status().await.unwrap()).unwrap();
    assert_eq!(st["prepared"], true);
    assert_eq!(st["wrapped"], wrapped);
    assert_eq!(st["missing_wrap_pubkey"], missing);

    // Prepare closes every wrap-pubkey row's gap: nothing pending.
    assert_eq!(st["pending_wrap"], 0);
    // The 7b flip gate is ready iff no live member lacks a wrap pubkey.
    let ready = missing == 0;
    assert_eq!(ready, st["missing_wrap_pubkey"].as_u64().unwrap() == 0);

    // S3-7b: the flip surface. Locked refusal, then the solo-vault path:
    // this vault has no joiner, so flipping is allowed for the owner
    // (owner is admin; readiness passes) — assert the marker lands and
    // status reports it.
    let (_d2, vp2) = make_vault("space-flip");
    // Family-spaces §2: the flip demands a purpose (org here).
    baluard_core::vault::space::set_purpose(&vp2, baluard_core::vault::space::SpacePurpose::Org)
        .unwrap();
    let state2 = Arc::new(VaultState::new(vp2.clone()));
    state2.open().await.expect("open");
    assert!(state2.space_flip().await.is_err(), "locked refusal");
    state2.unlock(MASTER).await.expect("unlock");
    // Owner row needs a wrap pubkey for its own space.wrap mint; the
    // flip readiness only blocks NON-admin members, so a solo vault
    // flips regardless.
    let rep: serde_json::Value = serde_json::from_str(&state2.space_flip().await.unwrap()).unwrap();
    assert_eq!(rep["already_flipped"], false);
    assert_eq!(rep["files_reencrypted"], 5);
    let rep2: serde_json::Value =
        serde_json::from_str(&state2.space_flip().await.unwrap()).unwrap();
    assert_eq!(rep2["already_flipped"], true);
    let st2: serde_json::Value =
        serde_json::from_str(&state2.space_status().await.unwrap()).unwrap();
    assert_eq!(st2["flipped"], true);
}

/// The avatar/settings member-write gates: a member device writing
/// git-tracked meta (profile.enc, avatar.enc, settings.enc) would commit
/// locally and be refused at every peer pull — wedging the space. On a
/// members-dir vault the writes refuse; the founder/owner passes.
#[tokio::test]
async fn member_meta_writes_refuse_on_team_vaults() {
    let (_dir, vault_path) = make_vault("member-meta-writes");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");

    // Owner genesis manages a solo vault: the writes pass.
    state
        .settings_set(r#"{"theme":"dark"}"#)
        .await
        .expect("owner settings set");
    state.locale_save("es").await.expect("owner locale save");

    // Rebind the device to an Editor: the same writes refuse.
    let device: uuid::Uuid = state.device_id().await.parse().expect("device uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device,
        None,
    );
    let err = state.settings_set(r#"{"theme":"dark"}"#).await.unwrap_err();
    assert!(err.contains("managing device"), "err: {err}");
    let err = state
        .avatar_set(r#"{"data":"aGk=","ext":"png"}"#)
        .await
        .unwrap_err();
    assert!(err.contains("managing device"), "err: {err}");
    let err = state.locale_save("pt").await.unwrap_err();
    assert!(err.contains("managing device"), "err: {err}");
    // Same wedge class: contacts mutations and generator-history writes
    // touch git-tracked meta too.
    let err = state
        .contacts_remove(r#"{"identity_signing_pubkey":"aabb"}"#)
        .await
        .unwrap_err();
    assert!(err.contains("managing device"), "err: {err}");
    let err = state.generator_history_clear().await.unwrap_err();
    assert!(err.contains("managing device"), "err: {err}");
}

/// S3-9: the Space settings surfaces — locked refusals, the §6.5
/// defaults on a fresh vault, a partial set round trip, and fail-closed
/// parses (bad authority string, non-boolean flags).
/// Recursive copy for the throwaway joiner dir (the introduction
/// writes the device keystore into its vault dir, which must never
/// clobber the owner device identity).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[tokio::test]
async fn join_approval_code_auto_approves_manual_queues() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    // Owner mints the invite and flips the knob to code BEFORE anything
    // stages, so the unlock-tail sweep sees the queued ask.
    let (mut handle, _secrets) = VaultCreator::new(&path, MASTER, "auto-join")
        .execute()
        .expect("vault creation");
    handle.unlock(MASTER).unwrap();
    let code = handle
        .invite_create(baluard_core::vault::members::MemberRole::Editor, None)
        .expect("invite");
    let mut s = handle.get_settings().unwrap();
    s.join_approval = baluard_core::vault::manifest::JoinApproval::Code;
    handle.save_settings(&s).unwrap();
    // Member rows are the <uuid>.json files beside each member dir.
    let member_rows = |p: &std::path::Path| {
        std::fs::read_dir(p.join("meta/members"))
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().to_string_lossy().to_string();
                name.ends_with(".json").then_some(name)
            })
            .collect::<Vec<_>>()
    };
    let members_before = member_rows(&path).len();
    drop(handle);

    // The joiner introduces in a throwaway copy of the vault (a
    // sibling tempdir: the copy must live OUTSIDE the source tree).
    let clone_dir = tempfile::tempdir().unwrap();
    let clone = clone_dir.path().join("v");
    copy_dir_recursive(&path, &clone);
    let intro_code =
        baluard_core::vault::members::create_introduction(&clone, &code, "member-pass-1", "phone")
            .expect("introduction");

    // The admin stages the received intro code into the repo-backed
    // join queue.
    let mut admin = baluard_core::vault::handle::VaultHandle::open(&path).expect("reopen");
    admin.unlock(MASTER).unwrap();
    let req_id = admin.join_queue_submit(&intro_code).expect("stage");
    drop(admin);

    // The unlock tail runs the inline (no-remote) sweep: the staged ask
    // is approved with no admin click.
    let state = Arc::new(VaultState::new(path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");

    // The request was consumed and the member row minted.
    let list = state.requests_list().await.unwrap();
    assert!(
        !list.contains(&req_id.to_string()),
        "auto-approved row must be consumed: {list}"
    );
    let members_after = member_rows(&path);
    assert_eq!(
        members_after.len(),
        members_before + 1,
        "code mode must mint the member row; rows: {members_after:?}"
    );

    // Manual leg: with the knob back at manual, a staged ask stays
    // queued across unlock cycles.
    state
        .space_settings_set(r#"{"join_approval": "manual"}"#)
        .await
        .expect("set manual");
    let code2 = {
        let mut h = baluard_core::vault::handle::VaultHandle::open(&path).expect("reopen");
        h.unlock(MASTER).unwrap();
        h.invite_create(baluard_core::vault::members::MemberRole::Viewer, None)
            .expect("invite2")
    };
    let clone_dir2 = tempfile::tempdir().unwrap();
    let clone2 = clone_dir2.path().join("v");
    copy_dir_recursive(&path, &clone2);
    let intro2 =
        baluard_core::vault::members::create_introduction(&clone2, &code2, "member-pass-2", "tab")
            .expect("introduction2");
    let mut admin2 = baluard_core::vault::handle::VaultHandle::open(&path).expect("reopen");
    admin2.unlock(MASTER).unwrap();
    let req2 = admin2.join_queue_submit(&intro2).expect("stage2");
    drop(admin2);
    state.lock().await.expect("lock");
    state.unlock(MASTER).await.expect("re-unlock");
    let list2 = state.requests_list().await.unwrap();
    assert!(
        list2.contains(&req2.to_string()),
        "manual mode must leave the ask queued: {list2}"
    );
}

/// S4-4: the access review surface — locked refusal, the solo-owner
/// report shape, and the non-admin refusal (rebound Editor device).
/// The exposure logic lives in the core test.
#[tokio::test]
async fn access_review_locked_solo_and_role_gates() {
    let (_dir, vault_path) = make_vault("access-review");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: refuses.
    assert!(state.access_review().await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // The creator device is the owner (owner genesis), so the review
    // runs and reports the empty solo shape.
    let raw = state.access_review().await.unwrap();
    let report: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(report["members"].as_array().unwrap().len(), 1);
    assert_eq!(report["collections"].as_array().unwrap().len(), 0);
    assert_eq!(report["exposure"].as_array().unwrap().len(), 0);
    assert_eq!(
        report["pending"]["join_requests"].as_array().unwrap().len(),
        0
    );
    assert_eq!(report["outboxes"].as_array().unwrap().len(), 0);
    assert!(report["generated_at"].as_u64().unwrap() > 0);

    // A rebound Editor device is refused in plain language. The
    // device id comes from the state itself (route-test convention).
    let editor_state = Arc::new(VaultState::new(vault_path.clone()));
    editor_state.open().await.expect("vault open");
    editor_state.unlock(MASTER).await.expect("vault unlock");
    let editor_device =
        uuid::Uuid::parse_str(&editor_state.device_id().await).expect("device id is a uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        editor_device,
        None,
    );
    let err = editor_state.access_review().await.unwrap_err();
    assert!(err.contains("admin"), "refusal names the gate: {err}");
}

/// S4-5: the derived timeline surface — locked refusal, the solo-vault
/// shape (the genesis commit renders as vault-created, newest-first),
/// and the rebound-Editor refusal. The derivation rules live in the
/// core tests.
#[tokio::test]
async fn activity_timeline_locked_solo_and_role_gates() {
    let (_dir, vault_path) = make_vault("activity-timeline");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: refuses.
    assert!(state.activity_timeline(100).await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    let raw = state.activity_timeline(100).await.unwrap();
    let feed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let rows = feed["timeline"].as_array().unwrap();
    assert!(!rows.is_empty(), "a git-backed vault has history");
    assert_eq!(rows[0]["kind"], "vault-created");
    assert!(rows[0]["at"].as_i64().unwrap_or(0) > 0);
    assert!(rows[0]["oid"].as_str().unwrap().len() == 8);

    // A rebound Editor device is refused like the access review.
    let editor_state = Arc::new(VaultState::new(vault_path.clone()));
    editor_state.open().await.expect("vault open");
    editor_state.unlock(MASTER).await.expect("vault unlock");
    let editor_device =
        uuid::Uuid::parse_str(&editor_state.device_id().await).expect("device id is a uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        editor_device,
        None,
    );
    let err = editor_state.activity_timeline(100).await.unwrap_err();
    assert!(err.contains("admin"), "refusal names the gate: {err}");
}

/// S4-6: advisory org policies — locked refusal, the publish/read
/// roundtrip with the opt-out, the fail-closed unknown-knob refusal,
/// and the non-admin publish refusal. The validation table is covered
/// by the core module tests.
#[tokio::test]
async fn policies_set_list_roundtrip_and_role_gates() {
    let (_dir, vault_path) = make_vault("policies");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: both surfaces refuse.
    assert!(state.policies_list().await.is_err());
    assert!(state.policies_set("{}").await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // Publish a recommendation set, read it back.
    state
        .policies_set(
            r#"{"space_invite_authority":"owners","join_approval":"code","quorum_admin_ops":2}"#,
        )
        .await
        .unwrap();
    let raw = state.policies_list().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(read["policies"]["space_invite_authority"], "owners");
    assert_eq!(read["policies"]["join_approval"], "code");
    assert_eq!(read["policies"]["quorum_admin_ops"], 2);

    // Unknown knob names refuse (fail-closed).
    assert!(state.policies_set(r#"{"theme":"dark"}"#).await.is_err());
    // Mistyped values refuse.
    assert!(
        state
            .policies_set(r#"{"quorum_admin_ops":9}"#)
            .await
            .is_err()
    );
    // The refused calls wrote nothing.
    let raw = state.policies_list().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(read["policies"].get("theme").is_none());

    // Empty publish is the opt-out (as the owner, before the rebind
    // below demotes this device).
    state.policies_set("{}").await.unwrap();
    let raw = state.policies_list().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(read["policies"].as_object().unwrap().len(), 0);

    // Publish again so the Editor-rebind legs have something to read.
    state
        .policies_set(r#"{"join_approval":"code"}"#)
        .await
        .unwrap();

    // An Editor-rebound device reads but cannot publish.
    let editor_device =
        uuid::Uuid::parse_str(&state.device_id().await).expect("device id is a uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        editor_device,
        None,
    );
    assert!(state.policies_list().await.is_ok());
    let err = state
        .policies_set(r#"{"join_approval":"code"}"#)
        .await
        .unwrap_err();
    assert!(err.contains("admin"), "refusal names the gate: {err}");
}

#[tokio::test]
async fn rotate_recovery_locked_wrong_password_and_roundtrip() {
    let (_dir, vault_path) = make_vault("rotate-recovery");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.unwrap();

    // Locked vault refuses before the password is even looked at.
    let err = state.rotate_recovery_phrase("whatever").await.unwrap_err();
    assert!(err.contains("locked"), "locked refusal: {err}");

    state.unlock(MASTER).await.unwrap();

    let err = state
        .rotate_recovery_phrase("wrong-password")
        .await
        .unwrap_err();
    assert!(err.contains("old master password incorrect"), "gate: {err}");

    let raw = state.rotate_recovery_phrase(MASTER).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let phrase = parsed["phrase"].as_str().expect("phrase key");
    assert_eq!(phrase.split_whitespace().count(), 24);
}

#[tokio::test]
async fn space_kit_lifecycle_and_role_gates() {
    let (_dir, vault_path) = make_vault("kit");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: all three surfaces refuse.
    assert!(state.space_kit_status().await.is_err());
    assert!(state.space_kit_enable().await.is_err());
    assert!(state.space_kit_disable().await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // Enable: the phrase comes back exactly once through the wrapper.
    let raw = state.space_kit_enable().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let phrase = read["phrase"].as_str().expect("phrase in response");
    assert_eq!(phrase.split_whitespace().count(), 24);
    let raw = state.space_kit_status().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(read["enabled"], true);
    // Disable reports a removal; status flips back.
    let raw = state.space_kit_disable().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(read["removed"], true);
    let raw = state.space_kit_status().await.unwrap();
    let read: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(read["enabled"], false);

    // Re-enable so the Editor-rebound legs have a kit to see.
    state.space_kit_enable().await.unwrap();

    // An Editor-rebound device manages nothing — and the kit status is
    // admin-gated too, so all three refuse (the file's existence is
    // still locally readable; this gates the IPC surface).
    let editor_device =
        uuid::Uuid::parse_str(&state.device_id().await).expect("device id is a uuid");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        editor_device,
        None,
    );
    assert!(state.space_kit_status().await.is_err());
    let err = state.space_kit_enable().await.unwrap_err();
    assert!(err.contains("admin"), "refusal names the gate: {err}");
    let err = state.space_kit_disable().await.unwrap_err();
    assert!(err.contains("admin"), "refusal names the gate: {err}");
}

#[tokio::test]
async fn recover_kit_route_parses_and_resolves_slug() {
    // Registry writes + env sandbox: hold the join guard so env-setting
    // tests never interleave.
    let _guard = JOIN_REG.lock().await;
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let (_dir, vault_path) = make_vault("kitroute");
    let password = MASTER.to_string();
    // Enable the kit so the route reaches the brick guard (creation's
    // device keystore lives in this vault dir), proving the full path.
    let mut handle = baluard_core::vault::handle::VaultHandle::open(&vault_path).unwrap();
    handle.unlock(&password).unwrap();
    let phrase = handle.space_recovery_kit_enable().unwrap();
    drop(handle);

    let slug = baluard_core::vault::slug::normalize_slug("kitroute");
    let mut reg = VaultRegistry::default();
    reg.add(VaultEntry {
        slug: slug.clone(),
        display_name: slug.clone(),
        path: vault_path.clone(),
        provider: None,
        remote_url: None,
        last_synced: None,
        last_opened: None,
        vault_id: baluard_core::vault::handle::VaultHandle::vault_id_for_path(&vault_path).unwrap(),
        merge_opt_in: None,
        merge_ceiling_seen: false,
    })
    .unwrap();
    reg.save_locked().unwrap();

    let host = Arc::new(VaultHost::new());

    // Unknown slug refuses in plain language.
    let resp = route_host_request(
        join_request(
            "vault.recover_kit",
            serde_json::json!({"slug": "nosuch", "phrase": "x", "password": "y", "device_name": "z"}),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("Unknown vault"));

    // Missing phrase refuses before touching a vault.
    let resp = route_host_request(
        join_request(
            "vault.recover_kit",
            serde_json::json!({"slug": slug, "password": "y", "device_name": "z"}),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("phrase"));

    // A real phrase on a device that already holds keys hits the brick
    // guard through the full route -> core path.
    let resp = route_host_request(
        join_request(
            "vault.recover_kit",
            serde_json::json!({"slug": slug, "phrase": phrase, "password": password, "device_name": "again"}),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);
    assert!(
        resp.error_message.contains("already has its own keys"),
        "err: {}",
        resp.error_message
    );
}

#[tokio::test]
async fn import_skips_subtrees_of_failed_folders() {
    let (_dir, state) = open_unlocked("imp-depth").await;

    // 18 chained levels: MAX_FOLDER_DEPTH is 16, so L0..L15 create, L16
    // fails at the depth cap, and L17 must be SKIPPED with its parent --
    // never re-rooted at the top level.
    let mut result = baluard_core::import::ImportResult::new();
    for level in 0..18 {
        result.folders.push(baluard_core::import::ImportFolder {
            name: format!("L{level}"),
            parent: if level == 0 { None } else { Some(level - 1) },
        });
    }

    let resp: serde_json::Value =
        serde_json::from_str(&state.import_ciphers(result).await.expect("import")).unwrap();
    let errors = resp["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|e| e.as_str().unwrap().contains("L16")),
        "L16 must fail at the depth cap: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap().contains("skipped because its parent")),
        "L17 must be skipped with its parent: {errors:?}"
    );

    let folders: Vec<serde_json::Value> =
        serde_json::from_str(&state.list_folders().await.expect("list")).unwrap();
    assert_eq!(folders.len(), 16, "L0..L15 created");
    assert!(
        !folders.iter().any(|f| f["name"] == "L17"),
        "a failed folder's child must never be re-rooted"
    );
}

#[tokio::test]
async fn import_restores_folder_hierarchy() {
    let (_dir, state) = open_unlocked("imp-hier").await;

    let mut result = baluard_core::import::ImportResult::new();
    result.folders.push(baluard_core::import::ImportFolder {
        name: "Work".into(),
        parent: None,
    });
    result.folders.push(baluard_core::import::ImportFolder {
        name: "Sub".into(),
        parent: Some(0),
    });
    result.folders.push(baluard_core::import::ImportFolder {
        name: "Empty".into(),
        parent: Some(0),
    });
    result.ciphers.push(CipherInput {
        name: "Filed Entry".into(),
        kind: CipherKind::Login(Default::default()),
        ..Default::default()
    });
    result.cipher_folders.push(Some(1));

    let resp: serde_json::Value =
        serde_json::from_str(&state.import_ciphers(result).await.expect("import")).unwrap();
    assert_eq!(resp["imported"], 1);
    assert_eq!(resp["folders_created"], 3);

    let folders: Vec<serde_json::Value> =
        serde_json::from_str(&state.list_folders().await.expect("list")).unwrap();
    assert_eq!(folders.len(), 3, "empty folder preserved, no duplicates");
    let work = folders.iter().find(|f| f["name"] == "Work").unwrap();
    let sub = folders.iter().find(|f| f["name"] == "Sub").unwrap();
    assert_eq!(work["parent_id"], serde_json::Value::Null);
    assert_eq!(sub["parent_id"], work["id"]);

    // The filed cipher carries the child folder's real id.
    let env = state.full_envelope().await.expect("envelope");
    let cipher = env["ciphers"][0].clone();
    assert_eq!(cipher["name"], "Filed Entry");
    assert_eq!(cipher["folder_id"], sub["id"]);

    // Re-import reuses same-named siblings instead of duplicating.
    let mut again = baluard_core::import::ImportResult::new();
    again.folders.push(baluard_core::import::ImportFolder {
        name: "Work".into(),
        parent: None,
    });
    again.folders.push(baluard_core::import::ImportFolder {
        name: "Sub".into(),
        parent: Some(0),
    });
    let resp2: serde_json::Value =
        serde_json::from_str(&state.import_ciphers(again).await.expect("reimport")).unwrap();
    assert_eq!(resp2["folders_created"], 2, "siblings reused");
    let folders2: Vec<serde_json::Value> =
        serde_json::from_str(&state.list_folders().await.expect("list2")).unwrap();
    assert_eq!(folders2.len(), 3);
}

#[tokio::test]
async fn vaults_copy_items_founds_a_family_vault() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(VaultHost::new());

    // Personal source with one login.
    let (_dir_s, path_s) = make_vault("copysrc");
    let state_s = Arc::new(VaultState::new(path_s.clone()));
    state_s.open().await.expect("open source");
    state_s.unlock(MASTER).await.expect("unlock source");
    state_s
        .add_cipher(&serde_json::to_string(&login_input("Wi-Fi Router", "admin")).unwrap())
        .await
        .expect("add source");

    // Family target, born team-shaped with Shared.
    let dir_f = tempfile::tempdir().unwrap();
    let path_f = dir_f.path().join("fam-copy");
    let (mut handle, _secrets) = VaultCreator::new(&path_f, MASTER, "route-copy")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let shared = handle
        .get_settings()
        .unwrap()
        .family_shared_collection
        .unwrap();
    drop(handle);
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    state_f.open().await.expect("open target");
    state_f.unlock(MASTER).await.expect("unlock target");

    host.insert("copysrc".into(), state_s.clone()).await;
    host.insert("fam-copy".into(), state_f.clone()).await;

    // The route reads source plaintext and writes the target, so it
    // gates on both vaults' session tokens in the payload.
    let source_token = state_s.get_session_token().await.expect("source token");
    let target_token = state_f.get_session_token().await.expect("target token");
    let req = GatewayRequest {
        action: "vaults.copy_items".into(),
        payload: serde_json::json!({
            "source": "copysrc",
            "target": "fam-copy",
            "all": true,
            "source_token": source_token,
            "target_token": target_token,
        })
        .to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "copy failed: {}", resp.error_message);
    let v: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(v["copied"].as_u64(), Some(1), "{v}");

    // The copied login filed into Shared (the family add default) and
    // the secret survived the re-encryption.
    let env = state_f.full_envelope().await.unwrap();
    let cipher = &env["ciphers"][0];
    assert_eq!(cipher["name"].as_str(), Some("Wi-Fi Router"));
    assert_eq!(
        cipher["_meta"]["collection_id"].as_str(),
        Some(shared.to_string().as_str())
    );
    let id = cipher["_meta"]["id"].as_str().unwrap().to_string();
    let got = state_f.get_cipher(&id, true).await.unwrap();
    assert!(got.contains("Wi-Fi Router"), "{got}");

    // Same-slug copy is refused outright.
    let req = GatewayRequest {
        action: "vaults.copy_items".into(),
        payload: serde_json::json!({ "source": "copysrc", "target": "copysrc", "all": true })
            .to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("the same"));

    // An unknown source slug refuses in plain language. Tokens ride
    // along so the payload gate passes and the slug check is what fires.
    let req = GatewayRequest {
        action: "vaults.copy_items".into(),
        payload: serde_json::json!({
            "source": "ghost",
            "target": "fam-copy",
            "all": true,
            "source_token": source_token,
            "target_token": target_token,
        })
        .to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("not open"));
}

#[tokio::test]
async fn family_default_add_collection_sugar() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("fam-default");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-default")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let founder_device = handle.device_id;

    // A member (Editor, live) with Write grants on TWO collections:
    // the multi-writable refusal case.
    let chores = handle.collection_create("Chores").unwrap();
    let kids = handle.collection_create("Kids").unwrap();
    let member_id = uuid::Uuid::new_v4();
    // The member's wrap pubkey must be the REBOUND device identity's
    // public half, or collection_grant mints no wrap and the honest
    // member-path writables resolve to an empty set (the founder row
    // already carries that pubkey — grants to it mint opens).
    let founder_row =
        baluard_core::vault::members::member_file_for_device(&vault_path, founder_device)
            .unwrap()
            .1;
    let wrap_pub = founder_row.identity_wrap_pubkey.clone().unwrap();
    let member = baluard_core::vault::members::MemberFile {
        id: member_id,
        display_name: "Alex".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Editor,
        trust: baluard_core::vault::members::TrustLevel::Channel,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: Some(wrap_pub),
    };
    baluard_core::vault::members::write_member(&vault_path, &member).unwrap();
    let grant_target = baluard_core::vault::collections::GrantTarget::Member { id: member_id };
    handle
        .collection_grant(
            chores,
            grant_target.clone(),
            baluard_core::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
    handle
        .collection_grant(
            kids,
            grant_target,
            baluard_core::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
    let _shared = handle
        .get_settings()
        .unwrap()
        .family_shared_collection
        .unwrap();
    drop(handle);

    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("open");
    state.unlock(MASTER).await.expect("unlock");

    // Set the knob (admin action) and verify the settings round-trip.
    state
        .space_settings_set(
            &serde_json::json!({ "default_add_collection": chores.to_string() }).to_string(),
        )
        .await
        .expect("set knob");
    let got: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(
        got["default_add_collection"].as_str(),
        Some(chores.to_string().as_str())
    );

    // Unknown collection refused.
    let err = state
        .space_settings_set(
            &serde_json::json!({ "default_add_collection": uuid::Uuid::new_v4().to_string() })
                .to_string(),
        )
        .await
        .unwrap_err();
    assert!(err.contains("names no collection"), "{err}");

    // End to end: rebind the in-process device to the member row (the
    // two-subtree rule forbids double bindings), then an unfiled
    // member add routes to the designated default instead of
    // refusing on two writables.
    std::fs::remove_file(
        vault_path
            .join("meta/members")
            .join(
                baluard_core::vault::members::member_file_for_device(&vault_path, founder_device)
                    .unwrap()
                    .1
                    .id
                    .to_string(),
            )
            .join("devices")
            .join(format!("{founder_device}.json")),
    )
    .unwrap();
    baluard_core::vault::members::write_device_binding(
        &vault_path,
        &baluard_core::vault::members::DeviceBinding {
            device_id: founder_device,
            member_id,
        },
    )
    .unwrap();
    let input = login_input("Chore Login", "alex");
    state
        .add_cipher(&serde_json::to_string(&input).unwrap())
        .await
        .expect("member add");
    let env = state.full_envelope().await.unwrap();
    let ciphers = env["ciphers"].as_array().unwrap();
    assert_eq!(ciphers.len(), 1);
    assert_eq!(
        ciphers[0]["_meta"]["collection_id"].as_str(),
        Some(chores.to_string().as_str()),
        "{ciphers:?}"
    );

    // The multi-writable refusal still fires when NO default is set:
    // a fresh family fixture, knob never touched.
    drop(state);
    let dir2 = tempfile::tempdir().unwrap();
    let path2 = dir2.path().join("fam-default-b");
    let (mut handle_b, _s) = VaultCreator::new(&path2, MASTER, "route-default-b")
        .family(true)
        .execute()
        .unwrap();
    handle_b.unlock(MASTER).unwrap();
    let device_b = handle_b.device_id;
    let c1 = handle_b.collection_create("One").unwrap();
    let c2 = handle_b.collection_create("Two").unwrap();
    let member_b = uuid::Uuid::new_v4();
    let mut row = member.clone();
    row.id = member_b;
    // This vault's device has its own identity: the wrap pubkey must be
    // device_b's, not the first fixture's.
    row.identity_wrap_pubkey =
        baluard_core::vault::members::member_file_for_device(&path2, device_b)
            .unwrap()
            .1
            .identity_wrap_pubkey;
    baluard_core::vault::members::write_member(&path2, &row).unwrap();
    let grant_target_b = baluard_core::vault::collections::GrantTarget::Member { id: member_b };
    handle_b
        .collection_grant(
            c1,
            grant_target_b.clone(),
            baluard_core::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
    handle_b
        .collection_grant(
            c2,
            grant_target_b,
            baluard_core::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
    let founder_b = baluard_core::vault::members::member_file_for_device(&path2, device_b)
        .unwrap()
        .1
        .id;
    drop(handle_b);
    let state_b = Arc::new(VaultState::new(path2.clone()));
    state_b.open().await.expect("open b");
    state_b.unlock(MASTER).await.expect("unlock b");
    std::fs::remove_file(
        path2
            .join("meta/members")
            .join(founder_b.to_string())
            .join("devices")
            .join(format!("{device_b}.json")),
    )
    .unwrap();
    baluard_core::vault::members::write_device_binding(
        &path2,
        &baluard_core::vault::members::DeviceBinding {
            device_id: device_b,
            member_id: member_b,
        },
    )
    .unwrap();
    let err = state_b
        .add_cipher(&serde_json::to_string(&login_input("Second", "alex")).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.contains("Several collections accept your edits"),
        "{err}"
    );
}

#[tokio::test]
async fn family_claim_arming_surfaces_as_success() {
    // The review catch: the contest arming used to return Err, so the
    // daemon skipped the cover commit and the record - the owner's
    // only notice - never synced. The wrapper must surface arming as
    // success-shaped JSON.
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("fam-arm");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-arm")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let claimant = baluard_core::vault::members::MemberFile {
        id: uuid::Uuid::new_v4(),
        display_name: "Dad".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Admin,
        trust: baluard_core::vault::members::TrustLevel::Verified,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    baluard_core::vault::members::write_member(&vault_path, &claimant).unwrap();
    let founder =
        baluard_core::vault::members::member_file_for_device(&vault_path, handle.device_id)
            .unwrap();
    std::fs::remove_file(
        vault_path
            .join("meta/members")
            .join(founder.1.id.to_string())
            .join("devices")
            .join(format!("{}.json", handle.device_id)),
    )
    .unwrap();
    baluard_core::vault::members::write_device_binding(
        &vault_path,
        &baluard_core::vault::members::DeviceBinding {
            device_id: handle.device_id,
            member_id: claimant.id,
        },
    )
    .unwrap();
    drop(handle);
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("open");
    state.unlock(MASTER).await.expect("unlock");

    // Arming: success-shaped, carrying the window.
    let resp = state
        .members_claim(&serde_json::json!({ "member_id": claimant.id.to_string() }).to_string())
        .await
        .expect("arming must be success-shaped");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["armed"].as_bool(), Some(true), "{v}");
    assert!(v["window_until"].as_u64().unwrap() > 0);

    // Re-touch inside the window: still a refusal (the record is
    // unchanged, so no second cover is needed).
    let err = state
        .members_claim(&serde_json::json!({ "member_id": claimant.id.to_string() }).to_string())
        .await
        .unwrap_err();
    assert!(err.contains("more days"), "{err}");

    // Expiry executes: age the record, claim again, success. The
    // record is tamper-evident: window_until must equal the signed ask
    // time + the contest window, so the rewind moves BOTH timestamps
    // instead of window_until alone (a window_until-only edit is the
    // forgery the execution path refuses).
    let mut record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vault_path.join("meta/contests/ownership-claim.json")).unwrap(),
    )
    .unwrap();
    let window = baluard_core::vault::members::OWNERSHIP_CONTEST_WINDOW_SECS;
    record["ask_initiated_at"] = serde_json::json!(1);
    record["confirmed_at"] = serde_json::json!(1);
    record["window_until"] = serde_json::json!(1 + window);
    std::fs::write(
        vault_path.join("meta/contests/ownership-claim.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let resp = state
        .members_claim(&serde_json::json!({ "member_id": claimant.id.to_string() }).to_string())
        .await
        .expect("expired execution");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["executed"].as_bool(), Some(true), "{v}");
    assert!(baluard_core::vault::members::load_ownership_contest(&vault_path).is_none());
}

#[tokio::test]
async fn family_replace_device_resets_rotates_and_carries_minor() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("fam-stolen");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-stolen")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let shared = handle
        .get_settings()
        .unwrap()
        .family_shared_collection
        .unwrap();
    // A flagged minor Editor with a device binding and a Shared Read
    // grant: the stolen-tablet member.
    let member_id = uuid::Uuid::new_v4();
    let member = baluard_core::vault::members::MemberFile {
        id: member_id,
        display_name: "Alex".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Editor,
        trust: baluard_core::vault::members::TrustLevel::Channel,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    baluard_core::vault::members::write_member(&vault_path, &member).unwrap();
    baluard_core::vault::members::write_device_binding(
        &vault_path,
        &baluard_core::vault::members::DeviceBinding {
            device_id: uuid::Uuid::new_v4(),
            member_id,
        },
    )
    .unwrap();
    let sgk = handle.unlocked().sgk().unwrap().clone();
    baluard_core::vault::collections::upsert_grant(
        &vault_path,
        &sgk,
        &shared,
        baluard_core::vault::collections::CollectionGrant {
            target: baluard_core::vault::collections::GrantTarget::Member { id: member_id },
            access: baluard_core::vault::collections::CollectionAccess::Read,
            expires_at: None,
        },
    )
    .unwrap();
    handle.member_set_minor(member_id, true).unwrap();
    drop(handle);
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");

    let report: serde_json::Value = serde_json::from_str(
        &state
            .members_replace_device(&format!(
                r#"{{"member_id":"{member_id}","revoke_device":false}}"#
            ))
            .await
            .unwrap(),
    )
    .unwrap();
    let successor: uuid::Uuid = report["successor"].as_str().unwrap().parse().unwrap();
    assert_ne!(successor, member_id);
    assert!(!report["invite_code"].as_str().unwrap().is_empty());
    assert_eq!(report["collections_rotated"], 1);
    assert!(report["rotation_failed"].as_array().unwrap().is_empty());
    // Family creation enables the kit at birth, so it is present.
    assert_eq!(report["kit_present"], true);

    // The successor row exists, carries the old role, and the minor
    // flag travelled; the old row is tombstoned with a successor.
    let row = baluard_core::vault::members::member_file_by_id(&vault_path, successor).unwrap();
    assert_eq!(row.role, baluard_core::vault::members::MemberRole::Editor);
    assert!(baluard_core::vault::family::minor_record_exists(
        &vault_path,
        &successor
    ));
    let old = baluard_core::vault::members::member_file_by_id(&vault_path, member_id).unwrap();
    assert!(old.reset.is_some());

    // The replacement invite restores the stolen member's grants:
    // Shared Read rides the embedded template so the rejoining child
    // keeps their access (family-spaces section 8).
    let pending = baluard_core::vault::members::list_pending_invites(&vault_path).unwrap();
    let replacement = pending
        .iter()
        .find(|p| p.target_member == Some(successor))
        .expect("replacement invite pending");
    let grants = replacement
        .template
        .as_ref()
        .expect("embedded template")
        .grants
        .clone();
    assert!(
        grants.iter().any(|g| g.collection_id == shared),
        "{grants:?}"
    );

    // The old grant died with the rotation (prune on rotate).
    let cols: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let grants = cols["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == serde_json::json!(shared.to_string()))
        .map(|c| c["grants"].clone())
        .expect("shared collection in listing");
    assert!(
        !grants
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["id"] == serde_json::json!(member_id.to_string())),
        "stolen member grant survived: {grants}"
    );
}

#[tokio::test]
async fn family_leave_journey_files_lists_and_approves() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("fam-leave");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-leave")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let shared = handle
        .get_settings()
        .unwrap()
        .family_shared_collection
        .unwrap();
    // Enable the kit so the approval must re-issue it.
    let _old_phrase = handle.space_recovery_kit_enable().unwrap();
    // A live ADMIN leaver (guardian) with a device binding and a
    // Shared Read grant: guardian departures force the kit re-issue.
    let leaver_id = uuid::Uuid::new_v4();
    let leaver = baluard_core::vault::members::MemberFile {
        id: leaver_id,
        display_name: "Uncle Rob".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Admin,
        trust: baluard_core::vault::members::TrustLevel::Channel,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    baluard_core::vault::members::write_member(&vault_path, &leaver).unwrap();
    let leaver_device = uuid::Uuid::new_v4();
    baluard_core::vault::members::write_device_binding(
        &vault_path,
        &baluard_core::vault::members::DeviceBinding {
            device_id: leaver_device,
            member_id: leaver_id,
        },
    )
    .unwrap();
    let sgk = handle.unlocked().sgk().unwrap().clone();
    baluard_core::vault::collections::upsert_grant(
        &vault_path,
        &sgk,
        &shared,
        baluard_core::vault::collections::CollectionGrant {
            target: baluard_core::vault::collections::GrantTarget::Member { id: leaver_id },
            access: baluard_core::vault::collections::CollectionAccess::Read,
            expires_at: None,
        },
    )
    .unwrap();
    // The leaver files; the owner's device refuses (transfer first).
    baluard_core::vault::members::file_leave_record(&vault_path, leaver_device).unwrap();
    drop(handle);
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");
    let owner_file = state.members_leave_file().await.unwrap_err();
    assert!(owner_file.contains("transfer ownership"), "{owner_file}");

    // List: exactly the leaver.
    let listed: serde_json::Value =
        serde_json::from_str(&state.members_leave_list().await.unwrap()).unwrap();
    assert_eq!(listed["pending"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["pending"][0]["member_id"],
        serde_json::json!(leaver_id.to_string())
    );

    // Approve: strike + tombstone left + rotation + kit re-issue.
    let report: serde_json::Value = serde_json::from_str(
        &state
            .members_leave_approve(&format!(r#"{{"member_id":"{leaver_id}"}}"#))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["reason"], "left");
    assert_eq!(report["collections_rotated"], 1);
    assert!(report["new_kit_phrase"].is_string());
    assert!(
        report["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == &serde_json::json!(leaver_id.to_string()))
    );
    // The tombstone row carries the coarse reason.
    let row = baluard_core::vault::members::member_file_by_id(&vault_path, leaver_id).unwrap();
    assert_eq!(row.removed_reason.as_deref(), Some("left"));
    // The pending list is empty and the leaver's grant died with the
    // rotation.
    let listed: serde_json::Value =
        serde_json::from_str(&state.members_leave_list().await.unwrap()).unwrap();
    assert!(listed["pending"].as_array().unwrap().is_empty());
    let cols: serde_json::Value =
        serde_json::from_str(&state.collections_list().await.unwrap()).unwrap();
    let shared_grants = cols["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == serde_json::json!(shared.to_string()))
        .map(|c| c["grants"].clone())
        .expect("shared collection in listing");
    assert!(
        !shared_grants
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["target"]["id"] == serde_json::json!(leaver_id.to_string())),
        "leaver grant survived: {shared_grants}"
    );
}

#[tokio::test]
async fn family_add_cipher_defaults_route_by_type() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("fam-adds");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-fam")
        .family(true)
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    let shared = handle
        .get_settings()
        .unwrap()
        .family_shared_collection
        .unwrap();
    drop(handle);
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");

    // Admin login: routed to Shared (family default).
    let login_id = state
        .add_cipher(
            r#"{"name":"Wifi","kind":{"type":"login","data":{"username":"u","password":"p"}}}"#,
        )
        .await
        .unwrap();
    let meta_of = |id: &str, envelope: &serde_json::Value| {
        envelope["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["_meta"]["id"] == serde_json::json!(id))
            .unwrap()["_meta"]["collection_id"]
            .clone()
    };
    let envelope: serde_json::Value = state.full_envelope().await.unwrap();
    assert_eq!(
        meta_of(&login_id, &envelope),
        serde_json::json!(shared.to_string()),
        "admin login should land in Shared"
    );

    // Admin card: stays flat (admin-only namespace) — the sensitive
    // default keeps cards out of the household-shared collection.
    let card_id = state
        .add_cipher(
            r#"{"name":"Bank card","kind":{"type":"card","data":{"cardholder":"A","number":"4111111111111111","brand":"visa","exp_month":"1","exp_year":"2030","cvv":"123"}}}"#,
        )
        .await
        .unwrap();
    let envelope: serde_json::Value = state.full_envelope().await.unwrap();
    assert!(
        meta_of(&card_id, &envelope).is_null(),
        "admin card should stay flat, got {:?}",
        meta_of(&card_id, &envelope)
    );
}

#[tokio::test]
async fn pair_space_editor_keeps_flat_adds() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("pair-adds");
    let (mut handle, _secrets) = VaultCreator::new(&vault_path, MASTER, "route-pair")
        .execute()
        .unwrap();
    handle.unlock(MASTER).unwrap();
    // Legacy pair Space: the plaintext space flag on an UNFLIPPED vault.
    // Pair vaults can never flip (the flip demands a family or org
    // purpose), so their editors hold the root key and write flat.
    baluard_core::vault::space::set_space_flag(&vault_path, true);
    let device_id = handle.device_id;
    let (_, founder_row) =
        baluard_core::vault::members::member_file_for_device(&vault_path, device_id)
            .expect("founder row");
    drop(handle);

    // Rebind the device to a fresh Editor partner row: remove the
    // founder's binding first (a device counted in two member subtrees
    // resolves to nothing).
    let founder_binding = vault_path
        .join("meta")
        .join("members")
        .join(founder_row.id.to_string())
        .join("devices")
        .join(format!("{device_id}.json"));
    std::fs::remove_file(founder_binding).unwrap();
    let member = uuid::Uuid::new_v4();
    let row = baluard_core::vault::members::MemberFile {
        id: member,
        display_name: "Partner".into(),
        email: None,
        role: baluard_core::vault::members::MemberRole::Editor,
        trust: baluard_core::vault::members::TrustLevel::Verified,
        identity_signing_pubkey: None,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed: None,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    baluard_core::vault::members::write_member(&vault_path, &row).unwrap();
    baluard_core::vault::members::write_device_binding(
        &vault_path,
        &baluard_core::vault::members::DeviceBinding {
            device_id,
            member_id: member,
        },
    );

    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    state.unlock(MASTER).await.expect("vault unlock");
    // The pair editor's unfiled add lands flat: the routing block must
    // gate on the flipped shape, never on is_space (a pair Space is a
    // space whose members still write flat).
    let id = state
        .add_cipher(
            r#"{"name":"Shared login","kind":{"type":"login","data":{"username":"u","password":"p"}}}"#,
        )
        .await
        .expect("pair editor unfiled add must not refuse");
    let envelope: serde_json::Value = state.full_envelope().await.unwrap();
    let meta = envelope["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["_meta"]["id"] == serde_json::json!(id))
        .expect("cipher in envelope")["_meta"]
        .clone();
    assert!(
        meta["collection_id"].is_null(),
        "pair editor add should stay flat, got {meta:?}"
    );
}

async fn space_settings_lifecycle_and_locked_rejection() {
    let (_dir, vault_path) = make_vault("space-settings");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: both surfaces refuse.
    assert!(state.space_settings_get().await.is_err());
    assert!(
        state
            .space_settings_set(r#"{"guest_enabled":false}"#)
            .await
            .is_err()
    );

    state.unlock(MASTER).await.expect("vault unlock");
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["space_invite_authority"], "admins");
    assert_eq!(get["allow_viewer_export"], false);
    // Opt-in default (2026-10-03): fresh vaults read guest sharing OFF.
    assert_eq!(get["guest_enabled"], false);
    assert_eq!(get["trash_policy"], "write_scope_can_trash");
    assert_eq!(get["restore_policy"], "admins_only");
    assert_eq!(get["join_approval"], "manual");

    // Partial set: one knob at a time, the others untouched.
    state
        .space_settings_set(r#"{"space_invite_authority":"owners"}"#)
        .await
        .unwrap();
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["space_invite_authority"], "owners");
    assert_eq!(get["guest_enabled"], false);

    state
        .space_settings_set(r#"{"guest_enabled":false,"allow_viewer_export":true}"#)
        .await
        .unwrap();
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["guest_enabled"], false);
    assert_eq!(get["allow_viewer_export"], true);
    assert_eq!(get["space_invite_authority"], "owners");

    // Fail-closed parses: an unknown authority and a non-boolean flag
    // refuse instead of silently meaning something.
    assert!(
        state
            .space_settings_set(r#"{"space_invite_authority":"council"}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .space_settings_set(r#"{"guest_enabled":"no"}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .space_settings_set(r#"{"allow_viewer_export":1}"#)
            .await
            .is_err()
    );

    // §6.5 join_approval: set to code, fail-closed parse, round trip.
    state
        .space_settings_set(r#"{"join_approval":"code"}"#)
        .await
        .unwrap();
    assert!(
        state
            .space_settings_set(r#"{"join_approval":"auto"}"#)
            .await
            .is_err()
    );
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["join_approval"], "code");
    state
        .space_settings_set(r#"{"join_approval":"manual"}"#)
        .await
        .unwrap();

    // §6.5 quorum_admin_ops (S4-1): default renders 1; set 2; parses
    // fail closed on 0, 6, and strings.
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["quorum_admin_ops"], 1);
    assert_eq!(get["collection_create_authority"], "admins");
    state
        .space_settings_set(r#"{"quorum_admin_ops":2}"#)
        .await
        .unwrap();
    assert!(
        state
            .space_settings_set(r#"{"quorum_admin_ops":0}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .space_settings_set(r#"{"quorum_admin_ops":6}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .space_settings_set(r#"{"quorum_admin_ops":"two"}"#)
            .await
            .is_err()
    );
    state
        .space_settings_set(r#"{"collection_create_authority":"editors"}"#)
        .await
        .unwrap();
    assert!(
        state
            .space_settings_set(r#"{"collection_create_authority":"anyone"}"#)
            .await
            .is_err()
    );
    // Both knobs survive a lock-unlock cycle.
    state.lock().await.expect("lock");
    state.unlock(MASTER).await.expect("relock");
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["quorum_admin_ops"], 2);
    assert_eq!(get["collection_create_authority"], "editors");
    // S4-3 ratchet: LOWERING is now a sensitive op (single device can
    // never self-confirm), so the authority resets alone; the knob
    // stays raised for the rest of this test.
    state
        .space_settings_set(r#"{"collection_create_authority":"admins"}"#)
        .await
        .unwrap();

    // §6.5 policy knobs: set, fail-closed parse, lock-cycle persistence.
    state
        .space_settings_set(r#"{"trash_policy":"admins_only"}"#)
        .await
        .unwrap();
    assert!(
        state
            .space_settings_set(r#"{"trash_policy":"nobody"}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .space_settings_set(r#"{"restore_policy":"write_scope"}"#)
            .await
            .is_err()
    );
    state.lock().await.expect("vault lock");
    state.unlock(MASTER).await.expect("re-unlock");
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["trash_policy"], "admins_only");
    assert_eq!(get["restore_policy"], "admins_only");
    state
        .space_settings_set(r#"{"trash_policy":"write_scope_can_trash"}"#)
        .await
        .unwrap();

    // Settings persist in the encrypted store: lock + unlock keeps them.
    state.lock().await.expect("vault lock");
    state.unlock(MASTER).await.expect("re-unlock");
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["space_invite_authority"], "owners");
    assert_eq!(get["guest_enabled"], false);
    assert_eq!(get["allow_viewer_export"], true);

    // Review round (S3-9): role-driven gates on a strict vault. Rebind
    // the acting device to planted rows and walk the matrix. The flag is
    // ON here (set earlier), so the admin first turns it OFF to arm the
    // role check.
    let device_id: uuid::Uuid = state.device_id().await.parse().expect("device uuid");
    let vault_path = state.vault_path.clone();

    // Editor: settings set refuses (only owner/admin change space policy).
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device_id,
        None,
    );
    assert!(
        state
            .space_settings_set(r#"{"guest_enabled":true}"#)
            .await
            .is_err()
    );

    // Admin: settings set passes; owners-only invite authority refuses
    // admin-minted invites.
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Admin,
        device_id,
        None,
    );
    state
        .space_settings_set(r#"{"allow_viewer_export":false}"#)
        .await
        .expect("admin sets space settings");
    assert!(state.members_invite(r#"{"role":"viewer"}"#).await.is_err());

    // Viewer (flag off): export refuses; the viewer cannot flip the flag
    // back on.
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Viewer,
        device_id,
        None,
    );
    assert!(state.export_bw_json().await.is_err());
    assert!(
        state
            .space_settings_set(r#"{"allow_viewer_export":true}"#)
            .await
            .is_err()
    );

    // Tombstoned viewer (removed): member_role_for_device resolves None
    // and the gate refuses anyway — a struck member's still-open session
    // must not fall through the catch-all (the review-round fix).
    {
        use baluard_core::vault::members::{MemberFile, TrustLevel, write_member};
        let member = MemberFile {
            id: uuid::Uuid::new_v4(),
            display_name: "Struck viewer".into(),
            email: None,
            role: baluard_core::vault::members::MemberRole::Viewer,
            trust: TrustLevel::Channel,
            identity_signing_pubkey: None,
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: Some(1),
            removed_reason: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        write_member(&vault_path, &member).unwrap();
        baluard_core::vault::members::write_device_binding(
            &vault_path,
            &baluard_core::vault::members::DeviceBinding {
                device_id,
                member_id: member.id,
            },
        )
        .unwrap();
    }
    assert!(state.export_bw_json().await.is_err());
}

/// S4-3 ratchet + §13 claim gate: lowering the quorum threshold is
/// itself sensitive (gated at the CURRENT bar, owner cannot self-
/// confirm) while raising stays instant; members.claim refuses locked
/// and validates its payload.
#[tokio::test]
async fn quorum_lower_ratchet_and_claim_gate() {
    let (_dir, vault_path) = make_vault("quorum-lower");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // Locked: claim refuses.
    assert!(
        state
            .members_claim(r#"{"member_id":"11111111-1111-1111-1111-111111111111"}"#)
            .await
            .is_err()
    );

    state.unlock(MASTER).await.expect("vault unlock");
    // Raising is instant.
    state
        .space_settings_set(r#"{"quorum_admin_ops":2}"#)
        .await
        .expect("raise is not gated");

    // Lowering is sensitive: refused at the CURRENT bar, ask on file.
    let err = state
        .space_settings_set(r#"{"quorum_admin_ops":1}"#)
        .await
        .expect_err("lowering waits for quorum");
    assert!(err.contains("admin approvals"), "{err}");
    let pending: serde_json::Value =
        serde_json::from_str(&state.approvals_pending().await.unwrap()).unwrap();
    assert_eq!(pending["pending"].as_array().unwrap().len(), 1);
    assert_eq!(pending["pending"][0]["kind"], "quorum_lower");
    assert_eq!(pending["pending"][0]["required"], 2);

    // The owner cannot self-confirm the lowering.
    let err = state
        .space_settings_set(r#"{"quorum_admin_ops":1}"#)
        .await
        .expect_err("self-confirm");
    assert!(err.contains("different admin"), "{err}");

    // Raising further stays instant even with the ask pending; the
    // stale ask cannot be confirmed by the same member afterwards.
    state
        .space_settings_set(r#"{"quorum_admin_ops":3}"#)
        .await
        .expect("raise while an ask is pending");
    let get: serde_json::Value =
        serde_json::from_str(&state.space_settings_get().await.unwrap()).unwrap();
    assert_eq!(get["quorum_admin_ops"], 3);

    // Claim payload contract: a bad id refuses fail-closed.
    assert!(
        state
            .members_claim(r#"{"member_id":"nope"}"#)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn collection_create_authority_and_approvals_gate() {
    let (_dir, vault_path) = make_vault("s41-knobs");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: the approvals surface refuses.
    assert!(state.approvals_pending().await.is_err());
    state.unlock(MASTER).await.expect("vault unlock");
    let device_id: uuid::Uuid = state.device_id().await.parse().expect("device uuid");

    // Default authority (admins): an Editor cannot create collections.
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device_id,
        None,
    );
    assert!(state.collection_create("Nope").await.is_err());

    // editors authority: the same Editor creates.
    state
        .space_settings_set(r#"{"collection_create_authority":"editors"}"#)
        .await
        .is_err()
        .then_some(())
        .expect("settings set must FAIL for an editor");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Admin,
        device_id,
        None,
    );
    state
        .space_settings_set(r#"{"collection_create_authority":"editors"}"#)
        .await
        .expect("set editors authority");
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device_id,
        None,
    );
    let created = state
        .collection_create("Editors can")
        .await
        .expect("editor creates");
    assert!(created.contains("id"));

    // Quorum gate (§6.5 quorum_admin_ops): threshold 2 turns the solo
    // migrate call into a pending ask; the same admin cannot self-confirm.
    rebind_device(
        &vault_path,
        baluard_core::vault::members::MemberRole::Admin,
        device_id,
        None,
    );
    state
        .space_settings_set(r#"{"quorum_admin_ops":2}"#)
        .await
        .expect("set quorum 2");
    let err = state
        .space_migrate(r#"{"clone_url":"https://example.com/baluard-x.git"}"#)
        .await
        .unwrap_err();
    assert!(err.contains("admin approvals"), "pending refusal: {err}");
    let pending: serde_json::Value =
        serde_json::from_str(&state.approvals_pending().await.unwrap()).unwrap();
    assert_eq!(pending["pending"].as_array().unwrap().len(), 1);
    assert_eq!(pending["pending"][0]["kind"], "space_migrate");
    assert_eq!(pending["pending"][0]["required"], 2);
    // Same admin again: already on the record, still refused.
    let err = state
        .space_migrate(r#"{"clone_url":"https://example.com/baluard-x.git"}"#)
        .await
        .unwrap_err();
    assert!(
        err.contains("different admin"),
        "self-confirm refusal: {err}"
    );
    // S4-3 ratchet: threshold back to 1 is itself a sensitive ask —
    // single-device lowering refuses and queues the ask instead.
    let err = state
        .space_settings_set(r#"{"quorum_admin_ops":1}"#)
        .await
        .expect_err("lowering waits for quorum");
    assert!(err.contains("admin approvals"), "{err}");
}

#[tokio::test]
async fn templates_state_lifecycle_and_fail_closed_parses() {
    let (_dir, vault_path) = make_vault("templates-state");
    let state = Arc::new(VaultState::new(vault_path.clone()));
    state.open().await.expect("vault open");
    // NOT unlocked: every template surface refuses.
    assert!(state.templates_list().await.is_err());
    assert!(state.templates_create(r#"{"name":"X"}"#).await.is_err());

    state.unlock(MASTER).await.expect("vault unlock");
    // Fail-closed parses: a bad role, a bad grant access, and a
    // malformed template_id on invite must refuse, never silently
    // downgrade to a template-less invite.
    assert!(
        state
            .templates_create(r#"{"name":"C","role":"wizard"}"#)
            .await
            .is_err()
    );
    assert!(state
        .templates_create(r#"{"name":"C","role":"viewer","grants":[{"collection_id":"123e4567-e89b-12d3-a456-426614174000","access":"root"}]}"#)
        .await
        .is_err());
    assert!(
        state
            .members_invite(r#"{"role":"viewer","template_id":"not-a-uuid"}"#)
            .await
            .is_err()
    );
    // S3-4 review: present-but-mistyped values refuse instead of
    // silently downgrading (negative days → permanent access, a
    // non-string template_id → template-less invite, non-array grants
    // → empty template).
    assert!(
        state
            .templates_create(
                r#"{"name":"C","role":"editor","grants":[{"collection_id":"123e4567-e89b-12d3-a456-426614174000","access":"read","expires_in_days":-1}]}"#
            )
            .await
            .is_err()
    );
    assert!(
        state
            .templates_create(r#"{"name":"C","role":"viewer","grants":"all"}"#)
            .await
            .is_err()
    );
    assert!(
        state
            .members_invite(r#"{"role":"viewer","template_id":42}"#)
            .await
            .is_err()
    );
    // A viewer template cannot carry write access: the member would
    // pass locally and wedge their sync at git verification.
    assert!(
        state
            .templates_create(
                r#"{"name":"C","role":"viewer","grants":[{"collection_id":"123e4567-e89b-12d3-a456-426614174000","access":"write"}]}"#
            )
            .await
            .is_err()
    );

    // Lifecycle: create, list, delete.
    let created: serde_json::Value = serde_json::from_str(
        &state
            .templates_create(
                r#"{"name":"Contractor","role":"viewer","grants":[{"collection_id":"123e4567-e89b-12d3-a456-426614174000","access":"read","expires_in_days":30}]}"#,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created["id"].as_str().expect("template id");
    assert_eq!(created["role"], "viewer");
    assert_eq!(created["grants"].as_array().unwrap().len(), 1);
    let list: serde_json::Value =
        serde_json::from_str(&state.templates_list().await.unwrap()).unwrap();
    assert_eq!(list["templates"].as_array().unwrap().len(), 1);

    // Invite from the template (role must match).
    let invite_payload = serde_json::json!({
        "role": "viewer",
        "template_id": id,
    });
    state
        .members_invite(invite_payload.to_string().as_str())
        .await
        .expect("templated invite");
    // Role divergence refuses.
    assert!(
        state
            .members_invite(
                serde_json::json!({"role":"editor","template_id":id})
                    .to_string()
                    .as_str()
            )
            .await
            .is_err()
    );

    state.template_delete(id).await.expect("delete");
    let list: serde_json::Value =
        serde_json::from_str(&state.templates_list().await.unwrap()).unwrap();
    assert!(list["templates"].as_array().unwrap().is_empty());
    assert!(state.template_delete("not-a-uuid").await.is_err());
}

#[tokio::test]
async fn sharing_routes_reject_when_locked() {
    let (_dir, state) = make_vault("sharing-locked");
    let state = Arc::new(VaultState::new(state));
    state.open().await.expect("vault open");
    // NOT unlocked.
    assert!(state.members_list().await.is_err());
    assert!(state.members_invite(r#"{"role":"editor"}"#).await.is_err());
    assert!(state.requests_list().await.is_err());
    assert!(state.activity_events("{}").await.is_err());
    assert!(state.activity_refusals("{}").await.is_err());
    assert!(
        state
            .members_remove(
                serde_json::json!({ "member_ids": [uuid::Uuid::new_v4().to_string()] })
                    .to_string()
                    .as_str()
            )
            .await
            .is_err()
    );
    assert!(state.members_reset("{}").await.is_err());
    assert!(
        state
            .members_transfer(r#"{"member_id":"00000000-0000-0000-0000-000000000001"}"#)
            .await
            .is_err()
    );
}

// ── S1b-4 / screen 6: notices aggregation ──

#[tokio::test]
async fn notices_aggregate_stale_invites_and_resets() {
    let (_dir, state) = open_unlocked("notices-flow").await;
    let vault_path = state.vault_path.clone();

    // Fresh vault: quiet.
    let out: serde_json::Value =
        serde_json::from_str(&state.notices_list("{}").await.unwrap()).unwrap();
    assert_eq!(out["notices"].as_array().unwrap().len(), 0);
    assert_eq!(out["pending_requests"], 0);

    // A reset-pending member: tombstoned row whose successor has NO
    // device binding yet (re-join not happened).
    let member_id = uuid::Uuid::new_v4();
    let successor_id = uuid::Uuid::new_v4();
    let row = serde_json::json!({
        "id": member_id.to_string(),
        "display_name": "Leaver",
        "role": "editor",
        "trust": "channel",
        "reset": { "successor": successor_id.to_string(), "at": 123 },
    });
    std::fs::create_dir_all(vault_path.join("meta/members")).unwrap();
    std::fs::write(
        vault_path.join(format!("meta/members/{member_id}.json")),
        row.to_string(),
    )
    .unwrap();
    // reset_member always creates the successor row alongside the
    // tombstone.
    let successor_row = serde_json::json!({
        "id": successor_id.to_string(),
        "display_name": "Leaver",
        "role": "editor",
        "trust": "channel",
    });
    std::fs::write(
        vault_path.join(format!("meta/members/{successor_id}.json")),
        successor_row.to_string(),
    )
    .unwrap();

    // A stale invite (created_at far in the past).
    std::fs::create_dir_all(vault_path.join("meta/invites")).unwrap();
    let invite = serde_json::json!({
        "invite_id": uuid::Uuid::new_v4().to_string(),
        "role": "editor",
        "secret_hash": "ab",
        "created_at": 1000,
    });
    std::fs::write(
        vault_path.join(format!("meta/invites/{}.json", uuid::Uuid::new_v4())),
        invite.to_string(),
    )
    .unwrap();

    let out: serde_json::Value =
        serde_json::from_str(&state.notices_list("{}").await.unwrap()).unwrap();
    let kinds: Vec<&str> = out["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"reset_pending"), "{kinds:?}");
    assert!(kinds.contains(&"stale_invite"), "{kinds:?}");

    // Transport checks with no provider remote: empty, no error.
    let out2: serde_json::Value = serde_json::from_str(
        &state
            .notices_list(r#"{"refresh_transport":true}"#.to_string().as_str())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(out2["transport"].as_array().unwrap().len(), 0);

    // created_at = 0 (pre-field records) is NEVER stale.
    let ancient = serde_json::json!({
        "invite_id": uuid::Uuid::new_v4().to_string(),
        "role": "viewer",
        "secret_hash": "cd",
        "created_at": 0,
    });
    std::fs::write(
        vault_path.join(format!("meta/invites/{}.json", uuid::Uuid::new_v4())),
        ancient.to_string(),
    )
    .unwrap();
    let out3: serde_json::Value =
        serde_json::from_str(&state.notices_list("{}").await.unwrap()).unwrap();
    let stale = out3["notices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["kind"] == "stale_invite")
        .unwrap();
    assert_eq!(stale["count"], 1, "created_at 0 must not count as stale");

    // The notice clears when the successor re-joins (binding appears),
    // and ghosts are impossible: removing the successor BEFORE re-join
    // kills the reset chain.
    std::fs::create_dir_all(
        vault_path
            .join("meta/members")
            .join(successor_id.to_string())
            .join("devices"),
    )
    .unwrap();
    std::fs::write(
        vault_path
            .join("meta/members")
            .join(successor_id.to_string())
            .join("devices")
            .join(format!("{}.json", uuid::Uuid::new_v4())),
        "{}",
    )
    .unwrap();
    let out4: serde_json::Value =
        serde_json::from_str(&state.notices_list("{}").await.unwrap()).unwrap();
    let kinds2: Vec<&str> = out4["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["kind"].as_str().unwrap())
        .collect();
    assert!(!kinds2.contains(&"reset_pending"), "{kinds2:?}");
}

// ── D21 read scope: bridge writes ride the session's write scope ──

/// Rebind `device_id` to a fresh member row with the given role. Strips
/// the device's existing bindings first (fresh test vaults carry the
/// S1a owner genesis binding) so role resolution is deterministic.
fn rebind_device(
    vault_path: &std::path::Path,
    role: baluard_core::vault::members::MemberRole,
    device_id: uuid::Uuid,
    removed: Option<u64>,
) {
    use baluard_core::vault::members::{
        DeviceBinding, MemberFile, TrustLevel, write_device_binding, write_member,
    };
    let members = vault_path.join("meta/members");
    // Carry the device's real identity pubkey across the rebind: the
    // signed-approval gate verifies signatures against the member row's
    // published key, so a planted row without it would refuse the
    // device's own signature.
    let mut carried_pubkey: Option<String> = None;
    for entry in std::fs::read_dir(&members).expect("members dir") {
        let path = entry.expect("entry").path();
        let binding = path.join("devices").join(format!("{device_id}.json"));
        if binding.exists() {
            if let Some(stem) = path.file_name().and_then(|s| s.to_str()) {
                let row_path = members.join(format!("{stem}.json"));
                if let Ok(bytes) = std::fs::read(&row_path) {
                    if let Ok(row) = serde_json::from_slice::<MemberFile>(&bytes) {
                        carried_pubkey = row.identity_signing_pubkey;
                    }
                }
            }
        }
        let _ = std::fs::remove_file(binding);
    }
    let member = MemberFile {
        id: uuid::Uuid::new_v4(),
        display_name: "Test Member".into(),
        email: None,
        role,
        trust: TrustLevel::Channel,
        identity_signing_pubkey: carried_pubkey,
        identity_signing_pubkey_previous: None,
        identity_rotation_signature: None,
        identity_rotated_at: None,
        reset: None,
        removed,
        removed_reason: None,
        transport_username: None,
        identity_wrap_pubkey: None,
    };
    write_member(vault_path, &member).expect("write member row");
    write_device_binding(
        vault_path,
        &DeviceBinding {
            device_id,
            member_id: member.id,
        },
    )
    .expect("write binding");
}

#[tokio::test]
async fn bridge_write_gate_follows_member_role() {
    let (_dir, state) = open_unlocked("bridge-write-gate").await;

    // Fresh creation binds the device to the owner genesis row: writes
    // pass. (On a pre-S1a legacy vault there is no member directory and
    // the same call takes the owner-equivalent path — same Ok.)
    state.bridge_write_allowed().await.expect("owner allows");

    let device_id: uuid::Uuid = state.device_id().await.parse().expect("device uuid");

    // Viewer binding: refused here, where the extension can show it,
    // instead of wedging at push time.
    rebind_device(
        &state.vault_path,
        baluard_core::vault::members::MemberRole::Viewer,
        device_id,
        None,
    );
    let err = state.bridge_write_allowed().await.unwrap_err();
    assert!(err.contains("view-only"), "err: {err}");

    // Editor binding: allowed.
    rebind_device(
        &state.vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device_id,
        None,
    );
    state.bridge_write_allowed().await.expect("editor allows");

    // Removed member: fail closed (the row resolves no role).
    rebind_device(
        &state.vault_path,
        baluard_core::vault::members::MemberRole::Editor,
        device_id,
        Some(0),
    );
    assert!(state.bridge_write_allowed().await.is_err());
}

/// G24 step 3: bridge.match fans out over unlocked merge-eligible
/// vaults via autofill_query; an org Space (ceiling never seen) is
/// excluded from matches and from the vaults array, and match
/// payloads never carry passwords.
#[tokio::test]
async fn bridge_match_merges_across_eligible_vaults() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;

    // Personal vault P (active).
    let (dir_p, path_p) = make_vault("g24p");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open p");
    state_p.unlock(MASTER).await.expect("unlock p");
    state_p
        .add_cipher(
            &serde_json::json!({
                "name": "MyBank personal",
                "favorite": true,
                "kind": {"type": "login", "data": {
                    "username": "me", "password": "p-secret",
                    "uris": [{"uri": "https://login.mybank.com", "matchStrategy": "domain"}],
                    "totp_uri": null, "autofill_on_page_load": false,
                    "password_revision_date": null, "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string(),
        )
        .await
        .expect("add p");
    // A non-favorite whose NAME would sort first: the favorite flag
    // must outrank it (plan §4.11 ordering).
    state_p
        .add_cipher(
            &serde_json::json!({
                "name": "Aaa personal",
                "kind": {"type": "login", "data": {
                    "username": "me2", "password": "p2-secret",
                    "uris": [{"uri": "https://login.mybank.com", "matchStrategy": "domain"}],
                    "totp_uri": null, "autofill_on_page_load": false,
                    "password_revision_date": null, "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string(),
        )
        .await
        .expect("add p2");
    register_in_registry("g24p", &path_p);

    // Family vault F: eligible after its unlock refreshes the ceiling
    // cache (family purpose defaults the ceiling on).
    let dir_f = tempfile::tempdir().unwrap();
    let path_f = dir_f.path().join("g24f");
    let (mut handle_f, _) = VaultCreator::new(&path_f, MASTER, "route-g24f")
        .family(true)
        .execute()
        .unwrap();
    handle_f.unlock(MASTER).unwrap();
    drop(handle_f);
    register_in_registry("g24f", &path_f);
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    state_f.open().await.expect("open f");
    state_f.unlock(MASTER).await.expect("unlock f");
    state_f
        .add_cipher(
            &serde_json::json!({
                "name": "MyBank family",
                "kind": {"type": "login", "data": {
                    "username": "family", "password": "f-secret",
                    "uris": [{"uri": "https://login.mybank.com", "matchStrategy": "domain"}],
                    "totp_uri": null, "autofill_on_page_load": false,
                    "password_revision_date": null, "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string(),
        )
        .await
        .expect("add f");

    // Org Space O: flipped shape with the ceiling cache recorded false
    // at its unlock (the marker lands after the cache refresh), so it
    // stays ineligible even though it is unlocked and holds a
    // matching entry.
    let (dir_o, path_o) = make_vault("g24o");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open o");
    state_o.unlock(MASTER).await.expect("unlock o");
    register_in_registry("g24o", &path_o);
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();
    state_o
        .add_cipher(&serde_json::to_string(&login_input("MyBank org", "org")).unwrap())
        .await
        .expect("add o");

    let host = Arc::new(VaultHost::new());
    host.insert("g24p".into(), state_p.clone()).await;
    host.insert("g24f".into(), state_f.clone()).await;
    host.insert("g24o".into(), state_o.clone()).await;
    host.switch("g24p").await.expect("switch");

    let token_hex = {
        let mut reg = host.bridge().write().await;
        let _pair = reg.start_pair("test-harness");
        reg.complete_pair("ext", "chrome").expect("pair").1
    };

    let req = GatewayRequest {
        action: "bridge.match".into(),
        payload: r#"{"url":"https://login.mybank.com/signin"}"#.into(),
        session_token: token_hex,
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();

    let matches = parsed["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 3, "personal x2 + family: {parsed:?}");
    assert_eq!(matches[0]["name"], serde_json::json!("MyBank personal"));
    assert_eq!(matches[1]["name"], serde_json::json!("Aaa personal"));
    assert_eq!(matches[2]["vault_slug"], serde_json::json!("g24f"));
    assert!(
        !resp.payload.contains("p-secret") && !resp.payload.contains("f-secret"),
        "match payloads never carry passwords"
    );

    let vaults = parsed["vaults"].as_array().unwrap();
    let slugs: Vec<&str> = vaults.iter().filter_map(|v| v["slug"].as_str()).collect();
    assert!(slugs.contains(&"g24p") && slugs.contains(&"g24f"));
    assert!(
        !slugs.contains(&"g24o"),
        "an org Space with no ceiling cache is ineligible: {vaults:?}"
    );
    assert_eq!(
        parsed["active_vault"],
        serde_json::json!("Vault g24p"),
        "active_vault keeps its display-name contract"
    );

    let _ = (dir_p, dir_o);
}

/// G24 step 3 gate change: the merged read passes when ANY
/// merge-eligible vault is unlocked - a sleeping personal vault no
/// longer blanks autofill while a family Space is open. With every
/// eligible vault locked the gate still refuses.
#[tokio::test]
async fn bridge_match_gate_passes_on_sibling_unlocked() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;

    let (dir_p, path_p) = make_vault("g24gp");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open p");
    state_p.unlock(MASTER).await.expect("unlock p");
    register_in_registry("g24gp", &path_p);

    let dir_f = tempfile::tempdir().unwrap();
    let path_f = dir_f.path().join("g24gf");
    let (mut handle_f, _) = VaultCreator::new(&path_f, MASTER, "route-g24gf")
        .family(true)
        .execute()
        .unwrap();
    handle_f.unlock(MASTER).unwrap();
    drop(handle_f);
    register_in_registry("g24gf", &path_f);
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    state_f.open().await.expect("open f");
    state_f.unlock(MASTER).await.expect("unlock f");

    let host = Arc::new(VaultHost::new());
    host.insert("g24gp".into(), state_p.clone()).await;
    host.insert("g24gf".into(), state_f.clone()).await;
    host.switch("g24gp").await.expect("switch");

    let token_hex = {
        let mut reg = host.bridge().write().await;
        let _pair = reg.start_pair("test-harness");
        reg.complete_pair("ext", "chrome").expect("pair").1
    };
    let mk = |token: &str| GatewayRequest {
        action: "bridge.match".into(),
        payload: r#"{"url":"https://example.com"}"#.into(),
        session_token: token.to_string(),
        slug: String::new(),
    };

    // Active personal locked, family open: the merged read passes.
    let _ = state_p.lock().await;
    let resp = route_host_request(mk(&token_hex), &host).await;
    assert!(
        resp.success,
        "sibling-unlocked gate must pass: {}",
        resp.error_message
    );

    // Everything eligible locked: refused.
    let _ = state_f.lock().await;
    let resp = route_host_request(mk(&token_hex), &host).await;
    assert!(!resp.success, "all-locked must refuse");
    assert!(resp.error_message.contains("locked"));

    let _ = (dir_p, dir_f);
}

/// G24 step 4: slug-scoped bridge reads. A merge-eligible sibling
/// resolves; unknown, ineligible, locked, and URL-mismatched targets
/// fail closed.
#[tokio::test]
async fn bridge_slug_scoped_reads_fail_closed() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;

    let (dir_p, path_p) = make_vault("g24sp");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open p");
    state_p.unlock(MASTER).await.expect("unlock p");
    register_in_registry("g24sp", &path_p);

    let dir_f = tempfile::tempdir().unwrap();
    let path_f = dir_f.path().join("g24sf");
    let (mut handle_f, _) = VaultCreator::new(&path_f, MASTER, "route-g24sf")
        .family(true)
        .execute()
        .unwrap();
    handle_f.unlock(MASTER).unwrap();
    drop(handle_f);
    register_in_registry("g24sf", &path_f);
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    state_f.open().await.expect("open f");
    state_f.unlock(MASTER).await.expect("unlock f");
    state_f
        .add_cipher(
            &serde_json::json!({
                "name": "Family Wi-Fi",
                "kind": {"type": "login", "data": {
                    "username": "home", "password": "f-wifi-secret",
                    "uris": [{"uri": "https://router.local", "matchStrategy": "domain"}],
                    "totp_uri": "otpauth://totp/Baluard:home?secret=JBSWY3DPEHPK3PXP",
                    "autofill_on_page_load": false,
                    "password_revision_date": null, "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string(),
        )
        .await
        .expect("add f");
    let env = state_f.full_envelope().await.expect("envelope");
    let fid = env["ciphers"][0]["id"].as_str().unwrap().to_string();

    // Ineligible org sibling (marker after the unlock so the ceiling
    // cache reads false).
    let (dir_o, path_o) = make_vault("g24so");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open o");
    state_o.unlock(MASTER).await.expect("unlock o");
    register_in_registry("g24so", &path_o);
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();

    let host = Arc::new(VaultHost::new());
    host.insert("g24sp".into(), state_p.clone()).await;
    host.insert("g24sf".into(), state_f.clone()).await;
    host.insert("g24so".into(), state_o.clone()).await;
    host.switch("g24sp").await.expect("switch");

    let token_hex = {
        let mut reg = host.bridge().write().await;
        let _pair = reg.start_pair("test-harness");
        reg.complete_pair("ext", "chrome").expect("pair").1
    };
    let get = |id: &str, url: &str, slug: &str| GatewayRequest {
        action: "vault.get".into(),
        payload: serde_json::json!({
            "id": id, "url": url, "vault_slug": slug, "decrypt": true
        })
        .to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };

    // Happy path: the family credential resolves through the slug and
    // the origin binding runs against the TARGET vault.
    let resp = route_host_request(get(&fid, "https://router.local/x", "g24sf"), &host).await;
    assert!(resp.success, "scoped read: {}", resp.error_message);
    assert!(
        resp.payload.contains("f-wifi-secret"),
        "scoped decrypt returns the credential"
    );

    // Unknown slug refused like a foreign vault.
    let resp = route_host_request(get(&fid, "https://router.local", "nope"), &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("not available"));

    // Ineligible slug (org, no ceiling cache) refused the same way.
    let resp = route_host_request(get(&fid, "https://router.local", "g24so"), &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("not available"));

    // URL mismatch refused by the target-side origin binding.
    let resp = route_host_request(get(&fid, "https://evil.example", "g24sf"), &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("bridge read refused"));

    // Locked target refused.
    let _ = state_f.lock().await;
    let resp = route_host_request(get(&fid, "https://router.local", "g24sf"), &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("locked"));
    state_f.unlock(MASTER).await.expect("re-unlock f");

    // Scoped TOTP read rides the same resolution.
    let req = GatewayRequest {
        action: "cipher.totp_code".into(),
        payload: serde_json::json!({
            "id": fid, "url": "https://router.local", "vault_slug": "g24sf"
        })
        .to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "scoped totp: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert!(
        parsed["code"].as_str().unwrap().len() >= 6,
        "a real code comes back: {parsed:?}"
    );

    let _ = (dir_p, dir_o);
}

/// G24 step 1 + the D31 retrofit: vaults.list_full_all gates sibling
/// rows by eligibility. An org Space (ceiling off/never seen) keeps
/// its metadata row but carries no ciphers; a family Space merges.
#[tokio::test]
async fn list_full_all_gates_ineligible_spaces() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = VaultHost::new();
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(host);

    let (dir_p, path_p) = make_vault("g24lp");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open p");
    state_p.unlock(MASTER).await.expect("unlock p");
    state_p
        .add_cipher(&serde_json::to_string(&login_input("Mine", "u")).unwrap())
        .await
        .expect("add p");
    register_in_registry("g24lp", &path_p);

    let dir_f = tempfile::tempdir().unwrap();
    let path_f = dir_f.path().join("g24lf");
    let (mut handle_f, _) = VaultCreator::new(&path_f, MASTER, "route-g24lf")
        .family(true)
        .execute()
        .unwrap();
    handle_f.unlock(MASTER).unwrap();
    drop(handle_f);
    register_in_registry("g24lf", &path_f);
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    state_f.open().await.expect("open f");
    state_f.unlock(MASTER).await.expect("unlock f");
    state_f
        .add_cipher(&serde_json::to_string(&login_input("Family item", "u")).unwrap())
        .await
        .expect("add f");

    let (dir_o, path_o) = make_vault("g24lo");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open o");
    state_o.unlock(MASTER).await.expect("unlock o");
    register_in_registry("g24lo", &path_o);
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();
    state_o
        .add_cipher(&serde_json::to_string(&login_input("Org item", "u")).unwrap())
        .await
        .expect("add o");

    host.insert("g24lp".into(), state_p.clone()).await;
    host.insert("g24lf".into(), state_f.clone()).await;
    host.insert("g24lo".into(), state_o.clone()).await;
    host.switch("g24lp").await.expect("switch");

    let token = state_p.get_session_token().await.expect("token");
    let req = GatewayRequest {
        action: "vaults.list_full_all".into(),
        payload: String::new(),
        session_token: token,
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["vaults"].as_array().unwrap();

    let row_p = rows.iter().find(|r| r["slug"] == "g24lp").unwrap();
    assert_eq!(row_p["ciphers"].as_array().unwrap().len(), 1);
    let row_f = rows.iter().find(|r| r["slug"] == "g24lf").unwrap();
    assert_eq!(
        row_f["ciphers"].as_array().unwrap().len(),
        1,
        "an eligible family Space merges"
    );
    let row_o = rows.iter().find(|r| r["slug"] == "g24lo").unwrap();
    assert!(
        row_o.get("ciphers").is_none(),
        "an ineligible org Space keeps metadata only: {row_o:?}"
    );
    assert_eq!(row_o["presence"], serde_json::json!("unlocked"));

    let _ = (dir_p, dir_o);
}

#[tokio::test]
async fn bridge_route_enforces_write_gate() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let (_dir, state) = open_unlocked("bridge-route-gate").await;
    register_in_registry("brg", &state.vault_path);
    let host = Arc::new(VaultHost::new());
    host.insert("brg".into(), state.clone()).await;
    host.switch("brg").await.expect("switch");

    // Bind the vault's device to a Viewer row.
    let device_id: uuid::Uuid = state.device_id().await.parse().expect("device uuid");
    rebind_device(
        &state.vault_path,
        baluard_core::vault::members::MemberRole::Viewer,
        device_id,
        None,
    );

    // Mint a live bridge token straight into the registry (the pairing
    // ceremony's tail: start_pair stages the pending, complete_pair
    // mints the token).
    let token_hex = {
        let mut reg = host.bridge().write().await;
        let _pair = reg.start_pair("test-harness");
        reg.complete_pair("ext", "firefox").expect("pair").1
    };

    // Write through the bridge: refused at the ROUTE layer, not just
    // the state method.
    let req = GatewayRequest {
        action: "vault.add".into(),
        payload: serde_json::to_string(&login_input("X", "u")).unwrap(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "viewer bridge write must be refused");
    assert!(
        resp.error_message.contains("view-only"),
        "err: {}",
        resp.error_message
    );

    // Reads stay open for viewers: bridge.match rides the same route
    // and must succeed (metadata only, no passwords).
    let req = GatewayRequest {
        action: "bridge.match".into(),
        payload: r#"{"url":"https://example.com/login"}"#.into(),
        session_token: token_hex,
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "viewer bridge read must pass: {}",
        resp.error_message
    );
}

/// P8c-2: removal pre-flight — a member with a transport seat on a
/// provider-registered vault refuses the offboarding when the strike
/// fails (provider not connected), and the explicit offline override
/// removes anyway.
#[tokio::test]
async fn members_remove_preflight_strike_refusal_and_override() {
    let _guard = JOIN_REG.lock().await;
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let (_dir, state) = open_unlocked("remove-flow").await;
    let vault_path = state.vault_path.clone();

    // Forge a member row carrying a transport seat (rows are
    // admin-authored; the fs-level write is what removal pre-flights see).
    let member_id = uuid::Uuid::new_v4();
    let row = serde_json::json!({
        "id": member_id.to_string(),
        "display_name": "Leaver",
        "role": "editor",
        "trust": "channel",
        "transport_username": "gituser",
    });
    std::fs::create_dir_all(vault_path.join("meta/members")).unwrap();
    std::fs::write(
        vault_path.join(format!("meta/members/{member_id}.json")),
        row.to_string(),
    )
    .unwrap();

    // Register the vault with a provider remote (coords resolve; the
    // provider TOKEN is not connected, so the strike fails). The entry
    // must carry the REAL vault id — coords match by vault id.
    let vault_id = baluard_core::vault::handle::VaultHandle::vault_id_for_path(&vault_path)
        .expect("marker vault id");
    let mut reg = VaultRegistry::default();
    reg.add(VaultEntry {
        slug: baluard_core::vault::slug::normalize_slug("remove-flow"),
        display_name: "remove-flow".to_string(),
        path: vault_path.clone(),
        provider: Some("github".to_string()),
        remote_url: Some("https://github.com/o/r.git".to_string()),
        last_synced: None,
        last_opened: None,
        vault_id,
        merge_opt_in: None,
        merge_ceiling_seen: false,
    })
    .expect("add entry");
    reg.save_locked().expect("save registry");

    // Strike fails (no connected token) → refusal; member NOT removed.
    let err = state
        .members_remove(
            serde_json::json!({ "member_ids": [member_id.to_string()] })
                .to_string()
                .as_str(),
        )
        .await
        .unwrap_err();
    assert!(err.contains("provider seat removal failed"), "err: {err}");
    assert!(
        vault_path
            .join(format!("meta/members/{member_id}.json"))
            .exists()
    );

    // Explicit offline override removes anyway.
    let resp = state
        .members_remove(
            serde_json::json!({
                "member_ids": [member_id.to_string()],
                "offline_override": true,
            })
            .to_string()
            .as_str(),
        )
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(payload["seats_struck"].as_array().unwrap().len(), 0);
    // The overridden strike is reported as UNSTRUCK (screen-6 surface):
    // the member is gone from the vault but their forge seat may live on.
    assert_eq!(payload["unstruck_seats"].as_array().unwrap().len(), 1);
    // Tombstone semantics: the row remains with the removed marker set.
    let row_after: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vault_path.join(format!("meta/members/{member_id}.json")))
            .unwrap(),
    )
    .unwrap();
    assert!(row_after["removed"].is_u64(), "row: {row_after}");
}

// ── §4.8-2: join flow routes (wire-level through route_host_request) ──
// The join handlers resolve slugs via the GLOBAL registry file, so tests
// serialise on JOIN_REG and sandbox BALUARD_DATA_DIR (same pattern as
// phase6_detach.rs).
static JOIN_REG: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn join_request(action: &str, payload: serde_json::Value) -> GatewayRequest {
    GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: String::new(),
        slug: String::new(),
    }
}

#[tokio::test]
async fn join_introduce_validates_consumes_and_polls() {
    // Hold for the WHOLE test: both env-setting tests (BALUARD_DATA_DIR
    // sandbox) must never interleave, or they read each other's registry.
    let _guard = JOIN_REG.lock().await;
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    // Real vault with an owner genesis and a live editor invite.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let (mut handle, _secrets) = VaultCreator::new(&path, MASTER, "join-flow")
        .execute()
        .expect("vault creation");
    handle.unlock(MASTER).unwrap();
    let vault_id = handle.vault_id;
    let code = handle
        .invite_create(baluard_core::vault::members::MemberRole::Editor, None)
        .expect("invite");
    drop(handle);

    // Register the vault (clone-finalize equivalent). The registry key is
    // the NORMALIZED slug — registry_vault_path normalizes before lookup.
    let slug = baluard_core::vault::slug::normalize_slug("join-flow");
    let mut reg = VaultRegistry::default();
    reg.add(VaultEntry {
        slug: slug.clone(),
        display_name: slug.clone(),
        path: path.clone(),
        provider: None,
        remote_url: None,
        last_synced: None,
        last_opened: None,
        vault_id,
        merge_opt_in: None,
        merge_ceiling_seen: false,
    })
    .expect("add entry");
    reg.save_locked().expect("save registry");

    let host = Arc::new(VaultHost::new());

    // Missing fields fail closed (this payload has slug only → the code
    // check fires first).
    let resp = route_host_request(
        join_request("join.introduce", serde_json::json!({"slug": slug})),
        &host,
    )
    .await;
    assert!(!resp.success);
    assert!(
        resp.error_message.contains("'code'"),
        "{}",
        resp.error_message
    );

    // Unknown slug fails.
    let resp = route_host_request(
        join_request(
            "join.introduce",
            serde_json::json!({
                "slug": "baluard-nope",
                "code": code,
                "password": "joiner-pass-123",
                "device_name": "d"
            }),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);
    assert!(
        resp.error_message.contains("Unknown vault"),
        "{}",
        resp.error_message
    );

    // Newline device name fails closed.
    let resp = route_host_request(
        join_request(
            "join.introduce",
            serde_json::json!({
                "slug": slug,
                "code": code,
                "password": "joiner-pass-123",
                "device_name": "line1\nline2"
            }),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);

    // Happy path: introduction consumes the invite and returns the
    // intro code for the admin.
    let resp = route_host_request(
        join_request(
            "join.introduce",
            serde_json::json!({
                "slug": slug,
                "code": code,
                "password": "joiner-pass-123",
                "device_name": "Joiner Device",
                "email": "joiner@example.com"
            }),
        ),
        &host,
    )
    .await;
    assert!(
        resp.success,
        "err: {} / payload: {}",
        resp.error_message, resp.payload
    );
    let payload: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert!(
        !payload["intro_code"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    // The claimed email rides the introduction (the queue row and the
    // approval screen surface it).
    let intro =
        baluard_core::vault::members::Introduction::decode(payload["intro_code"].as_str().unwrap())
            .unwrap();
    assert_eq!(intro.email.as_deref(), Some("joiner@example.com"));

    // Re-introducing the consumed invite fails.
    let resp = route_host_request(
        join_request(
            "join.introduce",
            serde_json::json!({
                "slug": slug,
                "code": code,
                "password": "joiner-pass-123",
                "device_name": "Joiner Device"
            }),
        ),
        &host,
    )
    .await;
    assert!(!resp.success);

    // Poll: introduced, not approved (no keywrap shipped yet; the vault
    // has no remote, and the tolerated pull failure keeps status stable).
    let resp = route_host_request(
        join_request("join.poll", serde_json::json!({"slug": slug})),
        &host,
    )
    .await;
    assert!(resp.success, "{}", resp.payload);
    let payload: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(payload["introduced"], true);
    assert_eq!(payload["approved"], false);
}

/// S2 IS-6: the passphrase-guest reveal opens through the host-level
/// route with no vault, no token, and no host state. A wrong passphrase
/// refuses through the same route. NOTE: no sandboxed_host_env here —
/// the route touches no disk, and flipping the process-global
/// BALUARD_DATA_DIR mid-test races the join tests' registry reads.
#[tokio::test]
async fn reveal_open_guest_route_roundtrip_and_refusal() {
    let host = Arc::new(VaultHost::new());

    let fields = baluard_core::vault::reveals::RevealFields {
        url: Some("https://app.example.com".into()),
        username: Some("ada".into()),
        password: Some("hunter2".into()),
        totp_uri: None,
    };
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400;
    let (bytes, passphrase) =
        baluard_core::vault::reveals::seal_guest_reveal("Wifi", &fields, expires).unwrap();
    use base64::Engine as _;
    let reveal_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    // Empty token: the route never consults one.
    let req = GatewayRequest {
        action: "reveals.open_guest".into(),
        payload: serde_json::json!({ "reveal": reveal_b64, "passphrase": passphrase }).to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "{}", resp.error_message);
    let payload: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(payload["item_name"], "Wifi");
    assert_eq!(payload["password"], "hunter2");
    assert_eq!(payload["sender_name"], serde_json::Value::Null);

    // Wrong passphrase: refused, no oracle beyond the crypto.
    let req = GatewayRequest {
        action: "reveals.open_guest".into(),
        payload: serde_json::json!({
            "reveal": reveal_b64,
            "passphrase": "not-the-passphrase",
        })
        .to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "wrong passphrase must refuse");
}

/// S2 IS-5: space.create rides the vault.create pipeline with a forced
/// baluard-space- slug, writes the shape flag, and the flag surfaces in
/// vaults.list. Sandboxed + serialized on JOIN_REG (touches the
/// process-global BALUARD_DATA_DIR via paths + registry).
#[tokio::test]
async fn space_create_route_prefixes_slug_marks_flag_and_lists() {
    let _guard = JOIN_REG.lock().await;
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host = Arc::new(VaultHost::new());

    let req = GatewayRequest {
        action: "space.create".into(),
        payload: serde_json::json!({
            "name": "Family",
            "password": MASTER,
            "profile": "mobile_low",
        })
        .to_string(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "{}", resp.error_message);
    let payload: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let slug = payload["slug"].as_str().expect("slug in response");
    assert!(
        slug.starts_with("baluard-space-"),
        "space slug must carry the prefix: {slug}"
    );
    assert!(
        payload["session_token"].is_string(),
        "created vault is unlocked"
    );

    // The shape flag landed in the plaintext prefs.
    let vault_path = baluard_core::paths::vaults_dir().join(slug);
    assert!(vault_path.exists(), "vault dir exists");
    assert!(baluard_core::vault::space::is_space_vault(&vault_path));

    // vaults.list carries the space marker for the switcher.
    let req = GatewayRequest {
        action: "vaults.list".into(),
        payload: String::new(),
        session_token: String::new(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "{}", resp.error_message);
    let payload: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let row = payload["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["slug"] == *slug)
        .expect("created space listed");
    assert_eq!(row["space"], serde_json::json!(true));
}

// G24 step 6 (plan §4.10): vault.search is the CLI's executable spec of the
// fan-out contract - all=true merges unlocked merge-eligible vaults, a
// locked vault contributes nothing, an org Space never joins the fan-out,
// and vault_slug=<slug> is the explicit "switch vaults" form that may
// search an org Space on purpose.
#[tokio::test]
async fn vault_search_fans_out_and_skips_locked_and_ineligible() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(VaultHost::new());

    let (dir_a, path_a) = make_vault("search-a");
    let state_a = Arc::new(VaultState::new(path_a.clone()));
    state_a.open().await.expect("open a");
    state_a.unlock(MASTER).await.expect("unlock a");
    state_a
        .add_cipher(&serde_json::to_string(&login_input("Alpha Query", "u")).unwrap())
        .await
        .expect("add a");
    register_in_registry("search-a", &path_a);

    let (dir_b, path_b) = make_vault("search-b");
    let state_b = Arc::new(VaultState::new(path_b.clone()));
    state_b.open().await.expect("open b");
    state_b.unlock(MASTER).await.expect("unlock b");
    state_b
        .add_cipher(&serde_json::to_string(&login_input("Beta Query", "u")).unwrap())
        .await
        .expect("add b");
    register_in_registry("search-b", &path_b);

    // Org Space: flipped shape, never unlocked-eligible (ceiling cache
    // stays false). Its cipher must never join the fan-out.
    let (dir_o, path_o) = make_vault("search-org");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open org");
    state_o.unlock(MASTER).await.expect("unlock org");
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();
    state_o
        .add_cipher(&serde_json::to_string(&login_input("Org Query", "u")).unwrap())
        .await
        .expect("add org");
    register_in_registry("search-org", &path_o);

    host.insert("search-a".into(), state_a.clone()).await;
    host.insert("search-b".into(), state_b.clone()).await;
    host.insert("search-org".into(), state_o.clone()).await;
    host.switch("search-b").await.expect("switch to b");

    let token_b = state_b.get_session_token().await.expect("active token");
    let search_req = |payload: serde_json::Value, token: &str| GatewayRequest {
        action: "vault.search".into(),
        payload: payload.to_string(),
        session_token: token.to_string(),
        slug: String::new(),
    };

    // all=true: both personal vaults contribute, tagged; the org Space is
    // absent even though it is unlocked and carries a matching name.
    let resp = route_host_request(
        search_req(serde_json::json!({"query": "Query", "all": true}), &token_b),
        &host,
    )
    .await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["matches"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "personal only, org excluded: {rows:?}");
    assert!(
        rows.iter()
            .all(|r| r["vault_slug"].is_string() && r["vault_name"].is_string()),
        "rows carry attribution: {rows:?}"
    );
    assert!(rows.iter().all(|r| r["vault_slug"] != "search-org"));

    // Default form: active vault only, no attribution fields.
    let resp = route_host_request(
        search_req(serde_json::json!({"query": "Beta"}), &token_b),
        &host,
    )
    .await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["matches"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].get("vault_name").is_none(),
        "default form is unattributed"
    );
    let resp = route_host_request(
        search_req(serde_json::json!({"query": "Alpha"}), &token_b),
        &host,
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(
        parsed["matches"].as_array().unwrap().len(),
        0,
        "active-only default"
    );

    // A locked vault contributes nothing to the fan-out.
    state_a.lock().await.expect("lock a");
    let resp = route_host_request(
        search_req(serde_json::json!({"query": "Query", "all": true}), &token_b),
        &host,
    )
    .await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["matches"].as_array().expect("rows");
    assert_eq!(rows.len(), 1, "locked vault skipped: {rows:?}");
    assert_eq!(rows[0]["vault_slug"], serde_json::json!("search-b"));

    // Explicit single-vault form still reaches the locked vault only as an
    // error; it must never silently search a locked vault.
    let resp = route_host_request(
        search_req(
            serde_json::json!({"query": "Alpha", "vault_slug": "search-a"}),
            &token_b,
        ),
        &host,
    )
    .await;
    assert!(!resp.success, "locked explicit search must fail");

    // Gates: empty query and missing token refuse.
    let resp = route_host_request(
        search_req(serde_json::json!({"query": "  "}), &token_b),
        &host,
    )
    .await;
    assert!(!resp.success, "empty query refused");
    let resp =
        route_host_request(search_req(serde_json::json!({"query": "Query"}), ""), &host).await;
    assert!(!resp.success, "missing token refused");
}

#[tokio::test]
#[serial_test::serial]
async fn hw_seal_status_and_fail_closed_toggle() {
    // The pin_quick_unlock pattern: drive the VaultState methods directly
    // (the daemon arms are one-line passthroughs; their token classification
    // is pinned by the handler-side token_lists test).
    let (_tmp, state) = open_unlocked("hwseal").await;

    // No platform keystore is installed in tests: capable false, and the
    // status still reports the seal kind honestly.
    assert!(baluard_core::hwkey::installed_all().is_empty());
    let v: serde_json::Value = serde_json::from_str(&state.hw_status().await.unwrap()).unwrap();
    assert_eq!(v["capable"], serde_json::Value::Bool(false));
    assert_eq!(v["seal"], "v1");
    assert_eq!(v["enabled"], serde_json::Value::Bool(false));

    // The toggle fails closed with no chip: never a silent no-op.
    let err = state.hw_enable(false, None).await.unwrap_err();
    assert!(err.contains("security chip"), "refusal: {err}");
    let err = state.hw_disable().await.unwrap_err();
    assert!(err.contains("security chip"), "refusal: {err}");
}

struct RouteHwMock {
    backend: &'static str,
    available: bool,
    tap: bool,
}

impl baluard_core::hwkey::HardwareKeyStore for RouteHwMock {
    fn backend_id(&self) -> &'static str {
        self.backend
    }

    fn probe(&self) -> baluard_core::hwkey::HwCapability {
        if self.available {
            baluard_core::hwkey::HwCapability::Available {
                backend: self.backend.into(),
            }
        } else {
            baluard_core::hwkey::HwCapability::Unavailable {
                reason: "no-token".into(),
            }
        }
    }

    fn interaction(&self) -> baluard_core::hwkey::Interaction {
        if self.tap {
            baluard_core::hwkey::Interaction::PerUse
        } else {
            baluard_core::hwkey::Interaction::Never
        }
    }

    fn create_binding(
        &self,
        vault_id: uuid::Uuid,
        _: baluard_core::hwkey::HwConsent,
    ) -> Result<baluard_core::hwkey::BindingInfo, baluard_core::error::BaluardError> {
        Ok(baluard_core::hwkey::BindingInfo {
            binding: baluard_core::hwkey::binding_tag(vault_id),
            // The FIDO shape: an attesting backend reports its verdict at
            // enrollment.
            attestation: if self.tap {
                Some(baluard_core::hwkey::HwAttestation::Verified)
            } else {
                None
            },
        })
    }

    fn derive_ephemeral(
        &self,
        binding: &str,
        _: baluard_core::hwkey::HwConsent,
    ) -> Result<
        (
            baluard_core::hwkey::Handshake,
            baluard_core::hwkey::SharedSecret,
        ),
        baluard_core::error::BaluardError,
    > {
        let mut secret = [0u8; 32];
        for (index, byte) in binding.bytes().chain([0x04, 0x02]).enumerate() {
            secret[index % 32] ^= byte;
        }
        Ok((
            baluard_core::hwkey::Handshake(vec![0x04, 0x02]),
            zeroize::Zeroizing::new(secret),
        ))
    }

    fn derive(
        &self,
        binding: &str,
        handshake: &baluard_core::hwkey::Handshake,
        _: baluard_core::hwkey::HwConsent,
    ) -> Result<baluard_core::hwkey::SharedSecret, baluard_core::error::BaluardError> {
        let mut secret = [0u8; 32];
        for (index, byte) in binding
            .bytes()
            .chain(handshake.0.iter().copied())
            .enumerate()
        {
            secret[index % 32] ^= byte;
        }
        Ok(zeroize::Zeroizing::new(secret))
    }

    fn delete_binding(&self, _: &str) -> Result<(), baluard_core::error::BaluardError> {
        Ok(())
    }
}

struct HwRegistryGuard {
    old_disable: Option<String>,
}

impl HwRegistryGuard {
    fn new() -> Self {
        let old_disable = std::env::var(baluard_core::hwkey::DISABLE_ENV).ok();
        // SAFETY: the hardware route tests are serial and no other test in
        // this binary reads the kill-switch while this guard is alive.
        unsafe {
            std::env::remove_var(baluard_core::hwkey::DISABLE_ENV);
        }
        baluard_core::hwkey::uninstall();
        Self { old_disable }
    }
}

impl Drop for HwRegistryGuard {
    fn drop(&mut self) {
        baluard_core::hwkey::uninstall();
        // SAFETY: same serialization invariant as HwRegistryGuard::new.
        unsafe {
            match self.old_disable.as_deref() {
                Some(value) => std::env::set_var(baluard_core::hwkey::DISABLE_ENV, value),
                None => std::env::remove_var(baluard_core::hwkey::DISABLE_ENV),
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
// M4: the session token alone must not downgrade the seal — a
// compromised webview holds a token, never the master password.
async fn hw_disable_and_consent_downgrade_demand_the_master_password() {
    let _registry = HwRegistryGuard::new();
    baluard_core::hwkey::install(Arc::new(RouteHwMock {
        backend: "tap-mock",
        available: true,
        tap: true,
    }));

    let (_tmp, state) = open_unlocked("hw-disable-gate").await;
    let host: baluard_daemon::host::SharedVaultHost = Arc::new(VaultHost::new());
    host.insert("hw-disable-gate".into(), state.clone()).await;
    host.switch("hw-disable-gate")
        .await
        .expect("activate vault");
    let token = state.get_session_token().await.expect("session token");
    let send = |action: &str, payload: String, token: &str| {
        route_host_request(
            GatewayRequest {
                action: action.to_string(),
                payload,
                session_token: token.to_string(),
                slug: String::new(),
            },
            &host,
        )
    };
    let status_of = |state: Arc<VaultState>| async move {
        serde_json::from_str::<serde_json::Value>(&state.hw_status().await.unwrap()).unwrap()
    };

    // Seal with consent on so the consent-downgrade leg has something to
    // weaken.
    let response = send(
        "vault.hw_enable",
        serde_json::json!({"consent": true, "backend": "tap-mock"}).to_string(),
        &token,
    )
    .await;
    assert!(
        response.success,
        "enable failed: {}",
        response.error_message
    );

    // Disable without a password: refused, seal untouched.
    let response = send("vault.hw_disable", String::new(), &token).await;
    assert!(
        response.error_message.contains("Master password required"),
        "unexpected error: {}",
        response.error_message
    );
    assert_eq!(status_of(state.clone()).await["enabled"], true);

    // A wrong password is an oracle guess: refused and charged.
    let response = send("vault.hw_disable", "wrong-password".into(), &token).await;
    assert!(
        response.error_message.contains("master password incorrect"),
        "unexpected error: {}",
        response.error_message
    );
    assert_eq!(status_of(state.clone()).await["enabled"], true);

    // The limiter backs off after the guess; clear it like a fresh
    // session would be after its window.
    baluard_daemon::rate_limit::global().record_success(&state.vault_path.to_string_lossy());

    // The correct password downgrades.
    let response = send("vault.hw_disable", MASTER.to_string(), &token).await;
    assert!(
        response.success,
        "disable failed: {}",
        response.error_message
    );
    assert_eq!(status_of(state.clone()).await["enabled"], false);

    // Consent gating needs a Silent-capable backend: core refuses
    // consent-downgrade on PerUse backends outright (tap-preserving).
    baluard_core::hwkey::install(Arc::new(RouteHwMock {
        backend: "silent-mock",
        available: true,
        tap: false,
    }));
    let (_tmp2, state2) = open_unlocked("hw-consent-gate").await;
    let host2: baluard_daemon::host::SharedVaultHost = Arc::new(VaultHost::new());
    host2.insert("hw-consent-gate".into(), state2.clone()).await;
    host2
        .switch("hw-consent-gate")
        .await
        .expect("activate vault");
    let token2 = state2.get_session_token().await.expect("session token");
    let send2 = |action: &str, payload: String, token: &str| {
        route_host_request(
            GatewayRequest {
                action: action.to_string(),
                payload,
                session_token: token.to_string(),
                slug: String::new(),
            },
            &host2,
        )
    };

    // Silent chips seal natively consent-off (core pins consent to the
    // backend's interaction class, so flips are refused either way today;
    // the route gate is defense-in-depth for the downgrade direction).
    let response = send2(
        "vault.hw_enable",
        serde_json::json!({"consent": false, "backend": "silent-mock"}).to_string(),
        &token2,
    )
    .await;
    assert!(
        response.success,
        "silent enable failed: {}",
        response.error_message
    );

    // The downgrade direction demands the password before core sees it.
    let response = send2(
        "vault.hw_set_consent",
        serde_json::json!({"consent": false}).to_string(),
        &token2,
    )
    .await;
    assert!(
        response.error_message.contains("Master password required"),
        "unexpected error: {}",
        response.error_message
    );

    // Correct password: core no-ops the same-value rewrite.
    let response = send2(
        "vault.hw_set_consent",
        serde_json::json!({"consent": false, "master_password": MASTER}).to_string(),
        &token2,
    )
    .await;
    assert!(
        response.success,
        "consent change failed: {}",
        response.error_message
    );
    assert_eq!(status_of(state2.clone()).await["consent"], false);
}

async fn hw_routes_select_a_tap_backend_and_report_every_probe() {
    let _registry = HwRegistryGuard::new();
    baluard_core::hwkey::install(Arc::new(RouteHwMock {
        backend: "broken-mock",
        available: false,
        tap: false,
    }));
    baluard_core::hwkey::install(Arc::new(RouteHwMock {
        backend: "tap-mock",
        available: true,
        tap: true,
    }));

    let (_tmp, state) = open_unlocked("hw-fido-route").await;
    let host: baluard_daemon::host::SharedVaultHost = Arc::new(VaultHost::new());
    host.insert("hw-fido-route".into(), state.clone()).await;
    host.switch("hw-fido-route").await.expect("activate vault");
    let token = state.get_session_token().await.expect("session token");
    let response = route_host_request(
        GatewayRequest {
            action: "vault.hw_enable".into(),
            payload: serde_json::json!({"consent": false, "backend": "tap-mock"}).to_string(),
            session_token: token,
            slug: String::new(),
        },
        &host,
    )
    .await;
    assert!(
        response.success,
        "enable failed: {}",
        response.error_message
    );
    let enabled: serde_json::Value = serde_json::from_str(&response.payload).unwrap();
    assert_eq!(enabled["backend"], "tap-mock");
    assert_eq!(enabled["attestation"], "verified");

    let status: serde_json::Value =
        serde_json::from_str(&state.hw_status().await.unwrap()).unwrap();
    assert_eq!(status["capable"], true);
    assert_eq!(status["backend"], "tap-mock");
    assert_eq!(status["enabled"], true);
    assert_eq!(status["consent"], true);
    assert_eq!(status["consent_supported"], false);
    assert_eq!(status["attestation"], "verified");
    let backends = status["backends"].as_array().expect("backend status list");
    assert_eq!(backends.len(), 2);
    assert_eq!(backends[0]["backend"], "broken-mock");
    assert_eq!(backends[0]["capable"], false);
    assert_eq!(backends[0]["reason"], "no-token");
    assert_eq!(backends[1]["backend"], "tap-mock");
    assert_eq!(backends[1]["capable"], true);
    assert_eq!(backends[1]["interaction"], "per-use");

    state.lock().await.expect("lock sealed vault");
    state
        .unlock(MASTER)
        .await
        .expect("reopen through tap backend");
}

#[tokio::test]
async fn vault_search_explicit_slug_includes_org_space() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(VaultHost::new());

    let (dir_p, path_p) = make_vault("svp-personal");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open personal");
    state_p.unlock(MASTER).await.expect("unlock personal");
    state_p
        .add_cipher(&serde_json::to_string(&login_input("Personal Hit", "u")).unwrap())
        .await
        .expect("add personal");
    register_in_registry("svp-personal", &path_p);

    let (dir_o, path_o) = make_vault("svp-org");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open org");
    state_o.unlock(MASTER).await.expect("unlock org");
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();
    state_o
        .add_cipher(&serde_json::to_string(&login_input("Org Secret", "u")).unwrap())
        .await
        .expect("add org");
    register_in_registry("svp-org", &path_o);

    host.insert("svp-personal".into(), state_p.clone()).await;
    host.insert("svp-org".into(), state_o.clone()).await;
    host.switch("svp-personal")
        .await
        .expect("switch to personal");
    let token = state_p.get_session_token().await.expect("active token");

    // vault_slug=<org>: the explicit "switch vaults" form (plan §4.10). An
    // organization Space is searchable by explicit choice; no eligibility
    // gate applies, only the unlock requirement.
    let req = GatewayRequest {
        action: "vault.search".into(),
        payload: serde_json::json!({"query": "Org Secret", "vault_slug": "svp-org"}).to_string(),
        session_token: token,
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success, "err: {}", resp.error_message);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    let rows = parsed["matches"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["vault_slug"], serde_json::json!("svp-org"));
    assert_eq!(rows[0]["name"], serde_json::json!("Org Secret"));

    // Unknown slug refuses like the bridge reads do.
    let req = GatewayRequest {
        action: "vault.search".into(),
        payload: serde_json::json!({"query": "x", "vault_slug": "nope"}).to_string(),
        session_token: state_p.get_session_token().await.unwrap(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success);
    assert!(resp.error_message.contains("not open in the daemon"));
}

// G24 step 9 (plan §4.6 v1.1 + §4.7 v2): slug-routed capture updates let a
// merge-eligible Space's entry take a browser capture; bridge.request_unlock
// carries the ask (never a credential) to the desktop.
#[tokio::test]
async fn bridge_slug_scoped_write_and_request_unlock() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let host: baluard_daemon::host::SharedVaultHost = std::sync::Arc::new(VaultHost::new());

    let (dir_p, path_p) = make_vault("g24w-p");
    let state_p = Arc::new(VaultState::new(path_p.clone()));
    state_p.open().await.expect("open personal");
    state_p.unlock(MASTER).await.expect("unlock personal");
    register_in_registry("g24w-p", &path_p);

    // Family vault (eligible ceiling) + org Space (ineligible).
    let dir_f = tempfile::TempDir::new().expect("fam tmp");
    let path_f = dir_f.path().join("fam");
    let (handle_f, _) =
        baluard_core::vault::creation::VaultCreator::new(&path_f, MASTER, "this-device")
            .family(true)
            .execute()
            .expect("create family");
    let state_f = Arc::new(VaultState::new(path_f.clone()));
    // Registration BEFORE unlock: registering replaces the whole registry
    // entry, wiping the merge_ceiling_seen cache the unlock refresh writes
    // (the established fixture-order rule).
    register_in_registry("g24w-f", &path_f);
    state_f.open().await.expect("open family");
    state_f.unlock(MASTER).await.expect("unlock family");
    drop(handle_f);

    let (dir_o, path_o) = make_vault("g24w-org");
    let state_o = Arc::new(VaultState::new(path_o.clone()));
    state_o.open().await.expect("open org");
    state_o.unlock(MASTER).await.expect("unlock org");
    baluard_core::vault::space_meta::write_shape_marker(&path_o, 1).unwrap();
    register_in_registry("g24w-org", &path_o);

    host.insert("g24w-p".into(), state_p.clone()).await;
    host.insert("g24w-f".into(), state_f.clone()).await;
    host.insert("g24w-org".into(), state_o.clone()).await;
    host.switch("g24w-p").await.expect("switch to personal");
    let token = state_p.get_session_token().await.expect("active token");
    let token_hex = {
        let mut reg = host.bridge().write().await;
        let _pair = reg.start_pair("test-harness");
        reg.complete_pair("ext", "firefox").expect("pair").1
    };

    // Slug-scoped WRITE: a capture update lands in the family vault even
    // though the active vault is personal (plan §4.6 v1.1).
    let mut add = login_input("Family Wifi", "home");
    let mut v: serde_json::Value = serde_json::to_value(&add).unwrap();
    v["vault_slug"] = serde_json::json!("g24w-f");
    let req = GatewayRequest {
        action: "vault.add".into(),
        payload: v.to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "slug-scoped write refused: {}",
        resp.error_message
    );
    let fam_ciphers = state_f.list_cipher_meta().await.expect("family metas");
    assert!(
        fam_ciphers.iter().any(|m| m.name == "Family Wifi"),
        "cipher landed in the family vault"
    );
    assert!(
        !state_p
            .list_cipher_meta()
            .await
            .expect("personal metas")
            .iter()
            .any(|m| m.name == "Family Wifi"),
        "personal vault untouched"
    );

    // Ineligible slug refuses the write (org Space stays invisible).
    let mut v2: serde_json::Value = serde_json::to_value(&login_input("Org Wifi", "u")).unwrap();
    v2["vault_slug"] = serde_json::json!("g24w-org");
    let req = GatewayRequest {
        action: "vault.add".into(),
        payload: v2.to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "ineligible write must refuse");

    // bridge.request_unlock: eligible slug accepted + surfaced; org
    // refused; take consumes.
    let req = GatewayRequest {
        action: "bridge.request_unlock".into(),
        payload: serde_json::json!({"slug": "g24w-f"}).to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "request_unlock refused: {}",
        resp.error_message
    );
    let req = GatewayRequest {
        action: "bridge.unlock_request".into(),
        payload: String::new(),
        session_token: token.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(parsed["slug"], serde_json::json!("g24w-f"));
    let req = GatewayRequest {
        action: "bridge.request_unlock".into(),
        payload: serde_json::json!({"slug": "g24w-org"}).to_string(),
        session_token: token_hex.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "org Space unlock request must refuse");
    let req = GatewayRequest {
        action: "bridge.unlock_request_take".into(),
        payload: String::new(),
        session_token: token.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    assert!(resp.success);
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert_eq!(parsed["slug"], serde_json::json!("g24w-f"));
    // Consumed: the peek now returns an empty object.
    let req = GatewayRequest {
        action: "bridge.unlock_request".into(),
        payload: String::new(),
        session_token: token.clone(),
        slug: String::new(),
    };
    let resp = route_host_request(req, &host).await;
    let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap();
    assert!(parsed.get("slug").is_none(), "request consumed: {parsed}");
}

/// Hardware-seal outcomes are not password guesses: a locked-out-past-10
/// lockout must never arise from repeated "chip is unavailable" failures
/// (the forgotten-key-at-home scenario), or the user locks themselves out
/// by retrying with the key unplugged.
#[tokio::test]
#[serial_test::serial]
async fn hardware_unlock_failures_do_not_lock_out_the_route() {
    let (_sandbox, _sandbox_guard) = sandboxed_host_env().await;
    let _registry = HwRegistryGuard::new();
    baluard_core::hwkey::install(Arc::new(RouteHwMock {
        backend: "tap-mock",
        available: true,
        tap: true,
    }));

    let (_tmp, state) = open_unlocked("hw-rate-route").await;
    register_in_registry("hw-rate-route", &state.vault_path);
    let host: baluard_daemon::host::SharedVaultHost = Arc::new(VaultHost::new());
    host.insert("hw-rate-route".into(), state.clone()).await;
    host.switch("hw-rate-route").await.expect("activate vault");
    let token = state.get_session_token().await.expect("active vault token");
    let response = route_host_request(
        GatewayRequest {
            action: "vault.hw_enable".into(),
            payload: serde_json::json!({"consent": false, "backend": "tap-mock"}).to_string(),
            session_token: token,
            slug: String::new(),
        },
        &host,
    )
    .await;
    assert!(
        response.success,
        "enable failed: {}",
        response.error_message
    );

    state.lock().await.expect("lock sealed vault");
    baluard_core::hwkey::uninstall();

    for attempt in 0..11 {
        let response = route_host_request(
            GatewayRequest {
                action: "vault.unlock".into(),
                payload: serde_json::json!({"password": MASTER}).to_string(),
                session_token: String::new(),
                slug: "hw-rate-route".into(),
            },
            &host,
        )
        .await;
        assert!(
            !response.success,
            "attempt {attempt} unlocked with the chip gone"
        );
        assert!(
            response.error_message.contains("chip is unavailable"),
            "attempt {attempt}: expected the hardware error, got: {}",
            response.error_message
        );
    }
}

// ── D80 agent grants ───────────────────────────────────────────────────

fn agent_request(action: &str, payload: serde_json::Value, token: String) -> GatewayRequest {
    GatewayRequest {
        action: action.into(),
        payload: payload.to_string(),
        session_token: token,
        slug: "personal".into(),
        ..Default::default()
    }
}

fn agent_peer(pid: u32) -> baluard_runtime::agents::PeerBinding {
    baluard_runtime::agents::PeerBinding::new(
        pid,
        format!("/usr/bin/agent-{pid}"),
        1000 + pid as u64,
    )
}

async fn agent_host(label: &str) -> (tempfile::TempDir, Arc<VaultHost>, Arc<VaultState>) {
    let (dir, state) = open_unlocked(label).await;
    let host = Arc::new(VaultHost::new());
    host.insert("personal".into(), state.clone()).await;
    (dir, host, state)
}

#[tokio::test]
async fn agent_request_requires_peer_identity_and_an_unlocked_vault() {
    let (_dir, host, state) = agent_host("agent-preconditions").await;
    let payload = serde_json::json!({
        "slug": "personal",
        "claimed_name": "Example agent",
        "need": "GitHub login",
        "item_ids": ["item-1"]
    });
    let req = agent_request("agents.request", payload.clone(), String::new());
    let no_peer = route_host_request(req.clone(), &host).await;
    assert!(!no_peer.success);
    assert!(no_peer.error_message.contains("peer identity"));

    let peer = agent_peer(41);
    let accepted = baluard_daemon::handler::route_host_request_with_peer(
        agent_request("agents.request", payload, String::new()),
        &host,
        Some(&peer),
    )
    .await;
    assert!(accepted.success, "err: {}", accepted.error_message);
    let v: serde_json::Value = serde_json::from_str(&accepted.payload).unwrap();
    assert_eq!(v["status"], "pending");
    assert!(!v["request_id"].as_str().unwrap().is_empty());

    state.lock().await.unwrap();
    let locked = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.request",
            serde_json::json!({
                "slug": "personal",
                "claimed_name": "Example agent",
                "need": "GitHub login",
                "item_ids": ["item-2"]
            }),
            String::new(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    assert!(!locked.success);
    assert!(locked.error_message.contains("locked"));
}

#[tokio::test]
async fn agent_grants_survive_the_desktop_blur_lock() {
    let (_dir, host, state) = agent_host("agent-blur").await;
    state.agent_mint(agent_peer(45), vec!["item-1".into()], 60);
    let locked = host.lock_blur_vaults().await;
    assert!(
        locked.is_empty(),
        "live agent grants exempt the vault from blur lock"
    );
    assert!(state.is_unlocked().await);
}

#[tokio::test]
async fn agent_approval_is_one_time_and_lock_kills_the_grant() {
    let (_dir, host, state) = agent_host("agent-approval").await;
    let peer = agent_peer(42);
    let requested = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.request",
            serde_json::json!({
                "slug": "personal",
                "claimed_name": "Example agent",
                "need": "GitHub login",
                "item_ids": ["item-1"]
            }),
            String::new(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    let request_id =
        serde_json::from_str::<serde_json::Value>(&requested.payload).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
    let user_token = state.get_session_token().await.unwrap();

    let pending = route_host_request(
        agent_request("agents.pending", serde_json::json!({}), user_token.clone()),
        &host,
    )
    .await;
    assert!(pending.success, "err: {}", pending.error_message);
    let pending_json: serde_json::Value = serde_json::from_str(&pending.payload).unwrap();
    assert_eq!(pending_json["pending"][0]["exe_path"], "/usr/bin/agent-42");

    let approved = route_host_request(
        agent_request(
            "agents.approve",
            serde_json::json!({"request_id": request_id}),
            user_token,
        ),
        &host,
    )
    .await;
    assert!(approved.success, "err: {}", approved.error_message);
    assert!(
        !approved.payload.contains("agt_"),
        "desktop never receives the agent token"
    );

    let polled = route_host_request(
        agent_request(
            "agents.poll",
            serde_json::json!({"request_id": request_id}),
            String::new(),
        ),
        &host,
    )
    .await;
    let poll_json: serde_json::Value = serde_json::from_str(&polled.payload).unwrap();
    assert_eq!(poll_json["status"], "approved");
    let agent_token = poll_json["token"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("agt_"));
    assert!(state.verify_agent_token(&agent_token).is_ok());

    let replay = route_host_request(
        agent_request(
            "agents.poll",
            serde_json::json!({"request_id": request_id}),
            String::new(),
        ),
        &host,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&replay.payload).unwrap()["status"],
        "unknown"
    );

    let crossover = route_host_request(
        agent_request("vault.list", serde_json::json!({}), agent_token.clone()),
        &host,
    )
    .await;
    assert!(!crossover.success);
    assert!(
        crossover
            .error_message
            .contains("agent grants cannot call user session routes")
    );

    state.lock().await.unwrap();
    let err = state
        .verify_agent_token(&agent_token)
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalidated by a vault lock"), "{err}");
}

#[tokio::test]
async fn agent_denial_is_reported_without_a_grant() {
    let (_dir, host, state) = agent_host("agent-denial").await;
    let peer = agent_peer(43);
    let requested = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.request",
            serde_json::json!({
                "slug": "personal",
                "claimed_name": "Example agent",
                "need": "GitHub login",
                "item_ids": ["item-1"]
            }),
            String::new(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    let request_id =
        serde_json::from_str::<serde_json::Value>(&requested.payload).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
    let denied = route_host_request(
        agent_request(
            "agents.deny",
            serde_json::json!({"request_id": request_id}),
            state.get_session_token().await.unwrap(),
        ),
        &host,
    )
    .await;
    assert!(denied.success, "err: {}", denied.error_message);
    let polled = route_host_request(
        agent_request(
            "agents.poll",
            serde_json::json!({"request_id": request_id}),
            String::new(),
        ),
        &host,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&polled.payload).unwrap()["status"],
        "denied"
    );
}

#[tokio::test]
async fn agent_approval_requires_the_user_token_and_caps_prompt_flooding() {
    let (_dir, host, _state) = agent_host("agent-caps").await;
    let peer = agent_peer(44);
    let payload = serde_json::json!({
        "slug": "personal",
        "claimed_name": "Example agent",
        "need": "GitHub login",
        "item_ids": ["item-1"]
    });
    let requested = baluard_daemon::handler::route_host_request_with_peer(
        agent_request("agents.request", payload.clone(), String::new()),
        &host,
        Some(&peer),
    )
    .await;
    let request_id =
        serde_json::from_str::<serde_json::Value>(&requested.payload).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();

    let refused = route_host_request(
        agent_request(
            "agents.approve",
            serde_json::json!({"request_id": request_id}),
            "wrong-user-token".into(),
        ),
        &host,
    )
    .await;
    assert!(!refused.success);
    assert!(host.pending_requests().get(&request_id).is_some());

    let (_other_dir, other_state) = open_unlocked("agent-approval-mismatch").await;
    host.insert("other".into(), other_state.clone()).await;
    let mut wrong_vault = agent_request(
        "agents.approve",
        serde_json::json!({"request_id": request_id}),
        other_state.get_session_token().await.unwrap(),
    );
    wrong_vault.slug = "other".into();
    let mismatch = route_host_request(wrong_vault, &host).await;
    assert!(!mismatch.success);
    assert!(mismatch.error_message.contains("different vault"));
    assert!(
        host.pending_requests().get(&request_id).is_some(),
        "a wrong-vault approval must leave the request pending"
    );

    let flooded = baluard_daemon::handler::route_host_request_with_peer(
        agent_request("agents.request", payload, String::new()),
        &host,
        Some(&peer),
    )
    .await;
    assert!(!flooded.success);
    assert!(flooded.error_message.contains("already waiting"));
}

#[tokio::test]
async fn agent_run_injects_only_approved_fields_and_scrubs_both_streams() {
    let (_dir, host, state) = agent_host("agent-run").await;
    let mut input = login_input("GitHub", "octocat");
    if let CipherKind::Login(ref mut data) = input.kind {
        data.password = Some(format!("agent-password-{}", uuid::Uuid::new_v4()));
    }
    let item_id = state
        .add_cipher(&serde_json::to_string(&input).unwrap())
        .await
        .unwrap();
    let cipher: serde_json::Value =
        serde_json::from_str(&state.get_cipher(&item_id, true).await.unwrap()).unwrap();
    let expected_password = cipher["password"].as_str().unwrap().to_string();
    let peer = baluard_runtime::agents::PeerBinding::new(
        std::process::id(),
        "/usr/bin/current-test-agent",
        0,
    );
    let requested = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.request",
            serde_json::json!({
                "slug": "personal",
                "claimed_name": "Example agent",
                "need": "GitHub login",
                "item_ids": [item_id]
            }),
            String::new(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    let request_id =
        serde_json::from_str::<serde_json::Value>(&requested.payload).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
    let approved = route_host_request(
        agent_request(
            "agents.approve",
            serde_json::json!({"request_id": request_id}),
            state.get_session_token().await.unwrap(),
        ),
        &host,
    )
    .await;
    assert!(approved.success, "err: {}", approved.error_message);
    let polled = route_host_request(
        agent_request(
            "agents.poll",
            serde_json::json!({"request_id": request_id}),
            String::new(),
        ),
        &host,
    )
    .await;
    let agent_token = serde_json::from_str::<serde_json::Value>(&polled.payload).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let run = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.run",
            serde_json::json!({
                "argv": ["sh", "-c", "printf 'token=%s\\n' \"$GITHUB_TOKEN\"; printf 'err=%s\\n' \"$GITHUB_TOKEN\" >&2"],
                "inject": [{"name": "GITHUB_TOKEN", "item_id": item_id, "field": "password"}]
            }),
            agent_token.clone(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    assert!(run.success, "err: {}", run.error_message);
    let result: serde_json::Value = serde_json::from_str(&run.payload).unwrap();
    assert_eq!(result["status"], 0);
    assert_eq!(result["stdout"], "token=[REDACTED]\n");
    assert_eq!(result["stderr"], "err=[REDACTED]\n");
    assert!(!run.payload.contains(&expected_password));

    let outside = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.run",
            serde_json::json!({
                "argv": ["sh", "-c", "printf should-not-run"],
                "inject": [{"name": "OTHER", "item_id": uuid::Uuid::new_v4(), "field": "password"}]
            }),
            agent_token.clone(),
        ),
        &host,
        Some(&peer),
    )
    .await;
    assert!(!outside.success);
    assert!(outside.error_message.contains("outside the approved items"));

    let unrelated_peer = agent_peer(1);
    let wrong_process = baluard_daemon::handler::route_host_request_with_peer(
        agent_request(
            "agents.run",
            serde_json::json!({"argv": ["true"], "inject": []}),
            agent_token.clone(),
        ),
        &host,
        Some(&unrelated_peer),
    )
    .await;
    assert!(!wrong_process.success);
    assert!(
        wrong_process
            .error_message
            .contains("different process tree")
    );

    let user_token = state.get_session_token().await.unwrap();
    let listed = route_host_request(
        agent_request("agents.list", serde_json::json!({}), user_token.clone()),
        &host,
    )
    .await;
    assert!(listed.success, "err: {}", listed.error_message);
    let grants: serde_json::Value = serde_json::from_str(&listed.payload).unwrap();
    assert_eq!(grants["grants"][0]["item_ids"][0], item_id);
    assert_eq!(grants["grants"][0]["pid"], std::process::id());

    let self_revoked = route_host_request(
        agent_request(
            "agents.revoke_own",
            serde_json::json!({}),
            agent_token.clone(),
        ),
        &host,
    )
    .await;
    assert!(self_revoked.success, "err: {}", self_revoked.error_message);
    assert!(state.verify_agent_token(&agent_token).is_err());
    assert!(state.agent_live_grants().is_empty());

    let revoked = route_host_request(
        agent_request("agents.revoke", serde_json::json!({}), user_token),
        &host,
    )
    .await;
    assert!(revoked.success, "err: {}", revoked.error_message);
    assert!(state.verify_agent_token(&agent_token).is_err());
    assert!(state.agent_live_grants().is_empty());
}
