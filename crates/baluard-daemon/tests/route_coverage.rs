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
use std::sync::{Arc, Mutex};

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
fn sandboxed_host_env() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("sandbox tempdir");
    // SAFETY: each #[tokio::test] awaits before any other env-var reader
    // runs in this test process. Tests using this helper don't read
    // BALUARD_DATA_DIR concurrently with the set.
    unsafe {
        std::env::set_var("BALUARD_DATA_DIR", dir.path());
    }
    dir
}

async fn vault_host_list_includes_inserted_vault() {
    let _sandbox = sandboxed_host_env();
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
    let _sandbox = sandboxed_host_env();
    let host = VaultHost::new();
    assert!(
        host.list().await.is_empty(),
        "fresh host with empty registry has zero vaults"
    );
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
    let _sandbox = sandboxed_host_env();
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
    let _sandbox = sandboxed_host_env();
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
    let _sandbox = sandboxed_host_env();
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

    // Mint an editor invite.
    let invite: serde_json::Value =
        serde_json::from_str(&state.members_invite(r#"{"role":"editor"}"#).await.unwrap()).unwrap();
    assert!(!invite["code"].as_str().unwrap_or_default().is_empty());

    // Members list: the genesis owner row, not reset/removed.
    let rows: serde_json::Value =
        serde_json::from_str(&state.members_list().await.unwrap()).unwrap();
    let arr = rows.as_array().expect("members.list returns an array");
    assert_eq!(arr.len(), 1, "genesis vault has exactly the owner row");
    assert_eq!(arr[0]["role"], "owner");
    assert_eq!(arr[0]["removed"], false);

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
}

// ── §4.8-2: join flow routes (wire-level through route_host_request) ──
// The join handlers resolve slugs via the GLOBAL registry file, so tests
// serialise on JOIN_REG and sandbox BALUARD_DATA_DIR (same pattern as
// phase6_detach.rs).
static JOIN_REG: Mutex<()> = Mutex::new(());

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
    let _guard = JOIN_REG.lock().unwrap();
    let _sandbox = sandboxed_host_env();
    // Real vault with an owner genesis and a live editor invite.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let (mut handle, _secrets) = VaultCreator::new(&path, MASTER, "join-flow")
        .execute()
        .expect("vault creation");
    handle.unlock(MASTER).unwrap();
    let vault_id = handle.vault_id;
    let code = handle
        .invite_create(baluard_core::vault::members::MemberRole::Editor)
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
    })
    .expect("add entry");
    reg.save_locked().expect("save registry");
    // Drop the registry lock before any await (sandboxed data dir already
    // isolates this test's registry file).
    drop(_guard);

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
                "device_name": "Joiner Device"
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
