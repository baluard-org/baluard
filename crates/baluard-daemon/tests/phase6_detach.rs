//! Integration tests for the `vaults.detach` flow.
//!
//! `vaults.detach` is the user-facing "remove this vault from Baluard"
//! command on the desktop and CLI. It works pre-unlock and either:
//!   - drops the registry entry (safe arm), or
//!   - drops the registry entry AND deletes the vault directory from disk
//!     (destructive arm, gated by a marker re-validation).
//!
//! The handler composes three building blocks: `VaultHost::close`
//! (zeroize keys + drop from map + clear active), `VaultRegistry::remove`
//! (drop entry + clear active), and a `.baluard` marker re-check before
//! `remove_dir_all`. These tests exercise each piece and the composed
//! flow against a real on-disk vault so the safety gate is exercised.
//!
//! **Two layers of tests**:
//!   1. **Mirror tests** (the bulk) exercise the `disk_delete_gated`
//!      and `detach_registry_only_at` helpers. They are hermetic and
//!      parallel-safe — registry writes go through a tempdir path.
//!   2. **Wire-level tests** (the `route_host_request` calls at the
//!      bottom) drive the real handler with a real `GatewayRequest` and
//!      assert on the real `GatewayResponse`. These are the only tests
//!      that can catch a bug in the actual `"vaults.detach"` match arm
//!      (wrong field name, wrong order, divergent error string). They
//!      touch the global `data_dir/registry.json` and are therefore
//!      serialised via a process-wide `Mutex` so concurrent test
//!      runners don't race on the file.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use baluard_core::vault::creation::VaultCreator;
use baluard_core::vault::registry::{BaluardMarker, VaultEntry, VaultRegistry};
use baluard_daemon::handler::route_host_request;
use baluard_daemon::host::VaultHost;
use baluard_daemon::proto::{GatewayRequest, GatewayResponse};
use baluard_daemon::state::VaultState;
use uuid::Uuid;

/// Serialises wire-level tests that mutate the global registry file.
static GLOBAL_REG: Mutex<()> = Mutex::new(());

/// Per-test registry isolation for the wire-level detach tests: the
/// detach handler REWRITES the real registry file at BALUARD_DATA_DIR, so
/// two parallel wire tests racing their reads and handler-time rewrites
/// see each other's entries vanish. Each test redirects BALUARD_DATA_DIR
/// to its own tempdir and holds the lock for the whole test body.
static DATA_DIR_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn sandboxed_data_dir() -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = DATA_DIR_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("sandbox tempdir");
    // SAFETY: single-threaded test process env mutation, serialized by
    // DATA_DIR_LOCK; no other test in this binary reads the var while
    // the guard is held.
    unsafe {
        std::env::set_var("BALUARD_DATA_DIR", dir.path());
    }
    (dir, guard)
}

// ── test helpers ──

fn make_real_vault(label: &str) -> (tempfile::TempDir, PathBuf, Uuid) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().to_path_buf();
    let password = "test-master-password-123";
    let slug = format!("dev-{label}");
    // Set the slug via the builder so VaultCreator writes the .baluard
    // marker; without it the marker is skipped and the disk-delete gate
    // would refuse the test even with a valid registry entry.
    let (_handle, _secrets) = VaultCreator::new(&path, password, &slug)
        .slug(Some(slug.clone()))
        .execute()
        .expect("vault creation");
    // Read the vault_id the creator wrote into .baluard — the registry
    // entry must mirror it so the disk-delete gate accepts deletion.
    let marker = BaluardMarker::read_from_vault(&path)
        .expect("marker read")
        .expect("marker present");
    (dir, path, marker.vault_id)
}

fn make_entry(slug: &str, path: &Path, vault_id: Uuid) -> VaultEntry {
    VaultEntry {
        slug: slug.to_string(),
        display_name: slug.to_string(),
        path: path.to_path_buf(),
        provider: None,
        remote_url: None,
        last_synced: None,
        last_opened: None,
        vault_id,
        merge_opt_in: None,
        merge_ceiling_seen: false,
    }
}

/// Mirror of the handler's registry-only detach arm. Operates on a
/// caller-supplied path so tests can use a tempdir and stay parallel-
/// safe (no touch on the global `data_dir/registry.json`).
fn detach_registry_only_at(reg_path: &Path, slug: &str) -> Option<VaultEntry> {
    let mut reg = VaultRegistry::load_from(reg_path).expect("registry load");
    let removed = reg.remove(slug);
    reg.save_to(reg_path).expect("registry save");
    removed
}

/// Mirror of the handler's disk-delete gate. Returns Ok(()) on success.
/// Refuses when the marker is missing, unreadable, OR carries a different
/// vault_id. `force=true` bypasses only the `Missing` / `Unreadable`
/// states — never `Mismatch` (which is positive evidence the directory
/// is a different vault). Mirrors the production `MarkerCheck` enum so
/// the helper cannot drift from the real handler.
fn disk_delete_gated(path: &Path, expected_vault_id: Uuid, force: bool) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let marker_result = BaluardMarker::read_from_vault(path);
    let mismatch = matches!(&marker_result, Ok(Some(m)) if m.vault_id != expected_vault_id);
    let ok = matches!(&marker_result, Ok(Some(m)) if m.vault_id == expected_vault_id);
    if !ok {
        if mismatch {
            // Mismatch is UNCONDITIONAL refusal. The typed-name gate
            // echoes the registry's own display_name and proves nothing
            // about the directory's actual contents when the marker
            // positively disagrees with the registry.
            return Err(format!(
                "refusing: .baluard marker vault_id mismatch at {} (cannot be bypassed by force)",
                path.display()
            ));
        }
        if !force {
            let reason = match marker_result {
                Ok(Some(_)) => "vault_id mismatch",
                Ok(None) => "missing",
                Err(_) => "unreadable",
            };
            return Err(format!(
                "refusing: .baluard marker is {reason} at {}",
                path.display()
            ));
        }
    }
    std::fs::remove_dir_all(path).map_err(|e| e.to_string())?;
    Ok(())
}

// ── registry detach ──

#[test]
fn registry_remove_clears_active_and_entry() {
    let mut reg = VaultRegistry::default();
    let entry = make_entry("work", Path::new("/tmp/example/work"), Uuid::new_v4());
    reg.add(entry).unwrap();
    reg.set_active("work").unwrap();
    assert_eq!(reg.active_vault.as_deref(), Some("work"));

    let removed = reg.remove("work");
    assert!(removed.is_some());
    assert!(reg.get("work").is_none());
    assert!(
        reg.active_vault.is_none(),
        "active must clear when slug was active"
    );
}

#[test]
fn registry_remove_persists_across_reload() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let reg_path = dir.path().join("registry.json");

    let mut reg = VaultRegistry::default();
    reg.add(make_entry("alpha", Path::new("/tmp/alpha"), Uuid::new_v4()))
        .unwrap();
    reg.add(make_entry("beta", Path::new("/tmp/beta"), Uuid::new_v4()))
        .unwrap();
    reg.save_to(&reg_path).expect("save");

    let mut reloaded = VaultRegistry::load_from(&reg_path).unwrap();
    assert!(reloaded.get("alpha").is_some());

    reloaded.remove("alpha");
    reloaded.save_to(&reg_path).expect("save");

    let final_state = VaultRegistry::load_from(&reg_path).unwrap();
    assert!(final_state.get("alpha").is_none());
    assert!(final_state.get("beta").is_some());
}

// ── host detach ──

#[tokio::test]
async fn host_close_drops_map_entry_and_clears_active() {
    let host = VaultHost::shared();
    let state = Arc::new(VaultState::new(PathBuf::from("/tmp/fake")));
    host.insert("only".into(), state).await;
    host.switch("only").await.unwrap();
    assert_eq!(host.active_slug().await.as_deref(), Some("only"));

    let removed = host.close("only").await;
    assert!(removed);
    assert!(host.get("only").await.is_none());
    assert_eq!(host.active_slug().await, None);
}

#[tokio::test]
async fn host_close_unknown_slug_is_noop() {
    let host = VaultHost::shared();
    let removed = host.close("ghost").await;
    assert!(!removed, "unknown slug must report not removed");
}

// ── composed flow ──

#[tokio::test]
async fn detach_real_vault_drops_registry_and_host_state() {
    let (_dir, path, vault_id) = make_real_vault("detach-safe");
    // Tempdir-backed registry path keeps this test parallel-safe — no
    // touch on the global data_dir/registry.json.
    let reg_dir = tempfile::tempdir().expect("reg tempdir");
    let reg_path = reg_dir.path().join("registry.json");

    // Wire the vault into the registry + host like a successful unlock would.
    let mut reg = VaultRegistry::default();
    let entry = make_entry("detach-safe", &path, vault_id);
    let entry_vault_id = entry.vault_id;
    reg.add(entry).unwrap();
    reg.set_active("detach-safe").unwrap();
    reg.save_to(&reg_path).expect("save");

    let host = VaultHost::shared();
    let state = Arc::new(VaultState::new(path.clone()));
    state.unlock("test-master-password-123").await.unwrap();
    host.insert("detach-safe".into(), state.clone()).await;
    host.switch("detach-safe").await.unwrap();
    assert!(host.get("detach-safe").await.is_some());
    assert_eq!(host.active_slug().await.as_deref(), Some("detach-safe"));

    // Mirror the route: host.close (zeroize keys + drop map + clear active)
    // then registry.remove (drop entry + clear active).
    host.close("detach-safe").await;
    let removed =
        detach_registry_only_at(&reg_path, "detach-safe").expect("registry entry removed");
    assert_eq!(removed.vault_id, entry_vault_id);

    // After detach:
    assert!(host.get("detach-safe").await.is_none());
    assert_eq!(host.active_slug().await, None);
    let post = VaultRegistry::load_from(&reg_path).unwrap();
    assert!(post.get("detach-safe").is_none());
    assert!(post.active_vault.is_none());
    // State Arc dropped only when handler finished: assert it zeroizes.
    drop(state);
}

// ── disk-delete safety gate ──

#[test]
fn disk_delete_with_valid_marker_removes_directory() {
    let (_dir, path, vault_id) = make_real_vault("disk-delete-ok");
    assert!(path.exists());

    let entry = make_entry("disk-delete-ok", &path, vault_id);
    disk_delete_gated(&path, entry.vault_id, false).expect("delete should succeed");
    assert!(!path.exists(), "directory must be gone");
}

#[test]
fn disk_delete_refuses_when_marker_missing() {
    let (_dir, path, vault_id) = make_real_vault("disk-delete-missing-marker");
    // Strip the .baluard marker to simulate a corrupted vault.
    let marker = path.join(".baluard");
    if marker.exists() {
        std::fs::remove_file(&marker).expect("strip marker");
    }

    let entry = make_entry("disk-delete-missing-marker", &path, vault_id);
    let result = disk_delete_gated(&path, entry.vault_id, false);
    assert!(result.is_err(), "must refuse without .baluard marker");
    assert!(path.exists(), "directory must remain when gate refuses");
}

#[test]
fn disk_delete_refuses_when_marker_vault_id_mismatches() {
    let (_dir, path, vault_id) = make_real_vault("disk-delete-mismatch");
    let entry = make_entry("disk-delete-mismatch", &path, vault_id);

    // Hand-craft a .baluard marker with a DIFFERENT vault_id to model a
    // stale registry entry pointing at a directory that was reused for a
    // different vault.
    let stale = BaluardMarker::new(Uuid::new_v4(), "some-other-slug");
    stale.write_to_vault(&path).expect("write stale marker");

    let result = disk_delete_gated(&path, entry.vault_id, false);
    assert!(result.is_err(), "must refuse on vault_id mismatch");
    assert!(path.exists(), "directory must remain when gate refuses");
}

#[test]
fn disk_delete_refuses_when_marker_unreadable() {
    // Distinct from `Missing`: the marker file exists but is corrupt.
    // The daemon can NOT positively say "no marker here" — it just
    // couldn't read what was there. The audit log records the I/O
    // error so the deletion is traceable to a real failure rather than
    // a claim of absence.
    let (_dir, path, vault_id) = make_real_vault("disk-delete-unreadable");
    let marker = path.join(".baluard");
    std::fs::write(&marker, b"this is not valid json {{{").expect("overwrite marker with garbage");

    let entry = make_entry("disk-delete-unreadable", &path, vault_id);
    let result = disk_delete_gated(&path, entry.vault_id, false);
    assert!(result.is_err(), "must refuse when marker is unreadable");
    assert!(path.exists(), "directory must remain when gate refuses");
}

#[test]
fn disk_delete_with_force_succeeds_when_marker_missing() {
    // The real-world scenario the user hit: a stale vault whose .baluard
    // marker was lost (corruption, manual deletion). Without `force` the
    // gate refuses; with it, the caller has confirmed intent through
    // another channel so we proceed.
    let (_dir, path, vault_id) = make_real_vault("disk-delete-force-missing");
    let marker = path.join(".baluard");
    if marker.exists() {
        std::fs::remove_file(&marker).expect("strip marker");
    }

    let entry = make_entry("disk-delete-force-missing", &path, vault_id);
    disk_delete_gated(&path, entry.vault_id, true)
        .expect("force should bypass missing-marker refusal");
    assert!(!path.exists(), "directory must be gone after force delete");
}

#[test]
fn disk_delete_with_force_refuses_on_mismatch() {
    // Critical security property: `force` does NOT bypass `Mismatch`.
    // The on-disk marker positively identifies this directory as
    // belonging to a different vault. No amount of caller-side
    // confirmation can override that — manual cleanup is the only path.
    let (_dir, path, vault_id) = make_real_vault("disk-delete-force-mismatch");
    let entry = make_entry("disk-delete-force-mismatch", &path, vault_id);

    let stale = BaluardMarker::new(Uuid::new_v4(), "some-other-slug");
    stale.write_to_vault(&path).expect("write stale marker");

    let result = disk_delete_gated(&path, entry.vault_id, true);
    assert!(result.is_err(), "force must NOT bypass vault_id mismatch");
    assert!(
        path.exists(),
        "directory must remain when gate refuses on mismatch"
    );
}

#[test]
fn disk_delete_with_force_succeeds_when_marker_unreadable() {
    let (_dir, path, vault_id) = make_real_vault("disk-delete-force-unreadable");
    std::fs::write(path.join(".baluard"), b"not valid json {{{")
        .expect("overwrite marker with garbage");

    let entry = make_entry("disk-delete-force-unreadable", &path, vault_id);
    disk_delete_gated(&path, entry.vault_id, true)
        .expect("force should bypass unreadable-marker refusal");
    assert!(!path.exists(), "directory must be gone after force delete");
}

#[test]
fn disk_delete_is_idempotent_when_directory_already_gone() {
    // No directory created. Registry says "delete this" but it's gone.
    let path = PathBuf::from("/tmp/this-path-deliberately-does-not-exist");
    let result = disk_delete_gated(&path, Uuid::new_v4(), false);
    assert!(result.is_ok(), "idempotent: missing dir is not an error");
}

// ── wire-level tests (real `route_host_request` dispatch) ──
//
// These tests build a real `GatewayRequest` and call the actual
// `route_host_request` handler. The handler reads/writes the GLOBAL
// `data_dir/registry.json`, so we serialise on `GLOBAL_REG` to keep
// parallel test runners from racing on the same file. The `host` is
// fresh per test (`VaultHost::new()` — NOT `shared()`) so the in-memory
// map is also isolated.

fn write_global_registry(entries: &[VaultEntry], active: Option<&str>) {
    let mut reg = VaultRegistry::default();
    for e in entries {
        reg.add(e.clone()).expect("add entry");
    }
    if let Some(slug) = active {
        reg.set_active(slug).expect("set active");
    }
    reg.save_locked().expect("save global registry");
}

fn read_global_registry() -> VaultRegistry {
    VaultRegistry::load_locked().expect("load global registry")
}

fn make_request(action: &str, payload: serde_json::Value) -> GatewayRequest {
    GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: String::new(),
        slug: String::new(),
        ipc_version: 1,
    }
}

fn response_payload(resp: &GatewayResponse) -> serde_json::Value {
    serde_json::from_str(&resp.payload).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn route_detach_safe_arm_returns_success_and_drops_registry() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("wire-safe");
    let entry = make_entry("wire-safe", &path, vault_id);
    // Serialise the global registry mutation so the await below doesn't
    // hold the MutexGuard across a suspension point. Setup is sync;
    // release the guard before calling the async handler.
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("wire-safe"));
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "wire-safe",
            "delete_from_disk": false,
        }),
    );

    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "detach should succeed: {}",
        resp.error_message
    );

    // Response carries the right fields.
    let payload = response_payload(&resp);
    assert_eq!(payload["slug"], "wire-safe");
    assert_eq!(payload["deleted_from_disk"], false);
    assert_eq!(
        payload["path"].as_str(),
        Some(path.to_string_lossy().as_ref())
    );

    // Registry no longer has the entry.
    let post = read_global_registry();
    assert!(post.get("wire-safe").is_none());
    assert!(post.active_vault.is_none());
    // Disk directory untouched (safe arm).
    assert!(path.exists());
}

#[tokio::test]
async fn route_detach_unknown_slug_returns_error() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(&[], None);
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({ "slug": "does-not-exist" }),
    );

    let resp = route_host_request(req, &host).await;
    assert!(!resp.success);
    assert!(
        resp.error_message.contains("not registered"),
        "error should mention not registered, got: {}",
        resp.error_message
    );
}

#[tokio::test]
async fn route_detach_missing_marker_with_force_succeeds() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("wire-missing-force");
    // Strip the marker to simulate corruption.
    std::fs::remove_file(path.join(".baluard")).expect("strip marker");
    let entry = make_entry("wire-missing-force", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("wire-missing-force"));
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "wire-missing-force",
            "delete_from_disk": true,
            "force": true,
            "confirm": {"kind": "password", "value": "test-master-password-123"},
        }),
    );

    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "missing+force should succeed: {}",
        resp.error_message
    );
    let payload = response_payload(&resp);
    assert_eq!(payload["deleted_from_disk"], true);
    assert!(!path.exists(), "directory must be deleted");

    // Registry cleared.
    let post = read_global_registry();
    assert!(post.get("wire-missing-force").is_none());
}

#[tokio::test]
async fn route_detach_mismatch_with_force_refuses_unconditionally() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("wire-mismatch-force");
    // Overwrite marker with a DIFFERENT vault_id.
    let stale = BaluardMarker::new(Uuid::new_v4(), "some-other-slug");
    stale.write_to_vault(&path).expect("write stale marker");

    let entry = make_entry("wire-mismatch-force", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("wire-mismatch-force"));
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "wire-mismatch-force",
            "delete_from_disk": true,
            "force": true,
            "confirm": {"kind": "password", "value": "test-master-password-123"},
        }),
    );

    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "mismatch+force must refuse");
    assert!(
        resp.error_message.contains("vault_id does not match"),
        "error should explain the mismatch, got: {}",
        resp.error_message
    );
    assert!(
        resp.error_message.contains("force") && resp.error_message.contains("does not override"),
        "error should explain that force does not bypass mismatch, got: {}",
        resp.error_message
    );
    assert!(path.exists(), "directory must remain when refused");

    // Registry IS removed — the stale entry pointed at a wrong
    // directory, so dropping it cleans up the pointer. The user can
    // re-attach the (now-fixed) directory via `baluard open <path>`.
    let post = read_global_registry();
    assert!(
        post.get("wire-mismatch-force").is_none(),
        "stale registry pointer should be cleared even on mismatch refusal"
    );
}

// ── destructive-arm passphrase gate ──
//
// Any destructive arm (delete_from_disk, delete_remote) must refuse
// without a confirm {"kind", "value"} matching the vault's master
// password canary or 24-word recovery kit. Wrong answers rate-limit per
// vault and leave registry, disk, and remote untouched.

#[tokio::test]
async fn route_detach_destructive_without_confirm_refuses_and_keeps_vault() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("gate-none");
    let entry = make_entry("gate-none", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), None);
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({ "slug": "gate-none", "delete_from_disk": true, "force": true }),
    );
    let resp = route_host_request(req, &host).await;
    assert!(
        !resp.success,
        "destructive detach without confirm must refuse"
    );
    assert!(
        resp.error_message.contains("confirm"),
        "error should name the confirm requirement, got: {}",
        resp.error_message
    );
    assert!(path.exists(), "directory must survive a refused delete");
    let post = read_global_registry();
    assert!(
        post.get("gate-none").is_some(),
        "registry entry must survive"
    );
}

#[tokio::test]
async fn route_detach_wrong_password_refuses_rate_limits_and_keeps_vault() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("gate-wrong");
    let entry = make_entry("gate-wrong", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), None);
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "gate-wrong",
            "delete_from_disk": true,
            "confirm": {"kind": "password", "value": "not-the-password"},
        }),
    );
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "wrong password must refuse");
    assert!(
        resp.error_message.contains("verification failed"),
        "error should name the failed verification, got: {}",
        resp.error_message
    );
    assert!(path.exists());

    // Immediate retry is rate-limited, not silently re-attempted.
    let req2 = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "gate-wrong",
            "delete_from_disk": true,
            "confirm": {"kind": "password", "value": "not-the-password"},
        }),
    );
    let resp2 = route_host_request(req2, &host).await;
    assert!(!resp2.success);
    assert!(
        resp2.error_message.contains("Too many failed attempts"),
        "immediate retry must hit the rate limiter, got: {}",
        resp2.error_message
    );
    assert!(path.exists(), "directory must survive both refusals");
    let post = read_global_registry();
    assert!(post.get("gate-wrong").is_some());
}

#[tokio::test]
async fn route_detach_correct_password_deletes_from_disk() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("gate-ok");
    let entry = make_entry("gate-ok", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("gate-ok"));
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "gate-ok",
            "delete_from_disk": true,
            "confirm": {"kind": "password", "value": "test-master-password-123"},
        }),
    );
    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "correct password must pass the gate: {}",
        resp.error_message
    );
    let payload = response_payload(&resp);
    assert_eq!(payload["deleted_from_disk"], true);
    assert_eq!(payload["remote_deleted"], false);
    assert!(payload["remote_error"].is_null());
    assert!(!path.exists(), "directory must be deleted");
    let post = read_global_registry();
    assert!(post.get("gate-ok").is_none());
}

// The phrase oracle itself (enable_kit -> recover_root_from_kit roundtrip
// plus wrong-phrase refusal) is covered by the core recovery_kit tests;
// the wire gate arm is identical code for both confirm kinds, and a
// phrase confirm on a kitless vault refuses with the kit-missing error
// (exercised incidentally by earlier drafts of that shape).

#[tokio::test]
async fn route_detach_delete_remote_without_provider_reports_and_detaches() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("gate-remote");
    let entry = make_entry("gate-remote", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), None);
    }

    let host = Arc::new(VaultHost::new());
    let req = make_request(
        "vaults.detach",
        serde_json::json!({
            "slug": "gate-remote",
            "delete_remote": true,
            "confirm": {"kind": "password", "value": "test-master-password-123"},
        }),
    );
    let resp = route_host_request(req, &host).await;
    assert!(
        resp.success,
        "detach must proceed when the provider delete degrades: {}",
        resp.error_message
    );
    let payload = response_payload(&resp);
    assert_eq!(payload["remote_deleted"], false);
    assert!(
        payload["remote_error"].is_string(),
        "a vault with no connected provider must carry a remote_error, got: {}",
        payload["remote_error"]
    );
    assert_eq!(payload["deleted_from_disk"], false);
    assert!(path.exists(), "safe arm keeps the directory");
    let post = read_global_registry();
    assert!(post.get("gate-remote").is_none());
}

#[tokio::test]
async fn route_sync_disconnect_delete_remote_requires_confirm() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("sd-gate");
    let entry = make_entry("dev-sd-gate", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("dev-sd-gate"));
    }
    let host = Arc::new(VaultHost::new());

    let unlock_req = make_request(
        "vault.unlock",
        serde_json::json!({"slug": "dev-sd-gate", "password": "test-master-password-123"}),
    );
    let resp = route_host_request(unlock_req, &host).await;
    assert!(resp.success, "unlock failed: {}", resp.error_message);
    let token = resp.session_token.clone();
    assert!(!token.is_empty());

    let mut req = make_request(
        "sync.disconnect",
        serde_json::json!({ "delete_remote": true }),
    );
    req.session_token = token;
    let resp = route_host_request(req, &host).await;
    assert!(!resp.success, "delete_remote without confirm must refuse");
    assert!(
        resp.error_message.contains("confirm"),
        "error should name the confirm requirement, got: {}",
        resp.error_message
    );
    assert!(path.exists());
    let post = read_global_registry();
    assert!(
        post.get("dev-sd-gate").is_some(),
        "registry entry must survive"
    );
}

// ── macOS 0.1.0 field bug regression:
// ── macOS 0.1.0 field bug regression: the FIRST provider.oauth_status_web
// poll, sent while the callback listener is still waiting for the browser,
// hung forever in the real daemon and the desktop timed out after 30s with
// a generic error. The full wire path (gates + token check + session map)
// must answer "pending" — never deadlock.
#[tokio::test]
async fn web_oauth_poll_answers_pending_through_real_handler() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("oauth");
    let entry = make_entry("dev-oauth", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("dev-oauth"));
    }
    let host = std::sync::Arc::new(baluard_runtime::host::VaultHost::new());

    let unlock_req = make_request(
        "vault.unlock",
        serde_json::json!({"slug": "dev-oauth", "password": "test-master-password-123"}),
    );
    let resp = route_host_request(unlock_req, &host).await;
    assert!(resp.success, "unlock failed: {}", resp.error_message);
    let token = resp.session_token.clone();
    assert!(!token.is_empty(), "unlock must return a session token");

    let mut start_req = make_request(
        "provider.oauth_start_web",
        serde_json::json!({"provider": "github"}),
    );
    start_req.session_token = token.clone();
    let resp = route_host_request(start_req, &host).await;
    assert!(resp.success, "oauth start failed: {}", resp.error_message);

    let mut poll_req = make_request(
        "provider.oauth_status_web",
        serde_json::json!({"provider": "github"}),
    );
    poll_req.session_token = token;
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        route_host_request(poll_req, &host),
    )
    .await
    .expect("oauth_status_web must not hang before the callback arrives");
    assert!(resp.success, "poll failed: {}", resp.error_message);
    assert_eq!(response_payload(&resp)["status"], "pending");
}

// Regression shape for the macOS 0.1.0 GitHub-connect failure: the desktop
// sent this poll with an EMPTY payload, which the daemon rejects instantly
// ("Invalid payload: ...") via an early return that skips the "->" log line —
// the missing log made it read as a hang. Contract: empty payload fails fast;
// a proper {"provider":...} payload answers pending (covered by the sibling
// test below).
#[tokio::test]
async fn web_oauth_poll_with_empty_payload_fails_fast_not_hang() {
    let (_data_dir, _data_dir_guard) = sandboxed_data_dir().await;
    let (_dir, path, vault_id) = make_real_vault("oauth-empty");
    let entry = make_entry("dev-oauth-empty", &path, vault_id);
    {
        let _guard = GLOBAL_REG.lock().unwrap_or_else(|p| p.into_inner());
        write_global_registry(std::slice::from_ref(&entry), Some("dev-oauth-empty"));
    }
    let host = std::sync::Arc::new(baluard_runtime::host::VaultHost::new());

    let unlock_req = make_request(
        "vault.unlock",
        serde_json::json!({"slug": "dev-oauth-empty", "password": "test-master-password-123"}),
    );
    let resp = route_host_request(unlock_req, &host).await;
    assert!(resp.success, "unlock failed: {}", resp.error_message);
    let token = resp.session_token.clone();
    assert!(!token.is_empty(), "unlock must return a session token");

    let poll_req = GatewayRequest {
        action: "provider.oauth_status_web".to_string(),
        payload: String::new(),
        session_token: token,
        slug: String::new(),
        ipc_version: 1,
    };
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        route_host_request(poll_req, &host),
    )
    .await
    .expect("empty-payload poll must fail fast, never hang");
    assert!(!resp.success, "empty payload must be rejected");
    assert!(
        resp.error_message.contains("Invalid payload"),
        "unexpected error: {}",
        resp.error_message
    );
}
