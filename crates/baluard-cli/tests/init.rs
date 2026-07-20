//! Tests for `baluard init`.

mod common;

use std::fs;

use predicates::prelude::*;

use common::{TEST_PASSWORD, assert_vault_initialized, baluard, init_vault};

#[test]
fn init_creates_vault_with_files_on_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_path = tmp.path();

    init_vault(vault_path, "Test Vault", "test-vault");

    assert_vault_initialized(vault_path);
}

#[test]
fn init_writes_recovery_phrase_and_trust_fingerprint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_path = tmp.path();

    baluard(vault_path)
        .arg("init")
        .arg("--name")
        .arg("Alice")
        .arg("--slug")
        .arg("alice-vault")
        .assert()
        .success()
        .stdout(predicate::str::contains("RECOVERY PHRASE"))
        .stdout(predicate::str::contains("Trust fingerprint:"))
        .stdout(predicate::str::contains("Vault created successfully."));
}

#[test]
fn init_rejects_short_password() {
    // Bypass the helper because it forces TEST_PASSWORD; we need to feed a
    // 7-char password to exercise the length guard.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", "short77"); // 7 chars, under the 8-char floor
    cmd.arg("init")
        .arg("--name")
        .arg("X")
        .arg("--slug")
        .arg("x-vault")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "password must be at least 8 characters",
        ));
}

#[test]
fn init_rejects_duplicate_slug_in_registry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "First", "dup-slug");

    // Second init with the same slug must fail. The CLI's pre-flight registry
    // check fires before any disk write, so this also covers the
    // "don't overwrite an existing vault" guarantee.
    baluard(tmp.path())
        .arg("init")
        .arg("--name")
        .arg("Second")
        .arg("--slug")
        .arg("dup-slug")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_rejects_garbage_profile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("init")
        .arg("--profile")
        .arg("not-a-real-profile")
        .arg("--name")
        .arg("X")
        .arg("--slug")
        .arg("garbage-profile-vault")
        .assert()
        .failure();
}

#[test]
fn init_help_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("init")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Create a new vault"));
}

#[test]
fn init_default_profile_writes_full_keywrap_and_canary() {
    // Smoke test that the default profile path (desktop-std) finishes the full
    // init including keywrap + canary files. The common helper sandboxes the
    // global registry under BALUARD_DATA_DIR so this stays isolated from the
    // user's real registry.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Default Profile", "default-profile-vault");
    assert_vault_initialized(tmp.path());
    // meta/ should hold keywrap + at least one canary file
    let meta = tmp.path().join("meta");
    assert!(meta.is_dir(), "meta/ missing under {}", meta.display());
    let entries: Vec<_> = fs::read_dir(&meta)
        .expect("read meta")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.len() >= 2,
        "expected >= 2 meta files (keywrap + canary), found {}: {:?}",
        entries.len(),
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

#[test]
fn init_scripting_mode_does_not_require_tty() {
    // Confirms the BALUARD_PASSWORD branch (which short-circuits recovery
    // phrase verification) actually exercises end-to-end: env var is set, no
    // TTY is attached, init still succeeds. The other init tests already
    // use BALUARD_PASSWORD; this one exists to keep that contract visible.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD);
    cmd.arg("init")
        .arg("--name")
        .arg("Scripting")
        .arg("--slug")
        .arg("scripting-vault")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "verification skipped in scripting mode",
        ));
}
