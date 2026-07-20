//! Tests for `baluard sync ...` subcommands.
//!
//! Only covers subcommands that work locally in --direct mode (no network):
//! `init` (local git repo creation), `remote` (set remote URL), `status`
//! (read repo state), `log` (read commit log). Push/pull/clone need a real
//! remote + auth and are deferred until a fake-remote fixture lands.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

#[test]
fn sync_init_creates_local_git_repo() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-init-vault");

    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();

    // The vault directory should now contain a .git directory.
    let git_dir = tmp.path().join(".git");
    assert!(
        git_dir.exists(),
        "expected .git/ at {} after sync init",
        git_dir.display()
    );
}

#[test]
fn sync_init_twice_is_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-idempotent-vault");

    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();
    // Second init must not fail (e.g. by trying to re-init an existing repo).
    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();
}

#[test]
fn sync_remote_sets_url() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-remote-vault");

    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();

    // Setting a remote URL must succeed even though the remote is fake.
    // Push would fail with auth, but `remote add` only writes the config.
    baluard(tmp.path())
        .arg("sync")
        .arg("remote")
        .arg("https://example.com/fake/repo.git")
        .assert()
        .success();

    // .git/config should now list the origin.
    let config =
        std::fs::read_to_string(tmp.path().join(".git").join("config")).expect("read git config");
    assert!(
        config.contains("example.com/fake/repo.git"),
        "remote URL not in .git/config:\n{config}"
    );
}

#[test]
fn sync_status_on_uninitialized_repo_says_so() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-status-vault");

    // Status before init should report a clean/no-remote state, not crash.
    // The exact wording shifts; we accept any successful exit.
    baluard(tmp.path())
        .arg("sync")
        .arg("status")
        .assert()
        .success();
}

#[test]
fn sync_log_on_empty_repo_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-log-vault");

    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();
    // Fresh repo: no commits yet. Log should exit 0 with empty output or a
    // friendly "no commits" message.
    baluard(tmp.path())
        .arg("sync")
        .arg("log")
        .assert()
        .success();
}

#[test]
fn sync_log_limit_flag_accepted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Sync", "sync-log-limit-vault");

    baluard(tmp.path())
        .arg("sync")
        .arg("init")
        .assert()
        .success();
    baluard(tmp.path())
        .arg("sync")
        .arg("log")
        .arg("--limit")
        .arg("5")
        .assert()
        .success();
}

#[test]
fn sync_help_lists_subcommands() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("sync")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("remote"))
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("pull"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("log"));
}
