//! Tests for `baluard unlock`.

mod common;

use predicates::prelude::*;

use common::{TEST_PASSWORD, baluard, init_vault};

#[test]
fn unlock_succeeds_after_init() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Alice", "alice-vault");

    baluard(tmp.path())
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked (direct)"))
        .stdout(predicate::str::contains("Vault ID:"));
}

#[test]
fn unlock_works_on_repeated_invocations() {
    // Each CLI invocation is a fresh process — direct-mode state does not
    // persist between calls, so the in-process "already unlocked" short
    // circuit (VaultHandle::is_unlocked) cannot be exercised across
    // subprocesses. This test pins the contract that callers CAN invoke
    // `baluard unlock` as many times as they want without side effects.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Bob", "bob-vault");

    baluard(tmp.path()).arg("unlock").assert().success();
    baluard(tmp.path())
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked (direct)"));
}

#[test]
fn unlock_fails_with_wrong_password() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Carol", "carol-vault");

    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", "definitely-wrong-password");
    cmd.arg("unlock")
        .assert()
        .failure()
        // baluard-core surfaces a BaluardError::InvalidPassword / keywrap-fail;
        // the CLI message must contain a recognizable "password" or "keywrap"
        // hint. Looser predicate so we don't break if wording shifts.
        .stderr(predicate::str::contains("password").or(predicate::str::contains("keywrap")));
}

#[test]
fn unlock_without_init_fails() {
    // No init_vault() call — directory exists but is not a vault.
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path()).arg("unlock").assert().failure();
}

#[test]
fn unlock_reads_balguard_password_env_var() {
    // Locks in the BALUARD_PASSWORD scriptable-unlock contract. If a future
    // refactor drops the env-var branch in `unlock_direct`, this test catches
    // it before shipping.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Dave", "dave-vault");

    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD);
    cmd.arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked (direct)"));
}
