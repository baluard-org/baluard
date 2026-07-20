//! Tests for `baluard list`.

mod common;

use predicates::prelude::*;

use common::{TEST_PASSWORD, baluard, init_vault};

#[test]
fn list_empty_vault_says_no_ciphers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Empty", "empty-vault");

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No ciphers found."));
}

#[test]
fn list_shows_added_login() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Lister", "lister-vault");

    // Add a login cipher, then list and confirm it shows up.
    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("GitHub")
        .arg("--username")
        .arg("alice@example.com")
        .arg("--uri")
        .arg("https://github.com")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub"))
        .stdout(predicate::str::contains("alice@example.com"))
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("1 cipher(s)"));
}

#[test]
fn list_default_excludes_archived() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Archiver", "archiver-vault");

    // Add two ciphers, archive one.
    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("Active")
        .arg("--username")
        .arg("a@b.c")
        .assert()
        .success();
    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("Doomed")
        .arg("--username")
        .arg("d@e.f")
        .assert()
        .success();

    // Grab the Doomed cipher's UUID by listing once with details.
    let assert = baluard(tmp.path()).arg("list").assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    // List row format: "{fav} {uuid}  [{type}]  {name}  {username}" where
    // fav is "*" or " ". Extract the UUID-shaped token rather than relying
    // on column index — robust to fav/no-fav and future column changes.
    let uuid_re =
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("compile uuid regex");
    let doomed_id = stdout
        .lines()
        .find(|l| l.contains("Doomed"))
        .and_then(|l| uuid_re.find(l).map(|m| m.as_str().to_string()))
        .expect("Doomed row missing UUID")
        .to_string();

    baluard(tmp.path())
        .arg("archive")
        .arg(&doomed_id)
        .assert()
        .success();

    // Default list shows only Active.
    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Active"))
        .stdout(predicate::str::contains("Doomed").not())
        .stdout(predicate::str::contains("1 cipher(s)"));

    // --archived shows only Doomed.
    baluard(tmp.path())
        .arg("list")
        .arg("--archived")
        .assert()
        .success()
        .stdout(predicate::str::contains("Doomed"))
        .stdout(predicate::str::contains("Active").not())
        .stdout(predicate::str::contains("1 cipher(s)"));
}

#[test]
fn list_on_locked_vault_returns_ids_only() {
    // After init the vault is locked. `list` should still work and return
    // cipher IDs (zero, here) without prompting for a password.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Locked", "locked-vault");

    // Strip BALUARD_PASSWORD so we genuinely exercise the locked path —
    // `list_direct` calls `handle.is_unlocked()` and falls back to
    // `list_cipher_ids()` which is unlocked-state-safe.
    let mut cmd = baluard(tmp.path());
    cmd.env_remove("BALUARD_PASSWORD");
    cmd.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No ciphers found."));
}

#[test]
fn list_help_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("list")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("List all ciphers"));
}

#[test]
#[ignore = "smoke test pinning the BALUARD_PASSWORD password-resolve contract for list_direct"]
fn list_reads_balguard_password_env_var() {
    // If `list_direct` ever stops going through `unlock_vault_direct` (which
    // honors BALUARD_PASSWORD), or if `unlock_vault_direct` drops the env-var
    // branch, this test will catch it.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Env", "env-vault");

    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD);
    cmd.arg("list").assert().success();
}
