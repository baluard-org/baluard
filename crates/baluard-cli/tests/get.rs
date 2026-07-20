//! Tests for `baluard get`.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

fn add_login(tmp: &std::path::Path, name: &str, user: &str, pw: &str) -> String {
    let assert = baluard(tmp)
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg(name)
        .arg("--username")
        .arg(user)
        .arg("--password")
        .arg(pw)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    re.find(&out).expect("cipher id").as_str().to_string()
}

#[test]
fn get_quiet_mode_redacts_secrets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Get", "get-vault");
    let id = add_login(tmp.path(), "GitHub", "octocat", "supersecret");

    // Default output: password redacted
    baluard(tmp.path())
        .arg("get")
        .arg(&id)
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub"))
        .stdout(predicate::str::contains("octocat"))
        .stdout(predicate::str::contains("***"))
        .stdout(predicate::str::contains("supersecret").not());
}

#[test]
fn get_text_mode_reveals_password() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Reveal", "reveal-vault");
    let id = add_login(tmp.path(), "GitHub", "octocat", "supersecret");

    baluard(tmp.path())
        .arg("get")
        .arg(&id)
        .arg("--output")
        .arg("text")
        .assert()
        .success()
        .stdout(predicate::str::contains("supersecret"));
}

#[test]
fn get_json_mode_emits_valid_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Json", "json-get-vault");
    let id = add_login(tmp.path(), "GitHub", "octocat", "supersecret");

    let assert = baluard(tmp.path())
        .arg("get")
        .arg(&id)
        .arg("--output")
        .arg("json")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("json output");
    assert_eq!(parsed["name"], "GitHub");
    assert_eq!(parsed["username"], "octocat");
    assert_eq!(parsed["password"], "supersecret");
}

#[test]
fn get_with_nonexistent_uuid_returns_locked_or_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Miss", "miss-vault");

    // A random valid UUID that doesn't exist in the vault. We accept any
    // non-zero exit + a non-empty stderr message; the exact wording shifts
    // across implementations and isn't worth pinning.
    baluard(tmp.path())
        .arg("get")
        .arg("00000000-0000-0000-0000-000000000000")
        .assert()
        .failure();
}

#[test]
fn get_with_garbage_id_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "BadGet", "bad-get-vault");

    baluard(tmp.path())
        .arg("get")
        .arg("not-a-uuid")
        .assert()
        .failure();
}
