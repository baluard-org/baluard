//! Tests for `baluard delete`.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

fn add_login(tmp: &std::path::Path, name: &str) -> String {
    let assert = baluard(tmp)
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg(name)
        .arg("--username")
        .arg("u")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    re.find(&out).expect("cipher id").as_str().to_string()
}

#[test]
fn delete_removes_cipher_from_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Del", "del-vault");
    let id = add_login(tmp.path(), "Doomed");

    baluard(tmp.path())
        .arg("delete")
        .arg(&id)
        .assert()
        .success()
        .stdout(predicate::str::contains("Cipher deleted"));

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No ciphers found."));
}

#[test]
fn delete_with_invalid_uuid_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "BadDel", "bad-del-vault");

    baluard(tmp.path())
        .arg("delete")
        .arg("not-a-uuid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid UUID"));
}

#[test]
fn delete_nonexistent_uuid_fails_gracefully() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "MissDel", "miss-del-vault");

    baluard(tmp.path())
        .arg("delete")
        .arg("00000000-0000-0000-0000-000000000000")
        .assert()
        .failure();
}
