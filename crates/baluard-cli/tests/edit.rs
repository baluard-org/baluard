//! Tests for `baluard edit`.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

fn add_login(tmp: &std::path::Path, name: &str, username: &str) -> String {
    let assert = baluard(tmp)
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg(name)
        .arg("--username")
        .arg(username)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    re.find(&out).expect("cipher id").as_str().to_string()
}

#[test]
fn edit_renames_cipher() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Edit", "edit-vault");
    let id = add_login(tmp.path(), "old name", "u@example.com");

    baluard(tmp.path())
        .arg("edit")
        .arg(&id)
        .arg("--name")
        .arg("new name")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cipher updated."));

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("new name"))
        .stdout(predicate::str::contains("old name").not());
}

#[test]
fn edit_marks_cipher_favorite() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Fav", "fav-vault");
    let id = add_login(tmp.path(), "Site", "u");

    baluard(tmp.path())
        .arg("edit")
        .arg(&id)
        .arg("--favorite")
        .arg("true")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("*"));
}

#[test]
fn edit_assigns_tags() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Tags", "tags-vault");
    let id = add_login(tmp.path(), "Site", "u");

    baluard(tmp.path())
        .arg("edit")
        .arg(&id)
        .arg("--tags")
        .arg("work,important")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cipher updated."));

    // Cross-check via `tags delete` which reports how many ciphers it
    // updated — if the edit worked, deleting one tag removes exactly 1.
    baluard(tmp.path())
        .arg("tags")
        .arg("delete")
        .arg("work")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed from 1 entries"));
}

#[test]
fn edit_with_no_changes_warns() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Noop", "noop-vault");
    let id = add_login(tmp.path(), "X", "y");

    baluard(tmp.path())
        .arg("edit")
        .arg(&id)
        .assert()
        .success()
        .stderr(predicate::str::contains("Nothing to edit"));
}

#[test]
fn edit_rejects_invalid_uuid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Bad", "bad-vault");

    baluard(tmp.path())
        .arg("edit")
        .arg("not-a-uuid")
        .arg("--name")
        .arg("X")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid UUID"));
}

#[test]
fn edit_rejects_invalid_folder_uuid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "BadFolder", "bad-folder-vault");
    let id = add_login(tmp.path(), "X", "y");

    baluard(tmp.path())
        .arg("edit")
        .arg(&id)
        .arg("--folder")
        .arg("not-a-uuid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid folder UUID"));
}
