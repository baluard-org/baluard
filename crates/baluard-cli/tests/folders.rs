//! Tests for `baluard folders ...` subcommands.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

#[test]
fn folder_create_returns_uuid_and_appears_in_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Folders", "folders-vault");

    let assert = baluard(tmp.path())
        .arg("folders")
        .arg("create")
        .arg("Work")
        .assert()
        .success()
        .stdout(predicate::str::contains("Folder created:"));
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    let id = re.find(&out).expect("folder id").as_str().to_string();

    baluard(tmp.path())
        .arg("folders")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Work"))
        .stdout(predicate::str::contains(&id));
}

#[test]
fn folder_list_empty_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "EmptyFolders", "empty-folders-vault");

    baluard(tmp.path())
        .arg("folders")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No folders."));
}

#[test]
fn folder_rename_changes_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Rename", "rename-folder-vault");

    let assert = baluard(tmp.path())
        .arg("folders")
        .arg("create")
        .arg("old")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    let id = re.find(&out).expect("folder id").as_str().to_string();

    baluard(tmp.path())
        .arg("folders")
        .arg("rename")
        .arg(&id)
        .arg("new")
        .assert()
        .success()
        .stdout(predicate::str::contains("Folder renamed."));

    baluard(tmp.path())
        .arg("folders")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("new"))
        .stdout(predicate::str::contains("old").not());
}

#[test]
fn folder_rename_rejects_invalid_uuid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "BadRename", "bad-rename-folder-vault");

    baluard(tmp.path())
        .arg("folders")
        .arg("rename")
        .arg("not-a-uuid")
        .arg("newname")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid folder UUID"));
}

#[test]
fn folder_delete_removes_folder() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "DelFolder", "del-folder-vault");

    let assert = baluard(tmp.path())
        .arg("folders")
        .arg("create")
        .arg("Doomed")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    let id = re.find(&out).expect("folder id").as_str().to_string();

    baluard(tmp.path())
        .arg("folders")
        .arg("delete")
        .arg(&id)
        .assert()
        .success();

    baluard(tmp.path())
        .arg("folders")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Doomed").not());
}
