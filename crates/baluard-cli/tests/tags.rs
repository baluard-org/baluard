//! Tests for `baluard tags ...` subcommands.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

#[test]
fn tag_create_then_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Tags", "tags-vault");

    baluard(tmp.path())
        .arg("tags")
        .arg("create")
        .arg("important")
        .assert()
        .success()
        .stdout(predicate::str::contains("Tag 'important' created."));

    baluard(tmp.path())
        .arg("tags")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("important"));
}

#[test]
fn tag_list_empty_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "EmptyTags", "empty-tags-vault");

    baluard(tmp.path())
        .arg("tags")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No tags found."));
}

#[test]
fn tag_rename_updates_all_ciphers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "RenameTag", "rename-tag-vault");

    baluard(tmp.path())
        .arg("tags")
        .arg("create")
        .arg("old")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("Tagged")
        .arg("--username")
        .arg("u")
        .arg("--tags")
        .arg("old")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("tags")
        .arg("rename")
        .arg("old")
        .arg("new")
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed to 'new'"))
        .stdout(predicate::str::contains("1 entries updated"));

    baluard(tmp.path())
        .arg("tags")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("new"))
        .stdout(predicate::str::contains("old").not());
}

#[test]
fn tag_delete_removes_from_all_ciphers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "DelTag", "del-tag-vault");

    baluard(tmp.path())
        .arg("tags")
        .arg("create")
        .arg("doomed")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("Tagged")
        .arg("--username")
        .arg("u")
        .arg("--tags")
        .arg("doomed")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("tags")
        .arg("delete")
        .arg("doomed")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed from 1 entries"));

    baluard(tmp.path())
        .arg("tags")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("doomed").not());
}
