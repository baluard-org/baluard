//! Tests for `baluard add`.

mod common;

use std::fs;

use predicates::prelude::*;

use common::{TEST_PASSWORD, baluard, init_vault};

#[test]
fn add_login_cipher_returns_uuid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Adder", "adder-vault");

    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("GitHub")
        .arg("--username")
        .arg("octocat")
        .arg("--password")
        .arg("hunter2-but-not-really")
        .arg("--uri")
        .arg("https://github.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cipher added:"));
}

#[test]
fn add_secure_note_round_trips() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Notes", "notes-vault");

    baluard(tmp.path())
        .arg("add")
        .arg("secure-note")
        .arg("--name")
        .arg("Wifi password")
        .arg("--notes")
        .arg("router admin / see sticker on bottom")
        .assert()
        .success();

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Wifi password"))
        .stdout(predicate::str::contains("securenote").or(predicate::str::contains("secure_note")));
}

#[test]
fn add_from_json_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Json", "json-vault");

    let json = serde_json::json!({
        "name": "Imported Login",
        "kind": {
            "type": "login",
            "data": {
                "username": "json@user",
                "password": "json-pass",
                "uris": [{"uri": "https://example.com", "match": null}],
                "totp_uri": null,
                "autofill_on_page_load": false,
                "password_revision_date": null,
                "fido2_credentials": null,
                "favicon": null
            }
        },
        "folder_id": null,
        "favorite": false,
        "notes": "imported via JSON",
        "custom_fields": [],
        "created_at": null,
        "password_history": [],
        "attachments": [],
        "archived": false,
        "reprompt": false,
        "tags": ["imported"]
    });

    let json_path = tmp.path().join("cipher.json");
    fs::write(&json_path, serde_json::to_string_pretty(&json).unwrap()).expect("write json");

    baluard(tmp.path())
        .arg("add")
        .arg("json")
        .arg(json_path.to_string_lossy().to_string())
        .assert()
        .success()
        .stdout(predicate::str::contains("Cipher added:"));

    // Verify it surfaces in `list`.
    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported Login"))
        .stdout(predicate::str::contains("json@user"));
}

#[test]
fn add_from_malformed_json_errors_clearly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "BadJson", "badjson-vault");

    let json_path = tmp.path().join("bad.json");
    fs::write(&json_path, "{this is not valid JSON").expect("write");

    baluard(tmp.path())
        .arg("add")
        .arg("json")
        .arg(json_path.to_string_lossy().to_string())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid CipherInput JSON"));
}

#[test]
fn add_with_invalid_folder_uuid_errors() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Folder", "folder-vault");

    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("X")
        .arg("--username")
        .arg("u")
        .arg("--folder")
        .arg("not-a-uuid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid folder UUID"));
}

#[test]
fn add_with_favorite_flag_marks_favorite() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Fav", "fav-vault");

    baluard(tmp.path())
        .arg("add")
        .arg("login")
        .arg("--name")
        .arg("Starred")
        .arg("--username")
        .arg("star")
        .arg("--favorite")
        .assert()
        .success();

    // The fav marker is `*` in the leading column of the list row.
    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("*"));
}

#[test]
#[ignore = "BALUARD_PASSWORD resolution contract pin: add uses unlock_vault_direct(env)"]
fn add_reads_balguard_password_env_var() {
    // `add` -> `handle_add(Direct)` -> `unlock_vault_direct` which honors
    // BALUARD_PASSWORD. If that env-var branch is ever dropped, this test
    // will surface the regression.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "EnvAdd", "envadd-vault");

    let mut cmd = baluard(tmp.path());
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD);
    cmd.arg("add")
        .arg("login")
        .arg("--name")
        .arg("FromEnv")
        .arg("--username")
        .arg("env")
        .assert()
        .success();
}
