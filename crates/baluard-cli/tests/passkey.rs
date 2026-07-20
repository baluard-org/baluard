//! Tests for `baluard passkey ...` subcommands.
//!
//! `list`, `delete`, `rename` operate on passkey data embedded inside a
//! Login cipher's `fido2_credentials` field. We construct a Login with a
//! hand-rolled PasskeyData via the `add json` subcommand (the only path
//! that accepts arbitrary cipher shapes from the CLI surface).

mod common;

use std::fs;

use predicates::prelude::*;

use common::{baluard, init_vault};

/// Build a CipherInput JSON file with a Login containing a single passkey,
/// then run `baluard add json` to import it. Returns (cipher_uuid, credential_id).
fn add_login_with_passkey(
    tmp: &std::path::Path,
    login_name: &str,
    rp_id: &str,
    pk_name: &str,
    credential_id: &str,
) -> String {
    let json = serde_json::json!({
        "name": login_name,
        "kind": {
            "type": "login",
            "data": {
                "username": "u@example.com",
                "password": "p",
                "uris": [],
                "totp_uri": null,
                "autofill_on_page_load": false,
                "password_revision_date": null,
                "favicon": null,
                "fido2_credentials": [{
                    "credential_id": credential_id,
                    "key_type": "public-key",
                    "key_algorithm": "ECDSA_SHA256",
                    "key_curve": "P256",
                    "key_value": "AAAA",
                    "rp_id": rp_id,
                    "rp_name": "Acme",
                    // user_handle is Vec<u8> in the core type. Serialize as a
                    // JSON array of bytes (ascii for "handle") so the default
                    // Vec<u8> deserializer accepts it without needing the
                    // serde_bytes feature on the CLI dependency tree.
                    "user_handle": vec![104u8, 97, 110, 100, 108, 101],
                    "user_name": "u@example.com",
                    "user_display_name": "U",
                    "counter": 0u32,
                    "aaguid": "00000000-0000-0000-0000-000000000000",
                    "prf_key": null,
                    "private_key": null,
                    "private_key_missing": true,
                    "creation_date": 1735689600u64,
                    "name": pk_name,
                }]
            }
        },
        "folder_id": null,
        "favorite": false,
        "notes": null,
        "custom_fields": [],
        "created_at": null,
        "password_history": [],
        "attachments": [],
        "archived": false,
        "reprompt": false,
        "tags": []
    });
    let json_path = tmp.join("cipher.json");
    fs::write(&json_path, serde_json::to_string_pretty(&json).unwrap()).expect("write json");

    let assert = baluard(tmp)
        .arg("add")
        .arg("json")
        .arg(json_path.to_string_lossy().to_string())
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    re.find(&out).expect("cipher id").as_str().to_string()
}

#[test]
fn passkey_list_shows_added_passkey() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Passkeys", "passkey-vault");
    add_login_with_passkey(tmp.path(), "GitHub", "github.com", "YubiKey", "cred-abc");

    // The CLI's passkey list emits one row per passkey with: login name,
    // rp_id, rp_name, user_name, credential_id. The per-credential display
    // name is NOT exposed by `baluard passkey list` (see handle_passkey_list).
    baluard(tmp.path())
        .arg("passkey")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("github.com"))
        .stdout(predicate::str::contains("GitHub"))
        .stdout(predicate::str::contains("u@example.com"))
        .stdout(predicate::str::contains("cred-abc"));
}

#[test]
fn passkey_list_filters_by_rp_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Filter", "passkey-filter-vault");
    add_login_with_passkey(tmp.path(), "GitHub", "github.com", "yk1", "cred-1");
    add_login_with_passkey(tmp.path(), "GitLab", "gitlab.com", "yk2", "cred-2");

    baluard(tmp.path())
        .arg("passkey")
        .arg("list")
        .arg("--rp-id")
        .arg("github.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("github.com"))
        .stdout(predicate::str::contains("gitlab.com").not());
}

#[test]
fn passkey_rename_updates_display_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Rename", "passkey-rename-vault");
    let cipher_id = add_login_with_passkey(tmp.path(), "Site", "example.com", "old name", "cred-x");

    baluard(tmp.path())
        .arg("passkey")
        .arg("rename")
        .arg(&cipher_id)
        .arg("--credential-id")
        .arg("cred-x")
        .arg("new name")
        .assert()
        .success()
        .stdout(predicate::str::contains("Passkey renamed."));

    // The CLI passkey list doesn't expose the per-credential name (only
    // the login name + rp info), so we confirm the rename succeeded via
    // the success message + re-issuing the same rename is idempotent.
    baluard(tmp.path())
        .arg("passkey")
        .arg("rename")
        .arg(&cipher_id)
        .arg("--credential-id")
        .arg("cred-x")
        .arg("new name")
        .assert()
        .success();
}

#[test]
fn passkey_rename_unknown_credential_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "MissPk", "miss-pk-vault");
    let cipher_id = add_login_with_passkey(tmp.path(), "Site", "example.com", "x", "cred-exists");

    baluard(tmp.path())
        .arg("passkey")
        .arg("rename")
        .arg(&cipher_id)
        .arg("--credential-id")
        .arg("cred-does-not-exist")
        .arg("newname")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Credential not found"));
}

#[test]
fn passkey_delete_removes_credential() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "DelPk", "del-pk-vault");
    let cipher_id =
        add_login_with_passkey(tmp.path(), "Site", "example.com", "yk", "cred-to-delete");

    baluard(tmp.path())
        .arg("passkey")
        .arg("delete")
        .arg(&cipher_id)
        .arg("--credential-id")
        .arg("cred-to-delete")
        .assert()
        .success()
        .stdout(predicate::str::contains("Passkey deleted."));

    baluard(tmp.path())
        .arg("passkey")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("cred-to-delete").not());
}
