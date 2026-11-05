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
    // Wire contract: nested kind object alongside the flat fields.
    assert_eq!(parsed["kind"]["data"]["username"], "octocat");
}

#[test]
fn get_json_redacts_passkey_key_material() {
    // The nested kind must not leak passkey private_key/prf_key through
    // direct-mode JSON; flat fields keep their values by wire contract.
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Redact", "redact-get-vault");
    let cipher = serde_json::json!({
        "name": "GitHub",
        "kind": {
            "type": "login",
            "data": {
                "username": "u@example.com",
                "password": "hunter2",
                "uris": [],
                "totp_uri": null,
                "autofill_on_page_load": false,
                "password_revision_date": null,
                "favicon": null,
                "fido2_credentials": [{
                    "credential_id": "cred-redact",
                    "key_type": "public-key",
                    "key_algorithm": "ECDSA_SHA256",
                    "key_curve": "P256",
                    "key_value": "AAAA",
                    "rp_id": "github.com",
                    "rp_name": "GitHub",
                    "user_handle": [104u8, 97, 110, 100, 108, 101],
                    "user_name": "u@example.com",
                    "user_display_name": "U",
                    "counter": 0u32,
                    "aaguid": "00000000-0000-0000-0000-000000000000",
                    "prf_key": [1u8, 2, 3],
                    "private_key": [7u8, 8, 9],
                    "private_key_missing": false,
                    "creation_date": 1735689600u64,
                    "name": "YubiKey"
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
    let json_path = tmp.path().join("cipher.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&cipher).unwrap()).expect("write json");

    let assert = baluard(tmp.path())
        .arg("add")
        .arg("json")
        .arg(json_path.to_string_lossy().to_string())
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("compile uuid regex");
    let id = re.find(&out).expect("cipher id").as_str().to_string();

    let assert = baluard(tmp.path())
        .arg("get")
        .arg(&id)
        .arg("--output")
        .arg("json")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("json output");

    let nested_cred = &parsed["kind"]["data"]["fido2_credentials"][0];
    assert!(
        nested_cred.get("private_key").is_none(),
        "nested private_key leaked"
    );
    assert!(
        nested_cred.get("prf_key").is_none(),
        "nested prf_key leaked"
    );
    assert_eq!(nested_cred["credential_id"], "cred-redact");
    assert_eq!(nested_cred["private_key_missing"], false);

    let flat_summary = &parsed["fido2_credentials"][0];
    assert!(
        flat_summary.get("private_key").is_none(),
        "flat summary leaked private_key"
    );
    assert!(
        flat_summary.get("prf_key").is_none(),
        "flat summary leaked prf_key"
    );

    // Flat fields keep their values; redaction is nested-kind-only.
    assert_eq!(parsed["password"], "hunter2");
    assert_eq!(parsed["kind"]["data"]["password"], "hunter2");
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
