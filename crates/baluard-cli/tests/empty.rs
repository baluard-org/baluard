//! Tests for `baluard vault empty`.

mod common;

use common::baluard;
use predicates::prelude::*;

/// A valid 24-word BIP-39 mnemonic that is NOT this vault's phrase.
const WRONG_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// `init --json` prints a JSON object carrying the recovery phrase; pick
/// it out of stdout so the test holds the vault's own words.
fn init_with_phrase(tmp: &std::path::Path, slug: &str) -> String {
    let assert = baluard(tmp)
        .args(["init", "--json", "--name", "Empty", "--slug", slug])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let re = regex::Regex::new(r#""recovery_phrase":"([a-z ]+)""#).expect("phrase regex");
    let caps = re
        .captures(&out)
        .expect("init --json prints recovery_phrase");
    let phrase = caps[1].to_string();
    assert_eq!(phrase.split_whitespace().count(), 24, "24-word phrase");
    phrase
}

fn add_login(tmp: &std::path::Path, name: &str) {
    baluard(tmp)
        .args(["add", "login", "--name", name, "--username", "u"])
        .assert()
        .success();
}

fn first_cipher_id(tmp: &std::path::Path) -> String {
    let out = String::from_utf8(
        baluard(tmp)
            .arg("list")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .expect("utf8 stdout");
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("uuid regex");
    re.find(&out).expect("cipher id").as_str().to_string()
}

#[test]
fn empty_wipes_entries_trash_and_refuses_wrong_phrase() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let phrase = init_with_phrase(tmp.path(), "empty-basic");

    add_login(tmp.path(), "A");
    add_login(tmp.path(), "B");

    // A different VALID 24-word phrase opens nothing and changes nothing.
    baluard(tmp.path())
        .args(["vault", "empty", "--phrase", WRONG_PHRASE, "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match this vault"));
    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("2 cipher"));

    // Soft-delete one entry: it rides in trash until the empty.
    let id = first_cipher_id(tmp.path());
    baluard(tmp.path()).args(["delete", &id]).assert().success();

    // Right phrase via env (scripting path): 1 live + 1 trashed removed.
    baluard(tmp.path())
        .env("BALUARD_RECOVERY_PHRASE", &phrase)
        .args(["vault", "empty", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed 2 entries"));

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No entries found."));
    baluard(tmp.path())
        .args(["trash", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trash is empty."));
}

#[test]
fn empty_rewrite_history_without_repo_reports_local_only() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let phrase = init_with_phrase(tmp.path(), "empty-rewrite");
    add_login(tmp.path(), "Only");

    baluard(tmp.path())
        .env("BALUARD_RECOVERY_PHRASE", &phrase)
        .args(["vault", "empty", "--rewrite-history", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed 1 entries"))
        .stdout(predicate::str::contains("no git remote"));

    baluard(tmp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No entries found."));
}

#[test]
fn empty_on_already_empty_vault_exits_before_prompting() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_with_phrase(tmp.path(), "empty-none");

    // No phrase available (no flag, no env): the early-out must fire
    // BEFORE the prompt, or the run hangs/fails on the prompt.
    baluard(tmp.path())
        .args(["vault", "empty", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault is already empty."));
}
