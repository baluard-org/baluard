//! Tests for `baluard vaults ...` subcommands.
//!
//! Only covers subcommands that work without a daemon: `list` (falls back
//! to registry-only when daemon unreachable) and `prune` (operates on the
//! registry directly). `switch`, `close`, `set-default`, and `detach`
//! require a live daemon — deferred until the daemon-spawn fixture lands.

mod common;

use predicates::prelude::*;

use common::{baluard, init_vault};

#[test]
fn vaults_list_with_one_registry_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Solo", "solo-vault");

    baluard(tmp.path())
        .arg("vaults")
        .arg("list")
        .assert()
        .success()
        // Daemon-unreachable fallback path prints a registry-only table.
        .stdout(predicate::str::contains("solo-vault"))
        .stdout(predicate::str::contains("Solo"));
}

#[test]
fn vaults_list_empty_registry_writes_guidance() {
    // Fresh sandboxed data dir with no vaults registered. The CLI should
    // print the "create one with" hint.
    let tmp = tempfile::tempdir().expect("tempdir");
    // Don't init — leave registry empty.

    baluard(tmp.path())
        .arg("vaults")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No vaults registered."))
        .stdout(predicate::str::contains("baluard init"));
}

#[test]
fn vaults_prune_no_stale_says_so() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_vault(tmp.path(), "Healthy", "healthy-vault");

    baluard(tmp.path())
        .arg("vaults")
        .arg("prune")
        .assert()
        .success()
        .stdout(predicate::str::contains("No stale vault entries"));
}

#[test]
fn vaults_help_lists_subcommands() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("vaults")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("prune"))
        .stdout(predicate::str::contains("detach"));
}
