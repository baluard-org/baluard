//! Shared helpers for CLI integration tests.
//!
//! All tests in `tests/*.rs` use these to spawn the `baluard` binary against a
//! `tempfile::TempDir`-backed vault path with `BALUARD_PASSWORD` set so the
//! recovery phrase verification and master-password prompts are bypassed.

// Each integration test file (`tests/init.rs`, `tests/list.rs`, ...) is a
// separate crate with its own copy of this module. Some helpers are only
// used by a subset of files (e.g. `assert_vault_initialized` is only called
// from `init.rs`), which would trigger `dead_code` warnings in the other
// crates. Allow at the module level — these helpers are intentionally
// shared even when not every consumer uses every helper.
#![allow(dead_code)]

use std::path::Path;

use assert_cmd::Command;

/// Master password used across tests. >= 8 chars (CLI's minimum) and a mix of
/// cases/digits so it's not flagged as trivially weak by future heuristics.
pub const TEST_PASSWORD: &str = "test-passw0rd-12chars";

/// Build a `Command` for the `baluard` binary, pre-configured for direct mode
/// against the given vault path with `BALUARD_PASSWORD` set so prompts and
/// recovery-phrase verification are skipped. Also redirects `BALUARD_DATA_DIR`
/// into the vault path itself (`.baluard-data/`) so each test's registry +
/// session token stay isolated inside its `TempDir` and never touch the
/// user's real `~/.config/baluard/registry.json`.
pub fn baluard(vault_path: &Path) -> Command {
    let mut cmd = Command::cargo_bin("baluard").expect("baluard binary not found");
    let data_dir = vault_path.join(".baluard-data");
    cmd.env("BALUARD_PASSWORD", TEST_PASSWORD)
        .env("BALUARD_DATA_DIR", &data_dir)
        // Tests must never touch the real keychain (interactive auth prompts
        // stall the suite; same policy as daemon_spawn).
        .env("BALUARD_DISABLE_KEYRING", "1")
        // Strip user-level env vars that could leak into tests (e.g. a custom
        // socket path pointing at a running daemon).
        .env_remove("BALUARD_SOCKET")
        .arg("--direct")
        .arg("--vault-path")
        .arg(vault_path);
    cmd
}

/// Run `baluard init` against a fresh vault directory.
///
/// Asserts exit-0 + expected stdout markers. Caller owns the `TempDir` so the
/// vault stays on disk for follow-up commands (unlock, add, list).
pub fn init_vault(vault_path: &Path, name: &str, slug: &str) {
    baluard(vault_path)
        .arg("init")
        .arg("--name")
        .arg(name)
        .arg("--slug")
        .arg(slug)
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault created successfully."))
        .stdout(predicates::str::contains("RECOVERY PHRASE"));
}

/// Confirm the vault's `meta/` directory was populated by `init`. The CLI does
/// not expose a stable "is vault initialized" check, so we peek at the
/// filesystem — same way the desktop's pre-unlock probe works. The reliable
/// sentinel is `meta/kek-canary.enc`, written by `VaultCreator::execute`
/// after a successful KDF + canary encrypt (see
/// `crates/baluard-core/src/vault/creation.rs:457`).
pub fn assert_vault_initialized(vault_path: &Path) {
    let kek_canary = vault_path.join("meta").join("kek-canary.enc");
    assert!(
        kek_canary.exists(),
        "expected meta/kek-canary.enc at {} (vault not initialized)",
        kek_canary.display()
    );
}
