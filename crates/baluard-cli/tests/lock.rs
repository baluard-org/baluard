//! Tests for `baluard lock`.
//!
//! DEFERRED: `baluard --direct lock` is intentionally a hard error
//! (`"lock requires daemon mode"`). Lock only works through the daemon, and
//! the daemon-spawn test fixture (escargot + ready-wait + teardown) does not
//! exist yet. Once `tests/common/daemon.rs` lands, this file should gain:
//!
//! - `lock_succeeds_via_daemon` — spawn `baluard-daemon` against a temp socket,
//!   init + unlock, then `lock`, assert session token is cleared.
//! - `lock_idempotent_via_daemon` — second `lock` is a no-op success.
//! - `lock_without_unlock_fails_clearly` — daemon rejects pre-unlock lock.
//!
//! In the meantime, the direct-mode contract is pinned by the `#[ignore]`d
//! test below so it can't silently regress.

mod common;

use predicates::prelude::*;

use common::baluard;

/// Direct-mode `lock` MUST fail with a clear "requires daemon mode" message.
/// If a future refactor weakens this guard (e.g. silently no-op), this test
/// catches it.
#[test]
fn lock_direct_mode_errors_clearly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    baluard(tmp.path())
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon"));
}
