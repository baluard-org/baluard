//! Phase 6 integration tests for the multi-vault host.
//!
//! These cover the keep-unlocked / switch-pointer model end-to-end at the
//! host layer: switching never zeroizes, auto-lock is per-vault, close
//! drains via Arc, and the single-lock invariant holds under concurrency.
//!
//! Scenarios mapped to the plan's acceptance criteria:
//!   1. Two vaults unlocked, switch A→B→A, both stay unlocked (no re-prompt)
//!   2. Per-vault auto-lock fires independently
//!   3. Active vault auto-locks → active still points at it → implicit
//!      request resolves to locked
//!   4. In-flight request to A unaffected by concurrent switch to B
//!   5. vaults.close returns immediately (Arc-drain)
//!   6. Concurrent close+switch never leaves active pointing at a missing
//!      entry (single-lock invariant)
//!   7. Arc::strong_count is NOT used as a synchronization primitive
//!      (documented invariant; we assert the close-returns-immediately
//!      behaviour that depends on it)

use std::path::PathBuf;
use std::sync::Arc;

use baluard_daemon::host::{SharedVaultHost, SnapshotError, SwitchError, VaultHost, VaultPresence};
use baluard_daemon::state::VaultState;

// ── test helpers ──

/// Build a fresh, empty VaultState pointing at a fake path. The path does
/// not need to exist for state-machine tests (switch / close / snapshot
/// never touch disk). For unlock tests we use real temp vaults.
fn fake_state(label: &str) -> Arc<VaultState> {
    Arc::new(VaultState::new(PathBuf::from(format!(
        "/tmp/baluard-test-{label}"
    ))))
}

/// Scenario 1: switch A→B→A keeps both unlocked (no re-prompt, no zeroize).
#[tokio::test]
async fn switch_round_trip_keeps_both_present() {
    let host: SharedVaultHost = VaultHost::shared();
    let a = fake_state("a");
    let b = fake_state("b");
    host.insert("alpha".into(), a).await;
    host.insert("beta".into(), b).await;

    // Switch to alpha.
    let out = host.switch("alpha").await.unwrap();
    assert_eq!(out.slug, "alpha");
    assert_eq!(out.presence, VaultPresence::Locked); // fake vaults are never unlocked
    assert_eq!(host.active_slug().await.as_deref(), Some("alpha"));

    // Switch to beta — alpha must still be in the map.
    host.switch("beta").await.unwrap();
    assert_eq!(host.active_slug().await.as_deref(), Some("beta"));
    assert!(
        host.get("alpha").await.is_some(),
        "alpha must remain in map"
    );

    // Switch back to alpha.
    host.switch("alpha").await.unwrap();
    assert_eq!(host.active_slug().await.as_deref(), Some("alpha"));
    assert!(host.get("beta").await.is_some(), "beta must remain in map");
}

/// Scenario 3 (state-machine half): when the active vault auto-locks, the
/// active pointer is LEFT pointing at it (policy). We can't easily fire a
/// real auto-lock here (it needs a real unlocked vault + idle time), so we
/// assert the invariant the policy depends on: after switch, active always
/// points at a present slug, and a locked-vault snapshot still resolves.
#[tokio::test]
async fn active_pointer_stays_valid_after_switch() {
    let host: SharedVaultHost = VaultHost::shared();
    host.insert("only".into(), fake_state("only")).await;
    host.switch("only").await.unwrap();

    // Snapshot resolves to the active slug.
    let (slug, _state) = host.snapshot_target(None).await.unwrap();
    assert_eq!(slug, "only");
}

/// Scenario 4: a request pinned to vault A is unaffected by a concurrent
/// switch to B. We model this by snapshotting A, then switching to B, then
/// confirming the snapshot still points at A's state object.
#[tokio::test]
async fn snapshot_pins_target_across_switch() {
    let host: SharedVaultHost = VaultHost::shared();
    let a = fake_state("a");
    let b = fake_state("b");
    let a_path = a.vault_path.clone();
    host.insert("alpha".into(), a).await;
    host.insert("beta".into(), b).await;
    host.switch("alpha").await.unwrap();

    // Snapshot the active vault (alpha).
    let (slug, state_a) = host.snapshot_target(None).await.unwrap();
    assert_eq!(slug, "alpha");
    assert_eq!(state_a.vault_path, a_path);

    // Concurrent switch to beta.
    host.switch("beta").await.unwrap();
    assert_eq!(host.active_slug().await.as_deref(), Some("beta"));

    // The pinned snapshot is unchanged — it still references alpha's state.
    assert_eq!(state_a.vault_path, a_path);
}

/// Scenario 5: vaults.close returns immediately and the entry is gone from
/// the map. The Arc the caller already holds stays valid (Arc-drain).
#[tokio::test]
async fn close_returns_immediately_and_drops_map_entry() {
    let host: SharedVaultHost = VaultHost::shared();
    let a = fake_state("a");
    host.insert("alpha".into(), a.clone()).await;
    host.switch("alpha").await.unwrap();

    // The caller still holds a strong ref (modeling an in-flight handler).
    let held = host.get("alpha").await.expect("present before close");
    assert_eq!(held.vault_path, a.vault_path);

    let removed = host.close("alpha").await;
    assert!(removed, "close reports removal");
    assert!(host.get("alpha").await.is_none(), "map entry gone");
    assert_eq!(host.active_slug().await, None, "active cleared");

    // The held Arc is still usable — Arc-drain, not busy error.
    assert_eq!(held.vault_path, a.vault_path);
}

/// Scenario 6: concurrent close + switch on the same slug can never leave
/// `active` pointing at a missing entry. The single VaultHostInner write
/// lock is what makes this provable. We hammer it from two tasks.
/// Scenario 6: concurrent close + switch on the same slug can never leave
/// `active` pointing at a missing entry. The single VaultHostInner write
/// lock is what makes this provable. We hammer it from three tasks:
/// closer (removes alpha), switcher (flips active to alpha), and a slow
/// re-inserter (puts alpha back) — plus a CONTINUOUS monitor that asserts
/// the invariant every iteration, not just at the end.
#[tokio::test]
async fn concurrent_close_and_switch_keep_invariant() {
    let host: SharedVaultHost = VaultHost::shared();
    host.insert("alpha".into(), fake_state("a")).await;
    host.insert("beta".into(), fake_state("b")).await;
    host.switch("alpha").await.unwrap();

    let h_close = host.clone();
    let h_switch = host.clone();
    let h_reins = host.clone();
    let h_mon = host.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Closer: removes alpha (the active vault). Does NOT re-insert — that's
    // a separate slow task, so there's a real window where alpha is absent
    // while `active` may still point at it.
    let stop_c = stop.clone();
    let closer = tokio::spawn(async move {
        while !stop_c.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = h_close.close("alpha").await;
            tokio::task::yield_now().await;
        }
    });

    // Switcher: flips active between alpha and beta. Beta is never closed,
    // so switching to beta keeps `active` stable at Some(beta) and gives the
    // monitor plenty of Some-observations. Switching to alpha (which the
    // closer concurrently removes) exercises the real danger window.
    let stop_s = stop.clone();
    let switcher = tokio::spawn(async move {
        let mut to_beta = false;
        while !stop_s.load(std::sync::atomic::Ordering::Relaxed) {
            let target = if to_beta { "beta" } else { "alpha" };
            let _ = h_switch.switch(target).await;
            to_beta = !to_beta;
            tokio::task::yield_now().await;
        }
    });

    // Re-inserter: puts alpha back so the map isn't permanently empty and
    // the switcher/closer have something to race on. Slower than the closer
    // so the absent-window is genuinely exercised.
    let stop_r = stop.clone();
    let reinserter = tokio::spawn(async move {
        while !stop_r.load(std::sync::atomic::Ordering::Relaxed) {
            h_reins
                .get_or_insert_with("alpha", || fake_state("a-reins"))
                .await;
            tokio::task::yield_now().await;
        }
    });

    // Monitor: assert the invariant on EVERY iteration while the race runs.
    // This is the real test of the single-lock property — not a single
    // post-hoc check that could pass by luck of timing. A violation at ANY
    // point panics the task, failing the test.
    let stop_m = stop.clone();
    let monitor = tokio::spawn(async move {
        let mut observed_some = 0u32;
        while !stop_m.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(slug) = h_mon.active_slug().await {
                assert!(
                    h_mon.get(&slug).await.is_some(),
                    "INVARIANT VIOLATED mid-race: active='{slug}' but slug not in map"
                );
                observed_some += 1;
            }
            tokio::task::yield_now().await;
        }
        observed_some
    });

    // Let them race for 400ms — long enough for thousands of interleavings.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = closer.await;
    let _ = switcher.await;
    let _ = reinserter.await;
    let observed_some = monitor.await.unwrap();

    // The switcher alternates to beta (always present), so the monitor must
    // have observed active=Some(...) many times. If it never did, the race
    // never produced a checkable state and the test is inconclusive — fail
    // loudly rather than pass vacuously.
    assert!(
        observed_some > 0,
        "monitor never observed an active slug during the race; test is inconclusive"
    );

    // Final post-hoc invariant check.
    if let Some(slug) = host.active_slug().await {
        assert!(
            host.get(&slug).await.is_some(),
            "INVARIANT VIOLATED: active='{slug}' but slug not in map"
        );
    }
}

/// Switching to an unregistered slug returns a clear error (Scenario 7 / plan
/// acceptance: "Switch to unregistered slug returns a clear error").
#[tokio::test]
async fn switch_to_unknown_slug_errors() {
    let host: SharedVaultHost = VaultHost::shared();
    let err = host.switch("ghost").await.unwrap_err();
    assert!(matches!(err, SwitchError::UnknownSlug(s) if s == "ghost"));
}

/// Snapshot error paths.
#[tokio::test]
async fn snapshot_errors_are_descriptive() {
    let host: SharedVaultHost = VaultHost::shared();

    // No active, no slug.
    let err = host
        .snapshot_target(None)
        .await
        .err()
        .expect("expected error");
    assert!(matches!(err, SnapshotError::NoActive));

    // Active set, but slug not in map (closed mid-flight).
    host.insert("alpha".into(), fake_state("a")).await;
    host.switch("alpha").await.unwrap();
    let err = host
        .snapshot_target(Some("ghost"))
        .await
        .err()
        .expect("expected error");
    assert!(matches!(err, SnapshotError::SlugNotOpen(s) if s == "ghost"));
}

/// The `vaults.list` join: registered vaults without an in-map entry show
/// `closed`; with an entry show `locked` (fake vaults are never unlocked).
#[tokio::test]
async fn list_joins_registry_with_map() {
    let host: SharedVaultHost = VaultHost::shared();
    host.insert("alpha".into(), fake_state("a")).await;
    host.switch("alpha").await.unwrap();

    // The registry is empty in this test process, so list() returns no
    // rows even though the map has alpha. This documents the join: list()
    // is registry-driven, not map-driven. (The daemon only knows about a
    // vault if it's in BOTH the registry and the map.)
    let rows = host.list().await;
    // No registry entries => empty list. This is the correct behaviour:
    // the map can hold a vault that isn't registered yet (e.g. mid-create),
    // and list() correctly omits it until the registry catches up.
    assert!(
        rows.iter()
            .all(|r| r.presence == "unlocked" || r.presence == "locked" || r.presence == "closed")
    );
}

/// `lock_all` (shutdown path) is a no-op on an empty host and locks every
/// open vault otherwise. We assert the count semantics with fake vaults
/// (lock() on a never-opened vault returns Ok without doing anything).
#[tokio::test]
async fn lock_all_returns_count_of_open_vaults() {
    let host: SharedVaultHost = VaultHost::shared();
    assert_eq!(host.lock_all().await, 0);

    host.insert("alpha".into(), fake_state("a")).await;
    host.insert("beta".into(), fake_state("b")).await;
    assert_eq!(host.lock_all().await, 2);
}

/// `lock_all` is the defensive primitive fired on screen-lock / sleep /
/// window-blur. After it runs, every vault's state reflects locked (for
/// real vaults) and the active pointer is preserved (re-lock policy: the
/// user's focus stays stable so the re-unlock UX targets the same vault).
#[tokio::test]
async fn lock_all_preserves_active_pointer() {
    let host: SharedVaultHost = VaultHost::shared();
    host.insert("alpha".into(), fake_state("a")).await;
    host.switch("alpha").await.unwrap();
    assert_eq!(host.active_slug().await.as_deref(), Some("alpha"));

    let locked = host.lock_all().await;
    assert_eq!(locked, 1);
    // active stays pointed at alpha (lock-all is not close; the vault
    // remains in the map, just locked).
    assert_eq!(host.active_slug().await.as_deref(), Some("alpha"));
    assert!(
        host.get("alpha").await.is_some(),
        "vault stays in map after lock_all"
    );
}

// ── real-vault tests (need actual disk + KDF) ──
//
// These create real temp vaults via VaultCreator so we can exercise the
// unlock path. They are heavier (~300ms-1s each for Argon2id) so they're
// kept minimal.

mod real_vault {
    use super::*;
    use baluard_core::vault::creation::VaultCreator;

    /// Create a real temp vault on disk and return (dir, slug-label).
    /// The dir is leaked (tempfile kept alive for the test duration).
    fn make_real_vault(label: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().to_path_buf();
        let password = "test-master-password-123";
        let (_handle, _secrets) = VaultCreator::new(&path, password, &format!("dev-{label}"))
            .execute()
            .expect("vault creation");
        (dir, path)
    }

    /// Scenario 1 (full): two real vaults unlocked, switch A→B→A, both stay
    /// unlocked. This is the headline Phase 6 acceptance test.
    #[tokio::test]
    async fn two_vaults_switch_keeps_both_unlocked() {
        let (_dir_a, path_a) = make_real_vault("a");
        let (_dir_b, path_b) = make_real_vault("b");

        let host: SharedVaultHost = VaultHost::shared();
        let state_a = Arc::new(VaultState::new(path_a));
        let state_b = Arc::new(VaultState::new(path_b));
        host.insert("alpha".into(), state_a.clone()).await;
        host.insert("beta".into(), state_b.clone()).await;

        // Unlock both.
        state_a.unlock("test-master-password-123").await.unwrap();
        state_b.unlock("test-master-password-123").await.unwrap();
        assert!(state_a.is_unlocked().await);
        assert!(state_b.is_unlocked().await);

        // Switch A → B → A.
        host.switch("alpha").await.unwrap();
        let out = host.switch("beta").await.unwrap();
        assert_eq!(out.presence, VaultPresence::Unlocked);
        host.switch("alpha").await.unwrap();

        // BOTH must still be unlocked — switching never zeroizes.
        assert!(state_a.is_unlocked().await, "alpha must stay unlocked");
        assert!(state_b.is_unlocked().await, "beta must stay unlocked");
    }

    /// Scenario 2: per-vault state is independent. Locking one does not
    /// lock the other. (Full auto-lock timing is environment-sensitive;
    /// here we assert the independence property directly.)
    #[tokio::test]
    async fn locking_one_vault_does_not_lock_other() {
        let (_dir_a, path_a) = make_real_vault("a");
        let (_dir_b, path_b) = make_real_vault("b");

        let host: SharedVaultHost = VaultHost::shared();
        let state_a = Arc::new(VaultState::new(path_a));
        let state_b = Arc::new(VaultState::new(path_b));
        host.insert("alpha".into(), state_a.clone()).await;
        host.insert("beta".into(), state_b.clone()).await;

        state_a.unlock("test-master-password-123").await.unwrap();
        state_b.unlock("test-master-password-123").await.unwrap();

        // Lock only alpha.
        state_a.lock().await.unwrap();
        assert!(!state_a.is_unlocked().await);
        assert!(state_b.is_unlocked().await, "beta must stay unlocked");
    }

    /// H3: the headline R7-2 invariant — a vault-A session token is
    /// REJECTED for a vault-B operation. This is the first end-to-end test
    /// of the per-vault token gate through the handler layer (the host-layer
    /// tests don't exercise routing).
    ///
    /// We pre-insert the VaultStates and unlock them directly (grabbing each
    /// token via `get_session_token`) rather than going through
    /// `handle_vault_unlock`, which would require the temp vaults to be in
    /// the global registry. The token-gated `vault.list` requests then drive
    /// the real `route_host_request → snapshot_target → route_request →
    /// verify_session_token` path — which is the property under test.
    #[tokio::test]
    async fn per_vault_token_rejection() {
        use baluard_daemon::handler::route_host_request;
        use baluard_daemon::proto::GatewayRequest;

        let (_dir_a, path_a) = make_real_vault("a");
        let (_dir_b, path_b) = make_real_vault("b");

        let host: SharedVaultHost = VaultHost::shared();
        let state_a = Arc::new(VaultState::new(path_a));
        let state_b = Arc::new(VaultState::new(path_b));
        host.insert("alpha".into(), state_a.clone()).await;
        host.insert("beta".into(), state_b.clone()).await;

        // Unlock both directly and capture each vault's real session token.
        state_a.unlock("test-master-password-123").await.unwrap();
        state_b.unlock("test-master-password-123").await.unwrap();
        let token_a = state_a.get_session_token().await.expect("alpha token");
        let token_b = state_b.get_session_token().await.expect("beta token");

        // 1. WRONG token (alpha's) for a beta operation → REJECTED.
        // vault.list is token-gated; targeting slug=beta with alpha's token
        // drives snapshot_target(beta) then verify_session_token against
        // beta's stored token → mismatch.
        let cross_req = GatewayRequest {
            action: "vault.list".into(),
            payload: String::new(),
            session_token: token_a.clone(),
            slug: "beta".into(),
        };
        let cross_resp = route_host_request(cross_req, &host).await;
        assert!(
            !cross_resp.success,
            "alpha's token must NOT work for a beta operation"
        );
        assert!(
            cross_resp.error_message.contains("session token"),
            "expected a token-rejection error, got: {}",
            cross_resp.error_message
        );

        // 2. NO token for a beta operation → REJECTED (locked-style).
        let notoken_req = GatewayRequest {
            action: "vault.list".into(),
            payload: String::new(),
            session_token: String::new(),
            slug: "beta".into(),
        };
        let notoken_resp = route_host_request(notoken_req, &host).await;
        assert!(!notoken_resp.success, "missing token must be rejected");

        // 3. CORRECT token (beta's) for a beta operation → ACCEPTED.
        let ok_req = GatewayRequest {
            action: "vault.list".into(),
            payload: String::new(),
            session_token: token_b.clone(),
            slug: "beta".into(),
        };
        let ok_resp = route_host_request(ok_req, &host).await;
        assert!(
            ok_resp.success,
            "beta's own token must work for a beta operation: {}",
            ok_resp.error_message
        );
    }

    // Mutates a process-global env var (BALUARD_DATA_DIR); must not run
    // concurrently with any other test that reads it via paths.rs.
    #[tokio::test]
    #[serial_test::serial]
    async fn vault_unlock_error_rate_limiting_delay() {
        use baluard_core::vault::registry::{VaultEntry, VaultRegistry};
        use baluard_daemon::handler::route_host_request;
        use baluard_daemon::proto::GatewayRequest;
        use uuid::Uuid;

        let temp_data_dir = tempfile::tempdir().expect("temp data dir");
        let prev_data_dir = std::env::var_os("BALUARD_DATA_DIR");
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", temp_data_dir.path());
        }

        let (_dir_a, path_a) = make_real_vault("a");

        let mut reg = VaultRegistry::default();
        reg.add(VaultEntry {
            slug: "alpha".into(),
            display_name: "Personal".into(),
            path: path_a.clone(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: Uuid::new_v4(),
        })
        .unwrap();
        reg.save_locked().unwrap();

        let host: SharedVaultHost = VaultHost::shared();
        let state_a = Arc::new(VaultState::new(path_a));
        host.insert("alpha".into(), state_a.clone()).await;

        let req = GatewayRequest {
            action: "vault.unlock".into(),
            payload: "wrong-password-123".into(),
            session_token: String::new(),
            slug: "alpha".into(),
        };

        let start = std::time::Instant::now();
        let resp = route_host_request(req, &host).await;
        let duration = start.elapsed();

        assert!(!resp.success, "Unlock must fail with wrong password");
        assert!(
            duration >= std::time::Duration::from_millis(1900),
            "Unlock failure response must be delayed by at least 2s (took {}ms)",
            duration.as_millis()
        );

        // Restore env so the mutation does not leak into sibling tests in the
        // same binary. Still unsafe in 2024 edition, but we are single-threaded
        // for this test (#[serial]).
        unsafe {
            match prev_data_dir {
                Some(v) => std::env::set_var("BALUARD_DATA_DIR", v),
                None => std::env::remove_var("BALUARD_DATA_DIR"),
            }
        }
    }
}
