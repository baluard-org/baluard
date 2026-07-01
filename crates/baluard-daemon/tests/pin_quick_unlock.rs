//! Session-bound PIN Quick Unlock lifecycle tests.
//!
//! Exercises the in-memory KEK escrow end-to-end at the VaultState layer:
//! enable / status / unlock happy path, wrong-PIN counting, 5-strike escrow
//! nuke, soft-lock survival, and enable/disable state transitions.
//!
//! These create real temp vaults via VaultCreator so the Argon2id KDF and
//! keywrap/canary verification paths are exercised (no mocking of crypto).

mod real_vault {
    use baluard_core::vault::creation::VaultCreator;
    use std::path::PathBuf;

    fn make_real_vault(label: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().to_path_buf();
        let password = "test-master-password-123";
        let (_handle, _secrets) = VaultCreator::new(&path, password, &format!("pin-{label}"))
            .execute()
            .expect("vault creation");
        (dir, path)
    }

    use baluard_daemon::state::VaultState;
    use std::sync::Arc;

    const MASTER: &str = "test-master-password-123";

    /// Open (locked) a real vault into a VaultState and insert it into the host.
    async fn open_locked(label: &str) -> (tempfile::TempDir, Arc<VaultState>) {
        let (dir, path) = make_real_vault(label);
        let state = Arc::new(VaultState::new(path));
        state.open().await.expect("vault open");
        (dir, state)
    }

    #[tokio::test]
    async fn pin_status_disabled_by_default() {
        let (_dir, state) = open_locked("status-default").await;
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], false, "PIN not enabled before enable()");
    }

    #[tokio::test]
    async fn pin_enable_then_status_enabled() {
        let (_dir, state) = open_locked("enable").await;
        // Must unlock first: pin_enable derives the KEK from the master
        // password, and needs the vault open. (The daemon's route is
        // token-gated post-unlock; here we simulate by unlocking.)
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "482910" }).to_string();
        let r = state.pin_enable(&payload).await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&r).unwrap()["enabled"],
            true
        );
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], true);
    }

    #[tokio::test]
    async fn pin_enable_wrong_master_password_fails() {
        let (_dir, state) = open_locked("enable-wrong-pw").await;
        state.unlock(MASTER).await.unwrap();
        let payload =
            serde_json::json!({ "password": "totally-wrong", "pin": "482910" }).to_string();
        let err = state.pin_enable(&payload).await.unwrap_err();
        assert!(
            err.contains("Incorrect master password"),
            "expected master-password error, got: {err}"
        );
        // Escrow must NOT be created on a failed enable.
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], false);
    }

    #[tokio::test]
    async fn pin_enable_rejects_bad_pin_format() {
        let (_dir, state) = open_locked("enable-bad-pin").await;
        state.unlock(MASTER).await.unwrap();
        for bad in &["12345", "1234567", "abcdef", ""] {
            let payload = serde_json::json!({ "password": MASTER, "pin": bad }).to_string();
            assert!(
                state.pin_enable(&payload).await.is_err(),
                "PIN {bad:?} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn pin_unlock_happy_path() {
        let (_dir, state) = open_locked("unlock-ok").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "111222" }).to_string();
        state.pin_enable(&payload).await.unwrap();
        // Soft-lock so pin_unlock actually has to re-unlock.
        state.lock().await.unwrap();
        assert!(!state.is_unlocked().await);
        let pin_payload = serde_json::json!({ "pin": "111222" }).to_string();
        state.pin_unlock(&pin_payload).await.expect("PIN unlock");
        assert!(state.is_unlocked().await, "vault unlocked via PIN");
    }

    #[tokio::test]
    async fn pin_unlock_wrong_pin_counts_and_nukes_at_cap() {
        let (_dir, state) = open_locked("unlock-cap").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "999999" }).to_string();
        state.pin_enable(&payload).await.unwrap();
        state.lock().await.unwrap();

        // First MAX_PIN_FAILURES-1 attempts: fail but escrow survives.
        let wrong = serde_json::json!({ "pin": "000000" }).to_string();
        for i in 0..(baluard_daemon::pin::MAX_PIN_FAILURES - 1) {
            let err = state.pin_unlock(&wrong).await.unwrap_err();
            assert!(
                err.contains("Incorrect PIN"),
                "attempt {i}: expected Incorrect PIN, got: {err}"
            );
            // Escrow must still be present (under the cap).
            let s = serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap())
                .unwrap();
            assert_eq!(s["enabled"], true, "escrow alive before cap (attempt {i})");
        }

        // Terminal attempt: escrow nuked, master password required.
        let err = state.pin_unlock(&wrong).await.unwrap_err();
        assert!(
            err.contains("disabled") || err.contains("master password"),
            "terminal failure must mention disabled/master password, got: {err}"
        );
        // Escrow is now gone.
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], false, "escrow nuked at cap");

        // A correct PIN now ALSO fails — the escrow is gone.
        let correct = serde_json::json!({ "pin": "999999" }).to_string();
        assert!(
            state.pin_unlock(&correct).await.is_err(),
            "correct PIN must fail after escrow nuke"
        );
    }

    #[tokio::test]
    async fn pin_unlock_correct_after_failure_resets_counter() {
        // A successful PIN unlock must reset the failure counter so the next
        // burst starts from 0 (not carry over the prior failures).
        let (_dir, state) = open_locked("counter-reset").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "555000" }).to_string();
        state.pin_enable(&payload).await.unwrap();
        state.lock().await.unwrap();

        // One wrong attempt, then the correct one.
        let wrong = serde_json::json!({ "pin": "000000" }).to_string();
        assert!(state.pin_unlock(&wrong).await.is_err());
        let correct = serde_json::json!({ "pin": "555000" }).to_string();
        state
            .pin_unlock(&correct)
            .await
            .expect("correct PIN unlocks");
        assert!(state.is_unlocked().await);

        // Re-lock and try one wrong PIN: should still have the full budget
        // (counter was reset on success). We assert the escrow survives 1 try.
        state.lock().await.unwrap();
        assert!(state.pin_unlock(&wrong).await.is_err());
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(
            s["enabled"], true,
            "escrow survives single failure after reset"
        );
    }

    #[tokio::test]
    async fn pin_unlock_when_not_enabled_fails_clearly() {
        let (_dir, state) = open_locked("not-enabled").await;
        let pin = serde_json::json!({ "pin": "123456" }).to_string();
        let err = state.pin_unlock(&pin).await.unwrap_err();
        assert!(
            err.contains("not enabled") || err.contains("master password"),
            "expected not-enabled guidance, got: {err}"
        );
    }

    #[tokio::test]
    async fn pin_disable_clears_escrow() {
        let (_dir, state) = open_locked("disable").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "314159" }).to_string();
        state.pin_enable(&payload).await.unwrap();
        state.pin_disable().await.unwrap();
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], false);
        // And a PIN unlock now fails.
        let pin = serde_json::json!({ "pin": "314159" }).to_string();
        assert!(state.pin_unlock(&pin).await.is_err());
    }

    #[tokio::test]
    async fn pin_survives_soft_lock() {
        // The escrow is a separate field from `inner`; soft-lock drops the
        // handle (keys zeroize) but must leave the PIN escrow intact so the
        // user can re-unlock with the PIN. This is the core session-PIN UX.
        let (_dir, state) = open_locked("survives-lock").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "271828" }).to_string();
        state.pin_enable(&payload).await.unwrap();

        state.lock().await.unwrap();
        assert!(!state.is_unlocked().await);

        // PIN still reported enabled after a soft-lock.
        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], true, "PIN escrow survives soft-lock");

        // And it still unlocks.
        let pin = serde_json::json!({ "pin": "271828" }).to_string();
        state
            .pin_unlock(&pin)
            .await
            .expect("PIN unlock after soft-lock");
        assert!(state.is_unlocked().await);
    }

    #[tokio::test]
    async fn pin_concurrent_wrong_attempts_cap_at_max() {
        // Regression guard for the verify+record atomicity fix. A burst of
        // concurrent wrong-PIN attempts must NOT let more than
        // MAX_PIN_FAILURES real Argon2id-verified guesses reach the live
        // escrow before it is nuked. Before the fix (verify under the lock,
        // record AFTER releasing it), queued attempts could verify against
        // the still-live escrow before the 5th failure's nuke landed.
        //
        // Observable invariant after the fix: at most MAX_PIN_FAILURES
        // attempts observe a live escrow (return an "Incorrect PIN" /
        // terminal message); the rest observe `None` ("not enabled").
        let (_dir, state) = open_locked("concurrent-cap").await;
        state.unlock(MASTER).await.unwrap();
        let payload = serde_json::json!({ "password": MASTER, "pin": "711711" }).to_string();
        state.pin_enable(&payload).await.unwrap();
        state.lock().await.unwrap();

        let wrong = serde_json::json!({ "pin": "000000" }).to_string();
        const BURST: usize = 24;
        let mut handles = Vec::new();
        for _ in 0..BURST {
            let wrong = wrong.clone();
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                state.pin_unlock(&wrong).await.unwrap_err()
            }));
        }
        let mut live_escrow_hits = 0u32;
        for h in handles {
            let msg = h.await.unwrap();
            // "not enabled" => the attempt saw a nuked escrow (good).
            // Anything else => the attempt reached a live escrow.
            if !msg.contains("not enabled") {
                live_escrow_hits += 1;
            }
        }

        assert!(
            live_escrow_hits <= baluard_daemon::pin::MAX_PIN_FAILURES,
            "concurrent burst got {live_escrow_hits} live-escrow verifications, \
             expected <= {}",
            baluard_daemon::pin::MAX_PIN_FAILURES
        );

        let s =
            serde_json::from_str::<serde_json::Value>(&state.pin_status().await.unwrap()).unwrap();
        assert_eq!(s["enabled"], false, "escrow nuked after concurrent burst");
    }
}
