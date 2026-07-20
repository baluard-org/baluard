//! Daemon VaultState coverage for routes still untested in `route_coverage.rs`.
//!
//! Covers the state methods that back routes I hadn't tested yet:
//!   - attach_upload / attach_download / attach_delete (round-trip + error paths)
//!   - create_vault (creates a new vault at a path)
//!
//! Conflict-decrypt-and-merge is intentionally skipped — it requires a pending
//! git conflict (set up by the sync cycle), which needs the full sync fixture
//! that's still TODO. Tracked as Phase 9b/c.

mod real_vault {
    use baluard_core::types::{CipherInput, CipherKind, LoginData, LoginUri};
    use baluard_core::vault::creation::VaultCreator;
    use baluard_daemon::state::VaultState;
    use base64::Engine;
    use std::path::PathBuf;
    use std::sync::Arc;

    const MASTER: &str = "test-master-password-123";

    fn make_vault(label: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().to_path_buf();
        VaultCreator::new(&path, MASTER, &format!("gaps-{label}"))
            .execute()
            .expect("vault creation");
        (dir, path)
    }

    async fn open_unlocked(label: &str) -> (tempfile::TempDir, Arc<VaultState>) {
        let (dir, path) = make_vault(label);
        let state = Arc::new(VaultState::new(path));
        state.open().await.expect("vault open");
        state.unlock(MASTER).await.expect("vault unlock");
        (dir, state)
    }

    fn login_input(name: &str) -> CipherInput {
        CipherInput {
            name: name.to_string(),
            folder_id: None,
            kind: CipherKind::Login(LoginData {
                username: Some("u".into()),
                password: Some("p".into()),
                uris: vec![LoginUri::new("https://example.com".to_string())],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags: vec![],
        }
    }

    // ── attach upload + download + delete ──

    #[tokio::test]
    async fn attach_round_trip_preserves_plaintext() {
        let (_dir, state) = open_unlocked("attach-rt").await;
        let id = state
            .add_cipher(&serde_json::to_string(&login_input("Doc")).unwrap())
            .await
            .unwrap();
        let plaintext = b"hello attachment world";
        let payload = serde_json::json!({
            "cipher_id": id.to_string(),
            "filename": "test.txt",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(plaintext),
        })
        .to_string();
        let resp = state.attach_upload(&payload).await.expect("upload");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        let attach_id = v["id"].as_str().expect("id").to_string();
        assert_eq!(v["filename"], "test.txt");

        // Download round-trip.
        let download = state
            .attach_download(
                &serde_json::json!({
                    "cipher_id": id.to_string(),
                    "attachment_id": attach_id,
                })
                .to_string(),
            )
            .await
            .expect("download");
        let d: serde_json::Value = serde_json::from_str(&download).expect("json");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(d["data_base64"].as_str().unwrap())
            .expect("base64");
        assert_eq!(decoded, plaintext, "round-tripped plaintext matches");
        assert_eq!(d["filename"], "test.txt");
        assert_eq!(d["size"], plaintext.len() as u64);
    }

    #[tokio::test]
    async fn attach_delete_removes_from_metadata() {
        let (_dir, state) = open_unlocked("attach-del").await;
        let id = state
            .add_cipher(&serde_json::to_string(&login_input("X")).unwrap())
            .await
            .unwrap();
        let upload = state
            .attach_upload(
                &serde_json::json!({
                    "cipher_id": id.to_string(),
                    "filename": "a.bin",
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(b"payload"),
                })
                .to_string(),
            )
            .await
            .expect("upload");
        let attach_id = serde_json::from_str::<serde_json::Value>(&upload).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Confirm it's listed on the cipher.
        let cipher_json = state.get_cipher(&id.to_string(), false).await.expect("get");
        let cipher: serde_json::Value = serde_json::from_str(&cipher_json).expect("json");
        let attachments = cipher["attachments"].as_array().expect("attachments");
        assert_eq!(attachments.len(), 1, "attachment present before delete");

        // Delete.
        state
            .attach_delete(
                &serde_json::json!({
                    "cipher_id": id.to_string(),
                    "attachment_id": attach_id,
                })
                .to_string(),
            )
            .await
            .expect("delete");

        // Re-fetch and confirm attachment gone.
        let cipher_json = state.get_cipher(&id.to_string(), false).await.expect("get");
        let cipher: serde_json::Value = serde_json::from_str(&cipher_json).expect("json");
        let attachments = cipher["attachments"].as_array().expect("attachments");
        assert!(attachments.is_empty(), "attachment removed");
    }

    #[tokio::test]
    async fn attach_upload_rejects_oversized() {
        let (_dir, state) = open_unlocked("attach-oversize").await;
        let id = state
            .add_cipher(&serde_json::to_string(&login_input("X")).unwrap())
            .await
            .unwrap();
        // 3 MB > 2 MB cap.
        let big = vec![0u8; 3 * 1024 * 1024];
        let payload = serde_json::json!({
            "cipher_id": id.to_string(),
            "filename": "huge.bin",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&big),
        })
        .to_string();
        let err = state.attach_upload(&payload).await.unwrap_err();
        assert!(
            err.contains("File too large") || err.contains("2MB"),
            "expected oversize error, got: {err}"
        );
    }

    #[tokio::test]
    async fn attach_upload_missing_cipher_id_errors() {
        let (_dir, state) = open_unlocked("attach-no-cipher").await;
        let payload = serde_json::json!({
            "filename": "x.txt",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(b"data"),
        })
        .to_string();
        let err = state.attach_upload(&payload).await.unwrap_err();
        assert!(err.contains("cipher_id") || err.contains("missing"));
    }

    #[tokio::test]
    async fn attach_upload_on_locked_vault_errors() {
        let (_dir, path) = make_vault("attach-locked");
        let state = Arc::new(VaultState::new(path));
        state.open().await.expect("open");
        // NOT unlocked.
        let payload = serde_json::json!({
            "cipher_id": "00000000-0000-0000-0000-000000000000",
            "filename": "x.txt",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(b"data"),
        })
        .to_string();
        let err = state.attach_upload(&payload).await.unwrap_err();
        assert!(err.contains("locked") || err.contains("Cipher not found"));
    }

    // ── create_vault ──

    #[tokio::test]
    async fn create_vault_at_empty_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let target = dir.path().join("new-vault");
        // First create a separate VaultState (the test harness's state
        // is bound to its own vault_path; create_vault creates a NEW one
        // at a different path).
        let state = VaultState::new(target.clone());
        let payload = serde_json::json!({
            "password": MASTER,
            "kdf_profile": "desktop-std",
            "name": "My New Vault",
            "slug": "new-vault",
        })
        .to_string();
        let result = state.create_vault(&payload).await.expect("create_vault");
        assert!(!result.is_empty(), "create_vault returns the new vault_id");
        // meta/kdf-params.json should now exist on disk.
        assert!(target.join("meta/kdf-params.json").exists());
    }

    #[tokio::test]
    async fn create_vault_refuses_to_overwrite() {
        let (_dir, state) = open_unlocked("create-vault-dup").await;
        // The state is already pointing at an initialized vault (from
        // open_unlocked). Try to create a new one at the same path.
        let payload = serde_json::json!({
            "password": MASTER,
            "kdf_profile": "desktop-std",
            "name": "Dup",
            "slug": "dup",
        })
        .to_string();
        let err = state.create_vault(&payload).await.unwrap_err();
        assert!(err.contains("exists") || err.contains("already"));
    }
}
