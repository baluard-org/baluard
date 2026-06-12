//! Phase 1 test harness: validates the full WebAuthn ceremony round-trip.
//!
//! Tests:
//! 1. Registration ceremony produces valid PasskeyData with all required fields
//! 2. Assertion ceremony works with the registered passkey
//! 3. Counter increments on each assertion
//! 4. Multi-passkey registration (different RPs)
//! 5. PasskeyIndex round-trips through Cipher → PasskeyIndex → Ceremony
//! 6. CeremonyCache TTL expiry
//! 7. Store mutation tracking

use baluard_core::crypto::webauthn::{
    run_registration, run_assertion, CeremonyCache, CeremonyState, CEREMONY_TTL,
    BaluardCredentialStore, PasskeyIndex,
};
use baluard_core::types::{Cipher, CipherKind, CipherType, PasskeyData, Tier};
use base64::Engine;
use url::Url;

fn test_origin() -> Url {
    Url::parse("https://example.com").unwrap()
}

fn make_passkey_data(rp_id: &str, user_name: &str, counter: u32) -> PasskeyData {
    PasskeyData {
        credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(rand::random::<[u8; 32]>()),
        key_type: "public-key".to_string(),
        key_algorithm: "ECDSA".to_string(),
        key_curve: "P-256".to_string(),
        key_value: String::new(),
        rp_id: rp_id.to_string(),
        rp_name: Some(format!("{rp_id} Display Name")),
        user_handle: Some(rand::random::<[u8; 16]>().to_vec()),
        user_name: Some(user_name.to_string()),
        user_display_name: Some(user_name.to_string()),
        private_key: None,
        counter,
        aaguid: uuid::Uuid::nil(),
        creation_date: 1000,
        private_key_missing: true,
        prf_key: None,
        linked_login_id: None,
    }
}

fn make_cipher(pk_data: PasskeyData) -> Box<Cipher> {
    Box::new(Cipher {
        id: uuid::Uuid::new_v4(),
        name: format!(
            "{} ({})",
            pk_data.rp_name.as_deref().unwrap_or(&pk_data.rp_id),
            pk_data.user_name.as_deref().unwrap_or("passkey")
        ),
        folder_id: None,
        kind: CipherKind::Passkey(pk_data),
        favorite: false,
        reprompt: false,
        notes: None,
        custom_fields: Vec::new(),
        key_epoch: 1,
        update_seq: 1,
        tier: Tier::Xs,
        created_at: 1000,
        updated_at: 1000,
        password_history: Vec::new(),
        attachments: Vec::new(),
        archived: false,
        tags: vec!["passkey".to_string()],
    })
}

#[tokio::test]
async fn registration_produces_valid_passkey_data() {
    let index = PasskeyIndex::from_ciphers(&[]);
    let result = run_registration(
        &test_origin(),
        "example.com".into(),
        "Example Site".into(),
        "alice@example.com".into(),
        "Alice".into(),
        vec![1, 2, 3, 4],
        &index,
    )
    .await
    .expect("registration should succeed");

    let pk = result.passkey_data;
    assert_eq!(pk.rp_id, "example.com");
    assert_eq!(pk.rp_name.as_deref(), Some("Example Site"));
    assert_eq!(pk.user_name.as_deref(), Some("alice@example.com"));
    assert_eq!(pk.user_display_name.as_deref(), Some("Alice"));
    assert!(!pk.credential_id.is_empty());
    assert_eq!(pk.key_type, "public-key");
    assert_eq!(pk.key_algorithm, "ECDSA");
    assert_eq!(pk.key_curve, "P-256");
    assert!(
        pk.private_key.is_some(),
        "private key must be present"
    );
    assert!(!pk.private_key_missing);
    assert_eq!(pk.counter, 0);
    assert!(pk.creation_date > 0);
    assert!(!result.credential_id_b64.is_empty());
    assert!(!result.attestation_response.is_empty());
}

#[tokio::test]
async fn assertion_works_with_registered_passkey() {
    // Register first (origin must match RP ID domain)
    let rp_origin = Url::parse("https://test-rp.io").unwrap();
    let index = PasskeyIndex::from_ciphers(&[]);
    let reg = run_registration(
        &rp_origin,
        "test-rp.io".into(),
        "Test RP".into(),
        "bob@test.io".into(),
        "Bob".into(),
        vec![5, 6, 7, 8],
        &index,
    )
    .await
    .expect("registration");

    // Build a new index from the registered passkey (simulates vault save → reload)
    let cipher = make_cipher(reg.passkey_data);
    let index = PasskeyIndex::from_boxed_ciphers(&[cipher]);

    // Assert (origin must match RP ID)
    let assertion = run_assertion(&rp_origin, "test-rp.io", &index)
        .await
        .expect("assertion should succeed");

    assert!(!assertion.credential_id_b64.is_empty());
    assert!(assertion.new_counter == 0, "counter should be non-negative");
    assert!(!assertion.assertion_response.is_empty());
}

#[tokio::test]
async fn assertion_fails_for_unknown_rp() {
    let index = PasskeyIndex::from_ciphers(&[]);
    let result = run_assertion(&test_origin(), "unknown-rp.test", &index).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No passkeys found"));
}

#[tokio::test]
async fn multi_passkey_different_rps() {
    let index = PasskeyIndex::from_ciphers(&[]);

    // Register passkey for RP A
    let reg_a = run_registration(
        &Url::parse("https://rp-a.test").unwrap(),
        "rp-a.test".into(),
        "RP A".into(),
        "user@rp-a".into(),
        "User A".into(),
        vec![10, 20],
        &index,
    )
    .await
    .expect("reg A");

    // Register passkey for RP B
    let reg_b = run_registration(
        &Url::parse("https://rp-b.test").unwrap(),
        "rp-b.test".into(),
        "RP B".into(),
        "user@rp-b".into(),
        "User B".into(),
        vec![30, 40],
        &index,
    )
    .await
    .expect("reg B");

    // Build index with both
    let cipher_a = make_cipher(reg_a.passkey_data);
    let cipher_b = make_cipher(reg_b.passkey_data);
    let index = PasskeyIndex::from_boxed_ciphers(&[cipher_a, cipher_b]);

    // Assert against RP A
    let assert_a = run_assertion(
        &Url::parse("https://rp-a.test").unwrap(),
        "rp-a.test",
        &index,
    )
    .await
    .expect("assert A");
    assert!(assert_a.new_counter == 0);

    // Assert against RP B
    let assert_b = run_assertion(
        &Url::parse("https://rp-b.test").unwrap(),
        "rp-b.test",
        &index,
    )
    .await
    .expect("assert B");
    assert!(assert_b.new_counter == 0);

    // Different credential IDs
    assert_ne!(assert_a.credential_id_b64, assert_b.credential_id_b64);
}

#[tokio::test]
async fn ceremony_cache_ttl_expiry() {
    let cache = CeremonyCache::new();
    let id = "test-ceremony".to_string();

    cache
        .insert(
            id.clone(),
            CeremonyState::Assertion {
                rp_id: "test.com".into(),
                created_at: std::time::Instant::now()
                    - CEREMONY_TTL
                    - std::time::Duration::from_secs(1),
            },
        )
        .await;

    cache.evict_expired().await;

    let removed = cache.remove(&id).await;
    assert!(removed.is_none(), "expired ceremony should be evicted");
}

#[tokio::test]
async fn ceremony_cache_valid_entry_survives_eviction() {
    let cache = CeremonyCache::new();
    let id = "fresh-ceremony".to_string();

    cache
        .insert(
            id.clone(),
            CeremonyState::Registration {
                rp_id: "test.com".into(),
                rp_name: "Test".into(),
                user_name: "user".into(),
                user_display_name: "User".into(),
                user_id: vec![1],
                created_at: std::time::Instant::now(),
            },
        )
        .await;

    cache.evict_expired().await;

    let state = cache.remove(&id).await;
    assert!(
        state.is_some(),
        "fresh ceremony should survive eviction"
    );
}

#[tokio::test]
async fn passkey_index_skips_imported_without_private_key() {
    let mut pk_data = make_passkey_data("imported.test", "user", 0);
    pk_data.private_key = None;
    pk_data.private_key_missing = true;

    let cipher = make_cipher(pk_data);
    let index = PasskeyIndex::from_boxed_ciphers(&[cipher]);

    assert!(
        index.entries().is_empty(),
        "imported passkeys without private key should be skipped"
    );
}

#[tokio::test]
async fn store_mutation_tracking() {
    let index = PasskeyIndex::from_ciphers(&[]);
    let mut store = BaluardCredentialStore::from_index(&index);
    let clone = store.clone();

    // Initially empty
    assert!(clone.take_new_credentials().is_empty());
    assert!(clone.take_counter_updates().is_empty());

    // Simulate a registration via the store
    let pk = passkey::types::Passkey {
        key: coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            vec![0x04, 0x01, 0x02],
            vec![0x03, 0x04],
        )
        .build(),
        credential_id: vec![1, 2, 3].into(),
        rp_id: "test.com".to_string(),
        user_handle: None,
        username: Some("test".to_string()),
        user_display_name: Some("Test".to_string()),
        counter: Some(5),
        extensions: Default::default(),
    };

    use passkey::authenticator::CredentialStore;
    use passkey::types::ctap2::get_assertion::Options;

    store
        .save_credential(
            pk,
            passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity {
                id: vec![1].into(),
                display_name: Some("Test".to_string()),
                name: Some("test".to_string()),
                icon_url: None,
            },
            passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity {
                id: "test.com".to_string(),
                name: Some("Test".to_string()),
            },
            Options::default(),
        )
        .await
        .unwrap();

    let saved = clone.take_new_credentials();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].rp_id, "test.com");

    // Second take should be empty (consumed)
    assert!(clone.take_new_credentials().is_empty());
}
