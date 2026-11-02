//! Phase 0.3 spike: evaluate `passkey` crate (1Password-maintained) for
//! Baluard's WebAuthn authenticator role.
//!
//! Integration pattern tested: webauthn-rs generates the challenge and
//! verifies the response. passkey-rs drives the ceremony (client +
//! authenticator + credential store). The bridge between them is the
//! JSON-serializable types.
//!
//! See `docs/adr/0095-passkey-support.md` Phase 0 and
//! `docs/adr/0094-passkey-rs-evaluation.md` for the verdict.

#![allow(clippy::needless_update)]

use passkey::authenticator::{Authenticator, MemoryStore, UserCheck, UserValidationMethod};
use passkey::client::{Client, DefaultClientData};
use passkey::types::Bytes;
use passkey::types::ctap2::Aaguid;
use passkey::types::webauthn::{
    AttestationConveyancePreference, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserVerificationRequirement,
};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Stub user-validation method. In Baluard this is replaced by the OS
/// biometric gate (Touch ID / Windows Hello) plus, on Linux, the master
/// password re-prompt per `docs/adr/0095-passkey-support.md` §3.1.
#[derive(Clone)]
struct AllowUserVerification;

#[async_trait::async_trait]
impl UserValidationMethod for AllowUserVerification {
    type PasskeyItem = passkey::types::Passkey;

    async fn check_user<'a>(
        &self,
        _hint: passkey::authenticator::UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, passkey::types::ctap2::Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

fn make_rp() -> (Url, Webauthn) {
    let rp_id = "baluard-spike.test".to_string();
    let rp_origin_str = format!("https://{rp_id}");
    let rp_origin = Url::parse(&rp_origin_str).unwrap();
    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("rp origin parses")
        .rp_name("Baluard Spike")
        .build()
        .expect("webauthn build");
    (rp_origin, webauthn)
}

fn make_client() -> (
    Client<MemoryStore, AllowUserVerification, public_suffix::PublicSuffixList, ()>,
    MemoryStore,
) {
    let aaguid = Aaguid::new_empty();
    let store = MemoryStore::new();
    let authenticator = Authenticator::new(aaguid, store.clone(), AllowUserVerification);
    let client = Client::new(authenticator);
    (client, store)
}

/// Convert a `webauthn-rs` CreationChallengeResponse to a passkey-rs
/// `CredentialCreationOptions`. The two types represent the same
/// underlying WebAuthn dict; they live in different crates; we bridge by
/// JSON.
fn challenge_to_passkey_options(
    chal: &CreationChallengeResponse,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> CredentialCreationOptions {
    let v: serde_json::Value =
        serde_json::to_value(chal.public_key.clone()).expect("serialize CreationChallengeResponse");
    let mut opts: PublicKeyCredentialCreationOptions =
        serde_json::from_value(v).expect("deserialize into passkey types");
    // Override the user (webauthn-rs uses the empty default; passkey-rs
    // requires a non-empty user entity).
    opts.user = PublicKeyCredentialUserEntity {
        id: Bytes::from(user_id.to_vec()),
        display_name: user_display_name.to_string(),
        name: user_name.to_string(),
    };
    // Per docs/adr/0095-passkey-support.md §4.5: always set resident+UV.
    opts.authenticator_selection = Some(AuthenticatorSelectionCriteria {
        authenticator_attachment: Some(AuthenticatorAttachment::Platform),
        resident_key: Some(ResidentKeyRequirement::Required),
        require_resident_key: true,
        user_verification: UserVerificationRequirement::Required,
    });
    // passkey-rs only supports ES256 (ECDSA w/ SHA-256). Keep whatever
    // the RP sent; the passkey authenticator will pick ES256 from the list.
    opts.attestation = AttestationConveyancePreference::None;
    opts.extensions = None;
    opts.hints = None;
    opts.attestation_formats = None;
    opts.exclude_credentials = None;
    opts.timeout = None;
    CredentialCreationOptions { public_key: opts }
}

/// The webauthn-rs `start_passkey_authentication` returns an
/// (RequestChallengeResponse, PasskeyAuthentication). The
/// RequestChallengeResponse has `public_key` field with
/// `PublicKeyCredentialRequestOptions`. We need to convert to passkey-rs
/// types.
fn auth_challenge_to_passkey_options(chal: &RequestChallengeResponse) -> CredentialRequestOptions {
    let v: serde_json::Value =
        serde_json::to_value(&chal.public_key).expect("serialize RequestChallengeResponse");
    let mut opts: passkey::types::webauthn::PublicKeyCredentialRequestOptions =
        serde_json::from_value(v).expect("deserialize into passkey types");
    opts.user_verification = UserVerificationRequirement::Required;
    opts.attestation = Default::default();
    opts.attestation_formats = None;
    opts.hints = None;
    CredentialRequestOptions { public_key: opts }
}

#[tokio::test]
async fn registration_round_trips_through_webauthn_rs() {
    let (rp_origin, webauthn) = make_rp();
    let (mut client, _store) = make_client();
    // _store shares the same Arc<MemoryStore> as client's internal
    // authenticator; not used directly but keeps the allocation alive.
    let user_uuid = Uuid::new_v4();
    let (chal, reg_state) = webauthn
        .start_passkey_registration(user_uuid, "spike@baluard.test", "Spike User", None)
        .expect("start reg");

    let opts = challenge_to_passkey_options(
        &chal,
        user_uuid.as_bytes(),
        "spike@baluard.test",
        "Spike User",
    );

    let created = client
        .register(&rp_origin, opts, DefaultClientData)
        .await
        .expect("register");

    // Bridge: serialize the passkey-rs CreatedPublicKeyCredential and
    // deserialize as webauthn-rs RegisterPublicKeyCredential.
    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&created).unwrap())
            .expect("bridge to webauthn-rs type");

    let _passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .expect("webauthn-rs must accept passkey-rs registration");
}

#[tokio::test]
async fn assertion_round_trips_through_webauthn_rs() {
    let (rp_origin, webauthn) = make_rp();
    let (mut client, _store) = make_client();
    // _store shares the same Arc<MemoryStore> as client's internal
    // authenticator; not used directly but keeps the allocation alive.
    let user_uuid = Uuid::new_v4();
    let (chal, reg_state) = webauthn
        .start_passkey_registration(user_uuid, "spike@baluard.test", "Spike User", None)
        .expect("start reg");

    let opts = challenge_to_passkey_options(
        &chal,
        user_uuid.as_bytes(),
        "spike@baluard.test",
        "Spike User",
    );

    let created = client
        .register(&rp_origin, opts, DefaultClientData)
        .await
        .expect("register");

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&created).unwrap())
            .expect("bridge to webauthn-rs type");

    let stored_passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .expect("finish reg");

    // --- Assertion ---
    let allow_credentials = vec![stored_passkey.clone()];
    let (auth_chal, auth_state) = webauthn
        .start_passkey_authentication(&allow_credentials)
        .expect("start auth");

    let auth_opts = auth_challenge_to_passkey_options(&auth_chal);

    let authenticated = client
        .authenticate(&rp_origin, auth_opts, DefaultClientData)
        .await
        .expect("authenticate");

    let auth_response: PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&authenticated).unwrap())
            .expect("bridge to webauthn-rs type");

    let _auth_result = webauthn
        .finish_passkey_authentication(&auth_response, &auth_state)
        .expect("webauthn-rs must accept passkey-rs assertion");

    let _ = stored_passkey;
}
