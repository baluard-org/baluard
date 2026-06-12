//! WebAuthn ceremony types, state cache, and ceremony runner.
//!
//! The daemon builds a `BaluardCredentialStore` from the vault's passkey
//! index, passes it to the `passkey-rs` Client for the ceremony, then
//! writes back any changes. Ceremony state lives in a TTL cache (300s).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use coset::iana;
use passkey::authenticator::{Authenticator, UserCheck, UserValidationMethod};
use passkey::client::{Client, DefaultClientData};
use passkey::types::ctap2::Aaguid;
use passkey::types::webauthn::{
    AttestationConveyancePreference, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserVerificationRequirement,
};
use passkey::types::Bytes;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

use crate::types::PasskeyData;

use super::store::{self, BaluardCredentialStore, PasskeyIndex};

/// TTL for pending ceremony states.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Baluard platform AAGUID (all zeros = self-attestation, no vendor tracking).
pub const BALUARD_AAGUID: Aaguid = Aaguid::new_empty();

/// Pending ceremony state.
#[derive(Debug)]
pub enum CeremonyState {
    Registration {
        rp_id: String,
        rp_name: String,
        user_name: String,
        user_display_name: String,
        user_id: Vec<u8>,
        created_at: Instant,
    },
    Assertion {
        rp_id: String,
        created_at: Instant,
    },
}

impl CeremonyState {
    pub fn is_expired(&self) -> bool {
        let at = match self {
            Self::Registration { created_at, .. } => created_at,
            Self::Assertion { created_at, .. } => created_at,
        };
        at.elapsed() > CEREMONY_TTL
    }
}

/// Opaque handle returned by start_* and passed to finish_*.
/// Must be generated from CSRNG (32 bytes hex minimum) when wired.
pub type CeremonyId = String;

/// Ceremony state cache. Lives in the daemon's VaultState.
pub struct CeremonyCache {
    states: RwLock<HashMap<CeremonyId, CeremonyState>>,
}

impl CeremonyCache {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert(&self, id: CeremonyId, state: CeremonyState) {
        self.states.write().await.insert(id, state);
    }

    pub async fn remove(&self, id: &str) -> Option<CeremonyState> {
        self.states.write().await.remove(id)
    }

    /// Evict expired entries. Call at ceremony entry points.
    pub async fn evict_expired(&self) {
        self.states
            .write()
            .await
            .retain(|_, s| !s.is_expired());
    }
}

/// Result of a successful registration ceremony.
pub struct RegistrationResult {
    /// New passkey data ready for vault storage.
    pub passkey_data: PasskeyData,
    /// Base64url-encoded credential ID (for display/logging).
    pub credential_id_b64: String,
    /// The authenticator response to return to the RP (JSON).
    pub attestation_response: String,
}

/// Result of a successful assertion ceremony.
pub struct AssertionResult {
    /// Base64url-encoded credential ID that was used.
    pub credential_id_b64: String,
    /// Updated signature counter.
    pub new_counter: u32,
    /// The authenticator response to return to the RP (JSON).
    pub assertion_response: String,
}

// ── User validation ──

/// Phase 1 user validation: always allows (no biometric gate).
/// Phase 2 will replace this with OS biometric / master password re-prompt.
#[derive(Clone)]
pub struct BaluardUserValidation;

#[async_trait::async_trait]
impl UserValidationMethod for BaluardUserValidation {
    type PasskeyItem = passkey::types::Passkey;

    async fn check_user<'a>(
        &self,
        _hint: passkey::authenticator::UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, passkey::types::ctap2::Ctap2Error> {
        // Phase 1: always allow. No biometric prompt.
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

// ── Ceremony runner ──

/// Run a registration ceremony.
///
/// Takes the RP details, constructs options, runs the passkey-rs ceremony,
/// and returns the result ready for vault storage.
pub async fn run_registration(
    origin: &Url,
    rp_id: String,
    rp_name: String,
    user_name: String,
    user_display_name: String,
    user_id: Vec<u8>,
    index: &PasskeyIndex,
) -> Result<RegistrationResult, String> {
    let store = BaluardCredentialStore::from_index(index);
    let extraction_clone = store.clone();

    let authenticator = Authenticator::new(BALUARD_AAGUID, store, BaluardUserValidation);
    let mut client = Client::new(authenticator);

    let options = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: passkey::types::webauthn::PublicKeyCredentialRpEntity {
                id: Some(rp_id.clone()),
                name: rp_name.clone(),
            },
            user: PublicKeyCredentialUserEntity {
                id: Bytes::from(user_id),
                display_name: user_display_name.clone(),
                name: user_name.clone(),
            },
            challenge: Bytes::from(rand::random::<[u8; 32]>().to_vec()),
            pub_key_cred_params: vec![passkey::types::webauthn::PublicKeyCredentialParameters {
                ty: passkey::types::webauthn::PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::ES256,
            }],
            timeout: Some(60_000),
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some(AuthenticatorAttachment::Platform),
                resident_key: Some(ResidentKeyRequirement::Required),
                require_resident_key: true,
                user_verification: UserVerificationRequirement::Required,
            }),
            attestation: AttestationConveyancePreference::None,
            extensions: None,
            hints: None,
            attestation_formats: None,
        },
    };

    let created = client
        .register(origin, options, DefaultClientData)
        .await
        .map_err(|e| format!("Registration failed: {:?}", e))?;

    // Extract the new passkey from the store
    let new_creds = extraction_clone.take_new_credentials();
    let passkey = new_creds
        .into_iter()
        .next()
        .ok_or("Registration produced no credential")?;

    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&*passkey.credential_id);

    let passkey_data = store::passkey_to_passkey_data(&passkey, Some(&rp_name))
        .ok_or("Failed to convert ceremony result to PasskeyData")?;

    let attestation_response = serde_json::to_string(&created)
        .map_err(|e| format!("Failed to serialize attestation response: {e}"))?;

    Ok(RegistrationResult {
        passkey_data,
        credential_id_b64,
        attestation_response,
    })
}

/// Run an assertion ceremony.
///
/// Takes the RP ID and origin, loads matching passkeys from the vault,
/// runs the passkey-rs assertion ceremony, and returns the result.
pub async fn run_assertion(
    origin: &Url,
    rp_id: &str,
    index: &PasskeyIndex,
) -> Result<AssertionResult, String> {
    // Check that we have credentials for this RP
    if index.by_rp(rp_id).is_empty() {
        return Err(format!("No passkeys found for RP: {rp_id}"));
    }

    let store = BaluardCredentialStore::from_index(index);
    let extraction_clone = store.clone();

    let authenticator = Authenticator::new(BALUARD_AAGUID, store, BaluardUserValidation);
    let mut client = Client::new(authenticator);

    let options = CredentialRequestOptions {
        public_key: passkey::types::webauthn::PublicKeyCredentialRequestOptions {
            challenge: Bytes::from(rand::random::<[u8; 32]>().to_vec()),
            rp_id: Some(rp_id.to_string()),
            allow_credentials: None, // None = discoverable
            timeout: Some(60_000),
            user_verification: UserVerificationRequirement::Required,
            attestation: Default::default(),
            attestation_formats: None,
            hints: None,
            extensions: None,
        },
    };

    let authenticated = client
        .authenticate(origin, options, DefaultClientData)
        .await
        .map_err(|e| format!("Assertion failed: {:?}", e))?;

    // Extract counter updates from the store
    let counter_updates = extraction_clone.take_counter_updates();

    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&*authenticated.raw_id);

    let new_counter = counter_updates
        .values()
        .next()
        .copied()
        .unwrap_or(0);

    let assertion_response = serde_json::to_string(&authenticated)
        .map_err(|e| format!("Failed to serialize assertion response: {e}"))?;

    Ok(AssertionResult {
        credential_id_b64,
        new_counter,
        assertion_response,
    })
}
