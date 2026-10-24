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
use passkey::client::{Client, DefaultClientData, DefaultClientDataWithCustomHash};
use passkey::types::Bytes;
use passkey::types::ctap2::Aaguid;
use passkey::types::webauthn::{
    AttestationConveyancePreference, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

use crate::types::PasskeyData;

use super::store::{self, BaluardCredentialStore, PasskeyIndex};

/// TTL for pending ceremony states.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Baluard platform AAGUID (all zeros = self-attestation, no vendor tracking).
pub const BALUARD_AAGUID: Aaguid = Aaguid::new_empty();

/// Pending ceremony state.
#[derive(Clone)]
pub enum CeremonyState {
    Registration {
        rp_id: String,
        rp_name: String,
        user_name: String,
        user_display_name: String,
        user_id: Vec<u8>,
        // The fresh credential stays Rust-side behind the ceremony id
        // (SEC-1): the registration response redacts key material and
        // finish_register takes the passkey from here, never from the
        // client echo.
        passkey_data: Box<PasskeyData>,
        created_at: Instant,
    },
    Assertion {
        rp_id: String,
        created_at: Instant,
    },
    /// Provider-grade pending registration: the fresh credential stays
    /// Rust-side behind the ceremony id (SEC-1 — key material never crosses
    /// the FFI/webview boundary) until store_registered consumes it.
    ProviderRegistration {
        // Boxed: PasskeyData dominates the enum size and the cache stores
        // many variants side by side.
        passkey_data: Box<PasskeyData>,
        rp_id: String,
        user_name: String,
        created_at: Instant,
    },
    /// Provider-grade pending assertion: records which vault entry served so
    /// a nonzero counter could be recorded at consume time (synced-model
    /// counters stay zero, so this is normally a no-op).
    ProviderAssertion {
        cipher_id: uuid::Uuid,
        credential_id: String,
        new_counter: u32,
        created_at: Instant,
    },
}

impl std::fmt::Debug for CeremonyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl: the provider variant holds PasskeyData whose derived
        // Debug would print the private key.
        match self {
            Self::Registration {
                rp_id, user_name, ..
            } => f
                .debug_struct("Registration")
                .field("rp_id", rp_id)
                .field("user_name", user_name)
                .finish(),
            Self::Assertion { rp_id, .. } => {
                f.debug_struct("Assertion").field("rp_id", rp_id).finish()
            }
            Self::ProviderRegistration {
                rp_id, user_name, ..
            } => f
                .debug_struct("ProviderRegistration")
                .field("rp_id", rp_id)
                .field("user_name", user_name)
                .finish(),
            Self::ProviderAssertion {
                credential_id,
                new_counter,
                ..
            } => f
                .debug_struct("ProviderAssertion")
                .field("credential_id", credential_id)
                .field("new_counter", new_counter)
                .finish(),
        }
    }
}

impl CeremonyState {
    pub fn is_expired(&self) -> bool {
        self.created_at().elapsed() > CEREMONY_TTL
    }

    pub fn created_at(&self) -> Instant {
        match self {
            Self::Registration { created_at, .. }
            | Self::Assertion { created_at, .. }
            | Self::ProviderRegistration { created_at, .. }
            | Self::ProviderAssertion { created_at, .. } => *created_at,
        }
    }
}

/// Opaque handle returned by start_* and passed to finish_*.
/// Must be generated from CSRNG (32 bytes hex minimum) when wired.
pub type CeremonyId = String;

/// Ceremony state cache. Lives in the daemon's VaultState.
/// Max 64 pending ceremonies per vault, FIFO eviction when full.
pub const MAX_PENDING_CEREMONIES: usize = 64;

pub struct CeremonyCache {
    states: RwLock<HashMap<CeremonyId, CeremonyState>>,
}

impl Default for CeremonyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CeremonyCache {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }
    pub async fn insert(&self, id: CeremonyId, state: CeremonyState) {
        let mut states = self.states.write().await;
        // FIFO eviction if at capacity
        while states.len() >= MAX_PENDING_CEREMONIES {
            // Evict oldest entry (lowest Instant)
            if let Some(oldest_key) = states
                .iter()
                .filter(|(_, s)| s.is_expired())
                .map(|(k, _)| k.clone())
                .next()
            {
                states.remove(&oldest_key);
            } else {
                // No expired entries; evict the oldest by creation time
                let oldest = states
                    .iter()
                    .min_by_key(|(_, s)| s.created_at())
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest {
                    states.remove(&key);
                } else {
                    break;
                }
            }
        }
        states.insert(id, state);
    }

    pub async fn remove(&self, id: &str) -> Option<CeremonyState> {
        self.states.write().await.remove(id)
    }

    /// Clone out the state WITHOUT consuming it: callers validate everything
    /// (vault unlocked, ids well-formed) before `remove`, so a failed store
    /// never destroys the pending ceremony.
    pub async fn get(&self, id: &str) -> Option<CeremonyState>
    where
        CeremonyState: Clone,
    {
        self.states.read().await.get(id).cloned()
    }

    /// Evict expired entries. Call at ceremony entry points.
    pub async fn evict_expired(&self) {
        self.states.write().await.retain(|_, s| !s.is_expired());
    }
}

/// Result of a successful registration ceremony.
#[derive(Debug)]
pub struct RegistrationResult {
    /// New passkey data ready for vault storage.
    pub passkey_data: PasskeyData,
    /// Base64url-encoded credential ID (for display/logging).
    pub credential_id_b64: String,
    /// The authenticator response to return to the RP (JSON).
    pub attestation_response: String,
}

/// Result of a successful assertion ceremony.
#[derive(Debug)]
pub struct AssertionResult {
    /// Base64url-encoded credential ID that was used.
    pub credential_id_b64: String,
    /// Updated signature counter.
    pub new_counter: u32,
    /// The authenticator response to return to the RP (JSON).
    pub assertion_response: String,
}

// ── User validation ──

/// Ceremony user validation.
///
/// `user_verified` is the per-call UV grant (plan-mobile-passkeys §5): the
/// system sheet's biometric prompt or the in-app fallback decides it per
/// request, so `Required` plus `false` fails the ceremony instead of silently
/// passing. The two-phase desktop routes use `default()` (always verified),
/// keeping their Phase-1 contract.
#[derive(Clone, Copy)]
pub struct BaluardUserValidation {
    user_verified: bool,
}

impl Default for BaluardUserValidation {
    fn default() -> Self {
        Self {
            user_verified: true,
        }
    }
}

impl BaluardUserValidation {
    pub fn with_user_verified(user_verified: bool) -> Self {
        Self { user_verified }
    }
}

#[async_trait::async_trait]
impl UserValidationMethod for BaluardUserValidation {
    type PasskeyItem = passkey::types::Passkey;

    async fn check_user<'a>(
        &self,
        _hint: passkey::authenticator::UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, passkey::types::ctap2::Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: self.user_verified,
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

    let authenticator = Authenticator::new(BALUARD_AAGUID, store, BaluardUserValidation::default());
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
            challenge: Bytes::from({
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                buf.to_vec()
            }),
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

    let credential_id_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*passkey.credential_id);

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

    let authenticator = Authenticator::new(BALUARD_AAGUID, store, BaluardUserValidation::default());
    let mut client = Client::new(authenticator);

    let options = CredentialRequestOptions {
        public_key: passkey::types::webauthn::PublicKeyCredentialRequestOptions {
            challenge: Bytes::from({
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                buf.to_vec()
            }),
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

    let credential_id_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*authenticated.raw_id);

    let new_counter = counter_updates
        .get(&*authenticated.raw_id)
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

// ── Provider-grade ceremonies (plan-mobile-passkeys §8) ──
//
// The credential-provider surface signs the RP's own request: challenge and
// client-data come from the caller, UV follows the request and a per-call
// grant, and credentials are pinned to the user's selection. The two-phase
// functions above remain the desktop contract.

/// Result of a provider registration ceremony.
pub struct ProviderRegistrationResult {
    pub passkey_data: PasskeyData,
    pub credential_id_b64: String,
    pub rp_id: String,
    pub user_name: String,
    /// `PublicKeyCredential.toJSON()`-shaped JSON (camelCase, clientDataJSON,
    /// attestationObject, ...) — the shape passkey-rs serializes natively.
    pub attestation_response: String,
}

impl std::fmt::Debug for ProviderRegistrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // passkey_data carries the private key; its derived Debug must never
        // reach a log line (same masking rule as CeremonyState).
        f.debug_struct("ProviderRegistrationResult")
            .field("passkey_data", &"[masked]")
            .field("credential_id_b64", &self.credential_id_b64)
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .finish_non_exhaustive()
    }
}

/// Result of a provider assertion ceremony.
#[derive(Debug)]
pub struct ProviderAssertionResult {
    pub credential_id_b64: String,
    /// The vault cipher that served the assertion.
    pub cipher_id: uuid::Uuid,
    /// Synced-model credentials keep the signature counter at zero (W3C L3
    /// multi-device guidance); passkey-rs only increments when the
    /// authenticator opts into a signature counter, which we never do.
    pub new_counter: u32,
    pub assertion_response: String,
}

/// The WebAuthn rp.id rule: either the origin's effective domain, or a
/// registered domain that is a dot-boundary suffix of it. Mirrors the check
/// passkey-rs' RpIdVerifier applies at ceremony time; running it first gives
/// callers a plain-language error instead of a library enum.
fn effective_rp_id(origin: &Url, rp_id: Option<&str>) -> Result<String, String> {
    // Android credential-manager origins carry the app identity, not a web
    // domain: rp.id is mandatory there and the app-identity check (asset
    // links) belongs to the platform service layer.
    if origin.scheme() == "android" {
        return rp_id
            .map(str::to_string)
            .ok_or_else(|| "android origins require rp.id".to_string());
    }
    let domain = origin
        .domain()
        .or_else(|| origin.host_str())
        .ok_or_else(|| "origin carries no domain".to_string())?
        .to_ascii_lowercase();
    match rp_id {
        Some(id) => {
            let id = id.to_ascii_lowercase();
            if domain == id {
                return Ok(id);
            }
            // WebAuthn L3 5.1.4.1: rp.id must be a registrable suffix of the
            // origin. A public suffix itself (com, github.io, co.uk) can
            // never host credentials, so cross-tenant claims are refused.
            use public_suffix::EffectiveTLDProvider;
            let registrable = public_suffix::DEFAULT_PROVIDER
                .effective_tld_plus_one(&id)
                .is_ok();
            if domain.ends_with(&format!(".{id}")) && registrable {
                Ok(id)
            } else {
                Err(format!("rp.id {id} is not valid for origin {domain}"))
            }
        }
        None => Ok(domain),
    }
}

fn decode_credential_id_b64(b64: &str) -> Result<Vec<u8>, String> {
    // Java/Android platform encoders pad base64url; strip before decoding.
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| "credential id is not valid base64url".to_string())
}

/// Privileged-browser callers hand us the clientDataJSON bytes they will
/// serve to the relying party; the response must carry those exact bytes or
/// the RP's signature check (sha256 over the served JSON) fails.
fn override_client_data_json(
    response: &mut serde_json::Value,
    client_data_json: Option<&[u8]>,
) -> Result<(), String> {
    let Some(cdj) = client_data_json else {
        return Ok(());
    };
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cdj);
    let Some(res) = response.get_mut("response").and_then(|r| r.as_object_mut()) else {
        return Err("ceremony response carries no response object".to_string());
    };
    res.insert(
        "clientDataJSON".to_string(),
        serde_json::Value::String(encoded),
    );
    Ok(())
}

/// Run a provider registration ceremony.
///
/// `request_json` is the `PublicKeyCredentialCreationOptions` — the INNER
/// WebAuthn options without the W3C `CredentialCreationOptions` `publicKey`
/// wrapper, which is what the Android credential manager delivers (androidx
/// validates `user.name` at the top level).
/// `client_data_json` is set by privileged browser callers that build their
/// own client data: the signature covers its SHA-256 and the response's
/// `clientDataJSON` is replaced with these exact bytes, so the relying party
/// verifies the signature against the JSON it sent. Provider passkeys are
/// always discoverable, so `residentKey` is forced to `required` regardless
/// of the request (a password manager must surface account selection); the
/// synced-model flags and zero counter come from passkey-rs' defaults.
pub async fn run_provider_registration(
    origin: &Url,
    request_json: &str,
    client_data_json: Option<Vec<u8>>,
    client_data_hash: Option<Vec<u8>>,
    user_verified: bool,
    index: &PasskeyIndex,
) -> Result<ProviderRegistrationResult, String> {
    let mut public_key: PublicKeyCredentialCreationOptions =
        serde_json::from_str(request_json).map_err(|e| format!("Invalid create options: {e}"))?;
    let rp_id = effective_rp_id(origin, public_key.rp.id.as_deref())?;

    // Fail-closed duplicate refusal before any key material is minted. The
    // library's own exclude check merely consults the UI hint and proceeds.
    if let Some(exclude) = &public_key.exclude_credentials {
        for desc in exclude {
            if let Some((pk, _, _)) = index.entries().get(&*desc.id) {
                if pk.rp_id == rp_id {
                    return Err("a passkey for this site already exists in the vault; \
                         replace it instead of creating a duplicate"
                        .to_string());
                }
            }
        }
    }

    let rp_name = public_key.rp.name.clone();
    let user_name = public_key.user.name.clone();

    // Force discoverable storage for account selection (map_rk reads this).
    let mut selection = public_key
        .authenticator_selection
        .take()
        .unwrap_or_default();
    selection.resident_key = Some(ResidentKeyRequirement::Required);
    selection.require_resident_key = true;
    public_key.authenticator_selection = Some(selection);

    let store = BaluardCredentialStore::from_index(index);
    let extraction_clone = store.clone();
    let authenticator = Authenticator::new(
        BALUARD_AAGUID,
        store,
        BaluardUserValidation::with_user_verified(user_verified),
    );
    // The provider path validates caller origins platform-side; the loopback
    // E2E affordance (plan §12) needs passkey-rs' web-origin check to accept
    // the https://localhost ceremony origin.
    let mut client = Client::new(authenticator).allows_insecure_localhost(true);

    let cdj_ref = client_data_json.as_deref();
    // Browser provider flows hand only the digest of their own client data
    // (the framework's getClientDataHash); the browser replaces the served
    // clientDataJSON with its own when forwarding, so signing the given hash
    // is the correct behavior there. Callers supplying full bytes take the
    // override path below.
    // passkey-rs' Client::register takes the W3C wrapper; re-wrap the parsed
    // inner options at the call boundary (one branch executes, so build
    // per-branch).
    let created = if let Some(hash) = client_data_hash.as_deref() {
        client
            .register(
                origin,
                CredentialCreationOptions { public_key },
                DefaultClientDataWithCustomHash(hash.to_vec()),
            )
            .await
    } else if let Some(cdj) = cdj_ref {
        let hash = Sha256::digest(cdj).to_vec();
        client
            .register(
                origin,
                CredentialCreationOptions { public_key },
                DefaultClientDataWithCustomHash(hash),
            )
            .await
    } else {
        client
            .register(
                origin,
                CredentialCreationOptions { public_key },
                DefaultClientData,
            )
            .await
    }
    .map_err(|e| format!("Registration failed: {e:?}"))?;

    let new_creds = extraction_clone.take_new_credentials();
    let passkey = new_creds
        .into_iter()
        .next()
        .ok_or("Registration produced no credential")?;

    let credential_id_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*passkey.credential_id);

    let passkey_data = store::passkey_to_passkey_data(&passkey, Some(&rp_name))
        .ok_or("Failed to convert ceremony result to PasskeyData")?;

    let mut attestation = serde_json::to_value(&created)
        .map_err(|e| format!("Failed to serialize attestation response: {e}"))?;
    override_client_data_json(&mut attestation, cdj_ref)?;
    let attestation_response = serde_json::to_string(&attestation)
        .map_err(|e| format!("Failed to serialize attestation response: {e}"))?;

    Ok(ProviderRegistrationResult {
        passkey_data,
        credential_id_b64,
        rp_id,
        user_name,
        attestation_response,
    })
}

/// Run a provider assertion ceremony for one selected credential.
///
/// `request_json` is the RP's `publicKey` request options. The ceremony is
/// pinned to `credential_id_b64`: it must exist in the vault under the
/// request's rp.id, and when the request carries a non-empty
/// `allowCredentials` list the selected id must be on it. The store is
/// narrowed to the single credential so the authenticator cannot serve any
/// other entry. `client_data_json` (privileged browser callers) replaces the
/// synthesized client data exactly as in registration.
pub async fn run_provider_assertion(
    origin: &Url,
    request_json: &str,
    credential_id_b64: &str,
    client_data_json: Option<Vec<u8>>,
    client_data_hash: Option<Vec<u8>>,
    user_verified: bool,
    index: &PasskeyIndex,
) -> Result<ProviderAssertionResult, String> {
    let mut options: passkey::types::webauthn::PublicKeyCredentialRequestOptions =
        serde_json::from_str(request_json).map_err(|e| format!("Invalid request options: {e}"))?;
    let rp_id = effective_rp_id(origin, options.rp_id.as_deref())?;

    let cred_bytes = decode_credential_id_b64(credential_id_b64)?;
    let (pk, pk_data, cipher_id) = index
        .entries()
        .get(&cred_bytes)
        .ok_or_else(|| "credential not found in this vault".to_string())?;
    if pk.rp_id != rp_id {
        return Err("credential belongs to a different site".to_string());
    }
    if let Some(allow) = &options.allow_credentials {
        if !allow.is_empty() && !allow.iter().any(|d| *d.id == *cred_bytes) {
            return Err("credential was not requested by this site".to_string());
        }
    }

    // Pin the ceremony to the user's selection. The narrowed credential
    // carries no signature counter: synced-model credentials never increment
    // (passkey-rs only bumps counters that are Some).
    let mut pk_narrowed = pk.clone();
    pk_narrowed.counter = None;
    let narrowed = PasskeyIndex::single(pk_narrowed, pk_data.clone(), *cipher_id);
    let mut options = options;
    options.allow_credentials = Some(vec![PublicKeyCredentialDescriptor {
        ty: PublicKeyCredentialType::PublicKey,
        id: Bytes::from(cred_bytes.clone()),
        transports: None,
    }]);

    let store = BaluardCredentialStore::from_index(&narrowed);
    let extraction_clone = store.clone();
    let authenticator = Authenticator::new(
        BALUARD_AAGUID,
        store,
        BaluardUserValidation::with_user_verified(user_verified),
    );
    // The provider path validates caller origins platform-side; the loopback
    // E2E affordance (plan §12) needs passkey-rs' web-origin check to accept
    // the https://localhost ceremony origin.
    let mut client = Client::new(authenticator).allows_insecure_localhost(true);

    let cdj_ref = client_data_json.as_deref();
    let authenticated = if let Some(hash) = client_data_hash.as_deref() {
        client
            .authenticate(
                origin,
                CredentialRequestOptions {
                    public_key: options,
                },
                DefaultClientDataWithCustomHash(hash.to_vec()),
            )
            .await
    } else if let Some(cdj) = cdj_ref {
        let hash = Sha256::digest(cdj).to_vec();
        client
            .authenticate(
                origin,
                CredentialRequestOptions {
                    public_key: options,
                },
                DefaultClientDataWithCustomHash(hash),
            )
            .await
    } else {
        client
            .authenticate(
                origin,
                CredentialRequestOptions {
                    public_key: options,
                },
                DefaultClientData,
            )
            .await
    }
    .map_err(|e| format!("Assertion failed: {e:?}"))?;

    let counter_updates = extraction_clone.take_counter_updates();
    let credential_id_b64_out =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*authenticated.raw_id);
    let new_counter = counter_updates
        .get(&*authenticated.raw_id)
        .copied()
        .unwrap_or(0);

    let mut assertion = serde_json::to_value(&authenticated)
        .map_err(|e| format!("Failed to serialize assertion response: {e}"))?;
    override_client_data_json(&mut assertion, cdj_ref)?;
    let assertion_response = serde_json::to_string(&assertion)
        .map_err(|e| format!("Failed to serialize assertion response: {e}"))?;

    Ok(ProviderAssertionResult {
        credential_id_b64: credential_id_b64_out,
        cipher_id: *cipher_id,
        new_counter,
        assertion_response,
    })
}

#[cfg(all(test, feature = "passkey-ceremony"))]
mod provider_tests {
    //! Provider-grade ceremony tests (plan-mobile-passkeys section 8 and 13).
    //!
    //! The assertion oracle verifies the ECDSA signature with p256 directly
    //! (dev-dependency) over authData concatenated with clientDataHash,
    //! independently of passkey-rs' own signing path.

    use super::*;
    use crate::crypto::webauthn::store::passkey_data_to_passkey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    const ORIGIN: &str = "https://example.com";
    const RP: &str = "example.com";
    const USER_ID: &[u8] = b"test-user-id-0001";

    fn b64url(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    fn create_options_json(
        challenge: &[u8],
        rp_id: Option<&str>,
        uv: &str,
        exclude_id: Option<&str>,
        alg: i64,
        cred_props: bool,
    ) -> String {
        use serde_json::{Value, json};
        let mut rp = serde_json::Map::new();
        if let Some(id) = rp_id {
            rp.insert("id".into(), json!(id));
        }
        rp.insert("name".into(), json!("Example"));
        let mut pk = serde_json::Map::new();
        pk.insert("rp".into(), Value::Object(rp));
        pk.insert(
            "user".into(),
            json!({"id": b64url(USER_ID), "name": "u@example.com", "displayName": "User One"}),
        );
        pk.insert("challenge".into(), json!(b64url(challenge)));
        pk.insert(
            "pubKeyCredParams".into(),
            json!([{"type": "public-key", "alg": alg}]),
        );
        pk.insert(
            "authenticatorSelection".into(),
            json!({"residentKey": "required", "userVerification": uv}),
        );
        if let Some(id) = exclude_id {
            pk.insert(
                "excludeCredentials".into(),
                json!([{"type": "public-key", "id": id}]),
            );
        }
        if cred_props {
            pk.insert("extensions".into(), json!({"credProps": true}));
        }
        // The Android credential-manager contract delivers the INNER options
        // (no W3C publicKey wrapper); serde parses it directly.
        serde_json::to_string(&Value::Object(pk)).unwrap()
    }

    fn assertion_options_json(
        challenge: &[u8],
        rp_id: Option<&str>,
        uv: &str,
        allow_ids: Option<&[&str]>,
    ) -> String {
        use serde_json::{Value, json};
        let mut o = serde_json::Map::new();
        o.insert("challenge".into(), json!(b64url(challenge)));
        if let Some(id) = rp_id {
            o.insert("rpId".into(), json!(id));
        }
        o.insert("userVerification".into(), json!(uv));
        if let Some(ids) = allow_ids {
            let list: Vec<Value> = ids
                .iter()
                .map(|id| json!({"type": "public-key", "id": id}))
                .collect();
            o.insert("allowCredentials".into(), Value::Array(list));
        }
        serde_json::to_string(&Value::Object(o)).unwrap()
    }

    fn empty_index() -> PasskeyIndex {
        PasskeyIndex::from_ciphers(&[])
    }

    fn index_with(result: &ProviderRegistrationResult) -> PasskeyIndex {
        let pk = passkey_data_to_passkey(&result.passkey_data).expect("index passkey");
        PasskeyIndex::single(pk, result.passkey_data.clone(), Uuid::new_v4())
    }

    fn decode_auth_data(json: &str) -> (Vec<u8>, serde_json::Value) {
        let v: serde_json::Value = serde_json::from_str(json).expect("response json");
        let auth_b64 = v["response"]["authenticatorData"]
            .as_str()
            .expect("authData");
        (URL_SAFE_NO_PAD.decode(auth_b64).expect("authData b64"), v)
    }

    /// authData layout: rpIdHash (32) | flags (1) | counter (4 BE) | ...
    fn flags_byte(auth_data: &[u8]) -> u8 {
        auth_data[32]
    }

    fn counter_bytes(auth_data: &[u8]) -> u32 {
        u32::from_be_bytes(auth_data[33..37].try_into().unwrap())
    }

    fn rp_id_hash_bytes() -> Vec<u8> {
        Sha256::digest(RP.as_bytes()).to_vec()
    }

    /// Locate the embedded authData inside the attestation object CBOR by its
    /// rpIdHash; the flags byte sits exactly 32 bytes after the hash starts.
    fn attestation_flags_byte(attestation_b64: &str) -> u8 {
        let bytes = URL_SAFE_NO_PAD.decode(attestation_b64).expect("attObj");
        let hash = rp_id_hash_bytes();
        let pos = bytes
            .windows(32)
            .position(|w| w == hash.as_slice())
            .expect("rpIdHash inside attestation object");
        bytes[pos + 32]
    }

    fn cose_verifying_key(private_key: &[u8]) -> p256::ecdsa::VerifyingKey {
        use coset::cbor::value::Value;
        use coset::iana::Ec2KeyParameter;
        use coset::{CborSerializable, Label};
        let key = coset::CoseKey::from_slice(private_key).expect("cose key");
        let (mut x, mut y) = (None, None);
        let (xi, yi) = (Ec2KeyParameter::X as i64, Ec2KeyParameter::Y as i64);
        for (k, v) in &key.params {
            match (k, v) {
                (Label::Int(i), Value::Bytes(b)) if *i == xi => x = Some(b.clone()),
                (Label::Int(i), Value::Bytes(b)) if *i == yi => y = Some(b.clone()),
                _ => {}
            }
        }
        let (x, y) = (x.expect("x coordinate"), y.expect("y coordinate"));
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..65].copy_from_slice(&y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("verifying key")
    }

    async fn register_default() -> (url::Url, ProviderRegistrationResult) {
        let origin = url::Url::parse(ORIGIN).unwrap();
        let result = run_provider_registration(
            &origin,
            &create_options_json(&[9u8; 32], Some(RP), "required", None, -7, false),
            None,
            None,
            true,
            &empty_index(),
        )
        .await
        .expect("registration");
        (origin, result)
    }

    #[tokio::test]
    async fn provider_registration_produces_synced_model_and_json_shape() {
        let challenge: [u8; 32] = rand::random();
        let origin = url::Url::parse(ORIGIN).unwrap();
        let result = run_provider_registration(
            &origin,
            &create_options_json(&challenge, Some(RP), "required", None, -7, true),
            None,
            None,
            true,
            &empty_index(),
        )
        .await
        .expect("registration");

        assert_eq!(result.rp_id, RP);
        assert_eq!(result.user_name, "u@example.com");
        assert_eq!(result.passkey_data.counter, 0);
        assert_eq!(result.passkey_data.user_handle.as_deref(), Some(USER_ID));
        assert!(result.passkey_data.private_key.is_some());

        let (auth_data, v) = decode_auth_data(&result.attestation_response);
        // Synced model: BE | BS | UP | UV, counter zero.
        let f = flags_byte(&auth_data);
        assert_ne!(f & 0x08, 0, "Backup Eligibility flag missing");
        assert_ne!(f & 0x10, 0, "Backup State flag missing");
        assert_ne!(f & 0x01, 0, "User Present flag missing");
        assert_ne!(f & 0x04, 0, "User Verified flag missing");
        assert_eq!(counter_bytes(&auth_data), 0);

        let att_obj = v["response"]["attestationObject"].as_str().expect("attObj");
        let af = attestation_flags_byte(att_obj);
        assert_ne!(af & 0x08, 0, "attObj authData missing BE");
        assert_ne!(af & 0x10, 0, "attObj authData missing BS");

        // PublicKeyCredential.toJSON() shape pins.
        assert_eq!(v["type"], "public-key");
        assert_eq!(v["id"], result.credential_id_b64);
        assert!(v["rawId"].is_string());
        assert!(v["response"]["clientDataJSON"].is_string());
        assert!(v["response"]["publicKeyAlgorithm"].is_i64());
        assert_eq!(
            v["clientExtensionResults"]["credProps"]["rk"],
            serde_json::json!(true),
            "credProps.rk must report discoverable storage"
        );

        // The challenge rides the client data verbatim (base64url).
        let cdj: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(v["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cdj["challenge"], serde_json::json!(b64url(&challenge)));
        assert_eq!(cdj["origin"], serde_json::json!(ORIGIN));
        assert_eq!(cdj["type"], serde_json::json!("webauthn.create"));
    }

    #[tokio::test]
    async fn provider_registration_accepts_browser_client_data_json() {
        let origin = url::Url::parse(ORIGIN).unwrap();
        let browser_cdj = b"{\"type\":\"webauthn.create\",\"challenge\":\"x\"}";
        let result = run_provider_registration(
            &origin,
            &create_options_json(&[1u8; 32], Some(RP), "required", None, -7, false),
            Some(browser_cdj.to_vec()),
            None,
            true,
            &empty_index(),
        )
        .await
        .expect("registration with override client data");
        assert_eq!(result.passkey_data.counter, 0);

        // The response carries the browser's clientDataJSON verbatim, so an
        // RP hashing the served JSON gets the hash that was signed.
        let (_, v) = decode_auth_data(&result.attestation_response);
        assert_eq!(
            v["response"]["clientDataJSON"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(browser_cdj)
        );
    }

    #[tokio::test]
    async fn provider_registration_rejects_excluded_duplicate() {
        let (origin, first) = register_default().await;
        let index = index_with(&first);

        let err = run_provider_registration(
            &origin,
            &create_options_json(
                &[8u8; 32],
                Some(RP),
                "required",
                Some(&first.credential_id_b64),
                -7,
                false,
            ),
            None,
            None,
            true,
            &index,
        )
        .await
        .expect_err("duplicate must refuse");
        assert!(err.contains("already exists"), "got: {}", err);
    }

    #[tokio::test]
    async fn provider_registration_rejects_unsupported_algorithm() {
        let origin = url::Url::parse(ORIGIN).unwrap();
        let err = run_provider_registration(
            &origin,
            &create_options_json(&[1u8; 32], Some(RP), "required", None, -257, false),
            None,
            None,
            true,
            &empty_index(),
        )
        .await
        .expect_err("RS256-only request must refuse");
        assert!(err.contains("Registration failed"), "got: {}", err);
    }

    #[tokio::test]
    async fn provider_registration_rp_id_defaults_and_refuses_mismatch() {
        let origin = url::Url::parse(ORIGIN).unwrap();
        let defaulted = run_provider_registration(
            &origin,
            &create_options_json(&[2u8; 32], None, "required", None, -7, false),
            None,
            None,
            true,
            &empty_index(),
        )
        .await
        .expect("registration without rp.id");
        assert_eq!(defaulted.rp_id, RP, "rp.id defaults to the origin domain");

        let err = run_provider_registration(
            &origin,
            &create_options_json(&[3u8; 32], Some("other.com"), "required", None, -7, false),
            None,
            None,
            true,
            &empty_index(),
        )
        .await
        .expect_err("cross-origin rp.id must refuse");
        assert!(err.contains("not valid for origin"), "got: {}", err);
    }

    #[tokio::test]
    async fn provider_registration_honors_uv_grant() {
        let origin = url::Url::parse(ORIGIN).unwrap();
        let err = run_provider_registration(
            &origin,
            &create_options_json(&[4u8; 32], Some(RP), "required", None, -7, false),
            None,
            None,
            false,
            &empty_index(),
        )
        .await
        .expect_err("required UV without a grant must fail");
        assert!(err.contains("Registration failed"), "got: {}", err);

        // Discouraged runs without verification and the UV flag stays clear.
        let result = run_provider_registration(
            &origin,
            &create_options_json(&[5u8; 32], Some(RP), "discouraged", None, -7, false),
            None,
            None,
            false,
            &empty_index(),
        )
        .await
        .expect("discouraged needs no grant");
        let (auth_data, _) = decode_auth_data(&result.attestation_response);
        assert_eq!(flags_byte(&auth_data) & 0x04, 0, "UV flag must stay clear");
        assert_ne!(flags_byte(&auth_data) & 0x01, 0, "UP still set");
    }

    #[tokio::test]
    async fn provider_assertion_oracle_and_pinning() {
        let (origin, reg) = register_default().await;
        let index = index_with(&reg);

        // The selected credential must be on the request's allowCredentials.
        let outsider = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = run_provider_assertion(
            &origin,
            &assertion_options_json(&[10u8; 32], Some(RP), "required", Some(&[outsider])),
            &reg.credential_id_b64,
            None,
            None,
            true,
            &index,
        )
        .await
        .expect_err("unlisted credential must refuse");
        assert!(err.contains("not requested"), "got: {}", err);

        // A credential stored under a different rp than the request's valid
        // rp.id refuses (origin first, then the credential's own rp).
        let foreign = {
            let mut d = reg.passkey_data.clone();
            d.rp_id = "other.com".to_string();
            let pk = passkey_data_to_passkey(&d).expect("foreign passkey");
            PasskeyIndex::single(pk, d, Uuid::new_v4())
        };
        let err = run_provider_assertion(
            &origin,
            &assertion_options_json(&[11u8; 32], Some(RP), "required", None),
            &reg.credential_id_b64,
            None,
            None,
            true,
            &foreign,
        )
        .await
        .expect_err("cross-rp credential must refuse");
        assert!(err.contains("different site"), "got: {}", err);

        // A request naming an rp.id the origin cannot claim refuses outright.
        let err = run_provider_assertion(
            &origin,
            &assertion_options_json(&[11u8; 32], Some("other.com"), "required", None),
            &reg.credential_id_b64,
            None,
            None,
            true,
            &index,
        )
        .await
        .expect_err("cross-origin rp.id must refuse");
        assert!(err.contains("not valid for origin"), "got: {}", err);

        // UV gate.
        let err = run_provider_assertion(
            &origin,
            &assertion_options_json(&[12u8; 32], Some(RP), "required", None),
            &reg.credential_id_b64,
            None,
            None,
            false,
            &index,
        )
        .await
        .expect_err("required UV without a grant must fail");
        assert!(err.contains("Assertion failed"), "got: {}", err);

        // Happy path with the credential listed.
        let assertion = run_provider_assertion(
            &origin,
            &assertion_options_json(
                &[13u8; 32],
                Some(RP),
                "required",
                Some(&[&reg.credential_id_b64]),
            ),
            &reg.credential_id_b64,
            None,
            None,
            true,
            &index,
        )
        .await
        .expect("assertion");
        assert_eq!(assertion.credential_id_b64, reg.credential_id_b64);
        assert_eq!(assertion.new_counter, 0, "synced model keeps counter zero");

        // Oracle: the signature verifies over authData concatenated with
        // SHA-256(clientDataJSON) using the stored credential's public key.
        let (auth_data, v) = decode_auth_data(&assertion.assertion_response);
        assert_ne!(flags_byte(&auth_data) & 0x08, 0, "assertion BE missing");
        assert_ne!(flags_byte(&auth_data) & 0x10, 0, "assertion BS missing");
        assert_eq!(counter_bytes(&auth_data), 0);
        assert_eq!(&auth_data[..32], rp_id_hash_bytes().as_slice());

        let sig = URL_SAFE_NO_PAD
            .decode(v["response"]["signature"].as_str().expect("signature"))
            .expect("signature b64");
        let cdj = URL_SAFE_NO_PAD
            .decode(
                v["response"]["clientDataJSON"]
                    .as_str()
                    .expect("clientDataJSON"),
            )
            .expect("clientDataJSON");
        let user_handle = URL_SAFE_NO_PAD
            .decode(v["response"]["userHandle"].as_str().expect("userHandle"))
            .expect("userHandle");
        assert_eq!(user_handle, USER_ID);

        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(&cdj).as_slice());
        let digest = Sha256::digest(&signed);
        let vk = cose_verifying_key(reg.passkey_data.private_key.as_ref().unwrap());
        let signature = p256::ecdsa::Signature::from_der(&sig).expect("der signature");
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&digest, &signature)
            .expect("assertion signature must verify against the stored public key");
    }

    #[tokio::test]
    async fn provider_assertion_signs_the_given_client_data_hash() {
        let (origin, reg) = register_default().await;
        let index = index_with(&reg);

        let browser_cdj = b"{\"type\":\"webauthn.get\",\"challenge\":\"y\"}";
        let assertion = run_provider_assertion(
            &origin,
            &assertion_options_json(&[15u8; 32], Some(RP), "required", None),
            &reg.credential_id_b64,
            Some(browser_cdj.to_vec()),
            None,
            true,
            &index,
        )
        .await
        .expect("assertion with override client data");

        let (auth_data, v) = decode_auth_data(&assertion.assertion_response);
        // The response carries the browser's JSON verbatim...
        assert_eq!(
            v["response"]["clientDataJSON"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(browser_cdj)
        );
        // ...and the signed digest covers authData concatenated with the
        // SHA-256 of those bytes — proving the override reached the signature.
        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(browser_cdj).as_slice());
        let digest = Sha256::digest(&signed);
        let vk = cose_verifying_key(reg.passkey_data.private_key.as_ref().unwrap());
        let sig = URL_SAFE_NO_PAD
            .decode(v["response"]["signature"].as_str().unwrap())
            .unwrap();
        let signature = p256::ecdsa::Signature::from_der(&sig).expect("der signature");
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&digest, &signature)
            .expect("signature must cover the browser-provided hash");
    }
}
