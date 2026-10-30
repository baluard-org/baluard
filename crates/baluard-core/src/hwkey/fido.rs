//! FIDO2 security-key backend (the hmac-secret seal).
//!
//! Cross-platform USB HID; backend id "fido2". The token derives a
//! deterministic 32-byte secret per (credential, salt) via the CTAP2
//! hmac-secret extension; the seal combines that secret with the KEK
//! subkey through [`super::combine_seal_inputs`], so possession of the
//! key (the tap) and the master password are both required.
//!
//! Everything the device does sits behind the narrow [`Token`] seam:
//! the whole contract below (binding format, salt determinism, UV-mode
//! pinning, typed touch outcomes) is unit-tested hermetically against a
//! stateful mock, and the real ctap-hid-fido2 token lives behind the
//! `fido2` cargo feature. The interaction model is always tap-per-use:
//! YubiKey firmware refuses `up=false` assertions
//! (CTAP2_ERR_UNSUPPORTED_OPTION), so [`super::Interaction::PerUse`] is
//! the honest declaration and a silent seal refuses at enable time.
//! The user PIN is deliberately never used - a host-stored PIN would
//! preserve the one-credential rule, but the UV mode changes the
//! derived secret (CredRandomWithoutUV vs WithUV), so the mode is
//! pinned to without-UV and a token that forces UV is unusable,
//! fail-closed.

use super::attest::{self, PackedAttestation};
use crate::error::{BaluardError, VaultError};
use base64::Engine as _;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const BINDING_PREFIX: &str = "fido:";
/// Token-side namespace only: CTAP matches the rp id at assertion time
/// and nothing here ever touches a network origin, so an offline-only
/// name is honest.
pub const RP_ID: &str = "baluard.local";

/// What [`Token::info`] reports about the plugged key.
#[derive(Clone, Copy, Debug)]
pub struct TokenInfo {
    pub aaguid: [u8; 16],
    pub hmac_secret: bool,
    pub pin_set: bool,
    /// CTAP 2.1 `alwaysUv`: the token insists on user verification, so
    /// the PIN-less CredRandomWithoutUV path this backend requires can
    /// never run.
    pub uv_forced: bool,
    /// CTAP 2.1 makeCredUvNotRqd: PIN-less enrollment is permitted even
    /// when the token has a PIN. Absent on CTAP2.0 firmware.
    pub make_cred_uv_not_required: bool,
}

#[derive(Debug)]
pub enum TokenError {
    KeyMissing,
    Busy,
    Timeout,
    Cancelled,
    UvForced,
    NoHmacSecret,
    UnknownCredential,
    Device(String),
}

/// The device seam: everything the seal math needs from a FIDO token,
/// and nothing more.
pub trait Token: Send + Sync {
    fn info(&self) -> Result<TokenInfo, TokenError>;
    /// Create the non-discoverable hmac-secret credential for one
    /// vault, carrying the attestation the enroll path verifies.
    fn make_credential(&self, vault_id: Uuid) -> Result<PackedAttestation, TokenError>;
    /// Tap the token and derive the hmac-secret output for `salt`.
    fn get_secret(&self, credential_id: &[u8], salt: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError>;
}

pub struct FidoStore {
    token: Box<dyn Token>,
}

impl FidoStore {
    pub fn new(token: Box<dyn Token>) -> Self {
        Self { token }
    }

    fn preflight(&self) -> Result<(), BaluardError> {
        let info = self.token.info().map_err(map_token)?;
        if !info.hmac_secret || info.uv_forced {
            return Err(VaultError::HardwareUnavailable.into());
        }
        if info.pin_set && !info.make_cred_uv_not_required {
            return Err(VaultError::Metadata(
                "security key: this token requires its PIN for hmac-secret; use a key without a PIN"
                    .into(),
            )
            .into());
        }
        Ok(())
    }
}

pub fn parse_binding(binding: &str) -> Result<Vec<u8>, BaluardError> {
    let rest = binding
        .strip_prefix(BINDING_PREFIX)
        .ok_or_else(|| VaultError::Corrupt("not a fido binding".into()))?;
    let (id, b64) = rest
        .split_once(':')
        .ok_or_else(|| VaultError::Corrupt("fido binding missing credential id".into()))?;
    Uuid::parse_str(id).map_err(|_| VaultError::Corrupt("fido binding vault id".into()))?;
    let credential = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| VaultError::Corrupt(format!("fido binding credential id: {e}")))?;
    if credential.len() > 1023 {
        return Err(VaultError::Corrupt("fido binding credential id is too long".into()).into());
    }
    Ok(credential)
}

fn map_token(e: TokenError) -> BaluardError {
    match e {
        TokenError::KeyMissing => VaultError::HardwareKeyMissing.into(),
        TokenError::Busy => VaultError::HardwareBusy.into(),
        TokenError::Timeout => VaultError::HardwareTouchTimeout.into(),
        TokenError::Cancelled => VaultError::HardwareTouchCancelled.into(),
        // A token without hmac-secret, or one demanding its PIN, cannot
        // serve this seal at all; the phrase path is the rescue.
        TokenError::UvForced | TokenError::NoHmacSecret => VaultError::HardwareUnavailable.into(),
        TokenError::UnknownCredential => VaultError::HardwareKeyWrong.into(),
        TokenError::Device(m) => VaultError::Metadata(format!("security key: {m}")).into(),
    }
}

impl super::HardwareKeyStore for FidoStore {
    fn backend_id(&self) -> &'static str {
        "fido2"
    }

    fn probe(&self) -> super::HwCapability {
        let reason = match self.token.info() {
            Ok(info) if !info.hmac_secret => "token-without-hmac-secret",
            Ok(info) if info.uv_forced => "uv-forced",
            Ok(info) if info.pin_set && !info.make_cred_uv_not_required => "pin-required",
            Ok(_) => {
                return super::HwCapability::Available {
                    backend: "fido2".into(),
                }
            }
            Err(TokenError::KeyMissing) => "no-token",
            Err(TokenError::Timeout) => "touch-timeout",
            Err(TokenError::Cancelled) => "cancelled",
            Err(TokenError::Busy) => "busy",
            // Transport-level failures carry the foreign transport's own detail
            // (e.g. "USB key read timed out"); keep it instead of a bare "no-hid".
            Err(TokenError::Device(detail)) => {
                return super::HwCapability::Unavailable {
                    reason: format!("security key: {detail}"),
                };
            }
            Err(_) => "no-hid",
        };
        super::HwCapability::Unavailable {
            reason: reason.into(),
        }
    }

    fn interaction(&self) -> super::Interaction {
        super::Interaction::PerUse
    }

    fn create_binding(
        &self,
        vault_id: Uuid,
        consent: super::HwConsent,
    ) -> Result<super::BindingInfo, BaluardError> {
        if !consent.is_per_use() {
            return Err(VaultError::HardwareTouchRequired.into());
        }
        self.preflight()?;
        let att = self.token.make_credential(vault_id).map_err(map_token)?;
        if att.credential_id.len() > 1023 {
            return Err(VaultError::Metadata(
                "security key returned an oversized credential id".into(),
            )
            .into());
        }
        // Plan policy: a cryptographically invalid attestation chain is
        // a hard refuse; unknown-vendor chains are allowed with copy at
        // the surface layer.
        let verdict = attest::verify(&att);
        if verdict == attest::AttestationVerdict::Invalid {
            return Err(VaultError::Metadata(
                "the security key's attestation is invalid; it cannot hold the seal"
                    .into(),
            )
            .into());
        }
        let attestation = match verdict {
            attest::AttestationVerdict::YubicoVerified => super::HwAttestation::Verified,
            attest::AttestationVerdict::UnknownVendor => super::HwAttestation::UnknownVendor,
            attest::AttestationVerdict::Invalid => unreachable!("refused above"),
        };
        Ok(super::BindingInfo {
            binding: format!(
                "{BINDING_PREFIX}{vault_id}:{}",
                base64::engine::general_purpose::STANDARD.encode(att.credential_id)
            ),
            attestation: Some(attestation),
        })
    }

    fn derive_ephemeral(
        &self,
        binding: &str,
        consent: super::HwConsent,
    ) -> Result<(super::Handshake, super::SharedSecret), BaluardError> {
        if !consent.is_per_use() {
            return Err(VaultError::HardwareTouchRequired.into());
        }
        let cred = parse_binding(binding)?;
        self.preflight()?;
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let secret = self.token.get_secret(&cred, &salt).map_err(map_token)?;
        Ok((super::Handshake(salt.to_vec()), secret))
    }

    fn derive(
        &self,
        binding: &str,
        handshake: &super::Handshake,
        consent: super::HwConsent,
    ) -> Result<super::SharedSecret, BaluardError> {
        if !consent.is_per_use() {
            return Err(VaultError::HardwareTouchRequired.into());
        }
        let cred = parse_binding(binding)?;
        let salt: [u8; 32] = handshake
            .0
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("fido handshake is not a 32-byte salt".into()))?;
        self.preflight()?;
        let secret = self.token.get_secret(&cred, &salt).map_err(map_token)?;
        Ok(secret)
    }

    fn delete_binding(&self, _binding: &str) -> Result<(), BaluardError> {
        // Deliberate no-op: a non-discoverable credential is invisible
        // without its id, so the orphan left after a disable is inert.
        // CTAP 2.1 credential deletion would demand the PIN we refuse.
        Ok(())
    }
}

#[cfg(feature = "fido2")]
mod real {
    //! The ctap-hid-fido2 token. Build-gated because the hidapi C
    //! scaffold needs libusb/libudev headers at build time; runtime
    //! needs the Yubico udev rules for non-root HID access.

    use super::{PackedAttestation, Token, TokenError, TokenInfo};
    use ctap_hid_fido2::fidokey::{
        AssertionExtension as Gext, CredentialExtension as Mext, GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder,
    };
    use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
    use ctap_hid_fido2::{HidInfo, HidParam};
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
    use uuid::Uuid;

    pub struct CtapToken;

    // ctap-hid-fido2 3.6.0 returns anyhow text errors; the embedded CTAP
    // status code is the only machine-readable signal it offers.
    pub(super) fn classify_message(msg: &str) -> TokenError {
        if msg.contains("0x2F CTAP2_ERR_USER_ACTION_TIMEOUT") {
            TokenError::Timeout
        } else if msg.contains("0x2D CTAP2_ERR_KEEPALIVE_CANCEL") {
            TokenError::Cancelled
        } else if msg.contains("0x06 CTAP1_ERR_CHANNEL_BUSY") {
            TokenError::Busy
        } else if msg.contains("0x2E CTAP2_ERR_NO_CREDENTIALS") {
            TokenError::UnknownCredential
        } else {
            TokenError::Device(msg.to_string())
        }
    }

    /// Every plugged FIDO HID, keyed by its unique path. The library's
    /// single-device factory refuses multiples outright; the seal instead
    /// tries each token for a derivation and asks for one at enrollment.
    fn devices() -> Vec<HidInfo> {
        ctap_hid_fido2::get_fidokey_devices()
    }

    fn open_param(param: &HidParam) -> Result<ctap_hid_fido2::FidoKeyHid, TokenError> {
        FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &Cfg::init())
            .map_err(|e| classify_message(&e.to_string()))
    }

    fn open_single() -> Result<ctap_hid_fido2::FidoKeyHid, TokenError> {
        let found = devices();
        match found.len() {
            0 => Err(TokenError::KeyMissing),
            1 => open_param(&found[0].param),
            _ => Err(TokenError::Device(
                "multiple security keys are plugged in; keep only the key you want to use".into(),
            )),
        }
    }

    /// NO_CREDENTIALS and device/open failures mean "try the next
    /// token": an unsupported or unopenable key must not hide the right
    /// one. Timeouts, cancellation and busy are real user outcomes.
    pub(super) fn try_next_device(error: &TokenError) -> bool {
        matches!(error, TokenError::UnknownCredential | TokenError::Device(_))
    }

    impl Token for CtapToken {
        fn info(&self) -> Result<TokenInfo, TokenError> {
            let found = devices();
            if found.is_empty() {
                return Err(TokenError::KeyMissing);
            }
            let mut last_error = TokenError::KeyMissing;
            for device in found {
                let info = match open_param(&device.param)
                    .and_then(|dev| dev.get_info().map_err(|e| classify_message(&e.to_string())))
                {
                    Ok(info) => info,
                    Err(error) => {
                        last_error = error;
                        continue;
                    }
                };
                let mut aaguid = [0u8; 16];
                if info.aaguid.len() == 16 {
                    aaguid.copy_from_slice(&info.aaguid);
                }
                return Ok(TokenInfo {
                    aaguid,
                    hmac_secret: info.extensions.iter().any(|e| e == "hmac-secret"),
                    pin_set: info.options.iter().any(|(k, v)| k == "clientPin" && *v),
                    uv_forced: info.options.iter().any(|(k, v)| k == "alwaysUv" && *v),
                    make_cred_uv_not_required: info
                        .options
                        .iter()
                        .any(|(k, v)| k == "makeCredUvNotRqd" && *v),
                });
            }
            Err(last_error)
        }

        fn make_credential(&self, vault_id: Uuid) -> Result<PackedAttestation, TokenError> {
            let dev = open_single()?;
            let mut challenge = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
            let user =
                PublicKeyCredentialUserEntity::new(Some(vault_id.as_bytes()), None, None);
            let args = MakeCredentialArgsBuilder::new(super::RP_ID, &challenge)
                .without_pin_and_uv()
                .user_entity(&user)
                .extensions(&[Mext::HmacSecret(Some(true))])
                .build();
            let att = dev
                .make_credential_with_args(&args)
                .map_err(|e| classify_message(&e.to_string()))?;
            Ok(PackedAttestation {
                credential_id: att.credential_descriptor.id,
                auth_data: att.auth_data,
                client_data_hash: challenge,
                alg: att.attstmt_alg as i64,
                sig: att.attstmt_sig,
                x5c: att.attstmt_x5c,
            })
        }

        fn get_secret(
            &self,
            credential_id: &[u8],
            salt: &[u8; 32],
        ) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError> {
            let found = devices();
            if found.is_empty() {
                return Err(TokenError::KeyMissing);
            }
            let mut last_error = TokenError::UnknownCredential;
            for device in found {
                let result = open_param(&device.param).and_then(|dev| {
                    let args = GetAssertionArgsBuilder::new(super::RP_ID, salt)
                        .without_pin_and_uv()
                        .credential_id(credential_id)
                        .extensions(&[Gext::HmacSecret(Some(*salt))])
                        .build();
                    let assertions = dev
                        .get_assertion_with_args(&args)
                        .map_err(|e| classify_message(&e.to_string()))?;
                    let a = assertions
                        .first()
                        .ok_or_else(|| TokenError::Device("no assertion returned".into()))?;
                    for e in &a.extensions {
                        if let Gext::HmacSecret(Some(out)) = e {
                            return Ok(zeroize::Zeroizing::new(*out));
                        }
                    }
                    Err(TokenError::Device(
                        "assertion carried no hmac-secret output".into(),
                    ))
                });
                match result {
                    Ok(secret) => return Ok(secret),
                    Err(error) if try_next_device(&error) => {
                        last_error = error;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(last_error)
        }
    }

    /// Registry entry point for the real token.
    pub fn store() -> std::sync::Arc<dyn super::super::HardwareKeyStore> {
        std::sync::Arc::new(super::FidoStore::new(Box::new(CtapToken)))
    }
}

#[cfg(feature = "fido2")]
pub use real::store;

#[cfg(all(test, feature = "fido2"))]
mod tests {

    #[test]
    fn only_an_unknown_credential_moves_to_the_next_device() {
        assert!(super::real::try_next_device(
            &super::TokenError::UnknownCredential
        ));
        // An unopenable/unsupported token must not hide the right key.
        assert!(super::real::try_next_device(&super::TokenError::Device(
            "permission denied".into()
        )));
        for err in [
            super::TokenError::Timeout,
            super::TokenError::Cancelled,
            super::TokenError::Busy,
            super::TokenError::KeyMissing,
        ] {
            assert!(!super::real::try_next_device(&err));
        }
    }

    #[test]
    fn desktop_adapter_classifies_the_library_text() {
        // The exact message shapes ctap-hid-fido2 3.6.0 emits
        // (response_status err = <get_status_message>).
        use crate::hwkey::fido::real::classify_message;
        use crate::hwkey::fido::TokenError;
        let timeout = "response_status err = 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT   Timeout waiting for user interaction.";
        assert!(matches!(classify_message(timeout), TokenError::Timeout));
        let cancel = "response_status err = 0x2D CTAP2_ERR_KEEPALIVE_CANCEL  Pending keep alive was cancelled.";
        assert!(matches!(classify_message(cancel), TokenError::Cancelled));
        let busy = "response_status err = 0x06 CTAP1_ERR_CHANNEL_BUSY Channel busy.";
        assert!(matches!(classify_message(busy), TokenError::Busy));
        let none = "response_status err = 0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided.";
        assert!(matches!(classify_message(none), TokenError::UnknownCredential));
        // Unknown library text keeps its detail for diagnostics.
        assert!(matches!(
            classify_message("read err = 0xFE"),
            TokenError::Device(msg) if msg.contains("read err")
        ));
    }
    use super::super::{
        Handshake, HardwareKeyStore, HwAttestation, HwCapability, HwConsent, binding_vault_id,
    };
    use super::*;
    use crate::error::BaluardError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn vault_err(e: &BaluardError) -> &VaultError {
        match e {
            crate::error::BaluardError::Vault(v) => v,
            other => panic!("not a vault error: {other}"),
        }
    }

    /// Stateful mock: holds credentials + their master secrets and
    /// derives hmac outputs the way a token does
    /// (SHA-256(master_secret || salt)). Configurable failure modes
    /// cover every typed outcome.
    struct MockToken {
        hmac_secret: bool,
        uv_forced: bool,
        pin_set: bool,
        make_cred_uv_not_required: bool,
        creds: Mutex<HashMap<Vec<u8>, [u8; 32]>>,
        fail: Option<TokenError>,
        chain: crate::hwkey::attest::test_chain::TestChain,
    }

    impl MockToken {
        fn new() -> Self {
            Self {
                hmac_secret: true,
                uv_forced: false,
                pin_set: false,
                make_cred_uv_not_required: true,
                creds: Mutex::new(HashMap::new()),
                fail: None,
                chain: crate::hwkey::attest::test_chain::TestChain::new(),
            }
        }
        fn hmac_off(mut self) -> Self {
            self.hmac_secret = false;
            self
        }
        fn uv_forced(mut self) -> Self {
            self.uv_forced = true;
            self
        }
        fn pin_required(mut self) -> Self {
            self.pin_set = true;
            self.make_cred_uv_not_required = false;
            self
        }
        fn failing(mut self, e: TokenError) -> Self {
            self.fail = Some(e);
            self
        }
        fn fail_err(&self) -> Result<(), TokenError> {
            match &self.fail {
                Some(e) => Err(match e {
                    TokenError::Busy => TokenError::Busy,
                    TokenError::Timeout => TokenError::Timeout,
                    TokenError::Cancelled => TokenError::Cancelled,
                    TokenError::KeyMissing => TokenError::KeyMissing,
                    other => TokenError::Device(format!("{other:?}")),
                }),
                None => Ok(()),
            }
        }
    }

    impl Token for MockToken {
        fn info(&self) -> Result<TokenInfo, TokenError> {
            self.fail_err()?;
            Ok(TokenInfo {
                aaguid: [7u8; 16],
                hmac_secret: self.hmac_secret,
                pin_set: self.pin_set,
                uv_forced: self.uv_forced,
                make_cred_uv_not_required: self.make_cred_uv_not_required,
            })
        }

        fn make_credential(&self, vault_id: Uuid) -> Result<PackedAttestation, TokenError> {
            self.fail_err()?;
            let mut secret = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
            let att = self.chain.attestation_for(vault_id.as_bytes());
            self.creds.lock().unwrap().insert(att.credential_id.clone(), secret);
            Ok(att)
        }

        fn get_secret(
            &self,
            credential_id: &[u8],
            salt: &[u8; 32],
        ) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError> {
            self.fail_err()?;
            let creds = self.creds.lock().unwrap();
            let secret = creds
                .get(credential_id)
                .ok_or(TokenError::UnknownCredential)?;
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(secret);
            h.update(salt);
            Ok(zeroize::Zeroizing::new(h.finalize().into()))
        }
    }

    fn store(tok: MockToken) -> FidoStore {
        FidoStore::new(Box::new(tok))
    }

    #[test]
    fn oversized_credential_ids_are_refused() {
        let binding = format!(
            "fido:{}:{}",
            uuid::Uuid::new_v4(),
            base64::engine::general_purpose::STANDARD.encode([7u8; 1024])
        );
        assert!(parse_binding(&binding).is_err());
    }

    #[test]
    fn binding_format_round_trips() {
        let vault_id = Uuid::new_v4();
        let s = store(MockToken::new());
        let info = s.create_binding(vault_id, HwConsent::PerUse).unwrap();
        // The mock's synthetic chain is self-consistent but not
        // Yubico-rooted: allowed, flagged unknown-vendor.
        assert_eq!(info.attestation, Some(HwAttestation::UnknownVendor));
        let binding = info.binding;
        assert!(binding.starts_with(BINDING_PREFIX), "got: {binding}");
        assert_eq!(binding_vault_id(&binding), Some(vault_id));
        let cred = parse_binding(&binding).unwrap();
        assert_eq!(cred, vault_id.as_bytes().to_vec());
    }

    #[test]
    fn salt_determinism_reproduces_the_secret() {
        let vault_id = Uuid::new_v4();
        let s = store(MockToken::new());
        let binding = s
            .create_binding(vault_id, HwConsent::PerUse)
            .unwrap()
            .binding;
        let (handshake, secret) = s.derive_ephemeral(&binding, HwConsent::PerUse).unwrap();
        assert_eq!(handshake.0.len(), 32);
        let again = s.derive(&binding, &handshake, HwConsent::PerUse).unwrap();
        assert_eq!(secret.as_ref(), again.as_ref(), "same salt must reproduce z");
        let mut other_salt = handshake.0.clone();
        other_salt[0] ^= 0xff;
        let different = s
            .derive(&binding, &Handshake(other_salt), HwConsent::PerUse)
            .unwrap();
        assert_ne!(secret.as_ref(), different.as_ref());
    }

    #[test]
    fn pin_required_ctap20_token_gets_a_plain_reason() {
        let store = FidoStore::new(Box::new(MockToken::new().pin_required()));
        let err = store.preflight().unwrap_err();
        assert!(
            matches!(vault_err(&err), VaultError::Metadata(msg) if msg.contains("PIN")),
            "pin-required token must explain itself: {err:?}"
        );
    }

    #[test]
    fn uv_forced_token_fails_closed() {
        let vault_id = Uuid::new_v4();
        let s = store(MockToken::new().uv_forced());
        match s.probe() {
            HwCapability::Unavailable { reason } => assert_eq!(reason, "uv-forced"),
            other => panic!("expected unavailable, got {other:?}"),
        }
        let err = s.create_binding(vault_id, HwConsent::PerUse).unwrap_err();
        assert!(matches!(vault_err(&err), VaultError::HardwareUnavailable));
    }

    #[test]
    fn token_without_hmac_secret_refuses() {
        let vault_id = Uuid::new_v4();
        let s = store(MockToken::new().hmac_off());
        match s.probe() {
            HwCapability::Unavailable { reason } => {
                assert_eq!(reason, "token-without-hmac-secret")
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
        assert!(s.create_binding(vault_id, HwConsent::PerUse).is_err());
    }

    #[test]
    fn silent_mode_is_refused_on_fido() {
        let vault_id = Uuid::new_v4();
        let s = store(MockToken::new());
        let err = s.create_binding(vault_id, HwConsent::Silent).unwrap_err();
        assert!(matches!(vault_err(&err), VaultError::HardwareTouchRequired));
    }

    #[test]
    fn typed_touch_outcomes_map_to_typed_errors() {
        let vault_id = Uuid::new_v4();
        let clean = store(MockToken::new());
        let binding = clean
            .create_binding(vault_id, HwConsent::PerUse)
            .unwrap()
            .binding;
        let salt = Handshake(vec![0u8; 32]);
        for (tok, expected) in [
            (TokenError::Busy, VaultError::HardwareBusy),
            (TokenError::Timeout, VaultError::HardwareTouchTimeout),
            (TokenError::Cancelled, VaultError::HardwareTouchCancelled),
        ] {
            let s = store(MockToken::new().failing(tok));
            let err = s.derive(&binding, &salt, HwConsent::PerUse).unwrap_err();
            assert!(std::mem::discriminant(vault_err(&err)) == std::mem::discriminant(&expected));
        }
    }

    #[test]
    fn swapped_credential_fails_closed() {
        // A different token (or a reset one) knows no credential: the
        // assertion fails natively, surfacing as wrong-key.
        let vault_id = Uuid::new_v4();
        let clean = store(MockToken::new());
        let binding = clean
            .create_binding(vault_id, HwConsent::PerUse)
            .unwrap()
            .binding;
        let other = store(MockToken::new());
        let err = other
            .derive(&binding, &Handshake(vec![0u8; 32]), HwConsent::PerUse)
            .unwrap_err();
        assert!(matches!(vault_err(&err), VaultError::HardwareKeyWrong));
    }

    #[test]
    fn missing_key_maps_to_key_missing() {
        let s = store(MockToken::new().failing(TokenError::KeyMissing));
        match s.probe() {
            HwCapability::Unavailable { reason } => assert_eq!(reason, "no-token"),
            other => panic!("expected unavailable, got {other:?}"),
        }
    }
}
