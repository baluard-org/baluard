//! [`super::fido::Token`] backed by the in-tree CTAP2 client.
//!
//! Mobile transports implement [`HidLink`]; every seal operation opens a
//! fresh CTAPHID session so no authenticator channel survives an unlock.

use super::super::attest::PackedAttestation;
use super::super::fido::{RP_ID, Token, TokenError, TokenInfo};
use super::apdu::{ApduError, ApduForm, Transceive};
use super::ctaphid::{CtapHidError, HidLink};
use super::protocol::{ClientError, Ctap2Error, CtapClient};
use uuid::Uuid;

pub struct CtapToken<L> {
    link: L,
}

pub struct NfcToken<T> {
    form: ApduForm,
    link: T,
}

impl<T> NfcToken<T> {
    /// Extended-length APDUs; see [`NfcToken::with_form`] for readers that
    /// cannot send them.
    pub fn new(link: T) -> Self {
        Self::with_form(link, ApduForm::Extended)
    }

    pub fn with_form(link: T, form: ApduForm) -> Self {
        Self { form, link }
    }
}

impl<L> CtapToken<L> {
    pub fn new(link: L) -> Self {
        Self { link }
    }

    pub fn into_link(self) -> L {
        self.link
    }
}

impl<L: HidLink> CtapToken<L> {
    fn client(&self) -> Result<CtapClient<'_>, ClientError> {
        CtapClient::new(&self.link)
    }
}

impl<T: Transceive> NfcToken<T> {
    fn client(&self) -> Result<CtapClient<'_>, ClientError> {
        CtapClient::new_apdu_form(&self.link, self.form)
    }
}

#[doc(hidden)]
pub fn token_info(client: CtapClient<'_>) -> Result<TokenInfo, TokenError> {
    let info = client.get_info().map_err(map_client_error)?;
    Ok(TokenInfo {
        aaguid: info.aaguid,
        hmac_secret: info.extensions.iter().any(|e| e == "hmac-secret"),
        pin_set: info.pin_set,
        uv_forced: info.uv_forced,
        make_cred_uv_not_required: info.make_cred_uv_not_required,
    })
}

#[doc(hidden)]
pub fn make_credential(
    client: CtapClient<'_>,
    vault_id: Uuid,
) -> Result<PackedAttestation, TokenError> {
    client.require_hmac_secret().map_err(map_client_error)?;
    let mut challenge = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
    client
        .make_credential(
            &challenge,
            RP_ID,
            vault_id.as_bytes(),
            "Baluard",
            &[],
            &mut |_| {},
        )
        .map(|made| made.attestation)
        .map_err(map_client_error)
}

#[doc(hidden)]
pub fn get_secret(
    client: CtapClient<'_>,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError> {
    let info = client.require_hmac_secret().map_err(map_client_error)?;
    let shared = client.shared_secret(&info).map_err(map_client_error)?;
    let assertion = client
        .get_assertion(
            RP_ID,
            salt,
            std::slice::from_ref(&credential_id.to_vec()),
            &shared,
            salt,
            None,
            &mut |_| {},
        )
        .map_err(map_client_error)?;
    match assertion.secrets.as_slice() {
        [secret] => Ok(zeroize::Zeroizing::new(**secret)),
        _ => Err(TokenError::Device(
            "assertion did not carry exactly one hmac-secret output".into(),
        )),
    }
}

/// The one mapping from client failures to seal-level token errors; every
/// transport adapter (including the UniFFI bridge) shares it.
pub fn map_client_error(error: ClientError) -> TokenError {
    match error {
        ClientError::Ctap2(Ctap2Error(code)) => match code {
            0x06 => TokenError::Busy,
            0x27 | 0x2d => TokenError::Cancelled,
            0x2e | 0x22 => TokenError::UnknownCredential,
            0x2f => TokenError::Timeout,
            0x31 | 0x36 | 0x3c | 0x3f => TokenError::UvForced,
            _ => TokenError::Device(format!("CTAP2 status 0x{code:02x}")),
        },
        ClientError::NoHmacSecret => TokenError::NoHmacSecret,
        ClientError::Unsupported(_) => TokenError::Device(
            "security key does not support this operation".into(),
        ),
        // CTAPHID channel-busy (0x06) is a busy key; the other HID
        // protocol codes are transport-class failures.
        ClientError::Hid(CtapHidError::Hid(0x06)) => TokenError::Busy,
        ClientError::Hid(CtapHidError::Timeout) | ClientError::Apdu(ApduError::Timeout) => {
            TokenError::Timeout
        }
        ClientError::Hid(_) | ClientError::Apdu(_) => TokenError::KeyMissing,
        other => TokenError::Device(other.to_string()),
    }
}

macro_rules! impl_token {
    ($ty:ident<$param:ident: $bound:path>) => {
        impl<$param: $bound + Send + Sync> Token for $ty<$param> {
            fn info(&self) -> Result<TokenInfo, TokenError> {
                token_info(self.client().map_err(map_client_error)?)
            }

            fn make_credential(&self, vault_id: Uuid) -> Result<PackedAttestation, TokenError> {
                make_credential(self.client().map_err(map_client_error)?, vault_id)
            }

            fn get_secret(
                &self,
                credential_id: &[u8],
                salt: &[u8; 32],
            ) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError> {
                get_secret(
                    self.client().map_err(map_client_error)?,
                    credential_id,
                    salt,
                )
            }
        }
    };
}

impl_token!(CtapToken<L: HidLink>);
impl_token!(NfcToken<T: Transceive>);

#[cfg(test)]
mod tests {

    #[test]
    fn operation_denied_and_nfc_deadline_are_typed() {
        assert!(matches!(
            map_client_error(ClientError::Ctap2(Ctap2Error(0x27))),
            TokenError::Cancelled
        ));
        assert!(matches!(
            map_client_error(ClientError::Apdu(ApduError::Timeout)),
            TokenError::Timeout
        ));
        assert!(matches!(
            map_client_error(ClientError::Unsupported("no pinUvAuth protocol".into())),
            TokenError::Device(message) if !message.contains("pinUvAuth")
        ));
    }

    #[test]
    fn keepalive_deadline_maps_to_touch_timeout() {
        assert!(matches!(
            super::map_client_error(ClientError::Hid(
                crate::hwkey::ctap::ctaphid::CtapHidError::Timeout
            )),
            TokenError::Timeout
        ));
    }

    #[test]
    fn hid_busy_maps_to_busy_not_key_missing() {
        // An HID ERROR frame carrying channel-busy is a busy key, not a
        // missing one (H9 consumer half).
        assert!(matches!(
            super::map_client_error(ClientError::Hid(
                crate::hwkey::ctap::ctaphid::CtapHidError::Hid(0x06)
            )),
            TokenError::Busy
        ));
    }
    use super::*;
    use crate::hwkey::ctap::authenticator::{ModelLink, SoftAuthenticator};
    use crate::hwkey::fido::parse_binding;
    use std::sync::Mutex;

    struct SharedLink<L>(Mutex<L>);

    impl<L: HidLink> HidLink for SharedLink<L> {
        fn write(&self, report: &[u8; 65]) -> Result<(), super::super::ctaphid::CtapHidError> {
            self.0.lock().expect("link lock").write(report)
        }

        fn read(&self) -> Result<[u8; 65], super::super::ctaphid::CtapHidError> {
            self.0.lock().expect("link lock").read()
        }
    }

    fn master() -> [u8; 32] {
        std::array::from_fn(|i| (i * 7 + 1) as u8)
    }

    /// Reader model: answers SELECT with `select_reply`, rejects extended
    /// APDUs when `extended` is false (as some phones' IsoDep does), buffers
    /// chained requests, and hands responses out in `chunk`-byte 61xx pieces.
    struct ModelApdu {
        model: Mutex<SoftAuthenticator>,
        select_reply: &'static [u8],
        extended: bool,
        chunk: usize,
        chained: Mutex<Vec<u8>>,
        outbox: Mutex<Vec<u8>>,
        extended_seen: Mutex<bool>,
    }

    impl ModelApdu {
        fn new(model: SoftAuthenticator) -> Self {
            Self {
                model: Mutex::new(model),
                select_reply: b"FIDO_2_0",
                extended: true,
                chunk: usize::MAX,
                chained: Mutex::new(Vec::new()),
                outbox: Mutex::new(Vec::new()),
                extended_seen: Mutex::new(false),
            }
        }

        fn page(&self) -> (Vec<u8>, [u8; 2]) {
            let mut outbox = self.outbox.lock().unwrap();
            let take = outbox.len().min(self.chunk).min(256);
            let part: Vec<u8> = outbox.drain(..take).collect();
            let sw = match outbox.len() {
                0 => [0x90, 0x00],
                n => [0x61, if n >= 256 { 0x00 } else { n as u8 }],
            };
            (part, sw)
        }
    }

    impl Transceive for ModelApdu {
        fn transceive(
            &self,
            request: &[u8],
        ) -> Result<(Vec<u8>, [u8; 2]), super::super::apdu::ApduError> {
            if request.get(1) == Some(&0xa4) {
                return Ok((self.select_reply.to_vec(), [0x90, 0x00]));
            }
            if request.get(1) == Some(&0xc0) {
                return Ok(self.page());
            }
            if request.len() < 5 || request[1] != 0x10 {
                return Ok((Vec::new(), [0x6d, 0x00]));
            }
            let (data, chaining) = if request[4] == 0 && request.len() >= 7 {
                if !self.extended {
                    return Ok((Vec::new(), [0x67, 0x00]));
                }
                *self.extended_seen.lock().unwrap() = true;
                let len = ((request[5] as usize) << 8) | request[6] as usize;
                (&request[7..7 + len], false)
            } else {
                let len = request[4] as usize;
                (&request[5..5 + len], request[0] & 0x10 != 0)
            };
            let mut chained = self.chained.lock().unwrap();
            chained.extend_from_slice(data);
            if chaining {
                return Ok((Vec::new(), [0x90, 0x00]));
            }
            let command = std::mem::take(&mut *chained);
            let response = self
                .model
                .lock()
                .expect("model lock")
                .handle(command[0], &command[1..]);
            *self.outbox.lock().unwrap() = response;
            drop(chained);
            Ok(self.page())
        }
    }

    #[test]
    fn nfc_token_enrolls_and_derives_through_the_same_client() {
        let reader = ModelApdu::new(SoftAuthenticator::new(master()));
        let token = NfcToken::new(reader);
        let vault_id = Uuid::new_v4();
        let attestation = token.make_credential(vault_id).unwrap();
        let salt = [0x24u8; 32];
        let first = token.get_secret(&attestation.credential_id, &salt).unwrap();
        let second = token.get_secret(&attestation.credential_id, &salt).unwrap();
        assert_eq!(first, second);
        assert_ne!(*first, [0u8; 32]);
        assert!(*token.link.extended_seen.lock().unwrap());
    }

    #[test]
    fn u2f_v2_select_reply_is_accepted_once_get_info_proves_ctap2() {
        let mut reader = ModelApdu::new(SoftAuthenticator::new(master()));
        reader.select_reply = b"U2F_V2";
        let token = NfcToken::new(reader);
        assert!(token.info().unwrap().hmac_secret);
        let attestation = token.make_credential(Uuid::new_v4()).unwrap();
        token
            .get_secret(&attestation.credential_id, &[1u8; 32])
            .unwrap();
    }

    #[test]
    fn u2f_only_key_is_refused_not_mistaken_for_ctap2() {
        let mut reader = ModelApdu::new(SoftAuthenticator::new(master()));
        reader.select_reply = b"U2F_V2";
        // The key answers CBOR commands with "instruction not supported".
        reader.model = Mutex::new(SoftAuthenticator::new(master()).with_versions(vec!["U2F_V2"]));
        let token = NfcToken::new(reader);
        let error = token.info().unwrap_err();
        assert!(matches!(error, TokenError::Device(m) if m.contains("does not support")));

        let mut garbage = ModelApdu::new(SoftAuthenticator::new(master()));
        garbage.select_reply = b"SOMETHING";
        assert!(NfcToken::new(garbage).info().is_err());
    }

    #[test]
    fn chained_form_works_on_a_reader_without_extended_apdus_and_paged_responses() {
        let mut reader = ModelApdu::new(SoftAuthenticator::new(master()));
        reader.extended = false;
        reader.chunk = 48;
        let token = NfcToken::with_form(reader, ApduForm::for_extended_support(false));
        let attestation = token.make_credential(Uuid::new_v4()).unwrap();
        let secret = token
            .get_secret(&attestation.credential_id, &[7u8; 32])
            .unwrap();
        assert_ne!(*secret, [0u8; 32]);
        assert!(!*token.link.extended_seen.lock().unwrap());

        // The same reader refuses the default extended shape.
        let mut strict = ModelApdu::new(SoftAuthenticator::new(master()));
        strict.extended = false;
        assert!(NfcToken::new(strict).info().is_err());
    }

    fn link() -> SharedLink<ModelLink> {
        SharedLink(Mutex::new(ModelLink::new(SoftAuthenticator::new(master()))))
    }

    #[test]
    fn token_matches_the_direct_client_and_binding_contract() {
        let vault_id = Uuid::new_v4();
        let token = CtapToken::new(link());
        let attestation = token.make_credential(vault_id).unwrap();
        let binding = format!(
            "fido:{vault_id}:{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &attestation.credential_id,
            )
        );
        assert_eq!(parse_binding(&binding).unwrap(), attestation.credential_id);
        assert_ne!(attestation.client_data_hash, [0u8; 32]);
        assert!(!attestation.x5c.is_empty());

        let salt = [0x42u8; 32];
        let through_token = token.get_secret(&attestation.credential_id, &salt).unwrap();
        let direct_link = link();
        let direct = CtapClient::new(&direct_link).unwrap();
        let info = direct.require_hmac_secret().unwrap();
        direct
            .make_credential(
                &[7u8; 32],
                RP_ID,
                vault_id.as_bytes(),
                "Baluard",
                &[],
                &mut |_| {},
            )
            .unwrap();
        let shared = direct.shared_secret(&info).unwrap();
        let expected = direct
            .get_assertion(
                RP_ID,
                &salt,
                &[attestation.credential_id.clone()],
                &shared,
                &salt,
                None,
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(*through_token, *expected.secrets[0]);
        assert_eq!(
            token.get_secret(&attestation.credential_id, &salt).unwrap(),
            through_token
        );
    }

    #[cfg(feature = "fido2")]
    #[test]
    fn reference_adapter_parses_the_same_attestation_bytes() {
        use crate::hwkey::ctap::cbor::Value;
        use crate::hwkey::ctap::protocol::parse_make_credential;

        let challenge = [7u8; 32];
        let request = Value::Map(vec![
            (Value::Unsigned(1), Value::ByteString(challenge.to_vec())),
            (
                Value::Unsigned(2),
                Value::Map(vec![(
                    Value::TextString("id".into()),
                    Value::TextString(RP_ID.into()),
                )]),
            ),
            (
                Value::Unsigned(3),
                Value::Map(vec![(
                    Value::TextString("id".into()),
                    Value::ByteString(vec![9u8; 16]),
                )]),
            ),
            (
                Value::Unsigned(4),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::TextString("type".into()),
                        Value::TextString("public-key".into()),
                    ),
                    (Value::TextString("alg".into()), Value::Negative(-7)),
                ])]),
            ),
            (
                Value::Unsigned(6),
                Value::Map(vec![(
                    Value::TextString("hmac-secret".into()),
                    Value::Bool(true),
                )]),
            ),
        ])
        .encode();
        let response = SoftAuthenticator::new(master()).handle(0x01, &request);
        assert_eq!(response[0], 0);
        let ours = parse_make_credential(&response[1..], &challenge).unwrap();
        let reference =
            ctap_hid_fido2::fidokey::make_credential::make_credential_response::parse_cbor(
                &response[1..],
            )
            .unwrap();
        assert_eq!(ours.credential_id, reference.credential_descriptor.id);
        assert_eq!(ours.attestation.auth_data, reference.auth_data);
        assert_eq!(ours.attestation.alg, reference.attstmt_alg as i64);
        assert_eq!(ours.attestation.sig, reference.attstmt_sig);
        assert_eq!(ours.attestation.x5c, reference.attstmt_x5c);
        assert_eq!(ours.attestation.client_data_hash, challenge);
    }

    #[test]
    fn token_surfaces_capability_and_typed_errors() {
        let token = CtapToken::new(link());
        let info = token.info().unwrap();
        assert!(info.hmac_secret);
        assert!(!info.uv_forced);
        let error = token.get_secret(&[0xde, 0xad], &[1u8; 32]).unwrap_err();
        assert!(matches!(error, TokenError::UnknownCredential));

        let unsupported = CtapToken::new(SharedLink(Mutex::new(ModelLink::new(
            SoftAuthenticator::new(master()).with_extensions(vec!["credProtect"]),
        ))));
        let error = unsupported.make_credential(Uuid::new_v4()).unwrap_err();
        assert!(matches!(error, TokenError::NoHmacSecret));
    }
}

/// Manual 4A exit gate. Run with a FIDO2 key plugged in:
/// `cargo test -p baluard-core --features fido2 real_key_enroll -- --ignored --nocapture`.
/// This creates one non-discoverable credential on the key.
#[cfg(all(test, feature = "fido2"))]
mod real_key_gate {
    use super::*;
    use crate::hwkey::ctap::ctaphid::CtapHidError;
    use hidapi::{HidApi, HidDevice};
    use std::sync::Mutex;

    struct DesktopLink(Mutex<HidDevice>);

    impl HidLink for DesktopLink {
        fn write(&self, report: &[u8; 65]) -> Result<(), CtapHidError> {
            self.0
                .lock()
                .map_err(|_| CtapHidError::Link)?
                .write(report)
                .map(|_| ())
                .map_err(|_| CtapHidError::Link)
        }

        fn read(&self) -> Result<[u8; 65], CtapHidError> {
            let mut report = [0u8; 65];
            self.0
                .lock()
                .map_err(|_| CtapHidError::Link)?
                .read_timeout(&mut report, 35_000)
                .map_err(|_| CtapHidError::Link)?;
            Ok(report)
        }
    }

    #[test]
    #[ignore = "requires a physical FIDO2 key and creates a credential"]
    fn real_key_enroll_and_derive_through_new_client() {
        let api = HidApi::new().expect("HID enumeration");
        let device = api
            .device_list()
            .find(|device| device.usage_page() == 0xf1d0)
            .expect("plug in a FIDO2 key")
            .open_device(&api)
            .expect("open the FIDO2 HID interface; check udev rules");
        let token = CtapToken::new(DesktopLink(Mutex::new(device)));
        let info = token.info().expect("getInfo from the real key");
        assert!(info.hmac_secret);
        assert!(!info.uv_forced);
        let vault_id = Uuid::new_v4();
        let attestation = token.make_credential(vault_id).expect("tap to enroll");
        let salt = [0x42u8; 32];
        let first = token
            .get_secret(&attestation.credential_id, &salt)
            .expect("tap to derive");
        let second = token
            .get_secret(&attestation.credential_id, &salt)
            .expect("tap to derive again");
        assert_eq!(first, second);
        assert_ne!(*first, [0u8; 32]);
    }
}
