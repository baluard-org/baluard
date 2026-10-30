//! A software CTAP2 authenticator for hermetic tests (plan slice 4A).
//!
//! Fresh ECDH keys and OsRng salts make recorded transcripts unusable, so
//! tests drive `CtapClient` against this model over real CTAPHID framing
//! instead. Credential secrets derive from a fixed master seed via HKDF,
//! which lets tests predict the exact hmac-secret outputs. It models only
//! what Baluard uses: getInfo, clientPIN getKeyAgreement, PIN-less
//! makeCredential (rk:false), and getAssertion with hmac-secret.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

use super::cbor::Value;
use super::pinproto::{Protocol, SharedSecret};

const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_CLIENT_PIN: u8 = 0x06;
const SUBCMD_GET_KEY_AGREEMENT: u8 = 0x02;

// CTAP2 status codes the model answers with.
const OK: u8 = 0x00;
const ERR_INVALID_CREDENTIAL: u8 = 0x22;
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const ERR_OPERATION_DENIED: u8 = 0x27;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_PIN_INVALID: u8 = 0x31;
const ERR_MISSING_PARAMETER: u8 = 0x14;

#[derive(Clone)]
struct SoftCredential {
    rp_id: String,
    id: Vec<u8>,
    cred_random: [u8; 32],
}

/// The in-process authenticator.
pub struct SoftAuthenticator {
    master: [u8; 32],
    token_key: p256::SecretKey,
    pin_protocols: Vec<u8>,
    versions: Vec<String>,
    extensions: Vec<String>,
    credentials: Vec<SoftCredential>,
    sign_counter: u32,
    aaguid: [u8; 16],
}

fn hkdf(master: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("32-byte expansion");
    out
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Token-side saltAuth check written from the spec, not from the client's
/// `authenticate`, so a shared mistake cannot pass both sides: protocol 1
/// carries LEFT(HMAC, 16), protocol 2 the full 32-byte HMAC.
fn expected_salt_auth(protocol: Protocol, secret: &[u8], salt_enc: &[u8]) -> Vec<u8> {
    let (key, keep) = match protocol {
        Protocol::One => (secret, 16),
        Protocol::Two => (&secret[..32], 32),
    };
    hmac_sha256(key, salt_enc)[..keep].to_vec()
}

impl SoftAuthenticator {
    pub fn new(master: [u8; 32]) -> Self {
        Self {
            master,
            token_key: p256::SecretKey::from_slice(&hkdf(&master, b"token-agreement", 32))
                .expect("valid key"),
            pin_protocols: vec![1, 2],
            versions: vec!["FIDO_2_0".into(), "FIDO_2_1".into()],
            extensions: vec!["hmac-secret".into(), "credProtect".into()],
            credentials: Vec::new(),
            sign_counter: 0,
            aaguid: [0u8; 16],
        }
    }

    pub fn with_pin_protocols(mut self, protocols: Vec<u8>) -> Self {
        self.pin_protocols = protocols;
        self
    }

    pub fn with_versions(mut self, versions: Vec<&str>) -> Self {
        self.versions = versions.iter().map(|v| v.to_string()).collect();
        self
    }

    pub fn with_extensions(mut self, extensions: Vec<&str>) -> Self {
        self.extensions = extensions.iter().map(|v| v.to_string()).collect();
        self
    }

    /// The deterministic credential secret, for predicting outputs in tests.
    pub fn credential_random(&self, rp_id: &str, user_id: &[u8]) -> [u8; 32] {
        let mut info = b"cred-rand".to_vec();
        info.extend_from_slice(rp_id.as_bytes());
        info.extend_from_slice(user_id);
        hkdf(&self.master, &info, 32).try_into().expect("32 bytes")
    }

    fn credential_id(&self, rp_id: &str, user_id: &[u8]) -> Vec<u8> {
        let mut info = b"cred-id".to_vec();
        info.extend_from_slice(rp_id.as_bytes());
        info.extend_from_slice(user_id);
        hkdf(&self.master, &info, 16)
    }

    /// Handles one CTAP2 command (command byte + CBOR), answering with a
    /// CTAP2 response body (status byte + CBOR).
    pub fn handle(&mut self, command: u8, body: &[u8]) -> Vec<u8> {
        let (status, payload) = match command {
            CMD_GET_INFO => (OK, self.get_info()),
            CMD_CLIENT_PIN => self.client_pin(body),
            CMD_MAKE_CREDENTIAL => self.make_credential(body),
            CMD_GET_ASSERTION => self.get_assertion(body),
            _ => (0x01, Vec::new()),
        };
        let mut out = vec![status];
        out.extend_from_slice(&payload);
        out
    }

    fn get_info(&self) -> Vec<u8> {
        Value::Map(vec![
            (
                Value::Unsigned(1),
                Value::Array(
                    self.versions
                        .iter()
                        .map(|v| Value::TextString(v.clone()))
                        .collect(),
                ),
            ),
            (
                Value::Unsigned(2),
                Value::Array(
                    self.extensions
                        .iter()
                        .map(|v| Value::TextString(v.clone()))
                        .collect(),
                ),
            ),
            (Value::Unsigned(3), Value::ByteString(self.aaguid.to_vec())),
            (Value::Unsigned(5), Value::Unsigned(1024)),
            (
                Value::Unsigned(6),
                Value::Array(
                    self.pin_protocols
                        .iter()
                        .map(|p| Value::Unsigned(*p as u64))
                        .collect(),
                ),
            ),
        ])
        .encode()
    }

    fn client_pin(&mut self, body: &[u8]) -> (u8, Vec<u8>) {
        let Ok((v, rest)) = Value::decode(body) else {
            return (0x12, Vec::new());
        };
        if !rest.is_empty() {
            return (0x12, Vec::new());
        }
        // Spec request shape: {1: pinUvAuthProtocol, 2: subCommand}.
        let Some(protocol) = v.get(1).and_then(Value::as_unsigned) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        if protocol != 1 && protocol != 2 {
            return (0x02, Vec::new());
        }
        if v.get(2).and_then(Value::as_unsigned) != Some(SUBCMD_GET_KEY_AGREEMENT as u64) {
            // Baluard never sends other clientPIN subcommands.
            return (ERR_PIN_INVALID, Vec::new());
        }
        let point = self.token_key.public_key().to_encoded_point(false);
        let cose = Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Negative(-25)),
            (Value::Negative(-1), Value::Unsigned(1)),
            (
                Value::Negative(-2),
                Value::ByteString(point.as_bytes()[1..33].to_vec()),
            ),
            (
                Value::Negative(-3),
                Value::ByteString(point.as_bytes()[33..65].to_vec()),
            ),
        ]);
        (OK, Value::Map(vec![(Value::Unsigned(1), cose)]).encode())
    }

    fn make_credential(&mut self, body: &[u8]) -> (u8, Vec<u8>) {
        let Ok((v, rest)) = Value::decode(body) else {
            return (0x12, Vec::new());
        };
        if !rest.is_empty() {
            return (0x12, Vec::new());
        }
        let Some(rp_id) = v
            .get(2)
            .and_then(|rp| rp.get_text("id"))
            .and_then(|r| match r {
                Value::TextString(t) => Some(t.clone()),
                Value::ByteString(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
        else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let Some(user_id) = v
            .get(3)
            .and_then(|u| u.get_text("id"))
            .and_then(Value::as_bytes)
        else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let Some(algs) = v.get(4).and_then(Value::as_array) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let es256 = algs.iter().any(|a| {
            matches!(a.get_text("type"), Some(Value::TextString(t)) if t == "public-key")
                && matches!(a.get_text("alg"), Some(Value::Negative(-7)))
        });
        if !es256 {
            return (ERR_UNSUPPORTED_ALGORITHM, Vec::new());
        }
        if let Some(exclude) = v.get(5).and_then(Value::as_array) {
            let known = exclude.iter().any(|d| {
                d.get_text("id")
                    .and_then(Value::as_bytes)
                    .is_some_and(|id| self.has_credential(&rp_id, id))
            });
            if known {
                return (ERR_CREDENTIAL_EXCLUDED, Vec::new());
            }
        }
        // hmac-secret at make time is the `true` enable form: it registers
        // the credential for later assertions and produces no output.
        let hmac_requested = v
            .get(6)
            .map(|e| e.get_text("hmac-secret").is_some())
            .unwrap_or(false);
        if !hmac_requested {
            return (ERR_OPERATION_DENIED, Vec::new());
        }
        let id = self.credential_id(&rp_id, user_id);
        let cred_random = self.credential_random(&rp_id, user_id);
        let cose = self.credential_public_key_cose(&id);
        self.credentials.push(SoftCredential {
            rp_id: rp_id.clone(),
            id: id.clone(),
            cred_random,
        });
        self.sign_counter += 1;

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        // UP | AT | EXT: the enable form answers with "hmac-secret": true.
        auth_data.push(0x41 | 0x80);
        auth_data.extend_from_slice(&self.sign_counter.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(&cose);
        auth_data.extend_from_slice(
            Value::Map(vec![(
                Value::TextString("hmac-secret".into()),
                Value::Bool(true),
            )])
            .encode()
            .as_slice(),
        );

        let signature = self.attestation_signature(&auth_data);
        let response = Value::Map(vec![
            (Value::Unsigned(1), Value::TextString("packed".into())),
            (Value::Unsigned(2), Value::ByteString(auth_data)),
            (
                Value::Unsigned(3),
                Value::Map(vec![
                    (Value::TextString("alg".into()), Value::Negative(-7)),
                    (
                        Value::TextString("sig".into()),
                        Value::ByteString(signature),
                    ),
                    (
                        Value::TextString("x5c".into()),
                        Value::Array(vec![Value::ByteString(vec![0x30, 0x00])]),
                    ),
                ]),
            ),
        ]);
        (OK, response.encode())
    }

    fn get_assertion(&mut self, body: &[u8]) -> (u8, Vec<u8>) {
        let Ok((v, rest)) = Value::decode(body) else {
            return (0x12, Vec::new());
        };
        if !rest.is_empty() {
            return (0x12, Vec::new());
        }
        let Some(rp_id) = v.get(1).and_then(|r| match r {
            Value::TextString(t) => Some(t.clone()),
            Value::ByteString(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let Some(ext) = v.get(4).and_then(|e| e.get_text("hmac-secret")) else {
            return (ERR_OPERATION_DENIED, Vec::new());
        };
        // Spec: keyAgreement rides inline as a COSE_Key map, not a bstr.
        let Some(client_cose) = ext.get(1) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let Some(salt_enc) = ext.get(2).and_then(Value::as_bytes) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let Some(salt_auth) = ext.get(3).and_then(Value::as_bytes) else {
            return (ERR_MISSING_PARAMETER, Vec::new());
        };
        let protocol = match ext.get(4).and_then(Value::as_unsigned) {
            // CTAP2.0 predates key 4: its absence selects protocol 1.
            None => Protocol::One,
            Some(2) => Protocol::Two,
            _ => return (ERR_OPERATION_DENIED, Vec::new()),
        };
        // The extension input carries the CLIENT keyAgreement COSE map;
        // reduce it to the raw P-256 point for the token-side ECDH.
        let client_point = match crate::hwkey::ctap::protocol::cose_p256_public(client_cose).ok() {
            Some(p) => p,
            None => return (ERR_OPERATION_DENIED, Vec::new()),
        };
        let secret = (|| {
            let peer = p256::PublicKey::from_sec1_bytes(&client_point).ok()?;
            let z =
                p256::ecdh::diffie_hellman(self.token_key.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .to_vec();
            SharedSecret::from_shared_z(protocol, &z).ok()
        })();
        let Some(secret) = secret else {
            return (ERR_OPERATION_DENIED, Vec::new());
        };
        if expected_salt_auth(protocol, &secret.secret, salt_enc) != salt_auth {
            return (ERR_OPERATION_DENIED, Vec::new());
        }
        let Ok(salt) = secret.decrypt(salt_enc) else {
            return (ERR_OPERATION_DENIED, Vec::new());
        };

        let allow = v.get(3).and_then(Value::as_array).map(|list| {
            list.iter()
                .filter_map(|d| {
                    d.get_text("id")
                        .and_then(Value::as_bytes)
                        .map(|b| b.to_vec())
                })
                .collect::<Vec<Vec<u8>>>()
        });
        let Some(cred) = self
            .credentials
            .iter()
            .find(|c| c.rp_id == rp_id && allow.as_ref().map(|a| a.contains(&c.id)).unwrap_or(true))
            .cloned()
        else {
            return (ERR_NO_CREDENTIALS, Vec::new());
        };

        let mut outputs = hmac_sha256(&cred.cred_random, &salt[..32]).to_vec();
        if salt.len() >= 64 {
            outputs.extend(hmac_sha256(&cred.cred_random, &salt[32..64]));
        }
        let ext_out = secret.encrypt(&outputs).expect("model salt alignment");
        self.sign_counter += 1;

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(cred.rp_id.as_bytes()));
        auth_data.push(0x81); // UP | EXT
        auth_data.extend_from_slice(&self.sign_counter.to_be_bytes());
        let ext_map = Value::Map(vec![(
            Value::TextString("hmac-secret".into()),
            Value::ByteString(ext_out),
        )])
        .encode();
        auth_data.extend_from_slice(&ext_map);

        let signature = self.attestation_signature(&auth_data);
        let response = Value::Map(vec![
            (
                Value::Unsigned(1),
                Value::Map(vec![
                    (
                        Value::TextString("id".into()),
                        Value::ByteString(cred.id.clone()),
                    ),
                    (
                        Value::TextString("type".into()),
                        Value::TextString("public-key".into()),
                    ),
                ]),
            ),
            (Value::Unsigned(2), Value::ByteString(auth_data)),
            (Value::Unsigned(3), Value::ByteString(signature)),
        ]);
        (OK, response.encode())
    }

    fn has_credential(&self, rp_id: &str, id: &[u8]) -> bool {
        self.credentials
            .iter()
            .any(|c| c.rp_id == rp_id && c.id == id)
    }

    /// ES256-like credential public key: a P-256 point derived from the
    /// master seed and the credential id (never used to sign anything).
    fn credential_public_key_cose(&self, id: &[u8]) -> Vec<u8> {
        let seed = hkdf(&self.master, &[b"cred-key ", id].concat(), 32);
        let key = p256::SecretKey::from_slice(&seed).expect("valid key");
        let point = key.public_key().to_encoded_point(false);
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Negative(-7)),
            (Value::Negative(-1), Value::Unsigned(1)),
            (
                Value::Negative(-2),
                Value::ByteString(point.as_bytes()[1..33].to_vec()),
            ),
            (
                Value::Negative(-3),
                Value::ByteString(point.as_bytes()[33..65].to_vec()),
            ),
        ])
        .encode()
    }

    fn attestation_signature(&self, auth_data: &[u8]) -> Vec<u8> {
        // A synthetic-but-stable stand-in for the packed signature; tests
        // treat it as opaque bytes.
        hmac_sha256(&self.master, &[b"packed-sig", auth_data].concat()).to_vec()
    }
}

#[cfg(test)]
pub use self::tests::ModelLink;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hwkey::ctap::ctaphid::{self, CtapHidError, HidLink};
    use crate::hwkey::ctap::protocol::{ClientError, Ctap2Error, CtapClient};

    /// Spec-shaped hmac-secret extension input: the client keyAgreement
    /// rides inline as a COSE_Key map.
    fn key_agreement_map(secret: &SharedSecret) -> Value {
        let Ok((v, _)) = Value::decode(&secret.client_cose) else {
            panic!("client_cose must decode")
        };
        v
    }
    use std::cell::RefCell;

    /// HID link backed by the model, exercising real CTAPHID framing
    /// (chunked requests are reassembled before dispatch).
    pub struct ModelLink {
        model: RefCell<SoftAuthenticator>,
        inbox: RefCell<Vec<[u8; 65]>>,
        pending: RefCell<(Vec<u8>, usize)>,
        cid: [u8; 4],
    }

    impl ModelLink {
        pub fn new(model: SoftAuthenticator) -> Self {
            Self {
                model: RefCell::new(model),
                inbox: RefCell::new(Vec::new()),
                pending: RefCell::new((Vec::new(), 0)),
                cid: [0x01, 0x02, 0x03, 0x04],
            }
        }

        fn enqueue(&self, cmd: u8, payload: &[u8]) {
            let mut seq: u8 = 0;
            let mut offset = 0usize;
            let mut reports = Vec::new();
            while offset < payload.len() || reports.is_empty() {
                let mut r = [0u8; 65];
                r[1..5].copy_from_slice(&self.cid);
                if reports.is_empty() {
                    r[5] = cmd;
                    let len = payload.len() as u16;
                    r[6] = (len >> 8) as u8;
                    r[7] = len as u8;
                    let take = 57.min(payload.len());
                    r[8..8 + take].copy_from_slice(&payload[..take]);
                    offset = take;
                } else {
                    r[5] = seq;
                    let take = 59.min(payload.len() - offset);
                    r[6..6 + take].copy_from_slice(&payload[offset..offset + take]);
                    offset += take;
                    seq += 1;
                }
                reports.push(r);
            }
            self.inbox.borrow_mut().extend(reports);
        }
    }

    impl HidLink for ModelLink {
        fn write(&self, report: &[u8; 65]) -> Result<(), CtapHidError> {
            let cid = [report[1], report[2], report[3], report[4]];
            let cmd = report[5];
            if cmd == ctaphid::wire::CMD_INIT {
                let mut r = [0u8; 65];
                r[1..5].copy_from_slice(&ctaphid::wire::BROADCAST_CID);
                r[5] = cmd;
                r[8..16].copy_from_slice(&report[8..16]); // nonce echo
                r[16..20].copy_from_slice(&self.cid);
                r[20] = 2;
                r[21] = 5;
                r[22] = 7;
                r[23] = 3;
                r[24] = 0x05;
                self.inbox.borrow_mut().push(r);
                return Ok(());
            }
            // Reassemble chunked requests: the first frame carries the total
            // length, continuations append.
            let mut pending = self.pending.borrow_mut();
            if cmd & 0x80 != 0 {
                let total = ((report[6] as usize) << 8) | report[7] as usize;
                let take = 57.min(total);
                *pending = (report[8..8 + take].to_vec(), total);
            } else {
                let take = 59.min(pending.1 - pending.0.len());
                pending.0.extend_from_slice(&report[6..6 + take]);
            }
            if pending.0.len() >= pending.1 {
                let payload = std::mem::take(&mut pending.0);
                drop(pending);
                // First payload byte is the CTAP2 command; the rest is CBOR.
                let (&ctap_command, cbor) = payload.split_first().ok_or(CtapHidError::Malformed)?;
                let response = self.model.borrow_mut().handle(ctap_command, cbor);
                self.enqueue(ctaphid::wire::CMD_CBOR, &response);
            }
            Ok(())
        }

        fn read(&self) -> Result<[u8; 65], CtapHidError> {
            let mut inbox = self.inbox.borrow_mut();
            if inbox.is_empty() {
                return Err(CtapHidError::Link);
            }
            Ok(inbox.remove(0))
        }
    }

    fn master() -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        m
    }

    const RP: &str = "baluard.example";
    const USER: &[u8] = b"vault-1234";

    fn client_of(model: SoftAuthenticator) -> CtapClient<'static> {
        // Leak a link per test client; tests are short-lived and hermetic.
        let link: &'static ModelLink = Box::leak(Box::new(ModelLink::new(model)));
        CtapClient::new(link).expect("handshake over the model link")
    }

    #[test]
    fn enroll_then_derive_roundtrip_yields_the_predicted_secret() {
        let model = SoftAuthenticator::new(master());
        let expected_random = {
            // Predict from the master before enrolling.
            SoftAuthenticator::new(master()).credential_random(RP, USER)
        };
        let client = client_of(model);
        let info = client.require_hmac_secret().unwrap();
        assert_eq!(info.pin_protocols, vec![1, 2]);
        let secret = client.shared_secret(&info).unwrap();
        let made = client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        assert!(made.hmac_output_enc.is_none());
        assert!(!made.credential_id.is_empty());

        let salt = [9u8; 32];
        let secret2 = client
            .shared_secret(&client.require_hmac_secret().unwrap())
            .unwrap();
        let assertion = client
            .get_assertion(
                RP,
                &[7u8; 32],
                &[made.credential_id.clone()],
                &secret2,
                &salt,
                None,
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(assertion.secrets.len(), 1);
        assert_eq!(*assertion.secrets[0], hmac_sha256(&expected_random, &salt));
    }

    #[test]
    fn two_salts_yield_two_outputs() {
        let client = client_of(SoftAuthenticator::new(master()));
        let made = client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let info = client.require_hmac_secret().unwrap();
        let secret = client.shared_secret(&info).unwrap();
        let (s1, s2) = ([3u8; 32], [4u8; 32]);
        let assertion = client
            .get_assertion(RP, &[7u8; 32], &[], &secret, &s1, Some(&s2), &mut |_| {})
            .unwrap();
        let random = SoftAuthenticator::new(master()).credential_random(RP, USER);
        assert_eq!(assertion.secrets.len(), 2);
        assert_eq!(*assertion.secrets[0], hmac_sha256(&random, &s1));
        assert_eq!(*assertion.secrets[1], hmac_sha256(&random, &s2));
    }

    #[test]
    fn tampered_salt_auth_is_refused() {
        let client = client_of(SoftAuthenticator::new(master()));
        client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let info = client.require_hmac_secret().unwrap();
        let secret = client.shared_secret(&info).unwrap();
        // Hand-craft an assertion whose saltAuth does not match saltEnc:
        // forge by encrypting one salt and authenticating another.
        let salt = [5u8; 32];
        let other = [6u8; 32];
        let salt_enc = secret.encrypt(&salt).unwrap();
        let salt_auth = secret.authenticate(&other);
        let ext = Value::Map(vec![(
            Value::TextString("hmac-secret".into()),
            Value::Map(vec![
                (
                    Value::Unsigned(1),
                    key_agreement_map(&secret),
                ),
                (Value::Unsigned(2), Value::ByteString(salt_enc)),
                (Value::Unsigned(3), Value::ByteString(salt_auth)),
                (Value::Unsigned(4), Value::Unsigned(1)),
            ]),
        )]);
        let request = [
            &[0x02u8][..],
            &Value::Map(vec![
                (Value::Unsigned(1), Value::TextString(RP.into())),
                (Value::Unsigned(2), Value::ByteString(vec![7u8; 32])),
                (Value::Unsigned(4), ext),
                (
                    Value::Unsigned(5),
                    Value::Map(vec![(Value::TextString("up".into()), Value::Bool(true))]),
                ),
            ])
            .encode(),
        ]
        .concat();
        // Drive through the same ctaphid path the client uses.
        let Ok((status, _)) = client.cbor_raw(&request) else {
            panic!("cbor_raw failed")
        };
        assert_eq!(status, ERR_OPERATION_DENIED);
    }

    #[test]
    fn protocol_two_rejects_a_truncated_salt_auth() {
        let client = client_of(SoftAuthenticator::new(master()));
        client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let info = client.require_hmac_secret().unwrap();
        let secret = client.shared_secret(&info).unwrap();
        assert_eq!(secret.protocol, Protocol::Two);
        let salt_enc = secret.encrypt(&[5u8; 32]).unwrap();
        let salt_auth = secret.authenticate(&salt_enc);
        assert_eq!(salt_auth.len(), 32);
        let ext = Value::Map(vec![(
            Value::TextString("hmac-secret".into()),
            Value::Map(vec![
                (
                    Value::Unsigned(1),
                    key_agreement_map(&secret),
                ),
                (Value::Unsigned(2), Value::ByteString(salt_enc)),
                (
                    Value::Unsigned(3),
                    Value::ByteString(salt_auth[..16].to_vec()),
                ),
                (Value::Unsigned(4), Value::Unsigned(2)),
            ]),
        )]);
        let request = [
            &[0x02u8][..],
            &Value::Map(vec![
                (Value::Unsigned(1), Value::TextString(RP.into())),
                (Value::Unsigned(2), Value::ByteString(vec![7u8; 32])),
                (Value::Unsigned(4), ext),
            ])
            .encode(),
        ]
        .concat();
        let (status, _) = client.cbor_raw(&request).unwrap();
        assert_eq!(status, ERR_OPERATION_DENIED);
    }

    #[test]
    fn unknown_rp_answers_no_credentials() {
        let client = client_of(SoftAuthenticator::new(master()));
        client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let info = client.require_hmac_secret().unwrap();
        let secret = client.shared_secret(&info).unwrap();
        let err = client
            .get_assertion(
                "other.example",
                &[7u8; 32],
                &[],
                &secret,
                &[9u8; 32],
                None,
                &mut |_| {},
            )
            .unwrap_err();
        assert!(matches!(err, ClientError::Ctap2(Ctap2Error(0x2e))));
    }

    #[test]
    fn exclude_list_refuses_a_re_enroll_of_the_same_credential() {
        let client = client_of(SoftAuthenticator::new(master()));
        let made = client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let err = client
            .make_credential(
                &[7u8; 32],
                RP,
                USER,
                "Baluard",
                &[made.credential_id.clone()],
                &mut |_| {},
            )
            .unwrap_err();
        assert!(matches!(err, ClientError::Ctap2(Ctap2Error(0x19))));
    }

    #[test]
    fn non_es256_algorithm_is_refused() {
        let client = client_of(SoftAuthenticator::new(master()));
        // Drive a raw request with alg -257 (RS256) through the link.
        let request = [
            &[0x01u8][..],
            &Value::Map(vec![
                (Value::Unsigned(1), Value::ByteString(vec![7u8; 32])),
                (
                    Value::Unsigned(2),
                    Value::Map(vec![(
                        Value::TextString("id".into()),
                        Value::TextString(RP.into()),
                    )]),
                ),
                (
                    Value::Unsigned(3),
                    Value::Map(vec![(
                        Value::TextString("id".into()),
                        Value::ByteString(USER.to_vec()),
                    )]),
                ),
                (
                    Value::Unsigned(4),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::TextString("type".into()),
                            Value::TextString("public-key".into()),
                        ),
                        (Value::TextString("alg".into()), Value::Negative(-257)),
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
            .encode(),
        ]
        .concat();
        let Ok((status, _)) = client.cbor_raw(&request) else {
            panic!("cbor_raw failed")
        };
        assert_eq!(status, ERR_UNSUPPORTED_ALGORITHM);
    }

    #[test]
    fn protocol_one_only_token_still_derives() {
        let client = client_of(SoftAuthenticator::new(master()).with_pin_protocols(vec![1]));
        client
            .make_credential(&[7u8; 32], RP, USER, "Baluard", &[], &mut |_| {})
            .unwrap();
        let info = client.require_hmac_secret().unwrap();
        let salt = [2u8; 32];
        let secret = client.shared_secret(&info).unwrap();
        assert_eq!(secret.protocol, Protocol::One);
        let assertion = client
            .get_assertion(RP, &[7u8; 32], &[], &secret, &salt, None, &mut |_| {})
            .unwrap();
        let random = SoftAuthenticator::new(master()).credential_random(RP, USER);
        assert_eq!(*assertion.secrets[0], hmac_sha256(&random, &salt));
    }

    #[test]
    fn token_without_hmac_secret_is_unsupported() {
        let client =
            client_of(SoftAuthenticator::new(master()).with_extensions(vec!["credProtect"]));
        let err = client.require_hmac_secret().unwrap_err();
        assert!(matches!(err, ClientError::NoHmacSecret));
    }
}
