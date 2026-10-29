//! CTAP2 command layer for the PIN-less hmac-secret seal (spec §6.1/6.2,
//! §12.2.6 hmac-secret extension).
//!
//! Only the four commands Baluard needs: getInfo, makeCredential,
//! getAssertion, and clientPIN getKeyAgreement. Everything rides the
//! canonical CBOR module and CTAPHID; transports differ only below this
//! layer.

use super::apdu::{self, ApduError, ApduForm, Transceive};
use super::cbor::Value;
use super::ctaphid::{self, CtapHidError, DeviceInfo, HidLink};
use super::pinproto::SharedSecret;
use crate::hwkey::attest::PackedAttestation;
use std::cell::OnceCell;
use zeroize::Zeroizing;

pub const CTAP2_OK: u8 = 0x00;
const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_CLIENT_PIN: u8 = 0x06;
const SUBCMD_GET_KEY_AGREEMENT: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctap2Error(pub u8);

impl std::fmt::Display for Ctap2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "security key error {}", map_status(self.0))
    }
}

/// CTAP2 status codes (spec §6.1.2 table) mapped to honest names.
fn map_status(code: u8) -> &'static str {
    match code {
        0x00 => "ok",
        0x01 => "invalid command",
        0x02 => "invalid parameter",
        0x03 => "invalid length",
        0x04 => "invalid sequence",
        0x05 => "timeout",
        0x06 => "channel busy",
        0x0a => "lock required",
        0x0b => "invalid channel",
        0x11 => "unexpected CBOR type",
        0x12 => "invalid CBOR",
        0x14 => "missing parameter",
        0x15 => "limit exceeded",
        0x16 => "unsupported extension",
        0x19 => "credential excluded",
        0x21 => "processing",
        0x22 => "invalid credential",
        0x23 => "user action pending",
        0x24 => "operation pending",
        0x25 => "no operations",
        0x26 => "unsupported algorithm",
        0x27 => "operation denied",
        0x28 => "key store full",
        0x2b => "unsupported option",
        0x2c => "invalid option",
        0x2d => "keepalive cancelled",
        0x2e => "no credentials",
        0x2f => "timed out waiting for touch",
        0x31 => "pin invalid",
        0x32 => "pin blocked",
        0x33 => "pinUvAuth invalid",
        0x34 => "pin auth blocked",
        0x35 => "pin not set",
        0x36 => "pin required",
        0x39 => "request too large",
        0x3b => "touch required",
        0x3c => "user verification blocked",
        0x3d => "integrity failure",
        0x3e => "invalid subcommand",
        0x3f => "user verification invalid",
        _ => "unknown error",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Hid(CtapHidError),
    Apdu(ApduError),
    Ctap2(Ctap2Error),
    /// The token cannot serve the PIN-less hmac-secret seal.
    Unsupported(String),
    Malformed(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Hid(e) => write!(f, "security key link error: {e:?}"),
            ClientError::Apdu(e) => write!(f, "security key NFC error: {e:?}"),
            ClientError::Ctap2(e) => write!(f, "{e}"),
            ClientError::Unsupported(m) => write!(f, "security key unsupported: {m}"),
            ClientError::Malformed(m) => write!(f, "security key response malformed: {m}"),
        }
    }
}

impl From<CtapHidError> for ClientError {
    fn from(e: CtapHidError) -> Self {
        ClientError::Hid(e)
    }
}

impl From<ApduError> for ClientError {
    fn from(e: ApduError) -> Self {
        ClientError::Apdu(e)
    }
}

/// The subset of getInfo Baluard reads before enrolling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInfo {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: [u8; 16],
    pub max_msg_size: Option<u32>,
    pub pin_protocols: Vec<u8>,
    pub pin_set: bool,
    pub uv_forced: bool,
}

/// A makeCredential result: the new credential plus its attestation object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MadeCredential {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    /// Encrypted hmac-secret output from the authData extensions, if the
    /// token produced one (it does for the creation seal).
    pub hmac_output_enc: Option<Vec<u8>>,
    /// Raw attestation object fields, carried for attest.rs verification.
    pub attestation: PackedAttestation,
}

/// No `Clone`; `Debug` hides the hmac-secret outputs.
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// Decrypted hmac-secret outputs (1 or 2 x 32 bytes), wiped on drop.
    pub secrets: Vec<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assertion")
            .field("credential_id", &self.credential_id)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

enum Channel<'a> {
    Hid {
        link: &'a dyn HidLink,
        device: DeviceInfo,
    },
    Apdu {
        link: &'a dyn Transceive,
        form: ApduForm,
    },
}

/// A PIN-less CTAP2 client over a CTAPHID or NFC link.
pub struct CtapClient<'a> {
    channel: Channel<'a>,
    /// getInfo answers are stable for one connection; ask the key once.
    info: OnceCell<GetInfo>,
}

impl<'a> CtapClient<'a> {
    pub fn new(link: &'a dyn HidLink) -> Result<Self, ClientError> {
        Ok(Self {
            channel: Channel::Hid {
                link,
                device: ctaphid::init(link)?,
            },
            info: OnceCell::new(),
        })
    }

    /// NFC client with extended-length APDUs. Use [`CtapClient::new_apdu_form`]
    /// when the phone's reader cannot send them.
    pub fn new_apdu(link: &'a dyn Transceive) -> Result<Self, ClientError> {
        Self::new_apdu_form(link, ApduForm::Extended)
    }

    /// NFC client with an explicit APDU shape: the caller knows what its
    /// reader supports (Android `IsoDep.isExtendedLengthApduSupported()`,
    /// see [`ApduForm::for_extended_support`]).
    ///
    /// SELECT answers `FIDO_2_0` for CTAP2-only keys and `U2F_V2` for keys
    /// that also speak U2F (YubiKeys); the latter proves CTAP2 with getInfo.
    pub fn new_apdu_form(link: &'a dyn Transceive, form: ApduForm) -> Result<Self, ClientError> {
        let version = apdu::select_fido(link)?;
        let proves_ctap2 = match version.as_slice() {
            b"FIDO_2_0" => false,
            b"U2F_V2" => true,
            _ => return Err(ClientError::Unsupported("FIDO applet is not CTAP2".into())),
        };
        let client = Self {
            channel: Channel::Apdu { link, form },
            info: OnceCell::new(),
        };
        if proves_ctap2 {
            let not_ctap2 = || ClientError::Unsupported("security key does not speak CTAP2".into());
            let info = client.get_info().map_err(|e| match e {
                ClientError::Apdu(ApduError::StatusWord(_)) | ClientError::Ctap2(_) => not_ctap2(),
                other => other,
            })?;
            if !info.versions.iter().any(|v| v.starts_with("FIDO_2")) {
                return Err(not_ctap2());
            }
        }
        Ok(client)
    }

    pub fn device(&self) -> Option<&DeviceInfo> {
        match &self.channel {
            Channel::Hid { device, .. } => Some(device),
            Channel::Apdu { .. } => None,
        }
    }

    fn cbor(
        &self,
        payload: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<(u8, Vec<u8>), ClientError> {
        match self.channel {
            Channel::Hid { link, ref device } => {
                ctaphid::cbor(link, &device.cid, payload, on_keepalive).map_err(Into::into)
            }
            Channel::Apdu { link, form } => {
                let (&command, cbor) = payload
                    .split_first()
                    .ok_or_else(|| ClientError::Malformed("empty CTAP2 request".into()))?;
                let response = apdu::nfcctap_msg(link, form, command, cbor)?;
                let (&status, body) = response
                    .split_first()
                    .ok_or(ClientError::Apdu(ApduError::Malformed))?;
                Ok((status, body.to_vec()))
            }
        }
    }

    fn cbor_wait(&self, payload: &[u8]) -> Result<(u8, Vec<u8>), ClientError> {
        // The caller drives its own touch UX; keepalive statuses are ignored
        // here and the link's own read timeout bounds the wait.
        self.cbor(payload, &mut |_| {})
    }

    /// Sends a raw CTAP2 command body (command byte + CBOR) and returns the
    /// unfiltered (status, CBOR) pair. Test-support and the 4B parity gate.
    pub fn cbor_raw(&self, payload: &[u8]) -> Result<(u8, Vec<u8>), ClientError> {
        self.cbor_wait(payload)
    }

    fn check(status: u8, body: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        if status == CTAP2_OK {
            Ok(body)
        } else {
            Err(ClientError::Ctap2(Ctap2Error(status)))
        }
    }

    pub fn get_info(&self) -> Result<GetInfo, ClientError> {
        if let Some(info) = self.info.get() {
            return Ok(info.clone());
        }
        let info = self.fetch_info()?;
        Ok(self.info.get_or_init(|| info).clone())
    }

    fn fetch_info(&self) -> Result<GetInfo, ClientError> {
        // getInfo request: empty map (optionally with 0x01 extensions list).
        let req = Value::Map(vec![]).encode();
        let payload = [&[CMD_GET_INFO][..], &req[..]].concat();
        let (status, body) = self.cbor_wait(&payload)?;
        let body = Self::check(status, body)?;
        let (v, rest) =
            Value::decode(&body).map_err(|_| ClientError::Malformed("getInfo".into()))?;
        if !rest.is_empty() {
            return Err(ClientError::Malformed("getInfo trailing bytes".into()));
        }
        let field = |k: i64| v.get(k).cloned();
        let versions = field(1)
            .map(|v| match v {
                Value::Array(items) => items
                    .into_iter()
                    .filter_map(|s| match s {
                        Value::TextString(t) => Some(t),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        let extensions = field(2)
            .map(|v| match v {
                Value::Array(items) => items
                    .into_iter()
                    .filter_map(|s| match s {
                        Value::TextString(t) => Some(t),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        let aaguid = field(3)
            .and_then(|v| v.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()))
            .ok_or_else(|| ClientError::Malformed("getInfo aaguid".into()))?;
        let max_msg_size = field(5).and_then(|v| v.as_unsigned().map(|n| n as u32));
        // CTAP2 authenticatorGetInfo: key 6 is pinUvAuthProtocols (key 7 is
        // maxCredentialCountInList).
        let pin_protocols = field(6)
            .map(|v| match v {
                Value::Array(items) => items
                    .into_iter()
                    .filter_map(|n| n.as_unsigned().map(|n| n as u8))
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        let option = |name: &str| {
            field(4)
                .and_then(|options| match options {
                    Value::Map(entries) => entries
                        .into_iter()
                        .find(|(k, _)| matches!(k, Value::TextString(k) if k == name))
                        .and_then(|(_, v)| match v {
                            Value::Bool(b) => Some(b),
                            _ => None,
                        }),
                    _ => None,
                })
                .unwrap_or(false)
        };
        Ok(GetInfo {
            versions,
            extensions,
            aaguid,
            max_msg_size,
            pin_protocols,
            pin_set: option("clientPin"),
            uv_forced: option("alwaysUv"),
        })
    }

    /// Proves the token can serve the PIN-less hmac-secret seal.
    pub fn require_hmac_secret(&self) -> Result<GetInfo, ClientError> {
        let info = self.get_info()?;
        if !info.versions.iter().any(|v| v.starts_with("FIDO_2")) {
            return Err(ClientError::Unsupported("no FIDO2 support".into()));
        }
        if !info.extensions.iter().any(|e| e == "hmac-secret") {
            return Err(ClientError::Unsupported("no hmac-secret extension".into()));
        }
        if info.pin_protocols.is_empty() {
            return Err(ClientError::Unsupported("no pinUvAuth protocol".into()));
        }
        Ok(info)
    }

    /// Establishes a shared secret under the token's preferred pinUvAuth
    /// protocol (PIN-less use: only salt encryption, never a PIN).
    pub fn shared_secret(&self, info: &GetInfo) -> Result<SharedSecret, ClientError> {
        // Prefer protocol 2 (constant, random-IV), fall back to 1.
        let protocol = if info.pin_protocols.contains(&2) {
            super::pinproto::Protocol::Two
        } else {
            super::pinproto::Protocol::One
        };
        // clientPIN getKeyAgreement: {1: pinUvAuthProtocol, 2: subCommand}.
        let protocol_no = match protocol {
            super::pinproto::Protocol::Two => 2,
            super::pinproto::Protocol::One => 1,
        };
        let req = Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(protocol_no)),
            (
                Value::Unsigned(2),
                Value::Unsigned(SUBCMD_GET_KEY_AGREEMENT as u64),
            ),
        ])
        .encode();
        let payload = [&[CMD_CLIENT_PIN][..], &req[..]].concat();
        let (status, body) = self.cbor_wait(&payload)?;
        let body = Self::check(status, body)?;
        let (v, rest) =
            Value::decode(&body).map_err(|_| ClientError::Malformed("clientPIN".into()))?;
        if !rest.is_empty() {
            return Err(ClientError::Malformed("clientPIN trailing bytes".into()));
        }
        // Response: {1: keyAgreement COSE}
        let key = v
            .get(1)
            .ok_or_else(|| ClientError::Malformed("clientPIN keyAgreement".into()))?;
        let cose = cose_p256_public(key)?;
        SharedSecret::new(protocol, &cose).map_err(ClientError::Malformed)
    }

    /// makeCredential for the PIN-less seal: ES256, discoverable=false,
    /// hmac-secret=true. `exclude_ids` lists existing credentials so a
    /// re-enroll against a token already holding the seal id fails instead
    /// of silently creating a second one.
    pub fn make_credential(
        &self,
        client_data_hash: &[u8; 32],
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        exclude_ids: &[Vec<u8>],
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<MadeCredential, ClientError> {
        let rp = Value::Map(vec![(
            Value::TextString("id".into()),
            Value::TextString(rp_id.into()),
        )]);
        let user = Value::Map(vec![
            (
                Value::TextString("id".into()),
                Value::ByteString(user_id.to_vec()),
            ),
            (
                Value::TextString("name".into()),
                Value::TextString(user_name.into()),
            ),
            (
                Value::TextString("displayName".into()),
                Value::TextString(user_name.into()),
            ),
        ]);
        let alg = Value::Map(vec![
            (
                Value::TextString("type".into()),
                Value::TextString("public-key".into()),
            ),
            (Value::TextString("alg".into()), Value::Negative(-7)),
        ]);
        let mut map = vec![
            (
                Value::Unsigned(1),
                Value::ByteString(client_data_hash.to_vec()),
            ),
            (Value::Unsigned(2), rp),
            (Value::Unsigned(3), user),
            (Value::Unsigned(4), Value::Array(vec![alg])),
            (
                Value::Unsigned(6),
                Value::Map(vec![(
                    Value::TextString("hmac-secret".into()),
                    Value::Bool(true),
                )]),
            ),
            (
                Value::Unsigned(7),
                Value::Map(vec![(Value::TextString("rk".into()), Value::Bool(false))]),
            ),
        ];
        if !exclude_ids.is_empty() {
            let list: Vec<Value> = exclude_ids
                .iter()
                .map(|id| {
                    Value::Map(vec![
                        (
                            Value::TextString("id".into()),
                            Value::ByteString(id.clone()),
                        ),
                        (
                            Value::TextString("type".into()),
                            Value::TextString("public-key".into()),
                        ),
                    ])
                })
                .collect();
            map.push((Value::Unsigned(5), Value::Array(list)));
        }
        // No pinUvAuthParam (7/8): the seal is PIN-less, uv discouraged.
        let payload = build_request(CMD_MAKE_CREDENTIAL, map);
        let (status, body) = self.cbor(&payload, on_keepalive)?;
        let body = Self::check(status, body)?;
        parse_make_credential(&body, client_data_hash)
    }

    /// getAssertion with the PIN-less hmac-secret extension.
    pub fn get_assertion(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allow_ids: &[Vec<u8>],
        secrets: &SharedSecret,
        salt1: &[u8; 32],
        salt2: Option<&[u8; 32]>,
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Assertion, ClientError> {
        let mut salt = salt1.to_vec();
        if let Some(s) = salt2 {
            salt.extend_from_slice(s);
        }
        let salt_enc = secrets.encrypt(&salt);
        let salt_auth = secrets.authenticate(&salt_enc);
        let extensions = Value::Map(vec![(
            Value::TextString("hmac-secret".into()),
            Value::Map(vec![
                // The extension input carries the CLIENT keyAgreement COSE
                // as an inline map, never a byte string.
                (
                    Value::Unsigned(1),
                    Value::decode(&secrets.client_cose)
                        .map_err(|_| ClientError::Malformed("keyAgreement COSE".into()))?
                        .0,
                ),
                (Value::Unsigned(2), Value::ByteString(salt_enc)),
                (Value::Unsigned(3), Value::ByteString(salt_auth)),
                (
                    Value::Unsigned(4),
                    Value::Unsigned(protocol_number(secrets)),
                ),
            ]),
        )]);
        let mut map = vec![
            (Value::Unsigned(1), Value::TextString(rp_id.into())),
            (
                Value::Unsigned(2),
                Value::ByteString(client_data_hash.to_vec()),
            ),
            (Value::Unsigned(4), extensions),
            (
                Value::Unsigned(5),
                Value::Map(vec![(Value::TextString("up".into()), Value::Bool(true))]),
            ),
        ];
        if !allow_ids.is_empty() {
            let list: Vec<Value> = allow_ids
                .iter()
                .map(|id| {
                    Value::Map(vec![
                        (
                            Value::TextString("id".into()),
                            Value::ByteString(id.clone()),
                        ),
                        (
                            Value::TextString("type".into()),
                            Value::TextString("public-key".into()),
                        ),
                    ])
                })
                .collect();
            map.push((Value::Unsigned(3), Value::Array(list)));
        }
        let payload = build_request(CMD_GET_ASSERTION, map);
        let (status, body) = self.cbor(&payload, on_keepalive)?;
        let body = Self::check(status, body)?;
        parse_assertion(&body, secrets)
    }
}

fn protocol_number(secrets: &SharedSecret) -> u64 {
    match secrets.protocol {
        super::pinproto::Protocol::One => 1,
        super::pinproto::Protocol::Two => 2,
    }
}

/// Encodes a CTAP2 command: command byte + canonical CBOR map.
fn build_request(command: u8, map: Vec<(Value, Value)>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(map.len() * 8 + 8);
    payload.push(command);
    payload.extend_from_slice(&Value::Map(map).encode());
    payload
}

/// makeCredential response: {1: fmt, 2: authData, 3: attStmt}.
pub fn parse_make_credential(
    body: &[u8],
    client_data_hash: &[u8; 32],
) -> Result<MadeCredential, ClientError> {
    let (v, rest) =
        Value::decode(body).map_err(|_| ClientError::Malformed("makeCredential".into()))?;
    if !rest.is_empty() {
        return Err(ClientError::Malformed(
            "makeCredential trailing bytes".into(),
        ));
    }
    let auth_data = v
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("authData".into()))?;
    let att = parse_attestation(&v, client_data_hash)?;
    let acd = attested_credential_data(auth_data)?;
    let hmac_output_enc = auth_data_extensions(auth_data)?;
    Ok(MadeCredential {
        credential_id: acd.0,
        credential_public_key: acd.1,
        hmac_output_enc,
        attestation: att,
    })
}

fn parse_attestation(
    v: &Value,
    client_data_hash: &[u8; 32],
) -> Result<PackedAttestation, ClientError> {
    let stmt = v
        .get(3)
        .ok_or_else(|| ClientError::Malformed("attStmt".into()))?;
    let alg = match stmt.get_text("alg") {
        Some(Value::Negative(n)) => *n,
        Some(Value::Unsigned(n)) => *n as i64,
        _ => return Err(ClientError::Malformed("attStmt alg".into())),
    };
    let sig = stmt
        .get_text("sig")
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("attStmt sig".into()))?;
    // x5c is an ARRAY of DER certificates, leaf first.
    let x5c = stmt
        .get_text("x5c")
        .and_then(Value::as_array)
        .map(|certs| {
            certs
                .iter()
                .filter_map(Value::as_bytes)
                .map(|cert| cert.to_vec())
                .collect::<Vec<_>>()
        })
        .filter(|certs| !certs.is_empty())
        .ok_or_else(|| ClientError::Malformed("attStmt x5c".into()))?;
    let auth_data = v
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("authData".into()))?;
    Ok(PackedAttestation {
        credential_id: attested_credential_data(auth_data)?.0,
        auth_data: auth_data.to_vec(),
        client_data_hash: *client_data_hash,
        alg,
        sig: sig.to_vec(),
        x5c,
    })
}

/// authData layout (flags bit 6 set): after rpIdHash/flags/signCount come
/// aaguid(16), credIdLen(2), credId, COSE pubkey. Returns (id, coseKey).
fn attested_credential_data(auth_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    const ATTESTED_FLAG: u8 = 0x40;
    if auth_data.len() < 37 || auth_data[32] & ATTESTED_FLAG == 0 {
        return Err(ClientError::Malformed("no attested credential data".into()));
    }
    let at = 37;
    let len = u16::from_be_bytes([
        *auth_data
            .get(at + 16)
            .ok_or_else(|| ClientError::Malformed("cred len".into()))?,
        *auth_data
            .get(at + 17)
            .ok_or_else(|| ClientError::Malformed("cred len".into()))?,
    ]) as usize;
    let end = at + 16 + 2;
    let id_end = end + len;
    if auth_data.len() < id_end {
        return Err(ClientError::Malformed("credential id".into()));
    }
    // COSE key is canonical CBOR; decode from the tail and ignore whatever
    // follows (extensions live after the key).
    let (cose, _) = Value::decode(&auth_data[id_end..])
        .map_err(|_| ClientError::Malformed("credential public key".into()))?;
    Ok((auth_data[end..id_end].to_vec(), cose.encode()))
}

/// authData trailing extensions (flags bit 7): a canonical CBOR map whose
/// "hmac-secret" entry is the encrypted output (creation or assertion).
/// When the attested-credential flag is set, the ACD block is skipped first.
fn auth_data_extensions(auth_data: &[u8]) -> Result<Option<Vec<u8>>, ClientError> {
    const ATTESTED_FLAG: u8 = 0x40;
    const EXT_FLAG: u8 = 0x80;
    if auth_data.len() < 37 || auth_data[32] & EXT_FLAG == 0 {
        return Ok(None);
    }
    let mut at = 37;
    if auth_data[32] & ATTESTED_FLAG != 0 {
        let len = u16::from_be_bytes([
            *auth_data
                .get(at + 16)
                .ok_or_else(|| ClientError::Malformed("cred len".into()))?,
            *auth_data
                .get(at + 17)
                .ok_or_else(|| ClientError::Malformed("cred len".into()))?,
        ]) as usize;
        at += 16 + 2 + len;
    }
    let (v, _) = Value::decode(&auth_data[at..])
        .map_err(|_| ClientError::Malformed("authData ext".into()))?;
    // Enable-form makeCredential answers "hmac-secret": true (applied, no
    // output); only salt-bearing requests and assertions carry ciphertext.
    match v.get_text("hmac-secret") {
        Some(Value::ByteString(out)) => Ok(Some(out.to_vec())),
        Some(Value::Bool(true)) | None => Ok(None),
        Some(_) => Err(ClientError::Malformed("hmac-secret output".into())),
    }
}

/// getAssertion response: {1: credentialId, 2: authData, 3: signature, 4: user,
/// 5: numberOfCredentials}; the hmac-secret output rides the authData
/// extensions map, exactly as in makeCredential.
pub fn parse_assertion(body: &[u8], secrets: &SharedSecret) -> Result<Assertion, ClientError> {
    let (v, rest) =
        Value::decode(body).map_err(|_| ClientError::Malformed("getAssertion".into()))?;
    if !rest.is_empty() {
        return Err(ClientError::Malformed("getAssertion trailing bytes".into()));
    }
    let credential_id = v
        .get(1)
        .and_then(|d| d.get_text("id"))
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("assertion credentialId".into()))?
        .to_vec();
    let auth_data = v
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("assertion authData".into()))?
        .to_vec();
    let signature = v
        .get(3)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("assertion signature".into()))?
        .to_vec();
    let enc = auth_data_extensions(&auth_data)?
        .ok_or_else(|| ClientError::Malformed("hmac-secret assertion output".into()))?;
    let plain = secrets.decrypt(&enc).map_err(ClientError::Malformed)?;
    if plain.len() != 32 && plain.len() != 64 {
        return Err(ClientError::Malformed("hmac-secret output length".into()));
    }
    let secrets_out = plain
        .chunks_exact(32)
        .map(|c| {
            let mut s = Zeroizing::new([0u8; 32]);
            s.copy_from_slice(c);
            s
        })
        .collect();
    Ok(Assertion {
        credential_id,
        auth_data,
        signature,
        secrets: secrets_out,
    })
}

/// Extracts the uncompressed P-256 point from a COSE EC2 key
/// ({1:2 EC2, 3:-25 ES256, -1:1 P-256, -2: x, -3: y}).
pub fn cose_p256_public(key: &Value) -> Result<Vec<u8>, ClientError> {
    let kty = key.get(1).and_then(Value::as_unsigned).unwrap_or(0);
    let crv = key.get(-1).and_then(Value::as_unsigned).unwrap_or(0);
    let alg_ok = matches!(key.get(3), Some(Value::Negative(-25)));
    if kty != 2 || crv != 1 || !alg_ok {
        return Err(ClientError::Malformed(
            "key agreement is not ES256 P-256 EC2".into(),
        ));
    }
    let x = key
        .get(-2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("x".into()))?;
    let y = key
        .get(-3)
        .and_then(Value::as_bytes)
        .ok_or_else(|| ClientError::Malformed("y".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(ClientError::Malformed("coordinate length".into()));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hwkey::ctap::cbor::Value;

    #[test]
    fn cose_point_extraction_rejects_non_p256() {
        let bad = Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::Negative(-1), Value::Unsigned(1)),
            (Value::Negative(-2), Value::ByteString(vec![0u8; 32])),
            (Value::Negative(-3), Value::ByteString(vec![0u8; 32])),
        ]);
        assert!(matches!(
            cose_p256_public(&bad),
            Err(ClientError::Malformed(_))
        ));
    }

    #[test]
    fn status_names_are_honest() {
        assert_eq!(map_status(0x19), "credential excluded");
        assert_eq!(map_status(0x2f), "timed out waiting for touch");
        assert_eq!(map_status(0x7f), "unknown error");
    }

    #[test]
    fn display_carries_the_status_name() {
        let e = Ctap2Error(0x2f);
        assert_eq!(
            e.to_string(),
            "security key error timed out waiting for touch"
        );
    }
}
