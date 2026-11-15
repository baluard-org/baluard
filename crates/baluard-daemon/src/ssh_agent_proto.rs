//! ssh-agent wire protocol (draft-miller-ssh-agent) framing and message
//! codec. Pure bytes in, pure bytes out: no sockets, no vault, no crypto.
//!
//! Message numbers as used by OpenSSH:
//! - `11` SSH_AGENTC_REQUEST_IDENTITIES
//! - `12` SSH_AGENT_IDENTITIES_ANSWER (also SSH_AGENT_FAILURE)
//! - `13` SSH_AGENTC_SIGN_REQUEST
//! - `14` SSH_AGENT_SIGN_RESPONSE
//!
//! The number 12 doubles as the failure answer: an agent answers any
//! unsupported request with the bare `12` opcode, and an identities
//! request with no keys is the same bytes plus a zero count. OpenSSH
//! treats both identically.

/// Frame size ceiling. A legitimate identities or sign request never
/// approaches this; anything larger is a hostile or broken client and the
/// connection is dropped before allocation.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

const AGENTC_REQUEST_IDENTITIES: u8 = 11;
const AGENT_FAILURE: u8 = 12;
const AGENT_IDENTITIES_ANSWER: u8 = 12;
const AGENTC_SIGN_REQUEST: u8 = 13;
const AGENT_SIGN_RESPONSE: u8 = 14;

/// One parsed client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    /// `11`: list served keys.
    RequestIdentities,
    /// `13`: sign `data` with the key named by `key_blob`.
    SignRequest {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        /// RSA SHA-2 variant flags. Only RSA reacts to them; Baluard serves
        /// ed25519 and P-256 only, so the value is parsed and ignored.
        flags: u32,
    },
    /// Anything else: answer with failure.
    Unsupported(u8),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Frame shorter than the opcode byte.
    Empty,
    /// String or integer field runs past the frame end.
    Truncated,
    /// Strict parsing: bytes left over after the last expected field.
    Trailing,
}

/// One key in an identities answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Wire-encoded public key blob (string alg + params).
    pub blob: Vec<u8>,
    pub comment: String,
}

/// Append a `u32` big-endian.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append an ssh wire string (u32 length + bytes).
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Wrap a message body in the u32 length frame.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    put_u32(&mut out, body.len() as u32);
    out.extend_from_slice(body);
    out
}

/// Parse one unframed message body (opcode + fields).
pub fn parse_request(body: &[u8]) -> Result<AgentRequest, ProtoError> {
    let (&opcode, rest) = body.split_first().ok_or(ProtoError::Empty)?;
    match opcode {
        AGENTC_REQUEST_IDENTITIES => {
            if !rest.is_empty() {
                return Err(ProtoError::Trailing);
            }
            Ok(AgentRequest::RequestIdentities)
        }
        AGENTC_SIGN_REQUEST => {
            let (key_blob, rest) = take_string(rest)?;
            let (data, rest) = take_string(rest)?;
            let (flags_raw, rest) = rest.split_first_chunk::<4>().ok_or(ProtoError::Truncated)?;
            if !rest.is_empty() {
                return Err(ProtoError::Trailing);
            }
            Ok(AgentRequest::SignRequest {
                key_blob,
                data,
                flags: u32::from_be_bytes(*flags_raw),
            })
        }
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

/// Parse a framed message (u32 length + body).
pub fn parse_frame(frame: &[u8]) -> Result<AgentRequest, ProtoError> {
    let (len_raw, body) = frame.split_first_chunk::<4>().ok_or(ProtoError::Empty)?;
    let len = u32::from_be_bytes(*len_raw) as usize;
    if body.len() != len {
        return Err(ProtoError::Truncated);
    }
    parse_request(body)
}

/// True when a length prefix is acceptable before reading the body.
pub fn frame_len_ok(len: u32) -> bool {
    len >= 1 && len <= MAX_FRAME_LEN
}

/// `12` with a zero key count — an empty key list and a failure are the
/// same wire bytes.
pub fn encode_identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(AGENT_IDENTITIES_ANSWER);
    put_u32(&mut out, identities.len() as u32);
    for id in identities {
        put_string(&mut out, &id.blob);
        put_string(&mut out, id.comment.as_bytes());
    }
    out
}

/// `14` + string signature. `signature_wire` is the full wire-encoded
/// signature (string alg + string sig blob) produced by the signer.
pub fn encode_sign_response(signature_wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(AGENT_SIGN_RESPONSE);
    put_string(&mut out, signature_wire);
    out
}

/// Bare `12` opcode.
pub fn encode_failure() -> Vec<u8> {
    vec![AGENT_FAILURE]
}

/// Read one u32-length-prefixed string, reject truncation.
fn take_string(buf: &[u8]) -> Result<(Vec<u8>, &[u8]), ProtoError> {
    let (len_raw, rest) = buf.split_first_chunk::<4>().ok_or(ProtoError::Truncated)?;
    let len = u32::from_be_bytes(*len_raw) as usize;
    if len > rest.len() {
        return Err(ProtoError::Truncated);
    }
    Ok((rest[..len].to_vec(), &rest[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed_request_identities() -> Vec<u8> {
        frame(&[AGENTC_REQUEST_IDENTITIES])
    }

    fn framed_sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut body = vec![AGENTC_SIGN_REQUEST];
        put_string(&mut body, blob);
        put_string(&mut body, data);
        put_u32(&mut body, flags);
        frame(&body)
    }

    // --- parse: identities ------------------------------------------------

    #[test]
    fn parses_a_request_identities_frame() {
        let req = parse_frame(&framed_request_identities()).unwrap();
        assert_eq!(req, AgentRequest::RequestIdentities);
    }

    #[test]
    fn identities_body_with_trailing_byte_is_rejected() {
        let body = vec![AGENTC_REQUEST_IDENTITIES, 0x00];
        assert_eq!(parse_request(&body), Err(ProtoError::Trailing));
    }

    // --- parse: sign request ----------------------------------------------

    #[test]
    fn parses_a_sign_request_round_trip() {
        let blob = vec![0xAA; 51];
        let data = vec![0xBB; 32];
        let req = parse_frame(&framed_sign_request(&blob, &data, 2)).unwrap();
        assert_eq!(
            req,
            AgentRequest::SignRequest {
                key_blob: blob,
                data,
                flags: 2,
            }
        );
    }

    #[test]
    fn sign_request_with_zero_flags_and_empty_data_parses() {
        let req = parse_frame(&framed_sign_request(&[0x01], &[], 0)).unwrap();
        assert_eq!(
            req,
            AgentRequest::SignRequest {
                key_blob: vec![0x01],
                data: Vec::new(),
                flags: 0,
            }
        );
    }

    #[test]
    fn truncated_sign_request_is_rejected() {
        // Drop the trailing flags field.
        let mut body = vec![AGENTC_SIGN_REQUEST];
        put_string(&mut body, &[0x01]);
        put_string(&mut body, &[0x02; 4]);
        let mut framed = frame(&body);
        framed.truncate(framed.len() - 2);
        assert_eq!(parse_frame(&framed), Err(ProtoError::Truncated));
    }

    #[test]
    fn string_len_past_frame_end_is_truncated_not_allocated() {
        // A hostile length prefix must fail parsing, not reserve memory.
        let mut body = vec![AGENTC_SIGN_REQUEST];
        put_u32(&mut body, u32::MAX - 1); // absurd string length
        body.extend_from_slice(&[0x00; 8]);
        let framed = frame(&body);
        assert_eq!(parse_frame(&framed), Err(ProtoError::Truncated));
    }

    #[test]
    fn sign_request_with_trailing_garbage_is_rejected() {
        let mut body = vec![AGENTC_SIGN_REQUEST];
        put_string(&mut body, &[0x01]);
        put_string(&mut body, &[0x02]);
        put_u32(&mut body, 0);
        body.push(0xFF);
        assert_eq!(parse_request(&body), Err(ProtoError::Trailing));
    }

    // --- parse: edges ------------------------------------------------------

    #[test]
    fn empty_frame_is_rejected() {
        assert_eq!(parse_frame(&[]), Err(ProtoError::Empty));
        assert_eq!(parse_request(&[]), Err(ProtoError::Empty));
    }

    #[test]
    fn frame_length_must_match_body() {
        let mut framed = framed_request_identities();
        framed[0] = 9; // claims a 9-byte body, delivers 1
        assert_eq!(parse_frame(&framed), Err(ProtoError::Truncated));
    }

    #[test]
    fn unknown_opcode_is_unsupported_not_an_error() {
        assert_eq!(
            parse_frame(&frame(&[27])),
            Ok(AgentRequest::Unsupported(27))
        );
        assert_eq!(parse_frame(&frame(&[0])), Ok(AgentRequest::Unsupported(0)));
    }

    #[test]
    fn frame_len_gate_rejects_empty_and_oversized() {
        assert!(!frame_len_ok(0));
        assert!(frame_len_ok(1));
        assert!(frame_len_ok(MAX_FRAME_LEN));
        assert!(!frame_len_ok(MAX_FRAME_LEN + 1));
    }

    // --- encode ------------------------------------------------------------

    #[test]
    fn identities_answer_layout_is_exact_for_one_key() {
        let out = encode_identities_answer(&[Identity {
            blob: vec![0xde, 0xad],
            comment: "github".into(),
        }]);
        let mut want = vec![AGENT_IDENTITIES_ANSWER];
        put_u32(&mut want, 1);
        put_string(&mut want, &[0xde, 0xad]);
        put_string(&mut want, b"github");
        assert_eq!(out, want);
    }

    #[test]
    fn empty_identities_answer_is_opcode_twelve_with_zero_count() {
        // Opcode 12 doubles as the failure answer; with a zero count it is
        // the empty-key-list form. Both leave OpenSSH with no identities.
        assert_eq!(encode_identities_answer(&[]), vec![12, 0, 0, 0, 0]);
    }

    #[test]
    fn sign_response_layout_is_exact() {
        let sig = [0x11, 0x22, 0x33];
        let out = encode_sign_response(&sig);
        let mut want = vec![AGENT_SIGN_RESPONSE];
        put_string(&mut want, &sig);
        assert_eq!(out, want);
    }

    #[test]
    fn failure_is_five_zero_padded_bytes() {
        assert_eq!(encode_failure(), vec![12]);
        assert_eq!(frame(&encode_failure()), vec![0, 0, 0, 1, 12]);
    }

    #[test]
    fn put_helpers_are_big_endian() {
        let mut out = Vec::new();
        put_u32(&mut out, 0x0102_0304);
        put_string(&mut out, b"ab");
        assert_eq!(out, vec![0x01, 0x02, 0x03, 0x04, 0, 0, 0, 2, b'a', b'b']);
    }
}
