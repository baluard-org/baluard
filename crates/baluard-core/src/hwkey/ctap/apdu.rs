//! CTAP2 over ISO 7814-4 APDUs (CTAP2 spec §11.2, "Messaging").
//!
//! NFC transport framing: `NFCCTAP_MSG` carries the CTAP command byte plus
//! CBOR payload as APDU data; responses arrive via `61xx`/GET RESPONSE chains
//! or after `91xx` keepalives polled with `NFCCTAP_GETRESPONSE`. The actual
//! byte exchange is delegated to a platform transceive callback (Android
//! IsoDep, CoreNFC ISO7816Tag, or the hermetic test double).

use std::time::Duration;

/// The FIDO application AID (FIDO alliance, CTAP2 §11.2.2); its select reply
/// names the CTAP version (`FIDO_2_0`, or `U2F_V2` on keys that also speak U2F).
pub const FIDO_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// The exchange failed at the ISO layer (transport returned Err).
    Transport,
    /// An ISO status word the CTAP layer cannot progress past.
    StatusWord([u8; 2]),
    /// The token replied with malformed framing (empty body, bad lengths).
    Malformed,
    /// The token stayed in its keepalive state beyond the bounded wait.
    Timeout,
}

/// Platform byte-exchange: send one APDU, receive the raw response body plus
/// its two status-word bytes.
pub trait Transceive {
    fn transceive(&self, request: &[u8]) -> Result<(Vec<u8>, [u8; 2]), ApduError>;
}

/// APDU shape: extended-length fields when the device accepts them, command
/// chaining (CLA 0x10) otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduForm {
    Extended,
    Chained,
}

impl ApduForm {
    /// Picks the APDU shape from the reader's capability (Android
    /// `IsoDep.isExtendedLengthApduSupported()`): extended when the reader
    /// sends them, command chaining otherwise.
    pub fn for_extended_support(extended_supported: bool) -> Self {
        if extended_supported {
            Self::Extended
        } else {
            Self::Chained
        }
    }
}

/// Selects the FIDO applet; the reply body is `FIDO_2_0` (CTAP2 only) or
/// `U2F_V2` (U2F plus possibly CTAP2). Callers must prove CTAP2 with getInfo
/// before relying on it.
pub fn select_fido(trans: &dyn Transceive) -> Result<Vec<u8>, ApduError> {
    let mut req = vec![0x00, 0xa4, 0x04, 0x00, FIDO_AID.len() as u8];
    req.extend_from_slice(&FIDO_AID);
    req.push(0x00);
    let (body, sw) = trans.transceive(&req)?;
    expect_sw(sw, &[[0x90, 0x00]])?;
    Ok(body)
}
/// Sends one CTAP2 command (command byte + CBOR payload) and returns the
/// final response payload, whose first byte is the CTAP2 status code.
pub fn nfcctap_msg(
    trans: &dyn Transceive,
    form: ApduForm,
    ctap_command: u8,
    payload: &[u8],
) -> Result<Vec<u8>, ApduError> {
    let mut data = Vec::with_capacity(payload.len() + 1);
    data.push(ctap_command);
    data.extend_from_slice(payload);
    let requests = build_nfcctap_msg(form, &data);
    let mut response = Vec::new();
    for (i, req) in requests.iter().enumerate() {
        let last = i + 1 == requests.len();
        let (body, sw) = trans.transceive(req)?;
        if last {
            response = collect_response(trans, body, sw)?;
        } else if sw != [0x90, 0x00] {
            return Err(ApduError::StatusWord(sw));
        }
    }
    Ok(response)
}

/// Builds the NFCCTAP_MSG APDU(s): `80 10 00 00 [Lc data Le]`.
pub fn build_nfcctap_msg(form: ApduForm, data: &[u8]) -> Vec<Vec<u8>> {
    match form {
        ApduForm::Extended => {
            let mut req = vec![
                0x80,
                0x10,
                0x00,
                0x00,
                0x00,
                (data.len() >> 8) as u8,
                data.len() as u8,
            ];
            req.extend_from_slice(data);
            req.extend_from_slice(&[0x00, 0x00]);
            vec![req]
        }
        ApduForm::Chained => {
            let mut out = Vec::new();
            if data.is_empty() {
                return vec![vec![0x80, 0x10, 0x00, 0x00, 0x00, 0x00]];
            }
            for (i, chunk) in data.chunks(255).enumerate() {
                let chained = i + 1 < data.chunks(255).count();
                let cla = if chained { 0x90 } else { 0x80 };
                let mut req = vec![cla, 0x10, 0x00, 0x00, chunk.len() as u8];
                req.extend_from_slice(chunk);
                if !chained {
                    req.push(0x00); // Le
                }
                out.push(req);
            }
            out
        }
    }
}

/// Delay between NFCCTAP_GETRESPONSE polls while the key reports it is busy.
const KEEPALIVE_POLL_DELAY: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_millis(50)
};
/// About 30 s of keepalive polling before the exchange is abandoned.
const MAX_KEEPALIVE_POLLS: usize = 600;
/// 61xx chunks carry up to 256 bytes; 128 chunks cover any CTAP2 response.
const MAX_GET_RESPONSE_CHUNKS: usize = 128;

/// Progresses `61xx` GET RESPONSE chains and `91xx` keepalive polling until
/// a terminal status word.
///
/// A `91xx` reply carries a one-byte keepalive status (processing, user
/// presence needed), never CTAP data: it is discarded and the key is polled
/// with NFCCTAP_GETRESPONSE until the real response arrives with `9000` or
/// `61xx`.
fn collect_response(
    trans: &dyn Transceive,
    mut body: Vec<u8>,
    mut sw: [u8; 2],
) -> Result<Vec<u8>, ApduError> {
    let mut keepalives = 0usize;
    let mut chunks = 0usize;
    loop {
        match sw {
            [0x90, 0x00] => return Ok(body),
            [0x61, remaining] => {
                chunks += 1;
                if chunks > MAX_GET_RESPONSE_CHUNKS {
                    return Err(ApduError::Malformed);
                }
                // SW2 = 0x00 means 256 or more bytes remain, and Le = 0x00
                // asks for 256.
                let (more, next) = trans.transceive(&[0x00, 0xc0, 0x00, 0x00, remaining])?;
                body.extend_from_slice(&more);
                sw = next;
            }
            [0x91, _] => {
                keepalives += 1;
                if keepalives > MAX_KEEPALIVE_POLLS {
                    return Err(ApduError::Timeout);
                }
                std::thread::sleep(KEEPALIVE_POLL_DELAY);
                let (reply, next) = trans.transceive(&[0x80, 0x11, 0x00, 0x00, 0x00])?;
                body = reply;
                sw = next;
            }
            other => return Err(ApduError::StatusWord(other)),
        }
    }
}

fn expect_sw(sw: [u8; 2], ok: &[[u8; 2]]) -> Result<(), ApduError> {
    if ok.contains(&sw) {
        Ok(())
    } else {
        Err(ApduError::StatusWord(sw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Plays a scripted (request-prefix-matched) sequence of responses.
    struct Script {
        steps: RefCell<Vec<(Vec<u8>, Vec<u8>, [u8; 2])>>,
    }
    impl Script {
        fn new(steps: Vec<(Vec<u8>, Vec<u8>, [u8; 2])>) -> Self {
            Self {
                steps: RefCell::new(steps),
            }
        }
    }
    impl Transceive for Script {
        fn transceive(&self, request: &[u8]) -> Result<(Vec<u8>, [u8; 2]), ApduError> {
            let mut steps = self.steps.borrow_mut();
            let (prefix, body, sw) = steps.remove(0);
            assert!(
                request.starts_with(&prefix),
                "unexpected request {request:02x?}"
            );
            Ok((body, sw))
        }
    }

    #[test]
    fn extended_request_layout() {
        let data = vec![0x04, 0xaa, 0xbb];
        let req = build_nfcctap_msg(ApduForm::Extended, &data).remove(0);
        assert_eq!(req[..5], [0x80, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(req[5..7], [0x00, 0x03]);
        assert_eq!(&req[7..10], &data[..]);
        assert_eq!(&req[10..], &[0x00, 0x00]);
    }

    #[test]
    fn chained_requests_split_over_255_and_mark_cla() {
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let reqs = build_nfcctap_msg(ApduForm::Chained, &data);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0][0], 0x90); // chained: CLA|0x10
        assert_eq!(reqs[0][4], 255);
        assert_eq!(reqs[1][0], 0x80); // last: plain CLA + Le
        assert_eq!(reqs[1][4], 45);
        assert_eq!(*reqs[1].last().unwrap(), 0x00);
    }

    #[test]
    fn select_fido_builds_standard_select() {
        let script = Script::new(vec![(
            vec![0x00, 0xa4, 0x04, 0x00, 0x08],
            b"FIDO_2_0".to_vec(),
            [0x90, 0x00],
        )]);
        let version = select_fido(&script).unwrap();
        assert_eq!(version, b"FIDO_2_0");
    }

    #[test]
    fn response_walks_the_61xx_get_response_chain() {
        let msg = build_nfcctap_msg(ApduForm::Chained, &[0x04]).remove(0);
        let script = Script::new(vec![
            (msg, b"part1".to_vec(), [0x61, 0x10]),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x10],
                b"part2".to_vec(),
                [0x61, 0x02],
            ),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x02],
                b"!".to_vec(),
                [0x90, 0x00],
            ),
        ]);
        let payload = nfcctap_msg(&script, ApduForm::Chained, 0x04, &[]).unwrap();
        let mut expected = b"part1".to_vec();
        expected.extend_from_slice(b"part2");
        expected.push(b'!');
        assert_eq!(payload, expected);
    }

    #[test]
    fn keepalive_91xx_status_is_discarded_and_the_final_payload_returned() {
        let msg = build_nfcctap_msg(ApduForm::Chained, &[0x02]).remove(0);
        // 91xx data is a keepalive status byte (1 = processing, 2 = touch
        // needed), never CTAP data. Only the 9000 reply is the response.
        let script = Script::new(vec![
            (msg, vec![0x01], [0x91, 0x00]),
            (vec![0x80, 0x11, 0x00, 0x00, 0x00], vec![0x02], [0x91, 0x00]),
            (vec![0x80, 0x11, 0x00, 0x00, 0x00], Vec::new(), [0x91, 0x00]),
            (
                vec![0x80, 0x11, 0x00, 0x00, 0x00],
                vec![0x00, 0xaa],
                [0x90, 0x00],
            ),
        ]);
        let payload = nfcctap_msg(&script, ApduForm::Chained, 0x02, &[]).unwrap();
        assert_eq!(payload, vec![0x00, 0xaa]);
    }

    #[test]
    fn keepalive_followed_by_a_61xx_chain_collects_every_chunk() {
        let msg = build_nfcctap_msg(ApduForm::Chained, &[0x02]).remove(0);
        let script = Script::new(vec![
            (msg, Vec::new(), [0x91, 0x00]),
            (
                vec![0x80, 0x11, 0x00, 0x00, 0x00],
                b"ab".to_vec(),
                [0x61, 0x02],
            ),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x02],
                b"cd".to_vec(),
                [0x90, 0x00],
            ),
        ]);
        let payload = nfcctap_msg(&script, ApduForm::Chained, 0x02, &[]).unwrap();
        assert_eq!(payload, b"abcd");
    }

    #[test]
    fn endless_keepalives_are_abandoned() {
        struct Busy;
        impl Transceive for Busy {
            fn transceive(&self, _: &[u8]) -> Result<(Vec<u8>, [u8; 2]), ApduError> {
                Ok((vec![0x01], [0x91, 0x00]))
            }
        }
        assert_eq!(
            collect_response(&Busy, Vec::new(), [0x91, 0x00]),
            Err(ApduError::Timeout)
        );
    }

    #[test]
    fn sw2_zero_asks_for_256_bytes_not_one() {
        let msg = build_nfcctap_msg(ApduForm::Chained, &[0x04]).remove(0);
        let first = vec![1u8; 100];
        let script = Script::new(vec![
            (msg, first.clone(), [0x61, 0x00]),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x00],
                vec![2u8; 256],
                [0x61, 0x05],
            ),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x05],
                vec![3u8; 5],
                [0x90, 0x00],
            ),
        ]);
        let payload = nfcctap_msg(&script, ApduForm::Chained, 0x04, &[]).unwrap();
        assert_eq!(payload.len(), 100 + 256 + 5);
        assert_eq!(&payload[..100], &first[..]);
    }

    #[test]
    fn form_follows_the_reader_capability() {
        assert_eq!(ApduForm::for_extended_support(true), ApduForm::Extended);
        assert_eq!(ApduForm::for_extended_support(false), ApduForm::Chained);
    }

    #[test]
    fn non_final_chained_apdus_must_answer_9000() {
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let first = build_nfcctap_msg(ApduForm::Chained, &data).remove(0);
        let script = Script::new(vec![(first[..5].to_vec(), Vec::new(), [0x6a, 0x80])]);
        assert_eq!(
            nfcctap_msg(&script, ApduForm::Chained, data[0], &data[1..]),
            Err(ApduError::StatusWord([0x6a, 0x80]))
        );
    }

    #[test]
    fn unexpected_status_word_surfaces() {
        let msg = build_nfcctap_msg(ApduForm::Chained, &[0x04]).remove(0);
        let script = Script::new(vec![(msg, Vec::new(), [0x6a, 0x82])]);
        assert_eq!(
            nfcctap_msg(&script, ApduForm::Chained, 0x04, &[]),
            Err(ApduError::StatusWord([0x6a, 0x82]))
        );
    }
}
