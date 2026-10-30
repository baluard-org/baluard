//! CTAPHID framing over a 64-byte HID report link (CTAPHID spec §11.2).
//!
//! Shared by the desktop real-key gate and Android USB-OTG. The link trait
//! works on 65-byte reports (leading report-id byte 0x00, the hidapi shape);
//! a raw USB adapter adds/strips the prefix itself.

const TYPE_INIT: u8 = 0x80;

/// Wire constants shared with the software authenticator's link adapter.
pub mod wire {
    pub const BROADCAST_CID: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
    pub const CMD_INIT: u8 = 0x80 | 0x06;
    pub const CMD_CBOR: u8 = 0x80 | 0x10;
    pub const CMD_KEEPALIVE: u8 = 0x80 | 0x3b;
    pub const CMD_ERROR: u8 = 0x80 | 0x3f;
    pub const INIT_PAYLOAD: usize = 57;
    pub const CONT_PAYLOAD: usize = 59;
}

const CTAPHID_INIT: u8 = wire::CMD_INIT;
const CTAPHID_CBOR: u8 = wire::CMD_CBOR;
const CTAPHID_CANCEL: u8 = TYPE_INIT | 0x11;
const CTAPHID_KEEPALIVE: u8 = wire::CMD_KEEPALIVE;
const CTAPHID_ERROR: u8 = wire::CMD_ERROR;
const BROADCAST_CID: [u8; 4] = wire::BROADCAST_CID;

const INIT_PAYLOAD: usize = wire::INIT_PAYLOAD;
const CONT_PAYLOAD: usize = wire::CONT_PAYLOAD;

/// Continuation sequence numbers run 0..=127 (bit 7 marks an init frame),
/// which caps a CTAPHID message at 57 + 128 * 59 = 7609 bytes.
const MAX_CONT_FRAMES: usize = 128;
pub const MAX_MESSAGE: usize = INIT_PAYLOAD + MAX_CONT_FRAMES * CONT_PAYLOAD;

/// Frames skipped while waiting for our INIT reply: replies to earlier
/// handshakes and traffic left in the pipe by an aborted operation.
const MAX_STALE_INIT_FRAMES: usize = 16;
/// A touch wait cannot spin forever: about a minute of authenticator
/// keepalives, then the operation is cancelled on the token.
const MAX_KEEPALIVE_FRAMES: usize = 600;
/// Other hidraw clients' traffic is ignored, but cannot starve us forever.
const MAX_FOREIGN_FRAMES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtapHidError {
    /// Transport-level write/read failure.
    Link,
    /// CTAPHID protocol error code (ERROR frame payload).
    Hid(u8),
    /// Framing was well-formed but semantically wrong (nonce, channel, seq).
    Malformed,
    /// The authenticator stayed in keepalive past the operation deadline.
    Timeout,
}

/// Byte-level HID link. 65-byte reports including the leading report id.
pub trait HidLink {
    fn write(&self, report: &[u8; 65]) -> Result<(), CtapHidError>;
    fn read(&self) -> Result<[u8; 65], CtapHidError>;
}

/// Result of the CTAPHID handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub cid: [u8; 4],
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub capabilities: u8,
}

/// Performs the CTAPHID handshake on the broadcast channel and returns the
/// allocated channel id.
pub fn init(link: &dyn HidLink) -> Result<DeviceInfo, CtapHidError> {
    let mut nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    init_with_nonce(link, &nonce)
}

pub fn init_with_nonce(link: &dyn HidLink, nonce: &[u8; 8]) -> Result<DeviceInfo, CtapHidError> {
    let mut report = [0u8; 65];
    report[1..5].copy_from_slice(&BROADCAST_CID);
    report[5] = CTAPHID_INIT;
    report[6..8].copy_from_slice(&8u16.to_be_bytes());
    report[8..16].copy_from_slice(nonce);
    link.write(&report)?;
    // An aborted earlier operation can leave frames in the pipe, and another
    // client's INIT reply on the broadcast channel carries a different
    // nonce. Only a reply echoing OUR nonce is trusted; the rest is drained.
    let mut resp = link.read()?;
    for _ in 0..MAX_STALE_INIT_FRAMES {
        if resp[1..5] == BROADCAST_CID && resp[5] == CTAPHID_ERROR {
            let bcnt = ((resp[6] as usize) << 8) | resp[7] as usize;
            if bcnt < 1 {
                return Err(CtapHidError::Malformed);
            }
            return Err(CtapHidError::Hid(resp[8]));
        }
        if resp[1..5] == BROADCAST_CID && resp[5] == CTAPHID_INIT && resp[8..16] == *nonce {
            break;
        }
        resp = link.read()?;
    }
    if resp[1..5] != BROADCAST_CID || resp[5] != CTAPHID_INIT || resp[8..16] != *nonce {
        return Err(CtapHidError::Malformed);
    }
    let bcnt = ((resp[6] as usize) << 8) | resp[7] as usize;
    if bcnt < 17 {
        return Err(CtapHidError::Malformed);
    }
    let cid = [resp[16], resp[17], resp[18], resp[19]];
    if cid == [0, 0, 0, 0] || cid == BROADCAST_CID {
        return Err(CtapHidError::Malformed);
    }
    Ok(DeviceInfo {
        cid,
        version_major: resp[21],
        version_minor: resp[22],
        version_build: resp[23],
        capabilities: resp[24],
    })
}

/// Sends one CTAPHID_CBOR transaction and returns (CTAP2 status, CBOR body).
/// Keepalive frames are skipped; `on_keepalive` observes them (status 1 =
/// processing, 2 = user presence needed) for touch-UI feedback.
pub fn cbor(
    link: &dyn HidLink,
    cid: &[u8; 4],
    payload: &[u8],
    on_keepalive: &mut dyn FnMut(u8),
) -> Result<(u8, Vec<u8>), CtapHidError> {
    for report in frame_cbor(cid, payload)? {
        link.write(&report)?;
    }
    let (cmd, data) = read_response(link, cid, CTAPHID_CBOR, on_keepalive)?;
    debug_assert_eq!(cmd, CTAPHID_CBOR);
    let (&status, body) = data.split_first().ok_or(CtapHidError::Malformed)?;
    Ok((status, body.to_vec()))
}

/// Best-effort cancel of an in-flight touch wait. The device may answer with
/// an ERROR frame (no-op cancel) or fail the pending CBOR transaction; both
/// end the wait.
pub fn send_cancel(link: &dyn HidLink, cid: &[u8; 4]) -> Result<(), CtapHidError> {
    let mut report = [0u8; 65];
    report[1..5].copy_from_slice(cid);
    report[5] = CTAPHID_CANCEL;
    link.write(&report)
}

/// Splits a CBOR payload into CTAPHID init + continuation reports. Payloads
/// over [`MAX_MESSAGE`] cannot be numbered in 7 bits and are refused.
pub fn frame_cbor(cid: &[u8; 4], payload: &[u8]) -> Result<Vec<[u8; 65]>, CtapHidError> {
    if payload.len() > MAX_MESSAGE {
        return Err(CtapHidError::Malformed);
    }
    let mut reports = Vec::new();
    let mut seq: u8 = 0;
    let mut offset = 0usize;
    while offset < payload.len() || reports.is_empty() {
        let mut report = [0u8; 65];
        report[1..5].copy_from_slice(cid);
        if reports.is_empty() {
            report[5] = CTAPHID_CBOR;
            let len = payload.len() as u16;
            report[6] = (len >> 8) as u8;
            report[7] = len as u8;
            let take = INIT_PAYLOAD.min(payload.len());
            report[8..8 + take].copy_from_slice(&payload[..take]);
            offset = take;
        } else {
            report[5] = seq;
            let take = CONT_PAYLOAD.min(payload.len() - offset);
            report[6..6 + take].copy_from_slice(&payload[offset..offset + take]);
            offset += take;
            seq += 1;
        }
        reports.push(report);
    }
    Ok(reports)
}

/// Reads CTAPHID frames until the wanted command completes, assembling the
/// response payload. Keepalives and errors interleave per spec.
fn read_response(
    link: &dyn HidLink,
    cid: &[u8; 4],
    want: u8,
    on_keepalive: &mut dyn FnMut(u8),
) -> Result<(u8, Vec<u8>), CtapHidError> {
    let mut payload: Vec<u8> = Vec::new();
    let total;
    let mut seq = 0u8;
    let mut keepalives = 0usize;
    let mut foreign = 0usize;
    loop {
        let report = link.read()?;
        if report[1..5] != *cid {
            foreign += 1;
            if foreign > MAX_FOREIGN_FRAMES {
                return Err(CtapHidError::Malformed);
            }
            continue;
        }
        let cmd = report[5];
        match cmd {
            CTAPHID_KEEPALIVE => {
                if ((report[6] as usize) << 8 | report[7] as usize) < 1 {
                    return Err(CtapHidError::Malformed);
                }
                keepalives += 1;
                if keepalives > MAX_KEEPALIVE_FRAMES {
                    send_cancel(link, cid)?;
                    return Err(CtapHidError::Timeout);
                }
                on_keepalive(report[8]);
                continue;
            }
            CTAPHID_ERROR => {
                if ((report[6] as usize) << 8 | report[7] as usize) < 1 {
                    return Err(CtapHidError::Malformed);
                }
                return Err(CtapHidError::Hid(report[8]));
            }
            c if c == want => {
                total = ((report[6] as usize) << 8) | report[7] as usize;
                if total > MAX_MESSAGE {
                    return Err(CtapHidError::Malformed);
                }
                let take = INIT_PAYLOAD.min(total);
                payload.extend_from_slice(&report[8..8 + take]);
            }
            _ => return Err(CtapHidError::Malformed),
        }
        // Continuation frames: bare seq in byte 5 (no type bit).
        while payload.len() < total {
            let report = link.read()?;
            if report[1..5] != *cid || report[5] != seq || seq as usize >= MAX_CONT_FRAMES {
                return Err(CtapHidError::Malformed);
            }
            let take = CONT_PAYLOAD.min(total - payload.len());
            payload.extend_from_slice(&report[6..6 + take]);
            seq += 1;
        }
        return Ok((want, payload));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Queue-based link: writes are recorded, reads replay scripted frames.
    struct QueueLink {
        written: RefCell<Vec<[u8; 65]>>,
        reads: RefCell<Vec<Result<[u8; 65], CtapHidError>>>,
    }
    impl QueueLink {
        fn new(reads: Vec<Result<[u8; 65], CtapHidError>>) -> Self {
            Self {
                written: RefCell::new(Vec::new()),
                reads: RefCell::new(reads),
            }
        }
        fn init_ok_response(nonce: &[u8; 8]) -> [u8; 65] {
            let mut r = [0u8; 65];
            r[1..5].copy_from_slice(&BROADCAST_CID);
            r[5] = CTAPHID_INIT;
            r[6..8].copy_from_slice(&17u16.to_be_bytes());
            r[8..16].copy_from_slice(nonce);
            r[16..20].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
            r[20] = 2; // protocol version
            r[21] = 5; // major
            r[22] = 7; // minor
            r[23] = 3; // build
            r[24] = 0x05; // wink + CBS
            r
        }
    }
    impl HidLink for QueueLink {
        fn write(&self, report: &[u8; 65]) -> Result<(), CtapHidError> {
            self.written.borrow_mut().push(*report);
            Ok(())
        }
        fn read(&self) -> Result<[u8; 65], CtapHidError> {
            let mut reads = self.reads.borrow_mut();
            if reads.is_empty() {
                return Err(CtapHidError::Link);
            }
            reads.remove(0)
        }
    }

    #[test]
    fn init_handshake_returns_allocated_channel_and_versions() {
        let nonce = [7u8; 8];
        let link = QueueLink::new(vec![Ok(QueueLink::init_ok_response(&nonce))]);
        let info = init_with_nonce(&link, &nonce).unwrap();
        assert_eq!(info.cid, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(info.version_major, 5);
        assert_eq!(info.capabilities, 0x05);
        let sent = &link.written.borrow()[0];
        assert_eq!(sent[1..5], BROADCAST_CID);
        assert_eq!(sent[5], CTAPHID_INIT);
        assert_eq!(&sent[6..8], &8u16.to_be_bytes());
        assert_eq!(&sent[8..16], &nonce[..]);
    }

    #[test]
    fn init_refuses_short_replies_and_invalid_channel_ids() {
        let nonce = [7u8; 8];
        let mut short = QueueLink::init_ok_response(&nonce);
        short[6..8].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(
            init_with_nonce(&QueueLink::new(vec![Ok(short)]), &nonce),
            Err(CtapHidError::Malformed)
        );
        for cid in [[0, 0, 0, 0], BROADCAST_CID] {
            let mut reply = QueueLink::init_ok_response(&nonce);
            reply[16..20].copy_from_slice(&cid);
            assert_eq!(
                init_with_nonce(&QueueLink::new(vec![Ok(reply)]), &nonce),
                Err(CtapHidError::Malformed)
            );
        }
    }

    #[test]
    fn init_refuses_a_nonce_mismatch() {
        let nonce = [7u8; 8];
        let link = QueueLink::new(vec![Ok(QueueLink::init_ok_response(&[9u8; 8]))]);
        // The foreign reply is drained; with nothing else coming the link
        // read fails rather than adopting a channel that never echoed us.
        assert_eq!(init_with_nonce(&link, &nonce), Err(CtapHidError::Link));
    }

    #[test]
    fn init_skips_stale_frames_and_adopts_the_reply_to_our_nonce() {
        let nonce = [7u8; 8];
        let mut stale_cbor = [0u8; 65];
        stale_cbor[1..5].copy_from_slice(&[9, 9, 9, 9]);
        stale_cbor[5] = CTAPHID_CBOR;
        let mut stale_cont = [0u8; 65];
        stale_cont[1..5].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let link = QueueLink::new(vec![
            Ok(QueueLink::init_ok_response(&[9u8; 8])),
            Ok(stale_cbor),
            Ok(stale_cont),
            Ok(QueueLink::init_ok_response(&nonce)),
        ]);
        let info = init_with_nonce(&link, &nonce).unwrap();
        assert_eq!(info.cid, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn init_gives_up_after_a_bounded_amount_of_noise() {
        let nonce = [7u8; 8];
        let noise = QueueLink::init_ok_response(&[9u8; 8]);
        let mut reads: Vec<_> = (0..MAX_STALE_INIT_FRAMES + 1).map(|_| Ok(noise)).collect();
        reads.push(Ok(QueueLink::init_ok_response(&nonce)));
        let link = QueueLink::new(reads);
        assert_eq!(init_with_nonce(&link, &nonce), Err(CtapHidError::Malformed));
    }

    #[test]
    fn init_surfaces_a_broadcast_error_frame() {
        let nonce = [7u8; 8];
        let mut busy = [0u8; 65];
        busy[1..5].copy_from_slice(&BROADCAST_CID);
        busy[5] = CTAPHID_ERROR;
        busy[6..8].copy_from_slice(&1u16.to_be_bytes());
        busy[8] = 0x06;
        let link = QueueLink::new(vec![Ok(busy)]);
        assert_eq!(init_with_nonce(&link, &nonce), Err(CtapHidError::Hid(0x06)));
    }

    #[test]
    fn requests_over_the_sequence_space_are_refused() {
        let cid = [0u8; 4];
        let longest = vec![0u8; MAX_MESSAGE];
        let reports = frame_cbor(&cid, &longest).unwrap();
        assert_eq!(reports.len(), 1 + MAX_CONT_FRAMES);
        assert_eq!(reports.last().unwrap()[5], 127);
        assert_eq!(
            frame_cbor(&cid, &vec![0u8; MAX_MESSAGE + 1]),
            Err(CtapHidError::Malformed)
        );
        let link = QueueLink::new(vec![]);
        assert_eq!(
            cbor(&link, &cid, &vec![0u8; MAX_MESSAGE + 1], &mut |_| {}),
            Err(CtapHidError::Malformed)
        );
        assert!(link.written.borrow().is_empty());
    }

    #[test]
    fn responses_announcing_more_than_the_protocol_allows_are_refused() {
        let cid = [1u8, 2, 3, 4];
        let mut first = [0u8; 65];
        first[1..5].copy_from_slice(&cid);
        first[5] = CTAPHID_CBOR;
        first[6..8].copy_from_slice(&((MAX_MESSAGE + 1) as u16).to_be_bytes());
        let link = QueueLink::new(vec![Ok(first)]);
        assert_eq!(
            cbor(&link, &cid, &[0x04], &mut |_| {}),
            Err(CtapHidError::Malformed)
        );
    }

    #[test]
    fn single_frame_cbor_roundtrip_shape() {
        let cid = [0xaa, 0xbb, 0xcc, 0xdd];
        let payload = [0x04, 0x01];
        let reports = frame_cbor(&cid, &payload).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0][1..5], cid);
        assert_eq!(reports[0][5], CTAPHID_CBOR);
        assert_eq!(&reports[0][6..8], &2u16.to_be_bytes());
        assert_eq!(&reports[0][8..10], &payload[..]);
        assert!(reports[0][10..].iter().all(|b| *b == 0));
    }

    #[test]
    fn long_payloads_chain_with_sequence_numbers() {
        let cid = [0u8; 4];
        let payload: Vec<u8> = (0..120).map(|i| i as u8).collect();
        let reports = frame_cbor(&cid, &payload).unwrap();
        // 57 in the init frame, then 59 + 4 across continuations.
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[1][5], 0);
        assert_eq!(reports[1][6..6 + 59].to_vec(), payload[57..116]);
        assert_eq!(reports[2][5], 1);
        assert_eq!(reports[2][6..6 + 4].to_vec(), payload[116..]);
    }

    #[test]
    fn cbor_transaction_returns_status_and_body() {
        let cid = [1u8, 2, 3, 4];
        let payload = [0x04];
        let mut response = [0u8; 65];
        response[1..5].copy_from_slice(&cid);
        response[5] = CTAPHID_CBOR;
        // status 0x00 + 3-byte body (getInfo CBOR)
        let len: u16 = 4;
        response[6] = (len >> 8) as u8;
        response[7] = len as u8;
        response[8] = 0x00;
        response[9..12].copy_from_slice(&[0xa1, 0x01, 0x02]);
        let link = QueueLink::new(vec![Ok(response)]);
        let mut keepalives = Vec::new();
        let (status, body) = cbor(&link, &cid, &payload, &mut |s| keepalives.push(s)).unwrap();
        assert_eq!(status, 0x00);
        assert_eq!(body, vec![0xa1, 0x01, 0x02]);
        assert!(keepalives.is_empty());
    }

    #[test]
    fn foreign_channel_frames_are_skipped() {
        let cid = [1u8, 2, 3, 4];
        let mut foreign = [0u8; 65];
        foreign[1..5].copy_from_slice(&[9, 9, 9, 9]);
        foreign[5] = CTAPHID_CBOR;
        foreign[6..8].copy_from_slice(&1u16.to_be_bytes());
        foreign[8] = 0x2f;
        let mut done = [0u8; 65];
        done[1..5].copy_from_slice(&cid);
        done[5] = CTAPHID_CBOR;
        done[6..8].copy_from_slice(&1u16.to_be_bytes());
        done[8] = 0x00;
        let link = QueueLink::new(vec![Ok(foreign), Ok(done)]);
        let (status, _) = cbor(&link, &cid, &[0x04], &mut |_| {}).unwrap();
        assert_eq!(status, 0);
    }

    #[test]
    fn keepalive_wait_is_bounded_and_cancels_the_token() {
        let cid = [1u8, 2, 3, 4];
        let mut up = [0u8; 65];
        up[1..5].copy_from_slice(&cid);
        up[5] = CTAPHID_KEEPALIVE;
        up[6..8].copy_from_slice(&1u16.to_be_bytes());
        up[8] = 2;
        let link = QueueLink::new(vec![Ok(up); 601]);
        assert_eq!(
            cbor(&link, &cid, &[0x02], &mut |_| {}),
            Err(CtapHidError::Timeout)
        );
        let writes = link.written.borrow();
        assert_eq!(writes.last().unwrap()[5], CTAPHID_CANCEL);
    }

    #[test]
    fn keepalive_frames_are_observed_and_skipped() {
        let cid = [1u8, 2, 3, 4];
        let mut up = [0u8; 65];
        up[1..5].copy_from_slice(&cid);
        up[5] = CTAPHID_KEEPALIVE;
        up[6..8].copy_from_slice(&1u16.to_be_bytes());
        up[8] = 2; // user presence needed, first payload byte
        let mut done = [0u8; 65];
        done[1..5].copy_from_slice(&cid);
        done[5] = CTAPHID_CBOR;
        done[6..8].copy_from_slice(&1u16.to_be_bytes());
        done[8] = 0x00;
        let link = QueueLink::new(vec![Ok(up), Ok(up), Ok(done)]);
        let mut keepalives = Vec::new();
        let (status, _) = cbor(&link, &cid, &[0x02], &mut |s| keepalives.push(s)).unwrap();
        assert_eq!(status, 0x00);
        assert_eq!(keepalives, vec![2, 2]);
    }

    #[test]
    fn error_frames_surface_the_protocol_code() {
        let cid = [1u8, 2, 3, 4];
        let mut err = [0u8; 65];
        err[1..5].copy_from_slice(&cid);
        err[5] = CTAPHID_ERROR;
        err[6..8].copy_from_slice(&1u16.to_be_bytes());
        err[8] = 0x06; // channel busy, first payload byte
        let link = QueueLink::new(vec![Ok(err)]);
        let mut ignored = Vec::new();
        assert_eq!(
            cbor(&link, &cid, &[0x04], &mut |_| ignored.push(0u8)),
            Err(CtapHidError::Hid(0x06))
        );
    }

    #[test]
    fn zero_length_status_frames_are_malformed() {
        // A KEEPALIVE/ERROR frame with BCNT = 0 has no status byte to
        // read; indexing the padding would invent a code.
        let cid = [1u8, 2, 3, 4];
        let mut err = [0u8; 65];
        err[1..5].copy_from_slice(&cid);
        err[5] = CTAPHID_ERROR;
        // [6..8] stay zero: BCNT = 0.
        let link = QueueLink::new(vec![Ok(err)]);
        assert_eq!(
            cbor(&link, &cid, &[0x04], &mut |_| {}),
            Err(CtapHidError::Malformed)
        );
    }

    #[test]
    fn foreign_channel_noise_does_not_become_a_protocol_error() {
        let cid = [1u8, 2, 3, 4];
        let mut other = [0u8; 65];
        other[1..5].copy_from_slice(&[9, 9, 9, 9]);
        other[5] = CTAPHID_CBOR;
        let link = QueueLink::new(vec![Ok(other)]);
        let mut ignored = Vec::new();
        assert_eq!(
            cbor(&link, &cid, &[0x04], &mut |_| ignored.push(0u8)),
            Err(CtapHidError::Link)
        );
    }

    #[test]
    fn multi_frame_responses_reassemble_in_sequence() {
        let cid = [0u8, 0, 0, 0];
        let body: Vec<u8> = (0..70).map(|i| i as u8).collect(); // status + 69-byte body
        let mut first = [0u8; 65];
        first[1..5].copy_from_slice(&cid);
        first[5] = CTAPHID_CBOR;
        let len = body.len() as u16;
        first[6] = (len >> 8) as u8;
        first[7] = len as u8;
        first[8..].copy_from_slice(&body[..57]);
        let mut cont = [0u8; 65];
        cont[1..5].copy_from_slice(&cid);
        cont[5] = 0; // seq 0
        cont[6..6 + 13].copy_from_slice(&body[57..]);
        let link = QueueLink::new(vec![Ok(first), Ok(cont)]);
        let mut ignored = Vec::new();
        let (status, out) = cbor(&link, &cid, &[0x04], &mut |_| ignored.push(0u8)).unwrap();
        assert_eq!(status, body[0]);
        assert_eq!(out, body[1..]);
    }

    #[test]
    fn cancel_writes_a_zero_length_cancel_frame() {
        let cid = [5u8, 6, 7, 8];
        let link = QueueLink::new(vec![]);
        send_cancel(&link, &cid).unwrap();
        let sent = &link.written.borrow()[0];
        assert_eq!(sent[1..5].to_vec(), cid.to_vec());
        assert_eq!(sent[5], CTAPHID_CANCEL);
        assert_eq!(&sent[6..8], &[0, 0]);
    }
}
