//! Spike E — stock Noise IK via `snow`, targeted at a browser-tether
//! (WASM in an MV3 extension, native responder on the phone side).
//!
//! Wire shape (IK: `Noise_IK_25519_ChaChaPoly_BLAKE2s`):
//! ```text
//! IK:  <- s            (initiator pre-knows responder static: pinned)
//!      ...
//!      -> e, es, s, ss  msg1: payload = PROTOCOL_LABEL
//!      <- e, ee, se     msg2: payload = fresh 32-byte responder nonce
//!      -> transport frame #1: payload = echoed nonce  (replay defense)
//!      ... 2 encrypted transport frames both directions
//! ```
//! Replay defense (ADR 0114 Appendix A item 6): the responder sends a fresh
//! CSPRNG nonce per attempt inside msg2; the initiator must echo it in its
//! first transport frame; the responder rejects any mismatch — and a replayed
//! echo ciphertext fails AEAD decryption anyway (transport counter 0 is
//! single-use). WebSocket is ordered/reliable, so a strict per-session
//! transport nonce counter suffices; no reorder window.

use std::fmt;

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Protocol label carried as msg1 payload and checked by the responder — a
/// stand-in for the transcript-binding label/version the ADR requires.
pub const PROTOCOL_LABEL: &[u8] = b"baluard-spike-e-v1";

pub const NONCE_LEN: usize = 32;
const MAX_MSG: usize = 1024; // spike frames are tiny; noise maxmsg is 65535

include!(concat!(env!("OUT_DIR"), "/pinned_keys.rs"));

#[derive(Debug)]
pub enum SpikeError {
    Noise(snow::Error),
    /// msg1 payload did not equal PROTOCOL_LABEL
    BadLabel,
    /// remote static did not match the pinned peer static
    PinnedKeyMismatch,
    /// echoed nonce != fresh nonce issued in msg2
    BadEcho,
    BadLen,
    WrongStage,
    Rng(String),
}

impl fmt::Display for SpikeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Noise(e) => write!(f, "noise: {e}"),
            Self::BadLabel => write!(f, "msg1 payload != protocol label"),
            Self::PinnedKeyMismatch => write!(f, "remote static != pinned peer static"),
            Self::BadEcho => write!(f, "nonce echo mismatch (replay?)"),
            Self::BadLen => write!(f, "unexpected message length"),
            Self::WrongStage => write!(f, "handshake state machine called out of order"),
            Self::Rng(e) => write!(f, "rng: {e}"),
        }
    }
}

impl std::error::Error for SpikeError {}

impl From<snow::Error> for SpikeError {
    fn from(e: snow::Error) -> Self {
        Self::Noise(e)
    }
}

impl From<getrandom::Error> for SpikeError {
    fn from(e: getrandom::Error) -> Self {
        Self::Rng(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SpikeError>;

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n)?;
    Ok(n)
}

// ---------------------------------------------------------------- initiator

pub struct Initiator {
    hs: Option<snow::HandshakeState>,
    transport: Option<snow::TransportState>,
}

impl Initiator {
    pub fn new() -> Result<Self> {
        let params: snow::params::NoiseParams = PATTERN.parse()?;
        let hs = snow::Builder::new(params)
            .local_private_key(&INITIATOR_STATIC_SK)?
            .remote_public_key(&RESPONDER_STATIC_PK)?
            .build_initiator()?;
        Ok(Self {
            hs: Some(hs),
            transport: None,
        })
    }

    /// msg1: `-> e, es, s, ss`, payload = protocol label.
    pub fn write_msg1(&mut self) -> Result<Vec<u8>> {
        let mut hs = self.hs.take().ok_or(SpikeError::WrongStage)?;
        let mut buf = vec![0u8; MAX_MSG];
        let n = hs.write_message(PROTOCOL_LABEL, &mut buf)?;
        buf.truncate(n);
        self.hs = Some(hs);
        Ok(buf)
    }

    /// msg2: `<- e, ee, se`, payload = responder nonce. Returns the nonce the
    /// initiator must echo in its first transport frame. Verifies the
    /// authenticated responder static against the pinned key before finishing.
    pub fn read_msg2(&mut self, msg2: &[u8]) -> Result<[u8; NONCE_LEN]> {
        let mut hs = self.hs.take().ok_or(SpikeError::WrongStage)?;
        let remote = hs.get_remote_static().ok_or(SpikeError::PinnedKeyMismatch)?;
        if remote != &RESPONDER_STATIC_PK[..] {
            return Err(SpikeError::PinnedKeyMismatch);
        }
        let mut buf = [0u8; MAX_MSG];
        let n = hs.read_message(msg2, &mut buf)?;
        if !hs.is_handshake_finished() {
            return Err(SpikeError::WrongStage);
        }
        if n != NONCE_LEN {
            return Err(SpikeError::BadLen);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[..NONCE_LEN]);
        self.transport = Some(hs.into_transport_mode()?);
        Ok(nonce)
    }

    /// First transport frame: payload = echoed nonce (transport counter 0).
    pub fn echo_frame(&mut self, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
        let t = self.transport.as_mut().ok_or(SpikeError::WrongStage)?;
        let mut buf = vec![0u8; NONCE_LEN + 64];
        let n = t.write_message(nonce, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let t = self.transport.as_mut().ok_or(SpikeError::WrongStage)?;
        let mut buf = vec![0u8; payload.len() + 64];
        let n = t.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let t = self.transport.as_mut().ok_or(SpikeError::WrongStage)?;
        let mut buf = [0u8; MAX_MSG];
        let n = t.read_message(frame, &mut buf)?;
        Ok(buf[..n].to_vec())
    }
}

// ---------------------------------------------------------------- responder

pub struct Responder {
    hs: Option<snow::HandshakeState>,
    transport: Option<snow::TransportState>,
    nonce: [u8; NONCE_LEN],
    pinned_initiator_pk: [u8; NONCE_LEN],
}

impl Responder {
    pub fn new() -> Result<Self> {
        Self::with_pinned_initiator(INITIATOR_STATIC_PK)
    }

    pub fn with_pinned_initiator(pinned_initiator_pk: [u8; NONCE_LEN]) -> Result<Self> {
        let params: snow::params::NoiseParams = PATTERN.parse()?;
        let hs = snow::Builder::new(params)
            .local_private_key(&RESPONDER_STATIC_SK)?
            .build_responder()?;
        Ok(Self {
            hs: Some(hs),
            transport: None,
            nonce: [0u8; NONCE_LEN],
            pinned_initiator_pk,
        })
    }

    /// msg1 in, msg2 out. Authenticates the initiator static against the
    /// pinned key, then issues a fresh CSPRNG nonce as the msg2 payload.
    pub fn read_msg1(&mut self, msg1: &[u8]) -> Result<Vec<u8>> {
        let mut hs = self.hs.take().ok_or(SpikeError::WrongStage)?;
        let mut buf = [0u8; MAX_MSG];
        let n = hs.read_message(msg1, &mut buf)?;
        if hs.is_handshake_finished() {
            // IK msg1 must not complete the handshake
            self.hs = Some(hs);
            return Err(SpikeError::WrongStage);
        }
        if &buf[..n] != PROTOCOL_LABEL {
            self.hs = Some(hs);
            return Err(SpikeError::BadLabel);
        }
        let remote = hs.get_remote_static().ok_or(SpikeError::PinnedKeyMismatch)?;
        if remote != &self.pinned_initiator_pk[..] {
            self.hs = Some(hs);
            return Err(SpikeError::PinnedKeyMismatch);
        }
        self.nonce = random_nonce()?;
        let mut out = vec![0u8; MAX_MSG];
        let n = hs.write_message(&self.nonce, &mut out)?;
        out.truncate(n);
        self.hs = Some(hs);
        Ok(out)
    }

    /// First transport frame: must decrypt (counter 0) and equal the issued
    /// nonce. Anything else — stale echo, forged frame — is rejected and the
    /// responder never enters the transport phase.
    pub fn read_echo(&mut self, frame: &[u8]) -> Result<()> {
        let hs = self.hs.take().ok_or(SpikeError::WrongStage)?;
        let mut t = hs.into_transport_mode()?;
        let mut buf = [0u8; MAX_MSG];
        let n = t.read_message(frame, &mut buf)?;
        if n != NONCE_LEN || buf[..NONCE_LEN] != self.nonce {
            return Err(SpikeError::BadEcho);
        }
        self.transport = Some(t);
        Ok(())
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let t = self.transport.as_mut().ok_or(SpikeError::WrongStage)?;
        let mut buf = vec![0u8; payload.len() + 64];
        let n = t.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let t = self.transport.as_mut().ok_or(SpikeError::WrongStage)?;
        let mut buf = [0u8; MAX_MSG];
        let n = t.read_message(frame, &mut buf)?;
        Ok(buf[..n].to_vec())
    }
}

// ------------------------------------------------------- WASM FFI (initiator)

// WASM randomness: getrandom 0.3's `custom` backend calls this Rust-defined
// hook, which forwards to a single plain `env` import (see glue.js: backed
// by crypto.getRandomValues, chunked to its 65536-byte limit). Defined only
// for the cdylib target; native builds use the OS backend unchanged.
#[cfg(target_arch = "wasm32")]
unsafe extern "C" {
    fn spike_js_random_fill(ptr: *mut u8, len: usize);
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> std::result::Result<(), getrandom::Error> {
    unsafe { spike_js_random_fill(dest, len) };
    Ok(())
}

/// Hand-written `extern "C"` surface for the browser: linear-memory buffers,
/// no wasm-bindgen. One session at a time (spike scope).
///
/// Stages: 0 idle / 1 awaiting msg2 / 2 transport.
#[cfg(target_arch = "wasm32")]
mod ffi {
    use super::*;
    use core::cell::RefCell;

    // error codes (negative)
    const E_GENERIC: i32 = -1;
    const E_NO_SESSION: i32 = -2;
    const E_DECRYPT: i32 = -3;
    const E_BUF_SMALL: i32 = -4;
    const E_BAD_ECHO: i32 = -5;
    const E_PINNED: i32 = -6;
    const E_BAD_LABEL: i32 = -7;
    const E_BAD_LEN: i32 = -8;

    fn code(e: &SpikeError) -> i32 {
        match e {
            SpikeError::Noise(snow::Error::Decrypt) => E_DECRYPT,
            SpikeError::Noise(_) => E_GENERIC,
            SpikeError::WrongStage => E_NO_SESSION,
            SpikeError::BadEcho => E_BAD_ECHO,
            SpikeError::PinnedKeyMismatch => E_PINNED,
            SpikeError::BadLabel => E_BAD_LABEL,
            SpikeError::BadLen => E_BAD_LEN,
            SpikeError::Rng(_) => E_GENERIC,
        }
    }

    thread_local! {
        static INITIATOR: RefCell<Option<Initiator>> = const { RefCell::new(None) };
        static AWAITING_MSG2: RefCell<bool> = const { RefCell::new(false) };
    }

    fn emit(bytes: Result<Vec<u8>>, out_ptr: *mut u8, out_cap: usize) -> i32 {
        match bytes {
            Ok(data) => {
                if data.len() > out_cap {
                    return E_BUF_SMALL;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
                }
                data.len() as i32
            }
            Err(e) => code(&e),
        }
    }

    fn with_initiator<F>(f: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&mut Initiator) -> Result<Vec<u8>>,
    {
        INITIATOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(initiator) = slot.as_mut() else {
                return Err(SpikeError::WrongStage);
            };
            f(initiator)
        })
    }

    /// Allocate `n` bytes in wasm linear memory; returns pointer (0 on failure).
    #[no_mangle]
    pub extern "C" fn spike_alloc(n: usize) -> *mut u8 {
        let Some(layout) = core::alloc::Layout::from_size_align(n.max(1), 16).ok() else {
            return core::ptr::null_mut();
        };
        unsafe { std::alloc::alloc(layout) }
    }

    /// Free a block previously returned by [`spike_alloc`] (same `n`).
    #[no_mangle]
    pub extern "C" fn spike_dealloc(ptr: *mut u8, n: usize) {
        if ptr.is_null() {
            return;
        }
        let Some(layout) = core::alloc::Layout::from_size_align(n.max(1), 16).ok() else {
            return;
        };
        unsafe { std::alloc::dealloc(ptr, layout) };
    }

    /// Create the initiator session (pinned statics baked in at build time)
    /// and write msg1 to `out_ptr`. Returns byte count or negative error code.
    #[no_mangle]
    pub extern "C" fn spike_start(out_ptr: *mut u8, out_cap: usize) -> i32 {
        let mut initiator = match Initiator::new() {
            Ok(i) => i,
            Err(_) => return E_GENERIC,
        };
        let msg1 = match initiator.write_msg1() {
            Ok(m) => m,
            Err(e) => return code(&e),
        };
        if msg1.len() > out_cap {
            return E_BUF_SMALL;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(msg1.as_ptr(), out_ptr, msg1.len());
        }
        INITIATOR.with(|s| *s.borrow_mut() = Some(initiator));
        AWAITING_MSG2.with(|s| *s.borrow_mut() = true);
        msg1.len() as i32
    }

    /// Feed the next inbound bytes. While awaiting msg2: process it and emit
    /// the echoed-nonce transport frame. In transport: decrypt into `out_ptr`.
    #[no_mangle]
    pub extern "C" fn spike_read(in_ptr: *const u8, in_len: usize, out_ptr: *mut u8, out_cap: usize) -> i32 {
        let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) }.to_vec();
        if AWAITING_MSG2.with(|s| *s.borrow()) {
            let nonce = with_initiator(|i| {
                let n = i.read_msg2(&input)?;
                i.echo_frame(&n)
            });
            AWAITING_MSG2.with(|s| *s.borrow_mut() = false);
            emit(nonce, out_ptr, out_cap)
        } else {
            emit(with_initiator(|i| i.read_frame(&input)), out_ptr, out_cap)
        }
    }

    /// Encrypt `in_len` bytes at `in_ptr` as a transport frame into `out_ptr`.
    #[no_mangle]
    pub extern "C" fn spike_write(in_ptr: *const u8, in_len: usize, out_ptr: *mut u8, out_cap: usize) -> i32 {
        let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) }.to_vec();
        emit(with_initiator(|i| i.write_frame(&input)), out_ptr, out_cap)
    }

    /// 0 idle, 1 awaiting msg2, 2 transport.
    #[no_mangle]
    pub extern "C" fn spike_stage() -> i32 {
        if AWAITING_MSG2.with(|s| *s.borrow()) {
            1
        } else if INITIATOR.with(|s| s.borrow().is_some()) {
            2
        } else {
            0
        }
    }
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_of(b: &[u8]) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&b[..NONCE_LEN]);
        n
    }

    fn complete_handshake() -> (Initiator, Responder) {
        let mut i = Initiator::new().unwrap();
        let mut r = Responder::new().unwrap();
        let msg1 = i.write_msg1().unwrap();
        let msg2 = r.read_msg1(&msg1)
            .expect("responder accepts msg1 from pinned initiator");
        let nonce = i.read_msg2(&msg2).unwrap();
        let echo = i.echo_frame(&nonce).unwrap();
        r.read_echo(&echo).expect("echo must verify");
        (i, r)
    }

    #[test]
    fn pinned_statics_are_consistent_pairs() {
        // pk must actually derive from the pinned sk (catches the Spike-D
        // finding-3 class of bug: never reinterpret sk bytes as pk).
        use x25519_dalek::{PublicKey, StaticSecret};
        assert_eq!(
            PublicKey::from(&StaticSecret::from(INITIATOR_STATIC_SK)).to_bytes(),
            INITIATOR_STATIC_PK
        );
        assert_eq!(
            PublicKey::from(&StaticSecret::from(RESPONDER_STATIC_SK)).to_bytes(),
            RESPONDER_STATIC_PK
        );
    }

    #[test]
    fn happy_path_handshake_and_frames_both_directions() {
        let (mut i, mut r) = complete_handshake();

        // 2 encrypted transport frames responder -> initiator
        let up1 = r.write_frame(b"spike-e-up-1").unwrap();
        assert_eq!(i.read_frame(&up1).unwrap(), b"spike-e-up-1");
        let up2 = r.write_frame(b"spike-e-up-2").unwrap();
        assert_eq!(i.read_frame(&up2).unwrap(), b"spike-e-up-2");

        // 2 encrypted transport frames initiator -> responder
        let dn1 = i.write_frame(b"spike-e-dn-1").unwrap();
        assert_eq!(r.read_frame(&dn1).unwrap(), b"spike-e-dn-1");
        let dn2 = i.write_frame(b"spike-e-dn-2").unwrap();
        assert_eq!(r.read_frame(&dn2).unwrap(), b"spike-e-dn-2");
    }

    #[test]
    fn responder_rejects_impostor_static() {
        let mut r = Responder::new().unwrap();
        let params: snow::params::NoiseParams = PATTERN.parse().unwrap();
        let mut impostor = snow::Builder::new(params)
            .local_private_key(&[7u8; 32]).unwrap()
            .remote_public_key(&RESPONDER_STATIC_PK).unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; MAX_MSG];
        let n = impostor.write_message(PROTOCOL_LABEL, &mut buf).unwrap();
        let err = r.read_msg1(&buf[..n]).unwrap_err();
        assert!(
            matches!(
                err,
                SpikeError::Noise(snow::Error::Decrypt) | SpikeError::PinnedKeyMismatch
            ),
            "impostor must be rejected at msg1 (auth failure), got: {err}"
        );
    }

    #[test]
    fn responder_rejects_unpinned_initiator() {
        let mut r = Responder::with_pinned_initiator([9u8; 32]).unwrap();
        let mut i = Initiator::new().unwrap();
        let msg1 = i.write_msg1().unwrap();
        let err = r.read_msg1(&msg1).unwrap_err();
        assert!(matches!(err, SpikeError::PinnedKeyMismatch), "got: {err}");
    }

    #[test]
    fn wrong_echo_rejected() {
        let mut i = Initiator::new().unwrap();
        let mut r = Responder::new().unwrap();
        let msg1 = i.write_msg1().unwrap();
        let msg2 = r.read_msg1(&msg1).unwrap();
        let mut nonce = i.read_msg2(&msg2).unwrap();
        nonce[0] ^= 0x01; // corrupt the echo
        let echo = i.echo_frame(&nonce).unwrap();
        assert!(
            matches!(
                r.read_echo(&echo).unwrap_err(),
                SpikeError::BadEcho | SpikeError::Noise(_)
            ),
            "wrong echo must be rejected"
        );
    }

    #[test]
    fn replayed_msg1_and_stale_echo_are_rejected() {
        // capture from a first, complete session
        let mut i_a = Initiator::new().unwrap();
        let mut r_a = Responder::new().unwrap();
        let msg1 = i_a.write_msg1().unwrap();
        let msg2 = r_a.read_msg1(&msg1).unwrap();
        let nonce_a = i_a.read_msg2(&msg2).unwrap();
        let echo_a = i_a.echo_frame(&nonce_a).unwrap();

        // fresh responder session (the phone's next handshake attempt):
        // the replayed msg1 authenticates (same pinned key) and yields a fresh
        // nonce in msg2_b; the STALE echo must be rejected.
        let mut r_b = Responder::new().unwrap();
        let msg2_b = r_b
            .read_msg1(&msg1)
            .expect("replayed msg1 accepted, but a FRESH nonce is issued");
        assert_ne!(msg2, msg2_b, "fresh msg2 must differ from captured msg2");
        let err = r_b.read_echo(&echo_a).unwrap_err();
        assert!(
            matches!(err, SpikeError::BadEcho | SpikeError::Noise(_)),
            "stale echo must be rejected, got: {err}"
        );
        // and the responder must NOT have entered the transport phase
        assert!(
            matches!(r_b.write_frame(b"x"), Err(SpikeError::WrongStage)),
            "rejected replay must never reach transport"
        );
    }

    #[test]
    fn replayed_echo_ciphertext_rejected_in_transport() {
        let mut i = Initiator::new().unwrap();
        let mut r = Responder::new().unwrap();
        let msg1 = i.write_msg1().unwrap();
        let msg2 = r.read_msg1(&msg1).unwrap();
        let nonce = i.read_msg2(&msg2).unwrap();
        let echo = i.echo_frame(&nonce).unwrap();
        r.read_echo(&echo).unwrap();
        // duplicate of the same ciphertext: counter 0 is spent -> AEAD failure
        assert!(
            matches!(r.read_frame(&echo), Err(SpikeError::Noise(snow::Error::Decrypt))),
            "replayed echo ciphertext must fail AEAD decryption"
        );
    }

    #[test]
    fn stale_msg2_rejected_by_fresh_initiator() {
        let mut r = Responder::new().unwrap();
        let mut i_capture = Initiator::new().unwrap();
        let msg1 = i_capture.write_msg1().unwrap();
        let stale_msg2 = r.read_msg1(&msg1).unwrap();
        let _ = i_capture;
        let mut i_b = Initiator::new().unwrap();
        let _msg1_b = i_b.write_msg1().unwrap();
        assert!(
            i_b.read_msg2(&stale_msg2).is_err(),
            "old msg2 must fail against a new ephemeral"
        );
    }
}
