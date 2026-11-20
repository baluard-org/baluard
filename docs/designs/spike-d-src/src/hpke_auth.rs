// Scheme 1: hpke-extra-ephemeral — upgrade of the repo's one-shot OpModeS::Base.
// Needs a JS HPKE implementation on the browser side (no WebCrypto HPKE API
// exists), which is the ADR's flagged new dependency. Implemented here for an
// apples-to-apples empirical comparison with the webnative scheme.
//
// Wire: msg1 = encapped(32) || seal(eI_pub). msg2 = eR_pub(32) || nonceR(32).
// Session key = HKDF(hpke_export || DH(eI,eR) || DH(eI,sR) || DH(sI,eR),
//                    salt=ROLE, info=transcript incl nonceR).
// The phone's ephemeral + nonce in the schedule is the FS/replay fix over
// plain sender-ephemeral HPKE Auth.

use crate::{kdf, Bytes, ROLE};
use hpke::kem::X25519HkdfSha256;
use hpke::{
    aead::AesGcm256, Deserializable, HpkeError, Kem as _, OpModeR, OpModeS, Serializable,
    kdf::HkdfSha256,
};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub, StaticSecret as XStatic};

type Kem = X25519HkdfSha256;
type Sk = <Kem as hpke::kem::Kem>::PrivateKey;
type Pk = <Kem as hpke::kem::Kem>::PublicKey;
pub(crate) const INFO: &[u8] = b"baluard-tether-hpke-v1";
pub(crate) const AAD: &[u8] = b"baluard-tether-msg1";
pub(crate) const EXPORT_LABEL: &[u8] = b"baluard-tether-session-v1";

pub struct Party {
    pub x_static: XStatic,
}

impl Party {
    pub fn generate() -> Party {
        Party {
            x_static: XStatic::random_from_rng(OsRng),
        }
    }
    pub fn sk_bytes(&self) -> [u8; 32] {
        self.x_static.to_bytes()
    }
    pub fn pub_bytes(&self) -> [u8; 32] {
        *x25519_dalek::PublicKey::from(&self.x_static).as_bytes()
    }
}

fn sk_of(b: &[u8; 32]) -> Sk {
    Sk::from_bytes(b).expect("valid x25519 key")
}
fn pk_of(b: &[u8; 32]) -> Pk {
    Pk::from_bytes(b).expect("valid x25519 key")
}

pub struct InitiatorHs {
    e_i: EphemeralSecret,
    e_i_pub: XPub,
    export_secret: Bytes,
    pub msg1: Bytes, // encapped(32) || ct_with_tag
}

pub fn initiator_start(dev_sk_bytes: &[u8; 32], phone_pub_bytes: &[u8; 32]) -> InitiatorHs {
    let e_i = EphemeralSecret::random_from_rng(OsRng);
    let e_i_pub = XPub::from(&e_i);
    // sender pub MUST be derived from the scalar (PublicKey::from(bytes) would
    // treat the scalar bytes as an x-coordinate and corrupt the Auth schedule).
    let dev_static = XStatic::from(*dev_sk_bytes);
    let dev_pub = *XPub::from(&dev_static).as_bytes();
    let (encapped, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Auth((sk_of(dev_sk_bytes), Pk::from_bytes(&dev_pub).unwrap())),
        &pk_of(phone_pub_bytes),
        INFO,
        &mut OsRng,
    )
    .unwrap();
    let ct = ctx.seal(e_i_pub.as_bytes(), AAD).unwrap();
    let mut msg1 = encapped.to_bytes().to_vec();
    msg1.extend_from_slice(&ct);
    let mut export = vec![0u8; 32];
    ctx.export(EXPORT_LABEL, &mut export).unwrap();
    InitiatorHs {
        e_i,
        e_i_pub,
        export_secret: export,
        msg1,
    }
}

pub struct ResponderHs {
    e_r: EphemeralSecret,
    nonce_r: Bytes,
    export_secret: Bytes,
    e_i_pub: XPub,
    pub msg2: Bytes,
}

pub fn responder_on_msg1(
    phone_sk_bytes: &[u8; 32],
    dev_pub_bytes: &[u8; 32],
    msg1: &[u8],
) -> Result<ResponderHs, HpkeError> {
    if msg1.len() < 32 + 16 {
        return Err(HpkeError::ValidationError);
    }
    let encapped = <Kem as hpke::kem::Kem>::EncappedKey::from_bytes(&msg1[..32])?;
    let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Auth(pk_of(dev_pub_bytes)),
        &sk_of(phone_sk_bytes),
        &encapped,
        INFO,
    )?;
    let payload = ctx.open(&msg1[32..], AAD)?;
    let e_i_pub =
        XPub::from(<[u8; 32]>::try_from(payload.as_slice()).map_err(|_| HpkeError::ValidationError)?);
    let e_r = EphemeralSecret::random_from_rng(OsRng);
    let e_r_pub = XPub::from(&e_r);
    let mut nonce_r = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce_r);
    let mut msg2 = Vec::new();
    msg2.extend_from_slice(e_r_pub.as_bytes());
    msg2.extend_from_slice(&nonce_r);
    let mut export = vec![0u8; 32];
    ctx.export(EXPORT_LABEL, &mut export).unwrap();
    Ok(ResponderHs {
        e_r,
        nonce_r,
        export_secret: export,
        e_i_pub,
        msg2,
    })
}

pub fn initiator_finish(hs: InitiatorHs, msg2: &[u8]) -> Result<(Bytes, Bytes), &'static str> {
    if msg2.len() != 64 {
        return Err("msg2 len");
    }
    let e_r_pub = XPub::from(<[u8; 32]>::try_from(&msg2[..32]).unwrap());
    let nonce_r = &msg2[32..64];
    let dh_ee = *hs.e_i.diffie_hellman(&e_r_pub).as_bytes();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(hs.e_i_pub.as_bytes());
    transcript.extend_from_slice(e_r_pub.as_bytes());
    transcript.extend_from_slice(nonce_r);
    // phone ephemeral + nonceR in the schedule: the FS/replay fix.
    let k = kdf(&[&hs.export_secret, &dh_ee], ROLE, &transcript, 32);
    let mut msg3 = Vec::new();
    msg3.extend_from_slice(nonce_r);
    Ok((msg3, k))
}

pub fn responder_finish(hs: ResponderHs, msg3: &[u8]) -> Result<Bytes, &'static str> {
    if msg3.len() != 32 {
        return Err("msg3 len");
    }
    if msg3 != hs.nonce_r.as_slice() {
        return Err("stale handshake: nonceR echo mismatch (replay)");
    }
    let e_r_pub = XPub::from(<[u8; 32]>::try_from(&hs.msg2[..32]).unwrap());
    let dh_ee = *hs.e_r.diffie_hellman(&hs.e_i_pub).as_bytes();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(hs.e_i_pub.as_bytes());
    transcript.extend_from_slice(e_r_pub.as_bytes());
    transcript.extend_from_slice(&hs.nonce_r);
    let k = kdf(&[&hs.export_secret, &dh_ee], ROLE, &transcript, 32);
    Ok(k)
}
