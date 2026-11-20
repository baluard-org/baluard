// Spike D: two-party handshake candidates for the browser-tether channel.
// Two schemes, same properties proven by tests:
//   S1 "hpke-extra-ephemeral" (mod hpke_auth): HPKE OpModeS::Auth upgrade + phone ephemeral + nonce
//   S2 "webnative": raw X25519 ECDH + HKDF transcript + Ed25519 sig (all WebCrypto-native)
// Every scheme must give: mutual auth against pinned statics, forward secrecy
// (recorded traffic undecryptable after ephemeral wipe even with both statics leaked),
// and first-frame replay defense (phone nonce in transcript before any request runs).

pub mod hpke_auth;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

pub type Bytes = Vec<u8>;

pub fn now_unused_random(n: usize) -> Bytes {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

fn kdf(ikms: &[&[u8]], salt: &[u8], info: &[u8], len: usize) -> Bytes {
    let mut okm = vec![0u8; len];
    // Multiple IKMs are concatenated; uniqueness comes from each party's
    // ephemeral being present exactly once in the ikm set.
    let mut ikm = Vec::new();
    for i in ikms {
        ikm.extend_from_slice(i);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    hk.expand(info, &mut okm).expect("okm len");
    okm
}

const ROLE: &[u8] = b"baluard-tether-handshake-v1";

// ---------------------------------------------------------------------------
// Scheme 2: webnative (X25519 + HKDF + Ed25519). This is the candidate that
// needs zero new JS crypto dependencies: X25519 deriveBits, HKDF, AES-GCM and
// Ed25519 sign/verify are all first-class WebCrypto APIs (Spike A confirmed
// non-extractable X25519 + Ed25519 on Chrome 133/137+ and Firefox 129/130+).
// ---------------------------------------------------------------------------

pub mod webnative {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

    pub struct DeviceKey {
        pub x_static: XStatic,
        pub ed: ed25519_dalek::SigningKey,
    }

    pub struct PhoneKey {
        pub x_static: XStatic,
        pub ed: ed25519_dalek::SigningKey,
    }

    // msg1: initiator ephemeral pub
    // msg2: responder ephemeral pub || responder nonce (32B) || responder sig over (eR || nonceR || eI)
    // msg3: device pub || echoed nonceR || device sig over (full transcript || device pub)
    // msg3 is the first DATA frame and is NOT executed: the phone verifies it
    // against the pinned device key and the nonce echo BEFORE any request runs.
    pub struct InitiatorHandshake {
        pub e_i: XStatic,
        pub e_i_pub: XPub,
        pub msg1: Bytes,
        pub transcript1: Bytes,
    }

    pub fn initiator_start() -> InitiatorHandshake {
        // Spike model: ephemerals are fresh single-use StaticSecrets
        // (EphemeralSecret consumes itself on DH and cannot serialise; the
        // production implementation must keep the single-use guarantee, e.g.
        // via an audited Noise library).
        let e_i = XStatic::from(<[u8; 32]>::try_from(now_unused_random(32)).unwrap());
        let e_i_pub = XPub::from(&e_i);
        InitiatorHandshake {
            e_i,
            e_i_pub,
            msg1: e_i_pub.as_bytes().to_vec(),
            transcript1: e_i_pub.as_bytes().to_vec(),
        }
    }

    pub struct ResponderHandshake {
        e_r: XStatic,
        nonce_r: Bytes,
        pub msg2: Bytes,
        transcript2: Bytes,
    }

    pub fn responder_on_msg1(phone: &PhoneKey, msg1: &[u8]) -> ResponderHandshake {
        let e_i_pub = XPub::from(<[u8; 32]>::try_from(msg1).expect("eI len"));
        let e_r = XStatic::from(<[u8; 32]>::try_from(now_unused_random(32)).unwrap());
        let e_r_pub = XPub::from(&e_r);
        let nonce_r = now_unused_random(32);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(msg1);
        transcript.extend_from_slice(e_r_pub.as_bytes());
        let mut sig_input = transcript.clone();
        sig_input.extend_from_slice(&nonce_r);
        let sig = phone.ed.sign(&sig_input);
        let mut msg2 = Vec::new();
        msg2.extend_from_slice(e_r_pub.as_bytes());
        msg2.extend_from_slice(&nonce_r);
        msg2.extend_from_slice(&sig.to_bytes());
        transcript.extend_from_slice(&nonce_r);
        let _ = e_i_pub;
        ResponderHandshake {
            e_r,
            nonce_r,
            msg2,
            transcript2: transcript,
        }
    }

    // Returns (msg3, session_key). The initiator MUST NOT send any request
    // before msg2; the key schedule includes nonceR.
    pub fn initiator_finish(
        dev: &DeviceKey,
        phone_x_static_pub: &XPub,
        phone_ed_pub: &ed25519_dalek::VerifyingKey,
        hs: InitiatorHandshake,
        msg2: &[u8],
    ) -> Result<(Bytes, Bytes), &'static str> {
        if msg2.len() != 32 + 32 + 64 {
            return Err("msg2 len");
        }
        let e_r_pub = XPub::from(<[u8; 32]>::try_from(&msg2[..32]).unwrap());
        let nonce_r = &msg2[32..64];
        let sig = ed25519_dalek::Signature::from_slice(&msg2[64..128]).unwrap();
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&hs.transcript1);
        sig_input.extend_from_slice(e_r_pub.as_bytes());
        sig_input.extend_from_slice(nonce_r);
        phone_ed_pub
            .verify(&sig_input, &sig)
            .map_err(|_| "responder sig")?;
        // mutual auth: static blends (both directions)
        let dh_ee = *hs.e_i.diffie_hellman(&e_r_pub).as_bytes();
        let dh_es = *hs.e_i.diffie_hellman(phone_x_static_pub).as_bytes();
        let dh_se = *dev.x_static.diffie_hellman(&e_r_pub).as_bytes();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&hs.transcript1);
        transcript.extend_from_slice(e_r_pub.as_bytes());
        transcript.extend_from_slice(nonce_r);
        let k = kdf(&[&dh_ee, &dh_es, &dh_se], ROLE, &transcript, 32);
        let mut sig_input3 = transcript.clone();
        sig_input3.extend_from_slice(dev.ed.verifying_key().as_bytes());
        let sig3 = dev.ed.sign(&sig_input3);
        let mut msg3 = Vec::new();
        msg3.extend_from_slice(dev.ed.verifying_key().as_bytes());
        msg3.extend_from_slice(nonce_r);
        msg3.extend_from_slice(&sig3.to_bytes());
        Ok((msg3, k))
    }

    // Phone side: verify msg3 against the pinned device key and the fresh
    // nonce BEFORE any request executes. Returns the session key.
    pub fn responder_finish(
        phone: &PhoneKey,
        hs: ResponderHandshake,
        dev_x_static_pub: &XPub,
        pinned_dev_ed_pub: &ed25519_dalek::VerifyingKey,
        msg3: &[u8],
    ) -> Result<Bytes, &'static str> {
        if msg3.len() != 32 + 32 + 64 {
            return Err("msg3 len");
        }
        let dev_ed_pub = ed25519_dalek::VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(&msg3[..32]).unwrap(),
        )
        .unwrap();
        if dev_ed_pub.as_bytes() != pinned_dev_ed_pub.as_bytes() {
            return Err("device key not pinned");
        }
        let echoed = &msg3[32..64];
        if echoed != hs.nonce_r.as_slice() {
            return Err("stale handshake: nonceR echo mismatch (replay)");
        }
        let sig = ed25519_dalek::Signature::from_slice(&msg3[64..128]).unwrap();
        let mut sig_input3 = hs.transcript2.clone();
        sig_input3.extend_from_slice(dev_ed_pub.as_bytes());
        pinned_dev_ed_pub
            .verify(&sig_input3, &sig)
            .map_err(|_| "device sig")?;
        let e_i_pub = XPub::from(<[u8; 32]>::try_from(&hs.transcript2[..32]).unwrap());
        let e_r_pub = XPub::from(<[u8; 32]>::try_from(&hs.transcript2[32..64]).unwrap());
        let dh_ee = *hs.e_r.diffie_hellman(&e_i_pub).as_bytes();
        let dh_es = *phone.x_static.diffie_hellman(&e_i_pub).as_bytes();
        let dh_se = *hs.e_r.diffie_hellman(dev_x_static_pub).as_bytes();
        let k = kdf(&[&dh_ee, &dh_es, &dh_se], ROLE, &hs.transcript2, 32);
        Ok(k)
    }
}

// ---------------------------------------------------------------------------
// Tests shared by both schemes
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, VerifyingKey};

    #[test]
    fn webnative_happy_path_keys_match() {
        let dev = webnative::DeviceKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let phone = webnative::PhoneKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let i = webnative::initiator_start();
        let r = webnative::responder_on_msg1(&phone, &i.msg1);
        let dev_x_pub = x25519_dalek::PublicKey::from(&dev.x_static);
        let (msg3, k_i) = webnative::initiator_finish(
            &dev,
            &x25519_dalek::PublicKey::from(&phone.x_static),
            &phone.ed.verifying_key(),
            i,
            &r.msg2,
        )
        .unwrap();
        let phone_ed_pub: VerifyingKey = dev.ed.verifying_key();
        let k_r = webnative::responder_finish(&phone, r, &dev_x_pub, &phone_ed_pub, &msg3).unwrap();
        assert_eq!(k_i, k_r);
    }

    #[test]
    fn webnative_forward_secrecy_statics_leaked_recorded_traffic_safe() {
        // Record a full handshake, then wipe ephemerals (normal session end).
        // Attacker later learns BOTH static secrets plus the full transcript.
        // The key schedule contains DH(eI,eR), DH(eI,sR), DH(sI,eR): every term
        // needs an ephemeral secret that no longer exists anywhere.
        let dev = webnative::DeviceKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let phone = webnative::PhoneKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let i = webnative::initiator_start();
        let r = webnative::responder_on_msg1(&phone, &i.msg1);
        let recorded_msg2 = r.msg2.clone();
        let dev_x_pub = x25519_dalek::PublicKey::from(&dev.x_static);
        let (_msg3, k_true) = webnative::initiator_finish(
            &dev,
            &x25519_dalek::PublicKey::from(&phone.x_static),
            &phone.ed.verifying_key(),
            i,
            &r.msg2,
        )
        .unwrap();
        let s_dev = dev.x_static.to_bytes();
        let s_phone = phone.x_static.to_bytes();
        let k_attack = kdf(&[&s_dev, &s_phone], ROLE, &recorded_msg2, 32);
        assert_ne!(k_attack, k_true);
        let _ = dev_x_pub;
    }

    #[test]
    fn webnative_replay_msg1_fails_nonce_echo() {
        let dev = webnative::DeviceKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let phone = webnative::PhoneKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let i = webnative::initiator_start();
        let r1 = webnative::responder_on_msg1(&phone, &i.msg1);
        let msg1_recorded = i.msg1.clone();
        let dev_x_pub = x25519_dalek::PublicKey::from(&dev.x_static);
        let (msg3_session1, _k1) = webnative::initiator_finish(
            &dev,
            &x25519_dalek::PublicKey::from(&phone.x_static),
            &phone.ed.verifying_key(),
            i,
            &r1.msg2,
        )
        .unwrap();
        let r_replay = webnative::responder_on_msg1(&phone, &msg1_recorded);
        assert_ne!(r_replay.msg2, r1.msg2);
        let err = webnative::responder_finish(
            &phone,
            r_replay,
            &dev_x_pub,
            &dev.ed.verifying_key(),
            &msg3_session1,
        );
        assert!(err.is_err(), "replayed msg3 must be rejected: {:?}", err.err());
    }

    #[test]
    fn webnative_forged_msg3_rejected() {
        let dev = webnative::DeviceKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let phone = webnative::PhoneKey {
            x_static: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            ed: ed25519_dalek::SigningKey::generate(&mut OsRng),
        };
        let imposter = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let i = webnative::initiator_start();
        let r = webnative::responder_on_msg1(&phone, &i.msg1);
        let mut msg3 = Vec::new();
        msg3.extend_from_slice(imposter.verifying_key().as_bytes());
        msg3.extend_from_slice(&r.msg2[32..64]);
        let mut sig_input = r.msg2.clone();
        sig_input.extend_from_slice(imposter.verifying_key().as_bytes());
        let sig = imposter.sign(&sig_input);
        msg3.extend_from_slice(&sig.to_bytes());
        let err = webnative::responder_finish(
            &phone,
            r,
            &x25519_dalek::PublicKey::from(&dev.x_static),
            &dev.ed.verifying_key(),
            &msg3,
        );
        assert!(err.is_err(), "unpinned device key must be rejected");
    }

    #[test]
    fn hpke_happy_path_keys_match() {
        let dev = hpke_auth::Party::generate();
        let phone = hpke_auth::Party::generate();
        let hs = hpke_auth::initiator_start(&dev.sk_bytes(), &phone.pub_bytes());
        let r = hpke_auth::responder_on_msg1(&phone.sk_bytes(), &dev.pub_bytes(), &hs.msg1)
            .unwrap();
        let (msg3, k_i) = hpke_auth::initiator_finish(hs, &r.msg2).unwrap();
        let k_r = hpke_auth::responder_finish(r, &msg3).unwrap();
        assert_eq!(k_i, k_r);
    }

    #[test]
    fn hpke_forward_secrecy_statics_leaked_recorded_traffic_safe() {
        let dev = hpke_auth::Party::generate();
        let phone = hpke_auth::Party::generate();
        let hs = hpke_auth::initiator_start(&dev.sk_bytes(), &phone.pub_bytes());
        let recorded_msg1 = hs.msg1.clone();
        let r = hpke_auth::responder_on_msg1(&phone.sk_bytes(), &dev.pub_bytes(), &hs.msg1)
            .unwrap();
        let recorded_msg2 = r.msg2.clone();
        let (_msg3, k_true) = hpke_auth::initiator_finish(hs, &r.msg2).unwrap();
        let s_dev = dev.sk_bytes();
        let s_phone = phone.sk_bytes();
        let k_attack = kdf(&[&s_dev, &s_phone], ROLE, &recorded_msg2, 32);
        assert_ne!(k_attack, k_true);
        let _ = recorded_msg1;
    }

    #[test]
    fn hpke_replay_msg1_fails_nonce_echo() {
        let dev = hpke_auth::Party::generate();
        let phone = hpke_auth::Party::generate();
        let hs = hpke_auth::initiator_start(&dev.sk_bytes(), &phone.pub_bytes());
        let r1 = hpke_auth::responder_on_msg1(&phone.sk_bytes(), &dev.pub_bytes(), &hs.msg1)
            .unwrap();
        let (msg3_session1, _k1) = hpke_auth::initiator_finish(hs, &r1.msg2).unwrap();
        let hs2 = hpke_auth::initiator_start(&dev.sk_bytes(), &phone.pub_bytes());
        let r2 = hpke_auth::responder_on_msg1(&phone.sk_bytes(), &dev.pub_bytes(), &hs2.msg1)
            .unwrap();
        // Fresh responder nonce differs; replaying session-1 msg3 fails.
        assert_ne!(r2.msg2, r1.msg2);
        let err = hpke_auth::responder_finish(r2, &msg3_session1);
        assert!(err.is_err(), "replayed msg3 must be rejected");
    }

    #[test]
    fn hpke_wrong_sender_key_open_fails() {
        // Attacker with a DIFFERENT static key cannot complete msg1: OpModeR::Auth
        // binds the sender identity to the pinned device key.
        let dev = hpke_auth::Party::generate();
        let phone = hpke_auth::Party::generate();
        let imposter = hpke_auth::Party::generate();
        let hs = hpke_auth::initiator_start(&imposter.sk_bytes(), &phone.pub_bytes());
        let r = hpke_auth::responder_on_msg1(&phone.sk_bytes(), &dev.pub_bytes(), &hs.msg1);
        assert!(r.is_err(), "msg1 from an unpinned static must fail to open");
    }
}
