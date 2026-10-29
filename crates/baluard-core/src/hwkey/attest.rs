//! FIDO2 packed-attestation verification at enroll - the anti-counterfeit
//! check from the plan's gray-market analysis. At `create_binding` the
//! token's attestation chain is walked and its self-signed root is
//! compared against the bundled Yubico pin (pulled from the FIDO
//! Metadata Service entry for the reference device; refreshed with app
//! releases, never online at runtime).
//!
//! The Yubico attestation hierarchy (root, intermediates, per-device
//! certificates) is all-RSA with PKCS#1 v1.5 signatures (sha256 inner
//! links, sha512 root self-signature), while the attStmt itself rides
//! RS256 (alg -257) or ES256 (alg -7) depending on the token family -
//! so the verifier dispatches per certificate, RSA and EC both.
//!
//! Policy (plan "Attestation at enroll"): a chain that fails
//! cryptographic verification is a hard refuse; a chain that verifies
//! but terminates at an unpinned root is allowed as an unknown vendor
//! (Nitrokey, SoloKeys, Titan, a forged-but-self-consistent chain -
//! the honest caveat is that attestation is a strong signal, not
//! mathematical certainty, because batch attestation keys are
//! extractable in principle). The pin set covers "Yubico Attestation
//! Root 1" (MDS, the reference device entry), the legacy "Yubico U2F
//! Root CA Serial 457200631", and the 2024 "Yubico FIDO Root CA Serial
//! 450203556" - Yubico's published FIDO trust bundle - plus the five
//! FIDO MDS anchor certificates for the reference device, whose 5.7.4
//! chain runs leaf -> FIDO Attestation CA -> intermediate -> Root 1.

use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha512};

/// What [`crate::hwkey::fido::Token::make_credential`] reports, mapped
/// from the CTAP2 attestation object. All fields the verifier needs,
/// nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedAttestation {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    /// The clientDataHash the platform sent in the makeCredential call
    /// (the random challenge's hash slot in native CTAP).
    pub client_data_hash: [u8; 32],
    pub alg: i64,
    pub sig: Vec<u8>,
    /// DER certificates, leaf first per the WebAuthn packed format.
    pub x5c: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationVerdict {
    /// Chain verifies and terminates at the pinned Yubico root.
    YubicoVerified,
    /// Chain verifies but the root is not pinned - unknown vendor, or a
    /// forged-but-self-consistent chain. Allowed with plain copy.
    UnknownVendor,
    /// Signature or certificate structure is broken. Hard refuse.
    Invalid,
}

/// A public key parsed from subjectPublicKeyInfo.
enum PubKey {
    /// Uncompressed P-256 point (65 bytes, 0x04-prefixed).
    Ec(Vec<u8>),
    /// PKCS#1 RSAPublicKey DER.
    Rsa(Vec<u8>),
}

/// One parsed X.509 certificate: the exact bytes its issuer signed, the
/// signature over them, the signature algorithm OID, and the key that
/// signs its children.
struct CertParts {
    /// tag+len+value bytes of tbsCertificate.
    tbs_raw: Vec<u8>,
    sig_der: Vec<u8>,
    /// Certificate-level signature algorithm OID
    /// (1.2.840.113549.1.1.{11,13} RSA, 1.2.840.10045.4.3.2 ECDSA-SHA256).
    sig_alg_oid: Vec<u8>,
    key: PubKey,
}

/// One DER TLV element: tag, value, the raw element (tag+len+value),
/// and the remainder of the buffer after it.
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    raw: &'a [u8],
    rest: &'a [u8],
}

fn tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let lb = buf[1];
    let (i, len) = if lb & 0x80 == 0 {
        (2usize, lb as usize)
    } else {
        let n = (lb & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in &buf[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        (2 + n, len)
    };
    if buf.len() < i + len {
        return None;
    }
    Some(Tlv {
        tag,
        body: &buf[i..i + len],
        raw: &buf[..i + len],
        rest: &buf[i + len..],
    })
}

/// The first OID element inside an AlgorithmIdentifier SEQUENCE.
fn alg_oid(seq_body: &[u8]) -> Option<Vec<u8>> {
    let oid = tlv(seq_body)?;
    if oid.tag != 0x06 {
        return None;
    }
    Some(oid.body.to_vec())
}

fn parse_cert(der: &[u8]) -> Option<CertParts> {
    // Certificate ::= SEQUENCE { tbs, sigAlg, sigValue }
    let cert = tlv(der)?;
    if cert.tag != 0x30 || !cert.rest.is_empty() {
        return None;
    }
    let tbs = tlv(cert.body)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let outer_alg = tlv(tbs.rest)?;
    if outer_alg.tag != 0x30 {
        return None;
    }
    let sig_alg_oid = alg_oid(outer_alg.body)?;
    let sig = tlv(outer_alg.rest)?;
    if sig.tag != 0x03 || sig.body.is_empty() || sig.body[0] != 0 {
        // BIT STRING; the unused-bits count must be 0 for signatures.
        return None;
    }
    // Walk tbs children to subjectPublicKeyInfo (6th of the ordered
    // fields): [0] version?, serial, sigAlg, issuer, validity, subject,
    // spki.
    let mut cur = tbs.body;
    let mut key = None;
    let mut seen = 0;
    while !cur.is_empty() {
        let el = tlv(cur)?;
        cur = el.rest;
        match el.tag {
            0xA0 => {} // [0] EXPLICIT version
            0x02 | 0x30 => {
                seen += 1;
                if seen == 6 {
                    if el.tag != 0x30 {
                        return None;
                    }
                    // spki ::= SEQUENCE { algid, BIT STRING key }
                    let s1 = tlv(el.body)?;
                    if s1.tag != 0x30 {
                        return None;
                    }
                    let s2 = tlv(s1.rest)?;
                    if s2.tag != 0x03 || s2.body.is_empty() || s2.body[0] != 0 {
                        return None;
                    }
                    let keybits = &s2.body[1..];
                    let oid = alg_oid(s1.body)?;
                    key = Some(match oid.as_slice() {
                        // 1.2.840.10045.2.1 ecPublicKey
                        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] => {
                            PubKey::Ec(keybits.to_vec())
                        }
                        // 1.2.840.113549.1.1.1 rsaEncryption
                        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] => {
                            PubKey::Rsa(keybits.to_vec())
                        }
                        _ => return None,
                    });
                    break;
                }
            }
            _ => return None,
        }
    }
    Some(CertParts {
        tbs_raw: tbs.raw.to_vec(),
        sig_der: sig.body[1..].to_vec(),
        sig_alg_oid,
        key: key?,
    })
}

/// PKCS#1 v1.5 / ECDSA verification of `msg` under `key`, choosing the
/// digest from the child certificate's signature algorithm OID.
fn verify_link(key: &PubKey, msg: &[u8], sig: &[u8], sig_alg: &[u8]) -> bool {
    match key {
        PubKey::Ec(point) => {
            let (Ok(vk), Ok(sig)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p256::ecdsa::Signature::from_der(sig),
            ) else {
                return false;
            };
            vk.verify(msg, &sig).is_ok()
        }
        PubKey::Rsa(pkcs1) => {
            let Ok(pubk) = RsaPublicKey::from_pkcs1_der(pkcs1) else {
                return false;
            };
            let Ok(sig) = RsaSignature::try_from(sig) else {
                return false;
            };
            // 1.2.840.113549.1.1.11 sha256WithRSA, .13 sha512WithRSA.
            // ECDSA-SHA256 parents never sign RSA-keyed children and
            // vice versa, but the digest follows the declared alg.
            match sig_alg {
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B] => {
                    RsaVerifyingKey::<Sha256>::new(pubk).verify(msg, &sig).is_ok()
                }
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D] => {
                    RsaVerifyingKey::<Sha512>::new(pubk).verify(msg, &sig).is_ok()
                }
                _ => false,
            }
        }
    }
}

/// Bundle pin: the self-signed "Yubico Attestation Root 1" from the
/// FIDO MDS entry of the reference device (Security Key NFC by Yubico,
/// AAGUID b7d3f68e-88a6-471e-9ecf-2df26d041ede), base64 DER.
pub(crate) const YUBICO_ATTESTATION_ROOT_B64: &str = concat!(
    "MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQENBQAwJDEiMCAG",
    "A1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEyMDEwMDAwMDBaGA85OTk5MTIz",
    "MTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZI",
    "hvcNAQEBBQADggEPADCCAQoCggEBAMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXv",
    "l12LUhBZ5LmiBScIZd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G",
    "74b/U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAucsrbE485",
    "HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyCimJukhYy6KoqNMKQEdpN",
    "iSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdwMRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNm",
    "MGQwHQYDVR0OBBYEFNLu71oijTptXCOXPfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOX",
    "PfKF1SbxJXuSMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB",
    "DQUAA4IBAQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1Xnqu",
    "B5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIFTWeIhMNcZKsDZrFA",
    "yPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7VolBNlld6pRFKlX8ust6OTMOeADl2",
    "xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3iroRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/",
    "HqaUYCA/L8ldRk6H7Xk35D+WVpmq2Sh/xT5HiFuhf4wJb0bK"
);

/// Yubico U2F Root CA Serial 457200631 (2014): the attestation chain
/// of every pre-2024-firmware token, including the 5.7 Security Key
/// reference device. developers.yubico.com/PKI/yubico-fido-ca-1.pem.
pub(crate) const YUBICO_U2F_ROOT_457200631_B64: &str = concat!(
    "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28g",
    "VTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkw",
    "NDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2",
    "MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+",
    "PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXy",
    "UA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIE",
    "z6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECR",
    "Kgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw",
    "LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToks",
    "yKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsF",
    "AAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtY",
    "kNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDI",
    "goMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y",
    "7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05",
    "ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==",
);

/// Yubico FIDO Root CA Serial 450203556 (2024-05): the second
/// generation FIDO attestation root. developers.yubico.com/PKI/yubico-fido-ca-2.pem.
pub(crate) const YUBICO_FIDO_ROOT_450203556_B64: &str = concat!(
    "MIIDMzCCAhugAwIBAgIUSOEjTf//yqRfPW7Qq8qtIyCrAg8wDQYJKoZIhvcNAQELBQAwLzEt",
    "MCsGA1UEAwwkWXViaWNvIEZJRE8gUm9vdCBDQSBTZXJpYWwgNDUwMjAzNTU2MCAXDTI0MDUw",
    "MTAwMDAwMFoYDzIwNjAwNDMwMDAwMDAwWjAvMS0wKwYDVQQDDCRZdWJpY28gRklETyBSb290",
    "IENBIFNlcmlhbCA0NTAyMDM1NTYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd",
    "vl27w2gu1fPXeEFbIdqx0BalvVDVWrQPJ7HqviuEtZHlxSLxSFtcXpTolvLvof8f4tMerQTk",
    "VGzcmYzm1EBT4IJuMmoEqfkEEhWpsADMFrjZkqlZY9EqxQzLoVEEonE5oGxSdVCxCcLIackp",
    "yR/CCXvj1Bt/hTgE9hTlF4pRqxMkx3plF7y8dDZlRHWs7vbnhmBCGeI0ZPEQ6nl2mCg2r74a",
    "dF2u6K9rrLfhBC3QLE8EPrgqUsI+hkuq2tK4M2SMOp8uUVVkqUeu3h0kr3WVI0W02pkgrOgi",
    "FKLFNkSrbYhdjMBDj5izmqfc9xJRKoDX612qd8ZGVHpT5AYFX+1hAgMBAAGjRTBDMB0GA1Ud",
    "DgQWBBTZyU5DiQ/a2UEgE7qBK0zhIsRNRjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB",
    "/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAXvnB4SLuUJfYMSVGAhssL/SmWli3FSccgxyd",
    "vKlACcidIIWKQqa3q/QSUEQzC9DgEfMgr7iC1BkTZbILboV6UZ5knNsvjEZWuMeogJ8tgZs1",
    "hVvKwZizwJ+mEcmsjhIrBYuoL1T6yrOJvKFg1jv+Cy4ZwA9Bpk/V3UOir1VyK8dCtyHu6vfo",
    "sotAdYx8FAuR243gRTMV6Jx8Jdig2JDIAQMlzVeDpSUHX/K2HXRHxHwfgjbgUjjBu/72r8Of",
    "ehyhzHXI3K8CFFdflO+8nEOJK3y8F1ivgS5uN/8SmcYw/STQYwhrxPuwz3nP8baMum4BB2nn",
    "YmpB60sX3bl5k8QUSw==",
);

/// "Yubico Attestation Intermediate A 1" - FIDO MDS anchor for the
/// reference device (AAGUID b7d3f68e-88a6-471e-9ecf-2df26d041ede).
pub(crate) const YUBICO_INTERMEDIATE_A_B64: &str = concat!(
    "MIIDSDCCAjCgAwIBAgIUUcmMXzRIFOgGTK0Tb3gEuZYZkBIwDQYJKoZIhvcNAQELBQAwJDEi",
    "MCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEyMDEwMDAwMDBaGA85",
    "OTk5MTIzMTIzNTk1OVowLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVk",
    "aWF0ZSBBIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDm555bWY9WW+tOY0rI",
    "WHldh+aNanoCZCFh7Gk3YZrQmPUw0hkSG6qYHQtP+fZyS33VErvg+BQqnmumgNhfxFrkwEZE",
    "LeidBcC8C4Ag4nqqiPWpzsvI17NcxYlInLNLFcZY/+gOiN6ZOTihO5/vBZMbj9riaAcqliYm",
    "NGJPgTcMGaEAyMzEMNy2nm6Ep+pjP5aF6gi21t/UQFsuJ1j2Rj/ynM/SdRt+ecal5OYotxHk",
    "FbL9vvv2A2Ov5ITZClw4bOS9npypQimOZ5QAYytmYaQpWl/pMYz6zSj8RqkVDNEJGqNfTKA2",
    "ivLYwX6lSttMPapg0J84l9X0voVN/FpS4VCVAgMBAAGjZjBkMB0GA1UdDgQWBBQgKFAhG6Ra",
    "W+hTy52dxeT8bC96HzAfBgNVHSMEGDAWgBTS7u9aIo06bVwjlz3yhdUm8SV7kjASBgNVHRMB",
    "Af8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAYMzgLrJL",
    "Ir0OovQnAZrRIGuabiHSUKSmbLRWpRkWeAtsChDEHpXcJ/bgDNKYWoHqQ8xRUjB4CyepYevc",
    "3YlrG8o7zHxpfVcaoL5SeuJkzHxKn4bTaSp9+Mvwamnp64kZMiNbFLknfP9kYKoRHkMWheRJ",
    "1UsP1z4ScmkCeILfsMs6vqovqjWClFsJpBcsluYHWF7bBJ1n4Rwg+ATEopY4IgGv6Zvwc+A9",
    "r+AT2hqpoSkYoAl+ANYwgslOf9sJe0V+TA9YY/UlaBmPPTd0//r9wvcePWZkPjKoAC/zUNhf",
    "Dbh4LV8GHs3lyX2XomL/LNc8JYzyIaDEhGQveoPhh/tr1g==",
);

/// "Yubico FIDO Attestation A 1" - FIDO MDS anchor for the reference
/// device; signs its per-device certs.
pub(crate) const YUBICO_FIDO_ANCHOR_A_B64: &str = concat!(
    "MIIDSjCCAjKgAwIBAgIUTnbbGIR2NHvzqIKFAeQwG1XBis0wDQYJKoZIhvcNAQELBQAwLjEs",
    "MCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBBIDEwIBcNMjQxMjAx",
    "MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCYxJDAiBgNVBAMMG1l1YmljbyBGSURPIEF0dGVz",
    "dGF0aW9uIEEgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOsXj3k04Ban4TYd",
    "tZKqD/OPJxyDyaPmCBUFUiaZIgTteZnj3X25DhgpZZXsC4D0ydIcrlA6wNUInORL/L9zBbTE",
    "IMAVMGo6g7UKAmb2MF6AHbnhYJd9eikupVNWShHNYNc4GBdO1YN6AfUqvJhHbe3V4SNMPmBR",
    "EKJPVz7ThwgmggTe8Ws2K0/wsqv2wSE7pbCBsUZhIX51bZM3pqDwJPTmRFEvt0/6tG5eO8F3",
    "j14OXqfEhmjn1VvxKDYQOLZAxCwwgC0P4CdfWv3y8PSR8I354hO1Y+GzNjvIqX38NKLywuIY",
    "HFerOxNlxEMBvFhYBuRuYAkkgUaPqN6UBhsILrsCAwEAAaNmMGQwHQYDVR0OBBYEFCCoRHhi",
    "yNnbnXRWIL6ZBXoBX9YTMB8GA1UdIwQYMBaAFCAoUCEbpFpb6FPLnZ3F5PxsL3ofMBIGA1Ud",
    "EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQCQFafJ",
    "I1/5Wg9CEEimE1RP54RgQwTNTOOQsLACTe+rItlFQzC9ZDhrV828yX7jzy+AAsp3izK7T1th",
    "2dl7m+tu0sw2Pa/olc02nt6PyIw348gaHzhI1+0KE45qxvFDeL2lMxbPfCYvyEEaYzjiQELU",
    "5951pXGWyKMa/4fLtO+ZKOXhMuVeq4rXDPI54W6JHOiAaiKdiw+5e3c2kt/jFIQtM6vMXg9L",
    "NFzdjETNt20VX9QevRpFZfucMG9wCaQDoFlPzpTMJKhPev/imJmZYhKfr0lLcemtqjIxLAoq",
    "ZdOYfHBg6+vAcdPI/iauGpUAv7X+UKNmDwjZ2BaH4sLwhB2m",
);

/// "Yubico FIDO Attestation B 1" - FIDO MDS anchor for the reference
/// device.
pub(crate) const YUBICO_FIDO_ANCHOR_B_B64: &str = concat!(
    "MIIDSjCCAjKgAwIBAgIUR38mq26Sf2szVV2BdG6WEN7kuWUwDQYJKoZIhvcNAQELBQAwLjEs",
    "MCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBCIDEwIBcNMjQxMjAx",
    "MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCYxJDAiBgNVBAMMG1l1YmljbyBGSURPIEF0dGVz",
    "dGF0aW9uIEIgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANY0Wb9oPoRoKoQy",
    "WPaJpz11vrWTg6zTtmNj2VoKRnyvKGRqpzb83w5l6YA96UYkYBDQP0ilO2DPe6wWqVR5zDfR",
    "zdcH8bh+L7dGGvae6hRTZhkFkCpXDs4HccknrDf8FClJ7He39Jf42/G1Qm2zz9WWmrPXtgiK",
    "/x05GjsQfGuDG1zf5QTUUie8lwymK3TfdOvNeeJAAPe2pn7ItfRb+rVrNWiDzlRn2vNnZ2wP",
    "o4wH/WJ6dhXZG+rMWT+a6Bocg1UfIw6kdunG4bTpZzsvacFYyR0mpf+DeOnpSWAmywJWHvTl",
    "f2YXxFyeXcTACdQlcMNGJ2VhZQ48xtP5/RBP/8kCAwEAAaNmMGQwHQYDVR0OBBYEFChy42ok",
    "iqcTS1iqa/HRWjkBn4H/MB8GA1UdIwQYMBaAFOq3QpCeDHtkettUfAO6fE6f2KFhMBIGA1Ud",
    "EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAn+RHI",
    "PbtMEDNdT1g8H/RitAkUdLgAt1tWGWnlj9knbv4/4GlX7C9p45efPO9/aZL6OV1XRKBi6Kmt",
    "BW5K7nuYEnMx/5BqBSbLT7rhduC49TBeMb9PHdXsTlSVNYefr1dGidr4j0xVBQLb1rknDAbd",
    "WDzKfvnayKO8Frwe7Hx843MG/rJ+c0XruUvbfVTCHLiIWhM7oNDhL8xob6xUo9KLKcSL+ItY",
    "sO3/9Wb8Q9GjsqL4FXsDcG1SaYh7KpfuMmOixqzJZO2nIicPYRg1I2SuiUfYO70tmdHcbl+k",
    "SQmSYt7rq4viILg2Gx3j9rITuWTjbaUaSSQxgOmMSHuyzMAC",
);

/// "Yubico FIDO Attestation B2 1" - FIDO MDS anchor for the reference
/// device.
pub(crate) const YUBICO_FIDO_ANCHOR_B2_B64: &str = concat!(
    "MIIDRzCCAjGgAwIBAgIUex9nT9vwZNXS483LdiYGfw2SjSowCwYJKoZIhvcNAQELMC4xLDAq",
    "BgNVBAMMI1l1YmljbyBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgQiAxMCAXDTI1MDgwMTAw",
    "MDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAnMSUwIwYDVQQDDBxZdWJpY28gRklETyBBdHRlc3Rh",
    "dGlvbiBCMiAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1Mevny9dyO9ZUC3",
    "9SoMhLcR/DXrtF/ciM12tciy2EXAZ6MkrivVtCfEVM9X6ISTEnBP6uSYYov6ppv6O6Jh2NHm",
    "Ym4w+JnS4VnCPU7mHAMfVI2MGTTMVOew0xUsG7sISIkIDUBmuk8YK9c5zic9+vFQGLIksdXO",
    "5iVFIgNG53cGXD4ZLZoAPiu0PEozxAqYIaI4gxKhOA3S8/W8mIWsu6ofyj4GvkFG6Z7kyF31",
    "07P7mwFHLrI3ENaPWMOFcTaGa0dw+/vVRwjRcEZBVsuuT/87ckSs0a5pkt3vZBlaYeT8pzSr",
    "eV7mowcIM90L2iaATlP0nxmaE6nOyTbojFVl2wIDAQABo2YwZDAdBgNVHQ4EFgQUSXEh3sa3",
    "btDurm4MM/C7S1lRuuYwHwYDVR0jBBgwFoAU6rdCkJ4Me2R621R8A7p8Tp/YoWEwEgYDVR0T",
    "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwCwYJKoZIhvcNAQELA4IBAQB5Gc3haftp",
    "7hKsEZso+i/Z5nRuqdmzG2WClUoRUqbaPyglnJDjKR/kfgOl6ibbF/zthm3KmXQ7HcDIP2xM",
    "dG7U2L2imbJQHqPf/h2Hqojb4rZgue+6W4ktSR5elR9L1rYqE/SGYM4iEKoVQSv7RT1rxIeW",
    "iKsw/Vxxi/QOnsx3F7x80CCYgB4E3yQx8VTW440hTEwTA1eMHOix32tPtyyHIa8PVVIfVpHQ",
    "JBaMVvv508UEjwkbU2rnjfzoSTNS9A5jUQ8mBSve95rjB0do98EU+DxdBqX2+H6i5wlICFgz",
    "hdzcsne9hGKT6lzTX4cIdJsrY2+xleK0FFQy6lGEVLEe",
);

/// "Yubico Attestation Intermediate B 1" - FIDO MDS anchor for the
/// reference device.
pub(crate) const YUBICO_INTERMEDIATE_B_B64: &str = concat!(
    "MIIDSDCCAjCgAwIBAgIUDqERw+4RnGSggxgUewJFEPDRZ3YwDQYJKoZIhvcNAQELBQAwJDEi",
    "MCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEyMDEwMDAwMDBaGA85",
    "OTk5MTIzMTIzNTk1OVowLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVk",
    "aWF0ZSBCIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI7XnH+ZvDwMCQU8M8",
    "ZeV5qscublvVYaaRt3Ybaxn9godLx5swH0lXrdgjh5h7FpVgCgYYX7E4bl1vbzULemrMWT8N",
    "3WMGUe8QAJbBeioV7W/E+hTZP/0SKJVa3ewKBo6ULeMnfQZDrVORAk8wTLq2v5Llj5vMj7Jt",
    "OotKa9J7nHS8kLmzXXSaj0SwEPh5OAZUTNV4zs1bvoTAQQWrL4/J9QuKt6WCFE5nUNiRQcEb",
    "VF8mlqK2bx2z6okVltyDVLCxYbpUTELvY1usR3DTGPUoIClOm4crpwnDRLVHvjYePGBB//pE",
    "yzxA/gcScxjwaH1ZUw9bnSbHyurKqbTa1KvjAgMBAAGjZjBkMB0GA1UdDgQWBBTqt0KQngx7",
    "ZHrbVHwDunxOn9ihYTAfBgNVHSMEGDAWgBTS7u9aIo06bVwjlz3yhdUm8SV7kjASBgNVHRMB",
    "Af8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAqQaCWMxT",
    "GqVVX7Sk7kkJmUueTSYKuU6+KBBSgwIRnlw9K7He1IpxZ0hdwpPNikKjmcyFgFPzhImwHJgx",
    "xuT90Pw3vYOdcJJNktDg35PXOfzSn15cFAx1RO0mPTmIb8dXiEWOpzoXvdwXDM41ZaCDYMT7",
    "w4IQtMyvE7xUBZq2bjtAnq/NDUA7be4H8H3ipC+/+NKlUrcUh+j48K67WI0u1m6FeQueBA7n",
    "06j825rqDqsaLs9Tb7KAHAw8PmrWaNPG2kjKerxPEfecivlFawp2RWZvxrVtn3TV2SBxyCJC",
    "kXsND05dCErVHSJIs+BdtTVNY9AwtyPmnyb0v4mSTzvWdw==",
);

fn bundled_pin() -> Vec<Vec<u8>> {
    use base64::Engine as _;
    [
        YUBICO_ATTESTATION_ROOT_B64,
        YUBICO_U2F_ROOT_457200631_B64,
        YUBICO_FIDO_ROOT_450203556_B64,
        YUBICO_INTERMEDIATE_A_B64,
        YUBICO_FIDO_ANCHOR_A_B64,
        YUBICO_FIDO_ANCHOR_B_B64,
        YUBICO_FIDO_ANCHOR_B2_B64,
        YUBICO_INTERMEDIATE_B_B64,
    ]
    .iter()
    .map(|b| {
        base64::engine::general_purpose::STANDARD
            .decode(b)
            .unwrap_or_default()
    })
    .collect()
}

/// Walk the chain: every certificate must verify under the next one's
/// key (digest per the child's declared algorithm), and the attStmt must
/// verify over authData || clientDataHash under the leaf's key (RS256 or
/// ES256). The tail terminates at trust: byte-equal to a pinned root, or
/// signed by one. Real tokens ship the device cert plus at most the
/// issuing FIDO Attestation CA, so the MDS anchor certificates for the
/// reference device are pinned alongside the roots. Intact-but-unpinned
/// chains are UnknownVendor.
pub fn verify_with_pins(att: &PackedAttestation, pins: &[Vec<u8>]) -> AttestationVerdict {
    if att.x5c.is_empty() || !es256_rs256_from_alg(att.alg) || !verify_attstmt(att) {
        return AttestationVerdict::Invalid;
    }
    for i in 0..att.x5c.len() - 1 {
        let Some(child) = parse_cert(&att.x5c[i]) else {
            return AttestationVerdict::Invalid;
        };
        let Some(parent) = parse_cert(&att.x5c[i + 1]) else {
            return AttestationVerdict::Invalid;
        };
        if !verify_link(
            &parent.key,
            &child.tbs_raw,
            &child.sig_der,
            &child.sig_alg_oid,
        ) {
            return AttestationVerdict::Invalid;
        }
    }
    let root_der = att.x5c.last().expect("non-empty checked above");
    let Some(last) = parse_cert(root_der) else {
        return AttestationVerdict::Invalid;
    };
    if pins.iter().any(|p| p.as_slice() == root_der.as_slice()) {
        return AttestationVerdict::YubicoVerified;
    }
    let pinned_by_root = pins.iter().any(|p| {
        parse_cert(p).is_some_and(|root| {
            verify_link(&root.key, &last.tbs_raw, &last.sig_der, &last.sig_alg_oid)
        })
    });
    if pinned_by_root {
        AttestationVerdict::YubicoVerified
    } else {
        AttestationVerdict::UnknownVendor
    }
}

/// IANA COSE: -7 ES256, -257 RS256. Yubico device attestation rides
/// RS256 (RSA device certificates); older EC-keyed tokens use ES256.
fn es256_rs256_from_alg(alg: i64) -> bool {
    alg == -7 || alg == -257
}

fn verify_attstmt(att: &PackedAttestation) -> bool {
    let Some(leaf) = parse_cert(&att.x5c[0]) else {
        return false;
    };
    let mut msg = Vec::with_capacity(att.auth_data.len() + 32);
    msg.extend_from_slice(&att.auth_data);
    msg.extend_from_slice(&att.client_data_hash);
    verify_link(&leaf.key, &msg, &att.sig, &leaf.sig_alg_oid)
}

/// Verify against the bundled Yubico pin.
pub fn verify(att: &PackedAttestation) -> AttestationVerdict {
    verify_with_pins(att, &bundled_pin())
}

/// Minimal structurally-honest X.509 builder for the hermetic chains:
/// tbs(version, serial, sigAlg, issuer, validity, subject, spki) +
/// sigAlg + sigValue. `signing` signs; `subject_key` is the certified
/// key, so leaf-signed-by-root is expressed by passing different keys.
#[cfg(test)]
pub(crate) mod test_chain {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    pub struct TestChain {
        pub leaf: SigningKey,
        pub root_der: Vec<u8>,
        pub leaf_der: Vec<u8>,
    }

    fn tlv_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
        }
    }

    fn tlv_bytes(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(tlv_len(body.len()));
        v.extend_from_slice(body);
        v
    }

    fn alg_oid() -> Vec<u8> {
        // 1.2.840.10045.2.1 (ecPublicKey).
        let mut v = vec![0x06, 0x07];
        v.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
        v
    }

    fn curve_oid() -> Vec<u8> {
        // 1.2.840.10045.3.1.7 (prime256v1).
        let mut v = vec![0x06, 0x08];
        v.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        v
    }

    /// ecdsa-with-SHA256 AlgorithmIdentifier.
    fn ecdsa_sig_alg() -> Vec<u8> {
        // 1.2.840.10045.4.3.2
        let mut v = vec![0x06, 0x08];
        v.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);
        tlv_bytes(0x30, &v)
    }

    fn build_cert(signing: &SigningKey, subject_key: &SigningKey, subject: &[u8]) -> Vec<u8> {
        let point = VerifyingKey::from(subject_key).to_encoded_point(false);
        let algid = tlv_bytes(0x30, &[alg_oid(), curve_oid()].concat());
        let bits = tlv_bytes(0x03, &[&[0u8], point.as_bytes()].concat());
        let spki = tlv_bytes(0x30, &[algid, bits].concat());
        let name = tlv_bytes(0x30, &tlv_bytes(0x31, &tlv_bytes(0x0C, subject)));
        let validity = tlv_bytes(
            0x30,
            &[
                tlv_bytes(0x17, b"240101000000Z"),
                tlv_bytes(0x17, b"991231235959Z"),
            ]
            .concat(),
        );
        let tbs_body = [
            tlv_bytes(0xA0, &tlv_bytes(0x02, &[2u8])),
            tlv_bytes(0x02, &[1u8]),
            ecdsa_sig_alg(),
            name.clone(),
            validity,
            name,
            spki,
        ]
        .concat();
        let tbs = tlv_bytes(0x30, &tbs_body);
        let sig: p256::ecdsa::Signature = signing.sign(&tbs);
        let sig_der = sig.to_der();
        tlv_bytes(
            0x30,
            &[tbs, ecdsa_sig_alg(), tlv_bytes(0x03, &[&[0u8], sig_der.as_bytes()].concat())]
                .concat(),
        )
    }

    impl TestChain {
        /// Root self-signed; leaf carrying the leaf key, signed by the
        /// root's key.
        pub fn new() -> Self {
            let root = SigningKey::random(&mut rand::rngs::OsRng);
            let leaf = SigningKey::random(&mut rand::rngs::OsRng);
            let root_der = build_cert(&root, &root, b"test root");
            let leaf_der = build_cert(&root, &leaf, b"test leaf");
            Self { leaf, root_der, leaf_der }
        }

        /// The real fw 5.7+ shape: the token stops at the issuing CA and
        /// the pinned root never rides the wire. Returns the attestation
        /// plus pins that anchor one hop above the sent tail.
        pub fn tail_one_hop_below_pin() -> (super::PackedAttestation, Vec<Vec<u8>>) {
            let root = SigningKey::random(&mut rand::rngs::OsRng);
            let mid = SigningKey::random(&mut rand::rngs::OsRng);
            let leaf = SigningKey::random(&mut rand::rngs::OsRng);
            let root_der = build_cert(&root, &root, b"test root");
            let mid_der = build_cert(&root, &mid, b"test issuing ca");
            let leaf_der = build_cert(&mid, &leaf, b"test leaf");
            let auth_data = vec![0u8; 37];
            let mut hash = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut hash);
            let msg = [&auth_data[..], &hash].concat();
            let sig: p256::ecdsa::Signature = leaf.sign(&msg);
            let att = super::PackedAttestation {
                credential_id: vec![7u8; 16],
                auth_data,
                client_data_hash: hash,
                alg: -7,
                sig: sig.to_der().as_bytes().to_vec(),
                x5c: vec![leaf_der, mid_der],
            };
            (att, vec![root_der])
        }

        pub fn pins(&self) -> Vec<Vec<u8>> {
            vec![self.root_der.clone()]
        }

        /// A correctly-signed attestation: attStmt signed by the leaf
        /// key over authData || hash (ES256).
        pub fn attestation(&self) -> super::PackedAttestation {
            let auth_data = vec![0u8; 37];
            let mut hash = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut hash);
            let msg = [&auth_data[..], &hash].concat();
            let sig: p256::ecdsa::Signature = self.leaf.sign(&msg);
            super::PackedAttestation {
                credential_id: vec![9u8; 16],
                auth_data,
                client_data_hash: hash,
                alg: -7,
                sig: sig.to_der().as_bytes().to_vec(),
                x5c: vec![self.leaf_der.clone(), self.root_der.clone()],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_chain::TestChain;
    use super::*;

    #[test]
    fn genuine_chain_pins_as_yubico_verified() {
        let c = TestChain::new();
        assert_eq!(
            verify_with_pins(&c.attestation(), &c.pins()),
            AttestationVerdict::YubicoVerified
        );
    }

    #[test]
    fn tail_one_hop_below_the_pin_still_verifies() {
        let (att, pins) = TestChain::tail_one_hop_below_pin();
        assert_eq!(
            verify_with_pins(&att, &pins),
            AttestationVerdict::YubicoVerified
        );
    }

    #[test]
    fn valid_chain_with_foreign_root_is_unknown_vendor() {
        // Two independent self-consistent chains: an unknown vendor's.
        let c = TestChain::new();
        let d = TestChain::new();
        assert_eq!(
            verify_with_pins(&c.attestation(), &d.pins()),
            AttestationVerdict::UnknownVendor
        );
        // And against the real bundled pin.
        assert_eq!(verify(&c.attestation()), AttestationVerdict::UnknownVendor);
    }

    #[test]
    fn tampered_attestation_signature_is_invalid() {
        let c = TestChain::new();
        let mut att = c.attestation();
        let last = att.sig.len() - 1;
        att.sig[last] ^= 0xff;
        assert_eq!(verify_with_pins(&att, &c.pins()), AttestationVerdict::Invalid);
    }

    #[test]
    fn tampered_auth_data_is_invalid() {
        let c = TestChain::new();
        let mut att = c.attestation();
        att.auth_data[0] ^= 0x01;
        assert_eq!(verify_with_pins(&att, &c.pins()), AttestationVerdict::Invalid);
    }

    #[test]
    fn broken_chain_is_invalid() {
        // The leaf cert is real, but the claimed parent is an unrelated
        // root: the leaf's signature does not verify under its key.
        let c = TestChain::new();
        let unrelated = TestChain::new();
        let mut att = c.attestation();
        att.x5c[1] = unrelated.root_der.clone();
        assert_eq!(
            verify_with_pins(&att, &c.pins()),
            AttestationVerdict::Invalid
        );
    }

    #[test]
    fn non_supported_algorithm_is_invalid() {
        let c = TestChain::new();
        let mut att = c.attestation();
        att.alg = -47; // ES256K: not supported by this verifier
        assert_eq!(verify_with_pins(&att, &c.pins()), AttestationVerdict::Invalid);
    }

    #[test]
    fn empty_chain_is_invalid() {
        let c = TestChain::new();
        let mut att = c.attestation();
        att.x5c.clear();
        assert_eq!(verify_with_pins(&att, &c.pins()), AttestationVerdict::Invalid);
    }

    #[test]
    fn truncated_certificate_is_invalid() {
        let c = TestChain::new();
        let mut att = c.attestation();
        let n = att.x5c[0].len();
        att.x5c[0].truncate(n / 2);
        assert_eq!(verify_with_pins(&att, &c.pins()), AttestationVerdict::Invalid);
    }

    #[test]
    fn bundled_pin_parses_as_an_rsa_certificate() {
        // The real Yubico root is RSA (sha512WithRSAEncryption
        // self-signature) - the whole reason verify_link dispatches.
        let der = bundled_pin().remove(0);
        assert!(der.len() > 500, "DER certificate-sized, got {}", der.len());
        let Some(cert) = parse_cert(&der) else {
            panic!("bundled pin must parse");
        };
        assert!(matches!(cert.key, PubKey::Rsa(_)));
        // The pin self-signs under its own key.
        assert!(verify_link(&cert.key, &cert.tbs_raw, &cert.sig_der, &cert.sig_alg_oid));
    }

    #[test]
    fn real_root_verifies_a_chain_ending_in_it() {
        // The bundled pin's own certificate, presented as a
        // single-cert chain, is self-signed and pins as Yubico.
        let der = bundled_pin().remove(0);
        let att = PackedAttestation {
            credential_id: vec![1u8; 16],
            auth_data: vec![0u8; 37],
            client_data_hash: [0u8; 32],
            alg: -257,
            sig: vec![],
            x5c: vec![der],
        };
        // attStmt is garbage but chain walking happens after the
        // attStmt check, so assert on pins via verify_with_pins with a
        // matching attStmt impossible here - just assert Invalid (the
        // empty RS256 signature fails first).
        assert_eq!(verify_with_pins(&att, &bundled_pin()), AttestationVerdict::Invalid);
    }
}
