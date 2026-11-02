//! X.509 certificate metadata for signing-key entries (D81).
//!
//! Reads only the fields a password manager displays: subject, issuer,
//! validity, and the SHA-256 fingerprint of the DER bytes. Signatures are
//! NOT verified here — this is metadata extraction for display and expiry
//! badges, not chain-of-trust evaluation.
//!
//! The DER walk reuses the total TLV reader from the attestation verifier:
//! checked lengths and bounds, hostile input fails to `None`, never panics.

use crate::hwkey::attest::tlv;
use sha2::{Digest, Sha256};

/// Per-certificate input cap. Real certificates are a few KB; anything
/// larger is hostile or corrupt.
pub const MAX_PEM_LEN: usize = 64_000;
/// Chain cap for one signing-key entry.
pub const MAX_CHAIN_LEN: usize = 16;

/// The displayable metadata of one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertInfo {
    pub subject: String,
    pub issuer: String,
    /// Unix seconds. `None` when the time string is malformed.
    pub not_before: Option<u64>,
    pub not_after: u64,
    /// Lowercase hex SHA-256 over the full DER bytes.
    pub fingerprint_sha256: String,
}

/// Extract the first `CERTIFICATE` PEM body as DER. Accepts surrounding
/// text, skips the rest, and caps the input.
pub fn pem_certificate_der(input: &str) -> Option<Vec<u8>> {
    if input.len() > MAX_PEM_LEN {
        return None;
    }
    let start = input.find("-----BEGIN CERTIFICATE-----")?;
    let rest = &input[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = rest.find("-----END CERTIFICATE-----")?;
    let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    const_engine_decode(b64.as_bytes())
}

fn const_engine_decode(b64: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Parse one DER `Certificate` for display metadata.
pub fn parse_certificate_der(der: &[u8]) -> Option<IssuedCertInfo> {
    let cert = tlv(der)?;
    if cert.tag != 0x30 {
        return None;
    }
    if !cert.rest.is_empty() {
        // Fingerprint parity with the attestation verifier: the hash covers
        // exactly one certificate, never trailing bytes.
        return None;
    }
    let tbs = tlv(cert.body)?;
    if tbs.tag != 0x30 {
        return None;
    }

    // tbsCertificate ::= SEQUENCE { version [0] EXPLICIT INTEGER OPTIONAL,
    // serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name,
    // validity Validity, subject Name, subjectPublicKeyInfo, ... }
    let mut cur = tbs.body;
    if let Some(v) = tlv(cur) {
        if v.tag == 0xA0 {
            cur = v.rest;
        }
    }
    let _serial = tlv(cur)?;
    let sig_alg = tlv(_serial.rest)?;
    let issuer = tlv(sig_alg.rest)?;
    let validity = tlv(issuer.rest)?;
    let subject = tlv(validity.rest)?;
    if validity.tag != 0x30 || issuer.tag != 0x30 || subject.tag != 0x30 {
        return None;
    }

    let nb = tlv(validity.body)?;
    let na = tlv(nb.rest)?;
    let not_before = time_to_unix(nb.tag, nb.body);
    let not_after = time_to_unix(na.tag, na.body)?;

    Some(IssuedCertInfo {
        subject: render_name(subject.body),
        issuer: render_name(issuer.body),
        not_before,
        not_after,
        fingerprint_sha256: hex(&Sha256::digest(der)),
    })
}

/// Parse a leaf-first chain of PEM certificates. Entries that do not parse
/// are skipped; the badge only needs the survivors.
pub fn parse_certificate_chain(pems: &[String]) -> Vec<IssuedCertInfo> {
    pems.iter()
        .take(MAX_CHAIN_LEN)
        .filter_map(|p| {
            let der = pem_certificate_der(p)?;
            parse_certificate_der(&der)
        })
        .collect()
}

/// Earliest `not_after` across a parsed chain, for the expiry badge.
pub fn earliest_expiry(chain: &[IssuedCertInfo]) -> Option<u64> {
    chain.iter().map(|c| c.not_after).min()
}

/// RFC 5280 Name: a SEQUENCE OF RDN (SET OF AttributeTypeAndValue),
/// rendered "CN=x, O=y" in certificate order.
fn render_name(mut buf: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    while let Some(rdn) = tlv(buf) {
        if rdn.tag != 0x31 {
            break;
        }
        if let Some(atv) = tlv(rdn.body) {
            if let (Some(oid), Some(value)) =
                (tlv(atv.body), tlv(atv.body).and_then(|o| tlv(o.rest)))
            {
                if let Some(label) = oid_label(oid.body) {
                    parts.push(format!("{label}={}", printable(value.tag, value.body)));
                }
            }
        }
        buf = rdn.rest;
    }
    parts.join(", ")
}

/// The common attribute OIDs a password manager shows; anything else is
/// skipped rather than rendered with dotted numbers.
fn oid_label(der_oid: &[u8]) -> Option<&'static str> {
    match der_oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x07] => Some("L"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x0A] => Some("O"),
        [0x55, 0x04, 0x0B] => Some("OU"),
        [0x55, 0x04, 0x05] => Some("serialNumber"),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => Some("emailAddress"),
        _ => None,
    }
}

fn printable(tag: u8, body: &[u8]) -> String {
    let decoded = match tag {
        0x0C | 0x13 | 0x16 => String::from_utf8_lossy(body).into_owned(),
        0x1E => body
            .chunks_exact(2)
            .map(|p| char::from_u32(u16::from_be_bytes([p[0], p[1]]) as u32).unwrap_or('\u{FFFD}'))
            .collect(),
        _ => String::new(),
    };
    // Display hygiene only: control characters and bidi/zero-width marks
    // cannot survive into copied DNs. Separator characters ("," "=") stay,
    // so a hostile CN can shape its own display line — this is metadata for
    // humans, not an authorization identity.
    decoded
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{FFFD}' && !is_bidi_or_zero_width(*c))
        .collect()
}

fn is_bidi_or_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

/// UTCTime ("YYMMDDHHMMSSZ", RFC 5280: YY < 50 is 20YY) and GeneralizedTime
/// ("YYYYMMDDHHMMSSZ"). Only the exact Z-terminated seconds form parses;
/// offset forms are refused rather than guessed.
fn time_to_unix(tag: u8, body: &[u8]) -> Option<u64> {
    if !matches!(tag, 0x17 | 0x18) {
        return None;
    }
    if !body.iter().all(|b| b.is_ascii_digit() || *b == b'Z') {
        return None;
    }
    let (year, rest) = match body.len() {
        13 if body.ends_with(b"Z") => {
            let yy: u64 = std::str::from_utf8(&body[..2]).ok()?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &body[2..])
        }
        15 if body.ends_with(b"Z") => {
            let yyyy: u64 = std::str::from_utf8(&body[..4]).ok()?.parse().ok()?;
            (yyyy, &body[4..])
        }
        _ => return None,
    };
    let num = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<u64>().ok();
    let month = num(&rest[0..2])?;
    let day = num(&rest[2..4])?;
    let hour = num(&rest[4..6])?;
    let minute = num(&rest[6..8])?;
    let second = num(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Pre-1970 dates have no unix representation; casting a negative day
    // count used to wrap into a huge "valid forever" expiry.
    let days = days_from_civil(year as i64, month, day);
    if days < 0 {
        return None;
    }
    let day_secs = (days as i64).checked_mul(86_400)?;
    let secs = day_secs.checked_add((hour * 3600 + minute * 60 + second) as i64)?;
    u64::try_from(secs).ok()
}

/// Format unix seconds as "YYYY-MM-DD" (UTC) for entry display. Out-of-range
/// seconds render as the raw number rather than a wrong date.
pub fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    if !(1..=9999).contains(&y) {
        return format!("{secs}");
    }
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    if hh == 0 && mm == 0 && ss == 0 {
        format!("{y:04}-{m:02}-{d:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
    }
}

/// Days since 1970-01-01 (Howard Hinnant's civil-from-days inverse).
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp as u64 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe as i64 - 719_468
}

/// Inverse of `days_from_civil` (Howard Hinnant's civil-from-days).
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hand-built minimal v3 certificate fixtures shared by handle-layer
/// tests. Every field the parser reads is present; nothing is real crypto.
#[cfg(test)]
pub(crate) mod fixture {
    use super::test_der::{alg, der, name, time, tlv_bytes};

    pub fn pem_certificate(not_before: &str, not_after: &str, cn: &str) -> String {
        use base64::Engine as _;
        let der =
            fixture_certificate_der(not_before.as_bytes(), not_after.as_bytes(), cn.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----")
    }

    pub fn fixture_certificate_der(not_before: &[u8], not_after: &[u8], cn: &[u8]) -> Vec<u8> {
        let version = tlv_bytes(0xA0, &tlv_bytes(0x02, &[2]));
        let serial = tlv_bytes(0x02, &[1]);
        let issuer = name(b"Test CA");
        let validity = der(&[time(0x17, not_before), time(0x17, not_after)].concat());
        let subject = name(cn);
        let spki_der = der(&[alg(), tlv_bytes(0x03, &[0x00, 1, 2, 3])].concat());
        let tbs = der(&[version, serial, alg(), issuer, validity, subject, spki_der].concat());
        der(&[tbs, alg(), tlv_bytes(0x03, &[0x00, 9, 9])].concat())
    }
}

/// DER wire helpers shared by the fixture module and the parser tests.
#[cfg(test)]
pub(crate) mod test_der {
    /// DER SEQUENCE wrapper.
    pub fn der(seq_body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        push_len(&mut out, seq_body.len());
        out.extend_from_slice(seq_body);
        out
    }

    pub fn push_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(bytes.len() - 1);
            let n = bytes.len() - first;
            out.push(0x80 | n as u8);
            out.extend_from_slice(&bytes[first..]);
        }
    }

    pub fn tlv_bytes(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        push_len(&mut out, body.len());
        out.extend_from_slice(body);
        out
    }

    pub fn name(cn: &[u8]) -> Vec<u8> {
        // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, value } } }
        let oid = tlv_bytes(0x06, &[0x55, 0x04, 0x03]);
        let value = tlv_bytes(0x0C, cn);
        let atv = der(&[oid, value].concat());
        let set = tlv_bytes(0x31, &atv);
        der(&set)
    }

    pub fn alg() -> Vec<u8> {
        // SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
        let oid = tlv_bytes(
            0x06,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
        );
        let nul = tlv_bytes(0x05, &[]);
        der(&[oid, nul].concat())
    }

    pub fn time(tag: u8, ascii: &[u8]) -> Vec<u8> {
        tlv_bytes(tag, ascii)
    }
}

#[cfg(test)]
mod tests {
    use super::test_der::{alg, der, name, time, tlv_bytes};
    use super::*;

    fn utc(s: &str) -> Vec<u8> {
        time(0x17, s.as_bytes())
    }

    fn fixture_cert(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        fixture::fixture_certificate_der(not_before, not_after, b"leaf.example")
    }

    #[test]
    fn fixture_parses_subject_issuer_validity_and_fingerprint() {
        let der = fixture_cert(b"260101000000Z", b"300101000000Z");
        let info = parse_certificate_der(&der).expect("the fixture must parse");
        assert_eq!(info.subject, "CN=leaf.example");
        assert_eq!(info.issuer, "CN=Test CA");
        assert_eq!(info.not_before, Some(1_767_225_600)); // 2026-01-01
        assert_eq!(info.not_after, 1_893_456_000); // 2030-01-01
        assert_eq!(info.fingerprint_sha256.len(), 64);
        let again = parse_certificate_der(&der).unwrap();
        assert_eq!(info, again, "the fingerprint is deterministic");
    }

    #[test]
    fn generalized_time_and_fifty_rule_parse() {
        let der = fixture_cert(b"250601120000Z", b"20501231235959Z");
        let info = parse_certificate_der(&der).unwrap();
        assert_eq!(info.not_before, Some(1_748_779_200)); // 2025-06-01T12:00Z
        // UTCTime 50 maps to 2050 per RFC 5280.
        assert_eq!(info.not_after, 2_556_143_999); // 2050-12-31T23:59:59Z
    }

    #[test]
    fn pem_body_extracts_and_caps() {
        let der = fixture_cert(b"260101000000Z", b"300101000000Z");
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!(
            "noise before\n-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\nnoise after"
        );
        let parsed = pem_certificate_der(&pem).unwrap();
        assert_eq!(parsed, der);

        let chain = parse_certificate_chain(&[pem]);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].not_after, 1_893_456_000);
        assert_eq!(earliest_expiry(&chain), Some(1_893_456_000));

        assert!(pem_certificate_der(&"x".repeat(MAX_PEM_LEN + 1)).is_none());
        assert!(pem_certificate_der("no pem here").is_none());
        assert!(parse_certificate_chain(&["garbage".into()]).is_empty());
    }

    #[test]
    fn malformed_time_strings_are_refused_not_guessed() {
        // Offset time form, wrong lengths, out-of-range values.
        let bad_times: [&[u8]; 4] = [
            b"260101000000+0100",
            b"2601",
            b"991301000000Z", // month 13
            b"260101250000Z", // hour 25
        ];
        for bad in bad_times {
            let der = fixture_cert(bad, b"300101000000Z");
            let info = parse_certificate_der(&der).unwrap();
            assert_eq!(info.not_before, None, "bad time must be None: {bad:?}");
        }
    }

    #[test]
    fn pre_1970_dates_refuse_instead_of_wrapping() {
        // UTCTime 59 is 2059 (fine); a year before 1970 must refuse rather
        // than wrap into a huge "valid forever" expiry.
        // notBefore unparseable → None, and notAfter unparseable → the
        // whole parse fails (bad validity is not a displayable cert).
        let der = fixture_cert(b"010101000000Z", b"690101000000Z");
        assert!(parse_certificate_der(&der).is_none());
        // UTCTime maps 50-99 into 19xx, so its newest year is 49 = 2049.
        let der = fixture_cert(b"260101000000Z", b"491231235959Z");
        let info = parse_certificate_der(&der).unwrap();
        assert_eq!(info.not_after, 2_524_607_999); // 2049-12-31T23:59:59Z
    }

    #[test]
    fn trailing_bytes_refuse_so_the_fingerprint_covers_one_certificate() {
        let der = fixture_cert(b"260101000000Z", b"300101000000Z");
        let mut padded = der.clone();
        padded.extend_from_slice(b"junk");
        assert!(parse_certificate_der(&padded).is_none());
        assert!(parse_certificate_der(&der).is_some());
    }

    #[test]
    fn time_tags_are_strict() {
        // A PrintableString (0x13) of the right length is not a time.
        let version = test_der::tlv_bytes(0xA0, &test_der::tlv_bytes(0x02, &[2]));
        let serial = test_der::tlv_bytes(0x02, &[1]);
        let issuer = name(b"Test CA");
        let validity =
            der(&[utc("260101000000Z"), test_der::time(0x13, b"300101000000Z")].concat());
        let subject = name(b"leaf.example");
        let spki_der = der(&[alg(), test_der::tlv_bytes(0x03, &[0x00, 1, 2, 3])].concat());
        let tbs = der(&[version, serial, alg(), issuer, validity, subject, spki_der].concat());
        let cert = der(&[tbs, alg(), test_der::tlv_bytes(0x03, &[0x00, 9, 9])].concat());
        assert!(
            parse_certificate_der(&cert).is_none(),
            "a non-time tag is not a time; bad validity refuses the cert"
        );
    }

    #[test]
    fn unix_dates_format_as_utc() {
        assert_eq!(format_unix_utc(0), "1970-01-01");
        assert_eq!(format_unix_utc(1_893_456_000), "2030-01-01");
        assert_eq!(format_unix_utc(1_893_455_999), "2029-12-31 23:59:59");
        // Far-future values fall back to the number, never a wrong date.
        assert_eq!(format_unix_utc(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn hostile_truncations_fail_to_none() {
        let der = fixture_cert(b"260101000000Z", b"300101000000Z");
        for cut in [0, 1, 2, 3, 5, 8, 13, 21, 34, der.len() / 2] {
            assert!(parse_certificate_der(&der[..cut]).is_none(), "cut at {cut}");
        }
        // Random tags in place of SEQUENCEs fail closed.
        let mut mangled = der.clone();
        mangled[0] = 0x05;
        assert!(parse_certificate_der(&mangled).is_none());
    }

    #[test]
    fn control_characters_never_forgive_dn_injection() {
        // A CN carrying a newline would forge a second RDN line in copy.
        let oid = tlv_bytes(0x06, &[0x55, 0x04, 0x03]);
        let evil = tlv_bytes(0x0C, b"evil\nCN=injected");
        let atv = der(&[oid, evil].concat());
        let set = tlv_bytes(0x31, &atv);
        let issuer = der(&set);
        let validity = der(&[utc("260101000000Z"), utc("300101000000Z")].concat());
        let subject = name(b"leaf.example");
        let spki_der = der(&[alg(), tlv_bytes(0x03, &[0x00, 1])].concat());
        let tbs = der(&[
            tlv_bytes(0x02, &[1]),
            alg(),
            issuer,
            validity,
            subject,
            spki_der,
        ]
        .concat());
        let cert = der(&[tbs, alg(), tlv_bytes(0x03, &[0x00, 9])].concat());
        let info = parse_certificate_der(&cert).unwrap();
        assert_eq!(info.issuer, "CN=evilCN=injected");
        assert!(!info.issuer.contains('\n'));
    }
}
