//! TOTP code generation (RFC 6238).
//!
//! Parses `otpauth://` URIs, generates time-based one-time passwords.
//! Supports SHA-1, SHA-256, SHA-512 algorithms, 6/8 digit codes, 30/60s periods.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::ZeroizeOnDrop;

/// Parsed TOTP parameters from an `otpauth://` URI.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct TotpParams {
    /// Base32-encoded secret (raw bytes after decoding).
    pub secret: Vec<u8>,
    /// HMAC algorithm. Default: SHA-1.
    pub algorithm: TotpAlgorithm,
    /// Time step in seconds. Default: 30.
    pub period: u64,
    /// Number of digits in the code. Default: 6.
    pub digits: u32,
    /// Optional issuer (extracted from URI).
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, zeroize::Zeroize, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// Parse an `otpauth://totp/` URI into TOTP parameters.
///
/// Format: `otpauth://totp/<label>?secret=<base32>&algorithm=<alg>&digits=<n>&period=<s>&issuer=<name>`
pub fn parse_totp_uri(uri: &str) -> Result<TotpParams, String> {
    if !uri.starts_with("otpauth://totp/") {
        return Err("URI must start with otpauth://totp/".into());
    }

    let query = uri.split('?').nth(1).ok_or("Missing query string")?;
    let mut secret = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut issuer = None;

    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");

        match key {
            "secret" => {
                let bytes = decode_base32(value)?;
                secret = Some(bytes);
            }
            "algorithm" => {
                algorithm = match value.to_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    other => return Err(format!("Unknown algorithm: {other}")),
                };
            }
            "digits" => {
                digits = value
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid digits: {e}"))?;
                if digits != 6 && digits != 8 {
                    return Err(format!("digits must be 6 or 8, got {digits}"));
                }
            }
            "period" => {
                let p = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid period: {e}"))?;
                if p == 0 {
                    return Err("period must be > 0".into());
                }
                period = p;
            }
            "issuer" => {
                issuer = Some(urldecode(value));
            }
            _ => {} // ignore unknown params (e.g. counter, lock)
        }
    }

    let secret = secret.ok_or("Missing required 'secret' parameter")?;

    Ok(TotpParams {
        secret,
        algorithm,
        period,
        digits,
        issuer,
    })
}

/// Generate a TOTP code for the given parameters at the current time.
/// Returns (code, period_seconds, expires_at_timestamp).
pub fn generate_totp(params: &TotpParams) -> (String, u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let counter = now / params.period;
    let expires_at = (counter + 1) * params.period;

    let code = compute_totp(&params.secret, counter, params.algorithm, params.digits);
    (code, params.period, expires_at)
}

/// Generate a TOTP code for a specific counter value (for testing).
pub fn generate_totp_at(params: &TotpParams, timestamp_secs: u64) -> String {
    let counter = timestamp_secs / params.period;
    compute_totp(&params.secret, counter, params.algorithm, params.digits)
}

/// Core TOTP computation: HMAC + dynamic truncation.
fn compute_totp(secret: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();

    let hmac_result = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC key error");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key error");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret).expect("HMAC key error");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226)
    let offset = (hmac_result.last().expect("HMAC digest is never empty") & 0x0F) as usize;
    let binary = ((hmac_result[offset] as u32 & 0x7F) << 24)
        | ((hmac_result[offset + 1] as u32) << 16)
        | ((hmac_result[offset + 2] as u32) << 8)
        | (hmac_result[offset + 3] as u32);

    let otp = binary % (10u32.pow(digits));
    format!("{:0>width$}", otp, width = digits as usize)
}

/// RFC 4648 Base32 decode (case-insensitive, ignores padding).
fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let s: String = input
        .to_uppercase()
        .chars()
        .filter(|c| *c != '=' && *c != ' ')
        .collect();

    if s.is_empty() {
        return Err("Empty base32 secret".into());
    }

    let mut bits = 0u64;
    let mut bit_count = 0u32;
    let mut result = Vec::new();

    for c in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&b| b as char == c)
            .ok_or_else(|| format!("Invalid base32 character: {c}"))? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
        }
    }

    Ok(result)
}

/// Minimal URL percent-decoding.
fn urldecode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let byte = hex_val(hi) << 4 | hex_val(lo);
            result.push(byte as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_totp_uri() {
        let uri = "otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=Test";
        let params = parse_totp_uri(uri).unwrap();
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert_eq!(params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(params.issuer, Some("Test".into()));
        assert!(!params.secret.is_empty());
    }

    #[test]
    fn parse_sha256_uri() {
        let uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60";
        let params = parse_totp_uri(uri).unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 60);
    }

    #[test]
    fn parse_defaults_when_missing_params() {
        let uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP";
        let params = parse_totp_uri(uri).unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert!(params.issuer.is_none());
    }

    #[test]
    fn reject_non_totp_uri() {
        assert!(parse_totp_uri("https://example.com").is_err());
        assert!(parse_totp_uri("otpauth://hotp/Test?secret=AAA").is_err());
    }

    #[test]
    fn reject_missing_secret() {
        assert!(parse_totp_uri("otpauth://totp/Test?digits=6").is_err());
    }

    #[test]
    fn reject_period_zero() {
        let result = parse_totp_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("period must be > 0"),
            "Expected period error, got: {msg}"
        );
    }

    // RFC 6238 test vectors for SHA-1 with secret "12345678901234567890"
    // Secret base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    #[test]
    fn rfc6238_sha1_test_vector() {
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let secret = decode_base32(secret_b32).unwrap();
        // The secret should be "12345678901234567890" as ASCII
        assert_eq!(String::from_utf8_lossy(&secret), "12345678901234567890");

        let params = TotpParams {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            period: 30,
            digits: 8,
            issuer: None,
        };

        // RFC 6238 test vectors (SHA1, 8 digits)
        let test_cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1234567890, "89005924"),
        ];

        for (timestamp, expected) in test_cases {
            let code = generate_totp_at(&params, timestamp);
            assert_eq!(code, expected, "SHA1 TOTP at t={timestamp}");
        }
    }

    #[test]
    fn sha256_generates_correctly() {
        // RFC 6238 SHA256 uses 32-byte key: "12345678901234567890123456789012"
        let params = TotpParams {
            secret: b"12345678901234567890123456789012".to_vec(),
            algorithm: TotpAlgorithm::Sha256,
            period: 30,
            digits: 8,
            issuer: None,
        };
        let code = generate_totp_at(&params, 59);
        assert_eq!(code.len(), 8);
        assert_eq!(code, "46119246");
    }

    #[test]
    fn sha512_generates_correctly() {
        // RFC 6238 SHA512 uses 64-byte key
        let params = TotpParams {
            secret: b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            algorithm: TotpAlgorithm::Sha512,
            period: 30,
            digits: 8,
            issuer: None,
        };
        let code = generate_totp_at(&params, 59);
        assert_eq!(code.len(), 8);
        // RFC 6238 SHA512 at t=59: "90693936"
        assert_eq!(code, "90693936");
    }

    #[test]
    fn sha256_at_larger_timestamp() {
        // RFC 6238 SHA256 at t=1111111109: "68084774"
        let params = TotpParams {
            secret: b"12345678901234567890123456789012".to_vec(),
            algorithm: TotpAlgorithm::Sha256,
            period: 30,
            digits: 8,
            issuer: None,
        };
        let code = generate_totp_at(&params, 1111111109);
        assert_eq!(code, "68084774");
    }

    #[test]
    fn sha512_at_larger_timestamp() {
        // RFC 6238 SHA512 at t=1111111109: "25091201"
        let params = TotpParams {
            secret: b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            algorithm: TotpAlgorithm::Sha512,
            period: 30,
            digits: 8,
            issuer: None,
        };
        let code = generate_totp_at(&params, 1111111109);
        assert_eq!(code, "25091201");
    }

    #[test]
    fn six_digit_code() {
        let params = TotpParams {
            secret: decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            algorithm: TotpAlgorithm::Sha1,
            period: 30,
            digits: 6,
            issuer: None,
        };
        let code = generate_totp_at(&params, 0);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn period_60_uses_60_second_window() {
        let params = TotpParams {
            secret: decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            algorithm: TotpAlgorithm::Sha1,
            period: 60,
            digits: 6,
            issuer: None,
        };
        // Same code for t=0 and t=59 (same 60s window)
        assert_eq!(generate_totp_at(&params, 0), generate_totp_at(&params, 59));
        // Different code at t=60 (next window)
        assert_ne!(generate_totp_at(&params, 0), generate_totp_at(&params, 60));
    }

    #[test]
    fn generate_totp_returns_valid_metadata() {
        let params = TotpParams {
            secret: decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            algorithm: TotpAlgorithm::Sha1,
            period: 30,
            digits: 6,
            issuer: None,
        };
        let (code, period, expires_at) = generate_totp(&params);
        assert_eq!(code.len(), 6);
        assert_eq!(period, 30);
        assert!(expires_at > 0);
    }

    #[test]
    fn base32_decode_rfc_test_vector() {
        assert_eq!(decode_base32("MZXW6===").unwrap(), b"foo");
        // Verify the RFC 6238 SHA1 test secret decodes correctly
        let secret = decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(secret.len(), 20);
        assert_eq!(String::from_utf8_lossy(&secret), "12345678901234567890");
    }
}
