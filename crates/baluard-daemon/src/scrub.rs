//! D80 output scrubbing for agent child processes. This is accident
//! containment, not a secrecy boundary: a hostile child can transform or
//! exfiltrate its own environment in ways no scrubber can recognize.

use base64::Engine;
use zeroize::Zeroizing;

pub const REDACTED: &str = "[REDACTED]";

/// Replaces exact and common transport-encoded forms of every injected
/// secret. The caller scrubs complete captured streams, so a secret split
/// across pipe reads cannot slip through a chunk boundary.
pub fn scrub_output(input: &[u8], secrets: &[Zeroizing<String>]) -> String {
    let mut out = String::from_utf8_lossy(input).into_owned();
    for secret in secrets {
        if secret.len() < 4 {
            continue;
        }
        let mut forms = vec![
            secret.to_string(),
            base64::engine::general_purpose::STANDARD.encode(secret.as_bytes()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.as_bytes()),
            percent_encode(secret),
            percent_encode_lower(secret),
            json_escape(secret),
        ];
        // Replace longer forms first so overlapping encodings cannot leave a
        // recognizable suffix behind.
        forms.sort_by_key(|form| std::cmp::Reverse(form.len()));
        forms.dedup();
        for form in forms {
            if !form.is_empty() {
                out = out.replace(&form, REDACTED);
            }
        }
    }
    out
}

fn percent_encode(value: &str) -> String {
    percent_encode_case(value, true)
}

fn percent_encode_lower(value: &str) -> String {
    percent_encode_case(value, false)
}

fn percent_encode_case(value: &str, uppercase: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else if uppercase {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

fn json_escape(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(&quoted)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_string())
    }

    #[test]
    fn exact_secrets_are_redacted_from_both_streams() {
        let secrets = vec![secret("s3cret-value")];
        assert_eq!(
            scrub_output(b"token=s3cret-value\n", &secrets),
            "token=[REDACTED]\n"
        );
        assert_eq!(
            scrub_output(b"s3cret-value s3cret-value", &secrets),
            "[REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn base64_url_and_json_forms_are_redacted() {
        let value = "p@ss/word\nline";
        let secrets = vec![secret(value)];
        let encoded = format!(
            "{} {} {} {}",
            base64::engine::general_purpose::STANDARD.encode(value),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value),
            percent_encode(value),
            json_escape(value),
        );
        let scrubbed = scrub_output(encoded.as_bytes(), &secrets);
        assert!(!scrubbed.contains("p@ss"));
        assert!(!scrubbed.contains("cEBzcy"));
        assert!(!scrubbed.contains("line"));
        assert_eq!(scrubbed.matches(REDACTED).count(), 4);
    }

    #[test]
    fn secrets_split_across_input_chunks_are_still_redacted() {
        // The route captures the whole stream before calling this function;
        // these two chunks model a secret crossing an OS pipe read boundary.
        let chunks = [b"prefix s3cr".as_slice(), b"et-value suffix".as_slice()];
        let complete = chunks.concat();
        assert_eq!(
            scrub_output(&complete, &[secret("s3cret-value")]),
            "prefix [REDACTED] suffix"
        );
    }

    #[test]
    fn lowercase_percent_encoding_is_redacted_without_lowercasing_plain_letters() {
        let secrets = vec![secret("Ab/CD")];
        assert_eq!(scrub_output(b"Ab%2fCD", &secrets), REDACTED);
        assert_eq!(scrub_output(b"ab%2fcd", &secrets), "ab%2fcd");
    }

    #[test]
    fn short_secrets_do_not_destroy_unrelated_output() {
        assert_eq!(
            scrub_output(b"a normal log line", &[secret("ab")]),
            "a normal log line"
        );
    }

    #[test]
    fn invalid_utf8_is_lossy_without_panicking() {
        let out = scrub_output(&[0xff, b'x', 0xfe], &[]);
        assert!(out.contains('x'));
    }
}
