//! Vault slug generation and validation.
//!
//! A slug is a machine-friendly, filesystem-safe, URL-safe identifier for a vault.
//! Used as: repository name on provider, local folder name, registry key, CLI argument.
//!
//! Rules:
//! - Lowercase `a-z0-9` and hyphens only
//! - Must start and end with alphanumeric
//! - 4-63 characters
//! - `baluard-` prefix enforced: normalize_slug() prepends it at every entry
//!   point (users type "personal", the slug becomes "baluard-personal")
//! - Immutable after vault creation

/// Normalize any user-provided slug into the enforced canonical form.
///
/// Enforcement rule: every vault slug and provider repo name carries the
/// `baluard-` prefix. Users type "personal", the stored slug becomes
/// "baluard-personal" - normalization, never rejection.
///
/// Pipeline: clean_slug -> ensure `baluard-` prefix -> enforce_length.
/// Empty input falls back to `baluard-vault`.
pub fn normalize_slug(slug: &str) -> String {
    let (cleaned, _) = clean_slug(slug);
    if cleaned.is_empty() {
        return "baluard-vault".to_string();
    }
    let with_prefix = if cleaned.starts_with("baluard-") {
        cleaned
    } else {
        format!("baluard-{cleaned}")
    };
    enforce_length(&with_prefix)
}

/// Normalize a user-provided name into a suggested slug.
///
/// Alias for [normalize_slug]; kept for call sites that read as
/// "generate a suggestion from a display name".
pub fn suggest_slug(name: &str) -> String {
    normalize_slug(name)
}

/// Validate a slug string against the rules.
///
/// Returns `Ok(())` if valid, `Err` with a human-readable message otherwise.
pub fn validate_slug(slug: &str) -> Result<(), SlugError> {
    if slug.is_empty() {
        return Err(SlugError::Empty);
    }
    if slug.len() < 4 {
        return Err(SlugError::TooShort(slug.len(), 4));
    }
    if slug.len() > 63 {
        return Err(SlugError::TooLong(slug.len(), 63));
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(SlugError::LeadingTrailingHyphen);
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(SlugError::InvalidChars);
    }
    if slug.contains("--") {
        return Err(SlugError::ConsecutiveHyphens);
    }
    Ok(())
}

/// Validate and normalize a user-edited slug.
///
/// Unlike `suggest_slug`, this only applies minimal fixes:
/// - Lowercases
/// - Strips invalid characters
/// - Collapses consecutive hyphens
/// - Strips leading/trailing hyphens
///
/// Returns the cleaned slug and whether it was modified from the input.
pub fn clean_slug(input: &str) -> (String, bool) {
    let lowered = input.to_lowercase();

    let mut chars = Vec::new();
    let mut prev_hyphen = false;
    for ch in lowered.chars() {
        if ch.is_ascii_alphanumeric() {
            chars.push(ch);
            prev_hyphen = false;
        } else if !prev_hyphen {
            chars.push('-');
            prev_hyphen = true;
        }
    }

    // Strip leading/trailing hyphens
    while chars.first() == Some(&'-') {
        chars.remove(0);
    }
    while chars.last() == Some(&'-') {
        chars.pop();
    }

    let result: String = chars.into_iter().collect();
    let modified = result != input;
    (result, modified)
}

fn enforce_length(slug: &str) -> String {
    if slug.len() <= 63 {
        return slug.to_string();
    }

    // Truncate to 63, then strip trailing hyphens
    let truncated: String = slug.chars().take(63).collect();
    let trimmed = truncated.trim_end_matches('-');

    if trimmed.len() < 4 {
        // Extremely unlikely: baluard- prefix alone is 9 chars
        "baluard-vault".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlugError {
    Empty,
    TooShort(usize, usize),
    TooLong(usize, usize),
    LeadingTrailingHyphen,
    InvalidChars,
    ConsecutiveHyphens,
}

impl std::fmt::Display for SlugError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlugError::Empty => write!(f, "Slug cannot be empty"),
            SlugError::TooShort(len, min) => {
                write!(f, "Slug is {len} chars, minimum is {min}")
            }
            SlugError::TooLong(len, max) => {
                write!(f, "Slug is {len} chars, maximum is {max}")
            }
            SlugError::LeadingTrailingHyphen => {
                write!(f, "Slug cannot start or end with a hyphen")
            }
            SlugError::InvalidChars => {
                write!(
                    f,
                    "Slug can only contain lowercase letters, digits, and hyphens"
                )
            }
            SlugError::ConsecutiveHyphens => {
                write!(f, "Slug cannot contain consecutive hyphens")
            }
        }
    }
}

impl std::error::Error for SlugError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_basic() {
        assert_eq!(suggest_slug("Personal"), "baluard-personal");
    }

    #[test]
    fn suggest_multi_word() {
        assert_eq!(suggest_slug("My Work Vault"), "baluard-my-work-vault");
    }

    #[test]
    fn suggest_already_prefixed() {
        assert_eq!(suggest_slug("baluard-work"), "baluard-work");
    }

    #[test]
    fn suggest_special_chars() {
        assert_eq!(suggest_slug("Test@#$Vault!!!"), "baluard-test-vault");
    }

    #[test]
    fn suggest_unicode_stripped() {
        // Unicode chars become hyphens, consecutive collapsed
        let result = suggest_slug("Café Español");
        assert!(result.starts_with("baluard-"));
    }

    #[test]
    fn suggest_long_name_truncated() {
        let long_name = "a".repeat(100);
        let result = suggest_slug(&long_name);
        assert!(result.len() <= 63);
        assert!(validate_slug(&result).is_ok());
    }

    #[test]
    fn suggest_empty_input() {
        assert_eq!(suggest_slug(""), "baluard-vault");
    }

    #[test]
    fn suggest_only_special_chars() {
        assert_eq!(suggest_slug("@#$%"), "baluard-vault");
    }

    #[test]
    fn validate_valid_slugs() {
        assert!(validate_slug("baluard-personal").is_ok());
        assert!(validate_slug("work").is_ok());
        assert!(validate_slug("my-vault-2024").is_ok());
        assert!(validate_slug("a1b2").is_ok());
    }

    #[test]
    fn validate_too_short() {
        assert!(matches!(
            validate_slug("ab"),
            Err(SlugError::TooShort(2, 4))
        ));
        assert!(matches!(
            validate_slug("abc"),
            Err(SlugError::TooShort(3, 4))
        ));
    }

    #[test]
    fn validate_too_long() {
        let long_slug = "a".repeat(64);
        assert!(matches!(
            validate_slug(&long_slug),
            Err(SlugError::TooLong(64, 63))
        ));
    }

    #[test]
    fn validate_leading_trailing_hyphen() {
        assert!(matches!(
            validate_slug("-personal"),
            Err(SlugError::LeadingTrailingHyphen)
        ));
        assert!(matches!(
            validate_slug("personal-"),
            Err(SlugError::LeadingTrailingHyphen)
        ));
    }

    #[test]
    fn validate_invalid_chars() {
        assert!(matches!(
            validate_slug("My_Vault"),
            Err(SlugError::InvalidChars)
        ));
        assert!(matches!(
            validate_slug("vault.name"),
            Err(SlugError::InvalidChars)
        ));
    }

    #[test]
    fn validate_consecutive_hyphens() {
        assert!(matches!(
            validate_slug("my--vault"),
            Err(SlugError::ConsecutiveHyphens)
        ));
    }

    #[test]
    fn clean_preserves_valid_input() {
        let (result, modified) = clean_slug("baluard-personal");
        assert_eq!(result, "baluard-personal");
        assert!(!modified);
    }

    #[test]
    fn clean_lowercases() {
        let (result, modified) = clean_slug("BALUARD-PERSONAL");
        assert_eq!(result, "baluard-personal");
        assert!(modified);
    }

    #[test]
    fn clean_strips_invalid_chars() {
        let (result, modified) = clean_slug("my_vault.name");
        assert_eq!(result, "my-vault-name");
        assert!(modified);
    }

    #[test]
    fn suggest_exactly_at_limit() {
        // "baluard-" is 8 chars. 8 + 55 = 63.
        let slug_63 = format!("baluard-{}", "a".repeat(55));
        assert_eq!(slug_63.len(), 63, "len was {}", slug_63.len());
        assert!(validate_slug(&slug_63).is_ok());
    }

    #[test]
    fn suggest_no_prefix_works() {
        // User removes prefix, still valid
        assert!(validate_slug("work").is_ok());
        assert!(validate_slug("my-vault").is_ok());
    }

    #[test]
    fn normalize_prepends_prefix() {
        // Users type "personal", the slug becomes "baluard-personal".
        assert_eq!(normalize_slug("personal"), "baluard-personal");
        assert_eq!(normalize_slug("My_Work.Vault"), "baluard-my-work-vault");
    }

    #[test]
    fn normalize_keeps_existing_prefix() {
        assert_eq!(normalize_slug("baluard-personal"), "baluard-personal");
    }

    #[test]
    fn normalize_empty_falls_back() {
        assert_eq!(normalize_slug(""), "baluard-vault");
        assert_eq!(normalize_slug("@#$"), "baluard-vault");
    }

    #[test]
    fn normalize_idempotent() {
        assert_eq!(
            normalize_slug(&normalize_slug("personal")),
            normalize_slug("personal")
        );
    }

    #[test]
    fn normalize_output_always_valid() {
        for input in ["personal", "work", "baluard-x", "My Vault 2026"] {
            let slug = normalize_slug(input);
            assert!(validate_slug(&slug).is_ok(), "input {input} -> {slug}");
        }
    }
}

// ── Property-based tests ──

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any input string produces a valid slug via suggest_slug
        #[test]
        fn suggest_always_valid(ref s in "\\PC*") {
            let slug = suggest_slug(s);
            let is_valid = validate_slug(&slug).is_ok();
            prop_assert!(is_valid,
                "slug from input failed validation: slug={}", slug);
        }

        /// Any input string produces a valid slug via clean_slug
        #[test]
        fn clean_always_valid(ref s in "\\PC*") {
            let (cleaned, _) = clean_slug(s);
            if !cleaned.is_empty() && cleaned.len() >= 4 {
                let is_valid = validate_slug(&cleaned).is_ok();
                prop_assert!(is_valid,
                    "cleaned slug failed validation: {}", cleaned);
            }
        }

        /// suggest_slug is idempotent: suggest(suggest(x)) == suggest(x)
        #[test]
        fn suggest_idempotent(ref s in "[a-zA-Z0-9 ]{1,50}") {
            let slug1 = suggest_slug(s);
            let slug2 = suggest_slug(&slug1);
            prop_assert_eq!(slug1, slug2);
        }

        /// Valid slugs survive validate + clean round-trip
        #[test]
        fn valid_slug_clean_identity(ref s in "[a-z0-9]([a-z0-9]-?[a-z0-9]){1,30}[a-z0-9]") {
            let (cleaned, modified) = clean_slug(s);
            prop_assert!(!modified, "valid slug was modified: {}", s);
            prop_assert_eq!(cleaned, s.clone());
        }
    }
}
