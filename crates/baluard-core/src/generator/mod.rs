//! Password + passphrase generator.
//!
//! Single source of truth for credential generation, consumed by the desktop
//! (via a daemon route, future migration from its current JS impl) and mobile
//! (via `baluard-uniffi`). Ported from `desktop/src/lib/utils.js` 2026-07-23
//! (Phase 4 prerequisite — plan §3.3 listed `mobile_generate_password` /
//! `mobile_generate_passphrase` assuming a Rust impl existed; it didn't).
//!
//! ## Randomness
//!
//! All selection uses [`rand::rngs::OsRng`] (CSPRNG), the Rust equivalent of
//! the desktop's `crypto.getRandomValues`. **One deliberate divergence from
//! the JS port:** the desktop picks indices via `uint32 % pool.len()`
//! (modulo bias, negligible for these pool sizes but present). This impl uses
//! [`rand::Rng::gen_range`] which is unbiased. The output distribution is what
//! matters; bit-exact parity with the biased JS algorithm is not a goal.
//!
//! ## Wordlists
//!
//! Passphrase pool = merged EFF EN (EFF large 7,776 ∪ EFF short 1,296,
//! 8,232 unique words, CC-BY-3.0) + BIP-39 Spanish (2,048 words, MIT).
//! Embedded via `include_str!` from `data/` so the crate is self-contained;
//! the desktop imports the same two .txt files (`?raw`), making these the
//! single wordlist sources for every platform.

use rand::Rng;
use rand::rngs::OsRng;

/// Merged EFF English wordlist (large ∪ short, deduplicated, sorted).
/// Sources: eff.org/files/2016/07/25/eff_large_wordlist.txt + eff_short_wordlist_2_0.txt (CC-BY-3.0)
const EFF_EN: &str = include_str!("data/eff-en.txt");
/// BIP-39 Spanish (diacritics stripped). Source: github.com/bitcoin/bips bip-0039/spanish.txt
const BIP39_ES: &str = include_str!("data/bip39-es.txt");

/// Character pools for password generation (mirrors desktop `utils.js`).
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
/// Symbols available for passphrase insertion (mirrors desktop; a deliberately
/// smaller, shell-safe subset than the password `SYMBOLS` pool).
const PASSPHRASE_SYMBOLS: &str = "!@#$%&*+?";

/// Options for [`generate_password`].
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    /// Length of the generated password. Must be >= 1.
    pub length: usize,
    /// Include uppercase letters (A-Z).
    pub upper: bool,
    /// Include digits (0-9).
    pub numbers: bool,
    /// Include symbols (see [`SYMBOLS`]).
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        // Mirrors desktop defaults: length 16, upper + numbers + symbols on.
        Self {
            length: 16,
            upper: true,
            numbers: true,
            symbols: true,
        }
    }
}

/// Options for [`generate_passphrase`].
#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    /// Number of words to draw. Must be >= 1.
    pub word_count: usize,
    /// Separator inserted between words (e.g. "-", "_", "."). Empty allowed.
    pub separator: String,
    /// Capitalize one randomly-chosen word's first letter.
    pub upper: bool,
    /// Insert a random 0-99 number at a random position.
    pub number: bool,
    /// Insert a random symbol from [`PASSPHRASE_SYMBOLS`] at a random position.
    pub symbol: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        // Mirrors desktop defaults: 5 words, "-" separator, no transforms.
        Self {
            word_count: 5,
            separator: "-".to_string(),
            upper: false,
            number: false,
            symbol: false,
        }
    }
}

/// Generate a random password from the configured character pools.
///
/// At least one pool must be selected (lowercase is always included; if all of
/// `upper`/`numbers`/`symbols` are false, the pool is lowercase-only).
pub fn generate_password(opts: &PasswordOptions) -> Result<String, GenerateError> {
    if opts.length == 0 {
        return Err(GenerateError::InvalidLength);
    }
    let mut pool = String::from(LOWERCASE);
    if opts.upper {
        pool.push_str(UPPERCASE);
    }
    if opts.numbers {
        pool.push_str(NUMBERS);
    }
    if opts.symbols {
        pool.push_str(SYMBOLS);
    }
    let chars: Vec<char> = pool.chars().collect();
    let mut rng = OsRng;
    let mut out = String::with_capacity(opts.length);
    for _ in 0..opts.length {
        // gen_range is unbiased (unlike the desktop's `uint32 % len`).
        let c = chars[rng.gen_range(0..chars.len())];
        out.push(c);
    }
    Ok(out)
}

/// Generate a random passphrase from the combined EFF-EN + BIP-39-ES wordlist,
/// optionally applying capitalize / insert-number / insert-symbol transforms.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<String, GenerateError> {
    if opts.word_count == 0 {
        return Err(GenerateError::InvalidWordCount);
    }
    let pool: Vec<&str> = EFF_EN
        .lines()
        .chain(BIP39_ES.lines())
        .filter(|l| !l.is_empty())
        .collect();
    let mut rng = OsRng;
    let mut words: Vec<String> = (0..opts.word_count)
        .map(|_| pool[rng.gen_range(0..pool.len())].to_string())
        .collect();

    let mut result = words.join(&opts.separator);

    if opts.upper && !words.is_empty() {
        let idx = rng.gen_range(0..words.len());
        let w = words[idx].clone();
        let mut upcased = w.chars();
        if let Some(first) = upcased.next() {
            words[idx] = first.to_uppercase().chain(upcased).collect();
        }
        result = words.join(&opts.separator);
    }
    if opts.number {
        let n: u32 = rng.gen_range(0..100);
        let pos = rng.gen_range(0..=result.len()); // insert at 0..=len ( inclusive, mirrors JS slice(0, idx) )
        let (head, tail) = result.split_at(pos);
        result = format!("{head}{n}{tail}");
    }
    if opts.symbol {
        let syms: Vec<char> = PASSPHRASE_SYMBOLS.chars().collect();
        let s = syms[rng.gen_range(0..syms.len())];
        let pos = rng.gen_range(0..=result.len());
        let (head, tail) = result.split_at(pos);
        result = format!("{head}{s}{tail}");
    }
    Ok(result)
}

/// Generator errors.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("length must be >= 1")]
    InvalidLength,
    #[error("word_count must be >= 1")]
    InvalidWordCount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_default_length_and_charset() {
        let p = generate_password(&PasswordOptions::default()).unwrap();
        assert_eq!(p.len(), 16, "default length");
        assert!(p.is_ascii(), "ascii only");
    }

    #[test]
    fn password_lowercase_only_respects_flags() {
        let opts = PasswordOptions {
            length: 200,
            upper: false,
            numbers: false,
            symbols: false,
        };
        let p = generate_password(&opts).unwrap();
        assert!(
            p.chars().all(|c| c.is_ascii_lowercase()),
            "lowercase-only pool"
        );
    }

    #[test]
    fn password_includes_each_enabled_class() {
        // With a long-enough sample, every enabled class should appear.
        let opts = PasswordOptions {
            length: 500,
            upper: true,
            numbers: true,
            symbols: true,
        };
        let p = generate_password(&opts).unwrap();
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn password_zero_length_errors() {
        assert!(matches!(
            generate_password(&PasswordOptions {
                length: 0,
                upper: true,
                numbers: true,
                symbols: true
            }),
            Err(GenerateError::InvalidLength)
        ));
    }

    #[test]
    fn passphrase_word_count() {
        let opts = PassphraseOptions {
            word_count: 7,
            separator: "-".into(),
            ..Default::default()
        };
        let pp = generate_passphrase(&opts).unwrap();
        assert_eq!(pp.split('-').count(), 7, "7 words joined by '-'");
    }

    #[test]
    fn passphrase_custom_separator() {
        let opts = PassphraseOptions {
            word_count: 3,
            separator: ".".into(),
            ..Default::default()
        };
        let pp = generate_passphrase(&opts).unwrap();
        assert_eq!(pp.split('.').count(), 3, "separator honored");
    }

    #[test]
    fn passphrase_number_transform_inserts_a_digit() {
        let opts = PassphraseOptions {
            word_count: 5,
            number: true,
            ..Default::default()
        };
        let pp = generate_passphrase(&opts).unwrap();
        assert!(
            pp.chars().any(|c| c.is_ascii_digit()),
            "number insert adds a digit"
        );
    }

    #[test]
    fn passphrase_symbol_transform_inserts_a_symbol() {
        let opts = PassphraseOptions {
            word_count: 5,
            symbol: true,
            ..Default::default()
        };
        let pp = generate_passphrase(&opts).unwrap();
        assert!(
            pp.chars().any(|c| PASSPHRASE_SYMBOLS.contains(c)),
            "symbol insert adds a symbol"
        );
    }

    #[test]
    fn passphrase_upper_transform_capitalizes_a_word() {
        let opts = PassphraseOptions {
            word_count: 8,
            upper: true,
            ..Default::default()
        };
        let pp = generate_passphrase(&opts).unwrap();
        assert!(
            pp.chars().any(|c| c.is_ascii_uppercase()),
            "upper transform capitalizes one word"
        );
    }

    #[test]
    fn passphrase_zero_word_count_errors() {
        let opts = PassphraseOptions {
            word_count: 0,
            ..Default::default()
        };
        assert!(matches!(
            generate_passphrase(&opts),
            Err(GenerateError::InvalidWordCount)
        ));
    }

    #[test]
    fn wordlist_pool_is_loaded_and_nontrivial() {
        let en: usize = EFF_EN.lines().filter(|l| !l.is_empty()).count();
        let es: usize = BIP39_ES.lines().filter(|l| !l.is_empty()).count();
        // EFF short 2.0 is 1296 (1295 unique after dedup); BIP-39 ES is 2048.
        // Merged EFF lists (large + short, deduplicated) are 8,232 unique words.
        assert!((8200..=8250).contains(&en), "EFF-EN count {en}");
        assert_eq!(es, 2048, "BIP-39 ES count");
    }
}
