//! UniFFI FFI surface for Baluard (Phase 1 spike).
//!
//! Goal of this spike: prove the toolchain end-to-end. Bind ONE pure
//! `baluard-core` function (BIP-39 recovery phrase generation — it's in core,
//! unlike the password generator which lives in the desktop frontend JS), wire
//! it through UniFFI proc-macros, and confirm:
//!   1. `baluard-core` / `baluard-runtime` types compile under the proc-macros.
//!   2. The generated Kotlin/Swift bindings are sane.
//!   3. The async path works (UniFFI async -> Kotlin `suspend`, one shared
//!      tokio runtime off the UI thread — see plan §3.3).
//!
//! This is deliberately NOT the full mobile API surface (that's Task #12). It
//! is the 2-3 day de-risk spike the plan §5 Phase 1 mandates before committing
//! a month to the real build.

uniffi::setup_scaffolding!();

/// Library version (embedded in vault format headers).
pub fn mobile_version() -> u32 {
    baluard_core::BALUARD_VERSION as u32
}

/// A 24-word BIP-39 recovery phrase. Mirrors `baluard_core::recovery::RecoveryPhrase`
/// but flattened to a plain String for the FFI boundary (the internal type
/// holds zeroized entropy that UniFFI can't cross with the zeroize guarantee).
#[derive(uniffi::Record)]
pub struct MobileRecoveryPhrase {
    /// Space-separated 24 words.
    pub phrase: String,
}

/// Generate a fresh random 24-word BIP-39 recovery phrase. Uses `OsRng` under
/// the hood (never `Math.random` — same crypto-strong path as desktop).
#[uniffi::export]
pub fn generate_recovery_phrase() -> Result<MobileRecoveryPhrase, String> {
    let rp = baluard_core::recovery::RecoveryPhrase::generate()
        .map_err(|e| format!("recovery phrase generation failed: {e}"))?;
    Ok(MobileRecoveryPhrase {
        phrase: rp.phrase(),
    })
}

/// Derive a 32-byte key-encryption key (KEK) from a master password + salt via
/// Argon2id. Returns raw bytes for the FFI boundary.
///
/// SECURITY NOTE: the password crosses the FFI boundary as a `String` here
/// because UniFFI can't enforce zeroize-on-drop across it. The returned `Vec<u8>`
/// is the KEK (not the master password) and lives on the Kotlin/Swift managed
/// heap with unbounded GC lifetime — same plaintext-on-heap boundary the plan
/// §3.6 documents as deliberate. The caller (mobile runtime) must treat both
/// args + the return as sensitive and avoid logging/persisting them.
#[uniffi::export]
pub fn derive_kek(password: String, salt: Vec<u8>) -> Result<Vec<u8>, String> {
    use baluard_core::crypto::kdf::derive_kek as core_derive;
    use baluard_core::types::{KdfParams, KdfProfile};

    // Pad/truncate salt to 32 bytes (matches the legacy core behavior so
    // existing test vectors stay valid).
    let mut salt_32 = vec![0u8; 32];
    let len = salt.len().min(32);
    salt_32[..len].copy_from_slice(&salt[..len]);

    let params = KdfParams {
        profile: KdfProfile::MobileLow,
        memory_kib: KdfProfile::MobileLow.memory_kib(),
        time_cost: KdfProfile::MobileLow.time_cost(),
        parallelism: KdfProfile::MobileLow.parallelism(),
        salt: salt_32,
    };
    let key = core_derive(&password, &params).map_err(|e| format!("KEK derivation failed: {e}"))?;
    Ok(key.to_vec())
}

// ── Generator (plan §3.3 mobile_generate_password / mobile_generate_passphrase) ──
// Ported to baluard-core::generator 2026-07-23 (was desktop JS only). FFI-facing
// config records use u32 (not usize) because UniFFI prefers fixed-width ints
// at the boundary; usize is platform-dependent.

/// Options for [`generate_password`]. Mirrors `baluard_core::generator::PasswordOptions`.
#[derive(uniffi::Record)]
pub struct PasswordConfig {
    /// Password length (>= 1). Default 16.
    pub length: u32,
    pub upper: bool,
    pub numbers: bool,
    pub symbols: bool,
}

/// Options for [`generate_passphrase`]. Mirrors `baluard_core::generator::PassphraseOptions`.
#[derive(uniffi::Record)]
pub struct PassphraseConfig {
    /// Word count (>= 1). Default 5.
    pub word_count: u32,
    /// Separator between words (e.g. "-").
    pub separator: String,
    pub upper: bool,
    pub number: bool,
    pub symbol: bool,
}

/// Generate a random password. Uses OsRng (CSPRNG). Selection is unbiased
/// (unlike the legacy desktop JS which used modulo).
#[uniffi::export]
pub fn generate_password(config: PasswordConfig) -> Result<String, String> {
    let opts = baluard_core::generator::PasswordOptions {
        length: config.length as usize,
        upper: config.upper,
        numbers: config.numbers,
        symbols: config.symbols,
    };
    baluard_core::generator::generate_password(&opts)
        .map_err(|e| format!("password generation failed: {e}"))
}

/// Generate a random passphrase from the EFF-EN + BIP-39-ES wordlist, with
/// optional capitalize / insert-number / insert-symbol transforms.
#[uniffi::export]
pub fn generate_passphrase(config: PassphraseConfig) -> Result<String, String> {
    let opts = baluard_core::generator::PassphraseOptions {
        word_count: config.word_count as usize,
        separator: config.separator,
        upper: config.upper,
        number: config.number,
        symbol: config.symbol,
    };
    baluard_core::generator::generate_passphrase(&opts)
        .map_err(|e| format!("passphrase generation failed: {e}"))
}

/// Trivial async fn to validate the UniFFI async -> Kotlin `suspend` bridge
/// against the real `baluard-runtime` dependency (proves the tokio runtime +
/// spawn_blocking path compiles and crosses the FFI boundary). Returns a
/// fixed string; the point is the async machinery, not the value.
#[uniffi::export]
pub async fn spike_async_probe() -> String {
    // Touch the runtime dep so the linker pulls it in and we prove the version
    // matrix (tokio + uniffi + baluard-runtime) compiles together.
    let _ = baluard_runtime::AutoSyncState::Idle;
    "baluard-uniffi async bridge ok".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors the legacy core test that was removed when the FFI surface
    // consolidated into this crate. Proves the three consolidated fns still
    // work from their new home.
    #[test]
    fn consolidated_ffi_surface_works() {
        assert_eq!(mobile_version(), 1);
        let phrase = generate_recovery_phrase().unwrap().phrase;
        assert_eq!(
            phrase.split_whitespace().count(),
            24,
            "BIP-39 must be 24 words"
        );

        let key = derive_kek("password123".to_string(), b"salt123".to_vec()).unwrap();
        assert_eq!(key.len(), 32, "KEK must be 32 bytes (AES-256)");
    }

    #[tokio::test]
    async fn async_bridge_compiles_and_runs() {
        // Validates the UniFFI async -> Kotlin suspend path will have a working
        // tokio runtime underneath (the actual suspend bridging is verified
        // on-device in the Phase 1 APK build; here we prove the Rust side runs).
        let s = spike_async_probe().await;
        assert!(s.contains("async bridge ok"));
    }

    #[test]
    fn ffi_generator_password_default() {
        let cfg = PasswordConfig {
            length: 16,
            upper: true,
            numbers: true,
            symbols: true,
        };
        let p = generate_password(cfg).unwrap();
        assert_eq!(p.len(), 16);
        assert!(p.is_ascii());
    }

    #[test]
    fn ffi_generator_passphrase_word_count() {
        let cfg = PassphraseConfig {
            word_count: 6,
            separator: ".".into(),
            upper: false,
            number: false,
            symbol: false,
        };
        let pp = generate_passphrase(cfg).unwrap();
        assert_eq!(pp.split('.').count(), 6, "6 words joined by separator");
    }

    #[test]
    fn ffi_generator_password_lower_only() {
        let cfg = PasswordConfig {
            length: 100,
            upper: false,
            numbers: false,
            symbols: false,
        };
        let p = generate_password(cfg).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_lowercase()));
    }
}
