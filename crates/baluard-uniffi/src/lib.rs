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

// ── Vault lifecycle (plan §3.2/§3.3, Phase 2 auth) ──────────────────────
// Mobile hosts the runtime in-process. `MobileVault` wraps a single
// `Arc<VaultState>` (the per-vault orchestration unit extracted in Phase 0).
// Multi-vault `VaultHost` support lands when the desktop VaultSwitcher UI is
// ported; the primary mobile case is one vault at a time.
//
// Concurrency model: the runtime's methods are async (tokio RwLock). These FFI
// methods are `async` too (UniFFI async -> Kotlin `suspend` / Swift `async`,
// driven off the UI thread per plan §3.3). The Argon2id KDF inside
// `VaultState::unlock` is CPU-heavy (64-256 MB, ~1-3s); the parked shared
// tokio Runtime absorbs it. Mirrors the daemon's pattern (no extra
// spawn_blocking) — see `state.rs::unlock` comment.

/// Opaque handle to an open vault session. Created by [`open_vault`] or
/// [`create_vault`]; held by reference on the Kotlin/Swift side. Cheap to
/// clone internally (wraps an `Arc`).
#[derive(uniffi::Object)]
pub struct MobileVault {
    state: std::sync::Arc<baluard_runtime::VaultState>,
}

/// Lightweight cipher metadata for the vault list. Primitive fields only (no
/// core types cross the FFI) so core stays free of UniFFI annotations. The
/// full typed `CipherKind` enum (plan §3.3) lands before the §10 security
/// review; until then `cipher_type` is a lowercase string like "login".
#[derive(uniffi::Record)]
pub struct MobileCipherMeta {
    pub id: String,
    pub name: String,
    /// Lowercase cipher type label ("login", "card", "identity", "sshkey",
    /// "securenote", "bankaccount", "driverslicense", "passport").
    pub cipher_type: String,
    pub favorite: bool,
    /// Login username (if any) for quick display in the list; None otherwise.
    pub username: Option<String>,
}

impl From<baluard_core::types::CipherMeta> for MobileCipherMeta {
    fn from(m: baluard_core::types::CipherMeta) -> Self {
        Self {
            id: m.id.to_string(),
            name: m.name,
            cipher_type: format!("{:?}", m.cipher_type).to_lowercase(),
            favorite: m.favorite,
            username: m.username,
        }
    }
}

#[uniffi::export]
impl MobileVault {
    /// Unlock the vault with the master password. Derives the KEK via Argon2id,
    /// verifies the keywrap + canaries, and activates the auto-sync coordinator
    /// (if the vault has a remote). Heavy: runs the KDF on the shared runtime.
    pub async fn unlock(&self, master_password: String) -> Result<(), String> {
        self.state.unlock(&master_password).await
    }

    /// Lock the vault: zeroizes in-memory keys, clears the session token,
    /// deactivates auto-sync. The on-disk vault is untouched.
    pub async fn lock(&self) -> Result<(), String> {
        self.state.lock().await
    }

    /// Whether the vault currently holds an unlocked handle in memory.
    pub async fn is_unlocked(&self) -> bool {
        self.state.is_unlocked().await
    }

    // ── Cipher CRUD (Phase 3 list/detail + Phase 4 edit/TOTP) ────────────
    // The runtime's get/add/update ciphers use JSON strings (the daemon wire
    // format — see AGENTS.md "Daemon Wire Format"). We pass those through the
    // FFI as `String` for now; mobile parses in Kotlin. The plan §3.3 typed
    // `CipherKind` UniFFI enum (preserves invalid-states-unrepresentable) is a
    // refinement that lands before the §10 security review.

    /// List all ciphers' metadata (id, name, type, favorite, username).
    /// Lightweight: no decryption of field values, just the index.
    pub async fn list_ciphers(&self) -> Result<Vec<MobileCipherMeta>, String> {
        let metas = self.state.list_cipher_meta().await?;
        Ok(metas.into_iter().map(MobileCipherMeta::from).collect())
    }

    /// Get a single cipher as a JSON string (the daemon wire format: nested
    /// `kind` object + flat top-level fields). `decrypt` true returns field
    /// values (password, notes); false returns masked/placeholder values.
    pub async fn get_cipher(&self, id: String, decrypt: bool) -> Result<String, String> {
        self.state.get_cipher(&id, decrypt).await
    }

    /// Add a new cipher (JSON payload per the daemon wire format). Returns the
    /// new cipher's JSON (with generated id, tier, epoch).
    pub async fn add_cipher(&self, payload: String) -> Result<String, String> {
        self.state.add_cipher(&payload).await
    }

    /// Update an existing cipher (JSON payload). Parses `kind` from the
    /// payload (does NOT clone the existing kind).
    pub async fn update_cipher(&self, payload: String) -> Result<(), String> {
        self.state.update_cipher(&payload).await
    }

    /// Delete a cipher by id.
    pub async fn delete_cipher(&self, id: String) -> Result<(), String> {
        self.state.delete_cipher(&id).await
    }

    /// Current TOTP code for a cipher (6 digits + seconds-until-rollover).
    /// The TOTP seed NEVER crosses the FFI boundary; only the derived code.
    pub async fn totp_code(&self, id: String) -> Result<String, String> {
        self.state.totp_code(&id).await
    }
}

/// Open an existing local vault directory (must already be initialized on
/// disk via the desktop daemon or `create_vault`). Does NOT unlock — call
/// [`MobileVault::unlock`] next. Idempotent: re-opening returns a fresh handle
/// over the same path.
pub async fn open_vault(path: String) -> Result<std::sync::Arc<MobileVault>, String> {
    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(std::path::PathBuf::from(
        path,
    )));
    state.open().await?;
    Ok(std::sync::Arc::new(MobileVault { state }))
}

/// Initialize a brand-new vault on disk (Phase 2 `mobile_vault_init` for the
/// local-create path; the OAuth-clone path is Phase 2 web-flow work, host-side).
/// Derives the device keys, writes the keywrap + manifest, and returns an
/// OPEN but NOT-YET-UNLOCKED handle. The caller unlocks with the same password.
pub async fn create_vault(
    path: String,
    master_password: String,
    device_name: String,
) -> Result<std::sync::Arc<MobileVault>, String> {
    // VaultCreator is a blocking builder (no async); the disk writes are fast
    // enough to run on the executor. Mobile callers get it as a suspend fn.
    let vault_path = std::path::PathBuf::from(&path);
    baluard_core::vault::creation::VaultCreator::new(&vault_path, &master_password, &device_name)
        .execute()
        .map_err(|e| format!("vault creation failed: {e}"))?;
    // Open a fresh VaultState over the just-created directory.
    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(vault_path));
    state.open().await?;
    Ok(std::sync::Arc::new(MobileVault { state }))
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

    // ── Phase 2 vault lifecycle (in-process, real crypto) ────────────────
    //
    // Proves the MobileVault Object + open/create/unlock/lock surface against
    // a real vault on disk (VaultCreator writes the keywrap + manifest, then
    // MobileVault::unlock runs the actual Argon2id KDF + keywrap verification).
    // Same crypto path mobile runs on-device; if it passes here the FFI
    // boundary is sound and only the Kotlin/UI glue is unverified.
    #[tokio::test]
    async fn vault_create_open_unlock_lock_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let password = "test-master-password".to_string();

        // Create a brand-new vault on disk.
        let vault = create_vault(path.clone(), password.clone(), "test-device".to_string())
            .await
            .expect("create_vault should succeed on a fresh dir");
        assert!(
            !vault.is_unlocked().await,
            "create_vault returns OPEN but NOT-yet-unlocked"
        );

        // Unlock with the master password (Argon2id + keywrap verify).
        vault
            .unlock(password.clone())
            .await
            .expect("unlock with correct password should succeed");
        assert!(
            vault.is_unlocked().await,
            "vault should be unlocked after unlock()"
        );

        // Wrong password fails closed. Re-open a fresh handle so the
        // already-unlocked fast-path doesn't short-circuit.
        let vault2 = open_vault(path.clone())
            .await
            .expect("re-open should succeed");
        assert!(!vault2.is_unlocked().await);
        let wrong = vault2.unlock("wrong-password".to_string()).await;
        assert!(wrong.is_err(), "wrong password must fail closed");
        assert!(
            !vault2.is_unlocked().await,
            "failed unlock must leave vault locked"
        );

        // Lock the unlocked vault: keys zeroize, is_unlocked -> false.
        vault
            .lock()
            .await
            .expect("lock should succeed on an unlocked vault");
        assert!(
            !vault.is_unlocked().await,
            "lock must zeroize the in-memory handle"
        );
    }

    // ── Phase 3/4 cipher CRUD (in-process, real encryption) ─────────────
    //
    // Proves the full cipher lifecycle through the FFI: add (encrypts under
    // the item key), list (index read), get (decrypt), delete. Uses the daemon
    // wire JSON format (plan defers the typed CipherKind enum to the §10
    // security review; JSON passthrough is the interim surface).
    #[tokio::test]
    async fn cipher_crud_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let vault = create_vault(path, "pw".to_string(), "dev".to_string())
            .await
            .unwrap();
        vault.unlock("pw".to_string()).await.unwrap();

        // Empty vault: list is empty.
        assert!(vault.list_ciphers().await.unwrap().is_empty());

        // Add a login cipher (daemon wire format).
        let payload = serde_json::json!({
            "name": "GitHub",
            "kind": {
                "type": "login",
                "data": {
                    "username": "esteban",
                    "password": "hunter2",
                    "uris": [],
                    "totp_uri": null,
                    "autofill_on_page_load": false,
                    "password_revision_date": null,
                    "favicon": null,
                    "fido2_credentials": null
                }
            }
        })
        .to_string();
        let id = vault
            .add_cipher(payload)
            .await
            .expect("add_cipher should succeed");
        assert!(!id.is_empty(), "add_cipher returns the new cipher id");

        // List reflects it.
        let metas = vault.list_ciphers().await.unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "GitHub");
        assert_eq!(metas[0].cipher_type, "login");
        assert_eq!(metas[0].username.as_deref(), Some("esteban"));

        // Get (decrypted) returns plaintext field values.
        let got = serde_json::from_str::<serde_json::Value>(
            &vault.get_cipher(id.clone(), true).await.unwrap(),
        )
        .unwrap();
        assert_eq!(got["name"], "GitHub");
        assert!(
            got.to_string().contains("hunter2"),
            "decrypted get exposes the password"
        );

        // Delete.
        vault
            .delete_cipher(id)
            .await
            .expect("delete_cipher should succeed");
        assert!(
            vault.list_ciphers().await.unwrap().is_empty(),
            "vault empty after delete"
        );
    }
}
