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

static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

pub fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Typed error for the mobile FFI surface.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BaluardError {
    /// Network connection or transport failed.
    #[error("network error: {detail}")]
    Network { detail: String },

    /// Git provider error (OAuth, device flow, PAT validation, repo detection).
    #[error("provider error: {detail}")]
    Provider { detail: String },

    /// Device is not enrolled in the target vault (requires 24-word recovery phrase entry).
    #[error("device not enrolled: {detail}")]
    DeviceNotEnrolled { detail: String },

    /// Master password verification failed (wrong password).
    #[error("wrong master password")]
    WrongPassword,

    /// Device keystore no longer matches the vault (reinstalled or
    /// re-cloned app, stale pairing). Re-pair the device from one that can
    /// open the vault, or unlock with the recovery phrase. This is NOT a
    /// wrong-password case.
    #[error("device unpaired: {detail}")]
    DeviceUnpaired { detail: String },

    /// Target resource or key not found.
    #[error("not found: {detail}")]
    NotFound { detail: String },

    /// A cryptographic operation failed (Argon2id KDF, keywrap verification, BIP-39 entropy).
    #[error("crypto error: {detail}")]
    Crypto { detail: String },

    /// A vault-layer operation failed (open, lock, cipher CRUD, TOTP).
    #[error("vault error: {detail}")]
    Vault { detail: String },

    /// Initializing a new vault on disk failed (device keys, keywrap, manifest).
    #[error("vault creation failed: {detail}")]
    Creation { detail: String },

    /// Invalid input at the FFI boundary (KEK not 32 bytes, generator config).
    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },
}

impl From<baluard_core::error::CryptoError> for BaluardError {
    fn from(e: baluard_core::error::CryptoError) -> Self {
        Self::Crypto {
            detail: e.to_string(),
        }
    }
}

impl From<baluard_core::generator::GenerateError> for BaluardError {
    fn from(e: baluard_core::generator::GenerateError) -> Self {
        Self::InvalidInput {
            detail: e.to_string(),
        }
    }
}

impl From<baluard_core::error::BaluardError> for BaluardError {
    fn from(e: baluard_core::error::BaluardError) -> Self {
        match e {
            baluard_core::error::BaluardError::Crypto(ce) => Self::Crypto {
                detail: ce.to_string(),
            },
            baluard_core::error::BaluardError::Vault(ve) => match ve {
                baluard_core::error::VaultError::NotFound(msg) => Self::NotFound { detail: msg },
                baluard_core::error::VaultError::DeviceUnpaired(msg) => {
                    Self::DeviceUnpaired { detail: msg }
                }
                baluard_core::error::VaultError::Metadata(msg) => Self::Vault { detail: msg },
                baluard_core::error::VaultError::Corrupt(msg) => Self::Vault { detail: msg },
                baluard_core::error::VaultError::NotInitialized => Self::Vault {
                    detail: "Vault not initialized".to_string(),
                },
                other => Self::Vault {
                    detail: other.to_string(),
                },
            },
            baluard_core::error::BaluardError::Key(ke) => Self::Crypto {
                detail: ke.to_string(),
            },
            baluard_core::error::BaluardError::Sync(se) => Self::Network {
                detail: se.to_string(),
            },
            baluard_core::error::BaluardError::Provider(pe) => Self::Provider {
                detail: pe.to_string(),
            },
            other => Self::Vault {
                detail: other.to_string(),
            },
        }
    }
}

// The runtime returns `String` errors; map them to the vault-layer variant.
impl From<String> for BaluardError {
    fn from(detail: String) -> Self {
        Self::Vault { detail }
    }
}

/// Library version (embedded in vault format headers).
#[uniffi::export]
pub fn mobile_version() -> u32 {
    baluard_core::BALUARD_VERSION as u32
}

/// Set the platform-specific data directory (used by Android/iOS to point at app storage).
#[uniffi::export]
pub fn init_data_dir(data_dir: String) {
    unsafe { std::env::set_var("BALUARD_DATA_DIR", data_dir) };
}

/// Install the provider-token encryption key (M3). The mobile app calls
/// this ONCE at startup, before any provider flow. On Android the key is a
/// random 32-byte secret unwrapped at runtime by a non-exportable
/// AndroidKeystore key. Without it, provider tokens fall back to the
/// plaintext 0600 file (headless/test environments only).
#[uniffi::export]
pub fn set_token_encryption_key(key: Vec<u8>) -> Result<(), BaluardError> {
    let k: [u8; 32] = key
        .try_into()
        .map_err(|v: Vec<u8>| BaluardError::InvalidInput {
            detail: format!("token encryption key must be 32 bytes, got {}", v.len()),
        })?;
    baluard_core::providers::token::set_token_encryption_key(k);
    Ok(())
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
pub fn generate_recovery_phrase() -> Result<MobileRecoveryPhrase, BaluardError> {
    let rp = baluard_core::recovery::RecoveryPhrase::generate()?;
    Ok(MobileRecoveryPhrase {
        phrase: rp.phrase(),
    })
}

/// Render the recovery sheet (TXT or one-page PDF) for the mobile export
/// surface. Same renderer as desktop (D77): one writer, three consumers.
/// `format` is "txt" or "pdf"; `phrase` is the space-separated 24 words.
/// Returns raw file bytes — the platform side writes them through its
/// document picker (SAF on Android), so no filesystem path crosses the FFI.
#[uniffi::export]
pub fn recovery_sheet_bytes(
    format: String,
    title: String,
    warning: String,
    phrase: String,
) -> Result<Vec<u8>, BaluardError> {
    use baluard_core::recovery_sheet::{RecoverySheet, SheetFormat};

    let sheet_format = match format.as_str() {
        "txt" => SheetFormat::Txt,
        "pdf" => SheetFormat::Pdf,
        other => {
            return Err(BaluardError::InvalidInput {
                detail: format!("unknown recovery sheet format: {other}"),
            });
        }
    };
    let words: Vec<&str> = phrase.split_whitespace().collect();
    // The sheet layout is a fixed 2x12 grid; fail closed on anything else
    // (same gate as the desktop Tauri command).
    if words.len() != 24 {
        return Err(BaluardError::InvalidInput {
            detail: format!(
                "recovery phrase must have exactly 24 words, got {}",
                words.len()
            ),
        });
    }
    let sheet = RecoverySheet {
        title: &title,
        warning: &warning,
        words: &words,
    };
    Ok(match sheet_format {
        SheetFormat::Txt => sheet.to_txt().into_bytes(),
        SheetFormat::Pdf => sheet.to_pdf(),
    })
}

/// Derive a 32-byte key-encryption key (KEK) from a master password + salt via
/// Argon2id. Returns raw bytes for the FFI boundary. Runs off the UI thread via `spawn_blocking`.
#[uniffi::export(async_runtime = "tokio")]
pub async fn derive_kek(password: String, salt: Vec<u8>) -> Result<Vec<u8>, BaluardError> {
    tokio::task::spawn_blocking(move || {
        use baluard_core::crypto::kdf::derive_kek as core_derive;
        use baluard_core::types::{KdfParams, KdfProfile};

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
        let key = core_derive(&password, &params)?;
        Ok(key.to_vec())
    })
    .await
    .map_err(|e| BaluardError::Crypto {
        detail: e.to_string(),
    })?
}

/// Derive KEK for a specific vault on disk by reading its own `meta/kdf-params.json`
/// (no hardcoded params or salt truncation; fixes mobile autofill KDF mismatch).
#[uniffi::export(async_runtime = "tokio")]
pub async fn derive_kek_for_vault(
    vault_path: String,
    password: String,
) -> Result<Vec<u8>, BaluardError> {
    tokio::task::spawn_blocking(move || {
        let p = std::path::Path::new(&vault_path);
        let kdf_json = std::fs::read_to_string(p.join("meta/kdf-params.json")).map_err(|e| {
            BaluardError::InvalidInput {
                detail: format!("reading kdf params: {e}"),
            }
        })?;
        let params: baluard_core::types::KdfParams =
            serde_json::from_str(&kdf_json).map_err(|e| BaluardError::InvalidInput {
                detail: format!("corrupt kdf params: {e}"),
            })?;
        let key = baluard_core::crypto::kdf::derive_kek(&password, &params)?;
        Ok(key.to_vec())
    })
    .await
    .map_err(|e| BaluardError::Crypto {
        detail: e.to_string(),
    })?
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
    /// Tags for filtering (sidebar pills on desktop).
    pub tags: Vec<String>,
    /// Folder id (if any) for folder filtering; resolved to a name via
    /// `list_folders` on the Kotlin side.
    pub folder_id: Option<String>,
    /// Collection id (if any) — set for ciphers living inside a shared
    /// collection directory; drives the Shared section filter.
    pub collection_id: Option<String>,
    /// Archived entries are hidden from the mobile list.
    pub archived: bool,
}

impl From<baluard_core::types::CipherMeta> for MobileCipherMeta {
    fn from(m: baluard_core::types::CipherMeta) -> Self {
        Self {
            id: m.id.to_string(),
            name: m.name,
            cipher_type: format!("{:?}", m.cipher_type).to_lowercase(),
            favorite: m.favorite,
            username: m.username,
            tags: m.tags,
            folder_id: m.folder_id.map(|u| u.to_string()),
            collection_id: m.collection_id.map(|u| u.to_string()),
            archived: m.archived,
        }
    }
}

/// Coordinator status snapshot (plan §3.5). Drives the mobile sync indicator:
/// `active` false = no remote/provider; `state` is the lowercase coordinator
/// state (idle/dirty/syncing/offline/needsdecision); `pending` is the
/// debounce-window mutation count; `last_sync` is unix seconds or None.
#[derive(uniffi::Record)]
pub struct MobileSyncStatus {
    pub active: bool,
    pub state: String,
    pub last_sync: Option<u64>,
    pub pending: u32,
}

#[uniffi::export(async_runtime = "tokio")]
impl MobileVault {
    /// Unlock the vault with the master password. Derives the KEK via Argon2id,
    /// verifies the keywrap + canaries, and activates the auto-sync coordinator
    /// (if the vault has a remote). Heavy: runs the KDF on the shared runtime.
    pub async fn unlock(&self, master_password: String) -> Result<(), BaluardError> {
        Ok(self.state.unlock(&master_password).await?)
    }

    /// Lock the vault: zeroizes in-memory keys, clears the session token,
    /// deactivates auto-sync. The on-disk vault is untouched.
    pub async fn lock(&self) -> Result<(), BaluardError> {
        Ok(self.state.lock().await?)
    }

    /// **Autofill / extension quick-unlock path (plan §3.2).** Unlocks with a
    /// pre-derived KEK, SKIPPING the Argon2id KDF. The caller retrieves the
    /// biometric-gated KEK from the platform keychain (StrongBox / Secure
    /// Enclave) and passes it here. The master-password KDF never runs in the
    /// memory-capped autofill process (OOM guard — a 64-256 MB KDF would OOM
    /// an Android AutofillService or iOS credential extension).
    ///
    /// SECURITY: the [kek] is the Argon2id output over the master password
    /// (NOT the password itself). Treat as sensitive at the FFI boundary.
    pub async fn unlock_with_kek(&self, kek: Vec<u8>) -> Result<(), BaluardError> {
        let mut arr = [0u8; 32];
        if kek.len() != 32 {
            return Err(BaluardError::InvalidInput {
                detail: "KEK must be exactly 32 bytes".to_string(),
            });
        }
        arr.copy_from_slice(&kek);
        Ok(self.state.unlock_with_kek(&arr).await?)
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
    pub async fn list_ciphers(&self) -> Result<Vec<MobileCipherMeta>, BaluardError> {
        let metas = self.state.list_cipher_meta().await?;
        Ok(metas.into_iter().map(MobileCipherMeta::from).collect())
    }

    /// Get a single cipher as a JSON string (the daemon wire format: nested
    /// `kind` object + flat top-level fields). `decrypt` true returns field
    /// values (password, notes); false returns masked/placeholder values.
    pub async fn get_cipher(&self, id: String, decrypt: bool) -> Result<String, BaluardError> {
        Ok(self.state.get_cipher(&id, decrypt).await?)
    }

    /// Import entries from an external password manager (G2, one parser
    /// set for every surface). [data] is the raw file payload — text
    /// formats UTF-8, 1PUX binary. Returns the daemon-shaped summary
    /// JSON: {imported, skipped, folders_created, errors}.
    pub async fn import_data(&self, format: String, data: Vec<u8>) -> Result<String, BaluardError> {
        use baluard_core::import::ImportFormat;
        let fmt = ImportFormat::from_name(&format).ok_or_else(|| BaluardError::InvalidInput {
            detail: format!("unknown import format: {format}"),
        })?;
        let parsed = match fmt {
            ImportFormat::OnePassword1pux => baluard_core::import::onepassword_1pux::parse(&data),
            _ => {
                let text = String::from_utf8(data).map_err(|_| BaluardError::InvalidInput {
                    detail: "import file is not valid UTF-8".to_string(),
                })?;
                match fmt {
                    ImportFormat::BaluardJson => {
                        let result = match baluard_core::import::baluard_json::parse_backup(&text) {
                            Ok(backup) => {
                                Ok(baluard_core::import::baluard_json::backup_to_import(backup))
                            }
                            Err(e) => Err(e),
                        };
                        match result {
                            Ok(r) => r,
                            Err(e) => {
                                let mut r = baluard_core::import::ImportResult::new();
                                r.skip(e);
                                r
                            }
                        }
                    }
                    ImportFormat::BwJson => baluard_core::import::bw_json::parse(&text),
                    ImportFormat::BwCsv => baluard_core::import::bw_csv::parse(&text),
                    ImportFormat::ChromeCsv => baluard_core::import::chrome_csv::parse(&text),
                    ImportFormat::FirefoxCsv => baluard_core::import::firefox_csv::parse(&text),
                    ImportFormat::LastPassCsv => baluard_core::import::lastpass_csv::parse(&text),
                    ImportFormat::OnePasswordCsv => {
                        baluard_core::import::onepassword_csv::parse(&text)
                    }
                    ImportFormat::KeePassXml => baluard_core::import::keepass_xml::parse(&text),
                    ImportFormat::OnePassword1pux => unreachable!("matched above"),
                }
            }
        };
        self.state
            .import_ciphers(parsed)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Export the vault in one of three shapes: "baluard" (the Baluard
    /// backup — full-fidelity JSON in our own format, the default),
    /// "bw-json" (Bitwarden JSON, for moving to other apps) or "bw-csv"
    /// (Bitwarden CSV, logins only). All returned strings are UNENCRYPTED —
    /// the caller owns where they land. Space export policy (viewer rules)
    /// is enforced runtime-side and fails closed.
    pub async fn export_data(&self, format: String) -> Result<String, BaluardError> {
        match format.as_str() {
            "baluard" | "baluard-backup" | "baluard.vault" => self
                .state
                .export_backup_json()
                .await
                .map_err(|e| BaluardError::Vault { detail: e }),
            "bw-json" => self
                .state
                .export_bw_json()
                .await
                .map_err(|e| BaluardError::Vault { detail: e }),
            "bw-csv" => self
                .state
                .export_bw_csv()
                .await
                .map_err(|e| BaluardError::Vault { detail: e }),
            other => Err(BaluardError::InvalidInput {
                detail: format!("unknown export format: {other}"),
            }),
        }
    }

    /// Master-password re-prompt verification (G18). Opens a TEMPORARY
    /// handle and actually verifies the password — unlike [Self::unlock],
    /// which short-circuits Ok on an already-unlocked vault and would
    /// accept ANY password here. Wrong password maps to
    /// [BaluardError::WrongPassword]; failures burn the shared per-vault
    /// rate-limit budget by design. Returns the grant expiry (unix
    /// seconds) from the runtime's 30s window.
    pub async fn reprompt_verify(&self, master_password: String) -> Result<u64, BaluardError> {
        let json = self
            .state
            .reprompt_verify(&master_password)
            .await
            .map_err(|e| {
                if e.contains("Incorrect master password") {
                    BaluardError::WrongPassword
                } else {
                    BaluardError::Vault { detail: e }
                }
            })?;
        let v: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| BaluardError::Vault {
                detail: e.to_string(),
            })?;
        Ok(v["expires_at"].as_u64().unwrap_or(0))
    }

    /// Autofill credential query (Phase 6, plan D1/D2/D4). Match vault
    /// logins against a fill target: `https://...` for web fills,
    /// `androidapp://com.pkg` for native app fills. Returns a JSON object
    /// `{matches: [...], app_suggestions: [{domain, matches}]}` ranked
    /// favorites-first; passwords NEVER cross this boundary (fetch the
    /// chosen cipher via `get_cipher`). `app_suggestions` carries the
    /// path-B app-to-web flow (empty unless suggest_app_logins is on).
    pub async fn autofill_query(&self, target: String) -> Result<String, BaluardError> {
        Ok(self.state.autofill_query(&target).await?)
    }

    /// Record a user TRUST decision for a (package, domain) pairing
    /// (path B app-to-web matching). Web-saved logins for `domain` may
    /// then fill inside the native app `package`.
    pub async fn autofill_app_trust(
        &self,
        package: String,
        domain: String,
    ) -> Result<(), BaluardError> {
        Ok(self
            .state
            .autofill_app_trust_set(&package, &domain, true)
            .await?)
    }

    /// Record a user REJECTION for a (package, domain) pairing: the picker
    /// never suggests the pairing again.
    pub async fn autofill_app_reject(
        &self,
        package: String,
        domain: String,
    ) -> Result<(), BaluardError> {
        Ok(self
            .state
            .autofill_app_trust_set(&package, &domain, false)
            .await?)
    }

    /// Add a new cipher (JSON payload per the daemon wire format). Returns the
    /// new cipher's JSON (with generated id, tier, epoch).
    pub async fn add_cipher(&self, payload: String) -> Result<String, BaluardError> {
        Ok(self.state.add_cipher(&payload).await?)
    }

    /// Update an existing cipher (JSON payload). Parses `kind` from the
    /// payload (does NOT clone the existing kind).
    pub async fn update_cipher(&self, payload: String) -> Result<(), BaluardError> {
        Ok(self.state.update_cipher(&payload).await?)
    }

    /// Delete a cipher by id.
    pub async fn delete_cipher(&self, id: String) -> Result<(), BaluardError> {
        Ok(self.state.delete_cipher(&id).await?)
    }

    /// Current TOTP code for a cipher (6 digits + seconds-until-rollover).
    /// The TOTP seed NEVER crosses the FFI boundary; only the derived code.
    pub async fn totp_code(&self, id: String) -> Result<String, BaluardError> {
        Ok(self.state.totp_code(&id).await?)
    }

    // ── Sync lifecycle events (Phase 5; plan §3.2/§3.5) ──────────────────
    // Mobile drives the coordinator via these events instead of a background
    // tokio loop. The daemon keeps its background_loop; both hit the same
    // Inner state machine (Phase 0 Task #2). The OS host (Kotlin
    // ProcessLifecycleOwner / iOS SceneDelegate) calls these from lifecycle
    // hooks; device_name is read from the registry/handle so the host doesn't
    // thread it through every lifecycle callback.

    async fn device_name(&self) -> String {
        self.state.device_name().await
    }

    /// This device's UUID — feeds the autosync coordinator (C5: engine
    /// identity is the id, never the display name).
    async fn device_id(&self) -> String {
        self.state.device_id().await
    }

    /// Pull immediately after unlock so other-device edits land first.
    pub async fn sync_on_unlock(&self) {
        let dn = self.device_id().await;
        self.state.autosync.on_unlock(dn).await;
    }

    /// Arm the 5s debounced push after a CRUD mutation (coalesces bursts).
    pub async fn sync_on_mutation(&self) {
        let dn = self.device_id().await;
        self.state.autosync.on_mutation(dn).await;
    }

    /// Pull on app foreground (10-min guard collapses focus flicker).
    pub async fn sync_on_foreground(&self) {
        let dn = self.device_id().await;
        self.state.autosync.on_foreground(dn).await;
    }

    /// FLUSH any pending debounce immediately on background (OS suspends the
    /// process within seconds; the 5s timer would be dropped).
    pub async fn sync_on_background(&self) {
        self.state.autosync.on_background().await;
    }

    /// User pull-to-refresh / "Sync now".
    pub async fn sync_pull_now(&self) {
        let dn = self.device_id().await;
        self.state.autosync.pull_now(dn).await;
    }

    /// Host-scheduled 30s probe while Offline + foregrounded (the one piece of
    /// background_loop mobile must reproduce).
    pub async fn sync_offline_tick(&self) {
        let dn = self.device_id().await;
        self.state.autosync.offline_tick(dn).await;
    }

    /// Coordinator status snapshot for the sync indicator.
    pub async fn sync_status(&self) -> MobileSyncStatus {
        let s = self.state.autosync.status().await;
        MobileSyncStatus {
            active: s.active,
            state: format!("{:?}", s.state).to_lowercase(),
            last_sync: s.last_sync,
            pending: s.pending,
        }
    }

    /// List cipher metadata for entries that have a TOTP seed (hub card).
    pub async fn list_totp_ciphers(&self) -> Result<Vec<MobileCipherMeta>, BaluardError> {
        let metas = self.state.list_totp_meta().await?;
        Ok(metas.into_iter().map(MobileCipherMeta::from).collect())
    }

    /// List archived cipher metadata (Archive view).
    pub async fn list_archived_ciphers(&self) -> Result<Vec<MobileCipherMeta>, BaluardError> {
        let metas = self.state.list_archived_meta().await?;
        Ok(metas.into_iter().map(MobileCipherMeta::from).collect())
    }

    /// List trashed cipher metadata (Trash view).
    pub async fn list_trash_ciphers(&self) -> Result<Vec<MobileCipherMeta>, BaluardError> {
        let metas = self.state.list_trash_meta().await?;
        Ok(metas.into_iter().map(MobileCipherMeta::from).collect())
    }

    /// Generate an SSH keypair. `keyType`: "ed25519" (default) | "ecdsa256".
    /// Returns JSON {public_key, fingerprint, private_key}; formatted OpenSSH
    /// strings only, matching the desktop generator (RSA removed, L7).
    pub async fn ssh_generate_key(&self, key_type: String) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "type": key_type }).to_string();
        Ok(self.state.ssh_generate_key(&payload).await?)
    }

    /// Fetch a favicon for a login's domain. Payload is the URI or bare
    /// domain; the runtime self-gates on the fetch_favicons setting (returns
    /// "" when disabled or on failure). Returns JSON {data, mime} or "".
    pub async fn fetch_favicon(&self, payload: String) -> Result<String, BaluardError> {
        Ok(self.state.fetch_favicon(&payload).await?)
    }

    /// Archive a cipher: hide from the main list, search, and suggestions.
    pub async fn archive_cipher(&self, id: String) -> Result<(), BaluardError> {
        Ok(self.state.archive_cipher(&id).await?)
    }

    /// Unarchive a cipher: return it to the main list.
    pub async fn unarchive_cipher(&self, id: String) -> Result<(), BaluardError> {
        Ok(self.state.unarchive_cipher(&id).await?)
    }

    /// Restore a cipher from trash back to the active vault.
    pub async fn restore_cipher(&self, id: String) -> Result<(), BaluardError> {
        Ok(self.state.restore_cipher(&id).await?)
    }

    /// Check if coordinator state has a pending conflict and return masked details JSON.
    pub async fn get_pending_conflict_details(&self) -> Result<String, BaluardError> {
        if self.state.autosync.pending_conflict_count().await == 0 {
            let body = serde_json::json!({ "pending": false, "count": 0 });
            Ok(body.to_string())
        } else {
            Ok(self.state.conflict_decrypt_and_merge().await?)
        }
    }

    /// Resolve a pending conflict by cloning the remote entry with a new UUID (keep both).
    pub async fn resolve_conflict_keep_both(&self) -> Result<String, BaluardError> {
        Ok(self.state.conflict_resolve_keep_both().await?)
    }

    /// Apply a conflict verdict: "keep_local" | "keep_remote" | "keep_both".
    /// keep_local/keep_remote are raw-blob picks (cross-epoch safe, no decrypt);
    /// keep_both decrypts + clones the remote side under a new UUID. Returns
    /// JSON `{resolved, remaining}`.
    pub async fn resolve_conflict(&self, verdict: String) -> Result<String, BaluardError> {
        Ok(self.state.conflict_resolve_verdict(&verdict).await?)
    }

    /// Whether the vault should auto-lock NOW (idle >= the vault's
    /// `vault_timeout` policy). Side-effect free; the host calls `lock()` on
    /// true. Foreground-lifecycle driven on mobile (no background walker).
    pub async fn should_auto_lock(&self) -> bool {
        self.state.should_auto_lock().await
    }

    /// Deterministic vault UUID (derived from the KDF salt, stable across
    /// renames + git sync). Scopes platform keychain entries (e.g. the
    /// biometric-gated KEK) per vault.
    pub async fn vault_id(&self) -> Result<String, BaluardError> {
        Ok(self.state.vault_id_str().await?)
    }

    // ── Folders & Tags ────────────────────────────────────────────────────

    /// List all folders as a JSON array string.
    pub async fn list_folders(&self) -> Result<String, BaluardError> {
        Ok(self.state.list_folders().await?)
    }

    /// Create a new folder (JSON payload `{"name": "..."}`).
    pub async fn create_folder(&self, payload: String) -> Result<String, BaluardError> {
        Ok(self.state.create_folder(&payload).await?)
    }

    /// Rename an existing folder (JSON payload `{"id": "...", "name": "..."}`).
    pub async fn rename_folder(&self, payload: String) -> Result<(), BaluardError> {
        Ok(self.state.rename_folder(&payload).await?)
    }

    /// Delete a folder by id (unassigns ciphers first).
    pub async fn delete_folder(&self, id: String) -> Result<(), BaluardError> {
        Ok(self.state.delete_folder(&id).await?)
    }

    /// List all tags as a JSON array string.
    pub async fn list_tags(&self) -> Result<String, BaluardError> {
        Ok(self.state.list_tags().await?)
    }

    /// Create a new tag by name.
    pub async fn create_tag(&self, name: String) -> Result<String, BaluardError> {
        Ok(self.state.create_tag(&name).await?)
    }

    /// Delete a tag by name.
    pub async fn delete_tag(&self, name: String) -> Result<String, BaluardError> {
        Ok(self.state.delete_tag(&name).await?)
    }

    // ── Vault Settings ───────────────────────────────────────────────────

    /// Get current vault settings as JSON string.
    pub async fn get_settings(&self) -> Result<String, BaluardError> {
        Ok(self.state.settings_get().await?)
    }

    /// Update vault settings from JSON string.
    pub async fn set_settings(&self, payload: String) -> Result<(), BaluardError> {
        Ok(self.state.settings_set(&payload).await?)
    }

    // ── Generator History ─────────────────────────────────────────────────

    /// Record a generated password into encrypted generator history.
    pub async fn generator_history_add(&self, payload: String) -> Result<String, BaluardError> {
        Ok(self.state.generator_history_add(&payload).await?)
    }

    /// List generator history entries as JSON string.
    pub async fn generator_history_list(&self) -> Result<String, BaluardError> {
        Ok(self.state.generator_history_list().await?)
    }

    /// Clear all generator history entries.
    pub async fn generator_history_clear(&self) -> Result<(), BaluardError> {
        Ok(self.state.generator_history_clear().await?)
    }

    // ---- Sharing surfaces (§4.8-6). Thin delegation to the same
    // VaultState wrappers the desktop daemon routes through, so the JSON
    // payload contracts have ONE authoritative parser (baluard-runtime
    // state.rs). Mobile never re-implements validation.

    /// List shared collections as JSON. Role-aware: managing devices get
    /// every collection with its grant table; members get only the rows
    /// they can open (grant-wrapped names), no grants key.
    pub async fn collections_list(&self) -> Result<String, BaluardError> {
        self.state
            .collections_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Ask for access to a collection (request-access JIT). Payload:
    /// `{collection_id, access: "read"|"write", note?}`. Returns
    /// `{request_id}`.
    pub async fn collection_request_access(&self, payload: String) -> Result<String, BaluardError> {
        self.state
            .collection_request_access(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// The caller's own pending asks: `{requests: [{id, collection_id,
    /// access, created_at}]}`.
    pub async fn collection_requests_mine(&self) -> Result<String, BaluardError> {
        self.state
            .collection_requests_mine()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Withdraw one of the caller's pending asks. Payload:
    /// `{request_id}`.
    pub async fn collection_requests_withdraw(
        &self,
        payload: String,
    ) -> Result<String, BaluardError> {
        self.state
            .collection_requests_withdraw(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Admin access-request inbox: `{requests: [...], malformed}`.
    pub async fn collection_requests_list(&self) -> Result<String, BaluardError> {
        self.state
            .collection_requests_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Admin approve. Payload: `{request_id, requester_member_id,
    /// access, expires_at?}`. Returns the grant summary.
    pub async fn collection_requests_approve(
        &self,
        payload: String,
    ) -> Result<String, BaluardError> {
        self.state
            .collection_requests_approve(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Admin deny. Payload: `{request_id, requester_member_id}`.
    pub async fn collection_requests_deny(&self, payload: String) -> Result<String, BaluardError> {
        self.state
            .collection_requests_deny(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Optional plaintext catalog (admin-curated collection names):
    /// `{catalog: [{collection_id, name}]}`.
    pub async fn collection_catalog_list(&self) -> Result<String, BaluardError> {
        self.state
            .collection_catalog_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    // ── Admin surfaces (§4.8-7): same runtime wrappers the desktop
    // daemon routes through; the daemon layer stays the only validator.

    /// People list. `{members: [{id, display_name, role, trust, reset,
    /// removed, identity_rotated_at, is_self}], your_role}`.
    pub async fn members_list(&self) -> Result<String, BaluardError> {
        self.state
            .members_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Mint a one-time invite code. Payload: `{role: "viewer"|"editor"
    /// |"admin", transport_username?}` (role parsing fails closed).
    /// Returns `{code, seat_granted, seat_error}`.
    pub async fn member_invite(&self, payload: String) -> Result<String, BaluardError> {
        self.state
            .members_invite(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Queued join introductions (S1a join queue).
    /// `{requests: [{req_id, invite_id, device_id, display_name,
    /// secret_ok}], malformed}`.
    pub async fn join_requests_list(&self) -> Result<String, BaluardError> {
        self.state
            .requests_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Approve a queued join. Payload: `{req_id}`. Runs the standard
    /// verification path; consumed only on success.
    pub async fn join_requests_approve(&self, payload: String) -> Result<String, BaluardError> {
        self.state
            .requests_approve(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Deny a queued join. Payload: `{req_id}`.
    pub async fn join_requests_deny(&self, payload: String) -> Result<String, BaluardError> {
        self.state
            .requests_deny(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Grant collection access. Payload: `{id, member_id, access:
    /// "read"|"write"|"manage", expires_at?}` (expires_at is an absolute
    /// epoch second; absent = never).
    pub async fn collection_grant(&self, payload: String) -> Result<String, BaluardError> {
        let v: serde_json::Value =
            serde_json::from_str(&payload).map_err(|e| BaluardError::Vault {
                detail: e.to_string(),
            })?;
        let id = v["id"].as_str().ok_or_else(|| BaluardError::Vault {
            detail: "missing id".into(),
        })?;
        self.state
            .collection_grant(id, &v)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Revoke a member's collection access. Payload: `{id, member_id}`.
    pub async fn collection_revoke(&self, payload: String) -> Result<String, BaluardError> {
        let v: serde_json::Value =
            serde_json::from_str(&payload).map_err(|e| BaluardError::Vault {
                detail: e.to_string(),
            })?;
        let id = v["id"].as_str().ok_or_else(|| BaluardError::Vault {
            detail: "missing id".into(),
        })?;
        self.state
            .collection_revoke(id, &v)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Whether this device manages the space (holds the Root Key) —
    /// the admin marker that stays true for zero-collection vaults.
    pub async fn is_admin_device(&self) -> Result<bool, BaluardError> {
        self.state
            .is_admin_device()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Space policy knobs (§6.5). Returns the JSON the runtime wrapper
    /// emits: {space_invite_authority, allow_viewer_export, guest_enabled}.
    pub async fn space_settings_get(&self) -> Result<String, BaluardError> {
        self.state
            .space_settings_get()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Set Space policy knobs (partial, admin-gated). Typed args so the
    /// app never hand-builds JSON; the bridge constructs the payload.
    /// Set Space policy knobs (partial). Present-fields-only: the
    /// runtime parser treats a present-null key as a mistyped value, so
    /// None args must stay absent. The typed-args rule (D53) makes the
    /// width deliberate.
    #[allow(clippy::too_many_arguments)]
    pub async fn space_settings_set(
        &self,
        invite_authority: Option<String>,
        allow_viewer_export: Option<bool>,
        guest_enabled: Option<bool>,
        trash_policy: Option<String>,
        join_approval: Option<String>,
        quorum_admin_ops: Option<u64>,
        collection_create_authority: Option<String>,
    ) -> Result<(), BaluardError> {
        // Present fields only: the runtime parser treats a present-null
        // key as a mistyped value, so None args must stay absent.
        let mut map = serde_json::Map::new();
        if let Some(ia) = invite_authority {
            map.insert("space_invite_authority".into(), ia.into());
        }
        if let Some(ave) = allow_viewer_export {
            map.insert("allow_viewer_export".into(), ave.into());
        }
        if let Some(ge) = guest_enabled {
            map.insert("guest_enabled".into(), ge.into());
        }
        if let Some(tp) = trash_policy {
            map.insert("trash_policy".into(), tp.into());
        }
        if let Some(ja) = join_approval {
            map.insert("join_approval".into(), ja.into());
        }
        if let Some(q) = quorum_admin_ops {
            map.insert("quorum_admin_ops".into(), q.into());
        }
        if let Some(cca) = collection_create_authority {
            map.insert("collection_create_authority".into(), cca.into());
        }
        let payload = serde_json::Value::Object(map);
        self.state
            .space_settings_set(&payload.to_string())
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Readiness counts for the Team-shape flip (S3-7b): {prepared,
    /// wrapped, missing_wrap_pubkey, pending_wrap, flipped}.
    pub async fn space_status(&self) -> Result<String, BaluardError> {
        self.state
            .space_status()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Pending sensitive-op asks (§6.5 quorum_admin_ops): {pending:
    /// [{kind, params_digest, initiated_by, initiated_at, required,
    /// approvals}]}. Read-only, unlocked-gated.
    pub async fn approvals_list(&self) -> Result<String, BaluardError> {
        self.state
            .approvals_pending()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Published advisory org policies (S4-6): {policies: {knob:
    /// value}} — empty object when nothing is published. Read-only,
    /// unlocked-gated; member surfaces render the hints.
    pub async fn policies_list(&self) -> Result<String, BaluardError> {
        self.state
            .policies_list()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Mint or refresh the shared-space key wraps for every live
    /// member (S3-7a). Run before flipping; the report lists members
    /// that still need to sign in with a current app version.
    pub async fn space_prepare(&self) -> Result<String, BaluardError> {
        self.state
            .space_prepare()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Flip the vault to team shape (S3-7b, one-way). Afterwards
    /// members keep access only to entries shared with them, starting
    /// from their next unlock. Admin-gated at the core layer.
    pub async fn space_flip(&self) -> Result<String, BaluardError> {
        self.state
            .space_flip()
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Needs-attention notices (S1b-4). refresh_transport triggers the
    /// optional best-effort forge seat check; the phone passes false.
    pub async fn notices_list(&self, refresh_transport: bool) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "refresh_transport": refresh_transport });
        self.state
            .notices_list(&payload.to_string())
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// This device's local share-event log (S1b-1), in chronological
    /// order (oldest first, per the core contract; the client reverses
    /// for display). The wrapper clamps the limit (max 500).
    pub async fn activity_events(&self, limit: u64) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "limit": limit });
        self.state
            .activity_events(&payload.to_string())
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// This device's local refusal log lines (S1b-1). The wrapper
    /// clamps the limit (max 200).
    pub async fn activity_refusals(&self, limit: u64) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "limit": limit });
        self.state
            .activity_refusals(&payload.to_string())
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Mint a collection (admin-gated core). Returns `{id}`.
    pub async fn collection_create(&self, name: String) -> Result<String, BaluardError> {
        self.state
            .collection_create(&name)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Rename a collection (admin-gated core). Returns `{ok: true}`.
    pub async fn collection_rename(
        &self,
        id: String,
        name: String,
    ) -> Result<String, BaluardError> {
        self.state
            .collection_rename(&id, &name)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Delete a collection (admin-gated core; grants die with it,
    /// entries are preserved). Returns `{ok: true}`.
    pub async fn collection_delete(&self, id: String) -> Result<String, BaluardError> {
        self.state
            .collection_delete(&id)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Publish the request catalog (admin-gated): the entries requesters
    /// may ask for by name. An empty list clears the catalog (opt-out).
    /// Returns `{published: true}`.
    pub async fn collection_catalog_set(
        &self,
        entries: Vec<MobileCatalogInput>,
    ) -> Result<String, BaluardError> {
        let payload = serde_json::json!({
            "entries": entries.iter().map(|e| serde_json::json!({
                "collection_id": e.collection_id,
                "name": e.name,
            })).collect::<Vec<_>>(),
        })
        .to_string();
        self.state
            .collection_catalog_set(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Reset a member: their identity is tombstoned and a successor row
    /// is minted; the member re-joins with the returned one-time code.
    /// Returns `{successor_id, reset_code}`.
    pub async fn member_reset(&self, member_id: String) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "member_id": member_id }).to_string();
        self.state
            .members_reset(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Transfer ownership to a member (owner-only; core-gated). The
    /// caller is demoted to Admin. Returns `{}`.
    pub async fn member_transfer(&self, member_id: String) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "member_id": member_id }).to_string();
        self.state
            .members_transfer(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// §13: claim ownership when the Owner cannot act (admin-only;
    /// quorum-gated, the ask binds both member ids). `member_id` is the
    /// claimant's member id — the co-approver repeats the same ask.
    /// Returns `{}`.
    pub async fn member_claim(&self, member_id: String) -> Result<String, BaluardError> {
        let payload = serde_json::json!({ "member_id": member_id }).to_string();
        self.state
            .members_claim(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Remove members and rotate the root key so their key material is
    /// dead. Provider seats are struck first; a strike failure refuses
    /// the removal unless `offline_override` is explicit. Returns
    /// `{removed, new_epoch, seats_struck, unstruck_seats}`.
    pub async fn member_remove(
        &self,
        member_ids: Vec<String>,
        offline_override: bool,
    ) -> Result<String, BaluardError> {
        let payload = serde_json::json!({
            "member_ids": member_ids,
            "offline_override": offline_override,
        })
        .to_string();
        self.state
            .members_remove(&payload)
            .await
            .map_err(|e| BaluardError::Vault { detail: e })
    }

    /// Join a shared space (member side of the join ceremony). The vault
    /// must already be cloned locally (see `clone_vault_start`). Payload
    /// fields: `code` (the invite code), `password` (the joiner's chosen
    /// master password, >= 8 chars), `device_name`. Returns
    /// `{intro_code}` — an out-of-band code the admin consumes to
    /// approve. The password seeds the joiner's local unlock material;
    /// it is zeroized after the introduction is written.
    pub async fn join_introduce(
        &self,
        code: String,
        password: String,
        device_name: String,
        email: Option<String>,
    ) -> Result<String, BaluardError> {
        let pw = zeroize::Zeroizing::new(password);
        if device_name.contains(['\n', '\r']) {
            return Err(BaluardError::Vault {
                detail: "device name must not contain newlines".into(),
            });
        }
        let intro_code = baluard_core::vault::members::create_introduction_with_email(
            &self.state.vault_path,
            &code,
            &pw,
            &device_name,
            email.as_deref(),
        )
        .map_err(|e| BaluardError::Vault {
            detail: e.to_string(),
        })?;
        Ok(serde_json::json!({ "intro_code": intro_code }).to_string())
    }

    /// Poll the join status: `{introduced, approved}`. While introduced
    /// but not approved and the vault is locked, this best-effort pulls
    /// (the joiner has no signing seat yet — pull is fetch + verify +
    /// checkout, which needs no keys), so the admin's approval arrives
    /// without a manual sync.
    pub async fn join_poll(&self) -> Result<String, BaluardError> {
        let (introduced, approved) =
            baluard_core::vault::members::join_status(&self.state.vault_path);
        if introduced && !approved && !self.state.is_unlocked().await {
            let engine = baluard_core::sync::engine::SyncEngine::new(
                &self.state.vault_path,
                "join-poll",
                None,
            );
            if let Ok(repo) = engine.open_repo() {
                let _ = engine.pull(&repo, "origin");
            }
            let (introduced, approved) =
                baluard_core::vault::members::join_status(&self.state.vault_path);
            return Ok(
                serde_json::json!({ "introduced": introduced, "approved": approved }).to_string(),
            );
        }
        Ok(serde_json::json!({ "introduced": introduced, "approved": approved }).to_string())
    }
}

/// Open an existing local vault directory (must already be initialized on
/// disk via the desktop daemon or `create_vault`). Does NOT unlock — call
/// [`MobileVault::unlock`] next. Idempotent: re-opening returns a fresh handle
/// over the same path.
#[uniffi::export(async_runtime = "tokio")]
pub async fn open_vault(path: String) -> Result<std::sync::Arc<MobileVault>, BaluardError> {
    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(std::path::PathBuf::from(
        path,
    )));
    state.open().await?;
    Ok(std::sync::Arc::new(MobileVault { state }))
}

/// Initialize a brand-new vault on disk with MobileLow KDF profile.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_vault(
    path: String,
    master_password: String,
    device_name: String,
) -> Result<std::sync::Arc<MobileVault>, BaluardError> {
    let vault_path = std::path::PathBuf::from(&path);
    baluard_core::vault::creation::VaultCreator::new(&vault_path, &master_password, &device_name)
        .kdf_profile(baluard_core::types::KdfProfile::MobileLow)
        .execute()
        .map_err(|e| BaluardError::Creation {
            detail: e.to_string(),
        })?;
    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(vault_path));
    state.open().await?;
    Ok(std::sync::Arc::new(MobileVault { state }))
}

/// Result of creating a vault with recovery phrase returned.
#[derive(uniffi::Record)]
pub struct MobileCreateResult {
    pub vault: std::sync::Arc<MobileVault>,
    pub recovery_phrase: MobileRecoveryPhrase,
}

/// Create a new vault and return both the vault handle and the 24-word recovery phrase.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_vault_with_recovery(
    path: String,
    master_password: String,
    device_name: String,
) -> Result<MobileCreateResult, BaluardError> {
    let vault_path = std::path::PathBuf::from(&path);
    let (_handle, secrets) = baluard_core::vault::creation::VaultCreator::new(
        &vault_path,
        &master_password,
        &device_name,
    )
    .kdf_profile(baluard_core::types::KdfProfile::MobileLow)
    .execute()
    .map_err(|e| BaluardError::Creation {
        detail: e.to_string(),
    })?;

    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(vault_path));
    state.open().await?;
    Ok(MobileCreateResult {
        vault: std::sync::Arc::new(MobileVault { state }),
        recovery_phrase: MobileRecoveryPhrase {
            phrase: secrets.recovery_phrase.phrase(),
        },
    })
}

// ── Generator (plan §3.3 mobile_generate_password / mobile_generate_passphrase) ──
// Ported to baluard-core::generator 2026-07-23 (was desktop JS only). FFI-facing
// config records use u32 (not usize) because UniFFI prefers fixed-width ints
// at the boundary; usize is platform-dependent.

/// Options for [`generate_password`]. Mirrors `baluard_core::generator::PasswordOptions`.
/// One request-catalog entry the admin publishes: the collection id
/// plus the plaintext display name requesters see when asking.
#[derive(uniffi::Record)]
pub struct MobileCatalogInput {
    pub collection_id: String,
    pub name: String,
}

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
pub fn generate_password(config: PasswordConfig) -> Result<String, BaluardError> {
    let opts = baluard_core::generator::PasswordOptions {
        length: config.length as usize,
        upper: config.upper,
        numbers: config.numbers,
        symbols: config.symbols,
    };
    Ok(baluard_core::generator::generate_password(&opts)?)
}

/// Generate a random passphrase from the EFF-EN + BIP-39-ES wordlist, with
/// optional capitalize / insert-number / insert-symbol transforms.
#[uniffi::export]
pub fn generate_passphrase(config: PassphraseConfig) -> Result<String, BaluardError> {
    let opts = baluard_core::generator::PassphraseOptions {
        word_count: config.word_count as usize,
        separator: config.separator,
        upper: config.upper,
        number: config.number,
        symbol: config.symbol,
    };
    Ok(baluard_core::generator::generate_passphrase(&opts)?)
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

// ── Provider connection & device flow (Slice B) ──────────────────────

#[derive(uniffi::Enum)]
pub enum MobileProvider {
    GitHub,
    GitLab,
    Codeberg,
}

impl From<MobileProvider> for baluard_core::providers::Provider {
    fn from(mp: MobileProvider) -> Self {
        match mp {
            MobileProvider::GitHub => Self::GitHub,
            MobileProvider::GitLab => Self::GitLab,
            MobileProvider::Codeberg => Self::Codeberg,
        }
    }
}

impl From<baluard_core::providers::Provider> for MobileProvider {
    fn from(p: baluard_core::providers::Provider) -> Self {
        match p {
            baluard_core::providers::Provider::GitHub => Self::GitHub,
            baluard_core::providers::Provider::GitLab => Self::GitLab,
            baluard_core::providers::Provider::Codeberg => Self::Codeberg,
        }
    }
}

#[derive(uniffi::Record)]
pub struct MobileProviderConfig {
    pub client_id: Option<String>,
    pub instance_url: Option<String>,
}

impl From<MobileProviderConfig> for baluard_core::providers::ProviderConfig {
    fn from(cfg: MobileProviderConfig) -> Self {
        baluard_core::providers::ProviderConfig {
            client_id: cfg.client_id,
            instance_url: cfg.instance_url,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum MobileDeviceFlowStatus {
    Pending,
    Success,
    Expired,
    SlowDown,
}

#[derive(uniffi::Object)]
pub struct MobileDeviceFlow {
    session: baluard_core::providers::DeviceFlowSession,
    provider: baluard_core::providers::Provider,
    config: baluard_core::providers::ProviderConfig,
}

#[uniffi::export(async_runtime = "tokio")]
impl MobileDeviceFlow {
    pub fn user_code(&self) -> String {
        self.session.user_code.clone()
    }

    pub fn verification_uri(&self) -> String {
        self.session.verification_uri.clone()
    }

    pub fn expires_at(&self) -> u64 {
        self.session.expires_at
    }

    pub async fn poll(&self) -> Result<MobileDeviceFlowStatus, BaluardError> {
        let p = baluard_core::providers::provider_for(self.provider, self.config.clone()).map_err(
            |e| BaluardError::Provider {
                detail: e.to_string(),
            },
        )?;
        match p.device_flow_poll(&self.session).await {
            Ok(baluard_core::providers::DeviceFlowStatus::Success(token)) => {
                let user_info =
                    p.validate_token(&token)
                        .await
                        .map_err(|e| BaluardError::Provider {
                            detail: e.to_string(),
                        })?;
                baluard_core::providers::token::store_token(
                    self.provider,
                    &user_info.username,
                    &token,
                )
                .map_err(|e| BaluardError::Provider {
                    detail: format!("store token: {e}"),
                })?;
                let mut state =
                    baluard_core::providers::token::ProvidersState::load().map_err(|e| {
                        BaluardError::Provider {
                            detail: format!("load state: {e}"),
                        }
                    })?;
                state.set(user_info);
                state.save().map_err(|e| BaluardError::Provider {
                    detail: format!("save state: {e}"),
                })?;
                Ok(MobileDeviceFlowStatus::Success)
            }
            Ok(baluard_core::providers::DeviceFlowStatus::Pending) => {
                Ok(MobileDeviceFlowStatus::Pending)
            }
            Ok(baluard_core::providers::DeviceFlowStatus::Expired) => {
                Ok(MobileDeviceFlowStatus::Expired)
            }
            Ok(baluard_core::providers::DeviceFlowStatus::SlowDown { .. }) => {
                Ok(MobileDeviceFlowStatus::SlowDown)
            }
            Err(e) => Err(BaluardError::Provider {
                detail: e.to_string(),
            }),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn start_device_flow(
    provider: MobileProvider,
    config: MobileProviderConfig,
) -> Result<std::sync::Arc<MobileDeviceFlow>, BaluardError> {
    let p_enum = baluard_core::providers::Provider::from(provider);
    let p_cfg = baluard_core::providers::ProviderConfig::from(config);
    let session = baluard_runtime::providers::connect_device_flow(p_enum, p_cfg.clone()).await?;
    Ok(std::sync::Arc::new(MobileDeviceFlow {
        session,
        provider: p_enum,
        config: p_cfg,
    }))
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn connect_pat(
    provider: MobileProvider,
    token: String,
    config: MobileProviderConfig,
) -> Result<(), BaluardError> {
    let p_enum = baluard_core::providers::Provider::from(provider);
    let p_cfg = baluard_core::providers::ProviderConfig::from(config);
    baluard_runtime::providers::connect_pat(p_enum, &token, p_cfg).await?;
    Ok(())
}

#[derive(uniffi::Record)]
pub struct MobileRepo {
    pub name: String,
    pub full_name: String,
    pub clone_url: String,
    pub private: bool,
    pub vault_slug: Option<String>,
    pub vault_id: Option<String>,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn list_vault_repos(provider: MobileProvider) -> Result<Vec<MobileRepo>, BaluardError> {
    let p_enum = baluard_core::providers::Provider::from(provider);
    let repos = baluard_runtime::providers::detect_vault_repos(p_enum).await?;
    Ok(repos
        .into_iter()
        .map(|r| MobileRepo {
            name: r.name,
            full_name: r.full_name,
            clone_url: r.clone_url,
            private: r.private,
            vault_slug: r.vault_slug,
            vault_id: r.vault_id.map(|id| id.to_string()),
        })
        .collect())
}

#[derive(uniffi::Object)]
pub struct MobileCloneJob {
    cancel_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[uniffi::export]
impl MobileCloneJob {
    pub fn cancel(&self) {
        self.cancel_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn clone_vault_start(
    provider: MobileProvider,
    clone_url: String,
    local_path: String,
) -> Result<std::sync::Arc<MobileCloneJob>, BaluardError> {
    let p_enum = baluard_core::providers::Provider::from(provider);
    let path = std::path::PathBuf::from(local_path);
    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag_clone = cancel_flag.clone();

    tokio::task::spawn_blocking(move || {
        baluard_runtime::providers::clone_and_register(
            Some(p_enum),
            &clone_url,
            &path,
            Some(flag_clone),
        )
    })
    .await
    .map_err(|e| BaluardError::Vault {
        detail: e.to_string(),
    })??;

    Ok(std::sync::Arc::new(MobileCloneJob { cancel_flag }))
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn enroll_device_with_phrase(
    vault_path: String,
    master_password: String,
    recovery_phrase: String,
    device_name: String,
) -> Result<std::sync::Arc<MobileVault>, BaluardError> {
    let path = std::path::PathBuf::from(&vault_path);
    let pass_for_enroll = master_password.clone();
    let handle = tokio::task::spawn_blocking(move || {
        baluard_runtime::providers::enroll_device_pre_unlock(
            &path,
            &pass_for_enroll,
            &recovery_phrase,
            &device_name,
        )
    })
    .await
    .map_err(|e| BaluardError::Crypto {
        detail: e.to_string(),
    })??;

    let state = std::sync::Arc::new(baluard_runtime::VaultState::new(handle.path.clone()));
    state.open().await?;
    state.unlock(&master_password).await?;

    Ok(std::sync::Arc::new(MobileVault { state }))
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn provider_disconnect(provider: MobileProvider) -> Result<(), BaluardError> {
    let p_enum = baluard_core::providers::Provider::from(provider);
    baluard_runtime::providers::disconnect(p_enum).await?;
    Ok(())
}

/// Locked background pull (mobile background sync, plan-mobile §3.5):
/// fetch remote git objects WITHOUT unlocking. No decryption, no checkout,
/// no state transition — the next unlock's pull consumes the fetched
/// objects. Called by the Android WorkManager job (opt-in background sync)
/// with the vault path; works on a locked vault by design. Returns true when
/// the remote moved ahead of the local HEAD (objects fetched for later).
#[uniffi::export(async_runtime = "tokio")]
pub async fn background_fetch(path: String) -> Result<bool, BaluardError> {
    let vault_path = std::path::PathBuf::from(path);
    tokio::task::spawn_blocking(move || {
        // Fetch-only on a locked vault: no commit signing, so no seal key.
        let engine = baluard_core::sync::engine::SyncEngine::new(&vault_path, "background", None);
        let repo = engine.open_repo()?;
        engine
            .fetch_locked(&repo, "origin")
            .map_err(BaluardError::from)
    })
    .await
    .map_err(|e| BaluardError::Network {
        detail: format!("join: {e}"),
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_sheet_txt_routes_to_core() {
        let phrase = generate_recovery_phrase().unwrap().phrase;
        let bytes =
            recovery_sheet_bytes("txt".into(), "T".into(), "W".into(), phrase.clone()).unwrap();
        let txt = String::from_utf8(bytes).unwrap();
        assert!(txt.starts_with("T\n"));
        for word in phrase.split_whitespace() {
            assert!(txt.contains(word));
        }
    }

    #[test]
    fn recovery_sheet_pdf_routes_to_core() {
        let phrase = generate_recovery_phrase().unwrap().phrase;
        let bytes = recovery_sheet_bytes("pdf".into(), "T".into(), "W".into(), phrase).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn recovery_sheet_rejects_bad_format_and_word_count() {
        let phrase = generate_recovery_phrase().unwrap().phrase;
        let err =
            recovery_sheet_bytes("md".into(), "T".into(), "W".into(), phrase.clone()).unwrap_err();
        assert!(err.to_string().contains("unknown recovery sheet format"));
        let err =
            recovery_sheet_bytes("txt".into(), "T".into(), "W".into(), "one two three".into())
                .unwrap_err();
        assert!(err.to_string().contains("exactly 24 words, got 3"));
    }

    // Mirrors the legacy core test that was removed when the FFI surface
    // consolidated into this crate. Proves the three consolidated fns still
    // work from their new home.
    #[tokio::test]
    async fn consolidated_ffi_surface_works() {
        assert_eq!(mobile_version(), 1);
        let phrase = generate_recovery_phrase().unwrap().phrase;
        assert_eq!(
            phrase.split_whitespace().count(),
            24,
            "BIP-39 must be 24 words"
        );

        let key = derive_kek("password123".to_string(), b"salt123".to_vec())
            .await
            .unwrap();
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

    // ── G2: import/export through the FFI (real vault, real crypto) ─────
    #[tokio::test]
    async fn import_export_roundtrip_via_ffi() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let vault = create_vault(path, "pw".to_string(), "dev".to_string())
            .await
            .unwrap();
        vault.unlock("pw".to_string()).await.unwrap();

        // Import a minimal Bitwarden JSON payload (one folder, one login).
        let bw = serde_json::json!({
            "folders": [{"id": "f1", "name": "Work"}],
            "items": [{
                "id": "i1", "folderId": "f1", "type": 1, "name": "GH",
                "login": {"username": "u", "password": "p", "uris": []}
            }]
        })
        .to_string();
        let summary = vault
            .import_data("bw-json".into(), bw.into_bytes())
            .await
            .expect("bw-json import should succeed");
        let s: serde_json::Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(s["imported"].as_u64(), Some(1), "summary: {summary}");
        assert_eq!(vault.list_ciphers().await.unwrap().len(), 1);

        // Export: Bitwarden JSON round-trips the entry (and its folder).
        let exported = vault.export_data("bw-json".into()).await.unwrap();
        let ex: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(ex["items"].as_array().unwrap().len(), 1);
        assert_eq!(ex["items"][0]["name"], "GH");
        assert_eq!(ex["folders"].as_array().unwrap().len(), 1);

        // Export: the Baluard backup format carries our own header and the
        // entry in the domain model; re-importing it must also work.
        let backup = vault.export_data("baluard".into()).await.unwrap();
        let b: serde_json::Value = serde_json::from_str(&backup).unwrap();
        assert_eq!(b["format"], "baluard.vault");
        assert_eq!(b["version"], 1);
        assert_eq!(b["manifest"]["cipher_count"], 1);
        assert_eq!(b["ciphers"][0]["name"], "GH");
        let re = vault
            .import_data("baluard".into(), backup.into_bytes())
            .await
            .expect("baluard import should succeed");
        let rs: serde_json::Value = serde_json::from_str(&re).unwrap();
        assert_eq!(rs["imported"].as_u64(), Some(1), "summary: {re}");

        // CSV export carries the login row.
        let csv = vault.export_data("bw-csv".into()).await.unwrap();
        assert!(csv.contains("GH"), "csv should carry the entry name");

        // Unknown formats fail closed on both directions.
        assert!(vault.import_data("md".into(), b"x".to_vec()).await.is_err());
        assert!(vault.export_data("pdf".into()).await.is_err());
    }

    #[tokio::test]
    async fn autofill_query_matches_logins_and_never_leaks_passwords() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let vault = create_vault(path, "pw".to_string(), "dev".to_string())
            .await
            .unwrap();
        vault.unlock("pw".to_string()).await.unwrap();

        let login = |name: &str, username: &str, password: &str, uris: serde_json::Value| {
            serde_json::json!({
                "name": name,
                "kind": {"type": "login", "data": {
                    "username": username,
                    "password": password,
                    "uris": uris,
                    "totp_uri": null,
                    "autofill_on_page_load": false,
                    "password_revision_date": null,
                    "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string()
        };

        vault
            .add_cipher(login(
                "GitHub",
                "esteban",
                "gh-secret",
                serde_json::json!([{"uri": "https://github.com", "matchStrategy": "domain"}]),
            ))
            .await
            .unwrap();
        vault
            .add_cipher(login(
                "Gist",
                "esteban2",
                "gist-secret",
                serde_json::json!([{"uri": "https://gist.github.com", "matchStrategy": "host"}]),
            ))
            .await
            .unwrap();
        vault
            .add_cipher(login(
                "Unrelated",
                "x",
                "x-secret",
                serde_json::json!([{"uri": "https://other.example", "matchStrategy": "domain"}]),
            ))
            .await
            .unwrap();
        // Non-login cipher: card must never appear in autofill results.
        vault
            .add_cipher(
                serde_json::json!({
                    "name": "Bank card",
                    "kind": {"type": "card", "data": {
                        "cardholder_name": "Esteban",
                        "number": "4111111111111111",
                        "brand": "visa",
                        "exp_month": "12",
                        "exp_year": "2030",
                        "code": "123"
                    }}
                })
                .to_string(),
            )
            .await
            .unwrap();

        // Domain strategy: github.com matches subdomains too.
        let web = serde_json::from_str::<serde_json::Value>(
            &vault
                .autofill_query("https://gist.github.com/login".to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        let names: Vec<&str> = web["matches"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        assert!(
            names.contains(&"GitHub"),
            "domain strategy matches subdomain: {names:?}"
        );
        assert!(
            !names.contains(&"Unrelated"),
            "unrelated entry must not match"
        );

        // App target: package equality only; no suggestions without the
        // suggest_app_logins setting.
        let app = serde_json::from_str::<serde_json::Value>(
            &vault
                .autofill_query("androidapp://com.github.android".to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            app["matches"].as_array().unwrap().is_empty(),
            "web URIs must never match app targets: {app:?}"
        );
        assert!(
            app["app_suggestions"].as_array().unwrap().is_empty(),
            "suggestions require the opt-in setting: {app:?}"
        );

        // Secret-absence invariant: passwords never in autofill output.
        let raw = vault
            .autofill_query("https://github.com".to_string())
            .await
            .unwrap();
        assert!(
            !raw.contains("gh-secret"),
            "password leaked in autofill query"
        );
        assert!(!raw.contains("gist-secret"));
        assert!(
            !raw.contains("password"),
            "no password key in autofill output"
        );

        // Locked vault fails closed.
        vault.lock().await.unwrap();
        assert!(
            vault
                .autofill_query("https://github.com".to_string())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn autofill_app_to_web_trust_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let vault = create_vault(path, "pw".to_string(), "dev".to_string())
            .await
            .unwrap();
        vault.unlock("pw".to_string()).await.unwrap();

        let login = |name: &str, username: &str, password: &str, uris: serde_json::Value| {
            serde_json::json!({
                "name": name,
                "kind": {"type": "login", "data": {
                    "username": username,
                    "password": password,
                    "uris": uris,
                    "totp_uri": null,
                    "autofill_on_page_load": false,
                    "password_revision_date": null,
                    "favicon": null,
                    "fido2_credentials": null
                }}
            })
            .to_string()
        };
        vault
            .add_cipher(login(
                "MyBank",
                "esteban",
                "bank-secret",
                serde_json::json!([{"uri": "https://login.mybank.com", "matchStrategy": "domain"}]),
            ))
            .await
            .unwrap();

        // Opt in, then query the native app: untrusted candidate surfaces
        // as a suggestion, never as a match.
        vault
            .set_settings(r#"{"suggest_app_logins": true}"#.to_string())
            .await
            .unwrap();
        let parse = |raw: String| serde_json::from_str::<serde_json::Value>(&raw).unwrap();
        let q = parse(
            vault
                .autofill_query("androidapp://com.mybank.app".to_string())
                .await
                .unwrap(),
        );
        assert!(q["matches"].as_array().unwrap().is_empty());
        let sug = q["app_suggestions"].as_array().unwrap();
        assert_eq!(sug.len(), 1, "one candidate with matching entries: {q:?}");
        assert_eq!(sug[0]["domain"], "mybank.com");
        assert_eq!(sug[0]["matches"].as_array().unwrap().len(), 1);

        // A lookalike package derives the same candidate but has its own
        // (empty) trust scope: it can never inherit another app's trust.
        let lookalike = parse(
            vault
                .autofill_query("androidapp://com.mybank.evil".to_string())
                .await
                .unwrap(),
        );
        assert!(lookalike["matches"].as_array().unwrap().is_empty());

        // Reject: the pairing never surfaces again.
        vault
            .autofill_app_reject("com.mybank.app".to_string(), "mybank.com".to_string())
            .await
            .unwrap();
        let q = parse(
            vault
                .autofill_query("androidapp://com.mybank.app".to_string())
                .await
                .unwrap(),
        );
        assert!(q["app_suggestions"].as_array().unwrap().is_empty());

        // Trust (overrides the rejection): web entries flow into matches.
        vault
            .autofill_app_trust("com.mybank.app".to_string(), "mybank.com".to_string())
            .await
            .unwrap();
        let q = parse(
            vault
                .autofill_query("androidapp://com.mybank.app".to_string())
                .await
                .unwrap(),
        );
        let names: Vec<&str> = q["matches"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        assert_eq!(names, vec!["MyBank"], "trusted pair fills: {q:?}");
        assert!(q["app_suggestions"].as_array().unwrap().is_empty());

        // Trust is scoped per package: the lookalike never gets matches.
        // It still sees the SUGGESTION (same candidate heuristic) — that is
        // by design: the picker banner + explicit consent is the gate, and
        // its trust decision is recorded separately from the real app's.
        let lookalike = parse(
            vault
                .autofill_query("androidapp://com.mybank.evil".to_string())
                .await
                .unwrap(),
        );
        assert!(lookalike["matches"].as_array().unwrap().is_empty());
        let lsug = lookalike["app_suggestions"].as_array().unwrap();
        assert_eq!(lsug.len(), 1);
        assert_eq!(lsug[0]["domain"], "mybank.com");

        // Trust list survives a settings round-trip (git-synced payload).
        let s = serde_json::from_str::<serde_json::Value>(&vault.get_settings().await.unwrap())
            .unwrap();
        assert_eq!(s["trusted_app_packages"][0]["domain"], "mybank.com");
        assert_eq!(s["trusted_app_packages"][0]["package"], "com.mybank.app");

        // Invalid domain folds fail closed.
        assert!(
            vault
                .autofill_app_trust("com.x".to_string(), "not a host".to_string())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn create_vault_with_recovery_returns_phrase_and_derive_kek_for_vault_works() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let pw = "master-pass-123".to_string();

        let res = create_vault_with_recovery(path.clone(), pw.clone(), "device-rec".to_string())
            .await
            .unwrap();
        assert_eq!(res.recovery_phrase.phrase.split_whitespace().count(), 24);

        // Derive KEK using vault's on-disk params (2.2 fix)
        let kek = derive_kek_for_vault(path, pw).await.unwrap();
        assert_eq!(kek.len(), 32);

        // KEK unlocks the vault via unlock_with_kek
        res.vault.unlock_with_kek(kek).await.unwrap();
        assert!(res.vault.is_unlocked().await);
    }

    #[tokio::test]
    async fn mobile_vault_folder_tag_settings_generator_history_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let vault = create_vault(path, "pass123".to_string(), "test-dev".to_string())
            .await
            .unwrap();
        vault.unlock("pass123".to_string()).await.unwrap();

        // Folders
        assert_eq!(vault.list_folders().await.unwrap(), "[]");
        let f_id = vault
            .create_folder(r#"{"name": "Work"}"#.to_string())
            .await
            .unwrap();
        assert!(!f_id.is_empty(), "create_folder returns folder UUID");
        let folders = vault.list_folders().await.unwrap();
        assert!(folders.contains("Work"));

        // Tags
        assert_eq!(vault.list_tags().await.unwrap(), "[]");
        vault.create_tag("important".to_string()).await.unwrap();
        let tags = vault.list_tags().await.unwrap();
        assert!(tags.contains("important"));

        // Settings
        let settings = vault.get_settings().await.unwrap();
        assert!(settings.contains("theme") || settings.contains("system"));

        // Generator History
        assert_eq!(vault.generator_history_list().await.unwrap(), "[]");
        vault
            .generator_history_add(r#"{"value": "secret_pass_123"}"#.to_string())
            .await
            .unwrap();
        let hist = vault.generator_history_list().await.unwrap();
        assert!(hist.contains("secret_pass_123"));
        vault.generator_history_clear().await.unwrap();
        assert_eq!(vault.generator_history_list().await.unwrap(), "[]");
    }
}
