//! Vault creation ceremony (doc 03 Section 10).
//!
//! Establishes the root of trust: vault_id, master password, KDF params,
//! Root Key, device keypair, HPKE wrapping, initial commit.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::hkdf_derive;
use crate::crypto::hpke_wrap;
use crate::crypto::kdf;
use crate::crypto::signature;
use crate::device_manager::DeviceManager;
use crate::error::{BaluardError, VaultError};
use crate::keys::epoch::EpochInfo;
use crate::keys::hierarchy::RootKey;
use crate::recovery::RecoveryPhrase;
use crate::types::{KdfParams, KdfProfile};
use crate::vault::handle::{UnlockedState, VaultHandle, VaultState};
use rand_core::RngCore;

/// Result of a successful vault creation ceremony.
pub struct VaultCreationResult {
    /// Unique vault identifier.
    pub vault_id: Uuid,
    /// KDF parameters (including salt, stored in plaintext header).
    pub kdf_params: KdfParams,
    /// Initial epoch info (epoch 1, CREATED state).
    pub epoch_info: EpochInfo,
    /// Root Key for epoch 1.
    pub root_key: RootKey,
    /// Device X25519 private key (caller must store in OS keystore).
    pub device_x25519_secret: x25519_dalek::StaticSecret,
    /// Device Ed25519 signing key (caller must store in OS keystore).
    pub device_ed25519_signing: ed25519_dalek::SigningKey,
    /// Device ID.
    pub device_id: Uuid,
    /// 24-word recovery phrase (user must write down).
    pub recovery_phrase: RecoveryPhrase,
    /// SHA-256 fingerprint of the initial trust anchor.
    pub trust_fingerprint: [u8; 32],
    /// Session key (for local cache encryption).
    pub session_key: [u8; 32],
    /// Sync-only key (for locked desktop background sync).
    pub sync_key: [u8; 32],
    /// HPKE-wrapped Root Key for this device (to store in meta/keywrap/).
    pub wrapped_root_key: (Vec<u8>, Vec<u8>, [u8; 16]),
    /// HPKE-wrapped Root Key via recovery phrase (to store in meta/recovery.enc).
    pub wrapped_recovery_key: (Vec<u8>, Vec<u8>, [u8; 16]),
    /// KEK verification canary (encrypted with Session Key, stored in meta/kek-canary.enc).
    pub kek_canary: Vec<u8>,
    /// Root Key verification canary (encrypted with RK-derived key, stored in meta/rk-canary.enc).
    pub rk_canary: Vec<u8>,
}

/// Execute the vault creation ceremony in memory.
pub fn create_vault_ceremony(
    master_password: &str,
    profile: KdfProfile,
) -> Result<VaultCreationResult, BaluardError> {
    // Step 1: Vault ID
    let vault_id = Uuid::new_v4();

    // Step 2: KDF params with fresh salt, derive KEK
    let kdf_params = kdf::create_params(profile);
    let mut kek = kdf::derive_kek(master_password, &kdf_params)?;

    // Step 3: Root Key (epoch 1)
    let root_key = RootKey::generate();
    let epoch_info = EpochInfo::new(1);

    // Step 4: Device keypairs
    let (device_x25519_secret, device_x25519_public) = hpke_wrap::generate_x25519_keypair();
    let (device_ed25519_signing, _device_ed25519_verifying) = signature::generate_ed25519_keypair();
    let device_id = Uuid::new_v4();

    // Step 5: HPKE-wrap Root Key with device public key
    let wrapped_root_key = hpke_wrap::wrap_key(root_key.as_bytes(), &device_x25519_public)?;

    // Step 6: Derive Session + Sync keys from KEK
    let session_key = hkdf_derive::derive_session_key(&kek)?;
    let sync_key = hkdf_derive::derive_sync_key(&kek)?;
    kek.zeroize();

    // Step 7: BIP-39 recovery phrase, wrap Root Key
    let recovery_phrase = RecoveryPhrase::generate()?;
    let recovery_key = recovery_phrase.derive_key();
    // Derive X25519 key from recovery seed for HPKE wrapping
    let recovery_x25519_secret =
        x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(&recovery_key[..32]).unwrap());
    let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);
    let wrapped_recovery_key = hpke_wrap::wrap_key(root_key.as_bytes(), &recovery_x25519_public)?;

    // Step 8: Trust anchor fingerprint (SHA-256 of Root Key)
    let mut hasher = Sha256::new();
    hasher.update(root_key.as_bytes());
    let trust_fingerprint = hasher.finalize().into();

    // Step 9: KEK canary (encrypted with Session Key for password verification)
    let canary_nonce = crate::crypto::aead::build_nonce(0, vault_id);
    let canary_header = crate::types::EnvelopeHeader {
        version: crate::BALUARD_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let canary_envelope = crate::crypto::aead::encrypt(
        &session_key,
        b"baluard-kek-ok",
        b"baluard-kek-canary-v1",
        &canary_nonce,
        canary_header,
    )?;
    let kek_canary = crate::vault::envelope::serialize(&canary_envelope)?;

    // Step 10: Root Key canary (encrypted with RK-derived key for Root Key verification)
    let rk_canary_key = {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"baluard-rk-canary-v1", &mut key)
            .expect("32 bytes is valid for HKDF-SHA256");
        key
    };
    let rk_canary_nonce = crate::crypto::aead::build_nonce(0, vault_id);
    let rk_canary_header = crate::types::EnvelopeHeader {
        version: crate::BALUARD_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 1,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let rk_canary_envelope = crate::crypto::aead::encrypt(
        &rk_canary_key,
        b"baluard-rk-ok",
        b"baluard-rk-canary-v1",
        &rk_canary_nonce,
        rk_canary_header,
    )?;
    let rk_canary = crate::vault::envelope::serialize(&rk_canary_envelope)?;

    Ok(VaultCreationResult {
        vault_id,
        kdf_params,
        epoch_info,
        root_key,
        device_x25519_secret,
        device_ed25519_signing,
        device_id,
        recovery_phrase,
        trust_fingerprint,
        kek_canary,
        rk_canary,
        session_key,
        sync_key,
        wrapped_root_key,
        wrapped_recovery_key,
    })
}

// ── NEW REFINED HYBRID CEREMONY IMPLEMENTATION ──

/// Cryptographic entropy port for injecting reproducible randomness in tests.
pub trait EntropyProvider {
    fn fill_bytes(&mut self, dest: &mut [u8]);
    fn generate_uuid(&mut self) -> Uuid;
}

/// Production implementation of EntropyProvider using standard secure sources.
pub struct OsEntropy;

impl EntropyProvider for OsEntropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dest);
    }
    fn generate_uuid(&mut self) -> Uuid {
        Uuid::new_v4()
    }
}

/// Bridge between custom EntropyProvider and standard rand_core traits.
struct RngAdapter<'a> {
    provider: &'a mut dyn EntropyProvider,
}

impl<'a> rand_core::RngCore for RngAdapter<'a> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.provider.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.provider.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.provider.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.provider.fill_bytes(dest);
        Ok(())
    }
}

impl<'a> rand_core::CryptoRng for RngAdapter<'a> {}

/// Dynamic or static keystore port for secure private key storage.
pub trait SecureKeystore {
    fn store_secret(&self, key: &str, secret: &[u8]) -> Result<(), BaluardError>;
    fn get_secret(&self, key: &str) -> Result<Vec<u8>, BaluardError>;
}

/// The target mode of the initialization ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyMode {
    /// Create a brand-new vault and generate a new recovery phrase.
    Create,
    /// Join an existing vault using a recovery phrase.
    Join { recovery_phrase: String },
}

/// Crucial vault secrets returned by the ceremony.
/// Automatically zeroizes on drop to prevent leaking secrets in memory.
pub struct CeremonySecrets {
    pub recovery_phrase: RecoveryPhrase,
    pub trust_fingerprint: [u8; 32],
    pub device_id: Uuid,
    pub vault_id: Uuid,
}

impl Drop for CeremonySecrets {
    fn drop(&mut self) {
        self.trust_fingerprint.zeroize();
    }
}

/// Unified builder orchestrating the ceremony.
/// Implements Drop with memory zeroization to safeguard credentials.
pub struct VaultCreator<'a> {
    path: PathBuf,
    password: Zeroizing<String>,
    device_name: String,
    kdf_profile: KdfProfile,
    mode: CeremonyMode,
    initialize_git: bool,
    keystore: Option<&'a dyn SecureKeystore>,
    entropy: Option<Box<dyn EntropyProvider>>,
    // Wizard fields (applied post-creation)
    display_name: Option<String>,
    subtitle: Option<String>,
    slug: Option<String>,
    theme: Option<crate::types::ThemeMode>,
    lang: Option<String>,
    auto_lock_minutes: Option<u32>,
}

impl<'a> Drop for VaultCreator<'a> {
    fn drop(&mut self) {
        self.device_name.zeroize();
    }
}

impl<'a> VaultCreator<'a> {
    /// Initialize a new vault creator builder.
    pub fn new(path: impl AsRef<Path>, password: &str, device_name: &str) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: Zeroizing::new(password.to_string()),
            device_name: device_name.to_string(),
            kdf_profile: KdfProfile::DesktopStd,
            mode: CeremonyMode::Create,
            initialize_git: true,
            keystore: None,
            entropy: None,
            display_name: None,
            subtitle: None,
            slug: None,
            theme: None,
            lang: None,
            auto_lock_minutes: None,
        }
    }

    /// Override the default KDF tuning profile.
    pub fn kdf_profile(mut self, profile: KdfProfile) -> Self {
        self.kdf_profile = profile;
        self
    }

    /// Set the ceremony mode (Create or Join).
    pub fn mode(mut self, mode: CeremonyMode) -> Self {
        self.mode = mode;
        self
    }

    /// Configure Git repository initialization.
    pub fn initialize_git(mut self, enable: bool) -> Self {
        self.initialize_git = enable;
        self
    }

    /// Inject a secure keystore provider.
    pub fn keystore(mut self, keystore: &'a dyn SecureKeystore) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// Inject a custom entropy provider.
    pub fn entropy(mut self, entropy: impl EntropyProvider + 'static) -> Self {
        self.entropy = Some(Box::new(entropy));
        self
    }

    /// Set user profile fields (display name, subtitle).
    pub fn profile(mut self, display_name: Option<String>, subtitle: Option<String>) -> Self {
        self.display_name = display_name;
        self.subtitle = subtitle;
        self
    }

    /// Set vault slug (machine-friendly identifier).
    pub fn slug(mut self, slug: Option<String>) -> Self {
        self.slug = slug;
        self
    }

    /// Set user preferences (theme, language, auto-lock timeout).
    pub fn preferences(
        mut self,
        theme: Option<crate::types::ThemeMode>,
        lang: Option<String>,
        auto_lock_minutes: Option<u32>,
    ) -> Self {
        self.theme = theme;
        self.lang = lang;
        self.auto_lock_minutes = auto_lock_minutes;
        self
    }

    /// Executes the ceremony transactionally, sets files, and returns a pre-unlocked handle.
    pub fn execute(mut self) -> Result<(VaultHandle, CeremonySecrets), BaluardError> {
        let mut ep: Box<dyn EntropyProvider> = match self.entropy.take() {
            Some(e) => e,
            None => Box::new(OsEntropy),
        };

        let path = self.path.clone();
        let write_secret = |file_path: &Path, data: &[u8]| -> Result<(), BaluardError> {
            std::fs::write(file_path, data).map_err(|e| {
                BaluardError::from(VaultError::Corrupt(format!(
                    "Write {}: {e}",
                    file_path.display()
                )))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!(
                            "chmod {}: {e}",
                            file_path.display()
                        )))
                    })?;
            }
            Ok(())
        };

        match &self.mode {
            CeremonyMode::Create => {
                if path.join("meta/kdf-params.json").exists() {
                    return Err(VaultError::AlreadyExists(path.display().to_string()).into());
                }

                let device_id = ep.generate_uuid();

                let mut adapter = RngAdapter { provider: &mut *ep };

                std::fs::create_dir_all(path.join("ciphers")).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("mkdir ciphers: {e}")))
                })?;
                std::fs::create_dir_all(path.join("meta/keywrap")).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("mkdir keywrap: {e}")))
                })?;
                std::fs::create_dir_all(path.join("meta/sequences")).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("mkdir sequences: {e}")))
                })?;
                std::fs::create_dir_all(path.join("trash")).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("mkdir trash: {e}")))
                })?;

                let kdf_params = kdf::create_params(self.kdf_profile.clone());
                let vault_id = VaultHandle::derive_vault_id(&kdf_params);
                let mut kek = kdf::derive_kek(&self.password, &kdf_params)?;

                let mut root_key_bytes = [0u8; 64];
                adapter.fill_bytes(&mut root_key_bytes);
                let root_key = RootKey::from_bytes(root_key_bytes);
                root_key_bytes.zeroize();

                let device_x25519_secret =
                    x25519_dalek::StaticSecret::random_from_rng(&mut adapter);
                let device_x25519_public = x25519_dalek::PublicKey::from(&device_x25519_secret);
                let device_ed25519_signing = ed25519_dalek::SigningKey::generate(&mut adapter);

                let wrapped_root_key =
                    hpke_wrap::wrap_key(root_key.as_bytes(), &device_x25519_public)?;

                let session_key = hkdf_derive::derive_session_key(&kek)?;
                let sync_key = hkdf_derive::derive_sync_key(&kek)?;
                kek.zeroize();

                let recovery_phrase = RecoveryPhrase::generate_with_rng(&mut adapter)?;
                let mut recovery_key = recovery_phrase.derive_key();
                let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
                    <[u8; 32]>::try_from(&recovery_key[..32]).unwrap(),
                );
                recovery_key.zeroize();
                let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);
                let wrapped_recovery_key =
                    hpke_wrap::wrap_key(root_key.as_bytes(), &recovery_x25519_public)?;

                let mut hasher = Sha256::new();
                hasher.update(root_key.as_bytes());
                let trust_fingerprint: [u8; 32] = hasher.finalize().into();

                // Canaries
                let canary_nonce = crate::crypto::aead::build_nonce(0, vault_id);
                let canary_header = crate::types::EnvelopeHeader {
                    version: crate::BALUARD_VERSION,
                    alg_id: crate::ALG_AES_256_GCM,
                    key_epoch: 0,
                    nonce_counter: 0,
                    update_seq: 0,
                    tier: None,
                };
                let canary_envelope = crate::crypto::aead::encrypt(
                    &session_key,
                    b"baluard-kek-ok",
                    b"baluard-kek-canary-v1",
                    &canary_nonce,
                    canary_header,
                )?;
                let kek_canary = crate::vault::envelope::serialize(&canary_envelope)?;

                let mut rk_canary_key = {
                    use hkdf::Hkdf;
                    use sha2::Sha256;
                    let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
                    let mut key = [0u8; 32];
                    hkdf.expand(b"baluard-rk-canary-v1", &mut key).unwrap();
                    key
                };
                let rk_canary_nonce = crate::crypto::aead::build_nonce(0, vault_id);
                let rk_canary_header = crate::types::EnvelopeHeader {
                    version: crate::BALUARD_VERSION,
                    alg_id: crate::ALG_AES_256_GCM,
                    key_epoch: 1,
                    nonce_counter: 0,
                    update_seq: 0,
                    tier: None,
                };
                let rk_canary_envelope = crate::crypto::aead::encrypt(
                    &rk_canary_key,
                    b"baluard-rk-ok",
                    b"baluard-rk-canary-v1",
                    &rk_canary_nonce,
                    rk_canary_header,
                )?;
                let rk_canary = crate::vault::envelope::serialize(&rk_canary_envelope)?;
                rk_canary_key.zeroize();

                let mut registry = crate::devices::DeviceRegistry::new();
                let pub_enc = device_x25519_public;
                let verifying = device_ed25519_signing.verifying_key();
                registry.enroll_with_id(
                    device_id,
                    self.device_name.clone(),
                    pub_enc.to_bytes(),
                    verifying.to_bytes(),
                    None, // First device: no approver
                )?;

                // Write Files
                write_secret(
                    &path.join("meta/devices.json"),
                    serde_json::to_string_pretty(&registry).unwrap().as_bytes(),
                )?;

                write_secret(
                    &path.join("meta/kdf-params.json"),
                    serde_json::to_string_pretty(&kdf_params)
                        .unwrap()
                        .as_bytes(),
                )?;

                let keywrap_data = serde_json::json!({
                    "device_id": device_id.to_string(),
                    "ephemeral_public": hex::encode(wrapped_root_key.0),
                    "encrypted_key": hex::encode(wrapped_root_key.1),
                    "tag": hex::encode(wrapped_root_key.2),
                });
                write_secret(
                    &path.join(format!("meta/keywrap/{device_id}.json")),
                    serde_json::to_string_pretty(&keywrap_data)
                        .unwrap()
                        .as_bytes(),
                )?;

                let recovery_data = serde_json::json!({
                    "ephemeral_public": hex::encode(wrapped_recovery_key.0),
                    "encrypted_key": hex::encode(wrapped_recovery_key.1),
                    "tag": hex::encode(wrapped_recovery_key.2),
                });
                write_secret(
                    &path.join("meta/recovery.json"),
                    serde_json::to_string_pretty(&recovery_data)
                        .unwrap()
                        .as_bytes(),
                )?;

                if let Some(keystore) = self.keystore {
                    keystore
                        .store_secret("device_x25519_secret", &device_x25519_secret.to_bytes())?;
                    keystore.store_secret(
                        "device_ed25519_signing",
                        &device_ed25519_signing.to_bytes(),
                    )?;
                } else {
                    let mut x25519_hex = hex::encode(device_x25519_secret.to_bytes());
                    let mut ed25519_hex = hex::encode(device_ed25519_signing.to_bytes());
                    let mut json_str = format!(
                        "{{\n  \"x25519_private\": \"{}\",\n  \"ed25519_private\": \"{}\"\n}}",
                        x25519_hex, ed25519_hex
                    );
                    write_secret(&path.join("meta/device-privkey.json"), json_str.as_bytes())?;
                    x25519_hex.zeroize();
                    ed25519_hex.zeroize();
                    json_str.zeroize();
                }

                write_secret(&path.join("meta/kek-canary.enc"), &kek_canary)?;
                write_secret(&path.join("meta/rk-canary.enc"), &rk_canary)?;

                // Write .baluard marker file (vault detection, not secret)
                if let Some(ref slug) = self.slug {
                    // Validate slug at library boundary
                    crate::vault::slug::validate_slug(slug).map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!("invalid slug: {e}")))
                    })?;
                    let marker = crate::vault::registry::BaluardMarker::new(
                        vault_id,
                        slug,
                    );
                    marker.write_to_vault(&path)?;
                }

                // Initialize Git Sync Repo if required
                #[cfg(feature = "git-sync")]
                if self.initialize_git {
                    let engine = crate::sync::engine::SyncEngine::new(&path, &self.device_name);
                    let _ = engine.init_repo()?;
                }

                #[cfg(not(feature = "git-sync"))]
                {
                    std::fs::write(
                        path.join(".gitignore"),
                        "# Secrets - never push these\nmeta/device-privkey.json\nmeta/kdf-attempts.json\n",
                    ).map_err(|e| BaluardError::from(VaultError::Corrupt(format!("Write gitignore: {e}"))))?;
                }

                let mut device_manager = DeviceManager::new();
                device_manager.set_vault_path(&path);
                device_manager
                    .epoch
                    .activate()
                    .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
                // H6 fix: sync registry so device_manager.is_enrolled() works
                device_manager.registry = registry.clone();

                let handle = VaultHandle {
                    path: path.clone(),
                    vault_id,
                    kdf_params,
                    registry,
                    device_id,
                    device_manager,
                    state: VaultState::Unlocked(UnlockedState {
                        root_key: root_key.clone(),
                        space_group_key:
                            crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                                &root_key, 1,
                            ),
                        session_key,
                        sync_key,
                        item_keys: HashMap::new(),
                        current_epoch: 1,
                    }),
                };

                let secrets = CeremonySecrets {
                    recovery_phrase,
                    trust_fingerprint,
                    device_id,
                    vault_id,
                };

                // Apply wizard profile + preferences
                self.apply_wizard_settings(&handle)?;

                Ok((handle, secrets))
            }
            CeremonyMode::Join {
                recovery_phrase: phrase_str,
            } => {
                let kdf_path = path.join("meta/kdf-params.json");
                if !kdf_path.exists() {
                    return Err(VaultError::NotFound(kdf_path.display().to_string()).into());
                }

                let kdf_json = std::fs::read_to_string(&kdf_path).map_err(|e| {
                    BaluardError::from(VaultError::Metadata(format!("reading kdf params: {e}")))
                })?;
                let kdf_params: KdfParams = serde_json::from_str(&kdf_json).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("kdf params: {e}")))
                })?;

                let mut kek = kdf::derive_kek(&self.password, &kdf_params)?;
                let session_key = hkdf_derive::derive_session_key(&kek)?;
                let sync_key = hkdf_derive::derive_sync_key(&kek)?;
                kek.zeroize();

                let kek_canary_path = path.join("meta/kek-canary.enc");
                if !kek_canary_path.exists() {
                    return Err(VaultError::NotFound("meta/kek-canary.enc".into()).into());
                }
                let canary_data = std::fs::read(&kek_canary_path).map_err(|e| {
                    BaluardError::from(VaultError::Metadata(format!("reading kek canary: {e}")))
                })?;
                let canary_envelope = crate::vault::envelope::deserialize(&canary_data)?;
                let canary_pt = crate::crypto::aead::decrypt(&session_key, &canary_envelope)
                    .map_err(|_| {
                        BaluardError::from(VaultError::Corrupt("master password incorrect".into()))
                    })?;
                if canary_pt != b"baluard-kek-ok" {
                    return Err(VaultError::Corrupt("master password incorrect".into()).into());
                }

                let recovery_json_str = std::fs::read_to_string(path.join("meta/recovery.json"))
                    .map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!(
                            "reading recovery wrapped key: {e}"
                        )))
                    })?;
                let recovery_json: serde_json::Value = serde_json::from_str(&recovery_json_str)
                    .map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!("recovery json format: {e}")))
                    })?;

                let eph_pub = hex::decode(recovery_json["ephemeral_public"].as_str().unwrap_or(""))
                    .map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!("recovery eph_public: {e}")))
                    })?;
                let ct = hex::decode(recovery_json["encrypted_key"].as_str().unwrap_or(""))
                    .map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!(
                            "recovery encrypted key: {e}"
                        )))
                    })?;
                let tag_hex = recovery_json["tag"].as_str().unwrap_or("");
                let mut tag = [0u8; 16];
                let tag_bytes = hex::decode(tag_hex).map_err(|e| {
                    BaluardError::from(VaultError::Corrupt(format!("recovery tag hex: {e}")))
                })?;
                if tag_bytes.len() != 16 {
                    return Err(VaultError::Corrupt("invalid tag length".into()).into());
                }
                tag.copy_from_slice(&tag_bytes);

                let recovery_phrase_obj = RecoveryPhrase::from_phrase(phrase_str)?;
                let mut recovery_key_bytes = recovery_phrase_obj.derive_key();
                let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
                    <[u8; 32]>::try_from(&recovery_key_bytes[..32]).unwrap(),
                );
                recovery_key_bytes.zeroize();

                let root_key_bytes =
                    hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, &recovery_x25519_secret)?;
                let root_key_arr: [u8; 64] = root_key_bytes.try_into().map_err(|_| {
                    BaluardError::from(VaultError::Corrupt(
                        "unwrapped root key not 64 bytes".into(),
                    ))
                })?;
                let root_key = RootKey::from_bytes(root_key_arr);

                let rk_canary_path = path.join("meta/rk-canary.enc");
                if !rk_canary_path.exists() {
                    return Err(VaultError::NotFound("meta/rk-canary.enc".into()).into());
                }
                let rk_canary_data = std::fs::read(&rk_canary_path).map_err(|e| {
                    BaluardError::from(VaultError::Metadata(format!("reading rk canary: {e}")))
                })?;
                let rk_canary_envelope = crate::vault::envelope::deserialize(&rk_canary_data)?;
                let mut rk_canary_key = {
                    use hkdf::Hkdf;
                    use sha2::Sha256;
                    let hkdf = Hkdf::<Sha256>::new(None, root_key.as_bytes());
                    let mut key = [0u8; 32];
                    hkdf.expand(b"baluard-rk-canary-v1", &mut key).unwrap();
                    key
                };
                let rk_canary_pt = crate::crypto::aead::decrypt(
                    &rk_canary_key,
                    &rk_canary_envelope,
                )
                .map_err(|_| {
                    BaluardError::from(VaultError::Corrupt("root key verification failed".into()))
                })?;
                rk_canary_key.zeroize();
                if rk_canary_pt != b"baluard-rk-ok" {
                    return Err(VaultError::Corrupt("root key verification failed".into()).into());
                }

                let registry_path = path.join("meta/devices.json");
                let mut registry = if registry_path.exists() {
                    let reg_json = std::fs::read_to_string(&registry_path).map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!("reading devices: {e}")))
                    })?;
                    serde_json::from_str(&reg_json).map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!("devices: {e}")))
                    })?
                } else {
                    crate::devices::DeviceRegistry::new()
                };

                let device_id = ep.generate_uuid();
                let mut adapter = RngAdapter { provider: &mut *ep };
                let device_x25519_secret =
                    x25519_dalek::StaticSecret::random_from_rng(&mut adapter);
                let device_x25519_public = x25519_dalek::PublicKey::from(&device_x25519_secret);
                let device_ed25519_signing = ed25519_dalek::SigningKey::generate(&mut adapter);

                let _entry = registry.enroll_with_id(
                    device_id,
                    self.device_name.clone(),
                    device_x25519_public.to_bytes(),
                    device_ed25519_signing.verifying_key().to_bytes(),
                    None, // First device: no approver
                )?;

                write_secret(
                    &registry_path,
                    serde_json::to_string_pretty(&registry).unwrap().as_bytes(),
                )?;

                let wrapped_root_key =
                    hpke_wrap::wrap_key(root_key.as_bytes(), &device_x25519_public)?;
                let keywrap_data = serde_json::json!({
                    "device_id": device_id.to_string(),
                    "ephemeral_public": hex::encode(wrapped_root_key.0),
                    "encrypted_key": hex::encode(wrapped_root_key.1),
                    "tag": hex::encode(wrapped_root_key.2),
                });
                write_secret(
                    &path.join(format!("meta/keywrap/{device_id}.json")),
                    serde_json::to_string_pretty(&keywrap_data)
                        .unwrap()
                        .as_bytes(),
                )?;

                if let Some(keystore) = self.keystore {
                    keystore
                        .store_secret("device_x25519_secret", &device_x25519_secret.to_bytes())?;
                    keystore.store_secret(
                        "device_ed25519_signing",
                        &device_ed25519_signing.to_bytes(),
                    )?;
                } else {
                    let mut x25519_hex = hex::encode(device_x25519_secret.to_bytes());
                    let mut ed25519_hex = hex::encode(device_ed25519_signing.to_bytes());
                    let mut json_str = format!(
                        "{{\n  \"x25519_private\": \"{}\",\n  \"ed25519_private\": \"{}\"\n}}",
                        x25519_hex, ed25519_hex
                    );
                    write_secret(&path.join("meta/device-privkey.json"), json_str.as_bytes())?;
                    x25519_hex.zeroize();
                    ed25519_hex.zeroize();
                    json_str.zeroize();
                }

                let mut hasher = Sha256::new();
                hasher.update(root_key.as_bytes());
                let trust_fingerprint: [u8; 32] = hasher.finalize().into();

                let vault_id = VaultHandle::derive_vault_id(&kdf_params);

                let mut device_manager = DeviceManager::new();
                device_manager.set_vault_path(&path);
                device_manager
                    .epoch
                    .activate()
                    .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
                // H6 fix: sync registry so device_manager.is_enrolled() works
                device_manager.registry = registry.clone();

                let handle = VaultHandle {
                    path: path.clone(),
                    vault_id,
                    kdf_params,
                    registry,
                    device_id,
                    device_manager,
                    state: VaultState::Unlocked(UnlockedState {
                        root_key: root_key.clone(),
                        space_group_key:
                            crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                                &root_key, 1,
                            ),
                        session_key,
                        sync_key,
                        item_keys: HashMap::new(),
                        current_epoch: 1,
                    }),
                };

                let secrets = CeremonySecrets {
                    recovery_phrase: recovery_phrase_obj,
                    trust_fingerprint,
                    device_id,
                    vault_id,
                };

                // Apply wizard profile + preferences
                self.apply_wizard_settings(&handle)?;

                Ok((handle, secrets))
            }
        }
    }

    /// Apply wizard profile + preferences to a freshly created vault.
    fn apply_wizard_settings(&self, handle: &VaultHandle) -> Result<(), BaluardError> {
        let has_profile = self.display_name.is_some() || self.subtitle.is_some();
        let has_prefs = self.theme.is_some()
            || self.lang.is_some()
            || self.auto_lock_minutes.is_some()
            || self.slug.is_some();

        if has_profile {
            let profile = crate::vault::manifest::UserProfile {
                display_name: self.display_name.clone(),
                subtitle: self.subtitle.clone(),
                avatar_ext: None,
            };
            handle.save_profile_and_strip_settings(&profile)?;
        }

        if has_prefs {
            let mut settings = handle.get_settings().unwrap_or_default();
            if let Some(ref theme) = self.theme {
                settings.theme = Some(*theme);
            }
            if let Some(ref lang) = self.lang {
                settings.lang = Some(lang.clone());
            }
            if let Some(auto_lock) = self.auto_lock_minutes {
                settings.auto_lock_minutes = Some(auto_lock);
            }
            if let Some(ref slug) = self.slug {
                settings.slug = Some(slug.clone());
            }
            handle.save_settings(&settings)?;
        }

        if let Some(ref lang) = self.lang {
            handle.save_locale(lang)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_vault_ceremony_completes() {
        let result = create_vault_ceremony("test-master-password", KdfProfile::MobileLow).unwrap();

        assert!(!result.vault_id.is_nil());
        assert_eq!(result.epoch_info.epoch, 1);
        assert_eq!(result.root_key.as_bytes().len(), 64);
        assert_eq!(result.session_key.len(), 32);
        assert_eq!(result.sync_key.len(), 32);
        assert_eq!(result.trust_fingerprint.len(), 32);

        let binding = result.recovery_phrase.phrase();
        assert_eq!(binding.split(' ').count(), 24);
    }

    #[test]
    fn wrapped_root_key_unwraps_correctly() {
        let result = create_vault_ceremony("test-password", KdfProfile::MobileLow).unwrap();
        let (eph_pub, ct, tag) = &result.wrapped_root_key;

        let unwrapped =
            hpke_wrap::unwrap_key(eph_pub, ct, tag, &result.device_x25519_secret).unwrap();
        assert_eq!(unwrapped.as_slice(), result.root_key.as_bytes());
    }

    #[test]
    fn recovery_key_unwraps_correctly() {
        let result = create_vault_ceremony("test-password", KdfProfile::MobileLow).unwrap();
        let (eph_pub, ct, tag) = &result.wrapped_recovery_key;

        let recovery_key_bytes = result.recovery_phrase.derive_key();
        let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&recovery_key_bytes[..32]).unwrap(),
        );

        let unwrapped = hpke_wrap::unwrap_key(eph_pub, ct, tag, &recovery_x25519_secret).unwrap();
        assert_eq!(unwrapped.as_slice(), result.root_key.as_bytes());
    }

    #[test]
    fn different_passwords_different_keys() {
        let r1 = create_vault_ceremony("password-1", KdfProfile::MobileLow).unwrap();
        let r2 = create_vault_ceremony("password-2", KdfProfile::MobileLow).unwrap();
        assert_ne!(r1.session_key, r2.session_key);
        assert_ne!(r1.sync_key, r2.sync_key);
    }

    // ── NEW BULDER TESTS ──

    struct DeterministicEntropy {
        val: u8,
    }

    impl EntropyProvider for DeterministicEntropy {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for x in dest.iter_mut() {
                *x = self.val;
            }
        }
        fn generate_uuid(&mut self) -> Uuid {
            Uuid::from_bytes([self.val; 16])
        }
    }

    #[test]
    fn test_vault_creator_builder_flow() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("my_new_vault");

        let (handle, secrets) = VaultCreator::new(&path, "master-pass", "StandardDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .entropy(DeterministicEntropy { val: 7 })
            .execute()
            .unwrap();

        assert!(handle.is_unlocked());
        assert_eq!(secrets.device_id.into_bytes(), [7u8; 16]);
        assert_ne!(secrets.vault_id.into_bytes(), [0u8; 16]);
        assert_eq!(secrets.recovery_phrase.phrase().split(' ').count(), 24);

        assert!(path.join("meta/kdf-params.json").exists());
        assert!(path.join("meta/devices.json").exists());
        assert!(path.join("meta/device-privkey.json").exists());
        assert!(path.join("meta/recovery.json").exists());
        assert!(path.join("meta/kek-canary.enc").exists());
        assert!(path.join("meta/rk-canary.enc").exists());

        // Now let's join on a second device using the recovery phrase
        let join_path = path.clone();
        let phrase_str = secrets.recovery_phrase.phrase();

        let (join_handle, join_secrets) =
            VaultCreator::new(&join_path, "master-pass", "SecondDevice")
                .kdf_profile(KdfProfile::MobileLow)
                .mode(CeremonyMode::Join {
                    recovery_phrase: phrase_str,
                })
                .initialize_git(false)
                .entropy(DeterministicEntropy { val: 9 })
                .execute()
                .unwrap();

        assert!(join_handle.is_unlocked());
        assert_eq!(join_secrets.device_id.into_bytes(), [9u8; 16]);
        assert_eq!(join_secrets.vault_id, secrets.vault_id); // matches initial vault ID!
    }

    #[test]
    fn test_vault_creator_with_profile_and_prefs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiled_vault");

        let (handle, _secrets) = VaultCreator::new(&path, "master-pass", "TestDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .entropy(DeterministicEntropy { val: 42 })
            .profile(
                Some("Esteban".into()),
                Some("Lead Architect".into()),
            )
            .preferences(
                Some(crate::types::ThemeMode::Dark),
                Some("es".into()),
                Some(30),
            )
            .execute()
            .unwrap();

        // Verify profile
        let profile = handle.load_profile().unwrap();
        assert_eq!(profile.display_name.as_deref(), Some("Esteban"));
        assert_eq!(profile.subtitle.as_deref(), Some("Lead Architect"));

        // Verify settings
        let settings = handle.get_settings().unwrap();
        assert_eq!(settings.theme, Some(crate::types::ThemeMode::Dark));
        assert_eq!(settings.lang.as_deref(), Some("es"));
        assert_eq!(settings.auto_lock_minutes, Some(30));

        // Verify locale file
        assert_eq!(handle.load_locale().as_deref(), Some("es"));
        assert!(path.join("meta/locale").exists());
    }

    #[test]
    fn test_vault_creator_without_wizard_fields() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("minimal_vault");

        let (handle, _secrets) = VaultCreator::new(&path, "master-pass", "TestDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .entropy(DeterministicEntropy { val: 11 })
            .execute()
            .unwrap();

        // No profile, no prefs, no locale file
        let profile = handle.load_profile().unwrap();
        assert!(profile.display_name.is_none());
        assert!(profile.subtitle.is_none());

        let settings = handle.get_settings().unwrap();
        assert!(settings.theme.is_none());
        assert!(settings.lang.is_none());
        assert!(settings.auto_lock_minutes.is_none());

        assert!(handle.load_locale().is_none());
        assert!(!path.join("meta/locale").exists());
    }
}
