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
#[deprecated(
    since = "0.2.0",
    note = "Use VaultCreator builder instead. This function will be removed in a future release."
)]
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
    let wrapped_root_key = hpke_wrap::wrap_key(
        root_key.as_bytes(),
        &device_x25519_public,
        "root-key-keywrap",
    )?;

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
    let wrapped_recovery_key = hpke_wrap::wrap_key(
        root_key.as_bytes(),
        &recovery_x25519_public,
        "recovery-keywrap",
    )?;

    // Step 8: Trust anchor fingerprint (SHA-256 of Root Key)
    let mut hasher = Sha256::new();
    hasher.update(root_key.as_bytes());
    let trust_fingerprint = hasher.finalize().into();

    // Step 9: KEK canary (encrypted with Session Key for password verification)
    let kek_canary = super::canary::create_kek_canary(&session_key, vault_id)?;

    // Step 10: Root Key canary (encrypted with RK-derived key for Root Key verification)
    let rk_canary = super::canary::create_rk_canary(&root_key, vault_id, 1)?;

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
pub trait SecureKeystore: Send + Sync {
    fn store_secret(&self, key: &str, secret: &[u8]) -> Result<(), BaluardError>;
    fn get_secret(&self, key: &str) -> Result<Vec<u8>, BaluardError>;
}

static GLOBAL_KEYSTORE: std::sync::RwLock<Option<std::sync::Arc<dyn SecureKeystore>>> =
    std::sync::RwLock::new(None);

pub fn set_global_keystore(keystore: std::sync::Arc<dyn SecureKeystore>) {
    if let Ok(mut lock) = GLOBAL_KEYSTORE.write() {
        *lock = Some(keystore);
    }
}

pub fn get_global_keystore() -> Option<std::sync::Arc<dyn SecureKeystore>> {
    GLOBAL_KEYSTORE.read().ok().and_then(|lock| lock.clone())
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
    /// Family-spaces section 7: the family kit phrase, shown exactly
    /// once at creation. `None` on personal vaults and on resumed
    /// family runs whose kit already exists.
    pub kit_phrase: Option<zeroize::Zeroizing<String>>,
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
    vault_timeout: Option<crate::vault::manifest::VaultTimeout>,
    /// Family-spaces §13: create the vault AS a family vault (purpose,
    /// Shared + Guardians, team-shape flip) in one transaction.
    family: bool,
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
            vault_timeout: None,
            family: false,
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
        vault_timeout: Option<crate::vault::manifest::VaultTimeout>,
    ) -> Self {
        self.theme = theme;
        self.lang = lang;
        self.vault_timeout = vault_timeout;
        self
    }

    /// Create the vault as a FAMILY vault (plan-family-spaces): stamps
    /// `purpose: family`, creates the `Shared` collection and the
    /// `Guardians` group, and flips to team shape in the same
    /// transaction. The purpose write hard-fails, so a crash never
    /// leaves a team-shaped vault without its purpose.
    pub fn family(mut self, family: bool) -> Self {
        self.family = family;
        self
    }

    /// Executes the ceremony transactionally, sets files, and returns a pre-unlocked handle.
    pub fn execute(mut self) -> Result<(VaultHandle, CeremonySecrets), BaluardError> {
        // A failed Create never showed the recovery phrase, so the
        // directory it scaffolded holds no user data; leaving it behind
        // wedges every re-run behind AlreadyExists. Only a directory we
        // created ourselves is removed — a pre-existing path the user
        // pointed at must survive a failed ceremony untouched.
        // Join/Recover touch an existing vault and are never cleaned up.
        let creating = matches!(self.mode, CeremonyMode::Create);
        let dir_did_not_exist = creating && !self.path.exists();
        let path_for_cleanup = self.path.clone();
        let result = self.execute_inner();
        if dir_did_not_exist && result.is_err() {
            let _ = std::fs::remove_dir_all(&path_for_cleanup);
        }
        result
    }

    fn execute_inner(mut self) -> Result<(VaultHandle, CeremonySecrets), BaluardError> {
        let mut ep: Box<dyn EntropyProvider> = match self.entropy.take() {
            Some(e) => e,
            None => Box::new(OsEntropy),
        };

        let path = self.path.clone();

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

                let wrapped_root_key = hpke_wrap::wrap_key(
                    root_key.as_bytes(),
                    &device_x25519_public,
                    "root-key-keywrap",
                )?;

                let session_key = hkdf_derive::derive_session_key(&kek)?;
                let sync_key = hkdf_derive::derive_sync_key(&kek)?;
                let devkey_seal = hkdf_derive::derive_devkey_seal_key(&kek)?;
                kek.zeroize();

                let recovery_phrase = RecoveryPhrase::generate_with_rng(&mut adapter)?;
                let mut recovery_key = recovery_phrase.derive_key();
                let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
                    <[u8; 32]>::try_from(&recovery_key[..32]).unwrap(),
                );
                recovery_key.zeroize();
                let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);
                let wrapped_recovery_key = hpke_wrap::wrap_key(
                    root_key.as_bytes(),
                    &recovery_x25519_public,
                    "recovery-keywrap",
                )?;

                let mut hasher = Sha256::new();
                hasher.update(root_key.as_bytes());
                let trust_fingerprint: [u8; 32] = hasher.finalize().into();

                // Canaries
                let kek_canary = super::canary::create_kek_canary(&session_key, vault_id)?;
                let rk_canary = super::canary::create_rk_canary(&root_key, vault_id, 1)?;

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
                super::write_vault_file(
                    &path.join("meta/devices.json"),
                    registry.to_deterministic_json().unwrap().as_bytes(),
                )?;

                // S1a: owner membership + founding-device binding, written
                // with the registry BEFORE the initial commit so the
                // roster-snapshot rule resolves roles from the root tree.
                // The identity vk is recorded after the identity is
                // generated below (rotation visibility keys off it).
                let owner_member_id = uuid::Uuid::new_v4();
                let owner_member = crate::vault::members::MemberFile {
                    id: owner_member_id,
                    display_name: self.display_name.clone().unwrap_or_else(|| "Owner".into()),
                    email: None,
                    role: crate::vault::members::MemberRole::Owner,
                    trust: crate::vault::members::TrustLevel::SelfTrust,
                    identity_signing_pubkey: None,
                    identity_signing_pubkey_previous: None,
                    identity_rotation_signature: None,
                    identity_rotated_at: None,
                    reset: None,
                    removed: None,
                    removed_reason: None,
                    transport_username: None,
                    identity_wrap_pubkey: None,
                };
                crate::vault::members::write_member(&path, &owner_member)?;
                crate::vault::members::write_device_binding(
                    &path,
                    &crate::vault::members::DeviceBinding {
                        device_id,
                        member_id: owner_member.id,
                    },
                )?;

                super::write_vault_file(
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
                super::write_vault_file(
                    &path.join(format!("meta/keywrap/{device_id}.json")),
                    serde_json::to_string_pretty(&keywrap_data)
                        .unwrap()
                        .as_bytes(),
                )?;

                let recovery_data = serde_json::json!({
                    "ephemeral_public": hex::encode(wrapped_recovery_key.0),
                    "encrypted_key": hex::encode(wrapped_recovery_key.1),
                    "tag": hex::encode(wrapped_recovery_key.2),
                    // H4 fix: store recovery X25519 public key for re-wrapping on rotation
                    "recovery_x25519_pubkey": hex::encode(recovery_x25519_public.as_bytes()),
                });
                super::write_vault_file(
                    &path.join("meta/recovery.json"),
                    serde_json::to_string_pretty(&recovery_data)
                        .unwrap()
                        .as_bytes(),
                )?;

                if let Some(keystore) = self.keystore {
                    let privkey_json = serde_json::json!({
                        "x25519_private": hex::encode(device_x25519_secret.to_bytes()),
                        "ed25519_private": hex::encode(device_ed25519_signing.to_bytes()),
                    });
                    let json_bytes = serde_json::to_vec(&privkey_json).unwrap_or_default();
                    keystore.store_secret(&device_id.to_string(), &json_bytes)?;
                    keystore.store_secret(&format!("device:{device_id}"), &json_bytes)?;
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
                        "{{\n  \"device_id\": \"{}\",\n  \"x25519_private\": \"{}\",\n  \"ed25519_private\": \"{}\"\n}}",
                        device_id, x25519_hex, ed25519_hex
                    );
                    // C1: seal under the KEK-derived subkey; raw hex keys
                    // never touch disk in new vaults.
                    super::device_privkey::seal_file(
                        &path.join("meta/device-privkey.json"),
                        &json_str,
                        &devkey_seal,
                        Some(device_id),
                    )?;
                    let _ = super::device_privkey::write_device_id(&path, device_id);
                    x25519_hex.zeroize();
                    ed25519_hex.zeroize();
                    json_str.zeroize();
                }

                super::write_vault_file(&path.join("meta/kek-canary.enc"), &kek_canary)?;
                super::write_vault_file(&path.join("meta/rk-canary.enc"), &rk_canary)?;

                // P1a: per-human identity — generated here, sealed under a
                // wrapping key that is NEVER the vault KEK (OS keystore random
                // key, or the WARNED Argon2id fallback on keystore-less
                // systems), and HPKE-escrowed to the recovery pubkey so
                // phrase recovery restores the identity.
                let identity_keys = crate::vault::identity::IdentityKeys::generate()?;
                let (identity_wrap_key, seal_mode, salt_hex) = match self.keystore {
                    Some(keystore) => {
                        let mut wrap_key = [0u8; 32];
                        adapter.fill_bytes(&mut wrap_key);
                        keystore.store_secret(&format!("identity:{vault_id}"), &wrap_key)?;
                        (wrap_key, "keystore", None)
                    }
                    None => {
                        // WARNED fallback (keystore-less systems): Argon2id
                        // over the master password with a dedicated salt —
                        // never the vault KEK. The downgrade is visible in
                        // meta/identity-meta.json.
                        let mut salt = [0u8; 32];
                        adapter.fill_bytes(&mut salt);
                        let mut params = kdf::create_params(KdfProfile::MobileLow);
                        params.salt = salt.to_vec();
                        let wrap_key = kdf::derive_kek(&self.password, &params)?;
                        (wrap_key, "passphrase", Some(hex::encode(salt)))
                    }
                };
                let identity_sealed =
                    crate::vault::identity::seal_identity(&identity_wrap_key, &identity_keys)?;
                super::write_vault_file(&path.join("meta/identity.enc"), &identity_sealed)?;
                let (escrow_eph, escrow_ct, escrow_tag) = crate::crypto::hpke_wrap::wrap_key(
                    &identity_keys.seed(),
                    &recovery_x25519_public,
                    "identity-escrow",
                )?;
                let identity_escrow = serde_json::json!({
                    "ephemeral_public": hex::encode(escrow_eph),
                    "encrypted_key": hex::encode(escrow_ct),
                    "tag": hex::encode(escrow_tag),
                });
                super::write_vault_file(
                    &path.join("meta/identity-escrow.json"),
                    serde_json::to_string_pretty(&identity_escrow)
                        .unwrap()
                        .as_bytes(),
                )?;
                let identity_meta = serde_json::json!({
                    "mode": seal_mode,
                    "salt_hex": salt_hex,
                    "memory_kib": kdf::create_params(KdfProfile::MobileLow).memory_kib,
                    "time_cost": kdf::create_params(KdfProfile::MobileLow).time_cost,
                    "parallelism": 1,
                    "keystore_key": format!("identity:{vault_id}"),
                    "recovery_pubkey_hex": hex::encode(recovery_x25519_public.as_bytes()),
                });
                super::write_vault_file(
                    &path.join("meta/identity-meta.json"),
                    serde_json::to_string_pretty(&identity_meta)
                        .unwrap()
                        .as_bytes(),
                )?;

                // S1a-4: record the owner's identity signing pubkey in the
                // member record (rotation visibility keys off this field).
                // The member file was written before the identity was
                // generated; rewrite it with the vk now — still before the
                // initial commit, so the root tree carries it.
                let mut owner_member: crate::vault::members::MemberFile = serde_json::from_str(
                    &std::fs::read_to_string(
                        path.join("meta/members")
                            .join(format!("{owner_member_id}.json")),
                    )
                    .map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!("read owner member: {e}")))
                    })?,
                )
                .map_err(|e| {
                    BaluardError::from(VaultError::Metadata(format!("parse owner member: {e}")))
                })?;
                owner_member.identity_signing_pubkey = Some(hex::encode(
                    identity_keys.signing_key().verifying_key().as_bytes(),
                ));
                // P1: the owner's wrap pubkey rides the genesis record so
                // grants to the owner mint per-member wraps immediately.
                owner_member.identity_wrap_pubkey =
                    Some(hex::encode(identity_keys.wrapping_pub_bytes()));
                crate::vault::members::write_member(&path, &owner_member)?;

                // Write .baluard marker file (vault detection, not secret).
                // Required for discover_orphans / vaults.detach / registry
                // self-heal. Always written: when a slug is set it is validated
                // and stored; when omitted (test fixtures, direct CLI without
                // --slug) an empty slug is stored and orphan discovery falls
                // back to the directory name (registry::discover_orphans).
                // Rotation artifacts live under meta/rekey/, so there is no
                // file/dir collision on this path.
                let slug = self.slug.as_deref().unwrap_or("");
                if !slug.is_empty() {
                    crate::vault::slug::validate_slug(slug).map_err(|e| {
                        BaluardError::from(VaultError::Corrupt(format!("invalid slug: {e}")))
                    })?;
                }
                let marker = crate::vault::registry::BaluardMarker::new(vault_id, slug);
                marker.write_to_vault(&path)?;

                // Persist DeviceManager state (meta/devices.json) BEFORE the
                // initial commit: the roster-snapshot rule verifies a root
                // commit against its own tree, so the registry must be part
                // of it (P2). The signing key (sealed privkey, written above)
                // is already on disk, so init_repo's initial commit is signed.
                let mut device_manager = DeviceManager::new();
                device_manager.set_vault_path(&path);
                device_manager.epoch = crate::keys::epoch::EpochInfo::new(1);
                device_manager.epoch.activate().map_err(|e| {
                    BaluardError::from(crate::error::KeyError::InvalidEpochState(e))
                })?;
                // H6 fix: sync registry so device_manager.is_enrolled() works
                device_manager.registry = registry.clone();
                // Persist DeviceManager state so VaultHandle::open() can reload it
                device_manager.save_to_vault()?;

                // Initialize Git Sync Repo if required
                #[cfg(feature = "git-sync")]
                if self.initialize_git {
                    let engine = crate::sync::engine::SyncEngine::new(
                        &path,
                        &self.device_name,
                        Some(&devkey_seal),
                    );
                    let _ = engine.init_repo()?;
                }

                #[cfg(not(feature = "git-sync"))]
                {
                    std::fs::write(
                        path.join(".gitignore"),
                        "# Secrets - never push these\nmeta/device-privkey.json\nmeta/device-id\nmeta/kdf-attempts.json\n",
                    ).map_err(|e| BaluardError::from(VaultError::Corrupt(format!("Write gitignore: {e}"))))?;
                }

                let mut handle = VaultHandle {
                    path: path.clone(),
                    vault_id,
                    kdf_params,
                    registry,
                    device_id,
                    device_manager,
                    quorum_satisfied: std::sync::Mutex::new(None),
                    state: VaultState::Unlocked(UnlockedState {
                        root_key: Some(root_key.clone()),
                        space_group_key: Some(
                            crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                                &root_key, 1,
                            ),
                        ),
                        smk: None,
                        session_key,
                        sync_key,
                        devkey_seal,
                        item_keys: HashMap::new(),
                        current_epoch: 1,
                        identity: Some(identity_keys),
                        identity_wrap_key: Some(zeroize::Zeroizing::new(identity_wrap_key)),
                    }),
                };

                let mut secrets = CeremonySecrets {
                    recovery_phrase,
                    trust_fingerprint,
                    device_id,
                    vault_id,
                    kit_phrase: None,
                };

                // Apply wizard profile + preferences
                self.apply_wizard_settings(&handle)?;

                // Family transaction runs LAST: purpose -> Shared +
                // Guardians -> flip -> kit, so a failure above leaves a
                // plain personal vault and a failure below leaves a
                // resumable family vault (setup_family_vault is
                // idempotent).
                if self.family {
                    let (_, kit) = super::family::setup_family_vault(&mut handle)?;
                    secrets.kit_phrase = kit.map(zeroize::Zeroizing::new);
                }

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
                let devkey_seal = hkdf_derive::derive_devkey_seal_key(&kek)?;
                kek.zeroize();

                let kek_canary_path = path.join("meta/kek-canary.enc");
                if !kek_canary_path.exists() {
                    return Err(VaultError::NotFound("meta/kek-canary.enc".into()).into());
                }
                let canary_data = std::fs::read(&kek_canary_path).map_err(|e| {
                    BaluardError::from(VaultError::Metadata(format!("reading kek canary: {e}")))
                })?;
                super::canary::verify_kek_canary(&session_key, &canary_data).map_err(|_| {
                    BaluardError::from(VaultError::Corrupt("master password incorrect".into()))
                })?;

                let recovery_json_str = std::fs::read_to_string(path.join("meta/recovery.json"))
                    .map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!(
                            "reading recovery wrapped key: {e}"
                        )))
                    })?;
                let kw = super::keywrap::parse_keywrap_json(&recovery_json_str)?;

                let recovery_phrase_obj = RecoveryPhrase::from_phrase(phrase_str)?;
                let mut recovery_key_bytes = recovery_phrase_obj.derive_key();
                let recovery_x25519_secret = x25519_dalek::StaticSecret::from(
                    <[u8; 32]>::try_from(&recovery_key_bytes[..32]).unwrap(),
                );
                recovery_key_bytes.zeroize();
                let recovery_x25519_public = x25519_dalek::PublicKey::from(&recovery_x25519_secret);

                let root_key_bytes = hpke_wrap::unwrap_key(
                    &kw.ephemeral_public,
                    &kw.encrypted_key,
                    &kw.tag,
                    &recovery_x25519_secret,
                    "recovery-keywrap",
                )?;
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
                super::canary::verify_rk_canary(&root_key, &rk_canary_data)?;

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

                super::write_vault_file(
                    &registry_path,
                    registry.to_deterministic_json().unwrap().as_bytes(),
                )?;

                // S1a: the joining device is the same human as the owner:
                // bind it to the owner member (no-op on legacy vaults
                // without a member directory).
                crate::vault::members::bind_to_owner(&path, device_id)?;

                let wrapped_root_key = hpke_wrap::wrap_key(
                    root_key.as_bytes(),
                    &device_x25519_public,
                    "root-key-keywrap",
                )?;
                let keywrap_data = serde_json::json!({
                    "device_id": device_id.to_string(),
                    "ephemeral_public": hex::encode(wrapped_root_key.0),
                    "encrypted_key": hex::encode(wrapped_root_key.1),
                    "tag": hex::encode(wrapped_root_key.2),
                });
                super::write_vault_file(
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
                        "{{\n  \"device_id\": \"{}\",\n  \"x25519_private\": \"{}\",\n  \"ed25519_private\": \"{}\"\n}}",
                        device_id, x25519_hex, ed25519_hex
                    );
                    // C1: seal under the KEK-derived subkey; raw hex keys
                    // never touch disk in new vaults.
                    super::device_privkey::seal_file(
                        &path.join("meta/device-privkey.json"),
                        &json_str,
                        &devkey_seal,
                        Some(device_id),
                    )?;
                    let _ = super::device_privkey::write_device_id(&path, device_id);
                    x25519_hex.zeroize();
                    ed25519_hex.zeroize();
                    json_str.zeroize();
                }

                let mut hasher = Sha256::new();
                hasher.update(root_key.as_bytes());
                let trust_fingerprint: [u8; 32] = hasher.finalize().into();

                let vault_id = VaultHandle::derive_vault_id(&kdf_params);

                // P1a: identity — same generation/seal/escrow as the other
                // ceremony path.
                let identity_keys = crate::vault::identity::IdentityKeys::generate()?;
                let (identity_wrap_key, seal_mode, salt_hex) = match self.keystore {
                    Some(keystore) => {
                        let mut wrap_key = [0u8; 32];
                        adapter.fill_bytes(&mut wrap_key);
                        keystore.store_secret(&format!("identity:{vault_id}"), &wrap_key)?;
                        (wrap_key, "keystore", None)
                    }
                    None => {
                        let mut salt = [0u8; 32];
                        adapter.fill_bytes(&mut salt);
                        let mut params = kdf::create_params(KdfProfile::MobileLow);
                        params.salt = salt.to_vec();
                        let wrap_key = kdf::derive_kek(&self.password, &params)?;
                        (wrap_key, "passphrase", Some(hex::encode(salt)))
                    }
                };
                let identity_sealed =
                    crate::vault::identity::seal_identity(&identity_wrap_key, &identity_keys)?;
                super::write_vault_file(&path.join("meta/identity.enc"), &identity_sealed)?;
                let (escrow_eph, escrow_ct, escrow_tag) = crate::crypto::hpke_wrap::wrap_key(
                    &identity_keys.seed(),
                    &recovery_x25519_public,
                    "identity-escrow",
                )?;
                let identity_escrow = serde_json::json!({
                    "ephemeral_public": hex::encode(escrow_eph),
                    "encrypted_key": hex::encode(escrow_ct),
                    "tag": hex::encode(escrow_tag),
                });
                super::write_vault_file(
                    &path.join("meta/identity-escrow.json"),
                    serde_json::to_string_pretty(&identity_escrow)
                        .unwrap()
                        .as_bytes(),
                )?;
                let identity_meta = serde_json::json!({
                    "mode": seal_mode,
                    "salt_hex": salt_hex,
                    // The passphrase reader derives from these; omitting
                    // them defaults to 8192 KiB/t=3, which can never
                    // unseal a MobileLow-sealed identity.
                    "memory_kib": kdf::create_params(KdfProfile::MobileLow).memory_kib,
                    "time_cost": kdf::create_params(KdfProfile::MobileLow).time_cost,
                    "parallelism": 1,
                    "keystore_key": format!("identity:{vault_id}"),
                    "recovery_pubkey_hex": hex::encode(recovery_x25519_public.as_bytes()),
                });
                super::write_vault_file(
                    &path.join("meta/identity-meta.json"),
                    serde_json::to_string_pretty(&identity_meta)
                        .unwrap()
                        .as_bytes(),
                )?;

                let mut device_manager = DeviceManager::new();
                device_manager.set_vault_path(&path);
                device_manager.epoch = crate::keys::epoch::EpochInfo::new(1);
                device_manager.epoch.activate().map_err(|e| {
                    BaluardError::from(crate::error::KeyError::InvalidEpochState(e))
                })?;
                // H6 fix: sync registry so device_manager.is_enrolled() works
                device_manager.registry = registry.clone();
                // Persist DeviceManager state so VaultHandle::open() can reload it
                device_manager.save_to_vault()?;

                let mut handle = VaultHandle {
                    path: path.clone(),
                    vault_id,
                    kdf_params,
                    registry,
                    device_id,
                    device_manager,
                    quorum_satisfied: std::sync::Mutex::new(None),
                    state: VaultState::Unlocked(UnlockedState {
                        root_key: Some(root_key.clone()),
                        space_group_key: Some(
                            crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                                &root_key, 1,
                            ),
                        ),
                        smk: None,
                        session_key,
                        sync_key,
                        devkey_seal,
                        item_keys: HashMap::new(),
                        current_epoch: 1,
                        identity: Some(identity_keys),
                        identity_wrap_key: Some(zeroize::Zeroizing::new(identity_wrap_key)),
                    }),
                };

                let secrets = CeremonySecrets {
                    recovery_phrase: recovery_phrase_obj,
                    trust_fingerprint,
                    device_id,
                    vault_id,
                    kit_phrase: None,
                };

                // Apply wizard profile + preferences
                self.apply_wizard_settings(&handle)?;

                // Family transaction runs LAST: purpose -> Shared +
                // Guardians -> flip, so a failure above leaves a plain
                // personal vault and a failure below leaves a resumable
                // family vault (setup_family_vault is idempotent).
                if self.family {
                    super::family::setup_family_vault(&mut handle)?;
                }

                Ok((handle, secrets))
            }
        }
    }

    /// Apply wizard profile + preferences to a freshly created vault.
    fn apply_wizard_settings(&self, handle: &VaultHandle) -> Result<(), BaluardError> {
        let has_profile = self.display_name.is_some() || self.subtitle.is_some();

        if has_profile {
            let profile = crate::vault::manifest::UserProfile {
                display_name: self.display_name.clone(),
                subtitle: self.subtitle.clone(),
                avatar_ext: None,
            };
            handle.save_profile_and_strip_settings(&profile)?;
        }

        // Always persist settings on creation. A vault without
        // settings.enc fail-closes to Strict at phrase-enrollment time,
        // so a prefs-less `init` used to produce a vault whose clones
        // could never phrase-enroll. Writing the product defaults
        // (enrollment_policy Personal) here makes every fresh vault
        // enrollable and removes the missing-file ambiguity entirely.
        let mut settings = handle.get_settings().unwrap_or_default();
        if let Some(ref theme) = self.theme {
            settings.theme = Some(*theme);
        }
        if let Some(ref lang) = self.lang {
            settings.lang = Some(lang.clone());
        }
        if let Some(timeout) = self.vault_timeout {
            settings.vault_timeout = timeout;
        }
        if let Some(ref slug) = self.slug {
            settings.slug = Some(slug.clone());
        }
        handle.save_settings(&settings)?;

        if let Some(ref lang) = self.lang {
            handle.save_locale(lang)?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
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

    /// S1a: vault creation writes the owner member file + founding-device
    /// binding before the initial commit, so the roster-snapshot rule
    /// resolves roles from the root tree.
    #[test]
    fn creation_writes_owner_membership() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("s1a_vault");

        let (_handle, secrets) = VaultCreator::new(&path, "master-pass", "StandardDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(true)
            .execute()
            .unwrap();

        // On-disk: owner member file + device binding.
        let members_dir = path.join("meta/members");
        let entries: Vec<_> = std::fs::read_dir(&members_dir).unwrap().flatten().collect();
        let member_files: Vec<_> = entries
            .iter()
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        assert_eq!(member_files.len(), 1, "exactly one owner member file");
        let member: crate::vault::members::MemberFile =
            serde_json::from_str(&std::fs::read_to_string(member_files[0].path()).unwrap())
                .unwrap();
        assert_eq!(member.role, crate::vault::members::MemberRole::Owner);
        let binding_path = members_dir
            .join(member.id.to_string())
            .join("devices")
            .join(format!("{}.json", secrets.device_id));
        assert!(binding_path.exists(), "founding device must be bound");

        // In-tree: the initial commit carries the member directory.
        let repo = git2::Repository::open(&path).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        head.tree()
            .unwrap()
            .get_path(std::path::Path::new("meta/members"))
            .expect("initial commit must carry meta/members");
    }

    /// P2 ordering contract: the initial commit of a git-initialized vault
    /// carries `meta/devices.json` in its tree AND an embedded signature, so
    /// the roster-snapshot rule can verify it on any peer.
    #[cfg(feature = "git-sync")]
    #[test]
    fn initial_commit_is_enrolled_and_signed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("p2_vault");

        let (_handle, _secrets) = VaultCreator::new(&path, "master-pass", "StandardDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(true)
            .execute()
            .unwrap();

        let repo = git2::Repository::open(&path).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();

        // Registry is part of the root tree (roster-snapshot verifiable).
        let tree = head.tree().unwrap();
        assert!(
            tree.get_path(std::path::Path::new("meta/devices.json"))
                .is_ok(),
            "initial commit must contain meta/devices.json"
        );
        // Root commit is signed (modern era at genesis).
        assert!(
            repo.extract_signature(&head.id(), None).is_ok(),
            "initial commit must carry an embedded signature"
        );
    }

    #[test]
    fn wrapped_root_key_unwraps_correctly() {
        let result = create_vault_ceremony("test-password", KdfProfile::MobileLow).unwrap();
        let (eph_pub, ct, tag) = &result.wrapped_root_key;

        let unwrapped = hpke_wrap::unwrap_key(
            eph_pub,
            ct,
            tag,
            &result.device_x25519_secret,
            "root-key-keywrap",
        )
        .unwrap();
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

        let unwrapped = hpke_wrap::unwrap_key(
            eph_pub,
            ct,
            tag,
            &recovery_x25519_secret,
            "recovery-keywrap",
        )
        .unwrap();
        assert_eq!(unwrapped.as_slice(), result.root_key.as_bytes());
    }

    #[test]
    fn different_passwords_different_keys() {
        let r1 = create_vault_ceremony("password-1", KdfProfile::MobileLow).unwrap();
        let r2 = create_vault_ceremony("password-2", KdfProfile::MobileLow).unwrap();
        assert_ne!(r1.session_key, r2.session_key);
        assert_ne!(r1.sync_key, r2.sync_key);
    }

    #[test]
    fn keystore_less_devkey_file_is_sealed_and_unlock_roundtrips() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("c1_vault");

        let (mut handle, _secrets) = VaultCreator::new(&path, "master-pass", "StandardDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .execute()
            .unwrap();
        handle.lock();
        drop(handle);

        // C1: keystore-less vault must hold NO raw hex private keys at rest.
        let privkey_path = path.join("meta/device-privkey.json");
        let raw = std::fs::read_to_string(&privkey_path).unwrap();
        assert!(!raw.contains("x25519_private"), "raw X25519 key on disk");
        assert!(!raw.contains("ed25519_private"), "raw Ed25519 key on disk");
        assert_eq!(
            crate::vault::device_privkey::file_kind(&privkey_path),
            crate::vault::device_privkey::PrivkeyFileKind::Sealed
        );

        // Unlock round-trips through the sealed file (seal subkey derives
        // from the KEK during unlock_with_kek).
        let mut reopened = VaultHandle::open(&path).unwrap();
        reopened.unlock("master-pass").unwrap();
        assert!(reopened.is_unlocked());
        assert!(reopened.devkey_seal().is_some());

        // Wrong password must still fail closed.
        reopened.lock();
        assert!(reopened.unlock("wrong-password").is_err());
    }

    #[test]
    fn legacy_plaintext_devkey_reseals_on_unlock() {
        use crate::vault::device_privkey::{PrivkeyFileKind, file_kind};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("c1_legacy");

        let (mut handle, _secrets) = VaultCreator::new(&path, "master-pass", "StandardDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .execute()
            .unwrap();

        // Simulate a phrase-flow write / pre-seal vault: overwrite the
        // sealed file with the legacy plaintext format.
        let privkey_path = path.join("meta/device-privkey.json");
        let seal_key = handle.devkey_seal().unwrap();
        let inner = crate::vault::device_privkey::open_bytes(
            &seal_key,
            std::fs::read(&privkey_path).unwrap().as_slice(),
        )
        .unwrap();
        super::super::write_vault_file(&privkey_path, inner.as_bytes()).unwrap();
        assert_eq!(file_kind(&privkey_path), PrivkeyFileKind::LegacyPlaintext);

        handle.lock();
        drop(handle);

        // Next successful unlock lazily re-seals it.
        let mut reopened = VaultHandle::open(&path).unwrap();
        reopened.unlock("master-pass").unwrap();
        assert_eq!(file_kind(&privkey_path), PrivkeyFileKind::Sealed);
        let raw = std::fs::read_to_string(&privkey_path).unwrap();
        assert!(!raw.contains("x25519_private"));
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

    /// C5: device display names must not live in the git-tracked plaintext
    /// devices.json. The fold-and-strip migration moves them into the
    /// encrypted settings map and blanks the registry entries.
    #[test]
    fn device_names_fold_into_encrypted_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("c5_vault");

        let (handle, secrets) = VaultCreator::new(&path, "master-pass", "Laptop-Name")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .entropy(DeterministicEntropy { val: 55 })
            .execute()
            .unwrap();
        let device_id = secrets.device_id.to_string();

        handle.migrate_device_names_into_settings().unwrap();

        // Registry file no longer carries any name.
        let reg_json = std::fs::read_to_string(path.join("meta/devices.json")).unwrap();
        assert!(
            !reg_json.contains("Laptop-Name"),
            "name leaked in devices.json"
        );
        let reg: serde_json::Value = serde_json::from_str(&reg_json).unwrap();
        for (_id, entry) in reg["devices"].as_object().unwrap() {
            assert_eq!(entry["name"].as_str().unwrap_or(""), "");
        }

        // Encrypted map holds it.
        let names = handle.device_display_names();
        assert_eq!(
            names.get(&device_id).map(String::as_str),
            Some("Laptop-Name")
        );

        // Idempotent: a second run is a no-op that keeps the name.
        handle.migrate_device_names_into_settings().unwrap();
        assert_eq!(
            handle
                .device_display_names()
                .get(&device_id)
                .map(String::as_str),
            Some("Laptop-Name")
        );
    }

    #[test]
    fn test_vault_creator_with_profile_and_prefs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiled_vault");

        let (handle, _secrets) = VaultCreator::new(&path, "master-pass", "TestDevice")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .entropy(DeterministicEntropy { val: 42 })
            .profile(Some("Esteban".into()), Some("Lead Architect".into()))
            .preferences(
                Some(crate::types::ThemeMode::Dark),
                Some("es".into()),
                Some(crate::vault::manifest::VaultTimeout::Minutes(30)),
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
        assert_eq!(
            settings.vault_timeout,
            crate::vault::manifest::VaultTimeout::Minutes(30)
        );

        // Verify locale pref (now in settings-pub.json, consolidating meta/locale).
        assert_eq!(handle.load_locale().as_deref(), Some("es"));
        assert!(path.join("meta/settings-pub.json").exists());
        assert!(
            !path.join("meta/locale").exists(),
            "legacy locale sidecar should be gone"
        );
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
        assert_eq!(
            settings.vault_timeout,
            crate::vault::manifest::VaultTimeout::default_for_new()
        );

        assert!(handle.load_locale().is_none());
        assert!(!path.join("meta/locale").exists());
    }
}
