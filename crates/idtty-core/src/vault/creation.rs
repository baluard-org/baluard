//! Vault creation ceremony (doc 03 Section 10).
//!
//! Establishes the root of trust: vault_id, master password, KDF params,
//! Root Key, device keypair, HPKE wrapping, initial commit.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::hkdf_derive;
use crate::crypto::hpke_wrap;
use crate::crypto::kdf;
use crate::crypto::signature;
use crate::error::IdttyError;
use crate::keys::epoch::EpochInfo;
use crate::keys::hierarchy::RootKey;
use crate::recovery::RecoveryPhrase;
use crate::types::{KdfParams, KdfProfile};

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

/// Execute the vault creation ceremony.
///
/// Per doc 03 Section 10:
/// 1. Generate vault_id
/// 2. Derive KEK from master password
/// 3. Generate Root Key (epoch 1)
/// 4. Generate device X25519 + Ed25519 keypairs
/// 5. HPKE-wrap Root Key with device public key
/// 6. Derive Session Key + Sync Key from KEK
/// 7. Generate BIP-39 recovery phrase, wrap Root Key
/// 8. Compute trust anchor fingerprint
pub fn create_vault_ceremony(
    master_password: &str,
    profile: KdfProfile,
) -> Result<VaultCreationResult, IdttyError> {
    // Step 1: Vault ID
    let vault_id = Uuid::new_v4();

    // Step 2: KDF params with fresh salt, derive KEK
    let kdf_params = kdf::create_params(profile);
    let kek = kdf::derive_kek(master_password, &kdf_params)?;

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
        version: crate::IDTTY_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 0,
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let canary_envelope = crate::crypto::aead::encrypt(
        &session_key,
        b"idtty-kek-ok",
        b"idtty-kek-canary-v1",
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
        hkdf.expand(b"idtty-rk-canary-v1", &mut key)
            .expect("32 bytes is valid for HKDF-SHA256");
        key
    };
    let rk_canary_nonce = crate::crypto::aead::build_nonce(0, vault_id);
    let rk_canary_header = crate::types::EnvelopeHeader {
        version: crate::IDTTY_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 1, // RK canary is epoch-bound
        nonce_counter: 0,
        update_seq: 0,
        tier: None,
    };
    let rk_canary_envelope = crate::crypto::aead::encrypt(
        &rk_canary_key,
        b"idtty-rk-ok",
        b"idtty-rk-canary-v1",
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

        // Recovery phrase is 24 words
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

        // Derive the recovery X25519 key from the phrase
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
}
