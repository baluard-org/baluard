//! Space Recovery Kit: the Root Key escrowed to an offline BIP-39 phrase.
//!
//! Power-pack S4-7 / section 10 Q5: an opt-in kit covering sole-admin
//! total loss. The owner writes the 24-word phrase into a physical safe;
//! the kit file (`meta/recovery-kit.json`, plaintext, git-tracked under
//! the meta/** Admin row) carries only an HPKE wrap of the Root Key to a
//! key derived from that phrase, so the Space can be recovered on a
//! fresh machine after every admin device is lost. The phrase is shown
//! exactly once, at enable time.
//!
//! Domain separation: `space-recovery-kit` (this file) vs
//! `recovery-keywrap` (the personal vault's meta/recovery.json) vs
//! `emergency-escrow` (the trusted-contact flow in crate::emergency).
//! The kit holds no status machinery on purpose: whoever holds the
//! phrase can unwrap whenever the file exists. An owner incapacitation
//! cannot wait for an in-band approval, and a removed file is the only
//! off switch (an admin disabling the kit).
//!
//! Recovery ceremony (device enrollment, owner-row binding, unlock) is
//! designed in docs/emergency-org-identity.md and lands as a follow-up
//! slice; this module provides the escrow primitives.

use crate::crypto::hpke_wrap;
use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::RootKey;
use crate::recovery::RecoveryPhrase;
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// HPKE context binding every kit wrap to this mechanism. Changing it
/// invalidates every existing kit.
const KIT_CONTEXT: &str = "space-recovery-kit";

/// The only kit file version this binary reads. Version 2 added the
/// root_check seal; version 1 kits cannot prove their public fields and
/// must be re-enabled.
const KIT_FORMAT: u8 = 2;

/// Git-tracked location, riding the meta/** Admin sync row so the kit
/// survives total machine loss.
const KIT_PATH: &str = "meta/recovery-kit.json";

/// Refuse absurd files before parsing (a torn or hostile write).
const MAX_KIT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKitFile {
    pub format: u8,
    /// Vault binding: a kit only recovers the vault it names.
    pub vault_id: String,
    /// X25519 public key derived from the phrase. Stored so root
    /// rotation can rewrap without the phrase.
    pub recipient_pub: String,
    pub ephemeral_pub: String,
    pub encrypted_key: String,
    pub tag: String,
    /// Family-spaces §7/§10: the public half of an Ed25519 key derived
    /// from the SAME phrase (the unused second half of the BIP-39
    /// seed). A kit-recovered device signs its FIRST commit with the
    /// private half so peers — who hold no Root Key on a flipped vault
    /// — can verify it. `None` on kits written before this field.
    #[serde(default)]
    pub verifier_pub: Option<String>,
    pub created_at: u64,
    /// AEAD seal (under a Root-Key-derived subkey) over vault_id,
    /// recipient_pub and verifier_pub. A git-writer without the Root
    /// Key cannot re-bind the kit to their own keys: rotation and
    /// recovery verify this before trusting either public field.
    pub root_check: String,
}

/// Load the kit file. `None` when absent; a present-but-damaged file is
/// an error so rotation rewires fail loudly (P4 rotation coverage).
pub fn load_kit(vault_path: &Path) -> Result<Option<RecoveryKitFile>, BaluardError> {
    let path = vault_path.join(KIT_PATH);
    if !path.exists() {
        return Ok(None);
    }
    // lstat, not stat: a symlinked kit (hostile committer) must not
    // borrow its target's size metadata to slip past the cap, and the
    // read itself is capped so a /dev/zero-style target cannot run the
    // parser unbounded.
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| VaultError::Metadata(format!("stating recovery kit: {e}")))?;
    if !meta.is_file() {
        return Err(VaultError::Corrupt("recovery kit is not a regular file".into()).into());
    }
    if meta.len() > MAX_KIT_BYTES {
        return Err(VaultError::Corrupt("recovery kit file is oversized".into()).into());
    }
    use std::io::Read;
    let mut limited = String::new();
    std::fs::File::open(&path)
        .map_err(|e| VaultError::Metadata(format!("reading recovery kit: {e}")))?
        .take(MAX_KIT_BYTES + 1)
        .read_to_string(&mut limited)
        .map_err(|e| VaultError::Metadata(format!("reading recovery kit: {e}")))?;
    if limited.len() as u64 > MAX_KIT_BYTES {
        return Err(VaultError::Corrupt("recovery kit file is oversized".into()).into());
    }
    let data = limited;
    let kit: RecoveryKitFile = serde_json::from_str(&data)
        .map_err(|e| VaultError::Corrupt(format!("recovery kit parsing: {e}")))?;
    if kit.format != KIT_FORMAT {
        return Err(VaultError::Corrupt(format!(
            "unsupported recovery kit format: {}",
            kit.format
        ))
        .into());
    }
    Ok(Some(kit))
}

fn save_kit(vault_path: &Path, kit: &RecoveryKitFile) -> Result<(), BaluardError> {
    let json = serde_json::to_string_pretty(kit)
        .map_err(|e| VaultError::Metadata(format!("recovery kit serialization: {e}")))?;
    crate::vault::write_vault_file(&vault_path.join(KIT_PATH), json.as_bytes())
        .map_err(|e| VaultError::Metadata(format!("writing recovery kit: {e}")))?;
    Ok(())
}

/// Seal the kit's identity fields under a Root-Key-derived subkey so
/// only a Root-Key holder (the minting device, or rotation) can produce
/// or re-bind a valid kit.
fn seal_root_check(
    root_key: &RootKey,
    vault_id: &str,
    recipient_pub: &str,
    verifier_pub: Option<&str>,
    created_at: u64,
) -> Result<String, BaluardError> {
    let key = crate::crypto::hkdf_derive::derive_kit_check_key(root_key.as_bytes())
        .map_err(|e| VaultError::Crypto(format!("kit check key: {e}")))?;
    let payload = format!(
        "{}|{}|{}|{}",
        vault_id,
        recipient_pub,
        verifier_pub.unwrap_or(""),
        created_at
    );
    let envelope = crate::crypto::aead::encrypt(
        &key,
        payload.as_bytes(),
        KIT_CONTEXT.as_bytes(),
        &crate::crypto::aead::build_random_nonce(),
        crate::types::EnvelopeHeader {
            version: 1,
            alg_id: 1,
            key_epoch: 0,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
    )
    .map_err(|e| VaultError::Crypto(format!("kit check seal: {e}")))?;
    // CipherEnvelope carries no serde impl, so the check blob is a
    // fixed-order hex packing: nonce | ciphertext | tag.
    Ok(format!(
        "{}:{}:{}",
        hex::encode(envelope.nonce),
        hex::encode(&envelope.ciphertext),
        hex::encode(envelope.tag)
    ))
}

/// Verify a kit's root_check against a candidate Root Key. Fails
/// closed: a kit whose public fields were swapped in git history does
/// not open under the vault's real Root Key.
pub fn verify_root_check(root_key: &RootKey, kit: &RecoveryKitFile) -> Result<(), BaluardError> {
    let key = crate::crypto::hkdf_derive::derive_kit_check_key(root_key.as_bytes())
        .map_err(|e| VaultError::Crypto(format!("kit check key: {e}")))?;
    // created_at anchors the kit enable-over approval, so it is sealed
    // alongside the key material fields.
    // Fixed-order hex packing written by seal_root_check (no serde on
    // CipherEnvelope): nonce | ciphertext | tag.
    let parts: Vec<&str> = kit.root_check.split(':').collect();
    if parts.len() != 3 {
        return Err(VaultError::Corrupt("recovery kit check is malformed".into()).into());
    }
    let nonce_vec = hex::decode(parts[0])
        .map_err(|e| VaultError::Corrupt(format!("recovery kit check nonce: {e}")))?;
    let ct_vec = hex::decode(parts[1])
        .map_err(|e| VaultError::Corrupt(format!("recovery kit check ciphertext: {e}")))?;
    let tag_vec = hex::decode(parts[2])
        .map_err(|e| VaultError::Corrupt(format!("recovery kit check tag: {e}")))?;
    let (nonce_arr, tag_arr) = match (nonce_vec.try_into(), tag_vec.try_into()) {
        (Ok(n), Ok(t)) => (n, t),
        _ => return Err(VaultError::Corrupt("recovery kit check is malformed".into()).into()),
    };
    let envelope = crate::types::CipherEnvelope {
        header: crate::types::EnvelopeHeader {
            version: 1,
            alg_id: 1,
            key_epoch: 0,
            nonce_counter: 0,
            update_seq: 0,
            tier: None,
        },
        nonce: nonce_arr,
        aad: KIT_CONTEXT.as_bytes().to_vec(),
        ciphertext: ct_vec,
        tag: tag_arr,
    };
    let plaintext = crate::crypto::aead::decrypt(&key, &envelope).map_err(|_| {
        VaultError::Corrupt(
            "recovery kit does not match this vault's root key; re-enable the kit".into(),
        )
    })?;
    let expected = format!(
        "{}|{}|{}|{}",
        kit.vault_id,
        kit.recipient_pub,
        kit.verifier_pub.as_deref().unwrap_or(""),
        kit.created_at
    );
    if plaintext != expected.as_bytes() {
        return Err(VaultError::Corrupt(
            "recovery kit fields were modified after minting; re-enable the kit".into(),
        )
        .into());
    }
    Ok(())
}

/// Derive the kit's X25519 unwrap secret from a BIP-39 phrase, mirroring
/// the personal-vault recovery derivation (first 32 bytes of the BIP-39
/// seed) so the two flows behave identically phrase-to-key.
fn phrase_to_secret(phrase: &RecoveryPhrase) -> x25519_dalek::StaticSecret {
    let mut seed = phrase.derive_key();
    let mut secret_bytes = zeroize::Zeroizing::new([0u8; 32]);
    secret_bytes.copy_from_slice(&seed[..32]);
    seed.zeroize();
    x25519_dalek::StaticSecret::from(*secret_bytes)
}

/// Create the kit: generate a fresh 24-word phrase, wrap the current
/// Root Key to it, and store the file. Returns the phrase, which the
/// caller must display exactly once. Re-enabling rotates the phrase
/// (a fresh kit replaces the old one; the old phrase dies with it).
pub fn enable_kit(
    vault_path: &Path,
    root_key: &RootKey,
    vault_id: Uuid,
) -> Result<String, BaluardError> {
    let phrase = RecoveryPhrase::generate()
        .map_err(|e| VaultError::Metadata(format!("phrase generation: {e}")))?;
    let secret = phrase_to_secret(&phrase);
    let recipient = x25519_dalek::PublicKey::from(&secret);

    let (ephemeral_pub, ciphertext, tag) =
        hpke_wrap::wrap_key(root_key.as_bytes(), &recipient, KIT_CONTEXT)?;

    let verifier_pub = kit_signing_key(&phrase).verifying_key();
    let recipient_hex = hex::encode(recipient.as_bytes());
    let verifier_hex = hex::encode(verifier_pub.as_bytes());

    let kit_created_at = crate::vault::collections::now_secs_pub();
    let kit = RecoveryKitFile {
        format: KIT_FORMAT,
        vault_id: vault_id.to_string(),
        recipient_pub: recipient_hex.clone(),
        ephemeral_pub: hex::encode(&ephemeral_pub),
        encrypted_key: hex::encode(&ciphertext),
        tag: hex::encode(tag),
        verifier_pub: Some(verifier_hex.clone()),
        created_at: kit_created_at,
        root_check: seal_root_check(
            root_key,
            &vault_id.to_string(),
            &recipient_hex,
            Some(&verifier_hex),
            kit_created_at,
        )?,
    };
    save_kit(vault_path, &kit)?;
    Ok(phrase.phrase())
}

/// The kit's Ed25519 signing key, derived from the second half of the
/// BIP-39 seed (the first half is the X25519 unwrap secret). Distinct
/// purposes, one phrase.
pub(crate) fn kit_signing_key(phrase: &RecoveryPhrase) -> ed25519_dalek::SigningKey {
    let seed = phrase.derive_key();
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&seed[32..]);
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

/// Parse the verifier out of a kit file. `None` on legacy kits.
pub(crate) fn kit_verifier(kit: &RecoveryKitFile) -> Option<ed25519_dalek::VerifyingKey> {
    let hex_pk = kit.verifier_pub.as_deref()?;
    let bytes = hex::decode(hex_pk).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// Whether a kit file exists (keyless filesystem check).
pub fn kit_exists(vault_path: &Path) -> Result<bool, BaluardError> {
    Ok(vault_path.join(KIT_PATH).exists())
}

/// Remove the kit. Returns whether a kit existed.
pub fn disable_kit(vault_path: &Path) -> Result<bool, BaluardError> {
    let path = vault_path.join(KIT_PATH);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path)
        .map_err(|e| VaultError::Metadata(format!("removing recovery kit: {e}")))?;
    Ok(true)
}

/// Root rotation: rewrap the kit to the NEW Root Key so the phrase in
/// the safe keeps working. Absent kit is a no-op; present-but-damaged
/// propagates (P4). The kit's root_check must open under the CURRENT
/// root first: a kit whose public fields were swapped in git history
/// is refused instead of re-wrapping the new root to the attacker's
/// key.
pub fn rewrap_kit(
    vault_path: &Path,
    current_root: &RootKey,
    new_root_key: &RootKey,
) -> Result<(), BaluardError> {
    let Some(mut kit) = load_kit(vault_path)? else {
        return Ok(());
    };
    verify_root_check(current_root, &kit)?;
    let recipient_bytes: [u8; 32] = hex::decode(&kit.recipient_pub)
        .map_err(|e| VaultError::Corrupt(format!("recovery kit recipient hex: {e}")))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("invalid recovery kit recipient length".into()))?;
    let recipient = x25519_dalek::PublicKey::from(recipient_bytes);

    let (ephemeral_pub, ciphertext, tag) =
        hpke_wrap::wrap_key(new_root_key.as_bytes(), &recipient, KIT_CONTEXT)?;
    kit.ephemeral_pub = hex::encode(&ephemeral_pub);
    kit.encrypted_key = hex::encode(&ciphertext);
    kit.tag = hex::encode(tag);
    kit.root_check = seal_root_check(
        new_root_key,
        &kit.vault_id,
        &kit.recipient_pub,
        kit.verifier_pub.as_deref(),
        kit.created_at,
    )?;
    save_kit(vault_path, &kit)?;
    Ok(())
}

/// Recover the Root Key from the kit with the offline phrase. The
/// caller must verify the returned key against the vault's root canary
/// before trusting it; the vault-id check here only stops a phrase for
/// one Space opening another.
pub fn recover_root_from_kit(
    vault_path: &Path,
    vault_id: Uuid,
    phrase: &str,
) -> Result<RootKey, BaluardError> {
    let kit = load_kit(vault_path)?.ok_or_else(|| {
        BaluardError::from(VaultError::InvalidOperation(
            "No recovery kit is set up for this space.".into(),
        ))
    })?;
    if kit.vault_id != vault_id.to_string() {
        return Err(
            VaultError::Corrupt("recovery kit file belongs to a different vault".into()).into(),
        );
    }

    let secret = match RecoveryPhrase::from_phrase(phrase) {
        Ok(parsed) => phrase_to_secret(&parsed),
        Err(e) => return Err(VaultError::Metadata(format!("invalid recovery phrase: {e}")).into()),
    };
    let eph_pub = hex::decode(&kit.ephemeral_pub)
        .map_err(|e| VaultError::Corrupt(format!("recovery kit ephemeral hex: {e}")))?;
    let ct = hex::decode(&kit.encrypted_key)
        .map_err(|e| VaultError::Corrupt(format!("recovery kit ciphertext hex: {e}")))?;
    let tag_bytes = hex::decode(&kit.tag)
        .map_err(|e| VaultError::Corrupt(format!("recovery kit tag hex: {e}")))?;
    if tag_bytes.len() != 16 {
        return Err(VaultError::Corrupt("invalid recovery kit tag length".into()).into());
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    let mut decrypted = hpke_wrap::unwrap_key(&eph_pub, &ct, &tag, &secret, KIT_CONTEXT)?;
    let root_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
        decrypted
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("recovered root key is invalid length".into()))?,
    );
    zeroize::Zeroize::zeroize(&mut decrypted);
    let root = RootKey::from_bytes(*root_bytes);
    // The unwrapped key must open the kit's seal: a git-swapped kit
    // (recipient or verifier fields rewritten) refuses here instead of
    // arming an attacker-chosen key for the next rotation.
    verify_root_check(&root, &kit)?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn temp_vault(label: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(label);
        std::fs::create_dir_all(path.join("meta")).expect("meta dir");
        (dir, path)
    }

    fn random_root() -> RootKey {
        let mut bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        RootKey::from_bytes(bytes)
    }

    #[test]
    fn kit_roundtrip_rewrap_disable_and_refusals() {
        let (_dir, path) = temp_vault("kit-roundtrip");
        let vid = Uuid::new_v4();
        let root = random_root();

        let phrase = enable_kit(&path, &root, vid).expect("enable");
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(kit_exists(&path).expect("exists"));

        // Right phrase, right vault: the unwrap returns the live root.
        let recovered = recover_root_from_kit(&path, vid, &phrase).expect("recover");
        assert_eq!(recovered.as_bytes(), root.as_bytes());

        // Wrong phrase refuses.
        let other = RecoveryPhrase::generate().expect("gen").phrase();
        assert!(recover_root_from_kit(&path, vid, &other).is_err());

        // Right phrase, wrong vault refuses.
        assert!(recover_root_from_kit(&path, Uuid::new_v4(), &phrase).is_err());

        // Rotation: the rewrap keeps the same phrase working against
        // the NEW root and only the new root.
        let new_root = random_root();
        rewrap_kit(&path, &root, &new_root).expect("rewrap");
        let recovered = recover_root_from_kit(&path, vid, &phrase).expect("recover after rotate");
        assert_eq!(recovered.as_bytes(), new_root.as_bytes());

        // Re-enabling rotates the phrase: the old phrase dies.
        let phrase2 = enable_kit(&path, &new_root, vid).expect("re-enable");
        assert_ne!(phrase, phrase2);
        assert!(recover_root_from_kit(&path, vid, &phrase).is_err());
        assert_eq!(
            recover_root_from_kit(&path, vid, &phrase2)
                .expect("recover with new phrase")
                .as_bytes(),
            new_root.as_bytes()
        );

        // Disable removes the file; a second disable is a no-op.
        assert!(disable_kit(&path).expect("disable"));
        assert!(!kit_exists(&path).expect("gone"));
        assert!(!disable_kit(&path).expect("second disable"));
        assert!(recover_root_from_kit(&path, vid, &phrase2).is_err());
    }

    #[test]
    fn damaged_kit_file_is_an_error_not_none() {
        let (_dir, path) = temp_vault("kit-damaged");
        std::fs::write(path.join(KIT_PATH), "{ not json").expect("write torn kit");
        assert!(load_kit(&path).is_err());
    }

    #[test]
    fn git_swapped_kit_fields_refuse_recovery_and_rewrap() {
        let (_dir, path) = temp_vault("kit-swap");
        let vid = Uuid::new_v4();
        let root = random_root();
        let phrase = enable_kit(&path, &root, vid).expect("enable");

        // A git-writer swaps recipient_pub (and the wrap fields) to
        // redirect the NEXT rotation's root key. No valid root_check
        // exists for that swap.
        let mut kit = load_kit(&path).expect("load").expect("kit");
        kit.recipient_pub = hex::encode([7u8; 32]);
        std::fs::write(
            path.join(KIT_PATH),
            serde_json::to_string(&kit).expect("serialize"),
        )
        .expect("write swapped kit");

        let swapped = load_kit(&path).expect("load").expect("kit");
        assert!(verify_root_check(&root, &swapped).is_err());
        let new_root = random_root();
        assert!(rewrap_kit(&path, &root, &new_root).is_err());

        // Recovery with the TRUE phrase also refuses: the phrase opens
        // the swapped wrap, but the result cannot open the kit's seal.
        assert!(recover_root_from_kit(&path, vid, &phrase).is_err());
    }
}
