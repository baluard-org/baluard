//! S1a-3: contact cards + trust dial (plan-sharing §4.1).
//!
//! A [`ContactCard`] is the member's self-describing credential, signed
//! by their vault identity key. Cards travel out-of-band (embedded in
//! join introductions or exchanged as codes). The owner imports them
//! into the local encrypted address book (`meta/contacts.enc`,
//! RootKey-derived [`crate::crypto::hkdf_derive::derive_contacts_key`],
//! covered by rotation like the other metadata artifacts).
//!
//! Trust dial (thin tracer subset):
//! - `Channel` (Level 1): card arrived over a trusted channel — inert,
//!   identity recorded.
//! - `Verified` (Level 2): both sides displayed the
//!   [`verification_code`] derived from the card's identity key and
//!   confirmed the match over another channel.
//!
//! Enforcement: `approve_join` refuses roles above Editor unless the
//! joiner's card is `Verified` (the code check happened). Level 3
//! (admin approval) will replace this for org joins in a later slice.
//!
//! Stored entries are UUIDs + display names + trust + public keys only
//! (plan constraint 8); the file is encrypted at rest (0600 via the
//! hardened vault-file writer is unnecessary — the file is encrypted —
//! but `secret_file` sealing already produces an authenticated blob).

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::signature;
use crate::error::{BaluardError, VaultError};

pub const CONTACTS_FILE: &str = "meta/contacts.enc";

/// The human-facing card payload. `identity_signing_pubkey` is the
/// stable identifier (Ed25519 identity key, hex).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactCard {
    pub display_name: String,
    /// Hex Ed25519 identity signing pubkey.
    pub identity_signing_pubkey: String,
    /// Unix timestamp of card creation.
    pub created_at: u64,
}

impl ContactCard {
    fn payload(&self) -> Vec<u8> {
        // Domain-separated canonical encoding: field order is fixed and
        // the name is the only free-text field — control characters are
        // rejected at sign time so it cannot shift field boundaries.
        let mut payload = b"baluard-contact-v1\n".to_vec();
        payload.extend_from_slice(self.display_name.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(self.identity_signing_pubkey.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(&self.created_at.to_le_bytes());
        payload
    }

    /// The human-comparison code for the Level 2 check: both apps derive
    /// it from the card's identity key and compare out-of-band. First 8
    /// hex chars of a domain-separated hash — 32 bits, enough to make a
    /// pubkey-swap collision infeasible for a manual check.
    pub fn verification_code(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"baluard-contact-verify-v1");
        hasher.update(self.identity_signing_pubkey.as_bytes());
        hex::encode(&hasher.finalize()[..4])
    }
}

/// A [`ContactCard`] plus its identity-key signature (hex).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedContactCard {
    pub card: ContactCard,
    pub signature: String,
}

impl SignedContactCard {
    /// Sign a card with the member's identity signing key. Display names
    /// containing control characters (newlines) are refused: the payload
    /// is newline-delimited and the name flows into UI lists.
    pub fn sign(
        display_name: &str,
        identity_signing_pubkey: &str,
        created_at: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, BaluardError> {
        if display_name.contains(['\n', '\r']) {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "display name must not contain newlines".into(),
            )));
        }
        let card = ContactCard {
            display_name: display_name.to_string(),
            identity_signing_pubkey: identity_signing_pubkey.to_string(),
            created_at,
        };
        let sig = signature::sign(signing_key, &card.payload())?;
        Ok(Self {
            card,
            signature: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify the signature against the card's own identity key.
    /// Proves the card was signed by the identity it claims — NOT who
    /// controls that identity (that is the trust dial's job).
    pub fn verify(&self) -> Result<(), BaluardError> {
        let vk_bytes: [u8; 32] = hex::decode(&self.card.identity_signing_pubkey)
            .map_err(|_| VaultError::Corrupt("contact pubkey hex".into()))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("contact pubkey length".into()))?;
        let vk = signature::verifying_key_from_bytes(&vk_bytes)
            .map_err(|_| VaultError::Corrupt("contact pubkey invalid".into()))?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| VaultError::Corrupt("contact signature hex".into()))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| VaultError::Corrupt("contact signature length".into()))?;
        signature::verify(&vk, &self.card.payload(), &sig).map_err(|e| {
            BaluardError::from(VaultError::Metadata(format!(
                "contact card signature invalid: {e}"
            )))
        })
    }
}

/// Address book entry: an imported card plus its dial position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEntry {
    pub card: ContactCard,
    pub trust: ContactTrust,
    /// Unix timestamp of the last trust transition.
    pub updated_at: u64,
}

/// Trust dial (thin tracer subset of §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContactTrust {
    /// Level 1: card arrived over a trusted channel. Inert — identity
    /// recorded, no elevated grants.
    Channel,
    /// Level 2: the verification code was compared out-of-band.
    Verified,
}

/// Load the address book. Missing file = empty book.
pub fn load_contacts(
    vault_path: &Path,
    contacts_key: &[u8; 32],
) -> Result<Vec<ContactEntry>, BaluardError> {
    let path = vault_path.join(CONTACTS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let sealed = std::fs::read(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("read contacts: {e}"))))?;
    let data = crate::secret_file::open_secret_blob(contacts_key, &sealed, "contacts-v1")?;
    let entries: Vec<ContactEntry> = serde_json::from_slice(&data)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("parse contacts: {e}"))))?;
    Ok(entries)
}

/// Encrypt + write the address book (authenticated blob, atomic).
pub fn save_contacts(
    vault_path: &Path,
    contacts_key: &[u8; 32],
    entries: &[ContactEntry],
) -> Result<(), BaluardError> {
    let path = vault_path.join(CONTACTS_FILE);
    let data = serde_json::to_vec(entries).map_err(|e| {
        BaluardError::from(VaultError::Metadata(format!("serialize contacts: {e}")))
    })?;
    let sealed = crate::secret_file::seal_secret_blob(contacts_key, &data, "contacts-v1")?;
    super::write_vault_file(&path, &sealed)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write contacts: {e}"))))
}

/// Upsert a card into the address book. New cards land at `Channel`;
/// an existing entry keeps its trust level unless it is lower than the
/// requested floor (verification only ever upgrades). Returns the
/// resulting trust.
pub fn upsert_contact(
    vault_path: &Path,
    contacts_key: &[u8; 32],
    card: &ContactCard,
    floor: ContactTrust,
    now: u64,
) -> Result<ContactTrust, BaluardError> {
    let mut entries = load_contacts(vault_path, contacts_key)?;
    let rank = |t: &ContactTrust| match t {
        ContactTrust::Channel => 1u8,
        ContactTrust::Verified => 2,
    };
    if let Some(entry) = entries
        .iter_mut()
        .find(|e| e.card.identity_signing_pubkey == card.identity_signing_pubkey)
    {
        entry.card = card.clone();
        let new_trust = if rank(&floor) > rank(&entry.trust) {
            floor
        } else {
            entry.trust
        };
        entry.trust = new_trust;
        entry.updated_at = now;
        save_contacts(vault_path, contacts_key, &entries)?;
        return Ok(new_trust);
    }
    entries.push(ContactEntry {
        card: card.clone(),
        trust: floor,
        updated_at: now,
    });
    save_contacts(vault_path, contacts_key, &entries)?;
    Ok(floor)
}

/// Downgrade address book entries whose pubkey no longer matches any
/// member's current identity (the member rotated). Verified entries
/// drop to Channel — the plan's trust reset: the member must re-issue a
/// card and re-run the code check. Returns the downgraded pubkeys.
/// No-op on legacy vaults (no member directory).
pub fn reconcile_stale_contacts(
    vault_path: &Path,
    contacts_key: &[u8; 32],
) -> Result<Vec<String>, BaluardError> {
    if !vault_path.join(crate::vault::members::MEMBERS_DIR).exists() {
        return Ok(Vec::new());
    }
    // Scope the reset to real rotations: a pubkey is "rotated out" only
    // if some member record lists it as previous AND no record carries it
    // as current. External (non-member) contacts are never touched.
    let mut current: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut rotated_out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(vault_path.join(crate::vault::members::MEMBERS_DIR))?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(entry.path()) {
            if let Ok(member) = serde_json::from_str::<crate::vault::members::MemberFile>(&json) {
                if let Some(cur) = &member.identity_signing_pubkey {
                    current.insert(cur.clone());
                }
                if let Some(prev) = &member.identity_signing_pubkey_previous {
                    rotated_out.insert(prev.clone());
                }
            }
        }
    }
    let mut entries = load_contacts(vault_path, contacts_key)?;
    let mut downgraded = Vec::new();
    for entry in &mut entries {
        let pubkey = &entry.card.identity_signing_pubkey;
        if entry.trust == ContactTrust::Verified
            && rotated_out.contains(pubkey)
            && !current.contains(pubkey)
        {
            entry.trust = ContactTrust::Channel;
            downgraded.push(pubkey.clone());
        }
    }
    if !downgraded.is_empty() {
        save_contacts(vault_path, contacts_key, &entries)?;
    }
    Ok(downgraded)
}

/// The recorded trust for an identity pubkey, if the contact is known.
pub fn contact_trust(
    vault_path: &Path,
    contacts_key: &[u8; 32],
    identity_signing_pubkey: &str,
) -> Option<ContactTrust> {
    load_contacts(vault_path, contacts_key)
        .ok()?
        .into_iter()
        .find(|e| e.card.identity_signing_pubkey == identity_signing_pubkey)
        .map(|e| e.trust)
}

/// Upgrade a known contact to Verified (Level 2 code check confirmed).
/// Errors when the contact is absent — import first.
pub fn mark_verified(
    vault_path: &Path,
    contacts_key: &[u8; 32],
    identity_signing_pubkey: &str,
) -> Result<(), BaluardError> {
    let mut entries = load_contacts(vault_path, contacts_key)?;
    let entry = entries
        .iter_mut()
        .find(|e| e.card.identity_signing_pubkey == identity_signing_pubkey)
        .ok_or_else(|| {
            BaluardError::from(VaultError::Metadata(
                "contact not found — import the card first".into(),
            ))
        })?;
    entry.trust = ContactTrust::Verified;
    entry.updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    save_contacts(vault_path, contacts_key, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf_derive::derive_contacts_key;

    fn test_card(
        signing: &ed25519_dalek::SigningKey,
        name: &str,
    ) -> Result<SignedContactCard, BaluardError> {
        let vk = signing.verifying_key();
        SignedContactCard::sign(name, &hex::encode(vk.as_bytes()), 1_700_000_000, signing)
    }

    #[test]
    fn card_sign_verify_roundtrip() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let card = test_card(&key, "Alice").unwrap();
        card.verify().unwrap();
    }

    #[test]
    fn tampered_card_refused() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let mut card = test_card(&key, "Alice").unwrap();
        card.card.display_name = "Mallory".into();
        assert!(card.verify().is_err());

        let key2 = crate::crypto::signature::generate_ed25519_keypair().0;
        let card2 = test_card(&key2, "Alice").unwrap();
        let mut swapped = card2.clone();
        swapped.card.identity_signing_pubkey = hex::encode(key.verifying_key().as_bytes());
        assert!(
            swapped.verify().is_err(),
            "pubkey swap must break the signature"
        );
    }

    #[test]
    fn verification_code_deterministic_and_distinct() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b = crate::crypto::signature::generate_ed25519_keypair().0;
        let card_a = test_card(&key_a, "A").unwrap();
        let card_b = test_card(&key_b, "B").unwrap();
        assert_eq!(
            card_a.card.verification_code(),
            card_a.card.verification_code()
        );
        assert_ne!(
            card_a.card.verification_code(),
            card_b.card.verification_code()
        );
    }

    #[test]
    fn upsert_never_downgrades_trust() {
        let dir = tempfile::tempdir().unwrap();
        let root = [7u8; 64];
        let key = derive_contacts_key(&root).unwrap();
        let signing = crate::crypto::signature::generate_ed25519_keypair().0;
        let vk = signing.verifying_key();
        let card = ContactCard {
            display_name: "A".into(),
            identity_signing_pubkey: hex::encode(vk.as_bytes()),
            created_at: 1,
        };

        let t = upsert_contact(dir.path(), &key, &card, ContactTrust::Channel, 1).unwrap();
        assert_eq!(t, ContactTrust::Channel);

        let t = upsert_contact(dir.path(), &key, &card, ContactTrust::Verified, 2).unwrap();
        assert_eq!(t, ContactTrust::Verified);

        // Re-import over a channel that claims channel: floor never
        // downgrades an existing Verified entry.
        let t = upsert_contact(dir.path(), &key, &card, ContactTrust::Channel, 3).unwrap();
        assert_eq!(t, ContactTrust::Verified);
    }

    #[test]
    fn contacts_encrypt_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let root = [9u8; 64];
        let key = derive_contacts_key(&root).unwrap();
        let signing = crate::crypto::signature::generate_ed25519_keypair().0;
        let card = test_card(&signing, "Secret Name").unwrap();
        upsert_contact(dir.path(), &key, &card.card, ContactTrust::Verified, 1).unwrap();

        let raw = std::fs::read_to_string(dir.path().join(CONTACTS_FILE)).unwrap();
        assert!(
            !raw.contains("Secret Name"),
            "address book must be encrypted at rest"
        );
    }
}
