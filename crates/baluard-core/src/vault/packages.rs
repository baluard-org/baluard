//! S2 IS-3: one-shot item packages (plan-sharing §4.6).
//!
//! A [`SharePackage`] is a self-contained encrypted file that carries a
//! copy of one cipher to a contact. Properties, per the plan:
//!
//! - **One-shot copy**: the recipient imports a fresh entry under their
//!   own vault's keys. There is no live link, no revocation, no
//!   sync — the pre-send UI states that the share cannot be un-shared.
//! - **Level 1 (channel trust)**: the package is HPKE-wrapped to the
//!   recipient's identity wrap pubkey from their signed contact card.
//!   A `Channel`-trust contact is enough — the package is inert.
//! - **Metadata minimal**: everything sensitive (item, sender card,
//!   timestamps) lives INSIDE the sealed payload. The envelope carries
//!   key material only, so a file intercepted in transit leaks nothing.
//! - **Fail closed**: the HPKE context binds the purpose, the payload
//!   seal binds the purpose via AAD (reuse of [`crate::secret_file`]),
//!   and the sender card signature is verified on open. Any tamper
//!   refuses the whole package.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{hpke_wrap, signature};
use crate::error::{BaluardError, VaultError};
use crate::types::CipherInput;
use crate::vault::contacts::SignedContactCard;
use crate::vault::identity::IdentityKeys;

/// Envelope format version.
pub const PACKAGE_FORMAT: u32 = 1;

/// HPKE wrap context (P7 pattern): binds the wrap to this purpose.
pub const PACKAGE_CONTEXT: &str = "item-share-v1";

/// Sealed-payload purpose string (flows into the AAD marker).
pub const PACKAGE_PAYLOAD_PURPOSE: &str = "item-share-payload-v1";

/// Size cap for the plaintext item payload (pre-encrypt DoS bound).
/// A padded-bucket cipher tops out at the XL tier (2 MB).
pub const MAX_PACKAGE_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Size cap for the serialized package file on disk and wire (4 MB).
/// Leaves ample slack for envelope, base64 expansion, and JSON overhead.
pub const MAX_PACKAGE_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Alias for backwards compatibility with existing references.
pub const MAX_PACKAGE_BYTES: usize = MAX_PACKAGE_FILE_BYTES;

/// The package file: transport envelope + sealed payload. Serialized as
/// JSON; the daemon route carries it base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePackage {
    pub format: u32,
    /// base64 HPKE ephemeral X25519 public key.
    pub ephemeral_public: String,
    /// base64 HPKE-encrypted content key.
    pub encrypted_key: String,
    /// base64 HPKE GCM tag.
    pub wrap_tag: String,
    /// The sealed payload document (see [`crate::secret_file`]).
    pub payload: serde_json::Value,
}

/// The decrypted payload. The sender's card travels inside so the
/// recipient learns who sent the item only by opening it. The package
/// signature binds the recipient public key, timestamp, and item to the
/// sender's identity signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagePayload {
    pub sender_card: SignedContactCard,
    /// Unix timestamp of the export.
    pub sent_at: u64,
    /// The shared item as a cipher-input copy. Attachments and password
    /// history are stripped by the exporter (attachment bytes never
    /// travel; history is stale on arrival).
    pub item: CipherInput,
    /// Hex Ed25519 signature over `(recipient_wrap_pub, sent_at, item)`
    /// signed with the sender's identity signing key.
    pub signature: String,
}

impl PackagePayload {
    /// Domain-separated canonical payload for the package signature.
    pub fn signing_payload(
        recipient_wrap_pub: &[u8; 32],
        sent_at: u64,
        item: &CipherInput,
    ) -> Result<Vec<u8>, BaluardError> {
        let item_bytes = serde_json::to_vec(item)
            .map_err(|e| VaultError::Metadata(format!("encode item: {e}")))?;
        let mut payload = b"baluard-package-v1\n".to_vec();
        payload.extend_from_slice(recipient_wrap_pub);
        payload.push(b'\n');
        payload.extend_from_slice(&sent_at.to_le_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(&item_bytes);
        Ok(payload)
    }
}

/// Seal a payload into a package wrapped to the recipient's X25519
/// identity wrap pubkey. Signs the package using the sender's identity key.
/// Returns the package file bytes (JSON).
pub fn seal_package(
    sender_card: SignedContactCard,
    sent_at: u64,
    item: CipherInput,
    recipient_wrap_pub: &[u8; 32],
    sender_signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, BaluardError> {
    let sign_payload = PackagePayload::signing_payload(recipient_wrap_pub, sent_at, &item)?;
    let sig = signature::sign(sender_signing_key, &sign_payload)?;
    let payload = PackagePayload {
        sender_card,
        sent_at,
        item,
        signature: hex::encode(sig.to_bytes()),
    };

    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| VaultError::Metadata(format!("encode package payload: {e}")))?;
    if payload_bytes.len() > MAX_PACKAGE_PAYLOAD_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "item too large to share as a package".into(),
        )));
    }

    // Random one-shot content key; zeroized on drop.
    let mut content_key = Zeroizing::new([0u8; 32]);
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(content_key.as_mut());

    let sealed = crate::secret_file::seal_secret_blob(
        &content_key,
        &payload_bytes,
        PACKAGE_PAYLOAD_PURPOSE,
    )?;
    let recipient_pub = x25519_dalek::PublicKey::from(*recipient_wrap_pub);
    let (eph, ct, tag) = hpke_wrap::wrap_key(&content_key[..], &recipient_pub, PACKAGE_CONTEXT)?;
    drop(content_key);

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pkg = SharePackage {
        format: PACKAGE_FORMAT,
        ephemeral_public: b64.encode(eph),
        encrypted_key: b64.encode(ct),
        wrap_tag: b64.encode(tag),
        payload: serde_json::from_slice(&sealed)
            .map_err(|e| VaultError::Metadata(format!("sealed payload doc: {e}")))?,
    };
    let pkg_bytes = serde_json::to_vec(&pkg)
        .map_err(|e| VaultError::Metadata(format!("encode package: {e}")))?;
    if pkg_bytes.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "package file exceeds maximum size".into(),
        )));
    }
    Ok(pkg_bytes)
}

/// Open a package with the recipient's identity. Verifies the sender
/// card signature and package signature, returning the payload.
pub fn open_package(
    bytes: &[u8],
    recipient: &IdentityKeys,
) -> Result<PackagePayload, BaluardError> {
    if bytes.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(BaluardError::from(VaultError::Corrupt(
            "package too large".into(),
        )));
    }
    let pkg: SharePackage = serde_json::from_slice(bytes)
        .map_err(|e| VaultError::Corrupt(format!("package envelope: {e}")))?;
    if pkg.format != PACKAGE_FORMAT {
        return Err(BaluardError::from(VaultError::InvalidEnvelopeVersion(
            pkg.format.min(u8::MAX as u32) as u8,
        )));
    }

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let eph = b64
        .decode(&pkg.ephemeral_public)
        .map_err(|_| VaultError::Corrupt("package ephemeral key".into()))?;
    let ct = b64
        .decode(&pkg.encrypted_key)
        .map_err(|_| VaultError::Corrupt("package wrapped key".into()))?;
    let tag: [u8; 16] = b64
        .decode(&pkg.wrap_tag)
        .map_err(|_| VaultError::Corrupt("package wrap tag".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("package wrap tag length".into()))?;

    let mut content_key = Zeroizing::new(hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        recipient.wrapping_secret(),
        PACKAGE_CONTEXT,
    )?);
    let content_key_arr: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt("package content key length invalid".into()))?;
    let content_key_arr = Zeroizing::new(content_key_arr);
    content_key.zeroize();

    let payload_doc = serde_json::to_vec(&pkg.payload)
        .map_err(|e| VaultError::Corrupt(format!("package payload doc: {e}")))?;
    let payload_bytes = crate::secret_file::open_secret_blob(
        &content_key_arr,
        &payload_doc,
        PACKAGE_PAYLOAD_PURPOSE,
    )?;
    drop(content_key_arr);

    let payload: PackagePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VaultError::Corrupt(format!("package payload: {e}")))?;
    payload.sender_card.verify().map_err(|_| {
        BaluardError::from(VaultError::Metadata(
            "package sender card signature invalid".into(),
        ))
    })?;

    // Verify package signature: binds recipient public key, timestamp, and item to sender
    let sign_payload = PackagePayload::signing_payload(
        &recipient.wrapping_pub_bytes(),
        payload.sent_at,
        &payload.item,
    )?;
    let vk_bytes: [u8; 32] = hex::decode(&payload.sender_card.card.identity_signing_pubkey)
        .map_err(|_| VaultError::Corrupt("package sender pubkey hex".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("package sender pubkey length".into()))?;
    let vk = signature::verifying_key_from_bytes(&vk_bytes)
        .map_err(|_| VaultError::Corrupt("package sender pubkey invalid".into()))?;
    let sig_bytes = hex::decode(&payload.signature)
        .map_err(|_| VaultError::Corrupt("package signature hex".into()))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| VaultError::Corrupt("package signature length".into()))?;
    signature::verify(&vk, &sign_payload, &sig).map_err(|_| {
        BaluardError::from(VaultError::Metadata("package signature invalid".into()))
    })?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::contacts::ContactCard;

    fn sender_card(signing: &ed25519_dalek::SigningKey, wrap_pub: &[u8; 32]) -> SignedContactCard {
        SignedContactCard::sign(
            "Sender",
            &hex::encode(signing.verifying_key().as_bytes()),
            &hex::encode(wrap_pub),
            None,
            1_700_000_000,
            signing,
        )
        .unwrap()
    }

    fn sample_item() -> CipherInput {
        serde_json::from_str(
            r#"{"name":"GitHub","kind":{"type":"login","data":{"username":"u","password":"p"}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let bytes = seal_package(
            card,
            42,
            sample_item(),
            &recipient.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();
        let opened = open_package(&bytes, &recipient).unwrap();
        assert_eq!(opened.item.name, "GitHub");
        assert_eq!(opened.sender_card.card.display_name, "Sender");
        assert_eq!(opened.sent_at, 42);
    }

    #[test]
    fn wrong_recipient_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let stranger = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let bytes = seal_package(
            card,
            42,
            sample_item(),
            &recipient.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();
        assert!(open_package(&bytes, &stranger).is_err());
    }

    #[test]
    fn tampered_envelope_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let mut bytes = seal_package(
            card,
            42,
            sample_item(),
            &recipient.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();
        // Flip a byte deep inside the sealed payload document.
        let last = bytes.len() - 2;
        bytes[last] ^= 0x01;
        assert!(open_package(&bytes, &recipient).is_err());
    }

    #[test]
    fn forged_sender_card_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let mut card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        card.card = ContactCard {
            display_name: "Mallory".into(),
            email: None,
            identity_signing_pubkey: card.card.identity_signing_pubkey.clone(),
            identity_wrap_pubkey: card.card.identity_wrap_pubkey.clone(),
            created_at: card.card.created_at,
        };
        let bytes = seal_package(
            card,
            42,
            sample_item(),
            &recipient.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();
        let err = open_package(&bytes, &recipient).unwrap_err();
        assert!(
            err.to_string().contains("sender card"),
            "must refuse at the card check: {err}"
        );
    }

    #[test]
    fn tampered_item_fails_package_signature() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());

        // Alice seals an item
        let bytes = seal_package(
            card.clone(),
            42,
            sample_item(),
            &recipient.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();

        // An attacker (who has Alice's card) attempts to create a payload with modified item
        // and Alice's signature from the old payload
        let opened = open_package(&bytes, &recipient).unwrap();
        let mut forged_payload = opened.clone();
        forged_payload.item.name = "PhishingBank".into();

        // Re-seal with valid recipient key but with forged item and Alice's stale signature
        let payload_bytes = serde_json::to_vec(&forged_payload).unwrap();
        let content_key = [7u8; 32];
        let sealed = crate::secret_file::seal_secret_blob(
            &content_key,
            &payload_bytes,
            PACKAGE_PAYLOAD_PURPOSE,
        )
        .unwrap();
        let recipient_pub = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&content_key, &recipient_pub, PACKAGE_CONTEXT).unwrap();

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = SharePackage {
            format: PACKAGE_FORMAT,
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
            payload: serde_json::from_slice(&sealed).unwrap(),
        };
        let forged_bytes = serde_json::to_vec(&pkg).unwrap();
        let err = open_package(&forged_bytes, &recipient).unwrap_err();
        assert!(
            err.to_string().contains("package signature invalid"),
            "must refuse tampered item: {err}"
        );
    }

    #[test]
    fn re_wrapped_package_for_different_recipient_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient1 = IdentityKeys::generate().unwrap();
        let recipient2 = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());

        // Alice sends to Recipient 1
        let bytes = seal_package(
            card,
            42,
            sample_item(),
            &recipient1.wrapping_pub_bytes(),
            sender.signing_key(),
        )
        .unwrap();

        // Recipient 1 decrypts it
        let payload = open_package(&bytes, &recipient1).unwrap();

        // Recipient 1 re-encrypts payload to Recipient 2 without Alice's signature over Recipient 2
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let content_key = [8u8; 32];
        let sealed = crate::secret_file::seal_secret_blob(
            &content_key,
            &payload_bytes,
            PACKAGE_PAYLOAD_PURPOSE,
        )
        .unwrap();
        let recipient2_pub = x25519_dalek::PublicKey::from(recipient2.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&content_key, &recipient2_pub, PACKAGE_CONTEXT).unwrap();

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = SharePackage {
            format: PACKAGE_FORMAT,
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
            payload: serde_json::from_slice(&sealed).unwrap(),
        };
        let rewrapped_bytes = serde_json::to_vec(&pkg).unwrap();
        let err = open_package(&rewrapped_bytes, &recipient2).unwrap_err();
        assert!(
            err.to_string().contains("package signature invalid"),
            "must refuse re-wrapped package: {err}"
        );
    }

    #[test]
    fn non_32_byte_content_key_refused_without_panic() {
        let recipient = IdentityKeys::generate().unwrap();
        // HPKE wrap a 16-byte key instead of 32 bytes
        let short_key = [1u8; 16];
        let recipient_pub = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&short_key, &recipient_pub, PACKAGE_CONTEXT).unwrap();

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = SharePackage {
            format: PACKAGE_FORMAT,
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
            payload: serde_json::json!({}),
        };
        let bytes = serde_json::to_vec(&pkg).unwrap();
        let err = open_package(&bytes, &recipient).unwrap_err();
        assert!(
            err.to_string().contains("content key length invalid"),
            "err: {err}"
        );
    }

    #[test]
    fn garbage_refused() {
        let recipient = IdentityKeys::generate().unwrap();
        assert!(open_package(b"not a package", &recipient).is_err());
    }
}
