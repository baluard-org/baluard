//! S2 IS-6: field-scoped item reveals (plan-sharing §4.6).
//!
//! A reveal is a self-contained encrypted file that carries a VIEW-ONLY
//! copy of selected login fields (default URL + username + password;
//! TOTP opt-in) to another person. Unlike IS-3 packages, a reveal is
//! never imported into a vault: the recipient opens it to look the
//! fields up ("view-only help").
//!
//! Two flavors:
//!
//! - **Contact-key** (trust Level 1): HPKE-wrapped to a contact card's
//!   identity wrap pubkey. The sender card travels inside the seal and
//!   the sender's identity key signs recipient + expiry + fields: the
//!   card's self-signature is copyable and HPKE Base mode authenticates
//!   neither party, so without this signature anyone holding a public
//!   card could forge the sender label or retarget the file.
//! - **Passphrase guest** (trust Level 0): sealed under an Argon2id key
//!   derived from an app-generated passphrase. No identity involved;
//!   the passphrase IS the authentication. KDF params and expiry are
//!   authenticated through the AAD marker (a wrong salt or an edited
//!   expiry breaks the GCM tag).
//!
//! Expiry binding: the envelope carries `expires_at` in plaintext and
//! the seal's AAD marker embeds the same value, so an edited envelope
//! date breaks the GCM tag and the sealed copy (checked for equality
//! after decrypt) binds the plaintext field. An expired file refuses to
//! open; the recipient asks for a fresh reveal.
//!
//! The TOTP seed, when opted in, only ever exists inside the seal; open
//! returns the current code, never the seed.

use base64::Engine as _;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{hpke_wrap, kdf, signature, totp};
use crate::error::{BaluardError, VaultError};
use crate::types::{KdfParams, KdfProfile};
use crate::vault::contacts::SignedContactCard;
use crate::vault::identity::IdentityKeys;

/// Envelope format version.
pub const REVEAL_FORMAT: u32 = 1;

/// HPKE wrap context (contact flavor only).
pub const REVEAL_CONTEXT: &str = "item-reveal-v1";

/// Sealed-payload purpose prefix; the full marker embeds the expiry
/// (`.../exp/<unix>`), putting the date under the AES-GCM AAD.
pub const REVEAL_PAYLOAD_PURPOSE: &str = "item-reveal-payload-v1";

/// Signature domain prefix (contact flavor).
pub const REVEAL_SIGNATURE_DOMAIN: &[u8] = b"baluard-item-reveal-v1\n";

/// Word count for the app-generated guest passphrase. The generator
/// pool merges the EFF English list with the Spanish BIP-39 list
/// (16,380 words total), so 7 words carry ~98 bits. The pool is
/// bilingual by design: the opening app shows the words on screen, and
/// voice delivery of a mixed-language passphrase is a known wrinkle
/// deferred to the UI wave (a language-scoped draw would need a
/// generator option).
pub const GUEST_PASSPHRASE_WORDS: usize = 7;

/// Ceilings for the UNTRUSTED KDF params on the guest open path. The
/// envelope's Argon2id block is attacker-controlled: without a clamp a
/// hostile file could set memory_kib to terabytes and abort the daemon
/// with an allocation failure the moment the victim types a passphrase.
/// Generous over the seal path (DesktopStd: 64 MiB / 3 / 2) so legit
/// files always verify; hostile params just collapse to a normal-cost
/// derivation and fail the GCM tag.
const GUEST_KDF_MAX_MEMORY_KIB: u32 = 128 * 1024;
const GUEST_KDF_MAX_TIME_COST: u32 = 6;
const GUEST_KDF_MAX_PARALLELISM: u32 = 4;

/// Size caps. Fields only, so the payload cap sits far below the
/// package cap; the file cap stays under the daemon socket frame.
pub const MAX_REVEAL_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_REVEAL_FILE_BYTES: usize = 1024 * 1024;

/// The revealed fields. Built from a Login cipher; nothing else travels.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevealFields {
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// otpauth:// URI. Opt-in at export; lives only inside the seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
}

/// The decrypted payload. `sender_card`/`sender_signature` are set only
/// in the contact flavor; the guest flavor has no identity by design.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevealPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_card: Option<SignedContactCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub item_name: String,
    pub fields: RevealFields,
}

/// Key-wrap half of the envelope, tagged per flavor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RevealWrap {
    Contact {
        /// base64 HPKE ephemeral X25519 public key.
        ephemeral_public: String,
        /// base64 HPKE-encrypted content key.
        encrypted_key: String,
        /// base64 HPKE GCM tag.
        wrap_tag: String,
    },
    Passphrase {
        /// Argon2id parameters including the salt.
        kdf: KdfParams,
    },
}

/// The reveal file: envelope + sealed payload. Serialized as JSON; the
/// daemon route carries it base64-encoded. `expires_at` is plaintext
/// and self-authenticating (see the module docs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevealPackage {
    pub format: u32,
    pub expires_at: u64,
    #[serde(flatten)]
    pub wrap: RevealWrap,
    /// The sealed payload document (see [`crate::secret_file`]).
    pub payload: serde_json::Value,
}

/// What the opening app shows. The TOTP seed never leaves this module;
/// only the current code and its validity window do.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OpenedReveal {
    pub item_name: String,
    pub sender_name: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp_code: Option<String>,
    /// Unix second at which `totp_code` stops being valid.
    pub totp_valid_until: Option<u64>,
}

fn expiry_purpose(expires_at: u64) -> String {
    format!("{REVEAL_PAYLOAD_PURPOSE}/exp/{expires_at}")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Canonical bytes the contact-flavor sender signs: recipient wrap key,
/// expiry, creation time, the item label, and the exact revealed
/// fields. Fixed-size fields first, both variable fields
/// length-prefixed. The label and timestamp are signed so a captured
/// signature cannot re-seal the same fields under a different name or
/// a forged "sent just now" freshness cue.
fn reveal_sign_payload(
    recipient_wrap_pub: &[u8; 32],
    expires_at: u64,
    created_at: u64,
    item_name: &str,
    fields: &RevealFields,
) -> Result<Vec<u8>, BaluardError> {
    let fields_json = serde_json::to_vec(fields)
        .map_err(|e| VaultError::Metadata(format!("encode reveal fields: {e}")))?;
    let mut payload = REVEAL_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(recipient_wrap_pub);
    payload.extend_from_slice(&expires_at.to_le_bytes());
    payload.extend_from_slice(&created_at.to_le_bytes());
    payload.extend_from_slice(&(item_name.len() as u64).to_le_bytes());
    payload.extend_from_slice(item_name.as_bytes());
    payload.extend_from_slice(&(fields_json.len() as u64).to_le_bytes());
    payload.extend_from_slice(&fields_json);
    Ok(payload)
}

fn checked_payload_bytes(payload: &RevealPayload) -> Result<Vec<u8>, BaluardError> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|e| VaultError::Metadata(format!("encode reveal payload: {e}")))?;
    if bytes.len() > MAX_REVEAL_PAYLOAD_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "fields too large to share as a reveal".into(),
        )));
    }
    Ok(bytes)
}

fn checked_package_bytes(pkg: &RevealPackage) -> Result<Vec<u8>, BaluardError> {
    let bytes =
        serde_json::to_vec(pkg).map_err(|e| VaultError::Metadata(format!("encode reveal: {e}")))?;
    if bytes.len() > MAX_REVEAL_FILE_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "reveal file exceeds maximum size".into(),
        )));
    }
    Ok(bytes)
}

fn sealed_doc(
    payload_bytes: &[u8],
    expires_at: u64,
    key: &[u8; 32],
) -> Result<serde_json::Value, BaluardError> {
    let sealed =
        crate::secret_file::seal_secret_blob(key, payload_bytes, &expiry_purpose(expires_at))?;
    serde_json::from_slice(&sealed)
        .map_err(|e| VaultError::Metadata(format!("sealed payload doc: {e}")).into())
}

/// Seal a contact-key reveal: HPKE-wrapped to the recipient's card wrap
/// pubkey, sender-attributed by the identity signature. Level 1 trust.
pub fn seal_contact_reveal(
    sender_card: SignedContactCard,
    sender_signing_key: &ed25519_dalek::SigningKey,
    item_name: &str,
    fields: &RevealFields,
    expires_at: u64,
    recipient_wrap_pub: &[u8; 32],
) -> Result<Vec<u8>, BaluardError> {
    let payload_created_at = now_unix();
    let payload = RevealPayload {
        sender_card: Some(sender_card),
        sender_signature: Some(hex::encode(
            signature::sign(
                sender_signing_key,
                &reveal_sign_payload(
                    recipient_wrap_pub,
                    expires_at,
                    payload_created_at,
                    item_name,
                    fields,
                )?,
            )?
            .to_bytes(),
        )),
        created_at: payload_created_at,
        expires_at,
        item_name: item_name.to_string(),
        fields: fields.clone(),
    };
    let payload_bytes = checked_payload_bytes(&payload)?;

    let mut content_key = Zeroizing::new([0u8; 32]);
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(content_key.as_mut());
    let sealed = sealed_doc(&payload_bytes, expires_at, &content_key)?;

    let recipient_pub = x25519_dalek::PublicKey::from(*recipient_wrap_pub);
    let (eph, ct, tag) = hpke_wrap::wrap_key(&content_key[..], &recipient_pub, REVEAL_CONTEXT)?;
    drop(content_key);

    let b64 = base64::engine::general_purpose::STANDARD;
    let pkg = RevealPackage {
        format: REVEAL_FORMAT,
        expires_at,
        wrap: RevealWrap::Contact {
            ephemeral_public: b64.encode(eph),
            encrypted_key: b64.encode(ct),
            wrap_tag: b64.encode(tag),
        },
        payload: sealed,
    };
    checked_package_bytes(&pkg)
}

/// Seal a passphrase-guest reveal: Argon2id over an app-generated
/// passphrase, no identity involved (Level 0). Returns the file bytes
/// and the passphrase to deliver out-of-band (voice).
pub fn seal_guest_reveal(
    item_name: &str,
    fields: &RevealFields,
    expires_at: u64,
) -> Result<(Vec<u8>, String), BaluardError> {
    let payload = RevealPayload {
        sender_card: None,
        sender_signature: None,
        created_at: now_unix(),
        expires_at,
        item_name: item_name.to_string(),
        fields: fields.clone(),
    };
    let payload_bytes = checked_payload_bytes(&payload)?;

    let passphrase = crate::generator::generate_passphrase(&crate::generator::PassphraseOptions {
        word_count: GUEST_PASSPHRASE_WORDS,
        separator: "-".into(),
        ..Default::default()
    })
    .map_err(|e| VaultError::Metadata(format!("generate passphrase: {e}")))?;

    let params = kdf::create_params(KdfProfile::DesktopStd);
    let key = Zeroizing::new(kdf::derive_kek(&passphrase, &params)?);

    let sealed = sealed_doc(&payload_bytes, expires_at, &key)?;
    let pkg = RevealPackage {
        format: REVEAL_FORMAT,
        expires_at,
        wrap: RevealWrap::Passphrase { kdf: params },
        payload: sealed,
    };
    Ok((checked_package_bytes(&pkg)?, passphrase))
}

fn parse_envelope(bytes: &[u8]) -> Result<RevealPackage, BaluardError> {
    if bytes.len() > MAX_REVEAL_FILE_BYTES {
        return Err(BaluardError::from(VaultError::Corrupt(
            "reveal too large".into(),
        )));
    }
    let pkg: RevealPackage = serde_json::from_slice(bytes)
        .map_err(|e| VaultError::Corrupt(format!("reveal envelope: {e}")))?;
    if pkg.format != REVEAL_FORMAT {
        return Err(BaluardError::from(VaultError::InvalidEnvelopeVersion(
            pkg.format.min(u8::MAX as u32) as u8,
        )));
    }
    Ok(pkg)
}

fn check_not_expired(expires_at: u64, now: u64) -> Result<(), BaluardError> {
    if expires_at <= now {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "This share has expired. Ask for a new one.".into(),
        )));
    }
    Ok(())
}

/// Clamp attacker-controlled KDF params before deriving (see the
/// ceiling constants).
fn clamped_guest_kdf(params: &KdfParams) -> KdfParams {
    let mut clamped = params.clone();
    clamped.memory_kib = clamped.memory_kib.min(GUEST_KDF_MAX_MEMORY_KIB);
    clamped.time_cost = clamped.time_cost.min(GUEST_KDF_MAX_TIME_COST);
    clamped.parallelism = clamped.parallelism.min(GUEST_KDF_MAX_PARALLELISM);
    clamped
}

fn payload_from_doc(pkg: &RevealPackage, key: &[u8; 32]) -> Result<RevealPayload, BaluardError> {
    let payload_doc = serde_json::to_vec(&pkg.payload)
        .map_err(|e| VaultError::Corrupt(format!("reveal payload doc: {e}")))?;
    let payload_bytes =
        crate::secret_file::open_secret_blob(key, &payload_doc, &expiry_purpose(pkg.expires_at))?;
    let payload: RevealPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VaultError::Corrupt(format!("reveal payload: {e}")))?;
    // The sealed copy must agree with the envelope field that fed the
    // AAD marker. Equality holds by construction; a mismatch means the
    // envelope shape drifted, so fail closed.
    if payload.expires_at != pkg.expires_at {
        return Err(BaluardError::from(VaultError::Corrupt(
            "reveal expiry mismatch".into(),
        )));
    }
    Ok(payload)
}

fn opened_from_payload(payload: RevealPayload) -> OpenedReveal {
    let (totp_code, totp_valid_until) = match payload.fields.totp_uri.as_deref() {
        Some(uri) => match totp::parse_totp_uri(uri) {
            Ok(params) => {
                let (code, _, valid_until) = totp::generate_totp(&params);
                (Some(code), Some(valid_until))
            }
            Err(_) => (None, None),
        },
        None => (None, None),
    };
    OpenedReveal {
        item_name: payload.item_name,
        sender_name: payload.sender_card.map(|c| c.card.display_name),
        created_at: payload.created_at,
        expires_at: payload.expires_at,
        url: payload.fields.url,
        username: payload.fields.username,
        password: payload.fields.password,
        totp_code,
        totp_valid_until,
    }
}

/// Open a contact-key reveal with the recipient's identity. Verifies
/// expiry, the sender card, and the sender signature before returning.
pub fn open_contact_reveal(
    bytes: &[u8],
    recipient: &IdentityKeys,
    now: u64,
) -> Result<OpenedReveal, BaluardError> {
    let pkg = parse_envelope(bytes)?;
    let RevealWrap::Contact {
        ephemeral_public,
        encrypted_key,
        wrap_tag,
    } = &pkg.wrap
    else {
        return Err(BaluardError::from(VaultError::Corrupt(
            "reveal is not a contact reveal".into(),
        )));
    };
    check_not_expired(pkg.expires_at, now)?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let eph = b64
        .decode(ephemeral_public)
        .map_err(|_| VaultError::Corrupt("reveal ephemeral key".into()))?;
    let ct = b64
        .decode(encrypted_key)
        .map_err(|_| VaultError::Corrupt("reveal wrapped key".into()))?;
    let tag: [u8; 16] = b64
        .decode(wrap_tag)
        .map_err(|_| VaultError::Corrupt("reveal wrap tag".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("reveal wrap tag length".into()))?;

    let mut content_key = Zeroizing::new(hpke_wrap::unwrap_key(
        &eph,
        &ct,
        &tag,
        recipient.wrapping_secret(),
        REVEAL_CONTEXT,
    )?);
    let content_key_arr: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt("reveal content key length invalid".into()))?;
    let content_key_arr = Zeroizing::new(content_key_arr);
    content_key.zeroize();

    let payload = payload_from_doc(&pkg, &content_key_arr)?;

    let card = payload
        .sender_card
        .as_ref()
        .ok_or_else(|| BaluardError::from(VaultError::Corrupt("reveal has no sender".into())))?;
    card.verify().map_err(|_| {
        BaluardError::from(VaultError::Metadata(
            "reveal sender card signature invalid".into(),
        ))
    })?;

    let signature_hex = payload
        .sender_signature
        .as_deref()
        .ok_or_else(|| BaluardError::from(VaultError::Corrupt("reveal has no signature".into())))?;
    let vk_bytes: [u8; 32] = hex::decode(&card.card.identity_signing_pubkey)
        .map_err(|_| VaultError::Corrupt("reveal sender pubkey hex".into()))?
        .try_into()
        .map_err(|_| VaultError::Corrupt("reveal sender pubkey length".into()))?;
    let vk = signature::verifying_key_from_bytes(&vk_bytes)
        .map_err(|_| VaultError::Corrupt("reveal sender pubkey invalid".into()))?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| VaultError::Corrupt("reveal signature hex".into()))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| VaultError::Corrupt("reveal signature length".into()))?;
    signature::verify(
        &vk,
        &reveal_sign_payload(
            &recipient.wrapping_pub_bytes(),
            payload.expires_at,
            payload.created_at,
            &payload.item_name,
            &payload.fields,
        )?,
        &sig,
    )
    .map_err(|_| BaluardError::from(VaultError::Metadata("reveal signature invalid".into())))?;

    Ok(opened_from_payload(payload))
}

/// Open a passphrase-guest reveal. No vault, no identity: the
/// passphrase is the only credential (Level 0).
pub fn open_guest_reveal(
    bytes: &[u8],
    passphrase: &str,
    now: u64,
) -> Result<OpenedReveal, BaluardError> {
    let pkg = parse_envelope(bytes)?;
    let RevealWrap::Passphrase { kdf: params } = &pkg.wrap else {
        return Err(BaluardError::from(VaultError::Corrupt(
            "reveal is not a passphrase reveal".into(),
        )));
    };
    check_not_expired(pkg.expires_at, now)?;

    let key = Zeroizing::new(kdf::derive_kek(passphrase, &clamped_guest_kdf(params))?);
    let payload = payload_from_doc(&pkg, &key)?;
    Ok(opened_from_payload(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> RevealFields {
        RevealFields {
            url: Some("https://app.example.com".into()),
            username: Some("ada".into()),
            password: Some("hunter2".into()),
            totp_uri: None,
        }
    }

    fn sender_card(signing: &ed25519_dalek::SigningKey, wrap_pub: &[u8; 32]) -> SignedContactCard {
        SignedContactCard::sign(
            "Sender",
            &hex::encode(signing.verifying_key().as_bytes()),
            &hex::encode(wrap_pub),
            1_700_000_000,
            signing,
        )
        .unwrap()
    }

    const DAY: u64 = 86_400;

    #[test]
    fn contact_reveal_roundtrip() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let expires = now_unix() + DAY;
        let bytes = seal_contact_reveal(
            card,
            sender.signing_key(),
            "Team login",
            &fields(),
            expires,
            &recipient.wrapping_pub_bytes(),
        )
        .unwrap();
        let opened = open_contact_reveal(&bytes, &recipient, now_unix()).unwrap();
        assert_eq!(opened.item_name, "Team login");
        assert_eq!(opened.sender_name.as_deref(), Some("Sender"));
        assert_eq!(opened.username.as_deref(), Some("ada"));
        assert_eq!(opened.password.as_deref(), Some("hunter2"));
        assert_eq!(opened.totp_code, None);
    }

    #[test]
    fn contact_reveal_wrong_recipient_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let stranger = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let bytes = seal_contact_reveal(
            card,
            sender.signing_key(),
            "n",
            &fields(),
            now_unix() + DAY,
            &recipient.wrapping_pub_bytes(),
        )
        .unwrap();
        assert!(open_contact_reveal(&bytes, &stranger, now_unix()).is_err());
    }

    #[test]
    fn contact_reveal_expired_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let bytes = seal_contact_reveal(
            card,
            sender.signing_key(),
            "n",
            &fields(),
            now_unix() - 60,
            &recipient.wrapping_pub_bytes(),
        )
        .unwrap();
        let err = open_contact_reveal(&bytes, &recipient, now_unix()).unwrap_err();
        assert!(err.to_string().contains("expired"), "err: {err}");
    }

    #[test]
    fn contact_reveal_tampered_fields_fail_signature() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let expires = now_unix() + DAY;

        // The recipient legitimately opened a first reveal; its fields
        // signature is now out in the world (screenshot, forwarded
        // message). The attacker re-seals DIFFERENT fields AND a
        // different item label under that captured signature.
        let forged_created_at = now_unix();
        let captured_sig = hex::encode(
            signature::sign(
                sender.signing_key(),
                &reveal_sign_payload(
                    &recipient.wrapping_pub_bytes(),
                    expires,
                    forged_created_at,
                    "Team login",
                    &fields(),
                )
                .unwrap(),
            )
            .unwrap()
            .to_bytes(),
        );
        let mut evil_fields = fields();
        evil_fields.password = Some("evil".into());
        let payload = RevealPayload {
            sender_card: Some(card),
            sender_signature: Some(captured_sig),
            created_at: forged_created_at,
            expires_at: expires,
            item_name: "Phishing Bank".into(),
            fields: evil_fields,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut content_key = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut content_key);
        let sealed = sealed_doc(&payload_bytes, expires, &content_key).unwrap();
        let recipient_pub = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&content_key, &recipient_pub, REVEAL_CONTEXT).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = RevealPackage {
            format: REVEAL_FORMAT,
            expires_at: expires,
            wrap: RevealWrap::Contact {
                ephemeral_public: b64.encode(eph),
                encrypted_key: b64.encode(ct),
                wrap_tag: b64.encode(tag),
            },
            payload: sealed,
        };
        let forged_bytes = serde_json::to_vec(&pkg).unwrap();

        let err = open_contact_reveal(&forged_bytes, &recipient, now_unix()).unwrap_err();
        assert!(
            err.to_string().contains("reveal signature invalid"),
            "must refuse swapped fields: {err}"
        );
    }

    #[test]
    fn contact_reveal_rewrapped_for_different_recipient_refused() {
        let sender = IdentityKeys::generate().unwrap();
        let recipient1 = IdentityKeys::generate().unwrap();
        let recipient2 = IdentityKeys::generate().unwrap();
        let card = sender_card(sender.signing_key(), &sender.wrapping_pub_bytes());
        let expires = now_unix() + DAY;
        let created = now_unix();

        // A signature legitimately bound to recipient1 leaks out; the
        // attacker re-wraps the same payload to recipient2.
        let captured_sig = hex::encode(
            signature::sign(
                sender.signing_key(),
                &reveal_sign_payload(
                    &recipient1.wrapping_pub_bytes(),
                    expires,
                    created,
                    "n",
                    &fields(),
                )
                .unwrap(),
            )
            .unwrap()
            .to_bytes(),
        );
        let payload = RevealPayload {
            sender_card: Some(card),
            sender_signature: Some(captured_sig),
            created_at: created,
            expires_at: expires,
            item_name: "n".into(),
            fields: fields(),
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut content_key = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut content_key);
        let sealed = sealed_doc(&payload_bytes, expires, &content_key).unwrap();
        let recipient2_pub = x25519_dalek::PublicKey::from(recipient2.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&content_key, &recipient2_pub, REVEAL_CONTEXT).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = RevealPackage {
            format: REVEAL_FORMAT,
            expires_at: expires,
            wrap: RevealWrap::Contact {
                ephemeral_public: b64.encode(eph),
                encrypted_key: b64.encode(ct),
                wrap_tag: b64.encode(tag),
            },
            payload: sealed,
        };
        let bytes = serde_json::to_vec(&pkg).unwrap();
        let err = open_contact_reveal(&bytes, &recipient2, now_unix()).unwrap_err();
        assert!(
            err.to_string().contains("reveal signature invalid"),
            "must refuse retargeted reveal: {err}"
        );
    }

    #[test]
    fn guest_reveal_hostile_kdf_params_refused_without_abort() {
        let expires = now_unix() + DAY;
        let (bytes, _passphrase) = seal_guest_reveal("Wifi", &fields(), expires).unwrap();
        // Hostile envelope: terabytes of Argon2id memory. The clamp must
        // cap the derivation so this returns an error (wrong key) instead
        // of aborting the process on allocation failure.
        let hostile = std::str::from_utf8(&bytes)
            .unwrap()
            .replace("\"memory_kib\":65536", "\"memory_kib\":1073741824")
            .replace("\"time_cost\":3", "\"time_cost\":9999")
            .replace("\"parallelism\":2", "\"parallelism\":4096");
        assert_ne!(
            hostile,
            std::str::from_utf8(&bytes).unwrap(),
            "tamper must apply"
        );
        let err = open_guest_reveal(&hostile.into_bytes(), "whatever", now_unix()).unwrap_err();
        let _ = err; // any error is fine; the point is returning, not aborting
    }

    #[test]
    fn guest_reveal_roundtrip() {
        let expires = now_unix() + DAY;
        let (bytes, passphrase) = seal_guest_reveal("Wifi", &fields(), expires).unwrap();
        let opened = open_guest_reveal(&bytes, &passphrase, now_unix()).unwrap();
        assert_eq!(opened.item_name, "Wifi");
        assert_eq!(opened.password.as_deref(), Some("hunter2"));
        assert_eq!(opened.sender_name, None, "guest flavor has no identity");
    }

    #[test]
    fn guest_reveal_wrong_passphrase_refused() {
        let expires = now_unix() + DAY;
        let (bytes, _passphrase) = seal_guest_reveal("Wifi", &fields(), expires).unwrap();
        assert!(open_guest_reveal(&bytes, "wrong-passphrase", now_unix()).is_err());
    }

    #[test]
    fn guest_reveal_expired_refused() {
        let expires = now_unix() - 60;
        let (bytes, passphrase) = seal_guest_reveal("Wifi", &fields(), expires).unwrap();
        let err = open_guest_reveal(&bytes, &passphrase, now_unix()).unwrap_err();
        assert!(err.to_string().contains("expired"), "err: {err}");
    }

    #[test]
    fn guest_reveal_envelope_expiry_tamper_refused() {
        let expires = now_unix() + DAY;
        let (mut bytes, passphrase) = seal_guest_reveal("Wifi", &fields(), expires).unwrap();
        // Push the envelope expiry far into the future; the AAD marker
        // no longer matches, so the seal refuses to open.
        let far_future = now_unix() + 365 * DAY;
        let text = std::str::from_utf8(&bytes).unwrap().replace(
            &format!("\"expires_at\":{expires}"),
            &format!("\"expires_at\":{far_future}"),
        );
        bytes = text.into_bytes();
        let err = open_guest_reveal(&bytes, &passphrase, now_unix()).unwrap_err();
        assert!(
            !(err.to_string().contains("expired")),
            "tampered expiry must fail the seal, not read as expired: {err}"
        );
    }

    #[test]
    fn contact_reveal_short_content_key_refused_without_panic() {
        let recipient = IdentityKeys::generate().unwrap();
        // HPKE-wrap a 16-byte key; the open path must reject the length,
        // never panic on the copy.
        let short_key = [1u8; 16];
        let recipient_pub = x25519_dalek::PublicKey::from(recipient.wrapping_pub_bytes());
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(&short_key, &recipient_pub, REVEAL_CONTEXT).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let pkg = RevealPackage {
            format: REVEAL_FORMAT,
            expires_at: now_unix() + DAY,
            wrap: RevealWrap::Contact {
                ephemeral_public: b64.encode(eph),
                encrypted_key: b64.encode(ct),
                wrap_tag: b64.encode(tag),
            },
            payload: serde_json::json!({}),
        };
        let bytes = serde_json::to_vec(&pkg).unwrap();
        let err = open_contact_reveal(&bytes, &recipient, now_unix()).unwrap_err();
        assert!(
            err.to_string().contains("content key length invalid"),
            "err: {err}"
        );
    }

    #[test]
    fn garbage_refused() {
        let recipient = IdentityKeys::generate().unwrap();
        assert!(open_contact_reveal(b"not a reveal", &recipient, now_unix()).is_err());
        assert!(open_guest_reveal(b"not a reveal", "pw", now_unix()).is_err());
    }
}
