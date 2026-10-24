//! macOS Secure Enclave key-agreement backend (plan:
//! `docs/plan-hardware-backed-keys.md` §3.3, Phase 1).
//!
//! Built on the `secure-enclave-rs` crate (BSD-3-Clause): SE-resident
//! P-256 keys whose private half is non-exportable by construction. Keys
//! persist in the keychain by application tag
//! (`baluard-hw:<vault_id>`); the binding id stored in the seal file is
//! that tag, so every open finds the same chip key.
//!
//! Platform requirements (crate README, verified 2026-10-20): the binary
//! must be code-signed; PERSISTENT keys additionally need an Apple
//! Development identity, a keychain-access-groups entitlement, and an
//! embedded provisioning profile - without them SecItemAdd returns
//! errSecMissingEntitlement. The daemon already carries the stable
//! Development signing identity (`xyz.actitud.baluard.daemon`, the P2
//! gotcha); the entitlement + profile are an Esteban-side packaging step.
//!
//! Silence: the chip key's access flags carry only PRIVATE_KEY_USAGE, so
//! ECDH never prompts - the seal runs on every unlock and password
//! change. Consent-gated variants are plan Phase 5.
//!
//! Thread safety: `SecureEnclaveKey` handles are pinned to their creating
//! thread, so every trait call constructs its handle (keychain `get`)
//! and drops it inside the call; nothing crosses threads.

use std::sync::Arc;

use secure_enclave_rs::{SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{BaluardError, VaultError};
use crate::hwkey::{EphemeralPub, HardwareKeyStore, HwCapability, SharedSecret};

const TAG_PREFIX: &str = "baluard-hw:";

pub struct SecureEnclaveStore;

/// Cached result of the consent-capability probe: a REAL throwaway
/// keygen with the per-use ACL. Static because Apple silicon without a
/// Touch ID sensor (Mac mini/Studio) has a working Secure Enclave but can
/// never create such a key - declaring consent there would surface a
/// broken toggle.
static CONSENT_CAPABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Map a secure-enclave-rs failure to the typed surface: an auth failure
/// or cancellation is retryable (distinct copy), everything else means
/// the key or chip is gone (phrase rescue).
fn map_se_err(e: secure_enclave_rs::Error) -> BaluardError {
    match e {
        secure_enclave_rs::Error::AuthFailed | secure_enclave_rs::Error::UserCancelled => {
            VaultError::HardwareAuthFailed.into()
        }
        _ => crate::hwkey::hw_unavailable_error(),
    }
}

impl SecureEnclaveStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    fn tag_for(vault_id: Uuid) -> Vec<u8> {
        format!("{TAG_PREFIX}{vault_id}").into_bytes()
    }
}

impl HardwareKeyStore for SecureEnclaveStore {
    fn probe(&self) -> HwCapability {
        // Honest probe: SE availability is only answerable by asking the
        // chip. Mint a throwaway NON-permanent key (code-signature only,
        // no provisioning profile); looking up a fixed tag would always
        // miss and read as "no Secure Enclave".
        let probe = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
            tag: b"baluard-hw:probe",
            access_flags: SecAccessControlFlags::empty(),
            permanent: false,
        });
        match probe {
            Ok(_) => HwCapability::Available {
                backend: "secure-enclave".into(),
            },
            Err(_) => HwCapability::Unavailable {
                reason: "secure-enclave-unavailable".into(),
            },
        }
    }

    fn supports_consent(&self) -> bool {
        *CONSENT_CAPABLE.get_or_init(|| {
            SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
                tag: b"baluard-hw:consent-probe",
                access_flags: SecAccessControlFlags::PRIVATE_KEY_USAGE
                    | SecAccessControlFlags::BIOMETRY_CURRENT_SET,
                permanent: false,
            })
            .is_ok()
        })
    }

    fn create_binding(
        &self,
        vault_id: Uuid,
        consent: crate::hwkey::HwConsent,
    ) -> Result<String, BaluardError> {
        let tag = if consent.is_per_use() {
            crate::hwkey::consent_binding_tag(vault_id).into_bytes()
        } else {
            Self::tag_for(vault_id)
        };
        // Idempotent per vault: reuse the persisted chip key when present.
        if SecureEnclaveKey::get(&tag).is_ok() {
            return Ok(
                String::from_utf8(tag).map_err(|_| VaultError::Corrupt("hwkey tag utf8".into()))?
            );
        }
        // Per-use keys carry BIOMETRY_CURRENT_SET: every agreement pops
        // Touch ID, and re-enrolled biometry invalidates the key (the
        // phrase path rescues). Silent keys keep the empty flags.
        let access_flags = if consent.is_per_use() {
            SecAccessControlFlags::PRIVATE_KEY_USAGE | SecAccessControlFlags::BIOMETRY_CURRENT_SET
        } else {
            SecAccessControlFlags::empty()
        };
        SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
            tag: &tag,
            access_flags,
            permanent: true,
        })
        .map_err(|e| VaultError::Metadata(format!("hwkey SE generate: {e}")))?;
        Ok(String::from_utf8(tag).map_err(|_| VaultError::Corrupt("hwkey tag utf8".into()))?)
    }

    fn ecdh_ephemeral(
        &self,
        binding: &str,
        _consent: crate::hwkey::HwConsent,
    ) -> Result<(EphemeralPub, SharedSecret), BaluardError> {
        let chip = SecureEnclaveKey::get(binding.as_bytes())
            .map_err(|_| crate::hwkey::hw_unavailable_error())?;
        // Throwaway in-memory SE key as the fresh peer input: SE keys can
        // only agree with valid P-256 points, so the ephemeral must come
        // from the same primitive family. `permanent: false` needs only a
        // code signature - no provisioning profile.
        let eph = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
            tag: b"baluard-hw:ephemeral",
            access_flags: SecAccessControlFlags::empty(),
            permanent: false,
        })
        .map_err(|_| crate::hwkey::hw_unavailable_error())?;
        let peer_bytes = eph
            .public_key_bytes()
            .map_err(|e| VaultError::Metadata(format!("hwkey ephemeral pubkey: {e}")))?;
        let mut peer = [0u8; 65];
        peer.copy_from_slice(&peer_bytes);
        let secret = derive(binding, &chip, &peer)?;
        Ok((EphemeralPub(peer), secret))
    }

    fn ecdh(
        &self,
        binding: &str,
        peer: &EphemeralPub,
        _consent: crate::hwkey::HwConsent,
    ) -> Result<SharedSecret, BaluardError> {
        let chip = SecureEnclaveKey::get(binding.as_bytes())
            .map_err(|_| crate::hwkey::hw_unavailable_error())?;
        derive(binding, &chip, &peer.0)
    }

    fn delete_binding(&self, binding: &str) -> Result<(), BaluardError> {
        // NotFound is the idempotent success case (crate semantics).
        match SecureEnclaveKey::remove_by_tag(binding.as_bytes()) {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(VaultError::Metadata(format!("hwkey SE delete: {e}")).into()),
        }
    }
}

/// ECDH between the chip key and a 65-byte X9.62 peer, 32 output bytes,
/// no KDF shared info (the seal layer applies its own HKDF over the
/// result). Failures surface as the typed unavailable error: a chip that
/// refuses to agree means the file is unwrappable right now.
fn derive(
    binding: &str,
    chip: &SecureEnclaveKey,
    peer: &[u8],
) -> Result<SharedSecret, BaluardError> {
    let _ = binding;
    let secret =
        secure_enclave_rs::derive_shared_secret(chip, peer, 32, &[]).map_err(map_se_err)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret);
    Ok(Zeroizing::new(out))
}
