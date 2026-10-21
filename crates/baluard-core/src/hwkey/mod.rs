//! Hardware-backed key-store trait: the progressive-enhancement seam for
//! the `baluard-devkey-seal-v2-hw` devkey seal (plan:
//! `docs/plan-hardware-backed-keys.md`).
//!
//! A device with a usable security chip (Secure Enclave, TPM 2.0) installs
//! a [`HardwareKeyStore`] implementation at daemon startup; devices without
//! one install nothing and every surface stays exactly as it is today
//! (seal v1). The chip never holds vault keys - it contributes an ECDH
//! secret to the seal's content key, so both the password AND the chip are
//! required to open the sealed file, while unlock friction stays zero.
//!
//! Platform backends live behind the `hw-seal` cargo feature. The daemon
//! owns all hardware operations; CLI, desktop frontend, NMH, and mobile
//! never touch a keystore directly.

use std::sync::Arc;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{BaluardError, VaultError};

/// Env kill-switch, mirroring `BALUARD_DISABLE_KEYRING`: setting
/// `BALUARD_DISABLE_HWKEY=1` makes every probe report unavailable so
/// `just test` and CI stay hermetic on machines that happen to have a chip.
pub const DISABLE_ENV: &str = "BALUARD_DISABLE_HWKEY";

/// Fresh per-write public input to the chip's ECDH, in the backend's own
/// wire format (X9.62 uncompressed for SE backends; opaque bytes for the
/// mock). The seal layer never interprets it - it only stores the bytes
/// and hands them back on open, so the backend can re-run the same
/// agreement deterministically.
#[derive(Clone, Copy)]
pub struct EphemeralPub(pub [u8; 65]);

/// The ECDH output. Never leaves the process; zeroized on drop.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// Result of probing this device for a usable hardware keystore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwCapability {
    /// The chip is present, usable, and not disabled. `backend` names the
    /// platform implementation for status copy ("secure-enclave",
    /// "tpm-pcp", "tpm-esapi").
    Available { backend: String },
    /// No usable chip, or the kill-switch is set. `reason` is a plain
    /// lowercase machine reason ("disabled", "no-tpm", "tpm-without-pcp",
    /// "driver-error") for honest status copy, never shown raw to users.
    Unavailable { reason: String },
}

/// One platform's hardware keystore. Binding ids are opaque platform
/// references (a keychain-persisted tag, a PCP key name, an ESAPI handle)
/// that the seal file stores so later opens find the right key. Bindings
/// are namespaced per vault via [`binding_tag`], the same discipline as
/// quick-unlock's `quick-unlock:<vault_id>`.
pub trait HardwareKeyStore: Send + Sync {
    fn probe(&self) -> HwCapability;
    /// Create (or return the existing) binding for this vault.
    fn create_binding(&self, vault_id: Uuid) -> Result<String, BaluardError>;
    /// Generate a fresh ephemeral input IN THE BACKEND'S PRIMITIVE FAMILY
    /// (the seal layer cannot know it - SE needs a P-256 point) and return
    /// it with the ECDH against the binding's non-exportable key. The
    /// seal layer stores the public half; [`Self::ecdh`] must reproduce
    /// the same secret from the stored bytes.
    fn ecdh_ephemeral(&self, binding: &str) -> Result<(EphemeralPub, SharedSecret), BaluardError>;
    /// ECDH between the binding's non-exportable key and a stored
    /// `peer`. Must be silent (no per-use user consent) - the v2-hw seal
    /// runs on every unlock and password change.
    fn ecdh(&self, binding: &str, peer: &EphemeralPub) -> Result<SharedSecret, BaluardError>;
    /// Idempotent. Implementations whose key is shared infrastructure
    /// (the TPM backend: slot-constrained firmwares get one chip key
    /// for all vaults) treat this as a no-op - disable downsizes the
    /// seal to v1 and leaves the key in place.
    fn delete_binding(&self, binding: &str) -> Result<(), BaluardError>;
}

/// Deterministic per-vault binding tag.
pub fn binding_tag(vault_id: Uuid) -> String {
    format!("baluard-hw:{vault_id}")
}

fn hw_disabled() -> bool {
    std::env::var(DISABLE_ENV).is_ok_and(|v| v == "1")
}

static HW_STORE: std::sync::OnceLock<std::sync::RwLock<Option<Arc<dyn HardwareKeyStore>>>> =
    std::sync::OnceLock::new();

fn hw_store() -> &'static std::sync::RwLock<Option<Arc<dyn HardwareKeyStore>>> {
    HW_STORE.get_or_init(|| std::sync::RwLock::new(None))
}

/// Install the platform keystore at daemon startup. A second install
/// replaces the first (matters for tests).
pub fn install(store: Arc<dyn HardwareKeyStore>) {
    *hw_store().write().expect("hw store lock") = Some(store);
}

/// Remove the installed keystore (tests).
pub fn uninstall() {
    *hw_store().write().expect("hw store lock") = None;
}

/// The installed keystore, if any. Callers must still probe before use.
pub fn installed() -> Option<Arc<dyn HardwareKeyStore>> {
    hw_store().read().expect("hw store lock").clone()
}

/// The keystore to use right now: installed, kill-switch off, and probing
/// available. `None` means this device has no usable chip - every surface
/// treats that as "feature not present" (progressive enhancement).
pub fn available() -> Option<Arc<dyn HardwareKeyStore>> {
    if hw_disabled() {
        return None;
    }
    let store = installed()?;
    matches!(store.probe(), HwCapability::Available { .. }).then_some(store)
}

/// Probe for status surfaces: reports the kill-switch and unavailable
/// reasons instead of collapsing them to `None`.
pub fn probe_status() -> HwCapability {
    if hw_disabled() {
        return HwCapability::Unavailable {
            reason: "disabled".into(),
        };
    }
    match installed() {
        None => HwCapability::Unavailable {
            reason: "no-backend".into(),
        },
        Some(s) => s.probe(),
    }
}

/// Shared-secret derivation used by the v2-hw seal:
/// `HKDF-SHA256(ikm = hw_secret || kek_subkey, info = seal-type bytes)`.
/// Public so the seal layer and its tests share one construction.
pub fn combine_seal_inputs(hw_secret: &[u8; 32], kek_subkey: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(hw_secret);
    ikm[32..].copy_from_slice(kek_subkey);
    let hk = Hkdf::<Sha256>::new(None, &*ikm);
    let mut okm = [0u8; 32];
    hk.expand(
        crate::vault::device_privkey::SEAL_TYPE_HW.as_bytes(),
        &mut okm,
    )
    .expect("32-byte okm");
    okm
}

#[cfg(all(target_os = "macos", feature = "hw-seal"))]
pub mod secure_enclave;

#[cfg(all(target_os = "linux", feature = "hw-seal"))]
pub mod tpm;

#[cfg(all(target_os = "windows", feature = "hw-seal"))]
pub mod pcp;

/// The platform keystore for THIS device, per the platform matrix (plan
/// §3.3). Returns None where no backend is compiled - the progressive
/// default on platforms without a landed backend.
pub fn platform_store() -> Option<Arc<dyn HardwareKeyStore>> {
    #[cfg(all(target_os = "macos", feature = "hw-seal"))]
    {
        Some(secure_enclave::SecureEnclaveStore::new())
    }
    #[cfg(all(target_os = "linux", feature = "hw-seal"))]
    {
        tpm::TpmStore::new()
            .ok()
            .map(|s| s as Arc<dyn HardwareKeyStore>)
    }
    #[cfg(all(target_os = "windows", feature = "hw-seal"))]
    {
        Some(pcp::PcpStore::new())
    }
    #[cfg(not(any(
        all(target_os = "macos", feature = "hw-seal"),
        all(target_os = "linux", feature = "hw-seal"),
        all(target_os = "windows", feature = "hw-seal")
    )))]
    {
        None
    }
}

/// Typed error for "the file demands the chip but the chip is gone". The
/// rescue is the existing phrase path; surfaces map this to plain copy
/// pointing at the recovery flow and the settings toggle.
pub fn hw_unavailable_error() -> BaluardError {
    BaluardError::from(VaultError::HardwareUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Software mock: X25519 agreement over the opaque peer bytes. Real
    /// backends use P-256 inside the chip; the seal layer treats the
    /// secret as opaque, so the mock exercises the same contract.
    struct MockStore;

    impl HardwareKeyStore for MockStore {
        fn probe(&self) -> HwCapability {
            HwCapability::Available {
                backend: "mock".into(),
            }
        }
        fn create_binding(&self, vault_id: Uuid) -> Result<String, BaluardError> {
            Ok(binding_tag(vault_id))
        }
        fn ecdh_ephemeral(
            &self,
            binding: &str,
        ) -> Result<(EphemeralPub, SharedSecret), BaluardError> {
            use sha2::{Digest, Sha256};
            // Random-looking fresh public in the mock's opaque format.
            let mut peer = [0u8; 65];
            peer[0] = 0x04;
            rand::Rng::fill(&mut rand::thread_rng(), &mut peer[1..]);
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(peer);
            Ok((EphemeralPub(peer), Zeroizing::new(h.finalize().into())))
        }
        fn ecdh(&self, binding: &str, peer: &EphemeralPub) -> Result<SharedSecret, BaluardError> {
            // binding and peer are both opaque here; derive deterministically.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(peer.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _binding: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    #[test]
    fn install_probe_and_available_flow() {
        uninstall();
        assert_eq!(
            probe_status(),
            HwCapability::Unavailable {
                reason: "no-backend".into()
            }
        );
        assert!(available().is_none());

        install(Arc::new(MockStore));
        assert_eq!(
            probe_status(),
            HwCapability::Available {
                backend: "mock".into()
            }
        );
        let s = available().expect("available with mock installed");
        let b = s.create_binding(Uuid::new_v4()).unwrap();
        let secret = s.ecdh(&b, &EphemeralPub([7u8; 65])).expect("mock ecdh");
        assert_eq!(secret.len(), 32);
        uninstall();
        assert!(available().is_none());
    }

    #[test]
    fn binding_tag_namespaces_by_vault() {
        let a = binding_tag(Uuid::new_v4());
        let b = binding_tag(Uuid::new_v4());
        assert_ne!(a, b);
        assert!(a.starts_with("baluard-hw:"));
    }
}
