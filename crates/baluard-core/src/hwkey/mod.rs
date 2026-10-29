//! Hardware-backed key-store trait: the progressive-enhancement seam for
//! the `baluard-devkey-seal-v2-hw` devkey seal (plan:
//! `docs/plan-hardware-backed-keys.md`).
//!
//! A device with a usable security chip (Secure Enclave, TPM 2.0) installs
//! a [`HardwareKeyStore`] implementation at daemon startup; devices without
//! one install nothing and every surface stays exactly as it is today
//! (seal v1). The chip never holds vault keys - it contributes an ECDH
//! secret to the seal's content key, so both the password AND the chip are
//! required to open the sealed file. Silent chips add zero unlock
//! friction; interactive backends (the FIDO2 security-key seal) demand
//! exactly one physical tap per use.
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

/// Fresh per-write public input to the chip's key agreement, in the
/// backend's own wire format (X9.62 uncompressed P-256 points for chip
/// backends; a 32-byte salt for the FIDO2 answerer). Opaque to the seal
/// layer: it stores the bytes and hands them back on open, so the
/// backend can reproduce the same secret deterministically. Length-bound
/// so a hostile seal file cannot drive allocation.
pub const MAX_HANDSHAKE_BYTES: usize = 65;

#[derive(Clone)]
pub struct Handshake(pub Vec<u8>);

impl Handshake {
    pub fn new(bytes: Vec<u8>) -> Result<Self, BaluardError> {
        if bytes.len() > MAX_HANDSHAKE_BYTES {
            return Err(VaultError::Corrupt("hardware handshake oversized".into()).into());
        }
        Ok(Handshake(bytes))
    }
}

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

/// How a backend's key agreement interacts with the human. `Never` chips
/// (Secure Enclave, TPM, PCP) answer silently; `PerUse` backends (FIDO2
/// security keys) physically refuse to answer without a tap. The seal
/// layer refuses to enable a `Silent` consent file on a `PerUse`
/// backend - the tap is not a prompt the firmware can waive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interaction {
    Never,
    PerUse,
}

/// One platform's hardware keystore. Bindings are opaque platform
/// references that the seal file stores so later opens find the right
/// key; [`Self::backend_id`] is the registry key the seal file records
/// so an open resolves the SAME backend that sealed it.
pub trait HardwareKeyStore: Send + Sync {
    /// Registry key and seal-file record ("secure-enclave", "tpm-esapi",
    /// "fido", "mock"). Must be unique per compiled backend.
    fn backend_id(&self) -> &'static str;
    fn probe(&self) -> HwCapability;
    /// Whether this backend's chips can demand the platform's own user
    /// verification on a chip agreement. Default: no - `PerUse` then
    /// refuses with `HardwareConsentUnavailable` everywhere.
    fn supports_consent(&self) -> bool {
        false
    }
    /// Whether using this backend's key demands human interaction every
    /// time. Default `Never` (silent chips); the FIDO2 backend is always
    /// `PerUse` - firmware refuses assertions without presence.
    fn interaction(&self) -> Interaction {
        Interaction::Never
    }
    /// Create (or return the existing) binding for this vault. A `PerUse`
    /// binding names a SEPARATE key whose every use demands user
    /// verification. Backends with an enroll-time attestation ceremony
    /// (FIDO2) report the verdict; chip backends return `None`.
    fn create_binding(
        &self,
        vault_id: Uuid,
        consent: HwConsent,
    ) -> Result<BindingInfo, BaluardError>;
    /// Generate a fresh ephemeral input IN THE BACKEND'S PRIMITIVE FAMILY
    /// (the seal layer cannot know it - chip backends need a P-256 point,
    /// the FIDO2 answerer picks a salt) and return it with the agreement
    /// against the binding's non-exportable key. The seal layer stores
    /// the handshake half; [`Self::derive`] must reproduce the same
    /// secret from the stored bytes. `PerUse` demands the platform's
    /// user verification on this call.
    fn derive_ephemeral(
        &self,
        binding: &str,
        consent: HwConsent,
    ) -> Result<(Handshake, SharedSecret), BaluardError>;
    /// Agreement between the binding's non-exportable key and a stored
    /// handshake. `Silent` must never prompt - the v2-hw seal runs on
    /// every unlock and password change; `PerUse` demands the platform's
    /// user verification each call.
    fn derive(
        &self,
        binding: &str,
        handshake: &Handshake,
        consent: HwConsent,
    ) -> Result<SharedSecret, BaluardError>;
    /// Idempotent. Implementations whose key is shared infrastructure
    /// (the TPM backend: slot-constrained firmwares get one chip key
    /// for all vaults; the FIDO2 credential survives disable) treat
    /// this as a no-op - disable downsizes the seal to v1 and leaves
    /// the key in place.
    fn delete_binding(&self, binding: &str) -> Result<(), BaluardError>;
}

/// Whether a chip ECDH demands the platform's own user verification
/// (Touch ID-class) before releasing its secret. `Silent` keys guard the
/// vault at rest; `PerUse` keys additionally refuse an on-device password
/// thief who cannot pass biometry - the Phase 5 upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwConsent {
    Silent,
    PerUse,
}

impl HwConsent {
    pub fn from_flag(flag: bool) -> Self {
        if flag {
            HwConsent::PerUse
        } else {
            HwConsent::Silent
        }
    }

    pub fn is_per_use(self) -> bool {
        matches!(self, HwConsent::PerUse)
    }
}

/// The enroll-time attestation outcome, recorded in the seal file for
/// status copy. Informational only: it is never an input to the open
/// path (the chip's answer is the proof, not the certificate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwAttestation {
    /// The chain verified against a bundled vendor root.
    Verified,
    /// The chain is self-consistent but the vendor root is unknown.
    UnknownVendor,
}

impl HwAttestation {
    pub fn as_str(self) -> &'static str {
        match self {
            HwAttestation::Verified => "verified",
            HwAttestation::UnknownVendor => "unknown-vendor",
        }
    }
}

/// What [`HardwareKeyStore::create_binding`] returns: the opaque binding
/// id plus the attestation verdict where the backend attests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingInfo {
    pub binding: String,
    pub attestation: Option<HwAttestation>,
}

/// Deterministic per-vault binding tag (silent keys).
pub fn binding_tag(vault_id: Uuid) -> String {
    format!("baluard-hw:{vault_id}")
}

/// Per-use-consent keys live in a SEPARATE binding (and a separate chip
/// key with its verification ACL): a silent file must never be opened by
/// a consenting key or vice versa.
pub fn consent_binding_tag(vault_id: Uuid) -> String {
    format!("baluard-hwc:{vault_id}")
}

pub fn binding_tag_for(vault_id: Uuid, consent: HwConsent) -> String {
    if consent.is_per_use() {
        consent_binding_tag(vault_id)
    } else {
        binding_tag(vault_id)
    }
}

/// Inverse of [`binding_tag`]/[`consent_binding_tag`].
pub fn binding_vault_id(binding: &str) -> Option<Uuid> {
    if let Some(rest) = binding.strip_prefix("fido:") {
        // fido:<vault_id>:<opaque credential id>
        return rest.split(':').next().and_then(|id| Uuid::parse_str(id).ok());
    }
    binding
        .strip_prefix("baluard-hwc:")
        .or_else(|| binding.strip_prefix("baluard-hw:"))
        .and_then(|id| Uuid::parse_str(id).ok())
}

fn hw_disabled() -> bool {
    std::env::var(DISABLE_ENV).is_ok_and(|v| v == "1")
}

static HW_STORE: std::sync::OnceLock<
    std::sync::RwLock<std::collections::BTreeMap<String, Arc<dyn HardwareKeyStore>>>,
> = std::sync::OnceLock::new();

fn hw_store()
-> &'static std::sync::RwLock<std::collections::BTreeMap<String, Arc<dyn HardwareKeyStore>>> {
    HW_STORE.get_or_init(|| std::sync::RwLock::new(std::collections::BTreeMap::new()))
}

/// Install a backend at daemon startup, keyed by its `backend_id`. A
/// re-install of the same id replaces that entry (tests); different ids
/// coexist so a machine can offer both a chip backend and a security
/// key.
pub fn install(store: Arc<dyn HardwareKeyStore>) {
    hw_store()
        .write()
        .expect("hw store lock")
        .insert(store.backend_id().to_string(), store);
}

/// Remove every installed backend (tests).
pub fn uninstall() {
    hw_store().write().expect("hw store lock").clear();
}

/// The backend a seal file was sealed with, if installed and the
/// kill-switch is off. An open resolves the SAME backend that sealed
/// the file; absence is the typed unavailable error, never a downgrade.
pub fn store_for(backend_id: &str) -> Option<Arc<dyn HardwareKeyStore>> {
    if hw_disabled() {
        return None;
    }
    hw_store().read().expect("hw store lock").get(backend_id).cloned()
}

/// Every installed backend, registry order. Status surfaces list these;
/// callers still probe before use.
pub fn installed_all() -> Vec<Arc<dyn HardwareKeyStore>> {
    hw_store().read().expect("hw store lock").values().cloned().collect()
}

/// The default keystore: the first installed backend probing available.
/// Single-chip devices have exactly one; multi-backend flows pass
/// explicit backend ids instead.
pub fn available() -> Option<Arc<dyn HardwareKeyStore>> {
    if hw_disabled() {
        return None;
    }
    installed_all().into_iter().find(|s| {
        matches!(s.probe(), HwCapability::Available { .. })
    })
}

/// Probe for status surfaces: reports the kill-switch and unavailable
/// reasons instead of collapsing them to `None`. Multi-backend status
/// listing rides the daemon layer; this reports the first installed
/// backend.
pub fn probe_status() -> HwCapability {
    if hw_disabled() {
        return HwCapability::Unavailable {
            reason: "disabled".into(),
        };
    }
    match installed_all().first() {
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

/// FIDO2 security-key backend (the hmac-secret seal). The contract and
/// the hermetic mock compile everywhere; the real ctap-hid-fido2 token
/// rides the `fido2` feature.
pub mod fido;

/// FIDO2 packed-attestation verification (the enroll-time
/// anti-counterfeit check; plan "Attestation at enroll").
pub mod attest;
pub mod cbor;

/// Transport-agnostic CTAP2 client (the mobile backend; plan slices 4A-4D).
#[cfg(feature = "ctap-client")]
pub mod ctap;

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

/// Serializes every test that touches the process-global keystore
/// registry (and the kill-switch env var) across ALL test modules - the
/// registry races otherwise, because cargo runs test modules in parallel.
#[cfg(test)]
pub(crate) static TEST_STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// Software mock: SHA-256 agreement over the opaque handshake bytes.
    /// Real chip backends agree inside the silicon; the seal layer treats
    /// the secret as opaque, so the mock exercises the same contract.
    struct MockStore;

    impl HardwareKeyStore for MockStore {
        fn backend_id(&self) -> &'static str {
            "mock"
        }
        fn probe(&self) -> HwCapability {
            HwCapability::Available {
                backend: "mock".into(),
            }
        }
        fn supports_consent(&self) -> bool {
            true
        }
        fn create_binding(
            &self,
            vault_id: Uuid,
            _consent: HwConsent,
        ) -> Result<BindingInfo, BaluardError> {
            Ok(BindingInfo {
                binding: binding_tag(vault_id),
                attestation: None,
            })
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _consent: HwConsent,
        ) -> Result<(Handshake, SharedSecret), BaluardError> {
            use sha2::{Digest, Sha256};
            // Random-looking fresh handshake in the mock's opaque format.
            let mut peer = vec![0x04u8];
            peer.resize(65, 0);
            rand::Rng::fill(&mut rand::thread_rng(), &mut peer[1..]);
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(&peer);
            Ok((Handshake(peer), Zeroizing::new(h.finalize().into())))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &Handshake,
            _consent: HwConsent,
        ) -> Result<SharedSecret, BaluardError> {
            // binding and handshake are both opaque here; derive
            // deterministically.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _binding: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    /// A second backend under a different id, exercising the registry's
    /// per-backend resolution.
    struct MockStoreB;

    impl HardwareKeyStore for MockStoreB {
        fn backend_id(&self) -> &'static str {
            "mock-b"
        }
        fn probe(&self) -> HwCapability {
            HwCapability::Available {
                backend: "mock-b".into(),
            }
        }
        fn create_binding(
            &self,
            vault_id: Uuid,
            _consent: HwConsent,
        ) -> Result<BindingInfo, BaluardError> {
            Ok(BindingInfo {
                binding: binding_tag(vault_id),
                attestation: None,
            })
        }
        fn derive_ephemeral(
            &self,
            binding: &str,
            _consent: HwConsent,
        ) -> Result<(Handshake, SharedSecret), BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"b");
            h.update(binding.as_bytes());
            Ok((Handshake(vec![0x04, 0x01]), Zeroizing::new(h.finalize().into())))
        }
        fn derive(
            &self,
            binding: &str,
            handshake: &Handshake,
            _consent: HwConsent,
        ) -> Result<SharedSecret, BaluardError> {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"b");
            h.update(binding.as_bytes());
            h.update(&handshake.0);
            Ok(Zeroizing::new(h.finalize().into()))
        }
        fn delete_binding(&self, _binding: &str) -> Result<(), BaluardError> {
            Ok(())
        }
    }

    struct DisableEnvGuard(Option<String>);

    impl DisableEnvGuard {
        fn new() -> Self {
            let old = std::env::var(DISABLE_ENV).ok();
            // SAFETY: every registry test holds TEST_STORE_LOCK, which also
            // serializes kill-switch mutation across hardware test modules.
            unsafe { std::env::remove_var(DISABLE_ENV) };
            Self(old)
        }
    }

    impl Drop for DisableEnvGuard {
        fn drop(&mut self) {
            // SAFETY: same lock invariant as DisableEnvGuard::new.
            unsafe {
                match self.0.as_deref() {
                    Some(value) => std::env::set_var(DISABLE_ENV, value),
                    None => std::env::remove_var(DISABLE_ENV),
                }
            }
        }
    }

    #[test]
    fn install_probe_and_available_flow() {
        let _g = TEST_STORE_LOCK.lock().unwrap();
        let _env = DisableEnvGuard::new();
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
        let b = s
            .create_binding(Uuid::new_v4(), HwConsent::Silent)
            .unwrap()
            .binding;
        let secret = s
            .derive(&b, &Handshake(vec![7u8; 65]), HwConsent::Silent)
            .expect("mock derive");
        assert_eq!(secret.len(), 32);
        uninstall();
        assert!(available().is_none());
    }

    #[test]
    fn registry_resolves_backends_by_id() {
        let _g = TEST_STORE_LOCK.lock().unwrap();
        let _env = DisableEnvGuard::new();
        uninstall();
        install(Arc::new(MockStore));
        install(Arc::new(MockStoreB));
        assert!(store_for("mock").is_some());
        assert!(store_for("mock-b").is_some());
        assert!(store_for("missing").is_none());
        // Deterministic default: the first installed backend in registry
        // order.
        assert_eq!(available().unwrap().backend_id(), "mock");
        assert_eq!(installed_all().len(), 2);
        uninstall();
    }

    #[test]
    fn binding_parser_reads_the_fido_prefix() {
        let id = Uuid::new_v4();
        let b = format!("fido:{id}:cGVuaw");
        assert_eq!(binding_vault_id(&b), Some(id));
        // Legacy chip bindings still parse.
        assert_eq!(binding_vault_id(&binding_tag(id)), Some(id));
        assert_eq!(binding_vault_id(&consent_binding_tag(id)), Some(id));
        assert_eq!(binding_vault_id("fido:not-a-uuid:x"), None);
        assert_eq!(binding_vault_id("garbage"), None);
    }

    #[test]
    fn binding_tag_namespaces_by_vault() {
        // Pure string shaping; no registry access, no lock needed.
        let a = binding_tag(Uuid::new_v4());
        let b = binding_tag(Uuid::new_v4());
        assert_ne!(a, b);
        assert!(a.starts_with("baluard-hw:"));
    }
}
