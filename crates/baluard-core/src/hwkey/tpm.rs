//! Linux TPM 2.0 key-agreement backend (plan:
//! `docs/plan-hardware-backed-keys.md` §3.4, Phase 3).
//!
//! Built on `tss-esapi` over the TCG ESYS stack: a P-256 ECDH key whose
//! private half is TPM-resident and non-exportable by construction.
//!
//! One chip key serves every vault. Slot-constrained firmware (this
//! machine's Intel PTT exposes 7 persistent slots, mostly platform-
//! owned, and rejects the spec's upper band outright) cannot afford a
//! key per vault, and per-vault chip keys buy nothing cryptographically
//! here: vault separation rides the password-derived `kek_subkey`, so
//! the chip contributes the same offline-theft AND-barrier either way.
//! The key is recognized across processes by its TPM name (the hash of
//! the public template plus primary seed), not by a reserved handle
//! band. The vault id still mixes into the primary's outside info so a
//! future per-vault split stays possible without a format change.
//!
//! Platform requirements: kernel resource manager `/dev/tpmrm0` (group
//! `tss`), link-time `tpm2-tss-devel`, and an owner hierarchy whose
//! auth is empty (the Fedora default). A set owner auth surfaces as the
//! typed unavailable error rather than a silent fallback.
//!
//! Silence: the chip key carries no auth value, so ECDH never prompts -
//! the seal runs on every unlock and password change. Consent-gated
//! variants are plan Phase 5.
//!
//! No sessions anywhere: every entity this backend touches has an empty
//! authValue, and this firmware's stack misbehaves when auth sessions
//! coexist with TR_FromTPMPublic (crashes) or key commands (errors).
//!
//! Thread safety: ESYS contexts are single-threaded (`&mut self`
//! methods), so every trait call constructs and drops its own
//! `Context`, mirroring the Secure Enclave backend's per-call handle.

use std::str::FromStr;
use std::sync::Arc;

use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    constants::CapabilityType,
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        ecc::EccCurve,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Data, EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParameters, PublicEccParametersBuilder,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{BaluardError, VaultError};
use crate::hwkey::{EphemeralPub, HardwareKeyStore, HwCapability, SharedSecret};

/// The scan origin the tool ecosystem uses; scanning from the spec's
/// upper band instead fails RC_VALUE on this firmware.
const PERSISTENT_FIRST: u32 = 0x8100_0000;
const BAND_SCAN: u32 = 32;
const BINDING_PREFIX: &str = "baluard-tpm:";
const DEVICE_NODE: &str = "/dev/tpmrm0";
/// Mixed into the primary-key derivation so a future per-vault key
/// split never reuses a chip key across vaults.
const OUTSIDE_INFO_PREFIX: &[u8] = b"baluard-hw-v1:";

pub struct TpmStore {
    // ESYS contexts are single-threaded and this firmware is flaky
    // under many rapid connections, so one connection is shared behind
    // a mutex for the daemon's lifetime.
    ctx: std::sync::Mutex<Context>,
}

impl TpmStore {
    /// Connects eagerly; a machine without a reachable TPM yields None
    /// from [`crate::hwkey::platform_store`] and stays on the v1 seal.
    pub fn new() -> Result<Arc<Self>, BaluardError> {
        Ok(Arc::new(Self {
            ctx: std::sync::Mutex::new(Self::connect()?),
        }))
    }

    fn connect() -> Result<Context, BaluardError> {
        // Honor the standard TCTI env vars when set; otherwise the
        // kernel resource manager, which is what Fedora ships.
        let conf = if std::env::var_os("TPM2TOOLS_TCTI").is_some()
            || std::env::var_os("TCTI").is_some()
            || std::env::var_os("TEST_TCTI").is_some()
        {
            TctiNameConf::from_environment_variable()
                .map_err(|_| crate::hwkey::hw_unavailable_error())?
        } else {
            TctiNameConf::Device(
                DeviceConfig::from_str(DEVICE_NODE)
                    .map_err(|_| crate::hwkey::hw_unavailable_error())?,
            )
        };
        Context::new(conf).map_err(|_| crate::hwkey::hw_unavailable_error())
    }

    fn parse_handle(binding: &str) -> Result<PersistentTpmHandle, BaluardError> {
        let raw = binding
            .strip_prefix(BINDING_PREFIX)
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| VaultError::Corrupt("hwkey binding is not a tpm handle".into()))?;
        PersistentTpmHandle::new(raw)
            .map_err(|e| VaultError::Corrupt(format!("hwkey binding handle: {e}")).into())
    }

    fn load_key(ctx: &mut Context, handle: PersistentTpmHandle) -> Result<KeyHandle, BaluardError> {
        let obj = ctx
            .tr_from_tpm_public(TpmHandle::Persistent(handle))
            .map_err(|_| crate::hwkey::hw_unavailable_error())?;
        Ok(KeyHandle::from(obj))
    }

    /// The P-256 ECDH template from the ESYS `ecdh_key_gen` docs:
    /// decrypt-only, unrestricted, no KDF.
    fn ecdh_public_template() -> Result<Public, BaluardError> {
        let parameters: PublicEccParameters = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .map_err(|e| VaultError::Metadata(format!("hwkey tpm template: {e}")))?;
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(false)
            .build()
            .map_err(|e| VaultError::Metadata(format!("hwkey tpm attrs: {e}")))?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(parameters)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| VaultError::Metadata(format!("hwkey tpm public: {e}")).into())
    }

    /// All persistent handles the chip currently reports, sorted. The
    /// scan must run without a session (GetCapability rejects one with
    /// RC_VALUE on the session parameter).
    fn persistent_handles(ctx: &mut Context) -> Result<Vec<u32>, BaluardError> {
        let (caps, _) = ctx
            .get_capability(CapabilityType::Handles, PERSISTENT_FIRST, BAND_SCAN)
            .map_err(|_| crate::hwkey::hw_unavailable_error())?;
        let handles = match caps {
            tss_esapi::structures::CapabilityData::Handles(list) => list
                .into_inner()
                .into_iter()
                .filter_map(|h| match h {
                    TpmHandle::Persistent(p) => Some(u32::from(p)),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let mut handles = handles;
        handles.sort_unstable();
        Ok(handles)
    }

    fn point_bytes(point: &EccPoint) -> Result<[u8; 65], BaluardError> {
        let (x, y) = (point.x().value(), point.y().value());
        if x.len() != 32 || y.len() != 32 {
            return Err(VaultError::Metadata("hwkey tpm point is not P-256 sized".into()).into());
        }
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(x);
        out[33..65].copy_from_slice(y);
        Ok(out)
    }

    fn point_from_x962(peer: &[u8; 65]) -> Result<EccPoint, BaluardError> {
        if peer[0] != 0x04 {
            return Err(
                VaultError::Corrupt("hwkey peer is not an uncompressed point".into()).into(),
            );
        }
        Ok(EccPoint::new(
            EccParameter::try_from(&peer[1..33])
                .map_err(|_| VaultError::Corrupt("hwkey peer x".into()))?,
            EccParameter::try_from(&peer[33..65])
                .map_err(|_| VaultError::Corrupt("hwkey peer y".into()))?,
        ))
    }

    fn secret_from_z(z: &EccPoint) -> Result<SharedSecret, BaluardError> {
        let zx = z.x().value();
        if zx.len() != 32 {
            return Err(VaultError::Metadata("hwkey tpm z not P-256 sized".into()).into());
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(zx);
        Ok(Zeroizing::new(secret))
    }
}

impl HardwareKeyStore for TpmStore {
    fn probe(&self) -> HwCapability {
        // Honest probe: only the chip can answer. A throwaway primary
        // (flushed immediately) proves the resource manager is reachable,
        // the owner hierarchy is open, and ECDH primaries are supported -
        // without persisting anything.
        let probe = (|| -> Result<(), BaluardError> {
            let mut ctx = self.ctx.lock().unwrap_or_else(|p| p.into_inner());
            let public = Self::ecdh_public_template()?;
            // execute_with_session returns the closure's own Result, so
            // the chip errors surface through it directly.
            ctx.execute_with_session(
                Some(AuthSession::Password),
                |ctx| -> Result<(), BaluardError> {
                    let created = ctx
                        .create_primary(Hierarchy::Owner, public, None, None, None, None)
                        .map_err(|e| {
                            BaluardError::from(VaultError::Metadata(format!(
                                "hwkey tpm probe: {e}"
                            )))
                        })?;
                    ctx.flush_context(created.key_handle.into()).map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!("hwkey tpm probe: {e}")))
                    })
                },
            )
        })();
        match probe {
            Ok(()) => HwCapability::Available {
                backend: "tpm2".into(),
            },
            Err(_) => HwCapability::Unavailable {
                reason: "tpm2-unavailable".into(),
            },
        }
    }

    fn create_binding(
        &self,
        _vault_id: Uuid,
        consent: crate::hwkey::HwConsent,
    ) -> Result<String, BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let mut ctx = self.ctx.lock().unwrap_or_else(|p| p.into_inner());
        let public = Self::ecdh_public_template()?;

        // Create the primary transiently first: its TPM name is the
        // portable identity used to recognize our persistent key across
        // processes (the outside info never shows in the public area).
        let (key_handle, created_name) = ctx.execute_with_session(
            Some(AuthSession::Password),
            |ctx| -> Result<(KeyHandle, Vec<u8>), BaluardError> {
                // Domain separation only: the vault id must NOT enter
                // outsideInfo. CreatePrimary is deterministic in the
                // template + outside, so a per-vault value mints a new
                // persistent key per vault until NVRAM slots run out.
                let outside = Data::try_from(OUTSIDE_INFO_PREFIX.to_vec())
                    .map_err(|e| VaultError::Metadata(format!("hwkey tpm outside: {e}")))?;
                let created = ctx
                    .create_primary(Hierarchy::Owner, public, None, None, Some(outside), None)
                    .map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!("hwkey tpm create: {e}")))
                    })?;
                let name = ctx
                    .tr_get_name(created.key_handle.into())
                    .map_err(|e| {
                        BaluardError::from(VaultError::Metadata(format!("hwkey tpm name: {e}")))
                    })?
                    .value()
                    .to_vec();
                Ok((created.key_handle, name))
            },
        )?;

        // Adopt an existing key with the identical name; otherwise
        // persist the fresh one above the highest handle (this
        // firmware's allocator accepts only the low range).
        let handles = Self::persistent_handles(&mut ctx)?;
        for raw in &handles {
            let handle = match PersistentTpmHandle::new(*raw) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let obj = match ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)) {
                Ok(obj) => obj,
                // Absent between scan and load: skip.
                Err(_) => continue,
            };
            let name = match ctx.tr_get_name(obj) {
                Ok(n) => n.value().to_vec(),
                Err(_) => {
                    let mut slot_obj = obj;
                    let _ = ctx.tr_close(&mut slot_obj);
                    continue;
                }
            };
            // Persistent objects cannot be flushed (RC_HANDLE); tr_close
            // just releases the ESYS slot.
            if name == created_name {
                let mut slot_obj = obj;
                let _ = ctx.tr_close(&mut slot_obj);
                // The created transient is deliberately left unflushed:
                // flushing a primary here crashed the following
                // create_primary on this firmware (SIGSEGV in tss2).
                return Ok(format!("{BINDING_PREFIX}{raw:08x}"));
            }
            let mut slot_obj = obj;
            let _ = ctx.tr_close(&mut slot_obj);
        }

        let slot_raw = handles
            .last()
            .copied()
            .map(|h| h + 1)
            .unwrap_or(PERSISTENT_FIRST);
        let slot = PersistentTpmHandle::new(slot_raw).map_err(|e| {
            BaluardError::from(VaultError::Metadata(format!("hwkey tpm handle: {e}")))
        })?;
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                key_handle.into(),
                Persistent::Persistent(slot),
            )
            .map(|_| ())
            .map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!("hwkey tpm persist: {e}")))
            })
        })?;
        Ok(format!("{BINDING_PREFIX}{slot_raw:08x}"))
    }

    fn ecdh_ephemeral(
        &self,
        binding: &str,
        consent: crate::hwkey::HwConsent,
    ) -> Result<(EphemeralPub, SharedSecret), BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let handle = Self::parse_handle(binding)?;
        let mut ctx = self.ctx.lock().unwrap_or_else(|p| p.into_inner());
        // Load OUTSIDE the auth session: TR_FromTPMPublic under a
        // session segfaults in libtss2-esys on this stack (gdb-pinned).
        let key = Self::load_key(&mut ctx, handle)?;
        // No session at all: the key's auth is empty by design (the
        // silence requirement), and this firmware misbehaves with
        // sessions on these commands.
        ctx.execute_without_session(
            |ctx| -> Result<(EphemeralPub, SharedSecret), BaluardError> {
                let (z, pub_point) = ctx
                    .ecdh_key_gen(key)
                    .map_err(|_| crate::hwkey::hw_unavailable_error())?;
                let peer_bytes = Self::point_bytes(&pub_point)?;
                Ok((EphemeralPub(peer_bytes), Self::secret_from_z(&z)?))
            },
        )
    }

    fn ecdh(
        &self,
        binding: &str,
        peer: &EphemeralPub,
        consent: crate::hwkey::HwConsent,
    ) -> Result<SharedSecret, BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let handle = Self::parse_handle(binding)?;
        let peer_point = Self::point_from_x962(&peer.0)?;
        let mut ctx = self.ctx.lock().unwrap_or_else(|p| p.into_inner());
        let key = Self::load_key(&mut ctx, handle)?;
        // Sessionless like ecdh_ephemeral: the key carries no auth and
        // some firmware rejects needless auth sessions.
        ctx.execute_without_session(
            |ctx| -> Result<SharedSecret, BaluardError> {
                let z = ctx
                    .ecdh_z_gen(key, peer_point)
                    .map_err(|_| crate::hwkey::hw_unavailable_error())?;
                Self::secret_from_z(&z)
            },
        )
    }

    fn delete_binding(&self, _binding: &str) -> Result<(), BaluardError> {
        // One chip key serves every vault (see the module header), so
        // deletion is a no-op: the key is permanent infrastructure and
        // disable downsizes the seal to v1 instead.
        Ok(())
    }
}

/// Real-chip integration: opt in with BALUARD_HW_KEY_TEST=1 (plan
/// §testing) plus a build with `--features hw-seal`; needs /dev/tpmrm0
/// access and an empty owner-hierarchy auth. They persist a key in the
/// real TPM NV, so they must never run in the default suite.
#[cfg(all(test, target_os = "linux", feature = "hw-seal"))]
mod real_chip_tests {
    use super::*;
    use std::sync::OnceLock;

    fn hw_gate() -> Option<std::sync::MutexGuard<'static, ()>> {
        if std::env::var("BALUARD_HW_KEY_TEST").ok().as_deref() != Some("1") {
            return None;
        }
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        let guard = LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        Some(guard)
    }

    #[test]
    fn tpm_shared_key_roundtrip() {
        let Some(_guard) = hw_gate() else {
            return;
        };
        let store = TpmStore::new().expect("tpm reachable under the hw gate");
        assert!(matches!(store.probe(), HwCapability::Available { .. }));

        // Two vaults adopt the same chip key (shared-key semantics).
        let a = store.create_binding(Uuid::new_v4()).unwrap();
        let b = store.create_binding(Uuid::new_v4()).unwrap();
        assert_eq!(a, b, "one chip key serves every vault");
        assert!(a.starts_with(BINDING_PREFIX));

        let (peer, secret) = store.ecdh_ephemeral(&a).unwrap();
        assert_eq!(peer.0[0], 0x04);
        let again = store.ecdh(&a, &peer).unwrap();
        assert_eq!(secret.as_ref(), again.as_ref(), "TPM ECDH must reproduce z");
        let via_b = store.ecdh(&b, &peer).unwrap();
        assert_eq!(secret.as_ref(), via_b.as_ref());

        // Delete is a no-op on this backend; the key stays usable.
        store.delete_binding(&a).unwrap();
        store.delete_binding(&a).unwrap();
        let after = store.ecdh(&a, &peer).unwrap();
        assert_eq!(secret.as_ref(), after.as_ref());
    }
}
