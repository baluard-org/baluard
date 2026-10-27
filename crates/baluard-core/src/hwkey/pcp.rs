//! Windows Platform Crypto Provider (PCP / TPM 2.0) key-agreement backend
//! (plan: `docs/plan-hardware-backed-keys.md` §3.4, Phase 2).
//!
//! Built on NCrypt over `Microsoft Platform Crypto Provider`: an ECDH
//! P-256 key whose private half is TPM-resident and non-exportable by
//! construction (PCP is the CNG face of the TPM; keys created under it
//! never leave the chip).
//!
//! Unlike the Linux ESAPI backend there is no slot scarcity: PCP keys are
//! named persistent objects, so every vault gets its own key and
//! [`HardwareKeyStore::delete_binding`] really deletes (the trait doc's
//! shared-infrastructure no-op applies to the TPM backend only).
//!
//! The fresh ephemeral input is minted in software via plain BCrypt, then
//! imported into the same NCrypt provider as the agreement peer. That is
//! cryptographically sound - secrecy lives in the chip key, the ephemeral
//! is public knowledge by design - and it keeps throwaway keypairs out of
//! the persistent key store.
//!
//! Endianness: `NCryptDeriveKey` with `BCRYPT_KDF_RAW_SECRET` ("TRUNCATE")
//! returns the X coordinate little-endian; reversed here to the big-endian
//! form the seal layer shares with the other backends.
//!
//! Verification boundary: this module is `cfg(windows)` and compiles out
//! on every other host. It was type-checked against the real windows-sys
//! signatures via a host-target harness (the full windows-msvc cargo
//! target cannot link ring's build script without an MSVC toolchain) but
//! has never executed; real-chip verification (`BALUARD_HW_KEY_TEST=1`)
//! is on-device work.
//!
//! Silence: PCP key agreements perform no UI prompt - the seal runs on
//! every unlock and password change. Consent-gated variants are plan
//! Phase 5.

use std::sync::Arc;

use uuid::Uuid;
use windows_sys::Win32::Security::Cryptography as nc;
use windows_sys::core::PCWSTR;
use zeroize::Zeroizing;

use crate::error::{BaluardError, VaultError};
use crate::hwkey::{Handshake, HardwareKeyStore, HwCapability, SharedSecret};

const PROVIDER_NAME: &str = "Microsoft Platform Crypto Provider";
const PCP_ECDH_P256_ALG: &str = "ECDH_P256";
// BCrypt names the curve, not "ECDH_PUBLIC_P256" (never a valid alg id).
const BCRYPT_ECDH_ALG: &str = "ECDH_P256";
const ECC_PUBLIC_BLOB: &str = "ECCPUBLICBLOB";
const KDF_RAW_SECRET: &str = "TRUNCATE";
const KEY_NAME_PREFIX: &str = "baluard-hw-";
const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345;
const COORD_LEN: usize = 32;
const BLOB_LEN: usize = 8 + 2 * COORD_LEN;
const POINT_LEN: usize = 1 + 2 * COORD_LEN;
const NTE_BAD_KEYSET: i32 = 0x8009_0016u32 as i32;
const NTE_EXISTS: i32 = 0x8009_000Fu32 as i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// NCrypt returns HRESULT (SECURITY_STATUS): 0 is success, everything
/// else is a chip-side failure and maps to the typed unavailable error so
/// chip problems never read as password problems.
fn check(status: i32) -> Result<(), BaluardError> {
    if status == 0 {
        Ok(())
    } else {
        Err(crate::hwkey::hw_unavailable_error())
    }
}

/// Malformed stored data (binding shape, peer point) is a vault-side
/// error, not a chip failure.
fn malformed(detail: &str) -> BaluardError {
    BaluardError::from(VaultError::Metadata(format!("hwkey pcp: {detail}")))
}

/// X9.62 uncompressed point (65 bytes, `0x04 || X || Y`) to a CNG
/// `ECCPUBLICBLOB` (magic, cbKey, X, Y).
fn point_to_blob(peer: &Handshake) -> Result<Vec<u8>, BaluardError> {
    if peer.0[0] != 0x04 {
        return Err(malformed("peer point is not an uncompressed P-256 point"));
    }
    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&(COORD_LEN as u32).to_le_bytes());
    blob.extend_from_slice(&peer.0[1..1 + COORD_LEN]);
    blob.extend_from_slice(&peer.0[1 + COORD_LEN..]);
    Ok(blob)
}

fn blob_to_point(blob: &[u8]) -> Result<Handshake, BaluardError> {
    if blob.len() != BLOB_LEN {
        return Err(malformed("public blob is not a P-256 ECCPUBLICBLOB"));
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let cb = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if magic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || cb as usize != COORD_LEN {
        return Err(malformed("public blob is not ECDH P-256"));
    }
    let mut point = [0u8; POINT_LEN];
    point[0] = 0x04;
    point[1..1 + COORD_LEN].copy_from_slice(&blob[8..8 + COORD_LEN]);
    point[1 + COORD_LEN..].copy_from_slice(&blob[8 + COORD_LEN..]);
    Ok(Handshake(point.to_vec()))
}

fn key_name(binding: &str) -> Result<String, BaluardError> {
    let id = binding
        .strip_prefix("baluard-hw:")
        .ok_or_else(|| malformed("binding is not a baluard-hw tag"))?;
    if id.is_empty() || id.len() > 200 {
        return Err(malformed("binding carries no usable vault id"));
    }
    Ok(format!("{KEY_NAME_PREFIX}{id}"))
}

/// RAII wrapper freeing an NCrypt object (provider, key, or secret) on
/// drop; NCrypt handles are `usize`.
struct NcryptHandle(usize);

impl NcryptHandle {
    /// Mark the handle as consumed (NCryptDeleteKey frees it itself).
    fn invalidate(&mut self) {
        self.0 = 0;
    }

    fn release(&mut self) {
        if self.0 != 0 {
            unsafe {
                nc::NCryptFreeObject(self.0);
            }
            self.0 = 0;
        }
    }
}

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        self.release();
    }
}

/// RAII wrapper for a BCrypt ephemeral keypair; BCrypt handles are
/// `*mut c_void`.
struct BcryptKey(*mut core::ffi::c_void);

impl Drop for BcryptKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                nc::BCryptDestroyKey(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

struct BcryptAlg(*mut core::ffi::c_void);

impl Drop for BcryptAlg {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                nc::BCryptCloseAlgorithmProvider(self.0, 0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Generate a software P-256 ephemeral keypair and return its public half
/// as X9.62. The private half dies with the handles.
fn mint_ephemeral_point() -> Result<Handshake, BaluardError> {
    let alg_name = wide(BCRYPT_ECDH_ALG);
    let mut alg: *mut core::ffi::c_void = std::ptr::null_mut();
    // BCrypt returns NTSTATUS, also 0 on success.
    if unsafe { nc::BCryptOpenAlgorithmProvider(&mut alg, alg_name.as_ptr(), std::ptr::null(), 0) }
        != 0
    {
        return Err(crate::hwkey::hw_unavailable_error());
    }
    let alg = BcryptAlg(alg);

    let mut key: *mut core::ffi::c_void = std::ptr::null_mut();
    if unsafe { nc::BCryptGenerateKeyPair(alg.0, &mut key, 256, 0) } != 0 {
        return Err(crate::hwkey::hw_unavailable_error());
    }
    let key = BcryptKey(key);
    if unsafe { nc::BCryptFinalizeKeyPair(key.0, 0) } != 0 {
        return Err(crate::hwkey::hw_unavailable_error());
    }

    let blob_type = wide(ECC_PUBLIC_BLOB);
    let mut len: u32 = 0;
    if unsafe {
        nc::BCryptExportKey(
            key.0,
            std::ptr::null_mut(),
            blob_type.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut len,
            0,
        )
    } != 0
    {
        return Err(crate::hwkey::hw_unavailable_error());
    }
    let mut blob = vec![0u8; len as usize];
    if unsafe {
        nc::BCryptExportKey(
            key.0,
            std::ptr::null_mut(),
            blob_type.as_ptr(),
            blob.as_mut_ptr(),
            len,
            &mut len,
            0,
        )
    } != 0
    {
        return Err(crate::hwkey::hw_unavailable_error());
    }
    blob.truncate(len as usize);
    blob_to_point(&blob)
}

/// The PCP backend. Stateless - handles live only inside trait calls -
/// so one instance serves the daemon's lifetime.
#[derive(Default)]
pub struct PcpStore;

impl PcpStore {
    pub fn new() -> Arc<Self> {
        Arc::new(PcpStore)
    }

    fn open_provider() -> Result<NcryptHandle, BaluardError> {
        let name = wide(PROVIDER_NAME);
        let mut prov: usize = 0;
        check(unsafe { nc::NCryptOpenStorageProvider(&mut prov, name.as_ptr(), 0) })?;
        Ok(NcryptHandle(prov))
    }

    /// Open the vault's persisted key, or `None` when it does not exist.
    fn open_key(prov: usize, binding: &str) -> Result<Option<NcryptHandle>, BaluardError> {
        let name = wide(&key_name(binding)?);
        let mut key: usize = 0;
        let status = unsafe { nc::NCryptOpenKey(prov, &mut key, name.as_ptr(), 0, 0) };
        if status == NTE_BAD_KEYSET {
            return Ok(None);
        }
        check(status)?;
        Ok(Some(NcryptHandle(key)))
    }

    /// Run the agreement against an imported peer point under `prov` and
    /// derive the raw X coordinate, reversed from CNG's little-endian.
    fn agree(
        prov: usize,
        chip_key: usize,
        peer: &Handshake,
    ) -> Result<SharedSecret, BaluardError> {
        let blob = point_to_blob(peer)?;
        let blob_type = wide(ECC_PUBLIC_BLOB);
        let mut peer_key: usize = 0;
        check(unsafe {
            nc::NCryptImportKey(
                prov,
                0,
                blob_type.as_ptr(),
                std::ptr::null(),
                &mut peer_key,
                blob.as_ptr(),
                blob.len() as u32,
                0,
            )
        })?;
        let mut peer_key = NcryptHandle(peer_key);

        let mut secret: usize = 0;
        check(unsafe { nc::NCryptSecretAgreement(chip_key, peer_key.0, &mut secret, 0) })?;
        let mut secret = NcryptHandle(secret);

        let kdf = wide(KDF_RAW_SECRET);
        let mut len: u32 = 0;
        check(unsafe {
            nc::NCryptDeriveKey(
                secret.0,
                kdf.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut len,
                0,
            )
        })?;
        if len as usize != COORD_LEN {
            return Err(malformed(
                "raw secret agreement returned an unexpected length",
            ));
        }
        let mut raw = vec![0u8; len as usize];
        check(unsafe {
            nc::NCryptDeriveKey(
                secret.0,
                kdf.as_ptr(),
                std::ptr::null(),
                raw.as_mut_ptr(),
                len,
                &mut len,
                0,
            )
        })?;
        // CNG returns the X coordinate little-endian (the BCRYPT_KDF_RAW_SECRET
        // quirk); the seal layer's secret is the big-endian X shared by every
        // backend.
        raw.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        secret.release();
        peer_key.release();
        Ok(Zeroizing::new(out))
    }
}

impl HardwareKeyStore for PcpStore {
    fn backend_id(&self) -> &'static str {
        "tpm-pcp"
    }

    fn probe(&self) -> HwCapability {
        // A real throwaway keygen exercises the full create path (provider
        // open, TPM-backed key creation, finalize, delete) instead of only
        // checking that the provider registry entry exists.
        let Ok(prov) = Self::open_provider() else {
            return HwCapability::Unavailable {
                reason: "no-tpm".into(),
            };
        };
        let name = wide(&format!(
            "{KEY_NAME_PREFIX}probe-{:08x}",
            rand::Rng::gen::<u32>(&mut rand::thread_rng())
        ));
        let mut key: usize = 0;
        if unsafe {
            nc::NCryptCreatePersistedKey(
                prov.0,
                &mut key,
                wide(PCP_ECDH_P256_ALG).as_ptr(),
                name.as_ptr(),
                0,
                0,
            )
        } != 0
        {
            return HwCapability::Unavailable {
                reason: "tpm-without-pcp".into(),
            };
        }
        let mut key = NcryptHandle(key);
        if unsafe { nc::NCryptFinalizeKey(key.0, 0) } != 0 {
            return HwCapability::Unavailable {
                reason: "driver-error".into(),
            };
        }
        unsafe {
            nc::NCryptDeleteKey(key.0, 0);
        }
        // NCryptDeleteKey already invalidated the handle; freeing it
        // again would be a use-after-delete.
        key.invalidate();
        HwCapability::Available {
            backend: "tpm-pcp".into(),
        }
    }

    fn create_binding(
        &self,
        vault_id: Uuid,
        consent: crate::hwkey::HwConsent,
    ) -> Result<String, BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let binding = crate::hwkey::binding_tag(vault_id);
        let prov = Self::open_provider()?;
        if Self::open_key(prov.0, &binding)?.is_some() {
            return Ok(binding);
        }
        let name = wide(&key_name(&binding)?);
        let mut key: usize = 0;
        let status = unsafe {
            nc::NCryptCreatePersistedKey(
                prov.0,
                &mut key,
                wide(PCP_ECDH_P256_ALG).as_ptr(),
                name.as_ptr(),
                0,
                0,
            )
        };
        if status == NTE_EXISTS {
            // Another process created it first - same binding.
            return Ok(binding);
        }
        check(status)?;
        let mut key = NcryptHandle(key);
        check(unsafe { nc::NCryptFinalizeKey(key.0, 0) })?;
        key.release();
        Ok(binding)
    }

    fn derive_ephemeral(
        &self,
        binding: &str,
        consent: crate::hwkey::HwConsent,
    ) -> Result<(Handshake, SharedSecret), BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let prov = Self::open_provider()?;
        let Some(chip) = Self::open_key(prov.0, binding)? else {
            return Err(crate::hwkey::hw_unavailable_error());
        };
        let peer = mint_ephemeral_point()?;
        let secret = Self::agree(prov.0, chip.0, &peer)?;
        Ok((peer, secret))
    }

    fn derive(
        &self,
        binding: &str,
        peer: &Handshake,
        consent: crate::hwkey::HwConsent,
    ) -> Result<SharedSecret, BaluardError> {
        if consent.is_per_use() {
            return Err(VaultError::HardwareConsentUnavailable.into());
        }
        let prov = Self::open_provider()?;
        let Some(chip) = Self::open_key(prov.0, binding)? else {
            return Err(crate::hwkey::hw_unavailable_error());
        };
        Self::agree(prov.0, chip.0, peer)
    }

    fn delete_binding(&self, binding: &str) -> Result<(), BaluardError> {
        let prov = Self::open_provider()?;
        let Some(key) = Self::open_key(prov.0, binding)? else {
            // Already gone - delete is idempotent per the trait contract.
            return Ok(());
        };
        let mut key = key;
        check(unsafe { nc::NCryptDeleteKey(key.0, 0) })?;
        key.invalidate();
        Ok(())
    }
}

#[cfg(all(test, target_os = "windows", feature = "hw-seal"))]
mod real_chip_tests {
    use super::*;

    fn chip_enabled() -> bool {
        std::env::var("BALUARD_HW_KEY_TEST").ok().as_deref() == Some("1")
    }

    // These persist and delete keys in the real PCP store, so they never
    // run in the default suite; Esteban-side on-device verification only.
    #[test]
    fn pcp_roundtrip_and_per_vault_keys() {
        if !chip_enabled() {
            return;
        }
        let store = PcpStore::new();
        assert!(matches!(
            store.probe(),
            HwCapability::Available { backend } if backend == "tpm-pcp"
        ));

        let a = store.create_binding(Uuid::new_v4()).unwrap();
        let b = store.create_binding(Uuid::new_v4()).unwrap();
        assert_ne!(a, b, "PCP keys are per-vault named objects");

        let (peer, secret) = store.ecdh_ephemeral(&a).unwrap();
        assert_eq!(peer.0[0], 0x04);
        let again = store.ecdh(&a, &peer).unwrap();
        assert_eq!(secret.as_ref(), again.as_ref(), "PCP must reproduce z");
        let via_b = store.ecdh(&b, &peer).unwrap();
        assert_ne!(secret.as_ref(), via_b.as_ref(), "per-vault keys differ");

        store.delete_binding(&a).unwrap();
        assert!(store.ecdh(&a, &peer).is_err(), "deleted key is gone");
        store.delete_binding(&a).unwrap();
        store.delete_binding(&b).unwrap();
    }
}
