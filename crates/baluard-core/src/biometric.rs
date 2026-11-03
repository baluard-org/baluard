//! OS keychain biometric unlock.
//!
//! Stores the master password in the OS keychain with biometric access control,
//! **namespaced per vault** by `vault_id`. Each vault gets its own keychain
//! entry, so enabling Quick Unlock on one vault never exposes it on another.
//!
//! On macOS: Uses Security framework with SecAccessControl (BIOMETRY_ANY).
//!   Reading triggers Touch ID. Writing does not (enrollment flow).
//! On other platforms: Uses the `keyring` crate with native backends
//!   (libsecret on Linux, Credential Manager on Windows).
//! The daemon retrieves the password and performs vault unlock internally.
//! The master password NEVER leaves the daemon process over IPC.
//!
//! Security asymmetry (audit C3) — read gates differ per platform:
//! - macOS: every read is gated by SecAccessControl(BIOMETRY_ANY), so a
//!   user-presence event (Touch ID or passcode) is required.
//! - Linux/Windows: the keyring backends have NO per-read gate. Any
//!   same-UID process can silently read the stored master password with
//!   no user-visible prompt. `read_gated()` reports which world we are in;
//!   callers must surface the asymmetry at enable time when it returns
//!   false. The real fix (TPM-backed key / Windows Hello KeyCredential)
//!   is deferred.
//!
//! L5 fix documentation:
//! - macOS: `BIOMETRY_ANY` access control flag allows passcode fallback.
//!   If Touch ID hardware is missing or not enrolled, the keychain will
//!   prompt for the device passcode instead. This is a security reduction
//!   vs biometrics-only. Users on Macs without Touch ID should NOT enable
//!   biometric unlock — the UI should gate this on hardware availability.
//! - A proper fix requires `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
//!   to detect biometric hardware presence. This is deferred (see audit
//!   finding L5 residual).
//! - The `is_available()` function returns `true` on macOS without verifying
//!   hardware. This is a known limitation; the UI should also check
//!   platform-specific signals before offering the toggle.
//!
//! Per-vault scoping (QU fix):
//! - The keychain account name is `quick-unlock:<vault_id>`, where `vault_id`
//!   is the deterministic UUID derived from the vault's KDF salt (see
//!   `VaultHandle::resolve_vault_id`). It is stable, unique per vault, and
//!   computable without unlocking. Enabling Quick Unlock on vault A therefore
//!   has no effect on the status or unlock path of vault B.
//!
//! Scope note: this is the macOS/Touch-ID path only. On Linux and on Windows
//! machines without Windows Hello, Quick Unlock uses the session-PIN escrow
//! (`baluard-daemon::pin`) instead — see AGENTS.md "Quick Unlock". The two
//! are independent; both buttons can appear for a vault that has both.

const SERVICE_NAME: &str = "com.baluard.desktop";
/// Legacy pre-QU account name: a single global entry shared across all
/// vaults. Kept only so `disable_legacy_global()` can wipe orphaned
/// secrets written by older daemon versions.
const LEGACY_ACCOUNT_NAME: &str = "quick-unlock";

/// Build the per-vault keychain account name.
fn account_for(vault_id: &str) -> String {
    format!("quick-unlock:{vault_id}")
}

// ── macOS: Security framework with biometric access control ──────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::SERVICE_NAME;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::access_control::SecAccessControl;
    use security_framework::passwords::AccessControlOptions;
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
    use zeroize::Zeroizing;

    /// Biometric constraint: Touch ID (any enrolled finger) OR device passcode fallback.
    const AC_FLAGS: AccessControlOptions = AccessControlOptions::BIOMETRY_ANY;

    /// Check if keychain access is available (always true on macOS).
    /// NOTE: Does not check for Touch ID hardware. Macs without biometrics
    /// will still report available; the keychain will use device passcode fallback.
    pub fn availability() -> super::Availability {
        super::Availability::Available
    }

    /// Store master password with biometric access control.
    /// macOS enforces Touch ID / Face ID on READ, not on write.
    ///
    /// Uses raw FFI with kSecUseDataProtectionKeychain=false to target the
    /// file-based keychain. The data protection keychain requires entitlements
    /// (restricted by provisioning profile), which sidecar binaries lack.
    /// The file-based keychain still supports SecAccessControl with biometric
    /// constraints (Touch ID / passcode prompt on read).
    pub fn enable(account: &str, master_password: &str) -> Result<(), String> {
        // Delete existing entry first (SecAccessControl is immutable on update;
        // we must delete + recreate to change access control flags).
        let _ = delete(account);

        let access_control = SecAccessControl::create_with_flags(AC_FLAGS.bits())
            .map_err(|e| format!("access control create: {e}"))?;

        let query: Vec<(CFString, core_foundation::base::CFType)> = unsafe {
            vec![
                unsafe_pair(
                    security_framework_sys::item::kSecClass,
                    CFString::wrap_under_get_rule(
                        security_framework_sys::item::kSecClassGenericPassword,
                    ),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrService,
                    CFString::from(SERVICE_NAME),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrAccount,
                    CFString::from(account),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrAccessControl,
                    access_control,
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecValueData,
                    CFData::from_buffer(master_password.as_bytes()),
                ),
                // Force file-based keychain to avoid entitlement requirement.
                // The data protection keychain needs restricted entitlements
                // authorized by a provisioning profile, unavailable to sidecars.
                unsafe_pair(
                    security_framework_sys::item::kSecUseDataProtectionKeychain,
                    CFBoolean::from(false),
                ),
            ]
        };

        let params = CFDictionary::from_CFType_pairs(&query);
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemAdd(
                params.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )
        };

        if status == errSecDuplicateItem {
            // Shouldn't happen (we deleted above), but handle gracefully.
            // Update requires a separate query without kSecValueData.
            return Err("keychain item already exists after delete".into());
        }

        if status != 0 {
            return Err(format!("keychain store: {}", status));
        }

        Ok(())
    }

    /// Delete stored master password. Ok if already deleted.
    pub fn disable(account: &str) -> Result<(), String> {
        delete(account)
    }

    /// Check if a stored secret exists. Does NOT trigger biometric prompt.
    pub fn is_enabled(account: &str) -> bool {
        // Build query dictionary manually using raw FFI.
        //
        // Strategy: kSecReturnAttributes=true + kSecUseAuthenticationUI=kSecUseAuthenticationUISkip
        // This checks existence without triggering Touch ID:
        //   errSecSuccess(0) = item exists
        //   errSecInteractionNotAllowed(-25308) = item exists, biometric-protected
        //   errSecItemNotFound = no item
        let query: Vec<(CFString, core_foundation::base::CFType)> = unsafe {
            vec![
                unsafe_pair(
                    security_framework_sys::item::kSecClass,
                    CFString::wrap_under_get_rule(
                        security_framework_sys::item::kSecClassGenericPassword,
                    ),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrService,
                    CFString::from(SERVICE_NAME),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrAccount,
                    CFString::from(account),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecReturnAttributes,
                    CFBoolean::from(true),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecUseAuthenticationUI,
                    CFString::wrap_under_get_rule(
                        security_framework_sys::item::kSecUseAuthenticationUISkip,
                    ),
                ),
                // Match the same keychain used by enable/unlock.
                unsafe_pair(
                    security_framework_sys::item::kSecUseDataProtectionKeychain,
                    CFBoolean::from(false),
                ),
            ]
        };

        let params = CFDictionary::from_CFType_pairs(&query);
        let mut ret: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemCopyMatching(
                params.as_concrete_TypeRef(),
                &mut ret,
            )
        };

        if !ret.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(ret) };
        }

        const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
        status == 0 || status == ERR_SEC_INTERACTION_NOT_ALLOWED
    }

    /// Retrieve stored master password. Triggers Touch ID / biometric prompt.
    /// The returned bytes are zeroized after conversion.
    pub fn unlock(account: &str) -> Result<String, String> {
        let query: Vec<(CFString, core_foundation::base::CFType)> = unsafe {
            vec![
                unsafe_pair(
                    security_framework_sys::item::kSecClass,
                    CFString::wrap_under_get_rule(
                        security_framework_sys::item::kSecClassGenericPassword,
                    ),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrService,
                    CFString::from(SERVICE_NAME),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrAccount,
                    CFString::from(account),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecReturnData,
                    CFBoolean::from(true),
                ),
                // Match the same keychain used by enable.
                unsafe_pair(
                    security_framework_sys::item::kSecUseDataProtectionKeychain,
                    CFBoolean::from(false),
                ),
            ]
        };

        let params = CFDictionary::from_CFType_pairs(&query);
        let mut ret: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemCopyMatching(
                params.as_concrete_TypeRef(),
                &mut ret,
            )
        };

        if status != 0 {
            return Err(format!("biometric unlock failed: status={status}"));
        }

        if ret.is_null() {
            return Err("biometric unlock failed: null result".into());
        }

        // Wrap in Zeroizing for secure cleanup of the CFData.
        let cf_data = unsafe {
            let data_ref = ret as core_foundation_sys::data::CFDataRef;
            let len = core_foundation_sys::data::CFDataGetLength(data_ref) as usize;
            let ptr = core_foundation_sys::data::CFDataGetBytePtr(data_ref);
            let bytes = std::slice::from_raw_parts(ptr, len).to_vec();
            core_foundation_sys::base::CFRelease(ret);
            Zeroizing::new(bytes)
        };

        String::from_utf8(cf_data.to_vec()).map_err(|e| format!("keychain data not utf8: {e}"))
    }

    fn delete(account: &str) -> Result<(), String> {
        let query: Vec<(CFString, core_foundation::base::CFType)> = unsafe {
            vec![
                unsafe_pair(
                    security_framework_sys::item::kSecClass,
                    CFString::wrap_under_get_rule(
                        security_framework_sys::item::kSecClassGenericPassword,
                    ),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrService,
                    CFString::from(SERVICE_NAME),
                ),
                unsafe_pair(
                    security_framework_sys::item::kSecAttrAccount,
                    CFString::from(account),
                ),
                // Match the same keychain used by enable.
                unsafe_pair(
                    security_framework_sys::item::kSecUseDataProtectionKeychain,
                    CFBoolean::from(false),
                ),
            ]
        };

        let params = CFDictionary::from_CFType_pairs(&query);
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemDelete(params.as_concrete_TypeRef())
        };

        if status == errSecItemNotFound {
            return Ok(());
        }

        if status != 0 {
            return Err(format!("keychain delete: status={status}"));
        }

        Ok(())
    }

    /// Helper: wrap a static CFStringRef key and a CFType value into a dictionary pair.
    #[inline]
    fn unsafe_pair<V: core_foundation::base::TCFType>(
        key: core_foundation_sys::string::CFStringRef,
        value: V,
    ) -> (CFString, core_foundation::base::CFType) {
        (
            unsafe { CFString::wrap_under_get_rule(key) },
            value.into_CFType(),
        )
    }
}

// ── Non-macOS: keyring crate with native backends ────────────────────────

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::SERVICE_NAME;
    use keyring::Entry;

    /// Probe the OS keyring with a real read so a missing Secret Service
    /// provider on Linux is reported distinctly (the UI then shows the
    /// install command instead of a button that fails on click).
    pub fn availability() -> super::Availability {
        let entry = match Entry::new(SERVICE_NAME, "quick-unlock:probe") {
            Ok(e) => e,
            Err(_) => return super::Availability::Unavailable,
        };
        match entry.get_password() {
            // Service answered (stale probe entry or cleanly missing).
            Ok(_) | Err(keyring::Error::NoEntry) => super::Availability::Available,
            // No Secret Service on the bus: say so, with the reason.
            Err(e) if crate::sysdeps::secret_service_absent(&e.to_string()) => {
                super::Availability::SecretServiceMissing
            }
            // Anything else (locked collection, declined prompt): let the
            // OS surface it at use time.
            Err(_) => super::Availability::Available,
        }
    }

    /// Store master password in OS keyring under the per-vault account.
    pub fn enable(account: &str, master_password: &str) -> Result<(), String> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| crate::sysdeps::keyring_error_hint(&format!("keyring entry: {e}")))?;
        entry
            .set_password(master_password)
            .map_err(|e| crate::sysdeps::keyring_error_hint(&format!("keyring store: {e}")))?;
        Ok(())
    }

    /// Delete stored master password. Ok if already deleted.
    pub fn disable(account: &str) -> Result<(), String> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| crate::sysdeps::keyring_error_hint(&format!("keyring entry: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(crate::sysdeps::keyring_error_hint(&format!(
                "keyring delete: {e}"
            ))),
        }
    }

    /// Check if a stored secret exists for this vault.
    pub fn is_enabled(account: &str) -> bool {
        let Ok(entry) = Entry::new(SERVICE_NAME, account) else {
            return false;
        };
        entry.get_password().is_ok()
    }

    /// Retrieve stored master password. May trigger OS credential prompt.
    pub fn unlock(account: &str) -> Result<String, String> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| crate::sysdeps::keyring_error_hint(&format!("keyring entry: {e}")))?;
        entry.get_password().map_err(|e| {
            crate::sysdeps::keyring_error_hint(&format!("biometric unlock failed: {e}"))
        })
    }
}

// ── Public API (platform-delegated, scoped per vault) ────────────────────

/// Why Quick Unlock is (un)available. `SecretServiceMissing` carries the
/// Linux "no org.freedesktop.secrets on the session bus" case so callers
/// can surface the install command (the app prints it; the user runs it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    SecretServiceMissing,
    Unavailable,
}

/// Availability with reason (single keyring probe per call).
pub fn availability() -> Availability {
    platform::availability()
}

/// Install command for the missing Linux Secret Service provider; `None`
/// when availability has another cause or the distro is unknown.
pub fn unavailability_hint() -> Option<&'static str> {
    match availability() {
        Availability::SecretServiceMissing => crate::sysdeps::secret_service_install_hint(),
        _ => None,
    }
}

/// Check if biometric unlock is available on this platform.
pub fn is_available() -> bool {
    availability() == Availability::Available
}

/// Whether reading the stored master password requires a user-presence
/// event (biometric or passcode prompt). True only on macOS: the
/// SecAccessControl(BIOMETRY_ANY) gate fires on every read. The plain
/// keyring backends on Linux/Windows have no per-read gate, so a same-UID
/// process reads the secret silently (audit C3). UIs must warn at enable
/// time when this returns false.
pub fn read_gated() -> bool {
    cfg!(target_os = "macos")
}

/// Enable biometric unlock by storing the master password in OS keychain,
/// scoped to `vault_id`. The `vault_id` MUST be the vault's deterministic
/// UUID (`VaultHandle::resolve_vault_id`) so the entry is stable across
/// restarts and unique per vault.
pub fn enable(vault_id: &str, master_password: &str) -> Result<(), String> {
    platform::enable(&account_for(vault_id), master_password)
}

/// Disable biometric unlock for `vault_id`. Must be called on master password
/// change to invalidate the stale secret for that vault only.
pub fn disable(vault_id: &str) -> Result<(), String> {
    platform::disable(&account_for(vault_id))
}

/// Check if biometric unlock is enabled for `vault_id` (secret exists).
/// Does NOT trigger biometric prompt on macOS.
pub fn is_enabled(vault_id: &str) -> bool {
    platform::is_enabled(&account_for(vault_id))
}

/// Retrieve the stored master password for `vault_id` from OS keychain.
/// On macOS: triggers Touch ID / Face ID biometric prompt.
/// On other platforms: may trigger OS credential prompt.
/// Returns the raw master password for vault unlock (daemon-internal only).
pub fn unlock(vault_id: &str) -> Result<String, String> {
    platform::unlock(&account_for(vault_id))
}

/// Best-effort wipe of the legacy global `quick-unlock` keychain entry
/// written by pre-QU daemon versions (which stored one shared secret for
/// all vaults). Safe to call repeatedly; returns Ok when no entry remains.
/// Call once at daemon startup so old per-app secrets do not linger.
pub fn disable_legacy_global() -> Result<(), String> {
    platform::disable(LEGACY_ACCOUNT_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_does_not_panic() {
        let _ = is_available();
    }

    #[test]
    fn is_enabled_does_not_panic() {
        let _ = is_enabled("00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn account_for_namespaces_per_vault() {
        assert_eq!(
            account_for("11111111-1111-1111-1111-111111111111"),
            "quick-unlock:11111111-1111-1111-1111-111111111111"
        );
        assert_ne!(
            account_for("11111111-1111-1111-1111-111111111111"),
            account_for("22222222-2222-2222-2222-222222222222")
        );
    }
}
