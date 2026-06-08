//! OS keychain biometric unlock.
//!
//! Stores the master password in the OS keychain with biometric access control.
//! On macOS: Uses Security framework with SecAccessControl (BIOMETRY_ANY).
//!   Reading triggers Touch ID. Writing does not (enrollment flow).
//! On other platforms: Uses the `keyring` crate with native backends.
//! The daemon retrieves the password and performs vault unlock internally.
//! The master password NEVER leaves the daemon process over IPC.

const SERVICE_NAME: &str = "com.idtty.desktop";
const ACCOUNT_NAME: &str = "quick-unlock";

// ── macOS: Security framework with biometric access control ──────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::ACCOUNT_NAME;
    use super::SERVICE_NAME;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password, generic_password,
        set_generic_password_options,
    };
    use security_framework_sys::base::errSecItemNotFound;
    use zeroize::Zeroizing;

    /// Biometric constraint: Touch ID (any enrolled finger) OR device passcode fallback.
    const AC_FLAGS: AccessControlOptions = AccessControlOptions::BIOMETRY_ANY;

    /// Check if keychain access is available (always true on macOS).
    /// NOTE: Does not check for Touch ID hardware. Macs without biometrics
    /// will still report available; the keychain will use device passcode fallback.
    pub fn is_available() -> bool {
        true
    }

    /// Store master password with biometric access control.
    /// macOS enforces Touch ID / Face ID on READ, not on write.
    pub fn enable(master_password: &str) -> Result<(), String> {
        // Delete existing entry first (SecAccessControl is immutable on update;
        // we must delete + recreate to change access control flags).
        let _ = delete();

        let mut opts = PasswordOptions::new_generic_password(SERVICE_NAME, ACCOUNT_NAME);
        opts.set_access_control_options(AC_FLAGS);

        set_generic_password_options(master_password.as_bytes(), opts)
            .map_err(|e| format!("keychain store: {e}"))
    }

    /// Delete stored master password. Ok if already deleted.
    pub fn disable() -> Result<(), String> {
        delete()
    }

    /// Check if a stored secret exists. Does NOT trigger biometric prompt.
    pub fn is_enabled() -> bool {
        // Build query dictionary manually using raw FFI.
        // We can't use PasswordOptions::push_query / to_dictionary (pub(crate)).
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
                    CFString::from(ACCOUNT_NAME),
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
    pub fn unlock() -> Result<String, String> {
        let opts = PasswordOptions::new_generic_password(SERVICE_NAME, ACCOUNT_NAME);
        // Zeroizing wrapper ensures master password bytes are cleared from heap on drop.
        let data = Zeroizing::new(
            generic_password(opts).map_err(|e| format!("biometric unlock failed: {e}"))?,
        );
        String::from_utf8(data.to_vec()).map_err(|e| format!("keychain data not utf8: {e}"))
    }

    fn delete() -> Result<(), String> {
        match delete_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == errSecItemNotFound => Ok(()),
            Err(e) => Err(format!("keychain delete: {e}")),
        }
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
    use super::ACCOUNT_NAME;
    use super::SERVICE_NAME;
    use keyring::Entry;

    /// Check if the OS keyring is accessible.
    pub fn is_available() -> bool {
        Entry::new(SERVICE_NAME, ACCOUNT_NAME).is_ok()
    }

    /// Store master password in OS keyring.
    pub fn enable(master_password: &str) -> Result<(), String> {
        let entry =
            Entry::new(SERVICE_NAME, ACCOUNT_NAME).map_err(|e| format!("keyring entry: {e}"))?;
        entry
            .set_password(master_password)
            .map_err(|e| format!("keyring store: {e}"))?;
        Ok(())
    }

    /// Delete stored master password. Ok if already deleted.
    pub fn disable() -> Result<(), String> {
        let entry =
            Entry::new(SERVICE_NAME, ACCOUNT_NAME).map_err(|e| format!("keyring entry: {e}"))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("keyring delete: {e}")),
        }
    }

    /// Check if a stored secret exists.
    pub fn is_enabled() -> bool {
        let Ok(entry) = Entry::new(SERVICE_NAME, ACCOUNT_NAME) else {
            return false;
        };
        entry.get_password().is_ok()
    }

    /// Retrieve stored master password. May trigger OS credential prompt.
    pub fn unlock() -> Result<String, String> {
        let entry =
            Entry::new(SERVICE_NAME, ACCOUNT_NAME).map_err(|e| format!("keyring entry: {e}"))?;
        entry
            .get_password()
            .map_err(|e| format!("biometric unlock failed: {e}"))
    }
}

// ── Public API (platform-delegated) ──────────────────────────────────────

/// Check if biometric unlock is available on this platform.
pub fn is_available() -> bool {
    platform::is_available()
}

/// Enable biometric unlock by storing the master password in OS keychain.
pub fn enable(master_password: &str) -> Result<(), String> {
    platform::enable(master_password)
}

/// Disable biometric unlock by deleting the stored master password.
/// IMPORTANT: Must be called on master password change to invalidate stale secrets.
pub fn disable() -> Result<(), String> {
    platform::disable()
}

/// Check if biometric unlock is enabled (secret exists in keychain).
/// Does NOT trigger biometric prompt on macOS.
pub fn is_enabled() -> bool {
    platform::is_enabled()
}

/// Retrieve the stored master password from OS keychain.
/// On macOS: triggers Touch ID / Face ID biometric prompt.
/// On other platforms: may trigger OS credential prompt.
/// Returns the raw master password for vault unlock (daemon-internal only).
pub fn unlock() -> Result<String, String> {
    platform::unlock()
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
        let _ = is_enabled();
    }
}
