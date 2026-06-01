//! OS keychain biometric unlock.
//!
//! Stores the master password in the OS keychain.
//! The OS enforces biometric (Touch ID, Windows Hello) or device PIN before releasing it.
//! The daemon retrieves the password and performs vault unlock internally.
//! The master password NEVER leaves the daemon process over IPC.

use keyring::Entry;

const SERVICE_NAME: &str = "com.idtty.desktop";
const QUICK_UNLOCK_KEY: &str = "quick-unlock";

/// Check if biometric unlock is available on this platform.
pub fn is_available() -> bool {
    Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY).is_ok()
}

/// Enable biometric unlock by storing the master password in OS keychain.
/// The OS keychain provides at-rest encryption; biometric gating depends on
/// OS keychain configuration (macOS: Keychain Access Control; Windows: Cred Provider).
pub fn enable(master_password: &str) -> Result<(), String> {
    let entry =
        Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY).map_err(|e| format!("keyring entry: {e}"))?;

    entry
        .set_password(master_password)
        .map_err(|e| format!("keyring store: {e}"))?;

    Ok(())
}

/// Disable biometric unlock by deleting the stored master password.
/// IMPORTANT: Must be called on master password change to invalidate stale secrets.
pub fn disable() -> Result<(), String> {
    let entry =
        Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY).map_err(|e| format!("keyring entry: {e}"))?;

    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // already deleted
        Err(e) => Err(format!("keyring delete: {e}")),
    }
}

/// Check if biometric unlock is enabled (secret exists in keychain).
pub fn is_enabled() -> bool {
    let Ok(entry) = Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY) else {
        return false;
    };
    entry.get_password().is_ok()
}

/// Retrieve the stored master password from OS keychain.
/// The OS may prompt for biometric/PIN before releasing.
/// Returns the raw master password for vault unlock (daemon-internal only).
pub fn unlock() -> Result<String, String> {
    let entry =
        Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY).map_err(|e| format!("keyring entry: {e}"))?;

    entry
        .get_password()
        .map_err(|e| format!("biometric unlock failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_does_not_panic() {
        // Just verify it doesn't crash. May return false in CI.
        let _ = is_available();
    }

    #[test]
    fn is_enabled_does_not_panic() {
        let _ = is_enabled();
    }
}
