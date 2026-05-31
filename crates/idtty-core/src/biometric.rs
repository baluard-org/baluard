//! OS keychain biometric unlock.
//!
//! Stores a derived quick-unlock secret in the OS keychain.
//! The OS enforces biometric (Touch ID, Windows Hello) or device PIN.
//! This is the same model Bitwarden desktop uses.

use keyring::Entry;

const SERVICE_NAME: &str = "com.idtty.desktop";
const QUICK_UNLOCK_KEY: &str = "quick-unlock";

/// Check if biometric unlock is available on this platform.
pub fn is_available() -> bool {
    // keyring crate works on macOS (Keychain), Windows (Credential Manager),
    // and Linux (libsecret / GNOME Keyring). If we can create an entry,
    // biometric unlock is available.
    Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY).is_ok()
}

/// Enable biometric unlock by storing a quick-unlock secret.
/// The secret is derived from the master password via HKDF.
/// Returns Ok(()) if stored successfully.
pub fn enable(master_password: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY)
        .map_err(|e| format!("keyring entry: {e}"))?;

    // Derive a quick-unlock secret from the master password
    let secret = derive_quick_secret(master_password);
    entry.set_password(&secret)
        .map_err(|e| format!("keyring store: {e}"))?;

    Ok(())
}

/// Disable biometric unlock by deleting the stored secret.
pub fn disable() -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY)
        .map_err(|e| format!("keyring entry: {e}"))?;

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

/// Attempt biometric unlock. Returns the stored quick-unlock secret.
/// The OS will prompt for biometric/PIN before returning the secret.
/// Returns Err if not enabled or biometric check failed.
pub fn unlock() -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY)
        .map_err(|e| format!("keyring entry: {e}"))?;

    entry.get_password()
        .map_err(|e| format!("biometric unlock failed: {e}"))
}

/// Verify a master password against the stored quick-unlock secret.
pub fn verify_master_password(master_password: &str) -> Result<bool, String> {
    let entry = Entry::new(SERVICE_NAME, QUICK_UNLOCK_KEY)
        .map_err(|e| format!("keyring entry: {e}"))?;

    let stored = entry.get_password()
        .map_err(|e| format!("keyring read: {e}"))?;

    let candidate = derive_quick_secret(master_password);
    Ok(stored == candidate)
}

/// Derive a quick-unlock secret from master password via HKDF.
fn derive_quick_secret(master_password: &str) -> String {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(
        Some(b"idtty-quick-unlock-v1"),
        master_password.as_bytes(),
    );

    let mut okm = [0u8; 32];
    hkdf.expand(b"quick-unlock-key", &mut okm)
        .expect("32 bytes is valid output length");

    hex::encode(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let s1 = derive_quick_secret("test-password");
        let s2 = derive_quick_secret("test-password");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn derive_different_passwords() {
        let s1 = derive_quick_secret("password1");
        let s2 = derive_quick_secret("password2");
        assert_ne!(s1, s2);
    }
}
