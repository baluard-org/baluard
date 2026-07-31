package xyz.actitud.baluard.autofill

/**
 * Retrieves the biometric-gated KEK from the AndroidKeystore for the autofill
 * quick-unlock path (plan §3.2). The KEK is the Argon2id output over the master
 * password (NOT the password), stored under a BiometricPrompt-gated key.
 *
 * Scaffold: returns null until the Keystore wiring lands. The real impl reads
 * an EncryptedSharedPreferences / Keystore-backed blob, requiring a BiometricPrompt
 * CryptoObject to decrypt it (biometric gates the read, not just the prompt).
 */
object KeystoreKekProvider {
    fun retrieveKek(vaultId: String): ByteArray? {
        // TODO Phase 6: AndroidKeystore + BiometricPrompt CryptoObject decrypt.
        // vaultId = deterministic UUID from the KDF salt (VaultHandle::derive_vault_id).
        return null
    }
}
