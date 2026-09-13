package xyz.actitud.baluard.platform

/**
 * Platform-abstract biometric quick-unlock (B5). `expect` in commonMain;
 * `actual` in androidMain (BiometricPrompt + AndroidKeystore) and iosMain
 * (LAContext + Keychain; stubbed until the iOS host build).
 *
 * Per plan §3.2 / §3.7: quick-unlock retrieves the biometric-gated KEK from
 * the platform store and unlocks via `unlockWith_kek` — NEVER the master
 * password or its Argon2id KDF (the memory-capped KDF must not run in an
 * autofill/extension process; the main app may run it, which is why
 * [enroll] accepts an already-derived KEK).
 *
 * [vaultKey] namespaces the stored KEK per vault (the vault path; the
 * Android impl hashes it into the keystore alias + prefs blob key).
 */
expect class Biometric() {
    /** Whether a biometric authenticator is available on this device. */
    fun isAvailable(): Boolean

    /** Whether a KEK is enrolled for [vaultKey] (quick-unlock offered). */
    fun isEnrolled(vaultKey: String): Boolean

    /**
     * Remove the enrolled KEK for [vaultKey] (quick-unlock off). Deletes the
     * keystore wrapping key and the stored blob. No-op when not enrolled;
     * always safe — the master password remains the fallback path.
     */
    fun disenroll(vaultKey: String)

    /**
     * Store the Argon2id-derived [kek] behind biometric gating. Runs the
     * platform biometric prompt (ENCRYPT ceremony) and persists the wrapped
     * KEK on success. Runs in the main app only (post master-password
     * unlock, explicit user action).
     */
    fun enroll(
        vaultKey: String,
        kek: ByteArray,
        title: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    )

    /**
     * Prompt + decrypt: on confirmed identity, [onSuccess] receives the KEK
     * (feed it to `MobileVault.unlockWithKek`). [onError] on failure,
     * cancellation, or invalidated enrollment (new fingerprint enrolled).
     */
    fun unlock(
        vaultKey: String,
        title: String,
        onSuccess: (kek: ByteArray) -> Unit,
        onError: (String) -> Unit,
    )
}
