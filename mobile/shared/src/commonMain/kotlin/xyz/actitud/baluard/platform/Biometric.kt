package xyz.actitud.baluard.platform

/**
 * Platform-abstract biometric prompt. `expect` in commonMain; `actual` in
 * androidMain (BiometricPrompt) and iosMain (LAContext wrapper).
 *
 * Per plan §3.2 / §3.6: biometric quick-unlock retrieves the biometric-gated
 * KEK from the platform keychain (StrongBox / Secure Enclave where available)
 * and unlocks via `VaultHandle::unlock_with_kek`, NOT the master password —
 * the memory-capped Argon2id KDF never runs in a biometric flow.
 *
 * Phase 2 declares the contract; the `actual` impls land when the platform
 * glue is wired (androidMain BiometricPrompt, iosMain LAContext).
 */
expect class Biometric() {
    /**
     * Whether a biometric authenticator is available on this device.
     * Cheap; safe to call on every unlock screen render.
     */
    fun isAvailable(): Boolean

    /**
     * Prompt the user for biometric auth. [onSuccess] runs on the platform's
     * main thread when the OS confirms identity; [onError] runs on failure or
     * cancellation.
     *
     * The actual KEK retrieval + `unlock_with_kek` call is orchestrated by the
     * platform layer (it owns the keychain access); this just gates the prompt.
     */
    fun prompt(
        title: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    )
}
