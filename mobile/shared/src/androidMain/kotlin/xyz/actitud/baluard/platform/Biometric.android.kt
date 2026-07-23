package xyz.actitud.baluard.platform

/**
 * Android `actual` for [Biometric]. Stub for Phase 2: returns false until the
 * BiometricPrompt + AndroidKeystore glue is wired. The real impl retrieves the
 * biometric-gated KEK from the keystore and unlocks via `unlock_with_kek`
 * (never the master-password KDF — plan §3.2 OOM guard).
 */
actual class Biometric actual constructor() {
    actual fun isAvailable(): Boolean = false

    actual fun prompt(
        title: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        onError("biometric not yet wired on Android")
    }
}
