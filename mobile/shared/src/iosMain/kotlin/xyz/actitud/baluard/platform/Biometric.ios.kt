package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [Biometric]. Stub for Phase 2: returns false until the
 * LAContext + Keychain glue is wired. The real impl retrieves the wrapped KEK
 * from the Secure Enclave / Keychain and unlocks via `unlock_with_kek`.
 */
actual class Biometric actual constructor() {
    actual fun isAvailable(): Boolean = false

    actual fun prompt(
        title: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        onError("biometric not yet wired on iOS")
    }
}
