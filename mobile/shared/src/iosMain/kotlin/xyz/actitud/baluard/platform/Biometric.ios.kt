package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [Biometric]. Stub until the iOS host build (plan §1.1:
 * Android first). The real impl uses LAContext + Keychain (kSecAccessControl
 * BiometryAny) mirroring the desktop's SecAccessControl(BIOMETRY_ANY) model.
 */
actual class Biometric actual constructor() {
    actual fun isAvailable(): Boolean = false

    actual fun isEnrolled(vaultKey: String): Boolean = false

    actual fun enroll(
        vaultKey: String,
        kek: ByteArray,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        onError("biometric not yet wired on iOS")
    }

    actual fun unlock(
        vaultKey: String,
        title: String,
        onSuccess: (kek: ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        onError("biometric not yet wired on iOS")
    }
}
