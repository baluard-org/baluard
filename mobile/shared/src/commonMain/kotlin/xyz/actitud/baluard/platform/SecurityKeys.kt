package xyz.actitud.baluard.platform

import xyz.actitud.baluard.MobileHardwareTransport
import xyz.actitud.baluard.i18n.t

/** Whether this device can reach a FIDO2 key over NFC or USB host. */
expect fun securityKeysSupported(): Boolean

/** A fresh operation-scoped transport. USB is preferred when already attached. */
expect fun newSecurityKeyTransport(): MobileHardwareTransport

suspend fun <T> withSecurityKeyTransport(
    block: suspend (MobileHardwareTransport) -> T,
): T {
    val transport = newSecurityKeyTransport()
    // A cancelled coroutine must not tear the transport down mid-tap: the
    // Rust blocking task keeps using the connection until the operation ends.
    return try {
        kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
            block(transport)
        }
    } finally {
        transport.shutdown()
    }
}

fun securityKeyErrorMessage(error: Throwable): String {
    val detail = error.message.orEmpty()
    return when {
        detail.contains("wrong password", ignoreCase = true) ||
            detail.contains("master password incorrect", ignoreCase = true) -> t("login.wrongPassword")
        detail.contains("not tapped", ignoreCase = true) ||
            detail.contains("timed out", ignoreCase = true) -> t("settings.hardwareKeyTimeout")
        detail.contains("cancel", ignoreCase = true) -> t("settings.hardwareKeyCancelled")
        detail.contains("NFC", ignoreCase = true) ||
            detail.contains("Hold the security key", ignoreCase = true) ||
            detail.contains("USB", ignoreCase = true) -> t("settings.hardwareKeyHold")
        else -> t("settings.hardwareKeyFailed")
    }
}
