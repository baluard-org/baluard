package xyz.actitud.baluard.platform

/**
 * iOS actual: no browser-owned third-party autofill switches exist; the
 * section hides.
 */
actual object BrowserAutofillIntegration {
    actual fun isAvailable(): Boolean = false
    actual fun isEnabled(): Boolean? = null
    actual fun openSettings() = Unit
}
