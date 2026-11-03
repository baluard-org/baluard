package app.baluard.mobile.platform

/**
 * iOS actual: no browser-owned third-party autofill switches exist; the
 * section renders no rows.
 */
actual object BrowserAutofillIntegration {
    actual fun browsers(): List<BrowserIntegration> = emptyList()
    actual fun openSettings(id: String) = Unit
}
