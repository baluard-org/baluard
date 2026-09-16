package xyz.actitud.baluard.platform

/**
 * Browser third-party autofill integration (Bitwarden-parity, plan 2b/S3).
 * Chromium-family browsers (Brave, Chrome, Vivaldi) expose their own
 * "third-party autofill services" switch; a password manager cannot flip it,
 * only mirror its state and deep-link the user to the browser's settings.
 */
expect object BrowserAutofillIntegration {
    /** Any Brave release channel installed on this device. */
    fun isAvailable(): Boolean

    /**
     * Brave's own third-party autofill switch. null = installed but the
     * probe cannot read it (provider missing); the UI shows the row anyway.
     */
    fun isEnabled(): Boolean?

    /** Open Brave's in-app autofill settings screen. */
    fun openSettings()
}
