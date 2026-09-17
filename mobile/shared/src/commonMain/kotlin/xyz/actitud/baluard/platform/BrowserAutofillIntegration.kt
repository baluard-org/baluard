package xyz.actitud.baluard.platform

/**
 * Browser third-party autofill integration (Bitwarden parity, plan 2b/S3).
 * Chromium-family browsers (Brave, Chrome, Vivaldi) carry their own
 * "third-party autofill services" switch; a password manager cannot flip it,
 * only mirror its state and deep-link the user into the browser's settings.
 * Rows render per installed browser; the switch state is a live mirror and
 * tapping opens that browser's settings.
 */
data class BrowserIntegration(
    /** Stable id ("brave", "chrome", "vivaldi"). */
    val id: String,
    /** Installed on this device (any channel). */
    val available: Boolean,
    /**
     * The browser's own third-party autofill switch. null = installed but
     * undetectable (provider missing); the row still shows.
     */
    val enabled: Boolean?,
)

expect object BrowserAutofillIntegration {
    /** All supported browsers with per-device availability + mirrored state. */
    fun browsers(): List<BrowserIntegration>

    /** Open the browser's in-app autofill settings screen. */
    fun openSettings(id: String)
}
