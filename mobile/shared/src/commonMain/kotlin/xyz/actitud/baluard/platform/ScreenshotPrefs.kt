package xyz.actitud.baluard.platform

/**
 * Device-local preference for allowing screenshots / screen recording.
 * Default OFF (fail secure): the app applies FLAG_SECURE unless the user
 * explicitly opts in. Mirrors the ClipboardPrefs pattern.
 */
expect class ScreenshotPrefs() {
    fun allowScreenshots(): Boolean
    fun setAllowScreenshots(allow: Boolean)
}
