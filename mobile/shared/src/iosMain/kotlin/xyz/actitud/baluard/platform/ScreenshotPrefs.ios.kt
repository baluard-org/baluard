package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [ScreenshotPrefs]. In-memory stub until the iOS host
 * build (plan §1.1), matching the ClipboardPrefs stub. Default secure.
 */
actual class ScreenshotPrefs actual constructor() {
    private var allow: Boolean = false

    actual fun allowScreenshots(): Boolean = allow

    actual fun setAllowScreenshots(allow: Boolean) {
        this.allow = allow
    }
}
