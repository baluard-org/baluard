package app.baluard.mobile.platform

import platform.Foundation.NSUserDefaults

/**
 * iOS `actual`: NSUserDefaults-backed. The screenshot SHIELD itself has no
 * iOS implementation yet; [screenshotShieldSupported] reports false so the
 * Settings row (and this pref) stays hidden until the host platform wires
 * blur-on-resign-active and a UIScreen.isCaptured check.
 */
actual class ScreenshotPrefs actual constructor() {
    private val d = NSUserDefaults.standardUserDefaults

    actual fun allowScreenshots(): Boolean =
        (d.objectForKey(KEY) as? Long)?.toInt() == 1

    actual fun setAllowScreenshots(allow: Boolean) {
        d.setObject((if (allow) 1 else 0).toLong(), forKey = KEY)
    }

    private companion object {
        const val KEY = "allowScreenshots"
    }
}
