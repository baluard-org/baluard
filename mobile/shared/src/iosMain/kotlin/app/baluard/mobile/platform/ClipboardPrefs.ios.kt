package app.baluard.mobile.platform

import platform.Foundation.NSUserDefaults

/**
 * iOS `actual`: NSUserDefaults-backed (non-secret preference), so the
 * Settings choice survives restarts and is visible to every instance —
 * the old in-memory stub ignored the user's pick entirely.
 */
actual class ClipboardPrefs actual constructor() {
    private val d = NSUserDefaults.standardUserDefaults

    actual fun loadSeconds(): Int {
        val v = d.objectForKey(KEY) as? Long ?: return DEFAULT
        return v.toInt().coerceIn(0, MAX)
    }

    actual fun saveSeconds(seconds: Int) {
        d.setObject(seconds.coerceIn(0, MAX).toLong(), forKey = KEY)
    }

    private companion object {
        const val KEY = "clipboardClearSeconds"
        const val DEFAULT = 60
        const val MAX = 600
    }
}
