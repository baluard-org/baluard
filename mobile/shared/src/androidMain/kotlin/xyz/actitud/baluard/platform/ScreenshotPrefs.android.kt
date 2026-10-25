package xyz.actitud.baluard.platform

import android.content.Context

/** SharedPreferences-backed persistence for the screenshot permission. */
actual class ScreenshotPrefs actual constructor() {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_local_prefs", Context.MODE_PRIVATE)

    actual fun allowScreenshots(): Boolean {
        val stored = CrossProcessPrefs.read(KEY) ?: run {
            val legacy = prefs().getBoolean(KEY, DEFAULT)
            CrossProcessPrefs.write(KEY, if (legacy) "1" else "0")
            return legacy
        }
        return stored == "1"
    }

    actual fun setAllowScreenshots(allow: Boolean) {
        CrossProcessPrefs.write(KEY, if (allow) "1" else "0")
    }

    private companion object {
        const val KEY = "allowScreenshots"
        const val DEFAULT = false
    }
}
