package xyz.actitud.baluard.platform

import android.content.Context

/** SharedPreferences-backed persistence for the screenshot permission. */
actual class ScreenshotPrefs actual constructor() {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_local_prefs", Context.MODE_PRIVATE)

    actual fun allowScreenshots(): Boolean = prefs().getBoolean(KEY, DEFAULT)

    actual fun setAllowScreenshots(allow: Boolean) {
        prefs().edit().putBoolean(KEY, allow).apply()
    }

    private companion object {
        const val KEY = "allowScreenshots"
        const val DEFAULT = false
    }
}
