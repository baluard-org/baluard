package xyz.actitud.baluard.platform

import android.content.Context

/** SharedPreferences-backed persistence for the clipboard auto-clear setting. */
actual class ClipboardPrefs actual constructor() {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_local_prefs", Context.MODE_PRIVATE)

    actual fun loadSeconds(): Int =
        prefs().getInt(KEY, DEFAULT).coerceIn(0, MAX)

    actual fun saveSeconds(seconds: Int) {
        prefs().edit().putInt(KEY, seconds.coerceIn(0, MAX)).apply()
    }

    private companion object {
        const val KEY = "clipboardClearSeconds"
        const val DEFAULT = 30
        const val MAX = 600
    }
}
