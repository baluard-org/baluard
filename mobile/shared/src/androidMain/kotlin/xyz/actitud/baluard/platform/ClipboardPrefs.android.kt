package xyz.actitud.baluard.platform

import android.content.Context

/** SharedPreferences-backed persistence for the clipboard auto-clear setting. */
actual class ClipboardPrefs actual constructor() {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_local_prefs", Context.MODE_PRIVATE)

    actual fun loadSeconds(): Int {
        val stored = CrossProcessPrefs.read(KEY) ?: run {
            val legacy = prefs().getInt(KEY, DEFAULT)
            CrossProcessPrefs.write(KEY, legacy.toString())
            legacy.toString()
        }
        return runCatching { stored.trim().toInt().coerceIn(0, MAX) }.getOrDefault(DEFAULT)
    }

    actual fun saveSeconds(seconds: Int) {
        CrossProcessPrefs.write(KEY, seconds.coerceIn(0, MAX).toString())
    }

    private companion object {
        const val KEY = "clipboardClearSeconds"
        const val DEFAULT = 30
        const val MAX = 600
    }
}
