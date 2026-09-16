package xyz.actitud.baluard.platform

/**
 * Android actual: SharedPreferences store shared by the main process and the
 * `:autofill` service process (the service reads this on every fill request).
 */
actual object AutofillSuggestions {

    private const val FILE = "baluard_autofill_prefs"
    private const val KEY = "inline_suggestions_enabled"

    private fun prefs() = AppContextHolder.get()
        ?.getSharedPreferences(FILE, android.content.Context.MODE_PRIVATE)

    actual fun inlineEnabled(): Boolean =
        prefs()?.getBoolean(KEY, true) ?: true

    actual fun setInlineEnabled(enabled: Boolean) {
        prefs()?.edit()?.putBoolean(KEY, enabled)?.apply()
    }
}
