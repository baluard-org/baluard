package app.baluard.mobile.platform

/**
 * Android actual: file-backed flag (AutofillFlagFile) shared across the
 * main process and the `:autofill` service process (review finding #7).
 */
actual object AutofillSuggestions {

    private const val FLAG_FILE = "inline_suggestions_enabled"

    actual fun inlineEnabled(): Boolean = AutofillFlagFile.read(FLAG_FILE, default = true)

    actual fun setInlineEnabled(enabled: Boolean) {
        AutofillFlagFile.write(FLAG_FILE, enabled)
    }
}
