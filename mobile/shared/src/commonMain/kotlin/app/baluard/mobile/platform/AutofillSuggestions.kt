package app.baluard.mobile.platform

/**
 * How autofill suggestions are displayed (Bitwarden-parity option, plan
 * 2b/S2): inline chips in the keyboard, or the classic popup dropdown over
 * the field. Default mirrors Bitwarden: inline when the IME supports it.
 */
expect object AutofillSuggestions {
    /** Inline keyboard chips on (true) or popup dropdown only (false). */
    fun inlineEnabled(): Boolean

    fun setInlineEnabled(enabled: Boolean)
}
