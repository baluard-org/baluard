package xyz.actitud.baluard.platform

/**
 * iOS actual: no autofill-framework display options (Phase 7 uses the
 * QuickType bar exclusively). Inline stays the no-op default.
 */
actual object AutofillSuggestions {
    actual fun inlineEnabled(): Boolean = true
    actual fun setInlineEnabled(enabled: Boolean) = Unit
}
