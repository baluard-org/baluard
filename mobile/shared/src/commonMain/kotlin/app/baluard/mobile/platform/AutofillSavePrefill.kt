package app.baluard.mobile.platform

/**
 * Captured login handed over from the autofill service's save prompt
 * (Phase 6 P4) into the main app's prefilled create-editor. Plain value
 * type so commonMain UI can consume it without Android imports.
 */
data class AutofillSavePrefill(
    val username: String?,
    val password: String?,
    /** https:// URI for web saves, androidapp://package for native app saves. */
    val uri: String?,
)
