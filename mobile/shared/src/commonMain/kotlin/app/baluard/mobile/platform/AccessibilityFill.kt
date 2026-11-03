package app.baluard.mobile.platform

/**
 * Accessibility fill feature gate (Phase 6.5, planandroid-accessibility-tile).
 * Baluard-side opt-in: the system accessibility switch alone does nothing.
 * Prefs live in app-sandbox storage readable from both the main process and
 * the `:autofill` process; the service checks the flag on every event.
 */
expect object AccessibilityFill {
    /** Baluard-side opt-in flag. Default OFF. */
    fun enabled(): Boolean

    fun setEnabled(enabled: Boolean)

    /** Whether the system currently has Baluard's accessibility service on. */
    fun serviceEnabledInSystem(): Boolean

    /** Open the system Accessibility settings screen. */
    fun openSystemA11ySettings()
}
