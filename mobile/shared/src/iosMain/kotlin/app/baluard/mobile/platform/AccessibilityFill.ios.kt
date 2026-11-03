package app.baluard.mobile.platform

/**
 * iOS actual: no accessibility-fill concept (Phase 7 uses the credential
 * provider). Gate stays off and the settings section hides on iOS.
 */
actual object AccessibilityFill {
    actual fun enabled(): Boolean = false
    actual fun setEnabled(enabled: Boolean) = Unit
    actual fun serviceEnabledInSystem(): Boolean = false
    actual fun openSystemA11ySettings() = Unit
}
