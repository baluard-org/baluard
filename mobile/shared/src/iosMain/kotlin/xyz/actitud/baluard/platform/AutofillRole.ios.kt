package xyz.actitud.baluard.platform

/**
 * iOS actual: there is no requestable autofill-provider role (the credential
 * provider is enabled in iOS Settings per password manager and iOS gives
 * apps no intent to request it). The settings section hides on iOS; Phase 7
 * revisits this surface.
 */
actual object AutofillRole {
    actual fun isSupported(): Boolean = false
    actual fun isEnabled(): Boolean = false
    actual fun requestRole() = Unit
}
