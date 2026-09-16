package xyz.actitud.baluard.platform

/**
 * System autofill-provider role (Phase 6 P5). Android lets the user pick the
 * autofill provider per device; iOS has no equivalent concept (credential
 * provider is set per-password-settings and cannot be requested), so iOS
 * reports unsupported and the settings section hides.
 */
expect object AutofillRole {
    /** Whether this platform has a requestable autofill-provider role. */
    fun isSupported(): Boolean

    /** Whether the OS currently has this app set as the autofill provider. */
    fun isEnabled(): Boolean

    /** Open the system screen where the user picks the autofill provider. */
    fun requestRole()
}
