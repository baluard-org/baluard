package app.baluard.mobile.passkeys

/**
 * UI-side mirror of the staged provider request (the androidApp
 * [PasskeyRequest] mapped into shared code — shared cannot see androidApp
 * types). Pure data: the screens render from this and hand results back
 * through [app.baluard.mobile.ui.App]'s passkey callbacks.
 */
sealed class PasskeyUiRequest {
    abstract val id: String

    data class Create(
        override val id: String,
        val requestJson: String,
        val rpId: String,
        val rpName: String?,
        val userName: String?,
        /** Validated ceremony origin (https URL or android:apk-key-hash). */
        val origin: String,
        /** Browser-supplied clientDataHash (base64url), when present. */
        val clientDataHash: String?,
    ) : PasskeyUiRequest()

    data class Assert(
        override val id: String,
        val requestJson: String,
        val rpId: String,
        val origin: String,
        val clientDataHash: String?,
        /** Entry chosen on the system sheet, when it carried one. */
        val credentialId: String?,
        val allowCredentialIds: List<String>,
    ) : PasskeyUiRequest()

    /** Locked-vault Begin leg: after an in-app unlock the sheet is re-listed. */
    data class Unlock(override val id: String) : PasskeyUiRequest()
}
