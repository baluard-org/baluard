package app.baluard.mobile.passkeys

import java.util.concurrent.ConcurrentHashMap

/** What the framework handed us, re-read from the intent (never memory). */
sealed class PasskeyRequest {
    abstract val id: String

    data class Create(
        override val id: String,
        val requestJson: String,
        val rpId: String,
        val rpName: String?,
        val userName: String?,
        val clientDataJson: String?,
        /** Browser-supplied clientDataHash (base64url), when present. */
        val clientDataHash: String?,
        /** Validated ceremony origin (https URL or android:apk-key-hash). */
        val origin: String,
    ) : PasskeyRequest()

    data class Assert(
        override val id: String,
        val requestJson: String,
        val rpId: String,
        val allowCredentialIds: List<String>,
        val clientDataJson: String?,
        val clientDataHash: String?,
        val origin: String,
        /** Entry chosen on the system sheet, when it carried one. */
        val credentialId: String?,
    ) : PasskeyRequest()

    /** Locked-vault Begin leg: after an in-app unlock we re-list and return. */
    data class Unlock(override val id: String) : PasskeyRequest()
}

/**
 * Cache linking the trampoline's intent to the fulfillment screens. The
 * intent is the authoritative request source (§4) — this store only proves
 * a request id is ours, so a crafted extra can never drive a ceremony
 * (§11). One pending request at a time; each is consumed on use.
 */
object PasskeyRequestManager {
    private val pending = ConcurrentHashMap<String, PasskeyRequest>()

    /**
     * The framework's requests, kept android-side for the unlock return leg
     * (MainActivity re-lists and answers it after an in-app unlock). The
     * AuthenticationAction PendingIntent delivers a BeginGetCredentialRequest
     * (NOT a ProviderGetCredentialRequest), so both shapes are kept.
     */
    var frameworkGet: androidx.credentials.provider.ProviderGetCredentialRequest? = null
    var frameworkBegin: androidx.credentials.provider.BeginGetCredentialRequest? = null

    fun put(
        request: PasskeyRequest,
        frameworkGetRequest: androidx.credentials.provider.ProviderGetCredentialRequest? = null,
        frameworkBeginRequest: androidx.credentials.provider.BeginGetCredentialRequest? = null,
    ) {
        pending.clear()
        frameworkGet = frameworkGetRequest
        frameworkBegin = frameworkBeginRequest
        pending[request.id] = request
    }

    fun peek(id: String): PasskeyRequest? = pending[id]

    fun consume(id: String): PasskeyRequest? = pending.remove(id)
}
