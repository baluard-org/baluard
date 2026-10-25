package xyz.actitud.baluard.autofill

import java.util.UUID
import xyz.actitud.baluard.platform.AppContextHolder
import xyz.actitud.baluard.platform.AutofillSavePrefill

/**
 * One-time token guarding the autofill save handoff (review finding #1:
 * getLaunchedFromPackage is API 34+, minSdk is 32). The :autofill service
 * mints a token into app-sandbox storage immediately before launching
 * MainActivity; the activity consumes it. Other apps can neither read the
 * sandbox file nor guess a UUID, and replay dies on first consume.
 */
object AutofillSaveToken {

    private const val FILE = "autofill_save_token"

    /**
     * Mint a token carrying the save payload. The captured credentials live
     * only in this sandbox file; the intent extra holds the random token
     * alone, so system_server and the task base intent never see them.
     */
    fun mint(username: String?, password: String?, uri: String?): String {
        val token = UUID.randomUUID().toString()
        runCatching {
            val dir = AppContextHolder.require().filesDir
            val payload = org.json.JSONObject().apply {
                put("token", token)
                put("username", username ?: "")
                put("password", password ?: "")
                put("uri", uri ?: "")
            }
            java.io.File(dir, FILE).writeText(payload.toString())
        }
        return token
    }

    /** Payload for [candidate], or null; always consumed. */
    fun consume(candidate: String): AutofillSavePrefill? {
        val dir = AppContextHolder.get()?.filesDir ?: return null
        val file = java.io.File(dir, FILE)
        val stored = runCatching { file.readText() }.getOrNull()
        runCatching { file.delete() }
        if (stored.isNullOrBlank()) return null
        val obj = runCatching { org.json.JSONObject(stored) }.getOrNull() ?: return null
        if (obj.optString("token") != candidate) return null
        val username = obj.optString("username").ifBlank { null }
        val password = obj.optString("password").ifBlank { null }
        val uri = obj.optString("uri").ifBlank { null }
        if (username == null && password == null && uri == null) return null
        return AutofillSavePrefill(username, password, uri)
    }
}
