package xyz.actitud.baluard.autofill

import java.util.UUID
import xyz.actitud.baluard.platform.AppContextHolder

/**
 * One-time token guarding the autofill save handoff (review finding #1:
 * getLaunchedFromPackage is API 34+, minSdk is 32). The :autofill service
 * mints a token into app-sandbox storage immediately before launching
 * MainActivity; the activity consumes it. Other apps can neither read the
 * sandbox file nor guess a UUID, and replay dies on first consume.
 */
object AutofillSaveToken {

    private const val FILE = "autofill_save_token"

    /** Mint a token, persist it, and return it for the intent extra. */
    fun mint(): String {
        val token = UUID.randomUUID().toString()
        runCatching {
            val dir = AppContextHolder.require().filesDir
            java.io.File(dir, FILE).writeText(token)
        }
        return token
    }

    /** True only when [candidate] matches the stored token; always consumed. */
    fun consume(candidate: String): Boolean {
        val dir = AppContextHolder.get()?.filesDir ?: return false
        val file = java.io.File(dir, FILE)
        val stored = runCatching { file.readText().trim() }.getOrNull()
        runCatching { file.delete() }
        return stored != null && stored.isNotEmpty() && stored == candidate
    }
}
