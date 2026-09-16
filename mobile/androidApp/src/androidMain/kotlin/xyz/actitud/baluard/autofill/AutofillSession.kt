package xyz.actitud.baluard.autofill

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.json.JSONArray
import org.json.JSONObject
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.openVault
import xyz.actitud.baluard.platform.VaultRegistry

/**
 * Autofill-side vault session (plan D6): ONE unlocked [MobileVault] living in
 * the `:autofill` process, shared by [BaluardAutofillService] and
 * [AutofillActivity] (both declared `android:process=":autofill"`, so the
 * Kotlin object is genuinely process-singleton).
 *
 * Unlock invariant: only [unlock] ever touches key material, and it only ever
 * receives the biometric-gated KEK (unwrapped by BiometricPrompt inside
 * [AutofillActivity]). The master-password KDF never runs in this process.
 *
 * Auto-lock: there is no background walker here; every fill request calls
 * [lockIfExpired], which consults the runtime's `should_auto_lock` (the
 * vault's own timeout policy). Process death = fail secure by design.
 */
object AutofillSession {

    data class Match(
        val id: String,
        val name: String,
        val username: String?,
        val favorite: Boolean,
    )

    private var vault: MobileVault? = null
    private var activePath: String? = null

    /** UI-facing async work runs here; never the main thread. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Open the last-active vault (main-app handoff via [VaultRegistry]'s
     * persisted active path). Returns whether the session is unlocked.
     * Switching the active vault in the main app is honored on the next call.
     */
    suspend fun ensureOpen(): Boolean {
        val path = VaultRegistry.loadActiveVault() ?: return false
        if (vault == null || activePath != path) {
            // Stale handle for a removed/switched vault: drop the reference;
            // the Rust Arc (and its keys) free on GC / process exit.
            vault = null
            activePath = path
            vault = runCatching { openVault(path) }.getOrNull()
        }
        return vault?.isUnlocked() == true
    }

    /** Lock when the vault's own timeout policy says so. Cheap, per request. */
    suspend fun lockIfExpired() {
        val v = vault ?: return
        if (v.isUnlocked() && v.shouldAutoLock()) lock()
    }

    /**
     * Unlock with the biometric-gated KEK. Returns false on any failure
     * (stale KEK after a password change fails closed in the runtime).
     */
    suspend fun unlock(kek: ByteArray): Boolean {
        ensureOpen()
        val v = vault ?: return false
        runCatching { v.unlockWithKek(kek) }.getOrElse { return false }
        return v.isUnlocked()
    }

    suspend fun lock() {
        runCatching { vault?.lock() }
        vault = null
        activePath = null
    }

    /**
     * Query matching logins for a fill target. Output NEVER contains
     * passwords (plan D2); the runtime enforces the shape, this parser only
     * reads id/name/username/favorite.
     */
    suspend fun matches(target: String): List<Match> {
        val v = vault?.takeIf { it.isUnlocked() } ?: return emptyList()
        val raw = runCatching { v.autofillQuery(target) }.getOrNull() ?: return emptyList()
        val arr = runCatching { JSONArray(raw) }.getOrDefault(JSONArray())
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            Match(
                id = o.optString("id"),
                name = o.optString("name"),
                username = o.opt("username") as? String,
                favorite = o.optBoolean("favorite", false),
            )
        }
    }

    /**
     * Full credential for a matched id: (username, password). Fetched only
     * here, only for entries about to be offered as datasets; passwords are
     * never kept beyond the returned pair.
     */
    suspend fun credential(id: String): Pair<String?, String?>? {
        val v = vault?.takeIf { it.isUnlocked() } ?: return null
        val raw = runCatching { v.getCipher(id, true) }.getOrNull() ?: return null
        val o = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val username = o.opt("username") as? String
        val password = o.opt("password") as? String
        return username to password
    }
}
