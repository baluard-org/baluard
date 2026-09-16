package xyz.actitud.baluard.autofill

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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

    /** Serializes session mutations (peer-review finding #4): the autofill
     *  service, the tile flow and the picker all call in from different
     *  dispatchers; open/unlock/lock must not interleave. */
    private val mutationMutex = Mutex()

    /** UI-facing async work runs here; never the main thread. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Open the last-active vault (main-app handoff via [VaultRegistry]'s
     * persisted active path). Returns whether the session is unlocked.
     * Switching the active vault in the main app is honored on the next call;
     * the superseded handle is LOCKED first so its keys zeroize
     * deterministically instead of waiting for GC (peer-review finding #5).
     */
    suspend fun ensureOpen(): Boolean = mutationMutex.withLock {
        val path = VaultRegistry.loadActiveVault() ?: return false
        if (vault == null || activePath != path) {
            runCatching { vault?.lock() }
            // Stale handle for a removed/switched vault: drop the reference;
            // the Rust Arc (and its keys) free on GC / process exit.
            vault = null
            activePath = path
            vault = runCatching { openVault(path) }.getOrNull()
        }
        vault?.isUnlocked() == true
    }

    /** Lock when the vault's own timeout policy says so. Cheap, per request. */
    suspend fun lockIfExpired() {
        val v = vault ?: return
        if (v.isUnlocked() && v.shouldAutoLock()) lock()
    }

    /**
     * Unlock with the biometric-gated KEK. Returns false on any failure
     * (stale KEK after a password change fails closed in the runtime).
     * The KEK is zeroized before return regardless of outcome (Agy finding
     * #8): JVM heap is GC-managed, but we still shrink the exposure window.
     */
    suspend fun unlock(kek: ByteArray): Boolean = mutationMutex.withLock {
        try {
            ensureOpenUnlocked()
            val v = vault ?: return@withLock false
            runCatching { v.unlockWithKek(kek) }.getOrElse { return@withLock false }
            v.isUnlocked()
        } finally {
            kek.fill(0)
        }
    }

    suspend fun lock() = mutationMutex.withLock {
        runCatching { vault?.lock() }
        vault = null
        activePath = null
    }

    /** ensureOpen body without the mutex (callers holding [mutationMutex]). */
    private suspend fun ensureOpenUnlocked() {
        val path = VaultRegistry.loadActiveVault() ?: return
        if (vault == null || activePath != path) {
            runCatching { vault?.lock() }
            vault = null
            activePath = path
            vault = runCatching { openVault(path) }.getOrNull()
        }
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

    /**
     * Derived TOTP code for a cipher (6 digits), or null when the entry has
     * no seed or the vault is locked. Only the derived code crosses the FFI;
     * the seed never does (same invariant as the desktop).
     */
    suspend fun totpCode(id: String): String? {
        val v = vault?.takeIf { it.isUnlocked() } ?: return null
        val raw = runCatching { v.totpCode(id) }.getOrNull() ?: return null
        val code = runCatching { JSONObject(raw).optString("code") }.getOrNull()
        return code?.takeIf { it.isNotEmpty() }
    }
}
