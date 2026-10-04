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

    /** Path-B app-to-web suggestion: an untrusted candidate domain and
     *  the entries that would match it after the user trusts the pairing. */
    data class AppSuggestion(
        val domain: String,
        val matches: List<Match>,
    )

    data class QueryResult(
        val matches: List<Match>,
        val suggestions: List<AppSuggestion>,
    )

    private var vault: MobileVault? = null
    private var activePath: String? = null

    /** Serializes session mutations (peer-review finding #4): the autofill
     *  service, the tile flow and the picker all call in from different
     *  dispatchers; open/unlock/lock must not interleave. */
    private val mutationMutex = Mutex()

    /** UI-facing async work runs here; never the main thread. Temp crash
     *  catcher (Brave device pass): uncaught coroutine failures were killing
     *  the process silently after fingerprint. */
    val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default +
            kotlinx.coroutines.CoroutineExceptionHandler { _, e ->
                android.util.Log.e("BaluardA11yDbg", "uncaught coroutine failure", e)
            },
    )

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
     * The KEK is zeroized before return regardless of outcome (review finding
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
    suspend fun matches(target: String): List<Match> = query(target).matches

    /**
     * Full query result: direct/trusted matches plus the path-B app-to-web
     * suggestions (untrusted domain candidates with candidate entries).
     * Suggestions are empty unless the vault setting is on and the target
     * is `androidapp://`.
     */
    suspend fun query(target: String): QueryResult {
        val v = vault?.takeIf { it.isUnlocked() } ?: return QueryResult(emptyList(), emptyList())
        val raw = runCatching { v.autofillQuery(target) }.getOrNull()
            ?: return QueryResult(emptyList(), emptyList())
        val obj = runCatching { JSONObject(raw) }.getOrNull()
            ?: return QueryResult(emptyList(), emptyList())
        return QueryResult(
            matches = parseMatches(obj.optJSONArray("matches")),
            suggestions = (obj.optJSONArray("app_suggestions") ?: JSONArray())
                .let { arr ->
                    (0 until arr.length()).mapNotNull { i ->
                        val s = arr.optJSONObject(i) ?: return@mapNotNull null
                        AppSuggestion(
                            domain = s.optString("domain"),
                            matches = parseMatches(s.optJSONArray("matches")),
                        )
                    }
                },
        )
    }

    private fun parseMatches(arr: JSONArray?): List<Match> {
        arr ?: return emptyList()
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
     * Record a user TRUST decision for a (package, domain) pairing:
     * web-saved logins for the domain may then fill inside that app.
     */
    suspend fun trustApp(packageName: String, domain: String) {
        vault?.takeIf { it.isUnlocked() }?.let {
            runCatching { it.autofillAppTrust(packageName, domain) }
        }
    }

    /** Record a user REJECTION: the picker never suggests the pairing again. */
    suspend fun rejectApp(packageName: String, domain: String) {
        vault?.takeIf { it.isUnlocked() }?.let {
            runCatching { it.autofillAppReject(packageName, domain) }
        }
    }

    /**
     * Full credential for a matched id: (username, password). Fetched only
     * here, only for entries about to be offered as datasets; passwords are
     * never kept beyond the returned pair. Reprompt-protected entries are
     * never autofilled (G18): the flag means every reveal demands the
     * master password, which a background autofill flow cannot ask for.
     */
    suspend fun credential(id: String): Pair<String?, String?>? {
        val v = vault?.takeIf { it.isUnlocked() } ?: return null
        val raw = runCatching { v.getCipher(id, true) }.getOrNull() ?: return null
        val o = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val reprompt = o.opt("reprompt")
        if (reprompt == true || reprompt == "true") return null
        val username = o.opt("username") as? String
        val password = o.opt("password") as? String
        return username to password
    }

    /**
     * All active login entries (id/name/username/favorite) regardless of any
     * target - used by the manual-pick fallback picker (plan: go-to-vault
     * parity). Passwords are never in the output.
     */
    suspend fun logins(): List<Match> {
        val v = vault?.takeIf { it.isUnlocked() } ?: return emptyList()
        val metas = runCatching { v.listCiphers() }.getOrDefault(emptyList())
        return metas.filter { it.cipherType == "login" }.map {
            Match(id = it.id, name = it.name, username = it.username, favorite = it.favorite)
        }
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
