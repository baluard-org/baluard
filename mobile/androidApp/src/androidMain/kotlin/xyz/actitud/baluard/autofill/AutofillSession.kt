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
 * Autofill-side vault sessions (plan D6, merged per plan-merged-search §4.8):
 * ONE opened [MobileVault] handle PER discovered vault, living in the
 * `:autofill` process and shared by [BaluardAutofillService] and
 * [AutofillActivity] (both declared `android:process=":autofill"`, so the
 * Kotlin object is genuinely process-singleton). Opening a handle is
 * keyless; only [unlock] ever touches key material, and it only ever
 * receives the biometric-gated KEK (unwrapped by BiometricPrompt inside
 * [AutofillActivity]). The master-password KDF never runs in this process.
 *
 * Merge rule: a fill query fans out over UNLOCKED handles only. A locked
 * vault contributes nothing until its per-vault biometric prompt succeeds -
 * sequential and explicit by design. App-trust decisions stay scoped to the
 * vault whose suggestion was confirmed.
 *
 * Auto-lock: there is no background walker here; every fill request calls
 * [lockIfExpired], which consults each handle's `should_auto_lock` (the
 * vault's own timeout policy). Process death = fail secure by design.
 */
object AutofillSession {

    data class Match(
        val id: String,
        val name: String,
        val username: String?,
        val favorite: Boolean,
        /** Owning vault (merged surfaces only; null = active-vault legacy). */
        val vaultPath: String? = null,
        val vaultName: String? = null,
    )

    /** Path-B app-to-web suggestion: an untrusted candidate domain and
     *  the entries that would match it after the user trusts the pairing.
     *  Trust decisions are per-vault, so the suggestion carries its owner. */
    data class AppSuggestion(
        val domain: String,
        val matches: List<Match>,
        val vaultPath: String? = null,
    )

    data class QueryResult(
        val matches: List<Match>,
        val suggestions: List<AppSuggestion>,
    )

    /** Open (keyless) handles by vault directory path. */
    private val handles = LinkedHashMap<String, MobileVault>()

    /** The last-active vault path: the default biometric unlock target. */
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
     * Open every discovered vault (keyless) and refresh the active path.
     * Returns whether ANY handle is unlocked. Handles for vaults that were
     * deleted or detached are locked and dropped; a vault switched to active
     * in the main app is honored on the next call.
     */
    suspend fun ensureOpen(): Boolean = mutationMutex.withLock {
        val active = VaultRegistry.loadActiveVault()
        activePath = active
        val discovered = VaultRegistry.listVaults()
        val paths = discovered.map { it.path }.toSet()
        // Prune handles whose directory vanished (detach/delete).
        for ((path, handle) in handles) {
            if (path !in paths) runCatching { handle.lock() }
        }
        handles.keys.retainAll(paths)
        for (v in discovered) {
            if (v.path !in handles) {
                handles[v.path] = runCatching { openVault(v.path) }.getOrNull() ?: continue
            }
        }
        handles.values.any { it.isUnlocked() }
    }

    /** Lock every handle whose own timeout policy says so. Cheap, per request. */
    suspend fun lockIfExpired() {
        for ((path, v) in snapshotHandles()) {
            if (v.isUnlocked() && v.shouldAutoLock()) lockOne(path)
        }
    }

    /**
     * Unlock the ACTIVE vault with the biometric-gated KEK. Returns false on
     * any failure (stale KEK after a password change fails closed in the
     * runtime). The KEK is zeroized before return regardless of outcome
     * (review finding #8): JVM heap is GC-managed, but we still shrink the
     * exposure window.
     */
    suspend fun unlock(kek: ByteArray): Boolean = mutationMutex.withLock {
        val path = activePath ?: return@withLock false
        try {
            unlockLocked(path, kek)
        } finally {
            kek.fill(0)
        }
    }

    /**
     * Unlock one explicit vault (per-vault auth datasets, plan-merged-search
     * §4.8): the activity passes the dataset's vault path. Same KEK rules as
     * [unlock].
     */
    suspend fun unlockPath(path: String, kek: ByteArray): Boolean = mutationMutex.withLock {
        try {
            unlockLocked(path, kek)
        } finally {
            kek.fill(0)
        }
    }

    /** Body under [mutationMutex]; zeroizing stays with the public callers. */
    private suspend fun unlockLocked(path: String, kek: ByteArray): Boolean {
        val v = handles[path] ?: runCatching { openVault(path) }.getOrNull() ?: return false
        handles[path] = v
        runCatching { v.unlockWithKek(kek) }.getOrElse { return false }
        return v.isUnlocked()
    }

    /** Lock and drop everything (process-wide reset). */
    suspend fun lock() = mutationMutex.withLock {
        for (v in handles.values) runCatching { v.lock() }
        handles.clear()
        activePath = null
    }

    private suspend fun lockOne(path: String) = mutationMutex.withLock {
        handles.remove(path)?.let { runCatching { it.lock() } }
    }

    /** Copy under [mutationMutex]: queries iterate the copy so a concurrent
     *  ensureOpen/lockOne prune can never throw ConcurrentModificationException
     *  mid-traversal. The FFI calls afterwards run UNLOCKED by design. */
    private suspend fun snapshotHandles(): Map<String, MobileVault> =
        mutationMutex.withLock { HashMap(handles) }

    /**
     * Opened-but-locked vaults (path, display name) for the per-vault unlock
     * datasets (plan-merged-search §4.8): each gets its own biometric
     * prompt, sequential and explicit.
     */
    suspend fun lockedVaults(): List<Pair<String, String>> = mutationMutex.withLock {
        handles.mapNotNull { (path, v) ->
            if (!v.isUnlocked()) Pair(path, nameFor(path) ?: path) else null
        }
    }

    /** Unlocked check for one handle without exposing the map. */
    private suspend fun isUnlocked(path: String): Boolean {
        val v = handles[path] ?: return false
        return v.isUnlocked()
    }

    /**
     * Query matching logins for a fill target across every UNLOCKED vault.
     * Output NEVER contains passwords (plan D2); the runtime enforces the
     * shape, this parser only reads id/name/username/favorite. Each match is
     * tagged with its owning vault so dataset labels and credential reads
     * can route to the right handle.
     */
    suspend fun matches(target: String): List<Match> = query(target).matches

    /**
     * Full query result: direct/trusted matches plus the path-B app-to-web
     * suggestions (untrusted domain candidates with candidate entries),
     * merged over unlocked vaults. Suggestions are empty unless the VAULT's
     * own setting is on and the target is `androidapp://` - the trust lists
     * stay per-vault, so a pairing trusted in one vault re-prompts in
     * another (plan §4.8).
     */
    suspend fun query(target: String): QueryResult {
        val matches = ArrayList<Match>()
        val suggestions = ArrayList<AppSuggestion>()
        for ((path, v) in snapshotHandles()) {
            if (!v.isUnlocked()) continue
            val raw = runCatching { v.autofillQuery(target) }.getOrNull() ?: continue
            val obj = runCatching { JSONObject(raw) }.getOrNull() ?: continue
            val vaultName = nameFor(path)
            matches.addAll(
                parseMatches(obj.optJSONArray("matches")).map {
                    it.copy(vaultPath = path, vaultName = vaultName)
                },
            )
            val arr = obj.optJSONArray("app_suggestions") ?: JSONArray()
            for (i in 0 until arr.length()) {
                val s = arr.optJSONObject(i) ?: continue
                suggestions.add(
                    AppSuggestion(
                        domain = s.optString("domain"),
                        matches = parseMatches(s.optJSONArray("matches")).map {
                            it.copy(vaultPath = path, vaultName = vaultName)
                        },
                        vaultPath = path,
                    ),
                )
            }
        }
        return QueryResult(matches, suggestions)
    }

    private fun nameFor(path: String): String? =
        VaultRegistry.listVaults().firstOrNull { it.path == path }?.name

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
     * Record a user TRUST decision for a (package, domain) pairing in the
     * vault that owned the suggestion: web-saved logins for the domain may
     * then fill inside that app - in THAT vault only.
     */
    suspend fun trustApp(packageName: String, domain: String, vaultPath: String? = null) {
        val target = vaultPath ?: activePath ?: return
        handles[target]?.takeIf { it.isUnlocked() }?.let {
            runCatching { it.autofillAppTrust(packageName, domain) }
        }
    }

    /** Record a user REJECTION: the picker never suggests the pairing again. */
    suspend fun rejectApp(packageName: String, domain: String, vaultPath: String? = null) {
        val target = vaultPath ?: activePath ?: return
        handles[target]?.takeIf { it.isUnlocked() }?.let {
            runCatching { it.autofillAppReject(packageName, domain) }
        }
    }

    /**
     * Full credential for a matched id from its OWNING vault:
     * (username, password). Fetched only here, only for entries about to be
     * offered as datasets; passwords are never kept beyond the returned
     * pair. Reprompt-protected entries are never autofilled (G18): the flag
     * means every reveal demands the master password, which a background
     * autofill flow cannot ask for.
     */
    suspend fun credential(vaultPath: String?, id: String): Pair<String?, String?>? {
        val v = resolve(vaultPath) ?: return null
        val raw = runCatching { v.getCipher(id, true) }.getOrNull() ?: return null
        val o = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val reprompt = o.opt("reprompt")
        if (reprompt == true || reprompt == "true") return null
        val username = o.opt("username") as? String
        val password = o.opt("password") as? String
        return username to password
    }

    /**
     * All active login entries (id/name/username/favorite) across unlocked
     * vaults regardless of any target - used by the manual-pick fallback
     * picker (plan: go-to-vault parity). Passwords are never in the output.
     */
    suspend fun logins(): List<Match> {
        val out = ArrayList<Match>()
        for ((path, v) in snapshotHandles()) {
            if (!v.isUnlocked()) continue
            val metas = runCatching { v.listCiphers() }.getOrDefault(emptyList())
            val vaultName = nameFor(path)
            out.addAll(
                metas.filter { it.cipherType == "login" }.map {
                    Match(
                        id = it.id,
                        name = it.name,
                        username = it.username,
                        favorite = it.favorite,
                        vaultPath = path,
                        vaultName = vaultName,
                    )
                },
            )
        }
        return out
    }

    /**
     * Derived TOTP code for a cipher from its owning vault (6 digits), or
     * null when the entry has no seed or the vault is locked. Only the
     * derived code crosses the FFI; the seed never does (same invariant as
     * the desktop).
     */
    suspend fun totpCode(vaultPath: String?, id: String): String? {
        val v = resolve(vaultPath) ?: return null
        val raw = runCatching { v.totpCode(id) }.getOrNull() ?: return null
        val code = runCatching { JSONObject(raw).optString("code") }.getOrNull()
        return code?.takeIf { it.isNotEmpty() }
    }

    private suspend fun resolve(vaultPath: String?): MobileVault? {
        val path = vaultPath ?: activePath ?: return null
        val v = mutationMutex.withLock { handles[path] } ?: return null
        return v.takeIf { it.isUnlocked() }
    }
}
