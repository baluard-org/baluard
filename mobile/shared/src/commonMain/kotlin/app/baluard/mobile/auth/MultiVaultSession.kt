package app.baluard.mobile.auth

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import app.baluard.mobile.MobileVault

/**
 * A vault handle the session can lock and interrogate. Exists so the LRU
 * bookkeeping is testable in commonTest without a real FFI vault — production
 * wraps [MobileVault].
 */
interface SessionVault {
    /** The real FFI handle, or null for test fakes. */
    val mobile: MobileVault?
    suspend fun isUnlocked(): Boolean
    suspend fun shouldAutoLock(): Boolean
    suspend fun lock()
}

/** Production adapter over the uniffi [MobileVault] handle. */
class MobileSessionVault(override val mobile: MobileVault) : SessionVault {
    override suspend fun isUnlocked(): Boolean = mobile.isUnlocked()
    override suspend fun shouldAutoLock(): Boolean = mobile.shouldAutoLock()
    override suspend fun lock() {
        mobile.lock()
    }
}

/** One unlocked vault inside the session: the handle plus its retained KEK. */
class SessionEntry internal constructor(
    val vault: SessionVault,
    internal val kek: ByteArray?,
)

/**
 * The mobile multi-Space host (ADR 0087 S4-9): keeps up to [max] vaults
 * unlocked at once so switching Spaces does not re-run the unlock ceremony.
 * Desktop parity — the desktop VaultHost has kept multiple vaults unlocked
 * since Phase 6; the phone was the last single-vault surface.
 *
 * OOM discipline (plan question 1): the bound IS the rule. Each unlocked vault
 * holds only resident keys (the runtime zeroizes on lock, so eviction reclaims
 * everything); the Argon2id KDF stays transient and user-serialized — never
 * two KDFs at once, and the :autofill process keeps its KEK-only path. A stale
 * cached handle (one that auto-locked itself while cached) self-heals: the
 * fast path checks [SessionVault.isUnlocked] before adopting, so an
 * auto-locked vault falls through to a normal unlock.
 *
 * Eviction is LRU by last use. An evicted vault's KEK is wiped before its slot
 * is reused; the dropped handle's keys are reclaimed by the runtime on its own
 * vault timeout, so eviction only hastens reclamation of the KEK secret.
 */
class MultiVaultSession(
    private val max: Int = MAX_UNLOCKED,
) : SessionStore {
    // Insertion-order, NOT access-order: a get() on an access-order map
    // rewires its linked list, and the credential-provider service reads
    // this map from a Binder thread. LRU order is maintained by re-inserting
    // on the mutation paths instead.
    private val sessions = LinkedHashMap<String, SessionEntry>()

    /**
     * ADR 0102: apply the entitlement to every session's unlock-tail sync
     * switch. [allowed] false stops any loop an entitled unlock started, so a
     * lapse lands without waiting for the next lock.
     */
    suspend fun applyAutosyncPolicy(allowed: Boolean) {
        for (entry in sessions.values) {
            val handle = entry.vault.mobile ?: continue
            runCatching { handle.setAutosyncAllowed(allowed) }
            // A Locked or Unknown cache at unlock leaves the coordinator
            // down even after refresh() flips the entitlement to unlocked;
            // arming here closes that hole for both unlock paths. The Rust
            // side refuses locked handles, so locked sessions no-op.
            if (allowed) runCatching { handle.activateAutosyncAfterRemote() }
        }
    }
    private val mapLock = Mutex()

    /** The active vault's handle, or null when nothing is unlocked. */
    override fun active(): SessionVault? = sessions.values.lastOrNull()?.vault

    /** The active entry (handle + KEK), or null. */
    fun activeEntry(): SessionEntry? = sessions.values.lastOrNull()

    /**
     * Adopt an already-unlocked handle (onboarding create, recovery enroll,
     * and the unlock flows). Replacing the same path locks and wipes the old
     * entry; LRU eviction beyond the bound LOCKS the evicted vault — the
     * Rust runtime has no background walker on mobile, so a merely-dropped
     * handle would keep its keys resident until process end.
     */
    override suspend fun adopt(path: String, vault: SessionVault, kek: ByteArray?) {
        mapLock.withLock {
            sessions.remove(path)?.let { old ->
                runCatching { old.vault.lock() }
                old.wipeKek()
            }
            sessions[path] = SessionEntry(vault, kek)
            evictBeyondBound(path)
        }
    }

    /**
     * Fast path: true when [path] already sits in the session AND is still
     * unlocked — it becomes the active vault with no unlock ceremony. A cached
     * vault that auto-locked returns false (the caller re-unlocks normally).
     */
    override suspend fun switchTo(path: String): Boolean {
        val entry = mapLock.withLock { touch(path) } ?: return false
        if (!entry.vault.isUnlocked()) {
            // Auto-locked while cached: drop the dead entry (wipe its KEK
            // like every other removal site); the caller runs the normal
            // unlock. Identity check + lock: an adopt landing during the
            // suspend must not have its fresh entry destroyed here.
            mapLock.withLock {
                if (sessions[path] === entry) {
                    sessions.remove(path)
                    entry.wipeKek()
                }
            }
            return false
        }
        return true
    }

    /** True when the path holds a live unlocked session. */
    suspend fun holds(path: String): Boolean =
        sessions[path]?.let { it.vault.isUnlocked() } == true

    /** G24 §4.9: paths of all still-unlocked sessions (merged search fan-out). */
    suspend fun unlockedPaths(): List<String> {
        // Snapshot before suspending: a concurrent adopt/lockOne would
        // otherwise mutate the map under a live fail-fast iterator.
        val paths = sessions.keys.toList()
        return paths.mapNotNull { path ->
            val e = sessions[path] ?: return@mapNotNull null
            if (e.vault.isUnlocked()) path else null
        }
    }

    /** The live FFI handle for [path], when its session is still unlocked. */
    suspend fun vaultFor(path: String): MobileVault? {
        val e = sessions[path] ?: return null
        if (!e.vault.isUnlocked()) return null
        return e.vault.mobile
    }

    /** Re-insert to the back = most recently used. Callers hold [mapLock]. */
    private fun touch(path: String): SessionEntry? {
        val entry = sessions.remove(path) ?: return null
        sessions[path] = entry
        return entry
    }

    override suspend fun lockActive(): Boolean {
        val last = sessions.keys.lastOrNull() ?: return false
        return lockOne(last)
    }

    override suspend fun lockAll(): Int {
        var n = 0
        for (key in sessions.keys.toList()) {
            if (lockOne(key)) n++
        }
        return n
    }

    /** Drop one vault's session: lock, wipe its KEK, forget the slot. */
    override suspend fun forget(path: String) {
        mapLock.withLock {
            sessions.remove(path)?.let { entry ->
                runCatching { entry.vault.lock() }
                entry.wipeKek()
            }
        }
    }

    /** Drop the active vault's session (the sign-out / removed-vault path). */
    suspend fun forgetActive() {
        val last = sessions.keys.lastOrNull() ?: return
        forget(last)
    }

    /**
     * Lock every session EXCEPT the active one. The app-shell rule (the
     * desktop lock-all-on-blur twin): only the vault on screen may ride out a
     * background stretch, governed by its own vault timeout; cached vaults
     * have no timer enforcement while inactive, so they lock on background.
     */
    suspend override fun lockInactive(): Int {
        var n = 0
        for (key in sessions.keys.toList().dropLast(1)) {
            if (lockOne(key)) n++
        }
        return n
    }

    /** Drop every session (vault removed, sign-out). */
    override suspend fun forgetAll() {
        for (key in sessions.keys.toList()) forget(key)
    }

    private suspend fun lockOne(path: String): Boolean {
        mapLock.withLock {
            val entry = sessions[path] ?: return false
            return try {
                // Lock BEFORE removing: the vault being locked stays the active
                // vault until the lock completes, so a mid-lock recomposition
                // never surfaces a different vault under this one's path.
                entry.vault.lock()
                sessions.remove(path)
                true
            } catch (_: Exception) {
                false
            } finally {
                entry.wipeKek()
            }
        }
    }

    /** Caller holds [mapLock]. */
    private suspend fun evictBeyondBound(keep: String) {
        while (sessions.size > max) {
            // Insertion order plus touch() re-insertion: the first key is
            // the least recently used. Never evict the just-touched active
            // path. Lock the evicted
            // vault: no background walker exists on mobile, so a dropped
            // handle would otherwise hold its keys until process end.
            val eldest = sessions.keys.firstOrNull { it != keep } ?: break
            sessions.remove(eldest)?.let { entry ->
                runCatching { entry.vault.lock() }
                entry.wipeKek()
            }
        }
    }

    /**
     * Enforce every session's own vault timeout — the mobile replacement for
     * the desktop daemon's 30s walker. The app shell polls the ACTIVE vault
     * with shouldAutoLock(); expired INACTIVE sessions are locked here so a
     * cached vault can never ride out its configured timeout unlocked.
     */
    override suspend fun enforceAutoLock(): Int {
        var n = 0
        for (key in sessions.keys.toList()) {
            val entry = sessions[key] ?: continue
            if (runCatching { entry.vault.shouldAutoLock() }.getOrDefault(false)) {
                if (lockOne(key)) n++
            }
        }
        return n
    }

    private fun SessionEntry.wipeKek() {
        kek?.fill(0)
    }

    companion object {
        /** Bounded unlocked set: enough for personal plus two Spaces, small
         * enough that resident keys stay trivial next to one Argon2id run. */
        const val MAX_UNLOCKED = 3
    }
}

/**
 * The session surface AuthViewModel and the app screens consume. Small enough
 * to fake wholesale in commonTest.
 */
interface SessionStore {
    fun active(): SessionVault?
    suspend fun adopt(path: String, vault: SessionVault, kek: ByteArray?)
    suspend fun switchTo(path: String): Boolean
    suspend fun lockActive(): Boolean
    suspend fun lockAll(): Int
    suspend fun lockInactive(): Int
    suspend fun enforceAutoLock(): Int
    suspend fun forget(path: String)
    suspend fun forgetAll()
}
