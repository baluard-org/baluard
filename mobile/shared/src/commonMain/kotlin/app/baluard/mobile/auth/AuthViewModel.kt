package app.baluard.mobile.auth

import app.baluard.mobile.data.UnlockResult
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.BaluardException
import app.baluard.mobile.MobileVault
import app.baluard.mobile.monetization.Entitlements
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import app.baluard.mobile.platform.withSecurityKeyTransport
/**
 * Drives the unlock flow over the multi-Space session (ADR 0087 S4-9):
 * up to [MultiVaultSession.MAX_UNLOCKED] vaults stay unlocked at once, so
 * switching Spaces does not re-run the unlock ceremony. The unlock screens own
 * the AuthState UI state machine; this class holds no UI state.
 *
 * Concurrency: unlock is a suspend fn (UniFFI async -> Kotlin suspend). The
 * caller (UnlockScreen) launches it in a coroutine scope off the UI thread;
 * the Argon2id KDF runs on the parked shared tokio Runtime under the hood.
 * The KDF stays user-serialized — one password prompt runs one KDF.
 */
class AuthViewModel(private val repo: VaultRepository) {

    /** ADR 0102: apply the entitlement to every session's unlock-tail sync switch. */
    suspend fun applyAutosyncPolicy(allowed: Boolean) = session.applyAutosyncPolicy(allowed)

    /**
     * G24 §4.9 merged app-search source: every OTHER still-unlocked session
     * whose vault passes the merge-eligibility sniff. (path, name, handle).
     */
    suspend fun mergeSearchSessions(excludePath: String): List<Triple<String, String, MobileVault>> {
        val out = ArrayList<Triple<String, String, MobileVault>>()
        for (path in session.unlockedPaths()) {
            if (path == excludePath) continue
            if (!app.baluard.mobile.platform.VaultRegistry.isMergeEligible(path)) continue
            val vault = session.vaultFor(path) ?: continue
            val name = app.baluard.mobile.platform.VaultRegistry.listVaults()
                .firstOrNull { it.path == path }?.name ?: path
            out.add(Triple(path, name, vault))
        }
        return out
    }
    // Process-wide store: the main-process passkey provider service reads
    // the same unlocked handles (SharedVaultSession doc).
    private val session = SharedVaultSession.multi

    /**
     * KEK retained from the most recent biometric quick-unlock of the ACTIVE
     * vault. Lets the Settings screen re-enroll (disable -> re-enable) without
     * ever asking for the master password again. Returns a COPY: the session
     * wipes its own array on lock/evict, and a wipe must never reach into a
     * caller's in-flight use (a biometric re-enroll mid-prompt would otherwise
     * encrypt zeros). Null after a password unlock (the KEK never materializes
     * on that path) and on lock.
     */
    val sessionKek: ByteArray?
        get() = session.activeEntry()?.kek?.copyOf()

    /**
     * Open a local vault directory and attempt to unlock it with [password].
     * A cached, still-unlocked session for [path] adopts with no unlock
     * ceremony at all (the multi-Space fast path). On a fresh unlock, the
     * handle joins the session (LRU-evicting the oldest beyond the bound).
     */
    suspend fun openAndUnlock(path: String, password: String): UnlockResult {
        return try {
            val v = repo.openVault(path)
            // ADR 0102: set the unlock-tail sync switch BEFORE unlocking so a
            // locked entitlement never activates sync for a vault with a remote.
            runCatching { v.setAutosyncAllowed(Entitlements.current().syncUnlocked) }
            if (requiresSecurityKey(v)) {
                withSecurityKeyTransport { v.unlockWithSecurityKey(password, it) }
            } else {
                v.unlock(password)
            }
            session.adopt(path, MobileSessionVault(v), kek = null)
            UnlockResult.Success
        } catch (e: BaluardException.DeviceUnpaired) {
            UnlockResult.DeviceMismatch
        } catch (e: Exception) {
            classifyUnlockError(e)
        }
    }

    suspend fun requiresSecurityKey(path: String): Boolean = runCatching {
        requiresSecurityKey(repo.openVault(path))
    }.getOrDefault(false)

    private suspend fun requiresSecurityKey(vault: MobileVault): Boolean = runCatching {
        val status = Json.parseToJsonElement(
            vault.hardwareStatus(app.baluard.mobile.platform.securityKeysSupported()),
        ).jsonObject
        status["enabled"]?.jsonPrimitive?.booleanOrNull == true
    }.getOrDefault(false)

    /**
     * Biometric quick-unlock (B5, plan §3.7): skip the Argon2id KDF, feed
     * the keychain-retrieved [kek] straight into the shared unlock tail
     * (still verifies keywrap + canaries, so a stale KEK fails closed).
     */
    suspend fun openAndUnlockWithKek(path: String, kek: ByteArray): UnlockResult {
        return try {
            val v = repo.openVault(path)
            if (requiresSecurityKey(v)) {
                withSecurityKeyTransport { v.unlockWithSecurityKeyAndKek(kek, it) }
            } else {
                v.unlockWithKek(kek)
            }
            session.adopt(path, MobileSessionVault(v), kek = kek)
            UnlockResult.Success
        } catch (e: BaluardException.DeviceUnpaired) {
            UnlockResult.DeviceMismatch
        } catch (e: Exception) {
            classifyUnlockError(e)
        }
    }

    /** Argon2id KEK for biometric enroll (main-app only; see repository). */
    suspend fun deriveKek(path: String, password: String): ByteArray =
        repo.deriveKek(path, password)

    /**
     * Multi-Space fast path: true when [path] already sits unlocked in the
     * session — the vault switcher skips the lock screen entirely.
     */
    suspend fun switchTo(path: String): Boolean = session.switchTo(path)

    /** Lock the active vault (zeroizes in-memory keys, frees its slot). */
    suspend fun lock(): Boolean = session.lockActive()

    /**
     * Lock every cached session EXCEPT the active one (the app-shell calls
     * this on background — the desktop lock-all-on-blur twin): a cached vault
     * has no timer enforcement while inactive, so it must not ride out a
     * background stretch unlocked.
     */
    suspend fun lockInactiveSessions(): Int = session.lockInactive()

    /**
     * Enforce every session's own vault timeout (the desktop walker's
     * replacement): the app shell calls this on its auto-lock poll so an
     * expired cached vault is locked even before anyone tries to switch to
     * it.
     */
    suspend fun enforceAutoLock(): Int = session.enforceAutoLock()

    /**
     * Drop the active vault's session: lock + wipe its KEK + free the slot
     * (vault switch-away, vault removed).
     */
    suspend fun forget() {
        session.forgetActive()
    }

    /**
     * Drop ONE vault's session by path (vault detached from the switcher):
     * lock + wipe its KEK + free the slot. No-op when the vault has no
     * cached session.
     */
    suspend fun forgetSession(path: String) {
        session.forget(path)
    }

    /** The active vault's handle, or null if nothing is unlocked. */
    fun vault(): MobileVault? = session.activeEntry()?.vault?.mobile

    /**
     * Adopt a vault handle produced outside [openAndUnlock]: the onboarding
     * create flow (plan §5.5), the provider/enroll flow, and the
     * recovery-phrase enroll flow (§5.4). The handle arrives already unlocked
     * from the FFI.
     */
    suspend fun adopt(path: String, v: MobileVault) {
        session.adopt(path, MobileSessionVault(v), kek = null)
    }

}

/**
 * UniFFI supplies the outcome type. Only its detail text is mapped to
 * localized copy; unrelated errors never become security-key failures.
 */
internal fun classifyUnlockError(e: Throwable): UnlockResult = when (e) {
    is app.baluard.mobile.BaluardException.WrongPassword -> UnlockResult.WrongPassword
    is app.baluard.mobile.BaluardException.SecurityKey -> UnlockResult.SecurityKey(
        app.baluard.mobile.platform.securityKeyErrorMessage(e),
    )
    else -> UnlockResult.Failure(app.baluard.mobile.i18n.t("login.unlockFailed"))
}
