package xyz.actitud.baluard.auth

import xyz.actitud.baluard.data.AuthState
import xyz.actitud.baluard.data.UnlockResult
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.MobileVault

/**
 * Drives the unlock flow. Holds the current [AuthState] and exposes
 * [unlock] / [lock] to the UI.
 *
 * Phase 2: master-password unlock only. Biometric quick-unlock (KEK path,
 * plan §3.2) is added when the platform glue lands — it calls a separate
 * repository path that skips the Argon2id KDF.
 *
 * Concurrency: unlock is a suspend fn (UniFFI async -> Kotlin suspend). The
 * caller (UnlockScreen) launches it in a coroutine scope off the UI thread;
 * the Argon2id KDF runs on the parked shared tokio Runtime under the hood.
 */
class AuthViewModel(private val repo: VaultRepository) {
    private var vault: MobileVault? = null

    /**
     * KEK retained from the most recent biometric quick-unlock. Lets the
     * Settings screen re-enroll (disable -> re-enable) without ever asking
     * for the master password again. Null after a password unlock (the KEK
     * never materializes on that path) and on lock.
     */
    var sessionKek: ByteArray? = null
        private set

    /**
     * Open a local vault directory and attempt to unlock it with [password].
     * On success, holds the unlocked [MobileVault] for subsequent cipher ops.
     */
    suspend fun openAndUnlock(path: String, password: String): UnlockResult {
        return try {
            val v = repo.openVault(path)
            v.unlock(password)
            vault = v
            UnlockResult.Success
        } catch (e: Exception) {
            UnlockResult.Failure(e.message ?: "unlock failed")
        }
    }

    /**
     * Biometric quick-unlock (B5, plan §3.7): skip the Argon2id KDF, feed
     * the keychain-retrieved [kek] straight into the shared unlock tail
     * (still verifies keywrap + canaries, so a stale KEK fails closed).
     */
    suspend fun openAndUnlockWithKek(path: String, kek: ByteArray): UnlockResult {
        return try {
            val v = repo.openVault(path)
            v.unlockWithKek(kek)
            vault = v
            sessionKek = kek
            UnlockResult.Success
        } catch (e: Exception) {
            UnlockResult.Failure(e.message ?: "unlock failed")
        }
    }

    /** Argon2id KEK for biometric enroll (main-app only; see repository). */
    suspend fun deriveKek(path: String, password: String): ByteArray =
        repo.deriveKek(path, password)

    /** Lock the currently-open vault (zeroizes in-memory keys). */
    suspend fun lock(): Boolean {
        val v = vault ?: return false
        return try {
            v.lock()
            sessionKek = null
            true
        } catch (e: Exception) {
            false
        }
    }

    /** The unlocked vault, or null if not yet unlocked. */
    fun vault(): MobileVault? = vault

    /**
     * Adopt a vault handle produced outside [openAndUnlock]: the onboarding
     * create flow (plan §5.5) and the recovery-phrase enroll flow (§5.4).
     * The handle arrives already unlocked from the FFI.
     */
    fun adopt(v: MobileVault) {
        vault = v
    }

    /** Whether the open vault currently holds an unlocked handle. */
    suspend fun isUnlocked(): Boolean = vault?.isUnlocked() ?: false
}
