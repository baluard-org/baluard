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

    /** Lock the currently-open vault (zeroizes in-memory keys). */
    suspend fun lock(): Boolean {
        val v = vault ?: return false
        return try {
            v.lock()
            true
        } catch (e: Exception) {
            false
        }
    }

    /** The unlocked vault, or null if not yet unlocked. */
    fun vault(): MobileVault? = vault

    /** Whether the open vault currently holds an unlocked handle. */
    suspend fun isUnlocked(): Boolean = vault?.isUnlocked() ?: false
}
