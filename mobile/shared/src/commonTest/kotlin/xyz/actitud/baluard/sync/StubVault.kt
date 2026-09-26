package xyz.actitud.baluard.sync

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileSyncStatus
import xyz.actitud.baluard.MobileVaultInterface

/**
 * In-memory [MobileVaultInterface] stub for commonTest. Every method records
 * the call; bodies error only if a test accidentally touches an unset field.
 */
open class StubVault(
    var pendingConflictJson: String = """{"pending":false}""",
    var resolveResultJson: String = """{"resolved":true,"remaining":0}""",
    var shouldLock: Boolean = false,
) : MobileVaultInterface {
    val calls = mutableListOf<String>()

    open override suspend fun getPendingConflictDetails(): String {
        calls += "getPendingConflictDetails"
        return pendingConflictJson
    }

    open override suspend fun resolveConflict(verdict: String): String {
        calls += "resolveConflict:$verdict"
        return resolveResultJson
    }

    override suspend fun resolveConflictKeepBoth(): String {
        calls += "resolveConflictKeepBoth"
        return resolveResultJson
    }

    override suspend fun autofillQuery(target: String): String {
        calls += "autofillQuery"
        return "[]"
    }

    override suspend fun autofillAppTrust(packageName: String, domain: String) {
        calls += "autofillAppTrust"
    }

    override suspend fun autofillAppReject(packageName: String, domain: String) {
        calls += "autofillAppReject"
    }

    override suspend fun shouldAutoLock(): Boolean {
        calls += "shouldAutoLock"
        return shouldLock
    }

    override suspend fun syncOnUnlock() { calls += "syncOnUnlock" }
    override suspend fun syncOnMutation() { calls += "syncOnMutation" }
    override suspend fun syncOnForeground() { calls += "syncOnForeground" }

    override suspend fun sshGenerateKey(keyType: String): String {
        calls += "sshGenerateKey:$keyType"
        return """{"public_key":"ssh-ed25519 AAAA","fingerprint":"SHA256:test","private_key":"-----BEGIN"}"""
    }

    override suspend fun fetchFavicon(payload: String): String {
        calls += "fetchFavicon:$payload"
        return ""
    }
    override suspend fun syncOnBackground() { calls += "syncOnBackground" }
    override suspend fun syncPullNow() { calls += "syncPullNow" }
    override suspend fun syncOfflineTick() { calls += "syncOfflineTick" }
    override suspend fun archiveCipher(id: String) { calls += "archiveCipher" }
    override suspend fun unarchiveCipher(id: String) { calls += "unarchiveCipher" }
    override suspend fun restoreCipher(id: String) { calls += "restoreCipher" }
    override suspend fun deviceId(): String = "stub-device"
    override suspend fun listArchivedCiphers(): List<MobileCipherMeta> = err()
    override suspend fun listTotpCiphers(): List<MobileCipherMeta> = err()
    override suspend fun listTrashCiphers(): List<MobileCipherMeta> = err()
    override suspend fun syncStatus(): MobileSyncStatus {
        calls += "syncStatus"
        return MobileSyncStatus(active = true, state = "idle", lastSync = null, pending = 0u)
    }

    // ── Unused by these tests: fail loudly if reached. ──────────────────────
    override suspend fun addCipher(payload: String): String = err()
    override suspend fun createFolder(payload: String): String = err()
    override suspend fun createTag(name: String): String = err()
    override suspend fun deleteCipher(id: String) = err()
    override suspend fun deleteFolder(id: String) = err()
    override suspend fun deleteTag(name: String): String = err()
    override suspend fun deviceName(): String = err()
    override suspend fun generatorHistoryAdd(payload: String): String = err()
    override suspend fun generatorHistoryClear() = err()
    override suspend fun generatorHistoryList(): String = err()
    override suspend fun getCipher(id: String, decrypt: Boolean): String = err()
    override suspend fun getSettings(): String = err()
    override suspend fun isUnlocked(): Boolean = err()
    override suspend fun listCiphers(): List<MobileCipherMeta> = err()
    override suspend fun listFolders(): String = err()
    override suspend fun listTags(): String = err()
    override suspend fun lock() = err()
    override suspend fun renameFolder(payload: String) = err()
    override suspend fun setSettings(payload: String) = err()
    override suspend fun totpCode(id: String): String = err()
    override suspend fun unlock(masterPassword: String) = err()
    override suspend fun unlockWithKek(kek: ByteArray) = err()
    override suspend fun updateCipher(payload: String) = err()
    override suspend fun vaultId(): String = err()

    private fun err(): Nothing = error("StubVault: unexpected call")
    // §4.8-6 sharing surfaces: the stubs never exercise them; bodies
    // mirror the err() discipline so an accidental touch fails loudly.
    override suspend fun `collectionCatalogList`(): String = err()
    // §4.8-7 admin surfaces: same err() discipline.
    override suspend fun `collectionGrant`(payload: String): String = err()
    override suspend fun `collectionRevoke`(payload: String): String = err()
    override suspend fun `joinRequestsApprove`(payload: String): String = err()
    override suspend fun `joinRequestsDeny`(payload: String): String = err()
    override suspend fun `joinRequestsList`(): String = err()
    override suspend fun `memberInvite`(payload: String): String = err()
    override suspend fun `membersList`(): String = err()
    override suspend fun `collectionRequestAccess`(payload: String): String = err()
    override suspend fun `collectionRequestsApprove`(payload: String): String = err()
    override suspend fun `collectionRequestsDeny`(payload: String): String = err()
    override suspend fun `collectionRequestsList`(): String = err()
    override suspend fun `collectionRequestsMine`(): String = err()
    override suspend fun `collectionRequestsWithdraw`(payload: String): String = err()
    override suspend fun `collectionsList`(): String = err()
    override suspend fun `joinIntroduce`(code: String, password: String, deviceName: String): String = err()
    override suspend fun `joinPoll`(): String = err()
}
