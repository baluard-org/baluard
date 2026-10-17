package xyz.actitud.baluard.sync

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileCatalogInput
import xyz.actitud.baluard.MobileSyncStatus
import xyz.actitud.baluard.MobileProvider
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
    override suspend fun setCollection(cipherId: String, collectionId: String?) = err()
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
    override suspend fun `joinRequestsStage`(payload: String): String = err()
    override suspend fun `joinRequestsApprove`(payload: String): String = err()
    override suspend fun `joinRequestsDeny`(payload: String): String = err()
    override suspend fun `joinRequestsList`(): String = err()
    override suspend fun `memberInvite`(payload: String): String = err()
    override suspend fun `membersList`(): String = err()
    // §4.8-8 offboarding surfaces: same err() discipline.
    override suspend fun `memberReset`(memberId: String): String = err()
    override suspend fun `memberTransfer`(memberId: String): String = err()
    override suspend fun `memberClaim`(memberId: String): String = err()
    override suspend fun `memberRemove`(memberIds: List<String>, offlineOverride: Boolean): String = err()
    override suspend fun `memberLeaveFile`(): String = err()
    override suspend fun `memberSetRole`(`memberId`: kotlin.String, `role`: kotlin.String): String = err()
    override suspend fun `contactsList`(): String = err()
    override suspend fun `myContactCard`(): String = err()
    override suspend fun `contactImportCard`(card: kotlin.String): String = err()
    override suspend fun `contactMarkVerified`(pubkey: kotlin.String): String = err()
    override suspend fun `contactRemove`(pubkey: kotlin.String): String = err()
    override suspend fun `memberLeaveList`(): String = err()
    override suspend fun `memberLeaveApprove`(memberId: String, offlineOverride: Boolean): String = err()
    // §4.8-9 collection CRUD: same err() discipline.
    override suspend fun `collectionCreate`(name: String): String = err()
    override suspend fun `collectionRename`(id: String, name: String): String = err()
    override suspend fun `collectionDelete`(id: String): String = err()
    override suspend fun `collectionCatalogSet`(entries: List<MobileCatalogInput>): String = err()
    override suspend fun `isAdminDevice`(): Boolean = err()
override suspend fun `myRole`(): String = err()
    override suspend fun `noticesList`(`refreshTransport`: Boolean): String = err()
    override suspend fun `activityEvents`(`limit`: ULong): String = err()
    override suspend fun `activityRefusals`(`limit`: ULong): String = err()
    override suspend fun `spaceSettingsGet`(): String = err()
    override suspend fun `spaceSettingsSet`(
        `inviteAuthority`: String?,
        `allowViewerExport`: Boolean?,
        `guestEnabled`: Boolean?,
        `trashPolicy`: String?,
        `joinApproval`: String?,
        `quorumAdminOps`: ULong?,
        `collectionCreateAuthority`: String?,
    ): Unit = err()
    override suspend fun `approvalsList`(): String = err()
    override suspend fun `policiesList`(): String = err()
    override suspend fun `spaceStatus`(): String = err()
    override suspend fun `spacePrepare`(): String = err()
    override suspend fun `spaceFlip`(): String = err()
    override suspend fun `collectionRequestAccess`(payload: String): String = err()
    override suspend fun `collectionRequestsApprove`(payload: String): String = err()
    override suspend fun `collectionRequestsDeny`(payload: String): String = err()
    override suspend fun `collectionRequestsList`(): String = err()
    override suspend fun `collectionRequestsMine`(): String = err()
    override suspend fun `collectionRequestsWithdraw`(payload: String): String = err()
    override suspend fun `collectionsList`(): String = err()
    override suspend fun `joinIntroduce`(code: String, password: String, deviceName: String, email: String?): String = err()
    override suspend fun `joinPoll`(): String = err()

    // G2/G18 surfaces: the stub's tests never touch these; error on
    // accidental use like every other unset method.
    override suspend fun `importData`(format: String, data: ByteArray): String = err()
    override suspend fun `exportData`(format: String): String = err()
    override suspend fun `exportEncryptedBackup`(passphrase: String): xyz.actitud.baluard.EncryptedBackup = err()
    override suspend fun `importEncryptedBackup`(passphrase: String, container: kotlin.ByteArray): String = err()
    override suspend fun `repromptVerify`(masterPassword: String): ULong = err()
    override suspend fun `importSharedPackage`(packageB64: String): String = err()
    override suspend fun `openSharedContact`(revealB64: String): String = err()
    override suspend fun `exportGuestReveal`(cipherId: String, expiresAt: ULong, includeTotp: Boolean): String = err()
    override suspend fun `rotateRecoveryPhrase`(oldPassword: String): String = err()
    // G13/G19/G21: groups, health, avatar — never exercised by stubs.
    override suspend fun `groupsList`(): String = err()
    override suspend fun `groupCreate`(payload: String): String = err()
    override suspend fun `groupRename`(payload: String): String = err()
    override suspend fun `groupDelete`(payload: String): String = err()
    override suspend fun `groupMemberAdd`(payload: String): String = err()
    override suspend fun `groupMemberRemove`(payload: String): String = err()
    override suspend fun `healthReport`(): String = err()
    override suspend fun `avatarGet`(): String = err()
    override suspend fun `avatarSet`(payload: String) = err()

    // G16: provider sync setup — the stub never exercises it.
    override suspend fun `setupSync`(
        provider: MobileProvider,
        repoName: String,
        cloneUrl: String?,
    ): String = err()
    override suspend fun `devicesList`(): String = err()
    override suspend fun `deviceRevoke`(deviceId: String): String = err()
    override suspend fun `spaceKitStatus`(): String = err()
    override suspend fun `spaceKitEnable`(): String = err()
    override suspend fun `spaceKitDisable`(): String = err()
}
