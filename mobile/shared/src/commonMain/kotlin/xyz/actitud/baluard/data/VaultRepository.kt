package xyz.actitud.baluard.data

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileCreateResult
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.generateRecoveryPhrase
import xyz.actitud.baluard.MobileRecoveryPhrase
import xyz.actitud.baluard.openVault as uniffiOpenVault
import xyz.actitud.baluard.createVault as uniffiCreateVault
import xyz.actitud.baluard.createVaultWithRecovery as uniffiCreateVaultWithRecovery
import xyz.actitud.baluard.MobileCloneJob
import xyz.actitud.baluard.MobileDeviceFlow
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.MobileProviderConfig
import xyz.actitud.baluard.MobileRepo
import xyz.actitud.baluard.cloneVaultStart as uniffiCloneVaultStart
import xyz.actitud.baluard.connectPat as uniffiConnectPat
import xyz.actitud.baluard.enrollDeviceWithPhrase as uniffiEnrollDeviceWithPhrase
import xyz.actitud.baluard.listVaultRepos as uniffiListVaultRepos
import xyz.actitud.baluard.startDeviceFlow as uniffiStartDeviceFlow

/**
 * Thin wrapper over the UniFFI-generated Kotlin bindings.
 *
 * Exposes the vault lifecycle (Phase 2) + cipher CRUD (Phase 3-4) + generator
 * (Phase 4 prereq). The generated binding functions are top-level Kotlin fns
 * produced by uniffi-bindgen from the Rust `#[uniffi::export]` decls; they land
 * in package `xyz.actitud.baluard` (set in uniffi.toml). Aliased on import to
 * avoid clashing with the repository method names.
 *
 * All vault/cipher ops are `suspend` (UniFFI async -> Kotlin suspend); the
 * Argon2id KDF and git ops run on the parked shared tokio Runtime off the UI
 * thread (plan §3.3).
 */
/** Minimal folder projection for the list filter (from `vault.list_folders` JSON). */
data class MobileFolderInfo(
    val id: String,
    val name: String,
)

class VaultRepository {
    fun generateRecoveryPhrase(): MobileRecoveryPhrase = generateRecoveryPhrase()

    suspend fun generatePassword(config: xyz.actitud.baluard.PasswordConfig): Result<String> =
        runCatching { xyz.actitud.baluard.generatePassword(config) }

    suspend fun generatePassphrase(config: xyz.actitud.baluard.PassphraseConfig): Result<String> =
        runCatching { xyz.actitud.baluard.generatePassphrase(config) }

    suspend fun openVault(path: String): MobileVault = uniffiOpenVault(path)
    suspend fun createVault(path: String, password: String, deviceName: String): MobileVault =
        uniffiCreateVault(path, password, deviceName)

    /**
     * Create a vault AND surface its 24-word recovery phrase (plan §3.5). The
     * phrase is HPKE-wrapped to meta/recovery.json by the ceremony and shown
     * exactly once here; [MobileCreateResult.vault] is already unlocked.
     */
    suspend fun createVaultWithRecovery(
        path: String,
        password: String,
        deviceName: String,
    ): MobileCreateResult = uniffiCreateVaultWithRecovery(path, password, deviceName)

    suspend fun listCiphers(vault: MobileVault): List<MobileCipherMeta> = vault.listCiphers()
    suspend fun getCipher(vault: MobileVault, id: String, decrypt: Boolean): String =
        vault.getCipher(id, decrypt)
    suspend fun addCipher(vault: MobileVault, payload: String): String = vault.addCipher(payload)
    suspend fun updateCipher(vault: MobileVault, payload: String): Unit = vault.updateCipher(payload)
    suspend fun deleteCipher(vault: MobileVault, id: String): Unit = vault.deleteCipher(id)
    suspend fun totpCode(vault: MobileVault, id: String): String = vault.totpCode(id)

    /** Folders as [{id, name}] for the list filter. Empty when the vault has none. */
    suspend fun listFolders(vault: MobileVault): List<MobileFolderInfo> {
        val raw = vault.listFolders()
        val arr = kotlinx.serialization.json.Json.parseToJsonElement(raw)
            as? kotlinx.serialization.json.JsonArray ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && name != null) MobileFolderInfo(id, name) else null
        }
    }
// ── Slice B: provider onboarding (plan §4) ──

    /** Start an RFC 8628 device-flow session; poll via [MobileDeviceFlow.poll]. */
    suspend fun startDeviceFlow(
        provider: MobileProvider,
        config: MobileProviderConfig = MobileProviderConfig(null, null),
    ): MobileDeviceFlow = uniffiStartDeviceFlow(provider, config)

    /** Connect with a personal access token (Codeberg default; works for all). */
    suspend fun connectPat(
        provider: MobileProvider,
        token: String,
        config: MobileProviderConfig = MobileProviderConfig(null, null),
    ) = uniffiConnectPat(provider, token, config)

    /** Repos that look like Baluard vaults on the connected account. */
    suspend fun listVaultRepos(provider: MobileProvider): List<MobileRepo> =
        uniffiListVaultRepos(provider)

    /** Clone a vault repo to [localPath]. Cancel via the returned job. */
    suspend fun cloneVaultStart(
        provider: MobileProvider,
        cloneUrl: String,
        localPath: String,
    ): MobileCloneJob = uniffiCloneVaultStart(provider, cloneUrl, localPath)

    /**
     * Enroll this device into an existing vault clone with the 24-word
     * recovery phrase (plan §2.4: clone -> enroll -> unlock). Returns the
     * vault already unlocked.
     */
    suspend fun enrollDeviceWithPhrase(
        vaultPath: String,
        masterPassword: String,
        recoveryPhrase: String,
        deviceName: String,
    ): MobileVault = uniffiEnrollDeviceWithPhrase(vaultPath, masterPassword, recoveryPhrase, deviceName)
}
