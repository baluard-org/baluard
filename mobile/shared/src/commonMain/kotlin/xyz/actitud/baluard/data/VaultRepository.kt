package xyz.actitud.baluard.data

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileCreateResult
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.generateRecoveryPhrase
import xyz.actitud.baluard.MobileRecoveryPhrase
import xyz.actitud.baluard.openVault as uniffiOpenVault
import xyz.actitud.baluard.createVault as uniffiCreateVault
import xyz.actitud.baluard.createVaultWithRecovery as uniffiCreateVaultWithRecovery

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
}
