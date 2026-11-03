package app.baluard.mobile.onboarding

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import app.baluard.mobile.auth.AuthViewModel
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.platformLogE

/**
 * Drives vault creation (plan §5.5). Calls `create_vault_with_recovery`, which
 * runs the ceremony (Argon2id KDF + device keypair + HPKE-escrowed recovery)
 * off the UI thread on the shared tokio Runtime, and returns the 24-word
 * phrase exactly once. The created vault arrives unlocked; it is adopted by
 * [AuthViewModel] so App routing proceeds to the vault list.
 */
class CreateVaultViewModel(
    private val repo: VaultRepository,
    private val auth: AuthViewModel,
) {
    /** The created vault's 24 words, in order; empty until creation succeeds. */
    var recoveryWords: List<String> = emptyList()
        private set

    /** Family vaults only: the Space Recovery Kit words, shown right after
     * the vault recovery phrase. Empty for personal vaults. */
    var kitWords: List<String> = emptyList()
        private set

    /** Real failure reason; i18n fallback when the FFI gives nothing usable. */
    var error: String? by mutableStateOf(null)
        private set

    /**
     * Create the vault at [path]. Returns true on success (words available in
     * [recoveryWords], vault adopted + unlocked). On failure [error] holds the
     * surfaced reason; the screen shows it instead of a bare generic string.
     * [displayName] names the vault in the switcher; blank resolves to
     * "Personal" inside the FFI. [family] founds a family vault; its kit
     * words land in [kitWords] for the words-once display.
     */
    suspend fun create(
        path: String,
        displayName: String,
        password: String,
        deviceName: String,
        family: Boolean,
    ): Boolean {
        return try {
            val result = repo.createVaultWithRecovery(path, displayName, password, deviceName, family)
            recoveryWords = result.recoveryPhrase.phrase.split(' ').filter { it.isNotBlank() }
            kitWords = result.kitPhrase?.split(' ')?.filter { it.isNotBlank() } ?: emptyList()
            auth.adopt(path, result.vault)
            true
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            platformLogE("CreateVault", "vault creation failed at $path", e)
            error = e.message?.removePrefix("detail=")?.ifBlank { null } ?: t("onboarding.errorCreateFailed")
            false
        }
    }
}
