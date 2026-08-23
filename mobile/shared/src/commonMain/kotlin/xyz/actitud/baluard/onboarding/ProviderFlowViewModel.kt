package xyz.actitud.baluard.onboarding

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay
import xyz.actitud.baluard.MobileCloneJob
import xyz.actitud.baluard.MobileDeviceFlow
import xyz.actitud.baluard.MobileDeviceFlowStatus
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.MobileRepo
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.VaultRepository

/**
 * Drives the "open an existing vault" onboarding path (plan §5.2-5.4):
 * provider connect -> repo pick -> clone -> enroll this device with the
 * recovery phrase -> unlocked vault.
 *
 * One state machine for four screens; each screen renders the stage it owns
 * and calls the transition functions. All FFI calls run on the shared tokio
 * Runtime via the suspend repository.
 */
class ProviderFlowViewModel(
    private val repo: VaultRepository,
    private val auth: AuthViewModel,
) {
    /** Flow stages; screens render the stage they own. */
    sealed interface Stage {
        data object PickProvider : Stage
        data class DeviceCode(val flow: MobileDeviceFlow) : Stage
        data class Repos(val repos: List<MobileRepo>) : Stage
        data object Cloning : Stage
        data object Enroll : Stage
    }

    // Snapshot-backed so App's stage router recomposes on transition.
    var stage: Stage by mutableStateOf(Stage.PickProvider)
        private set
    var provider: MobileProvider by mutableStateOf(MobileProvider.GIT_HUB)
        private set
    var busy: Boolean by mutableStateOf(false)
        private set
    var error: String? by mutableStateOf(null)
        private set

    private var cloneJob: MobileCloneJob? = null

    /** Last loaded repo list, so cancel/error can restore the picker. */
    var repos: List<MobileRepo> by mutableStateOf(emptyList())
        private set

    /** RFC 8628 poll interval; grows on SlowDown. */
    private var pollIntervalMs: Long = 5_000

    /** Current poll interval for the device-code screen's loop. */
    fun pollIntervalMs(): Long = pollIntervalMs

    fun selectProvider(p: MobileProvider) {
        provider = p
        error = null
    }

    /** Start the device flow (GitHub/GitLab; Codeberg has none, use PAT). */
    suspend fun startDeviceFlow() {
        if (busy) return
        busy = true
        error = null
        pollIntervalMs = 5_000
        try {
            stage = Stage.DeviceCode(repo.startDeviceFlow(provider))
        } catch (e: Exception) {
            error = e.message
        }
        busy = false
    }

    /**
     * Poll once; caller loops with [pollIntervalMs] between calls. Returns the
     * status so the screen can react (Success advances to repos), or `null`
     * when the flow failed for good. [error] then holds the reason and the
     * caller MUST stop looping.
     *
     * Transient network failures are absorbed on the Rust side (which can tell
     * a dropped socket from a rejected grant) and arrive here as PENDING. An
     * exception reaching this catch is therefore terminal: the device code is
     * single-use, so retrying a consumed or rejected code can only spin
     * forever. Never translate it back into PENDING.
     */
    suspend fun pollDeviceFlow(flow: MobileDeviceFlow): MobileDeviceFlowStatus? {
        return try {
            when (val s = flow.poll()) {
                MobileDeviceFlowStatus.SLOW_DOWN -> {
                    pollIntervalMs = (pollIntervalMs + 5_000).coerceAtMost(MAX_POLL_INTERVAL_MS)
                    s
                }
                // Approval landed. The token is persisted; if the repo listing
                // that follows fails, the flow is still over (the code is
                // spent); report it instead of polling a dead code.
                MobileDeviceFlowStatus.SUCCESS -> if (loadRepos()) s else null
                else -> s
            }
        } catch (e: Exception) {
            error = e.message ?: "Authorization failed"
            null
        }
    }

    /** Connect with a personal access token, then load repos. */
    suspend fun connectPat(token: String) {
        if (busy || token.isBlank()) return
        busy = true
        error = null
        try {
            repo.connectPat(provider, token)
            loadRepos()
        } catch (e: Exception) {
            error = e.message
        }
        busy = false
    }

    fun backToPickProvider() {
        error = null
        stage = Stage.PickProvider
    }

    /** From the enroll screen back to the repo picker (repos still cached). */
    fun backToRepos() {
        error = null
        stage = Stage.Repos(repos)
    }

    /** Load the repo list and advance to the picker. False = [error] is set. */
    private suspend fun loadRepos(): Boolean {
        busy = true
        return try {
            repos = repo.listVaultRepos(provider)
            stage = Stage.Repos(repos)
            true
        } catch (e: Exception) {
            error = e.message ?: "Could not list repositories"
            false
        } finally {
            busy = false
        }
    }

    /** Clone [r] to [localPath]; on success advance to enrollment. */
    suspend fun cloneRepo(r: MobileRepo, localPath: String) {
        if (busy) return
        busy = true
        error = null
        stage = Stage.Cloning
        try {
            cloneJob = this.repo.cloneVaultStart(provider, r.cloneUrl, localPath)
            stage = Stage.Enroll
        } catch (e: Exception) {
            error = e.message
            stage = Stage.Repos(repos)
        }
        busy = false
    }

    fun cancelClone() {
        cloneJob?.cancel()
    }

    /**
     * Enroll this device with the 24-word [recoveryPhrase] + master password
     * into the clone at [vaultPath]. On success the vault arrives unlocked
     * and is adopted; caller flips App routing to the vault list.
     */
    suspend fun enroll(vaultPath: String, masterPassword: String, recoveryPhrase: String, deviceName: String): Boolean {
        if (busy) return false
        busy = true
        error = null
        try {
            val vault: MobileVault = repo.enrollDeviceWithPhrase(vaultPath, masterPassword, recoveryPhrase, deviceName)
            auth.adopt(vault)
            return true
        } catch (e: Exception) {
            error = e.message
            return false
        } finally {
            busy = false
        }
    }

    private companion object {
        /** Ceiling for slow_down backoff, so a rate-limited flow still ends. */
        const val MAX_POLL_INTERVAL_MS = 30_000L
    }
}
