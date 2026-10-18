package xyz.actitud.baluard.onboarding

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import xyz.actitud.baluard.MobileCloneJob
import xyz.actitud.baluard.MobileDeviceFlow
import xyz.actitud.baluard.MobileDeviceFlowStatus
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.MobileRepo
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.openUrl
import xyz.actitud.baluard.platform.platformLogE
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
    /// Outlives composition: the clone must survive the repo picker leaving
    /// composition when the stage flips to Cloning.
    private val vmScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    /** Flow stages; screens render the stage they own. */
    sealed interface Stage {
        data object PickProvider : Stage
        data class DeviceCode(val flow: MobileDeviceFlow) : Stage
        /** Waiting in the browser for the web-OAuth redirect (GitHub). */
        data object WebAuth : Stage
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

    /** RFC 8628 poll interval; grows on SlowDown. */
    private var pollIntervalMs: Long = 5_000

    /** Whether the system back gesture has an in-app screen to return to.
     *  False mid-operation (Cloning/enroll in flight) - interrupting those
     *  leaves half-written state.
     */
    fun canGoBack(): Boolean = !busy && when (stage) {
        is Stage.DeviceCode, is Stage.Repos, is Stage.Enroll -> true
        else -> false
    }

    /** System back: one stage back. Call only when [canGoBack] is true. */
    fun back() {
        when (stage) {
            is Stage.DeviceCode, is Stage.WebAuth -> backToPickProvider()
            is Stage.Repos -> backToPickProvider()
            is Stage.Enroll -> backToRepos()
            else -> Unit
        }
    }

    fun pollIntervalMs(): Long = pollIntervalMs

    private var cloneJob: MobileCloneJob? = null

    /** Select the provider for this onboarding run. */
    fun selectProvider(p: MobileProvider) {
        provider = p
        error = null
    }
    private var cloneCoroutineJob: kotlinx.coroutines.Job? = null

    /** Last loaded repo list, so cancel/error can restore the picker. */
    var repos: List<MobileRepo> by mutableStateOf(emptyList())
        private set

    /** Clean up background resources. */
    /** Start the device flow (GitHub/GitLab; Codeberg has none, use PAT). */
    suspend fun startDeviceFlow() {
        if (busy) return
        busy = true
        error = null
        try {
            stage = Stage.DeviceCode(repo.startDeviceFlow(provider))
        } catch (e: Exception) {
            fail("startDeviceFlow", e, t("provider.errorConnection"))
        }
        busy = false
    }

    /**
     * Start the web-OAuth sign-in (GitHub): open the returned URL in the
     * phone's browser and wait on [Stage.WebAuth]; the redirect lands on the
     * in-process loopback listener. Poll with [pollWebOAuth].
     */
    suspend fun startWebOAuth() {
        if (busy) return
        busy = true
        error = null
        try {
            val url = repo.webOauthStart(provider)
            stage = Stage.WebAuth
            // Open after the stage flip so back-from-browser lands on the
            // waiting card, not the provider picker.
            openUrl(url)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            stage = Stage.PickProvider
            fail("startWebOAuth", e, t("provider.errorConnection"))
        }
        busy = false
    }

    /**
     * Poll once while on [Stage.WebAuth]. `true` = approved (repos loaded),
     * `false` = still pending, `null` = terminal ([error] holds the reason).
     * Mirrors [pollDeviceFlow]'s contract: only an exception reaching this
     * catch is terminal; a `status:"error"` result is terminal too (GitHub
     * denied or the code expired) and the user must restart the flow.
     */
    suspend fun pollWebOAuth(): Boolean? {
        return try {
            val o = kotlinx.serialization.json.Json.parseToJsonElement(
                repo.webOauthStatus(provider),
            ).jsonObject
            when (o["status"]?.jsonPrimitive?.content) {
                "success" -> if (loadRepos()) true else null
                "error" -> {
                    fail(
                        "pollWebOAuth",
                        IllegalStateException(
                            o["error"]?.jsonPrimitive?.content ?: "authorization failed",
                        ),
                        t("provider.errorAuth"),
                    )
                    null
                }
                else -> false
            }
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            fail("pollWebOAuth", e, t("provider.errorAuth"))
            null
        }
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
            fail("pollDeviceFlow", e, t("provider.errorAuth"))
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
            fail("connectPat", e, t("provider.errorConnection"))
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

    /** Load the repo list and advance to the picker. False = [error] is set.
     *
     * Retried: the first call often races app resume from the browser
     * (Android can briefly cut background sockets), surfacing as a Connect
     * error that a second attempt seconds later does not see.
     */
    private suspend fun loadRepos(): Boolean {
        busy = true
        return try {
            var list: List<MobileRepo>? = null
            var last: Exception? = null
            repeat(5) { attempt ->
                if (list == null) {
                    try {
                        list = repo.listVaultRepos(provider)
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        last = e
                        if (attempt < 4) delay(2_000)
                    }
                }
            }
            val found = list
            if (found != null) {
                repos = found
                stage = Stage.Repos(found)
                true
            } else {
                fail("loadRepos", last!!, t("provider.errorListRepos"))
                false
            }
        } finally {
            busy = false
        }
    }

    /** Clone [r] to [localPath]; on success advance to enrollment.
     *
     * Runs on [vmScope], NOT the caller's composition scope: the stage flip
     * to Cloning swaps the repo picker out of composition, which cancels a
     * rememberCoroutineScope-launched clone mid-flight ("The coroutine
     * scope left the composition").
     */
    fun cloneRepo(r: MobileRepo, localPath: String, onCloned: () -> Unit) {
        if (busy) return
        busy = true
        error = null
        stage = Stage.Cloning
        cloneCoroutineJob = vmScope.launch {
            try {
                cloneJob = repo.cloneVaultStart(provider, r.cloneUrl, localPath)
                stage = Stage.Enroll
                onCloned()
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                fail("cloneRepo", e, t("provider.errorClone"))
                stage = Stage.Repos(repos)
            } finally {
                busy = false
            }
        }
    }

    fun cancelClone() {
        cloneCoroutineJob?.cancel()
        cloneCoroutineJob = null
        cloneJob?.cancel()
        cloneJob = null
        stage = Stage.Repos(repos)
        busy = false
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
            // Zeroize the outgoing vault's keys before adopting the newly
            // enrolled one — never rely on GC timing to drop the old handle.
            if (auth.vault() != null) runCatching { auth.lock() }
            val vault: MobileVault = repo.enrollDeviceWithPhrase(vaultPath, masterPassword, recoveryPhrase, deviceName)
            auth.adopt(vaultPath, vault)
            return true
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            fail("enroll", e, "Enrollment failed")
            return false
        } finally {
            busy = false
        }
    }

    /**
     * Record a terminal flow failure: full exception (with stack) to the
     * platform log, a one-line reason on screen. The generated exception
     * message is "detail=<text>"; the prefix is display noise.
     */
    private fun fail(where: String, e: Exception, fallback: String) {
        if (e is kotlinx.coroutines.CancellationException) throw e
        platformLogE(TAG, "$where failed", e)
        error = e.message?.removePrefix("detail=")?.ifBlank { null } ?: fallback
    }

    private companion object {
        /** Ceiling for slow_down backoff, so a rate-limited flow still ends. */
        const val MAX_POLL_INTERVAL_MS = 30_000L
        /** Platform log tag for provider flow failures. */
        const val TAG = "ProviderFlow"
    }
}
