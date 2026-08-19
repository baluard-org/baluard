package xyz.actitud.baluard.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.auth.UnlockScreen
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.detail.CipherDetailScreen
import xyz.actitud.baluard.detail.CipherDetailViewModel
import xyz.actitud.baluard.edit.EditCipherScreen
import xyz.actitud.baluard.edit.EditCipherViewModel
import xyz.actitud.baluard.onboarding.CreateVaultScreen
import xyz.actitud.baluard.onboarding.DeviceCodeScreen
import xyz.actitud.baluard.onboarding.EnrollDeviceScreen
import xyz.actitud.baluard.onboarding.OnboardingScreen
import xyz.actitud.baluard.onboarding.ProviderConnectScreen
import xyz.actitud.baluard.onboarding.ProviderFlowViewModel
import xyz.actitud.baluard.onboarding.RepoPickerScreen
import xyz.actitud.baluard.platform.AppPaths
import xyz.actitud.baluard.ui.components.ConflictResolutionPanel
import xyz.actitud.baluard.ui.theme.BaluardTheme
import xyz.actitud.baluard.vault.VaultListScreen
import xyz.actitud.baluard.vault.VaultListViewModel
import xyz.actitud.baluard.settings.SettingsScreen
import xyz.actitud.baluard.settings.SettingsViewModel
import xyz.actitud.baluard.generator.GeneratorScreen
import xyz.actitud.baluard.generator.GeneratorViewModel
import xyz.actitud.baluard.totp.TotpViewModel
import xyz.actitud.baluard.sync.ConflictViewModel
import xyz.actitud.baluard.sync.SyncCoordinator
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Unlocked-subtree navigation (flat back stack, no nav library yet). */
private sealed interface Nav {
    data object List : Nav
    data class Detail(val cipherId: String) : Nav
    data class Edit(val cipherId: String?) : Nav
    data object Generator : Nav
    data object Settings : Nav
}

/**
 * Root navigation (plan §5): no vault at the default path -> OnboardingScreen;
 * vault exists -> UnlockScreen; unlocked -> VaultListScreen. The create flow
 * replaces the onboarding root until its recovery-phrase ack completes, then
 * lands directly in the vault list (the FFI returns the vault unlocked). The
 * open-from-provider flow (connect -> code -> repos -> clone -> enroll) is
 * driven by [ProviderFlowViewModel] stages.
 *
 * [vaultPath] overrides the platform default (host intent / debug builds).
 */
@Composable
fun App(vaultPath: String? = null) {
    BaluardTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            val path = remember(vaultPath) {
            vaultPath?.takeIf { it.isNotBlank() } ?: AppPaths.defaultVaultPath()
        }
        var hasVault by remember { mutableStateOf(AppPaths.vaultExists(path)) }
        var showCreate by remember { mutableStateOf(false) }
        var showOpen by remember { mutableStateOf(false) }
        var unlocked by remember { mutableStateOf(false) }

        val repo = remember { VaultRepository() }
        val auth = remember { AuthViewModel(repo) }
        val configStore = remember { xyz.actitud.baluard.platform.SyncConfigStore() }
        val sync = remember { SyncCoordinator(configStore.load()) }
        val settingsVm = remember { SettingsViewModel(configStore.load()) }
        val conflictVm = remember { ConflictViewModel() }
        val listVm = remember { VaultListViewModel(repo) }
        val flowVm = remember { ProviderFlowViewModel(repo, auth) }
        val detailVm = remember { CipherDetailViewModel(repo) }
        val editVm = remember { EditCipherViewModel(repo) }
        val totpVm = remember { TotpViewModel(repo) }
        val generatorVm = remember { GeneratorViewModel(repo) }
        var nav by remember { mutableStateOf<Nav>(Nav.List) }
        var saveRevision by remember { mutableStateOf(0) }
        val scope = rememberCoroutineScope()

        // Persist + apply every settings change (toggles live beyond the
        // Settings screen now; previously each visit reset them).
        val configState = settingsVm.config.collectAsState()
        val bgScheduler = remember { xyz.actitud.baluard.platform.BackgroundSyncScheduler() }
        LaunchedEffect(configState.value) {
            sync.updateConfig(configState.value)
            configStore.save(configState.value)
            bgScheduler.setEnabled(
                configState.value.backgroundSyncEnabled,
                configState.value.backgroundIntervalMinutes,
            )
        }

        /** B6: runtime idle-timeout reached — zeroize keys, drop to unlock. */
        suspend fun doAutoLock() {
            runCatching { auth.lock() }
            conflictVm.clear()
            nav = Nav.List
            unlocked = false
        }

        // B3 sync wiring: pull right after unlock. Foreground/background glue
        // rides the Activity lifecycle (single-activity app): ON_START ->
        // guarded pull, ON_STOP -> flush the 5s debounce before suspension.
        // The 10-min focus guard lives in the runtime, so flicker collapses
        // there; the suspend bridge parks on the shared tokio runtime.
        LifecycleEventEffect(Lifecycle.Event.ON_START) {
            auth.vault()?.let { v ->
                scope.launch {
                    // B6: lock check FIRST — returning to the foreground after
                    // a long background stretch must not flash the vault UI.
                    if (v.shouldAutoLock()) return@launch doAutoLock()
                    runCatching { sync.onForeground(v) }
                    conflictVm.refresh(v)
                }
            }
        }
        LifecycleEventEffect(Lifecycle.Event.ON_STOP) {
            auth.vault()?.let { v -> scope.launch { runCatching { sync.onBackground(v) } } }
        }

        LaunchedEffect(unlocked) {
            if (unlocked) {
                auth.vault()?.let { v ->
                    runCatching { sync.onUnlock(v) }
                    conflictVm.refresh(v)
                }
            }
        }

        // B4/B6: poll while unlocked + foregrounded. Conflict check surfaces
        // NeedsDecision pauses from background pulls; auto-lock check drives
        // the runtime's idle policy (foreground-lifecycle, no background
        // walker — plan §3.5). Both are cheap local FFI reads.
        suspend fun checkAutoLock() {
            val v = auth.vault() ?: return
            if (v.shouldAutoLock()) doAutoLock()
        }

        LaunchedEffect(unlocked) {
            while (unlocked && isActive) {
                checkAutoLock()
                if (unlocked) auth.vault()?.let { v -> conflictVm.refresh(v) }
                delay(15_000)
            }
        }

        /** Fire-and-forget the 5s debounced push after any local mutation. */
        fun notifyMutation() {
            auth.vault()?.let { v ->
                scope.launch {
                    runCatching { sync.onMutation(v) }
                    conflictVm.refresh(v)
                }
            }
        }

        Box(Modifier.fillMaxSize()) {
        when {
            unlocked -> auth.vault()?.let { vault ->
                when (val n = nav) {
                    is Nav.List -> VaultListScreen(
                        vault = vault,
                        listViewModel = listVm,
                        authViewModel = auth,
                        onLocked = {
                            nav = Nav.List
                            unlocked = false
                        },
                        onCipherClick = { nav = Nav.Detail(it) },
                        onAddEntry = { nav = Nav.Edit(null) },
                        onOpenGenerator = { nav = Nav.Generator },
                        onOpenSettings = { nav = Nav.Settings },
                        revision = saveRevision,
                        onPullRefresh = {
                            runCatching { sync.pullNow(vault) }
                            conflictVm.refresh(vault)
                            listVm.refresh(vault)
                            saveRevision++
                        },
                    )

                    is Nav.Detail -> CipherDetailScreen(
                        vault = vault,
                        cipherId = n.cipherId,
                        detailViewModel = detailVm,
                        totpViewModel = totpVm,
                        onEdit = { nav = Nav.Edit(n.cipherId) },
                        onDeleted = {
                            saveRevision++
                            notifyMutation()
                            nav = Nav.List
                        },
                        onBack = { nav = Nav.List },
                        revision = saveRevision,
                    )

                    is Nav.Edit -> EditCipherScreen(
                        vault = vault,
                        cipherId = n.cipherId,
                        viewModel = editVm,
                        onSaved = {
                            saveRevision++
                            notifyMutation()
                            nav = if (n.cipherId == null) Nav.List else Nav.Detail(n.cipherId)
                        },
                        onCancelled = { nav = if (n.cipherId == null) Nav.List else Nav.Detail(n.cipherId) },
                    )

                    Nav.Generator -> GeneratorScreen(
                        viewModel = generatorVm,
                        onBack = { nav = Nav.List },
                    )

                    Nav.Settings -> SettingsScreen(
                        vault = vault,
                        coordinator = sync,
                        viewModel = settingsVm,
                        onBack = { nav = Nav.List },
                    )
                }
            }

            showCreate -> CreateVaultScreen(
                vaultPath = path,
                authViewModel = auth,
                onCreated = {
                    hasVault = true
                    showCreate = false
                    unlocked = true
                },
                onCancelled = { showCreate = false },
            )

            showOpen -> {
                val stage = flowVm.stage
                val code = stage as? ProviderFlowViewModel.Stage.DeviceCode
                val repos = stage as? ProviderFlowViewModel.Stage.Repos
                when {
                    code != null -> DeviceCodeScreen(
                        vm = flowVm,
                        flow = code.flow,
                        onAuthorized = { }, // stage flipped to Repos by the VM
                        onCancelled = {
                            flowVm.backToPickProvider()
                        },
                    )

                    stage is ProviderFlowViewModel.Stage.Enroll -> EnrollDeviceScreen(
                        vm = flowVm,
                        vaultPath = path,
                        onEnrolled = {
                            hasVault = true
                            showOpen = false
                            unlocked = true
                        },
                        onCancelled = { flowVm.backToRepos() },
                    )

                    repos != null || stage is ProviderFlowViewModel.Stage.Cloning -> RepoPickerScreen(
                        vm = flowVm,
                        repos = (repos?.repos ?: flowVm.repos),
                        vaultPath = path,
                        onCloneDone = { }, // stage drives the next screen
                        onCancelled = { flowVm.backToPickProvider() },
                    )

                    else -> ProviderConnectScreen(
                        vm = flowVm,
                        onDeviceCodeStarted = { }, // stage flipped to DeviceCode
                        onPatConnected = { }, // stage flipped to Repos
                        onCancelled = {
                            // A clone may have landed mid-flow; re-check so a
                            // vault that exists routes to unlock, not onboarding.
                            hasVault = AppPaths.vaultExists(path)
                            showOpen = false
                        },
                    )
                }
            }

            !hasVault -> OnboardingScreen(
                onCreateVault = { showCreate = true },
                onOpenProvider = { showOpen = true },
            )

            else -> UnlockScreen(
                vaultPath = path,
                authViewModel = auth,
                onUnlocked = { unlocked = true },
            )
        }

        // B4 overlay: a paused conflict blocks the sync cycle; the decision
        // is unavoidable by design (no dismiss control on the panel).
        conflictVm.current?.let { dto ->
            ConflictResolutionPanel(
                conflict = dto,
                queued = conflictVm.queued,
                resolving = conflictVm.resolving,
                error = conflictVm.error,
                onVerdict = { verdict ->
                    scope.launch {
                        auth.vault()?.let { v ->
                            // Refresh the list on success: keep_both adds a
                            // cloned entry; the other verdicts may drop one.
                            if (conflictVm.resolve(v, verdict)) saveRevision++
                        }
                    }
                },
            )
        }
        } // Box
        } // Surface
    } // BaluardTheme
} // App

