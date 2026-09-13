package xyz.actitud.baluard.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.FastOutLinearInEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
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
import xyz.actitud.baluard.platform.AppBackground
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.data.vaultTimeoutToken
import xyz.actitud.baluard.data.vaultTimeoutMinutes
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

private fun navDepth(nav: Nav): Int = when (nav) {
    is Nav.List -> 0
    is Nav.Detail, Nav.Generator, Nav.Settings -> 1
    is Nav.Edit -> 2
}

/** Top-level navigation stages. */
private sealed interface RootStage {
    data object Onboarding : RootStage
    data object CreateVault : RootStage
    data object OpenProvider : RootStage
    data object Unlock : RootStage
    data object Unlocked : RootStage
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
        var autoLockToken by remember { mutableStateOf(VaultRepository.DEFAULT_VAULT_TIMEOUT) }
        var nav by remember { mutableStateOf<Nav>(Nav.List) }
        var saveRevision by remember { mutableStateOf(0) }
        val scope = rememberCoroutineScope()

        // System back: pop in-app navigation when a screen sits above its
        // parent; at the roots (vault list, unlock, provider picker) let the
        // system do its default (exit/minimize).
        BackPressHandler(
            enabled = (unlocked && nav != Nav.List) || (showOpen && flowVm.canGoBack()),
            onBack = {
                when {
                    unlocked && nav != Nav.List -> nav = Nav.List
                    showOpen -> flowVm.back()
                }
            },
        )

        // Auto-lock on background/return, per the vault's timeout policy.
        // Reads the policy fresh each time so Settings changes apply live.
        AppBackground.onPause = {
            if (unlocked) scope.launch {
                val vault = auth.vault() ?: return@launch
                val token = runCatching { vaultTimeoutToken(vault) }.getOrNull() ?: return@launch
                if (token == "immediately") {
                    auth.lock()
                    nav = Nav.List
                    unlocked = false
                }
            }
        }
        AppBackground.onResume = { backgroundedMs ->
            if (unlocked) scope.launch {
                val vault = auth.vault() ?: return@launch
                val token = runCatching { vaultTimeoutToken(vault) }.getOrNull() ?: return@launch
                val mins = vaultTimeoutMinutes(token) ?: return@launch
                if (backgroundedMs >= mins * 60_000L) {
                    auth.lock()
                    nav = Nav.List
                    unlocked = false
                }
            }
        }

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

        val currentRoot = when {
            unlocked -> RootStage.Unlocked
            showCreate -> RootStage.CreateVault
            showOpen -> RootStage.OpenProvider
            !hasVault -> RootStage.Onboarding
            else -> RootStage.Unlock
        }

        Box(Modifier.fillMaxSize()) {
            AnimatedContent(
                targetState = currentRoot,
                transitionSpec = {
                    if (targetState is RootStage.Unlocked) {
                        (fadeIn(animationSpec = tween(280, easing = FastOutSlowInEasing)) +
                         scaleIn(initialScale = 0.97f, animationSpec = tween(280, easing = FastOutSlowInEasing)))
                            .togetherWith(fadeOut(animationSpec = tween(180, easing = FastOutLinearInEasing)))
                    } else if (initialState is RootStage.Unlocked) {
                        fadeIn(animationSpec = tween(200, easing = FastOutSlowInEasing))
                            .togetherWith(
                                fadeOut(animationSpec = tween(180, easing = FastOutLinearInEasing)) +
                                scaleOut(targetScale = 0.97f, animationSpec = tween(180, easing = FastOutLinearInEasing))
                            )
                    } else {
                        (fadeIn(animationSpec = tween(240, easing = FastOutSlowInEasing)) +
                         slideInHorizontally(animationSpec = tween(240, easing = FastOutSlowInEasing)) { (it * 0.08f).toInt() })
                            .togetherWith(
                                fadeOut(animationSpec = tween(180, easing = FastOutLinearInEasing)) +
                                slideOutHorizontally(animationSpec = tween(180, easing = FastOutLinearInEasing)) { -(it * 0.08f).toInt() }
                            )
                    }
                },
                label = "RootStageTransition",
                modifier = Modifier.fillMaxSize(),
            ) { rootStage ->
                when (rootStage) {
                    RootStage.Unlocked -> auth.vault()?.let { vault ->
                        AnimatedContent(
                            targetState = nav,
                            transitionSpec = {
                                val forward = navDepth(targetState) >= navDepth(initialState)
                                if (forward) {
                                    (slideInHorizontally(animationSpec = tween(240, easing = FastOutSlowInEasing)) { (it * 0.12f).toInt() } +
                                     fadeIn(animationSpec = tween(240, easing = FastOutSlowInEasing)))
                                        .togetherWith(
                                            slideOutHorizontally(animationSpec = tween(200, easing = FastOutLinearInEasing)) { -(it * 0.08f).toInt() } +
                                            fadeOut(animationSpec = tween(200, easing = FastOutLinearInEasing))
                                        )
                                } else {
                                    (slideInHorizontally(animationSpec = tween(240, easing = FastOutSlowInEasing)) { -(it * 0.12f).toInt() } +
                                     fadeIn(animationSpec = tween(240, easing = FastOutSlowInEasing)))
                                        .togetherWith(
                                            slideOutHorizontally(animationSpec = tween(200, easing = FastOutLinearInEasing)) { (it * 0.08f).toInt() } +
                                            fadeOut(animationSpec = tween(200, easing = FastOutLinearInEasing))
                                        )
                                }
                            },
                            label = "NavTransition",
                            modifier = Modifier.fillMaxSize(),
                        ) { n ->
                            when (n) {
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
                                    onSyncNow = {
                                        val ok = runCatching { sync.pullNow(vault) }.isSuccess
                                        runCatching {
                                            conflictVm.refresh(vault)
                                            listVm.refresh(vault)
                                        }
                                        saveRevision++
                                        ok
                                    },
                                    onStageEntry = {
                                        // Unlock-pull in Rust is spawned (not
                                        // awaited), so the first list render can
                                        // race it. Sync once + reload so the
                                        // list reflects the synced state.
                                        runCatching { sync.pullNow(vault) }
                                        conflictVm.refresh(vault)
                                        listVm.refresh(vault)
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
                                    vaultTimeoutToken = autoLockToken,
                                    vaultPath = path,
                                    authViewModel = auth,
                                    onVaultRemoved = {
                                        auth.forget()
                                        unlocked = false
                                        hasVault = false
                                        nav = Nav.List
                                    },
                                    repo = repo,
                                    onVaultTimeoutChange = { token ->
                                        autoLockToken = token
                                        scope.launch {
                                            auth.vault()?.let { v ->
                                                runCatching { repo.setVaultTimeout(v, token) }
                                            }
                                        }
                                    },
                                    onBack = { nav = Nav.List },
                                )
                            }
                        }
                    }

                    RootStage.CreateVault -> CreateVaultScreen(
                        vaultPath = path,
                        authViewModel = auth,
                        onCreated = {
                            hasVault = true
                            showCreate = false
                            unlocked = true
                        },
                        onCancelled = { showCreate = false },
                    )

                    RootStage.OpenProvider -> {
                        AnimatedContent(
                            targetState = flowVm.stage,
                            transitionSpec = {
                                (slideInHorizontally(animationSpec = tween(240, easing = FastOutSlowInEasing)) { (it * 0.10f).toInt() } +
                                 fadeIn(animationSpec = tween(240, easing = FastOutSlowInEasing)))
                                    .togetherWith(
                                        slideOutHorizontally(animationSpec = tween(200, easing = FastOutLinearInEasing)) { -(it * 0.08f).toInt() } +
                                        fadeOut(animationSpec = tween(200, easing = FastOutLinearInEasing))
                                    )
                            },
                            label = "ProviderStageTransition",
                            modifier = Modifier.fillMaxSize(),
                        ) { stage ->
                            val code = stage as? ProviderFlowViewModel.Stage.DeviceCode
                            val repos = stage as? ProviderFlowViewModel.Stage.Repos
                            when {
                                code != null -> DeviceCodeScreen(
                                    vm = flowVm,
                                    flow = code.flow,
                                    onAuthorized = { },
                                    onCancelled = { flowVm.backToPickProvider() },
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
                                    onCloneDone = { },
                                    onCancelled = { flowVm.backToPickProvider() },
                                )

                                else -> ProviderConnectScreen(
                                    vm = flowVm,
                                    onDeviceCodeStarted = { },
                                    onPatConnected = { },
                                    onCancelled = {
                                        hasVault = AppPaths.vaultExists(path)
                                        showOpen = false
                                    },
                                )
                            }
                        }
                    }

                    RootStage.Onboarding -> OnboardingScreen(
                        onCreateVault = { showCreate = true },
                        onOpenProvider = { showOpen = true },
                    )

                    RootStage.Unlock -> UnlockScreen(
                        vaultPath = path,
                        authViewModel = auth,
                        onUnlocked = { unlocked = true },
                    )
                }
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

