package app.baluard.mobile.ui

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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import app.baluard.mobile.auth.AuthViewModel
import app.baluard.mobile.auth.UnlockScreen
import app.baluard.mobile.platform.AppBackground
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.data.vaultTimeoutToken
import app.baluard.mobile.data.vaultTimeoutMinutes
import app.baluard.mobile.detail.CipherDetailScreen
import app.baluard.mobile.detail.CipherDetailViewModel
import app.baluard.mobile.edit.EditCipherScreen
import app.baluard.mobile.edit.EditCipherViewModel
import app.baluard.mobile.onboarding.CreateVaultScreen
import app.baluard.mobile.onboarding.DeviceCodeScreen
import app.baluard.mobile.onboarding.EnrollDeviceScreen
import app.baluard.mobile.onboarding.OnboardingScreen
import app.baluard.mobile.onboarding.ProviderConnectScreen
import app.baluard.mobile.MobileVault
import app.baluard.mobile.i18n.t
import app.baluard.mobile.onboarding.ProviderFlowViewModel
import app.baluard.mobile.onboarding.RepoPickerScreen
import app.baluard.mobile.platform.AppPaths
import app.baluard.mobile.platform.VaultRegistry
import app.baluard.mobile.ui.components.ConflictResolutionPanel
import app.baluard.mobile.ui.theme.BaluardTheme
import app.baluard.mobile.ui.toast.Toast
import app.baluard.mobile.ui.toast.ToastHost
import app.baluard.mobile.vault.EntryListKind
import app.baluard.mobile.vault.ForeignHits
import app.baluard.mobile.vault.EntryListScreen
import app.baluard.mobile.vault.TagListScreen
import app.baluard.mobile.vault.VaultHomeScreen
import app.baluard.mobile.vault.VaultListViewModel
import app.baluard.mobile.settings.PeopleScreen
import app.baluard.mobile.settings.ActivityScreen
import app.baluard.mobile.settings.CollectionsScreen
import app.baluard.mobile.settings.SettingsScreen
import app.baluard.mobile.settings.SettingsViewModel
import app.baluard.mobile.generator.GeneratorScreen
import app.baluard.mobile.generator.GeneratorViewModel
import app.baluard.mobile.totp.TotpViewModel
import app.baluard.mobile.sync.ConflictViewModel
import app.baluard.mobile.sync.SyncCoordinator
import app.baluard.mobile.sync.SyncPhase
import app.baluard.mobile.sync.runSyncCycle
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
    data object People : Nav
    data object Collections : Nav
    data object Activity : Nav
    data class EntryList(val kind: EntryListKind) : Nav
    data object TagList : Nav
}

private fun navDepth(nav: Nav): Int = when (nav) {
    is Nav.List -> 0
    is Nav.Detail, Nav.Generator, Nav.Settings, is Nav.EntryList, Nav.TagList -> 1
    // Settings sub-pages sit one level below Settings: back animates a pop.
    Nav.People, Nav.Collections, Nav.Activity -> 2
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
fun App(
    vaultPath: String? = null,
    // Autofill save handoff (Phase 6 P4): a login the OS captured lands on a
    // prefilled create editor, after unlock if the vault was locked.
    savePrefill: app.baluard.mobile.platform.AutofillSavePrefill? = null,
    onSavePrefillConsumed: () -> Unit = {},
    // Passkey provider fulfillment (G10 §9): the staged framework request
    // (validated at the trampoline gate) rendered as a full-screen overlay.
    passkeyRequest: app.baluard.mobile.passkeys.PasskeyUiRequest? = null,
    onPasskeyResult: (String) -> Unit = {},
    onPasskeyCancel: () -> Unit = {},
    onPasskeyUnlockComplete: () -> Unit = {},
) {
    BaluardTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            var path by remember(vaultPath) {
            mutableStateOf(
                vaultPath?.takeIf { it.isNotBlank() }
                    ?: app.baluard.mobile.platform.VaultRegistry.loadActiveVault()
                        ?.takeIf { AppPaths.vaultExists(it) }
                    ?: AppPaths.defaultVaultPath()
            )
        }
        var hasVault by remember { mutableStateOf(AppPaths.vaultExists(path)) }
        // Sync feedback phases per screen and the screen a Detail was opened
        // from (back goes there).
        var homeSyncPhase by remember { mutableStateOf(SyncPhase.Idle) }
        var listSyncPhase by remember { mutableStateOf(SyncPhase.Idle) }
        var detailOrigin by remember { mutableStateOf<Nav?>(null) }
        // Clone-in-progress target: chosen at repo pick, consumed at enroll.
        var pendingVaultPath by remember { mutableStateOf<String?>(null) }

        var showCreate by remember { mutableStateOf(false) }
        var showOpen by remember { mutableStateOf(false) }
        var unlocked by remember { mutableStateOf(false) }
        // Where the create ceremony writes. Set by the switcher's create row
        // (fresh directory) or first-run staging (the default vault path); the
        // mount and both completion arms consume it, and it is nulled on
        // completion AND cancel so stale state can never route a later
        // first-run creation into the wrong directory.
        var createTarget by remember { mutableStateOf<String?>(null) }

        val repo = remember { VaultRepository() }
        val auth = remember { AuthViewModel(repo) }
        val configStore = remember { app.baluard.mobile.platform.SyncConfigStore() }
        val sync = remember { SyncCoordinator(configStore.load()) }
        val settingsVm = remember { SettingsViewModel(configStore.load()) }
        val conflictVm = remember { ConflictViewModel() }
        val listVm = remember { VaultListViewModel(repo) }
        // The hub search belongs to one vault; a query typed there must not
        // filter the next vault's hub after a switch.
        LaunchedEffect(path) { listVm.setQuery("") }
        // G24 §4.9: merged app-search fan-out source. The AuthViewModel owns
        // the session map; the ViewModel stays free of auth wiring.
        listVm.foreignSearch = { query, excludePath ->
            val out = ArrayList<ForeignHits>()
            for ((p, name, v) in auth.mergeSearchSessions(excludePath)) {
                val metas = runCatching { repo.listCiphers(v) }.getOrDefault(emptyList())
                out.add(ForeignHits(p, name, metas))
            }
            out
        }
        val flowVm = remember { ProviderFlowViewModel(repo, auth) }
        val detailVm = remember { CipherDetailViewModel(repo) }
        val editVm = remember { EditCipherViewModel(repo) }
        val totpVm = remember { TotpViewModel(repo) }
        val generatorVm = remember { GeneratorViewModel(repo) }
        // A locked vault must not keep decrypted entries or the search
        // haystack in memory — one observer covers every lock path.
        LaunchedEffect(unlocked) {
            if (!unlocked) {
                listVm.clear()
                detailVm.clear()
                editVm.clear()
            }
        }
        var autoLockToken by remember { mutableStateOf(VaultRepository.DEFAULT_VAULT_TIMEOUT) }
        var nav by remember { mutableStateOf<Nav>(Nav.List) }
        // Cached auto-lock policy so onResume can lock synchronously, before
        // a single frame of unlocked content draws.
        var timeoutMins by remember { mutableStateOf<Long?>(null) }
        LaunchedEffect(path, unlocked, nav, autoLockToken) {
            timeoutMins = null
            if (unlocked) {
                val v = auth.vault() ?: return@LaunchedEffect
                timeoutMins = vaultTimeoutMinutes(vaultTimeoutToken(v))
            }
        }
        var saveRevision by remember { mutableStateOf(0) }
        val scope = rememberCoroutineScope()
        // Land on the prefilled create editor when a save handoff arrives
        // (immediately if unlocked, right after unlock otherwise).
        LaunchedEffect(savePrefill) {
            if (savePrefill != null) {
                detailOrigin = null
                nav = Nav.Edit(null)
            }
        }
        // Passkey provider unlock leg (plan §4): the sheet waits for a
        // re-list; fire once when the in-app unlock completes. The callback
        // closes MainActivity with the fresh Begin response.
        LaunchedEffect(passkeyRequest, unlocked) {
            if (passkeyRequest is app.baluard.mobile.passkeys.PasskeyUiRequest.Unlock && unlocked) {
                onPasskeyUnlockComplete()
            }
        }
        // Multi-Space switch (S4-9): a cached, still-unlocked target adopts
        // with no unlock ceremony (desktop VaultHost parity); anything else
        // locks the outgoing vault and drops to the unlock screen as before.
        val switchVault: (String) -> Unit = { target ->
            scope.launch {
                if (auth.switchTo(target)) {
                    app.baluard.mobile.platform.VaultRegistry.saveActiveVault(target)
                    path = target
                    hasVault = true
                    detailOrigin = null
                    unlocked = true
                    nav = Nav.List
                    homeSyncPhase = SyncPhase.Idle
                    listSyncPhase = SyncPhase.Idle
                    auth.vault()?.let { v ->
                        runCatching { sync.onUnlock(v) }
                        conflictVm.refresh(v)
                    }
                } else {
                    runCatching { auth.lock() }
                    conflictVm.clear()
                    app.baluard.mobile.platform.VaultRegistry.saveActiveVault(target)
                    path = target
                    hasVault = AppPaths.vaultExists(target)
                    detailOrigin = null
                    unlocked = false
                    nav = Nav.List
                    homeSyncPhase = SyncPhase.Idle
                    listSyncPhase = SyncPhase.Idle
                }
            }
        }


        // Shared sync runner: guarantees a visible spin, then reports the
        // outcome phase. Used by the hub and the filtered entry lists.
        val startSync: (MobileVault, (SyncPhase) -> Unit) -> Unit = { vault, setPhase ->
            scope.launch {
                runSyncCycle(
                    doPull = { sync.pullNow(vault) },
                    afterPull = {
                        runCatching {
                            conflictVm.refresh(vault)
                            listVm.refresh(vault)
                        }
                        saveRevision++
                    },
                    setPhase = setPhase,
                    onResult = { ok ->
                        if (ok) Toast.success(t("sync.synced")) else Toast.error(t("sync.offline"))
                    },
                )
            }
        }

        val vaultDisplayName = remember(path, saveRevision) {
            runCatching { app.baluard.mobile.platform.VaultRegistry.listVaults() }
                .getOrNull()
                ?.firstOrNull { it.path == path }?.name
                ?: path.substringAfterLast('/')
        }

        // System back: pop in-app navigation when a screen sits above its
        // parent; at the roots (vault list, unlock, provider picker) let the
        // system do its default (exit/minimize).
        BackPressHandler(
            enabled = (unlocked && nav != Nav.List) || (showOpen && flowVm.canGoBack()),
            onBack = {
                when {
                    unlocked && (nav is Nav.Detail || nav is Nav.Edit) -> {
                        // Back from the detail/edit stack returns to the list
                        // the entry was opened from (hub when origin is null).
                        nav = detailOrigin ?: Nav.List
                        detailOrigin = null
                    }
                    // Settings sub-pages sit below Settings, not the list.
                    unlocked && (nav is Nav.People || nav is Nav.Collections || nav is Nav.Activity) -> {
                        nav = Nav.Settings
                    }
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
            val mins = timeoutMins
            if (mins != null && unlocked && backgroundedMs >= mins * 60_000L) {
                // Flip first: the lock IPC is async and unlocked content
                // must not draw for even one frame after the deadline.
                nav = Nav.List
                unlocked = false
                scope.launch { auth.lock() }
            }
        }

        // Persist + apply every settings change (toggles live beyond the
        // Settings screen now; previously each visit reset them).
        val configState = settingsVm.config.collectAsState()
        val bgScheduler = remember { app.baluard.mobile.platform.BackgroundSyncScheduler() }
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
            // Multi-Space rule (S4-9): only the vault on screen may ride out a
            // background stretch (its own vault timeout governs it); cached
            // vaults have no timer while inactive, so they lock on background —
            // the desktop lock-all-on-blur twin.
            scope.launch { runCatching { auth.lockInactiveSessions() } }
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
            // Enforce EVERY session's timeout (the desktop walker's
            // replacement), then the active vault's own check — an expired
            // cached vault must not survive its configured timeout unlocked.
            auth.enforceAutoLock()
            val v = auth.vault() ?: return
            if (v.shouldAutoLock()) doAutoLock()
        }

        LaunchedEffect(unlocked) {
            while (unlocked && isActive) {
                checkAutoLock()
                if (unlocked) auth.vault()?.let { v ->
                    conflictVm.refresh(v)
                    // 30s offline retry probe (plan §3.5): the runtime no-ops
                    // unless the vault is Offline; the coordinator spaces calls.
                    runCatching { sync.offlineTick(v) }
                }
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
                                Nav.List -> VaultHomeScreen(
                                    vault = vault,
                                    listViewModel = listVm,
                                    syncPhase = homeSyncPhase,
                                    onSyncClick = { startSync(vault) { homeSyncPhase = it } },
                                    onAddEntry = { nav = Nav.Edit(null) },
                                    onOpenGenerator = { nav = Nav.Generator },
                                    onOpenSettings = { nav = Nav.Settings },
                                    onLock = {
                                        scope.launch {
                                            auth.lock()
                                            unlocked = false
                                        }
                                    },
                                    onOpenKind = { nav = Nav.EntryList(it) },
                                    onOpenTags = { nav = Nav.TagList },
                                    onCipherClick = {
                                        detailOrigin = null
                                        nav = Nav.Detail(it)
                                    },
                                    onForeignOpen = { targetPath, cipherId ->
                                        // Fast path: the vault's session is
                                        // still unlocked - adopt it and open
                                        // the entry. Anything else falls back
                                        // to the normal switch (unlock screen).
                                        scope.launch {
                                            if (auth.switchTo(targetPath)) {
                                                app.baluard.mobile.platform.VaultRegistry.saveActiveVault(targetPath)
                                                path = targetPath
                                                auth.vault()?.let { v ->
                                                    runCatching { sync.onUnlock(v) }
                                                    conflictVm.refresh(v)
                                                }
                                                detailOrigin = null
                                                nav = Nav.Detail(cipherId)
                                            } else {
                                                switchVault(targetPath)
                                            }
                                        }
                                    },
                                    vaultName = vaultDisplayName,
                                    vaultPath = path,
                                    onSwitchVault = switchVault,
                                    onDetachVault = { targetPath ->
                                        // Drop the vault's cached session
                                        // and biometric KEK before the
                                        // directory moves aside.
                                        scope.launch {
                                            auth.forgetSession(targetPath)
                                            app.baluard.mobile.platform.Biometric().disenroll(targetPath)
                                            VaultRegistry.detach(targetPath)
                                        }
                                    },
                                    onAddVault = {
                                        // Stage flip only — the current vault
                                        // stays unlocked so cancel returns to
                                        // it without re-auth.
                                        unlocked = false
                                        showOpen = true
                                        nav = Nav.List
                                    },
                                    onCreateVault = {
                                        // Same stage flip; the current vault
                                        // stays unlocked in the session.
                                        unlocked = false
                                        createTarget = AppPaths.nextCreatedVaultPath()
                                        showCreate = true
                                        nav = Nav.List
                                    },
                                    revision = saveRevision,
                                )

                                is Nav.EntryList -> EntryListScreen(
                                    kind = n.kind,
                                    vault = vault,
                                    listViewModel = listVm,
                                    syncPhase = listSyncPhase,
                                    onSyncClick = { startSync(vault) { listSyncPhase = it } },
                                    onCipherClick = {
                                        detailOrigin = nav
                                        nav = Nav.Detail(it)
                                    },
                                    onBack = { nav = Nav.List },
                                    revision = saveRevision,
                                )

                                Nav.TagList -> TagListScreen(
                                    listViewModel = listVm,
                                    onTag = { nav = Nav.EntryList(EntryListKind.Tag(it)) },
                                    onBack = { nav = Nav.List },
                                )

                                is Nav.Detail -> CipherDetailScreen(
                                    vault = vault,
                                    cipherId = n.cipherId,
                                    detailViewModel = detailVm,
                                    totpViewModel = totpVm,
                                    onEdit = { nav = Nav.Edit(n.cipherId) },
                                    onDeleted = { id, permanent ->
                                        saveRevision++
                                        notifyMutation()
                                        if (permanent) listVm.evictContent(id)
                                        nav = detailOrigin ?: Nav.List
                                        detailOrigin = null
                                        Toast.success(
                                            t(if (permanent) "toast.deleted" else "toast.trashed"),
                                        )
                                    },
                                    onBack = {
                                        nav = detailOrigin ?: Nav.List
                                        detailOrigin = null
                                    },
                                    revision = saveRevision,
                                )

                                is Nav.Edit -> EditCipherScreen(
                                    vault = vault,
                                    cipherId = n.cipherId,
                                    viewModel = editVm,
                                    initialPrefill = savePrefill.takeIf { n.cipherId == null },
                                    onPrefillConsumed = onSavePrefillConsumed,
                                    onSaved = {
                                        saveRevision++
                                        notifyMutation()
                                        nav = if (n.cipherId == null) Nav.List else Nav.Detail(n.cipherId)
                                        Toast.success(t("toast.saved"))
                                    },
                                    onCancelled = { nav = if (n.cipherId == null) Nav.List else Nav.Detail(n.cipherId) },
                                )

                                Nav.Generator -> GeneratorScreen(
                                    viewModel = generatorVm,
                                    vault = vault,
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
                                        scope.launch { auth.forget() }
                                        Toast.success(t("toast.vaultRemoved"))
                                        // Prefer another discovered vault over
                                        // onboarding when one exists on disk.
                                        val others = runCatching {
                                            VaultRegistry.listVaults()
                                        }.getOrDefault(emptyList())
                                        val next = others.firstOrNull { it.path != path }
                                        if (next != null) {
                                            VaultRegistry.saveActiveVault(next.path)
                                            path = next.path
                                            hasVault = true
                                            Toast.success(t("toast.vaultSwitched", next.name))
                                        } else {
                                            VaultRegistry.saveActiveVault("")
                                            hasVault = false
                                        }
                                        unlocked = false
                                        nav = Nav.List
                                    },
                                    repo = repo,
                                    onOpenPeople = { nav = Nav.People },
                                    onOpenCollections = { nav = Nav.Collections },
                                    onSyncNudge = { notifyMutation() },
                                    onOpenActivity = { nav = Nav.Activity },
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

                                Nav.People -> PeopleScreen(
                                    vault = vault,
                                    repo = repo,
                                    onBack = { nav = Nav.Settings },
                                    onSyncNudge = { notifyMutation() },
                                )
                                Nav.Collections -> CollectionsScreen(
                                    vault = vault,
                                    repo = repo,
                                    onBack = { nav = Nav.Settings },
                                    onSyncNudge = { notifyMutation() },
                                )
                                Nav.Activity -> ActivityScreen(
                                    vault = vault,
                                    repo = repo,
                                    onBack = { nav = Nav.Settings },
                                )
                            }
                        }
                    }

                    RootStage.CreateVault -> CreateVaultScreen(
                        vaultPath = createTarget ?: path,
                        authViewModel = auth,
                        onCreated = {
                            val target = createTarget ?: return@CreateVaultScreen
                            path = target
                            app.baluard.mobile.platform.VaultRegistry.saveActiveVault(target)
                            hasVault = true
                            showCreate = false
                            createTarget = null
                            unlocked = true
                            nav = Nav.List
                            // Session adoption already happened in
                            // CreateVaultViewModel (auth.adopt); run the same
                            // post-unlock tail a vault switch gets.
                            auth.vault()?.let { v ->
                                scope.launch {
                                    runCatching { sync.onUnlock(v) }
                                    conflictVm.refresh(v)
                                }
                            }
                        },
                        onCancelled = {
                            val target = path
                            createTarget = null
                            scope.launch {
                                // Fast path: the live session is still
                                // unlocked, so restore without re-auth. Flip
                                // the stage flags together AFTER switchTo
                                // resolves so no unlock screen flashes.
                                if (auth.switchTo(target)) {
                                    unlocked = true
                                } else {
                                    runCatching { auth.lock() }
                                    conflictVm.clear()
                                    hasVault = AppPaths.vaultExists(target)
                                    unlocked = false
                                }
                                showCreate = false
                            }
                        },
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
                                    authViewModel = auth,
                                    vaultPath = pendingVaultPath ?: path,
                                    onEnrolled = {
                                        // Switch to the freshly enrolled vault.
                                        pendingVaultPath?.let { target ->
                                            path = target
                                            VaultRegistry.saveActiveVault(target)
                                        }
                                        hasVault = AppPaths.vaultExists(path)
                                        showOpen = false
                                        unlocked = true
                                        pendingVaultPath = null
                                    },
                                    onCancelled = { flowVm.backToRepos() },
                                )

                                repos != null || stage is ProviderFlowViewModel.Stage.Cloning -> RepoPickerScreen(
                                    vm = flowVm,
                                    repos = (repos?.repos ?: flowVm.repos),
                                    targetPathFor = { repo ->
                                        // Fresh directory per vault; remembered
                                        // so enrollment lands in the same one.
                                        AppPaths.nextVaultPath(
                                            repo.fullName.substringBefore('/'),
                                            repo.name,
                                        ).also { pendingVaultPath = it }
                                    },
                                    onCloneDone = { },
                                    onCancelled = { flowVm.backToPickProvider() },
                                )

                                else -> ProviderConnectScreen(
                                    vm = flowVm,
                                    onDeviceCodeStarted = { },
                                    onPatConnected = { },
                                    onCancelled = {
                                        // Same fast-path restore as the create
                                        // cancel: the current vault is still
                                        // unlocked in the session.
                                        val target = path
                                        scope.launch {
                                            if (auth.switchTo(target)) {
                                                unlocked = true
                                            } else {
                                                runCatching { auth.lock() }
                                                conflictVm.clear()
                                                hasVault = AppPaths.vaultExists(target)
                                                unlocked = false
                                            }
                                            showOpen = false
                                        }
                                    },
                                )
                            }
                        }
                    }

                    RootStage.Onboarding -> OnboardingScreen(
                        onCreateVault = {
                            // First run: the ceremony targets the default
                            // vault path; both entries flow through one var.
                            createTarget = path
                            showCreate = true
                        },
                        onOpenProvider = { showOpen = true },
                        onRecovered = { recovered ->
                            // G6: kit recovery on a fresh device — adopt
                            // the vault as active; the unlock stage takes
                            // it from here with the new password.
                            app.baluard.mobile.platform.VaultRegistry.saveActiveVault(recovered)
                            path = recovered
                            hasVault = true
                        },
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
            // Passkey fulfillment overlay: renders over the hub (or over the
            // unlock screen once a locked vault is unlocked — auth.vault()
            // gates it, so a locked mid-flow lock re-routes to unlock).
            passkeyRequest?.let { pk ->
                when (pk) {
                    is app.baluard.mobile.passkeys.PasskeyUiRequest.Create ->
                        auth.vault()?.let { vault ->
                            Surface(
                                modifier = Modifier.fillMaxSize().statusBarsPadding(),
                                color = MaterialTheme.colorScheme.background,
                            ) {
                                app.baluard.mobile.ui.passkey.PasskeyCreateScreen(
                                    vault = vault,
                                    request = pk,
                                    onResult = onPasskeyResult,
                                    onCancel = onPasskeyCancel,
                                )
                            }
                        }

                    is app.baluard.mobile.passkeys.PasskeyUiRequest.Assert ->
                        auth.vault()?.let { vault ->
                            Surface(
                                modifier = Modifier.fillMaxSize().statusBarsPadding(),
                                color = MaterialTheme.colorScheme.background,
                            ) {
                                app.baluard.mobile.ui.passkey.PasskeyAssertScreen(
                                    vault = vault,
                                    request = pk,
                                    onResult = onPasskeyResult,
                                    onCancel = onPasskeyCancel,
                                )
                            }
                        }

                    is app.baluard.mobile.passkeys.PasskeyUiRequest.Unlock -> Unit
                }
            }
            // Global toasts (desktop toastSignal parity): stacked bottom-center.
            ToastHost(
                Modifier
                    .align(Alignment.TopCenter)
                    .statusBarsPadding(),
            )
        } // Box
        } // Surface
    } // BaluardTheme
} // App

