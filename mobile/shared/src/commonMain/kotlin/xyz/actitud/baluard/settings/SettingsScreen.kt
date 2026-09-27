package xyz.actitud.baluard.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.TextButton
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.data.MobileSpaceSettings
import xyz.actitud.baluard.data.MobileSpaceStatus
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.toast.Toast
import xyz.actitud.baluard.data.vaultTimeoutLabel
import xyz.actitud.baluard.detail.str
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.AutofillRole
import xyz.actitud.baluard.platform.AutofillSuggestions
import xyz.actitud.baluard.platform.AccessibilityFill
import xyz.actitud.baluard.platform.Biometric
import xyz.actitud.baluard.platform.BrowserAutofillIntegration
import xyz.actitud.baluard.platform.ClipboardPrefs
import xyz.actitud.baluard.platform.removeVaultDirectory
import xyz.actitud.baluard.platform.ScreenshotPrefs
import xyz.actitud.baluard.platform.setSecureFlag
import xyz.actitud.baluard.platform.clipboardClearLabel
import xyz.actitud.baluard.platform.clipboardClearPresets
import xyz.actitud.baluard.sync.SyncCoordinator
import xyz.actitud.baluard.sync.SyncPhase
import xyz.actitud.baluard.sync.runSyncCycle
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardDivider
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import androidx.lifecycle.compose.LifecycleResumeEffect
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.LabeledPreset
import xyz.actitud.baluard.ui.components.PresetDropdown
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.components.ToggleRow

/**
 * Settings screen styled after Baluard design language.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    vault: MobileVault,
    coordinator: SyncCoordinator,
    viewModel: SettingsViewModel,
    vaultTimeoutToken: String,
    onVaultTimeoutChange: (String) -> Unit,
    vaultPath: String,
    authViewModel: AuthViewModel,
    onVaultRemoved: () -> Unit = {},
    repo: VaultRepository,
    onOpenPeople: () -> Unit = {},
    onOpenCollections: () -> Unit = {},
    onOpenActivity: () -> Unit = {},
    onBack: () -> Unit = {},
) {
    val biometric = remember { Biometric() }
    val config by viewModel.config.collectAsState()
    val status by viewModel.status.collectAsState()
    val scope = rememberCoroutineScope()

    // Sync-now feedback: shared runner choreography (spinner hold + terminal
    // beat + settle), same as the hub's sync button.
    var syncPhase by remember { mutableStateOf(SyncPhase.Idle) }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                title = t("settings.title"),
                onBack = onBack,
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Sync Status Overview Card
            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Default.CloudSync,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(22.dp),
                            )
                        }

                        Spacer(Modifier.width(12.dp))

                        Column {
                            Text(
                                text = t("settings.syncStatusTitle"),
                                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = t(
                                    "settings.status",
                                    status.state,
                                    if (status.active) "" else t("settings.inactiveSuffix"),
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(
                                if (status.active) MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f)
                                else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
                            )
                            .padding(horizontal = 8.dp, vertical = 3.dp),
                    ) {
                        Text(
                            text = if (status.active) t("settings.active") else t("settings.idle"),
                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                            color = if (status.active) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                Spacer(Modifier.height(12.dp))

                Text(
                    text = t("settings.pending", status.pending),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Spacer(Modifier.height(12.dp))

                BaluardPrimaryButton(
                    text = when (syncPhase) {
                        SyncPhase.Synced -> t("sync.synced")
                        SyncPhase.Offline -> t("sync.offline")
                        else -> t("settings.syncNow")
                    },
                    onClick = {
                        if (syncPhase == SyncPhase.Idle) {
                            scope.launch {
                                runSyncCycle(
                                    doPull = { coordinator.pullNow(vault) },
                                    afterPull = { runCatching { viewModel.refresh(vault, coordinator) } },
                                    setPhase = { syncPhase = it },
                                )
                            }
                        }
                    },
                    enabled = syncPhase != SyncPhase.Syncing,
                    loading = syncPhase == SyncPhase.Syncing,
                    leadingIcon = when (syncPhase) {
                        SyncPhase.Synced -> Icons.Default.Check
                        SyncPhase.Offline -> Icons.Default.CloudOff
                        else -> Icons.Default.Sync
                    },
                )
            }

            // Sync Preferences Section
            SectionCard(title = t("settings.sync")) {
                ToggleRow(t("settings.syncOnUnlock"), config.syncOnUnlock) {
                    viewModel.setSyncOnUnlock(it)
                }
                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                ToggleRow(t("settings.syncAfterChange"), config.syncAfterChange) {
                    viewModel.setSyncAfterChange(it)
                }
                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                ToggleRow(t("settings.syncOnForeground"), config.syncOnForeground) {
                    viewModel.setSyncOnForeground(it)
                }
                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                ToggleRow(
                    t("settings.backgroundSync", config.backgroundIntervalMinutes),
                    config.backgroundSyncEnabled,
                ) { viewModel.setBackgroundSync(it) }
                Text(
                    t("settings.backgroundHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 2.dp, bottom = 4.dp),
                )
                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                ToggleRow(t("settings.wifiOnly"), config.wifiOnly) {
                    viewModel.setWifiOnly(it)
                }
            }

            // Security Section
            SectionCard(title = t("settings.security")) {
                Text(
                    t("settings.autoLock"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
                PresetDropdown(
                    current = vaultTimeoutToken,
                    presets = VaultRepository.vaultTimeoutPresets.map { LabeledPreset(it.token, it.labelKey) },
                    onSelect = onVaultTimeoutChange,
                )
                Text(
                    t("settings.autoLockHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                // Website icons on new entries (fetch_favicons opt-in,
                // desktop SettingsModal parity; default off for privacy).
                var fetchFavicons by remember(vaultPath) { mutableStateOf(false) }
                var faviconsLoaded by remember(vaultPath) { mutableStateOf(false) }
                LaunchedEffect(vaultPath) {
                    val json = repo.getSettings(vault) ?: return@LaunchedEffect
                    fetchFavicons = runCatching {
                        (Json.parseToJsonElement(json) as? JsonObject).str("fetch_favicons") == "true"
                    }.getOrDefault(false)
                    faviconsLoaded = true
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = t("settings.favicons"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Switch(
                        checked = fetchFavicons,
                        enabled = faviconsLoaded,
                        onCheckedChange = { want ->
                            fetchFavicons = want
                            scope.launch {
                                val ok = repo.saveSettings(
                                    vault,
                                    """{"fetch_favicons": $want}""",
                                )
                                if (!ok) fetchFavicons = !want
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                            checkedTrackColor = MaterialTheme.colorScheme.primary,
                        ),
                    )
                }

                Text(
                    text = t("settings.faviconsHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                // Biometric quick unlock (per-vault). Disable always works;
                // enable runs the enroll ceremony with the KEK retained from
                // a biometric quick-unlock. Without it (password-unlock
                // session), the unlock screen's post-password offer is the
                // enable path — never a second password prompt here.
                if (biometric.isAvailable()) {
                    var biometricEnrolled by remember(vaultPath) { mutableStateOf(biometric.isEnrolled(vaultPath)) }
                    var biometricBusy by remember { mutableStateOf(false) }
                    var confirmDisable by remember { mutableStateOf(false) }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = t("settings.biometric"),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            if (!biometricEnrolled && authViewModel.sessionKek == null) {
                                Text(
                                    text = t("settings.biometric.enableHint"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Switch(
                            checked = biometricEnrolled,
                            enabled = !biometricBusy && (biometricEnrolled || authViewModel.sessionKek != null),
                            onCheckedChange = { want ->
                                when {
                                    !want -> confirmDisable = true
                                    else -> {
                                        val kek = authViewModel.sessionKek
                                        if (kek != null) {
                                            biometricBusy = true
                                            biometric.enroll(
                                                vaultKey = vaultPath,
                                                kek = kek,
                                                title = t("login.biometricTitle"),
                                                onSuccess = {
                                                    biometricBusy = false
                                                    biometricEnrolled = true
                                                },
                                                onError = { _, _ -> biometricBusy = false },
                                            )
                                        }
                                    }
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                                checkedTrackColor = MaterialTheme.colorScheme.primary,
                            ),
                        )
                    }

                    if (confirmDisable) {
                        AlertDialog(
                            onDismissRequest = { confirmDisable = false },
                            title = { Text(t("settings.biometric.disableTitle")) },
                            text = { Text(t("settings.biometric.disableBody")) },
                            confirmButton = {
                                TextButton(onClick = {
                                    confirmDisable = false
                                    biometric.disenroll(vaultPath)
                                    biometricEnrolled = false
                                }) {
                                    Text(t("settings.biometric.disableConfirm"), color = MaterialTheme.colorScheme.error)
                                }
                            },
                            dismissButton = {
                                TextButton(onClick = { confirmDisable = false }) {
                                    Text(t("common.cancel"))
                                }
                            },
                        )
                    }

                    BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                }

                // Clipboard auto-clear (device-local, desktop parity).
                val clipboardPrefs = remember { ClipboardPrefs() }
                var clipboardSeconds by remember { mutableStateOf(clipboardPrefs.loadSeconds()) }
                Text(
                    t("settings.clipboardClear"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
                PresetDropdown(
                    current = clipboardSeconds,
                    presets = clipboardClearPresets.map { LabeledPreset(it.seconds, it.labelKey) },
                    onSelect = {
                        clipboardSeconds = it
                        clipboardPrefs.saveSeconds(it)
                    },
                )
                Text(
                    t("settings.clipboardClearHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                // Allow screenshots (default off, fail secure). Toggling
                // applies the window flag live; the pref is re-read on the
                // next app start.
                val screenshotPrefs = remember { ScreenshotPrefs() }
                var allowScreenshots by remember { mutableStateOf(screenshotPrefs.allowScreenshots()) }
                ToggleRow(
                    t("settings.allowScreenshots"),
                    allowScreenshots,
                ) { allow ->
                    allowScreenshots = allow
                    screenshotPrefs.setAllowScreenshots(allow)
                    setSecureFlag(!allow)
                }
                Text(
                    t("settings.allowScreenshotsHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            // Autofill Section (Android only; iOS has no requestable role,
            // Phase 7). Status refreshes when the screen regains focus after
            // the user returns from the system provider picker.
            if (AutofillRole.isSupported()) {
                SectionCard(title = t("settings.autofillSection")) {
                    var roleEnabled by remember { mutableStateOf(AutofillRole.isEnabled()) }
                    LifecycleResumeEffect(Unit) {
                        roleEnabled = AutofillRole.isEnabled()
                        onPauseOrDispose { }
                    }

                    // Autofill services: mirrors the system provider state;
                    // flipping it opens the system picker.
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = t("settings.autofillServices"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        Switch(
                            checked = roleEnabled,
                            onCheckedChange = { AutofillRole.requestRole() },
                        )
                    }
                    Text(
                        t("settings.autofillServicesHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )

                    BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                    // Display autofill suggestions: inline chips or popup.
                    var inlineSuggestions by remember {
                        mutableStateOf(AutofillSuggestions.inlineEnabled())
                    }
                    Column(modifier = Modifier.padding(top = 6.dp)) {
                        Text(
                            text = t("settings.autofillSuggestions"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        PresetDropdown(
                            current = if (inlineSuggestions) "inline" else "popup",
                            presets = listOf(
                                LabeledPreset("inline", "settings.autofillSuggestionsInline"),
                                LabeledPreset("popup", "settings.autofillSuggestionsPopup"),
                            ),
                            onSelect = { choice ->
                                inlineSuggestions = choice == "inline"
                                AutofillSuggestions.setInlineEnabled(choice == "inline")
                            },
                            modifier = Modifier.padding(top = 6.dp),
                        )
                        Text(
                            t("settings.autofillSuggestionsHint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                    }

                    // Browser integrations: a live mirror of each browser's
                    // own third-party autofill switch; tapping opens that
                    // browser's settings. One row per installed browser.
                    val browsers = remember { BrowserAutofillIntegration.browsers() }
                    for (browser in browsers) {
                        BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                        var browserEnabled by remember(browser.id) {
                            mutableStateOf(browser.enabled == true)
                        }
                        LifecycleResumeEffect(browser.id) {
                            browserEnabled = BrowserAutofillIntegration.browsers()
                                .firstOrNull { it.id == browser.id }?.enabled == true
                            onPauseOrDispose { }
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = t("settings.browserIntegration." + browser.id),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurface,
                                )
                                Text(
                                    t("settings.browserIntegrationHint"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            }
                            Switch(
                                checked = browserEnabled,
                                onCheckedChange = { BrowserAutofillIntegration.openSettings(browser.id) },
                            )
                        }
                    }

                    // User-defined equivalent domain groups (Bitwarden
                    // equivalent-domains parity): domains in one group
                    // autofill each other. Stored in vault settings
                    // (encrypted, git-synced).
                    BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                    var domainGroups by remember(vaultPath) {
                        mutableStateOf<List<List<String>>>(emptyList())
                    }
                    LaunchedEffect(vaultPath) {
                        domainGroups = runCatching {
                            val json = repo.getSettings(vault) ?: return@runCatching emptyList()
                            val arr = (Json.parseToJsonElement(json) as? JsonObject)
                                ?.get("custom_equivalent_domains")
                                ?.let { it as? JsonArray }
                                ?: return@runCatching emptyList()
                            arr.mapNotNull { g ->
                                (g as? JsonArray)
                                    ?.mapNotNull { (it as? JsonPrimitive)?.content }
                                    ?.filter { it.isNotBlank() }
                                    ?.takeIf { it.size >= 2 }
                            }
                        }.getOrDefault(emptyList())
                    }
                    var showAddGroup by remember { mutableStateOf(false) }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = t("settings.equivalentDomainsTitle"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = { showAddGroup = true }) {
                            Text(t("settings.equivalentDomainsAdd"))
                        }
                    }
                    if (domainGroups.isEmpty()) {
                        Text(
                            t("settings.equivalentDomainsEmpty"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    for ((index, group) in domainGroups.withIndex()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = group.joinToString(", "),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = {
                                val next = domainGroups.toMutableList().apply { removeAt(index) }
                                domainGroups = next
                                scope.launch {
                                    repo.saveSettings(
                                        vault,
                                        buildJsonObject {
                                            put(
                                                "custom_equivalent_domains",
                                                JsonArray(next.map { g ->
                                                    JsonArray(g.map { JsonPrimitive(it) })
                                                }),
                                            )
                                        }.toString(),
                                    )
                                }
                            }) {
                                Text(t("common.delete"))
                            }
                        }
                    }
                    Text(
                        t("settings.equivalentDomainsHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                    if (showAddGroup) {
                        var groupInput by remember { mutableStateOf("") }
                        androidx.compose.material3.AlertDialog(
                            onDismissRequest = { showAddGroup = false },
                            title = { Text(t("settings.equivalentDomainsAdd")) },
                            text = {
                                androidx.compose.material3.OutlinedTextField(
                                    value = groupInput,
                                    onValueChange = { groupInput = it },
                                    singleLine = true,
                                )
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    val group: List<String> = groupInput.split(',')
                                        .map { entry ->
                                            entry.trim().lowercase()
                                                .removePrefix("https://").trimEnd('/')
                                        }
                                        .filter { entry -> entry.isNotBlank() && entry.contains('.') }
                                        .distinct()
                                    if (group.size >= 2) {
                                        val next: List<List<String>> = domainGroups + listOf(group)
                                        val groupJsons = next.map { g ->
                                            val entries = g.map { entry ->
                                                kotlinx.serialization.json.JsonPrimitive(entry)
                                            }
                                            kotlinx.serialization.json.JsonArray(entries)
                                        }
                                        val groupsJson =
                                            kotlinx.serialization.json.JsonArray(groupJsons)
                                        domainGroups = next
                                        scope.launch {
                                            repo.saveSettings(
                                                vault,
                                                buildJsonObject {
                                                    put("custom_equivalent_domains", groupsJson)
                                                }.toString(),
                                            )
                                        }
                                    }
                                    showAddGroup = false
                                }) { Text(t("common.save")) }
                            },
                            dismissButton = {
                                TextButton(onClick = { showAddGroup = false }) {
                                    Text(t("common.cancel"))
                                }
                            },
                        )
                    }

                    // App-to-web suggestions (path B trust-on-first-use):
                    // web-saved logins may fill inside a native app after
                    // the user trusts the (package, domain) pairing once.
                    // Opt-in, default off.
                    BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                    var suggestAppLogins by remember(vaultPath) { mutableStateOf(false) }
                    var trustedApps by remember(vaultPath) {
                        mutableStateOf<List<Pair<String, String>>>(emptyList())
                    }
                    var rejectedApps by remember(vaultPath) {
                        mutableStateOf<List<Pair<String, String>>>(emptyList())
                    }
                    // Re-read on every resume (review finding #2): trust and
                    // rejection decisions happen in the :autofill process,
                    // so in-memory state here goes stale across app
                    // switches. Stale writes would silently drop pairings.
                    val readAppTrust: () -> Unit = {
                        scope.launch {
                            val json = runCatching { repo.getSettings(vault) }.getOrNull()
                                ?: return@launch
                            val obj = Json.parseToJsonElement(json) as? JsonObject
                                ?: return@launch
                            suggestAppLogins =
                                (obj["suggest_app_logins"] as? JsonPrimitive)?.content == "true"
                            fun parsePairs(key: String): List<Pair<String, String>> =
                                (obj[key] as? JsonArray)?.mapNotNull { t ->
                                    val o = t as? JsonObject ?: return@mapNotNull null
                                    val p = (o["package"] as? JsonPrimitive)?.content
                                        ?: return@mapNotNull null
                                    val d = (o["domain"] as? JsonPrimitive)?.content
                                        ?: return@mapNotNull null
                                    p to d
                                } ?: emptyList()
                            trustedApps = parsePairs("trusted_app_packages")
                            rejectedApps = parsePairs("rejected_app_packages")
                        }
                    }
                    LaunchedEffect(vaultPath) { readAppTrust() }
                    LifecycleResumeEffect(vaultPath) {
                        readAppTrust()
                        onPauseOrDispose { }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = t("settings.suggestAppLogins"),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                t("settings.suggestAppLoginsHint"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 4.dp),
                            )
                        }
                        Switch(
                            checked = suggestAppLogins,
                            onCheckedChange = { on ->
                                suggestAppLogins = on
                                scope.launch {
                                    repo.saveSettings(
                                        vault,
                                        buildJsonObject {
                                            put("suggest_app_logins", JsonPrimitive(on))
                                        }.toString(),
                                    )
                                }
                            },
                        )
                    }
                    if (suggestAppLogins && trustedApps.isNotEmpty()) {
                        Text(
                            t("settings.trustedAppsTitle"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                        for ((index, pair) in trustedApps.withIndex()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = "${pair.first} / ${pair.second}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.weight(1f),
                                )
                                TextButton(onClick = {
                                    val next = trustedApps.toMutableList().apply {
                                        removeAt(index)
                                    }
                                    trustedApps = next
                                    scope.launch {
                                        repo.saveSettings(
                                            vault,
                                            buildJsonObject {
                                                put(
                                                    "trusted_app_packages",
                                                    JsonArray(next.map { p ->
                                                        buildJsonObject {
                                                            put("package", JsonPrimitive(p.first))
                                                            put("domain", JsonPrimitive(p.second))
                                                        }
                                                    }),
                                                )
                                            }.toString(),
                                        )
                                    }
                                }) {
                                    Text(t("common.delete"))
                                }
                            }
                        }
                    }
                    // Rejected pairings: "Not now" in the picker blocks the
                    // suggestion permanently (per design), so the user needs
                    // a recovery path (review finding #3). Removing a pair here
                    // lets the picker suggest it again.
                    if (suggestAppLogins && rejectedApps.isNotEmpty()) {
                        Text(
                            t("settings.rejectedAppsTitle"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                        for ((index, pair) in rejectedApps.withIndex()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = "${pair.first} / ${pair.second}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.weight(1f),
                                )
                                TextButton(onClick = {
                                    val next = rejectedApps.toMutableList().apply {
                                        removeAt(index)
                                    }
                                    rejectedApps = next
                                    scope.launch {
                                        repo.saveSettings(
                                            vault,
                                            buildJsonObject {
                                                put(
                                                    "rejected_app_packages",
                                                    JsonArray(next.map { p ->
                                                        buildJsonObject {
                                                            put("package", JsonPrimitive(p.first))
                                                            put("domain", JsonPrimitive(p.second))
                                                        }
                                                    }),
                                                )
                                            }.toString(),
                                        )
                                    }
                                }) {
                                    Text(t("common.delete"))
                                }
                            }
                        }
                    }

                    // Use accessibility (Phase 6.5): the quick-settings fill
                    // tile for apps that ignore normal autofill. Opt-in,
                    // default off, disclosed before enabling.
                    BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                    var a11yOn by remember { mutableStateOf(AccessibilityFill.enabled()) }
                    var showA11yDisclosure by remember { mutableStateOf(false) }
                    var a11ySystemOn by remember { mutableStateOf(AccessibilityFill.serviceEnabledInSystem()) }
                    LifecycleResumeEffect("a11y-system") {
                        a11ySystemOn = AccessibilityFill.serviceEnabledInSystem()
                        onPauseOrDispose { }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = t("settings.a11yTitle"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        Switch(
                            checked = a11yOn,
                            onCheckedChange = { want ->
                                if (want) {
                                    showA11yDisclosure = true
                                } else {
                                    AccessibilityFill.setEnabled(false)
                                    a11yOn = false
                                }
                            },
                        )
                    }
                    Text(
                        t("settings.a11ySummary"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                    if (a11yOn) {
                        if (!a11ySystemOn) {
                            BaluardPrimaryButton(
                                text = t("settings.a11yOpenSystem"),
                                onClick = { AccessibilityFill.openSystemA11ySettings() },
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                        Text(
                            t("settings.a11yTileHint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                    }

                    // Enable disclosure (out-of-card, same composable scope).
                    if (showA11yDisclosure) {
                        AlertDialog(
                            onDismissRequest = { showA11yDisclosure = false },
                            title = { Text(t("settings.a11yDisclosureTitle")) },
                            text = { Text(t("settings.a11yDisclosureBody")) },
                            confirmButton = {
                                TextButton(onClick = {
                                    AccessibilityFill.setEnabled(true)
                                    a11yOn = true
                                    AccessibilityFill.openSystemA11ySettings()
                                    showA11yDisclosure = false
                                }) { Text(t("settings.a11yDisclosureAccept")) }
                            },
                            dismissButton = {
                                TextButton(onClick = { showA11yDisclosure = false }) {
                                    Text(t("common.cancel"))
                                }
                            },
                        )
                    }
                }
            }

            // Vault Section: remove this device's copy (remote is kept).
            // §4.8-7: People & access entry — admin devices only. The admin
            // signal mirrors the desktop rule: any collections.list row
            // carrying access:"admin" means this device manages the space.
            var isAdminDevice by remember { mutableStateOf(false) }
            LaunchedEffect(vault) {
                isAdminDevice = repo.isAdminDevice(vault)
            }
            if (isAdminDevice) {
                SectionCard(title = t("people.title")) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenPeople() },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = t("people.entrySubtitle"),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
            if (isAdminDevice) {
                SectionCard(title = t("collections.title")) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenCollections() },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = t("collections.entrySubtitle"),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
            // Activity is per-device local data — every member gets it.
            SectionCard(title = t("activity.title")) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onOpenActivity() },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = t("activity.entrySubtitle"),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            if (isAdminDevice) {
                SectionCard(title = t("space.title")) {
                    val scope = rememberCoroutineScope()
                    var spaceSettings by remember(vault) { mutableStateOf<MobileSpaceSettings?>(null) }
                    var spaceBusy by remember(vault) { mutableStateOf(false) }
                    LaunchedEffect(vault) {
                        spaceSettings = repo.spaceSettingsGet(vault)
                    }

                    // Team mode (S3-7b): one-way upgrade. The daemon
                    // gates and re-checks everything; the UI only paves
                    // the path.
                    var spaceTeam by remember(vault) { mutableStateOf<MobileSpaceStatus?>(null) }
                    var teamBusy by remember(vault) { mutableStateOf(false) }
                    var showFlipConfirm by remember(vault) { mutableStateOf(false) }
                    var flipWord by remember(vault) { mutableStateOf("") }
                    LaunchedEffect(vault) {
                        spaceTeam = repo.spaceStatus(vault)
                    }

                    fun runPrepare() {
                        if (teamBusy) return
                        teamBusy = true
                        scope.launch {
                            try {
                                val r = repo.spacePrepare(vault)
                                spaceTeam = repo.spaceStatus(vault)
                                when {
                                    r == null -> Toast.error(t("error.generic"))
                                    r.missing > 0 -> Toast.error(t("space.teamMissing", r.missing.toString()))
                                    else -> Toast.success(t("space.teamPrepared"))
                                }
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error(t("error.generic"))
                            } finally {
                                teamBusy = false
                            }
                        }
                    }

                    fun runFlip() {
                        // D47: a typed-confirm guard needs a non-empty
                        // typed value, and the dialog stays open through
                        // the call so a failure is visible in place.
                        if (teamBusy || flipWord.trim() != "team") return
                        teamBusy = true
                        scope.launch {
                            try {
                                repo.spaceFlip(vault)
                                spaceTeam = repo.spaceStatus(vault)
                                Toast.success(t("space.teamDone"))
                                showFlipConfirm = false
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                // The core refusal is plain language;
                                // surface it instead of a generic error.
                                val raw = e.message ?: ""
                                val detail = if (raw.startsWith("detail=")) raw.removePrefix("detail=") else raw
                                Toast.error(detail.ifBlank { t("error.generic") })
                            } finally {
                                teamBusy = false
                            }
                        }
                    }

                    fun setSpace(
                        inviteAuthority: String? = null,
                        allowViewerExport: Boolean? = null,
                        guestEnabled: Boolean? = null,
                        trashPolicy: String? = null,
                    ) {
                        // Synchronous guard: launch dispatches, so a flag
                        // set inside the coroutine lets two rapid taps
                        // both through.
                        if (spaceBusy) return
                        if (inviteAuthority != null && spaceSettings?.inviteAuthority == inviteAuthority) return
                        if (trashPolicy != null && spaceSettings?.trashPolicy == trashPolicy) return
                        spaceBusy = true
                        scope.launch {
                            try {
                                repo.spaceSettingsSet(vault, inviteAuthority, allowViewerExport, guestEnabled, trashPolicy)
                                spaceSettings = repo.spaceSettingsGet(vault)
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error(t("error.generic"))
                            } finally {
                                spaceBusy = false
                            }
                        }
                    }

                    // Team mode status + upgrade path. Rendered
                    // unconditionally inside the admin card; gating the
                    // state-creating control on its own state deadlocks
                    // fresh vaults (the wave-23 lesson).
                    Text(t("space.teamLabel"), style = MaterialTheme.typography.bodyMedium)
                    if (spaceTeam?.flipped == true) {
                        Text(
                            text = t("space.teamOn"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        Text(
                            text = t("space.teamOff"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        val missing = spaceTeam?.missingWrapPubkey ?: 0
                        if (missing > 0) {
                            Text(
                                text = t("space.teamMissing", missing.toString()),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                enabled = !teamBusy && spaceTeam != null,
                                onClick = { runPrepare() },
                            ) {
                                Text(t("space.teamPrepare"))
                            }
                            OutlinedButton(
                                enabled = !teamBusy && spaceTeam?.prepared == true && missing == 0,
                                onClick = {
                                    flipWord = "" // no leak across dialog opens
                                    showFlipConfirm = true
                                },
                            ) {
                                Text(t("space.teamUpgrade"))
                            }
                        }
                    }
                    if (showFlipConfirm) {
                        AlertDialog(
                            onDismissRequest = { if (!teamBusy) showFlipConfirm = false },
                            title = { Text(t("space.teamConfirmTitle")) },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text(t("space.teamConfirmBody"))
                                    BaluardTextField(
                                        value = flipWord,
                                        onValueChange = { flipWord = it },
                                        label = t("space.teamConfirmWord"),
                                    )
                                }
                            },
                            confirmButton = {
                                TextButton(
                                    enabled = !teamBusy && flipWord.trim() == "team",
                                    onClick = { runFlip() },
                                ) { Text(t("space.teamUpgrade")) }
                            },
                            dismissButton = {
                                TextButton(enabled = !teamBusy, onClick = { showFlipConfirm = false }) {
                                    Text(t("common.cancel"))
                                }
                            },
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    // Who may invite members (admins+owner, or owner only).
                    Text(
                        text = t("space.inviteAuthorityLabel"),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = t("space.inviteAuthorityDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(inviteAuthority = "admins") },
                        ) {
                            Text(t("space.authorityAdmins"))
                        }
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(inviteAuthority = "owners") },
                        ) {
                            Text(t("space.authorityOwners"))
                        }
                    }
                    if (spaceSettings != null) {
                        Text(
                            text = t(
                                if (spaceSettings!!.inviteAuthority == "owners") {
                                    "space.authorityOwners"
                                } else {
                                    "space.authorityAdmins"
                                }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(t("space.viewerExportLabel"), style = MaterialTheme.typography.bodyMedium)
                            Text(
                                text = t("space.viewerExportDesc"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            enabled = !spaceBusy && spaceSettings != null,
                            checked = spaceSettings?.allowViewerExport == true,
                            onCheckedChange = { setSpace(allowViewerExport = it) },
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(t("space.guestLabel"), style = MaterialTheme.typography.bodyMedium)
                            Text(
                                text = t("space.guestDesc"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            enabled = !spaceBusy && spaceSettings != null,
                            checked = spaceSettings?.guestEnabled == true,
                            onCheckedChange = { setSpace(guestEnabled = it) },
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    // Who may trash entries (§6.5 trash_policy).
                    Text(t("space.trashPolicyLabel"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = t("space.trashPolicyDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(trashPolicy = "write_scope_can_trash") },
                        ) {
                            Text(t("space.trashWriteScope"))
                        }
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(trashPolicy = "admins_only") },
                        ) {
                            Text(t("space.trashAdminsOnly"))
                        }
                    }
                    if (spaceSettings != null) {
                        Text(
                            text = t(
                                if (spaceSettings!!.trashPolicy == "admins_only") {
                                    "space.trashAdminsOnly"
                                } else {
                                    "space.trashWriteScope"
                                }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    // Restore is admin-only in v1 — single-valued, shown
                    // read-only so the surface tells the whole truth.
                    Text(t("space.restorePolicyLabel"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = t("space.restorePolicyDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = t("space.restoreAdminsOnly"),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            SectionCard(title = t("settings.vaultSection")) {
                var confirmRemove by remember { mutableStateOf(false) }
                var removeError by remember { mutableStateOf<String?>(null) }
                Text(
                    t("settings.removeVaultHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = repo != null) { confirmRemove = true },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = t("settings.removeVault"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.weight(1f),
                    )
                }
                removeError?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }

                if (confirmRemove && repo != null) {
                    AlertDialog(
                        onDismissRequest = { confirmRemove = false },
                        title = { Text(t("settings.removeVaultTitle")) },
                        text = { Text(t("settings.removeVaultBody")) },
                        confirmButton = {
                            TextButton(onClick = {
                                confirmRemove = false
                                scope.launch {
                                    // Guard: only remove a fully synced vault
                                    // (idle + zero pending). Offline or dirty
                                    // means the remote may not have everything.
                                    val st = runCatching { repo.syncStatus(vault) }.getOrNull()
                                    if (st == null || st.pending > 0u || st.state != "idle") {
                                        removeError = t("settings.removeVaultPending")
                                        return@launch
                                    }
                                    authViewModel.lock()
                                    biometric.disenroll(vaultPath)
                                    if (removeVaultDirectory(vaultPath)) {
                                        onVaultRemoved()
                                    } else {
                                        removeError = t("settings.removeVaultFailed")
                                    }
                                }
                            }) {
                                Text(t("settings.removeVaultConfirm"), color = MaterialTheme.colorScheme.error)
                            }
                        },
                        dismissButton = {
                            TextButton(onClick = { confirmRemove = false }) {
                                Text(t("common.cancel"))
                            }
                        },
                    )
                }
            }

            // About & Architecture Section
            SectionCard(title = t("settings.aboutTitle")) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surface),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            text = t("settings.version"),
                            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = t("settings.aboutSubtitle"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}
