package xyz.actitud.baluard.settings

import androidx.compose.foundation.Image
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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
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
import kotlinx.coroutines.CancellationException
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.JsonObject
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.MobileHealthReport
import xyz.actitud.baluard.data.MobileHealthFinding
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.data.MobileSpaceSettings
import xyz.actitud.baluard.data.MobileSpaceStatus
import xyz.actitud.baluard.data.MobilePendingOp
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.components.rememberShareOpenFlow
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
import xyz.actitud.baluard.platform.PickedFile
import xyz.actitud.baluard.platform.removeVaultDirectory
import xyz.actitud.baluard.platform.decodeImageBitmap
import xyz.actitud.baluard.platform.rememberImportFilePicker
import xyz.actitud.baluard.platform.rememberRecoverySheetSaver
import xyz.actitud.baluard.platform.ScreenshotPrefs
import xyz.actitud.baluard.PassphraseConfig
import xyz.actitud.baluard.detail.formatEpochDate
import xyz.actitud.baluard.platform.copyToClipboard
import xyz.actitud.baluard.platform.setSecureFlag
import xyz.actitud.baluard.platform.clipboardClearLabel
import xyz.actitud.baluard.platform.clipboardClearPresets
import xyz.actitud.baluard.sync.SyncCoordinator
import xyz.actitud.baluard.sync.SyncPhase
import xyz.actitud.baluard.sync.runSyncCycle
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardDivider
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import androidx.lifecycle.compose.LifecycleResumeEffect
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.LabeledPreset
import xyz.actitud.baluard.ui.components.PresetDropdown
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.components.ToggleRow

/** i18n key for a pending sensitive-op kind; unknown kinds fall
 * through to the raw identifier (t() renders unknown keys verbatim). */
internal fun s4OpLabel(kind: String): String = when (kind) {
    "rotate_root_key" -> "space.opRotate"
    "member_remove" -> "space.opRemove"
    "transfer_ownership" -> "space.opTransfer"
    "member_reset" -> "space.opReset"
    "space_migrate" -> "space.opMigrate"
    "ownership_claim" -> "space.opClaim"
    "quorum_lower" -> "space.opLower"
    "kit.replace" -> "space.opKitReplace"
    "kit.disable" -> "space.opKitDisable"
    else -> kind
}

/** Localized health-finding reason: core sends a machine kind plus the
 * number it parametrizes; unknown kinds fall back to the English text. */
internal fun healthReasonText(f: MobileHealthFinding): String = when (f.kind) {
    "short" -> t("settings.healthRShort", f.n ?: 0)
    "common" -> t("settings.healthRCommon")
    "same_char" -> t("settings.healthRSameChar")
    "sequential" -> t("settings.healthRSequential")
    "old" -> t("settings.healthROld", f.n ?: 0)
    "reused" -> t("settings.healthRReused", f.n ?: 0)
    else -> f.reason
}

/**
 * Settings screen styled after Baluard design language.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalEncodingApi::class)
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
    onSyncNudge: () -> Unit = {},
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
            // G16: Git-backup wizard (provider + optional PAT + repo
            // name; setup_sync creates-or-reuses the repo and pushes).
            var showGitBackup by remember { mutableStateOf(false) }
            var gitProvider by remember { mutableStateOf(MobileProvider.GIT_HUB) }
            var gitPat by remember { mutableStateOf("") }
            var gitRepo by remember { mutableStateOf("") }
            var gitBusy by remember { mutableStateOf(false) }
            // Custom remote (use my own server).
            var gitCustom by remember { mutableStateOf(false) }
            var gitCustomUrl by remember { mutableStateOf("") }
            var gitCustomToken by remember { mutableStateOf("") }
            var gitCustomUsername by remember { mutableStateOf("") }
            var gitCustomProbeMsg by remember { mutableStateOf<String?>(null) }
            var gitCustomTrustJson by remember { mutableStateOf<String?>(null) }
            var gitCustomChangedJson by remember { mutableStateOf<String?>(null) }
            var gitCustomOk by remember { mutableStateOf(false) }

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
                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                BaluardOutlinedButton(
                    text = t("settings.gitBackup"),
                    onClick = { showGitBackup = true },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    t("settings.gitBackupDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 2.dp),
                )
            }

            if (showGitBackup) {
                // The PAT is a secret: every close path scrubs the
                // fields so it never lingers in Compose state.
                // Candidate credentials for the probe, and the stored
                // payload for the custom confirm. The host strips scheme,
                // userinfo, path, and port — bound-host release compares
                // bare host names.
                fun gitCustomHost(): String {
                    val raw = gitCustomUrl.trim()
                    val afterScheme = raw.substringAfter("://", raw)
                    val afterUser = afterScheme.substringAfter("@", afterScheme)
                    val noPath = afterUser.substringBefore('/')
                    // Bracketed IPv6: the port split must not cut the address.
                    val hostPart = if (noPath.startsWith("[")) {
                        noPath.substringAfter('[').substringBefore(']')
                    } else {
                        noPath.substringBefore(':')
                    }
                    return hostPart.lowercase()
                }

                fun gitCredsJson(): String? {
                    if (gitCustomToken.isBlank() && gitCustomUsername.isBlank()) return null
                    return buildJsonObject {
                        put("host", JsonPrimitive(gitCustomHost()))
                        if (gitCustomToken.isNotBlank()) {
                            put("token", JsonPrimitive(gitCustomToken.trim()))
                        }
                        if (gitCustomUsername.isNotBlank()) {
                            put("username", JsonPrimitive(gitCustomUsername.trim()))
                        }
                    }.toString()
                }

                fun closeGitBackup() {
                    if (!gitBusy) {
                        gitPat = ""
                        gitRepo = ""
                        showGitBackup = false
                    }
                }
                AlertDialog(
                    onDismissRequest = { closeGitBackup() },
                    title = { Text(t("settings.gitBackup")) },
                    text = {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                            modifier = Modifier.verticalScroll(rememberScrollState()),
                        ) {
                            Text(
                                t("settings.gitBackupHelp"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                listOf(
                                    MobileProvider.GIT_HUB,
                                    MobileProvider.GIT_LAB,
                                    MobileProvider.CODEBERG,
                                ).forEach { p ->
                                    FilterChip(
                                        selected = gitProvider == p && !gitCustom,
                                        onClick = {
                                            gitCustom = false
                                            gitProvider = p
                                        },
                                        label = {
                                            Text(
                                                when (p) {
                                                    MobileProvider.GIT_HUB -> "GitHub"
                                                    MobileProvider.GIT_LAB -> "GitLab"
                                                    MobileProvider.CODEBERG -> "Codeberg"
                                                }
                                            )
                                        },
                                    )
                                }
                                FilterChip(
                                    selected = gitCustom,
                                    onClick = { gitCustom = true },
                                    label = { Text(t("settings.customChip")) },
                                )
                            }
                            if (gitCustom) {
                                Text(
                                    t("settings.customWarn"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    t("settings.customSshNote"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                OutlinedTextField(
                                    value = gitCustomUrl,
                                    onValueChange = {
                                        gitCustomUrl = it
                                        gitCustomOk = false
                                        gitCustomProbeMsg = null
                                    },
                                    label = { Text(t("settings.customUrl")) },
                                    singleLine = true,
                                    enabled = !gitBusy,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    OutlinedTextField(
                                        value = gitCustomToken,
                                        onValueChange = { gitCustomToken = it },
                                        label = { Text(t("settings.customToken")) },
                                        singleLine = true,
                                        enabled = !gitBusy,
                                        visualTransformation = PasswordVisualTransformation(),
                                        modifier = Modifier.weight(1f),
                                    )
                                    OutlinedTextField(
                                        value = gitCustomUsername,
                                        onValueChange = { gitCustomUsername = it },
                                        label = { Text(t("settings.customUsername")) },
                                        singleLine = true,
                                        enabled = !gitBusy,
                                        modifier = Modifier.weight(1f),
                                    )
                                }
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    TextButton(
                                        enabled = !gitBusy && gitCustomUrl.isNotBlank(),
                                        onClick = {
                                            scope.launch {
                                                gitBusy = true
                                                try {
                                                    val res =
                                                        repo?.gitProbe(
                                                            gitCustomUrl.trim(),
                                                            gitCredsJson(),
                                                        )
                                                    val obj =
                                                        Json.parseToJsonElement(res ?: "{}") as? JsonObject
                                                    val ok =
                                                        obj?.get("ok")?.jsonPrimitive
                                                            ?.content == "true"
                                                    if (ok) {
                                                        gitCustomOk = true
                                                        gitCustomTrustJson = null
                                                        gitCustomChangedJson = null
                                                        gitCustomProbeMsg =
                                                            t("settings.customProbeOk")
                                                    } else {
                                                        val kind =
                                                            obj?.get("kind")?.jsonPrimitive
                                                                ?.content ?: "unreachable"
                                                        val detail =
                                                            obj?.get("detail")?.jsonPrimitive
                                                                ?.content ?: ""
                                                        if (kind == "host-untrusted") {
                                                            gitCustomTrustJson = detail
                                                            gitCustomProbeMsg =
                                                                t("settings.customTrustAsk")
                                                        } else if (kind == "host-changed") {
                                                            gitCustomTrustJson = null
                                                            gitCustomChangedJson = detail
                                                            gitCustomProbeMsg =
                                                                t("settings.customChangedTitle")
                                                        } else {
                                                            gitCustomTrustJson = null
                                                            gitCustomChangedJson = null
                                                            gitCustomProbeMsg = detail
                                                        }
                                                    }
                                                } catch (e: kotlinx.coroutines.CancellationException) {
                                                    throw e
                                                } catch (e: Exception) {
                                                    gitCustomProbeMsg =
                                                        (e.message ?: "").removePrefix("detail=")
                                                }
                                                gitBusy = false
                                            }
                                        },
                                    ) { Text(t("settings.customProbe")) }
                                }
                                gitCustomProbeMsg?.let {
                                    Text(
                                        it,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                gitCustomTrustJson?.let { trustJson ->
                                    val obj =
                                        Json.parseToJsonElement(trustJson) as? JsonObject
                                    val inner =
                                        obj?.get("host_key_untrusted") as? JsonObject
                                    val fp =
                                        inner?.get("fingerprint") ?: obj?.get("fingerprint")
                                    Text(
                                        fp?.toString() ?: trustJson,
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    if (inner?.get("known_other_type")?.jsonPrimitive?.content == "true") {
                                        Text(
                                            t("settings.customTrustOtherType"),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error,
                                            modifier = Modifier.fillMaxWidth(),
                                        )
                                    }
                                    TextButton(
                                        enabled = !gitBusy,
                                        onClick = {
                                            scope.launch {
                                                gitBusy = true
                                                try {
                                                    val marker =
                                                        Json.parseToJsonElement(trustJson)
                                                            .jsonObject["host_key_untrusted"]
                                                    val attemptId =
                                                        marker?.jsonObject?.get("attempt_id")
                                                            ?.jsonPrimitive?.content
                                                    if (attemptId != null) {
                                                        repo?.gitHostkeyTrust(attemptId)
                                                        gitCustomTrustJson = null
                                                    }
                                                } catch (e: kotlinx.coroutines.CancellationException) {
                                                    throw e
                                                } catch (e: Exception) {
                                                    gitCustomProbeMsg =
                                                        (e.message ?: "").removePrefix("detail=")
                                                }
                                                gitBusy = false
                                            }
                                        },
                                    ) { Text(t("settings.customTrustCta")) }
                                }
                                gitCustomChangedJson?.let { changedJson ->
                                    val obj =
                                        Json.parseToJsonElement(changedJson) as? JsonObject
                                    val fp =
                                        (obj?.get("host_key_untrusted") as? JsonObject)?.get("fingerprint")
                                            ?: obj?.get("fingerprint")
                                    Text(
                                        t("settings.customChangedTitle"),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error,
                                    )
                                    Text(
                                        t("settings.customChangedBody"),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    Text(
                                        fp?.toString() ?: changedJson,
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                            } else {
                                OutlinedTextField(
                                    value = gitPat,
                                    onValueChange = { gitPat = it },
                                    label = { Text(t("settings.gitPat")) },
                                    supportingText = { Text(t("settings.gitPatHint")) },
                                    singleLine = true,
                                    enabled = !gitBusy,
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                OutlinedTextField(
                                    value = gitRepo,
                                    onValueChange = { gitRepo = it },
                                    label = { Text(t("settings.gitRepo")) },
                                    supportingText = { Text(t("settings.gitRepoHint")) },
                                    singleLine = true,
                                    enabled = !gitBusy,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                            OutlinedTextField(
                                value = gitPat,
                                onValueChange = { gitPat = it },
                                label = { Text(t("settings.gitPat")) },
                                supportingText = { Text(t("settings.gitPatHint")) },
                                singleLine = true,
                                enabled = !gitBusy,
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = gitRepo,
                                onValueChange = { gitRepo = it },
                                label = { Text(t("settings.gitRepo")) },
                                supportingText = { Text(t("settings.gitRepoHint")) },
                                singleLine = true,
                                enabled = !gitBusy,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(
                            enabled = !gitBusy,
                            onClick = {
                                gitBusy = true
                                scope.launch {
                                    try {
                                        if (gitCustom) {
                                            val payload = buildJsonObject {
                                                put("host", JsonPrimitive(gitCustomHost()))
                                                if (gitCustomToken.isNotBlank()) {
                                                    put("token", JsonPrimitive(gitCustomToken.trim()))
                                                }
                                                if (gitCustomUsername.isNotBlank()) {
                                                    put(
                                                        "username",
                                                        JsonPrimitive(gitCustomUsername.trim()),
                                                    )
                                                }
                                            }
                                            repo?.gitCredentialsSet(vault, payload.toString())
                                            repo?.setupSyncCustom(vault, gitCustomUrl.trim())
                                            gitCustomToken = ""
                                            gitCustomUrl = ""
                                            showGitBackup = false
                                            Toast.success(t("settings.customDone"))
                                            onSyncNudge()
                                            return@launch
                                        }
                                        if (gitPat.isNotBlank()) {
                                            repo?.connectPat(
                                                gitProvider,
                                                gitPat.trim(),
                                            )
                                        }
                                        val json = repo?.setupSync(
                                            vault,
                                            gitProvider,
                                            gitRepo.trim(),
                                        )
                                        val url = (json?.let {
                                            Json.parseToJsonElement(it) as? JsonObject
                                        })?.get("repo")?.jsonPrimitive?.content
                                        gitPat = ""
                                        gitRepo = ""
                                        showGitBackup = false
                                        Toast.success(
                                            t("settings.gitBackupDone", url ?: ""),
                                        )
                                        onSyncNudge()
                                    } catch (e: kotlinx.coroutines.CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        // The FFI prefixes every error with
                                        // "detail="; strip it like the other
                                        // surfaces do.
                                        val raw = e.message ?: ""
                                        Toast.error(
                                            raw.removePrefix("detail=").ifBlank { t("settings.gitBackupFailed") },
                                        )
                                    }
                                    gitBusy = false
                                }
                            },
                        ) { Text(t("common.continue")) }
                    },
                    dismissButton = {
                        TextButton(
                            enabled = !gitBusy,
                            onClick = { closeGitBackup() },
                        ) { Text(t("common.cancel")) }
                    },
                )
            }

            // Security Section
            // G19 health states (composable scope — the dialog renders
            // outside the security card).
            var healthOpen by remember { mutableStateOf(false) }
            var healthBusy by remember { mutableStateOf(false) }
            var health by remember { mutableStateOf<MobileHealthReport?>(null) }
            var healthErr by remember { mutableStateOf<String?>(null) }

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

                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                // G3: recovery-phrase rotation (D74 ceremony). The current
                // master password gates it; the new 24 words show once.
                var rotateOpen by remember { mutableStateOf(false) }
                var rotatePw by remember { mutableStateOf("") }
                var rotateErr by remember { mutableStateOf<String?>(null) }
                var rotateBusy by remember { mutableStateOf(false) }
                var rotatedWords by remember { mutableStateOf<List<String>?>(null) }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = t("settings.rotatePhrase"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = { rotateOpen = true; rotateErr = null }, enabled = !rotateBusy) {
                        Text(t("settings.rotatePhraseBtn"))
                    }
                }
                Text(
                    t("settings.rotatePhraseHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                if (rotateOpen && rotatedWords == null) {
                    AlertDialog(
                        onDismissRequest = { if (!rotateBusy) rotateOpen = false },
                        title = { Text(t("settings.rotatePhraseTitle")) },
                        text = {
                            Column {
                                Text(
                                    t("settings.rotatePhraseBody"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = rotatePw,
                                    onValueChange = { rotatePw = it },
                                    label = { Text(t("login.password")) },
                                    singleLine = true,
                                    visualTransformation = PasswordVisualTransformation(),
                                    isError = rotateErr != null,
                                    supportingText = { rotateErr?.let { Text(it) } },
                                )
                            }
                        },
                        confirmButton = {
                            TextButton(
                                enabled = !rotateBusy && rotatePw.isNotEmpty(),
                                onClick = {
                                    rotateBusy = true
                                    rotateErr = null
                                    scope.launch {
                                        try {
                                            val json = repo.rotateRecoveryPhrase(vault, rotatePw)
                                            val words = (Json.parseToJsonElement(json) as? JsonObject)
                                                ?.get("phrase")?.jsonPrimitive?.content
                                                ?.trim()?.split(Regex("\\s+"))
                                                .orEmpty()
                                            if (words.size == 24) {
                                                rotatedWords = words
                                                rotateOpen = false
                                                rotatePw = ""
                                            } else {
                                                rotateErr = t("settings.rotatePhraseBad")
                                            }
                                        } catch (e: kotlinx.coroutines.CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            rotateErr = e.message ?: t("settings.rotatePhraseBad")
                                        }
                                        rotateBusy = false
                                    }
                                },
                            ) { Text(t("common.continue")) }
                        },
                        dismissButton = {
                            TextButton(onClick = { rotateOpen = false }) { Text(t("common.cancel")) }
                        },
                    )
                }

                // Words-once display after a successful rotation.
                rotatedWords?.let { words ->
                    var copiedRotation by remember { mutableStateOf(false) }
                    AlertDialog(
                        onDismissRequest = {},
                        title = { Text(t("settings.rotatePhraseDoneTitle")) },
                        text = {
                            Column {
                                Text(
                                    t("settings.rotatePhraseDoneBody"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    words.chunked(2).forEachIndexed { rowIdx, pair ->
                                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                            pair.forEachIndexed { colIdx, w ->
                                                Text(
                                                    text = "${rowIdx * 2 + colIdx + 1}. $w",
                                                    style = MaterialTheme.typography.bodyMedium,
                                                    fontFamily = FontFamily.Monospace,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            Row {
                                TextButton(onClick = {
                                    copyToClipboard(words.joinToString(" "))
                                    copiedRotation = true
                                }) {
                                    Text(if (copiedRotation) t("common.copied") else t("recovery.copyPhrase"))
                                }
                                TextButton(onClick = { rotatedWords = null }) {
                                    Text(t("recovery.ack"))
                                }
                            }
                        },
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))

                // G19: password health check (vault.health) — a decrypting
                // pass; findings are read-only, search the hub for the row.
                // States live at composable scope: the dialog below sits
                // outside this card's lambda.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (!healthBusy) {
                                healthOpen = true
                                healthBusy = true
                                health = null
                                healthErr = null
                                scope.launch {
                                    runCatching { repo.healthReport(vault) }
                                        .onSuccess { health = it }
                                        .onFailure {
                                            healthErr = it.message
                                                ?.removePrefix("detail=")
                                                ?.ifBlank { t("error.generic") }
                                        }
                                    healthBusy = false
                                }
                            }
                        },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = t("settings.healthTitle"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            if (healthOpen) {
                AlertDialog(
                    onDismissRequest = { healthOpen = false },
                    title = { Text(t("settings.healthTitle")) },
                    text = {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.verticalScroll(rememberScrollState()),
                        ) {
                            when {
                                healthBusy -> Text(t("settings.healthChecking"))
                                healthErr != null -> Text(
                                    healthErr ?: t("error.generic"),
                                    color = MaterialTheme.colorScheme.error,
                                )
                                health?.isEmpty == true -> Text(t("settings.healthClean"))
                                health != null -> {
                                    val r = health!!
                                    val sections: List<Pair<String, List<MobileHealthFinding>>> = listOf(
                                        "settings.healthWeak" to r.weak,
                                        "settings.healthReused" to r.reused,
                                        "settings.healthOld" to r.old,
                                    )
                                    sections.forEach { (label, findings) ->
                                        if (findings.isNotEmpty()) {
                                            Text(
                                                t(label),
                                                style = MaterialTheme.typography.labelLarge,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                            findings.forEach { f ->
                                                Column {
                                                    Text(f.name, style = MaterialTheme.typography.bodyMedium)
                                                    Text(
                                                        healthReasonText(f),
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { healthOpen = false }) { Text(t("common.close")) }
                    },
                )
            }

            // G5: device fleet. Lost-phone response without a desktop.
            SectionCard(title = t("settings.fleetSection")) {
                var fleet by remember(vault) { mutableStateOf<List<JsonObject>>(emptyList()) }
                var thisDevice by remember(vault) { mutableStateOf("") }
                var revokeTarget by remember { mutableStateOf<JsonObject?>(null) }
                var fleetBusy by remember { mutableStateOf(false) }
                LaunchedEffect(vault) {
                    thisDevice = vault.deviceId()
                    runCatching {
                        val json = repo.devicesList(vault)
                        fleet = ((Json.parseToJsonElement(json) as? JsonObject)
                            ?.get("devices") as? JsonArray)
                            ?.mapNotNull { it as? JsonObject }
                            .orEmpty()
                    }
                }
                if (fleet.isEmpty()) {
                    Text(
                        t("settings.fleetEmpty"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                fleet.forEach { d ->
                    val id = d.get("device_id")?.jsonPrimitive?.content.orEmpty()
                    val name = d.get("name")?.jsonPrimitive?.content.orEmpty()
                    val enrolled = d.get("enrolled_at")?.jsonPrimitive?.content?.toLongOrNull()
                    val isThis = id == thisDevice
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isThis) t("settings.fleetThisDevice", name) else name,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            enrolled?.let {
                                Text(
                                    text = t("settings.fleetEnrolled", formatEpochDate(it)),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        if (!isThis) {
                            TextButton(onClick = { revokeTarget = d }, enabled = !fleetBusy) {
                                Text(t("settings.fleetRevoke"), color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                    if (d != fleet.last()) BaluardDivider(modifier = Modifier.padding(vertical = 4.dp))
                }
                Text(
                    t("settings.fleetHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                revokeTarget?.let { target ->
                    val tname = target.get("name")?.jsonPrimitive?.content.orEmpty()
                    AlertDialog(
                        onDismissRequest = { if (!fleetBusy) revokeTarget = null },
                        title = { Text(t("settings.fleetRevokeTitle")) },
                        text = { Text(t("settings.fleetRevokeBody", tname)) },
                        confirmButton = {
                            TextButton(enabled = !fleetBusy, onClick = {
                                fleetBusy = true
                                scope.launch {
                                    try {
                                        repo.deviceRevoke(vault, target.get("device_id")?.jsonPrimitive?.content.orEmpty())
                                        val json = repo.devicesList(vault)
                                        fleet = ((Json.parseToJsonElement(json) as? JsonObject)
                                            ?.get("devices") as? JsonArray)
                                            ?.mapNotNull { it as? JsonObject }
                                            .orEmpty()
                                        Toast.success(t("settings.fleetRevoked"))
                                    } catch (e: kotlinx.coroutines.CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Toast.error(e.message ?: t("settings.fleetFailed"))
                                    }
                                    fleetBusy = false
                                    revokeTarget = null
                                }
                            }) { Text(t("settings.fleetRevoke"), color = MaterialTheme.colorScheme.error) }
                        },
                        dismissButton = {
                            TextButton(onClick = { revokeTarget = null }) { Text(t("common.cancel")) }
                        },
                    )
                }
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

                    // Passkey provider (G10 §10): deep-link to the system
                    // default-credential-provider page. The service component
                    // is never toggled here — only the user can choose a
                    // provider, and disabling ours would remove Baluard from
                    // that registry invisibly.
                    if (xyz.actitud.baluard.platform.credentialProviderSupported) {
                        val context = androidx.compose.ui.platform.LocalContext.current
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(t("settings.passkeyProvider"), style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    t("settings.passkeyProviderHint"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            TextButton(onClick = {
                                runCatching {
                                    context.startActivity(
                                        android.content.Intent("android.settings.CREDENTIAL_PROVIDER_SETTINGS")
                                            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                                    )
                                }
                            }) { Text(t("settings.passkeyProviderOpen")) }
                        }
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
                        var addError by remember { mutableStateOf(false) }
                        androidx.compose.material3.AlertDialog(
                            onDismissRequest = { showAddGroup = false },
                            title = { Text(t("settings.equivalentDomainsAdd")) },
                            text = {
                                androidx.compose.foundation.layout.Column {
                                    androidx.compose.material3.OutlinedTextField(
                                        value = groupInput,
                                        onValueChange = { groupInput = it; addError = false },
                                        singleLine = true,
                                        isError = addError,
                                        supportingText = { Text(t("settings.equivalentDomainsAddHint")) },
                                    )
                                    if (addError) {
                                        Text(
                                            text = t("settings.equivalentDomainsAddError"),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    val group: List<String> = groupInput.split(',')
                                        .map { entry ->
                                            entry.trim().lowercase()
                                                .removePrefix("https://").removePrefix("http://")
                                                .substringBefore('/').trimEnd('/')
                                        }
                                        .filter { entry -> entry.isNotBlank() && entry.contains('.') }
                                        .distinct()
                                    // Fail visibly: fewer than two valid domains is a
                                    // user-input problem, never a silent no-op.
                                    if (group.size < 2) {
                                        addError = true
                                    } else {
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
                                        showAddGroup = false
                                    }
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
            var myRole by remember { mutableStateOf("viewer") }
            LaunchedEffect(vault) {
                myRole = repo.myRole(vault)
            }
            // Role-gated, not key-gated: on a flipped Space an admin
            // holds no Root Key, so holds_root is the wrong signal here.
            if (myRole == "owner" || myRole == "admin") {
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
            if (myRole == "owner" || myRole == "admin") {
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
            if (myRole == "owner" || myRole == "admin") {
                SectionCard(title = t("space.title")) {
                    val scope = rememberCoroutineScope()
                    var spaceSettings by remember(vault) { mutableStateOf<MobileSpaceSettings?>(null) }
                    var spaceBusy by remember(vault) { mutableStateOf(false) }
                    var pendingOps by remember(vault) { mutableStateOf(listOf<MobilePendingOp>()) }
                    // S4-6: advisory org policies (recommended settings).
                    var spacePolicies by remember(vault) { mutableStateOf(mapOf<String, String>()) }
                    LaunchedEffect(vault) {
                        spaceSettings = repo.spaceSettingsGet(vault)
                        pendingOps = repo.approvalsPending(vault)
                        spacePolicies = repo.policiesList(vault)
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
                                onSyncNudge()
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
                        joinApproval: String? = null,
                        quorumAdminOps: ULong? = null,
                        collectionCreateAuthority: String? = null,
                    ) {
                        // Synchronous guard: launch dispatches, so a flag
                        // set inside the coroutine lets two rapid taps
                        // both through.
                        if (spaceBusy) return
                        if (inviteAuthority != null && spaceSettings?.inviteAuthority == inviteAuthority) return
                        if (trashPolicy != null && spaceSettings?.trashPolicy == trashPolicy) return
                        if (joinApproval != null && spaceSettings?.joinApproval == joinApproval) return
                        if (quorumAdminOps != null && spaceSettings?.quorumAdminOps == quorumAdminOps.toInt()) return
                        if (collectionCreateAuthority != null && spaceSettings?.collectionCreateAuthority == collectionCreateAuthority) return
                        spaceBusy = true
                        scope.launch {
                            try {
                                repo.spaceSettingsSet(vault, inviteAuthority, allowViewerExport, guestEnabled, trashPolicy, joinApproval, quorumAdminOps, collectionCreateAuthority)
                                spaceSettings = repo.spaceSettingsGet(vault)
                                pendingOps = repo.approvalsPending(vault)
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

                    // G6: Space Recovery Kit. Family vaults carry one from
                    // creation; enabling over it (or disabling) may demand
                    // the fixed two-admin confirmation, which surfaces in
                    // the pending asks above.
                    var kitEnabled by remember(vault) { mutableStateOf<Boolean?>(null) }
                    var kitBusy by remember { mutableStateOf(false) }
                    var kitConfirm by remember { mutableStateOf<String?>(null) }
                    var kitWords by remember { mutableStateOf<List<String>?>(null) }
                    LaunchedEffect(vault) {
                        runCatching {
                            val json = repo.spaceKitStatus(vault)
                            kitEnabled = (Json.parseToJsonElement(json) as? JsonObject)
                                ?.get("enabled")?.jsonPrimitive?.content == "true"
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(t("space.kitLabel"), style = MaterialTheme.typography.bodyMedium)
                            Text(
                                text = t("space.kitDesc"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    // Replace re-runs enable (enable-over rotates the
                    // phrase behind the fixed threshold); Disable is a
                    // separate destructive affordance.
                    val kitRunEnable: () -> Unit = kitRunEnable@{
                        kitBusy = true
                        scope.launch {
                            try {
                                val json = repo.spaceKitEnable(vault)
                                val words = (Json.parseToJsonElement(json) as? JsonObject)
                                    ?.get("phrase")?.jsonPrimitive?.content
                                    ?.trim()?.split(Regex("\\s+")).orEmpty()
                                kitWords = if (words.size == 24) words else null
                                kitEnabled = true
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error(e.message ?: t("space.kitFailed"))
                            }
                            kitBusy = false
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(
                            enabled = !kitBusy && kitEnabled != null,
                            onClick = { kitRunEnable() },
                        ) {
                            Text(
                                when (kitEnabled) {
                                    true -> t("space.kitReplace")
                                    false -> t("space.kitEnable")
                                    null -> t("common.loading")
                                },
                            )
                        }
                        if (kitEnabled == true) {
                            TextButton(
                                enabled = !kitBusy,
                                onClick = { kitConfirm = "disable" },
                            ) {
                                Text(t("space.kitDisable"), color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                    if (kitEnabled == false) {
                        Text(
                            t("space.kitOffHint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    }
                    
                    if (kitConfirm == "disable") {
                        AlertDialog(
                            onDismissRequest = { if (!kitBusy) kitConfirm = null },
                            title = { Text(t("space.kitDisableTitle")) },
                            text = { Text(t("space.kitDisableBody")) },
                            confirmButton = {
                                TextButton(enabled = !kitBusy, onClick = {
                                    kitBusy = true
                                    scope.launch {
                                        try {
                                            repo.spaceKitDisable(vault)
                                            kitEnabled = false
                                            Toast.success(t("space.kitDisabled"))
                                        } catch (e: kotlinx.coroutines.CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            Toast.error(e.message ?: t("space.kitFailed"))
                                        }
                                        kitBusy = false
                                        kitConfirm = null
                                    }
                                }) { Text(t("space.kitDisable"), color = MaterialTheme.colorScheme.error) }
                            },
                            dismissButton = {
                                TextButton(onClick = { kitConfirm = null }) { Text(t("common.cancel")) }
                            },
                        )
                    }

                    kitWords?.let { words ->
                        AlertDialog(
                            onDismissRequest = {},
                            title = { Text(t("space.kitPhraseTitle")) },
                            text = {
                                Column {
                                    Text(
                                        t("space.kitPhraseBody"),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        words.chunked(2).forEachIndexed { rowIdx, pair ->
                                            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                                pair.forEachIndexed { colIdx, w ->
                                                    Text(
                                                        text = "${rowIdx * 2 + colIdx + 1}. $w",
                                                        style = MaterialTheme.typography.bodyMedium,
                                                        fontFamily = FontFamily.Monospace,
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    copyToClipboard(words.joinToString(" "))
                                    Toast.success(t("common.copied"))
                                }) { Text(t("recovery.copyPhrase")) }
                            },
                            dismissButton = {
                                TextButton(onClick = { kitWords = null }) { Text(t("common.done")) }
                            },
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
                    // How join asks are approved (§6.5 join_approval).
                    Text(t("space.joinApprovalLabel"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = t("space.joinApprovalDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(joinApproval = "manual") },
                        ) {
                            Text(t("space.joinManual"))
                        }
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(joinApproval = "code") },
                        ) {
                            Text(t("space.joinCode"))
                        }
                    }
                    if (spaceSettings != null) {
                        Text(
                            text = t(
                                if (spaceSettings!!.joinApproval == "code") {
                                    "space.joinCode"
                                } else {
                                    "space.joinManual"
                                }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    // How many admins must confirm sensitive ops
                    // (§6.5 quorum_admin_ops, decided 2026-09-27).
                    Text(t("space.quorumLabel"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = t("space.quorumDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(1UL, 2UL, 3UL).forEach { n ->
                            OutlinedButton(
                                enabled = !spaceBusy,
                                onClick = { setSpace(quorumAdminOps = n) },
                            ) {
                                Text(n.toString())
                            }
                        }
                    }
                    if (spaceSettings != null) {
                        Text(
                            text = t("space.quorumCurrent", spaceSettings!!.quorumAdminOps),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    // Who may create collections (§6.5, decided
                    // 2026-09-27): admins by default, editors optional.
                    Text(t("space.createAuthLabel"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = t("space.createAuthDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(collectionCreateAuthority = "admins") },
                        ) {
                            Text(t("space.createAdmins"))
                        }
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(collectionCreateAuthority = "editors") },
                        ) {
                            Text(t("space.createEditors"))
                        }
                    }
                    if (spaceSettings != null) {
                        Text(
                            text = t(
                                if (spaceSettings!!.collectionCreateAuthority == "editors") {
                                    "space.createEditors"
                                } else {
                                    "space.createAdmins"
                                }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    // S4-6: recommendations that DIFFER from the current
                    // value render as one hint block (a small screen shows
                    // what is worth acting on, not the full list).
                    val policyDiffs = spacePolicies.entries.mapNotNull { (key, rec) ->
                        val label = when (key) {
                            "space_invite_authority" -> t("space.inviteAuthorityLabel")
                            "allow_viewer_export" -> t("space.viewerExportLabel")
                            "guest_enabled" -> t("space.guestLabel")
                            "trash_policy" -> t("space.trashPolicyLabel")
                            "join_approval" -> t("space.joinApprovalLabel")
                            "quorum_admin_ops" -> t("space.quorumLabel")
                            "collection_create_authority" -> t("space.createAuthLabel")
                            else -> return@mapNotNull null
                        }
                        val current = when (key) {
                            "space_invite_authority" -> spaceSettings?.inviteAuthority
                            "allow_viewer_export" -> spaceSettings?.allowViewerExport?.toString()
                            "guest_enabled" -> spaceSettings?.guestEnabled?.toString()
                            "trash_policy" -> spaceSettings?.trashPolicy
                            "join_approval" -> spaceSettings?.joinApproval
                            "quorum_admin_ops" -> spaceSettings?.quorumAdminOps?.toString()
                            "collection_create_authority" -> spaceSettings?.collectionCreateAuthority
                            else -> null
                        }
                        // Render the recommendation through its existing
                        // chip label, never as a raw wire string.
                        val recLabel = when (rec) {
                            "admins" -> t("space.authorityAdmins")
                            "owners" -> t("space.authorityOwners")
                            "editors" -> t("space.createEditors")
                            "write_scope_can_trash" -> t("space.trashWriteScope")
                            "admins_only" -> t("space.trashAdminsOnly")
                            "manual" -> t("space.joinManual")
                            "code" -> t("space.joinCode")
                            "true" -> t("settings.enabled")
                            "false" -> t("settings.disabled")
                            else -> rec
                        }
                        if (current != null && current != rec) label to recLabel else null
                    }
                    if (policyDiffs.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(t("space.policyTitle"), style = MaterialTheme.typography.bodyMedium)
                        policyDiffs.forEach { (label, rec) ->
                            Text(
                                text = t("space.policyHint", "$label: $rec"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }

                    // Pending sensitive-op asks (visible when quorum > 1).
                    if (pendingOps.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(t("space.pendingTitle"), style = MaterialTheme.typography.bodyMedium)
                        pendingOps.forEach { op ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(t(s4OpLabel(op.kind)), style = MaterialTheme.typography.bodySmall)
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = t("space.pendingItem", op.approvals, op.required),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    // §13 review F1: confirming a pending
                                    // claim repeats the SAME ask — the row
                                    // carries the claimant id. A pending
                                    // transfer works the same way: the
                                    // owner initiates, an admin confirms
                                    // the named successor.
                                    if (op.kind == "ownership_claim" && op.claimantId != null) {
                                        TextButton(onClick = {
                                            scope.launch {
                                                try {
                                                    repo.memberClaim(vault, op.claimantId!!)
                                                    pendingOps = repo.approvalsPending(vault)
                                                } catch (e: Exception) {
                                                    Toast.error(e.message ?: t("error.generic"))
                                                }
                                            }
                                        }) {
                                            Text(t("people.approve"))
                                        }
                                    }
                                    if (op.kind == "kit.replace" || op.kind == "kit.disable") {
                                        TextButton(onClick = {
                                            scope.launch {
                                                try {
                                                    if (op.kind == "kit.replace") {
                                                        repo.spaceKitEnable(vault)
                                                        kitEnabled = true
                                                    } else {
                                                        repo.spaceKitDisable(vault)
                                                        kitEnabled = false
                                                    }
                                                    pendingOps = repo.approvalsPending(vault)
                                                    Toast.success(t("space.kitConfirmed"))
                                                } catch (e: kotlinx.coroutines.CancellationException) {
                                                    throw e
                                                } catch (e: Exception) {
                                                    Toast.error(e.message ?: t("space.kitFailed"))
                                                }
                                            }
                                        }) {
                                            Text(t("people.approve"))
                                        }
                                    }
                                    if (op.kind == "transfer_ownership" && op.transferTarget != null) {
                                        TextButton(onClick = {
                                            scope.launch {
                                                try {
                                                    repo.memberTransfer(vault, op.transferTarget!!)
                                                    pendingOps = repo.approvalsPending(vault)
                                                } catch (e: Exception) {
                                                    Toast.error(e.message ?: t("error.generic"))
                                                }
                                            }
                                        }) {
                                            Text(t("people.approve"))
                                        }
                                    }
                                }
                            }
                        }
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
            // ── Data: import / export (G2, one core parser set) ───────
            SectionCard(title = t("settings.dataSection")) {
                val importPicker = rememberImportFilePicker()
                val saver = rememberRecoverySheetSaver()
                val importFormats = listOf(
                    "baluard", "bw-json", "bw-csv", "chrome-csv", "firefox-csv",
                    "lastpass-csv", "1password-1pux", "1password-csv", "keepass-xml",
                )
                // Human labels per format id: raw enum strings never render.
                // Import and export need SEPARATE maps — "bw-csv" means
                // Bitwarden CSV on the import side but renders as
                // "Spreadsheet" on export.
                val formatLabels = mapOf(
                    "baluard" to "settings.formatBaluard",
                    "bw-json" to "settings.formatBwJson",
                    "bw-csv" to "settings.formatBwCsv",
                    "chrome-csv" to "settings.formatChromeCsv",
                    "firefox-csv" to "settings.formatFirefoxCsv",
                    "lastpass-csv" to "settings.formatLastpassCsv",
                    "1password-1pux" to "settings.format1password1pux",
                    "1password-csv" to "settings.format1passwordCsv",
                    "keepass-xml" to "settings.formatKeePassXml",
                )
                val exportLabels = mapOf(
                    "baluard" to "settings.exportBackup",
                    "bw-csv" to "settings.exportSpreadsheet",
                )
                var pendingImport by remember { mutableStateOf<PickedFile?>(null) }
                var importFormat by remember { mutableStateOf("baluard") }
                var importBusy by remember { mutableStateOf(false) }
                var exportDialog by remember { mutableStateOf(false) }
                var exportFormat by remember { mutableStateOf("baluard") }
                var exportBusy by remember { mutableStateOf(false) }

                // Encrypted backup (docs/plan-encrypted-backup.md §7): one
                // passphrase dialog serving both directions. Generated
                // 6-word default; the master password is never offered.
                val bakMagic = byteArrayOf(0x42, 0x4C, 0x44, 0x42, 0x41, 0x4B) // "BLDBAK"
                var backupMode by remember { mutableStateOf<String?>(null) }
                var backupPw by remember { mutableStateOf("") }
                var backupPwConfirm by remember { mutableStateOf("") }
                var backupPwSaved by remember { mutableStateOf(false) }
                var backupBusy by remember { mutableStateOf(false) }
                var encFile by remember { mutableStateOf<PickedFile?>(null) }

                // Master-password gate before ENCRYPTED EXPORT (§7: same
                // credential, not a new one; import stays ungated). Reuses
                // the detail-screen reprompt strings.
                var showReprompt by remember { mutableStateOf(false) }
                var repromptPw by remember { mutableStateOf("") }
                var repromptError by remember { mutableStateOf(false) }

                // G4: open a shared file someone sent (Settings entry;
                // the onboarding screen carries the pre-vault guest flow).
                val shareOpen = rememberShareOpenFlow(guestOnly = false, vault = vault, repo = repo)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !shareOpen.busy) { shareOpen.open() },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = t("share.openRow"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    text = t("share.openDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )

                // Import row (restored: the 3180802 share-open refactor
                // dropped it along with the export row, leaving the
                // dialogs orphaned and mobile unable to import at all).
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !importBusy && !exportBusy) {
                            importPicker(listOf("*/*")) { file ->
                                if (file != null) {
                                    val isEncBackup =
                                        file.bytes.size >= 6 && bakMagic.indices.all { file.bytes[it] == bakMagic[it] }
                                    when {
                                        // Encrypted container: the passphrase
                                        // dialog decides everything else.
                                        isEncBackup -> {
                                            encFile = file
                                            backupMode = "import"
                                        }
                                        // Auto-detect our own backup first: the
                                        // header identifies it with no collision
                                        // risk, so restoring a Baluard backup
                                        // never needs a format answer.
                                        file.bytes
                                            .decodeToString(0, minOf(file.bytes.size, 512))
                                            .contains("baluard.vault") -> {
                                            importFormat = "baluard"
                                            pendingImport = file
                                        }
                                        file.name.endsWith(".1pux", ignoreCase = true) -> {
                                            importFormat = "1password-1pux"
                                            pendingImport = file
                                        }
                                        file.name.endsWith(".json", ignoreCase = true) -> {
                                            importFormat = "bw-json"
                                            pendingImport = file
                                        }
                                        file.name.endsWith(".xml", ignoreCase = true) -> {
                                            importFormat = "keepass-xml"
                                            pendingImport = file
                                        }
                                        else -> {
                                            importFormat = "bw-csv"
                                            pendingImport = file
                                        }
                                    }
                                }
                            }
                        },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (importBusy) t("settings.importBusy") else t("settings.importTitle"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    text = t("settings.importDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )

                Spacer(Modifier.height(12.dp))

                // Export row: opens the format dialog (Baluard backup or
                // spreadsheet). The dialog carries the plaintext warning;
                // the viewer role is refused at the repo layer.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !importBusy && !exportBusy) { exportDialog = true },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (exportBusy) t("settings.exportBusy") else t("settings.exportTitle"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    text = t("settings.exportDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )

                Spacer(Modifier.height(12.dp))

                // Import: format confirmation once a file is picked (the
                // picker's extension guesses, the user confirms).
                pendingImport?.let { file ->
                    AlertDialog(
                        onDismissRequest = { pendingImport = null },
                        title = { Text(t("settings.importPickFormat")) },
                        text = {
                            Column(
                                modifier = Modifier.verticalScroll(rememberScrollState()),
                            ) {
                                Text(
                                    file.name,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                importFormats.forEach { fmt ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable { importFormat = fmt }
                                            .padding(vertical = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        RadioButton(
                                            selected = importFormat == fmt,
                                            onClick = null,
                                        )
                                        Text(
                                            t(formatLabels[fmt] ?: fmt),
                                            style = MaterialTheme.typography.bodyMedium,
                                        )
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            TextButton(
                                enabled = !importBusy,
                                onClick = {
                                    scope.launch {
                                        importBusy = true
                                        val raw = runCatching {
                                            repo.importData(vault, importFormat, file.bytes)
                                        }.getOrNull()
                                        importBusy = false
                                        pendingImport = null
                                        if (raw == null) {
                                            Toast.error(t("settings.importFailed"))
                                        } else {
                                            val s = runCatching {
                                                Json.parseToJsonElement(raw) as JsonObject
                                            }.getOrNull()
                                            val imported = (s?.get("imported") as? JsonPrimitive)?.content ?: "?"
                                            val skipped = (s?.get("skipped") as? JsonPrimitive)?.content ?: "?"
                                            Toast.success(t("settings.importDone", imported, skipped))
                                        }
                                    }
                                },
                            ) { Text(t("common.continue")) }
                        },
                        dismissButton = {
                            TextButton(onClick = { pendingImport = null }) { Text(t("common.cancel")) }
                        },
                    )
                }

                // Export: format choice + the plaintext warning. The bytes
                // ride the same SAF saver as the recovery sheet.
                if (exportDialog) {
                    AlertDialog(
                        onDismissRequest = { exportDialog = false },
                        title = { Text(t("settings.exportPickFormat")) },
                        text = {
                            Column {
                                Text(
                                    t("settings.exportWarn"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                )
                                Spacer(Modifier.height(8.dp))
                                listOf("baluard", "bw-csv").forEach { fmt ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable { exportFormat = fmt }
                                            .padding(vertical = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        RadioButton(
                                            selected = exportFormat == fmt,
                                            onClick = null,
                                        )
                                        Text(
                                            t(exportLabels[fmt] ?: fmt),
                                            style = MaterialTheme.typography.bodyMedium,
                                        )
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            TextButton(
                                enabled = !exportBusy,
                                onClick = {
                                    scope.launch {
                                        exportBusy = true
                                        val content = runCatching {
                                            repo.exportData(vault, exportFormat)
                                        }.getOrNull()
                                        exportBusy = false
                                        exportDialog = false
                                        if (content == null) {
                                            Toast.error(t("settings.exportFailed"))
                                        } else {
                                            val csv = exportFormat == "bw-csv"
                                            saver(
                                                content.encodeToByteArray(),
                                                if (csv) "text/csv" else "application/json",
                                                if (csv) "baluard-logins.csv" else "baluard-backup.json",
                                            ) { ok ->
                                                if (ok) Toast.success(t("settings.exportDone"))
                                            }
                                        }
                                    }
                                },
                            ) { Text(t("common.continue")) }
                        },
                        dismissButton = {
                            TextButton(onClick = { exportDialog = false }) { Text(t("common.cancel")) }
                        },
                    )
                }

                // Encrypted-backup passphrase dialog (§7). Export prefills a
                // generated 6-word passphrase and requires the saved
                // acknowledgment; import explains this is the backup's
                // password, not the master password.
                LaunchedEffect(backupMode) {
                    // Reset stale state on every open: a cancelled export
                    // must not leave a checked ack or half-typed confirm
                    // behind, and import must not inherit an export's
                    // generated passphrase.
                    backupPwConfirm = ""
                    backupPwSaved = false
                    if (backupMode == "export") {
                        repo?.generatePassphrase(
                            PassphraseConfig(
                                wordCount = 6u,
                                separator = "-",
                                upper = false,
                                number = false,
                                symbol = false,
                            ),
                        )?.getOrNull()?.let { backupPw = it }
                    } else if (backupMode == "import") {
                        backupPw = ""
                    }
                }
                if (backupMode != null) {
                    AlertDialog(
                        onDismissRequest = { if (!backupBusy) backupMode = null },
                        title = {
                            Text(
                                t(
                                    if (backupMode == "export") "settings.backupPassTitleExport"
                                    else "settings.backupPassTitleImport",
                                ),
                            )
                        },
                        text = {
                            Column {
                                Text(
                                    t(
                                        if (backupMode == "export") "settings.backupPassDesc"
                                        else "settings.backupPassImportDesc",
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = backupPw,
                                    onValueChange = { backupPw = it },
                                    singleLine = true,
                                    // Export shows the generated passphrase
                                    // for verification; import masks what
                                    // the user types.
                                    visualTransformation = if (backupMode == "export") {
                                        VisualTransformation.None
                                    } else {
                                        PasswordVisualTransformation()
                                    },
                                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                if (backupMode == "export") {
                                    Spacer(Modifier.height(6.dp))
                                    Row {
                                        TextButton(onClick = { copyToClipboard(backupPw) }) {
                                            Text(t("common.copy"))
                                        }
                                        TextButton(onClick = {
                                            scope.launch {
                                                repo?.generatePassphrase(
                                                    PassphraseConfig(
                                                        wordCount = 6u,
                                                        separator = "-",
                                                        upper = false,
                                                        number = false,
                                                        symbol = false,
                                                    ),
                                                )?.getOrNull()?.let { backupPw = it }
                                            }
                                        }) { Text(t("settings.backupRegenerate")) }
                                    }
                                    Spacer(Modifier.height(6.dp))
                                    OutlinedTextField(
                                        value = backupPwConfirm,
                                        onValueChange = { backupPwConfirm = it },
                                        singleLine = true,
                                        label = { Text(t("settings.backupPassConfirmLabel")) },
                                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    Spacer(Modifier.height(6.dp))
                                    Row(
                                        modifier = Modifier.clickable { backupPwSaved = !backupPwSaved },
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        RadioButton(selected = backupPwSaved, onClick = null)
                                        Text(
                                            t("settings.backupSavedAck"),
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            TextButton(
                                enabled = !backupBusy && backupPw.length >= 8 &&
                                    (backupMode != "export" || (backupPw == backupPwConfirm && backupPwSaved)),
                                onClick = {
                                    scope.launch {
                                        backupBusy = true
                                        if (backupMode == "export") {
                                            // CancellationException must
                                            // keep propagating: runCatching
                                            // would swallow coroutine cancel.
                                            val r = try {
                                                vault.exportEncryptedBackup(backupPw)
                                            } catch (e: CancellationException) {
                                                throw e
                                            } catch (_: Exception) {
                                                null
                                            }
                                            if (r == null) {
                                                backupBusy = false
                                                Toast.error(t("settings.backupFailed"))
                                            } else {
                                                val entries = r.entries.toString()
                                                backupMode = null
                                                saver(
                                                    r.container,
                                                    "application/octet-stream",
                                                    "baluard-backup-${formatEpochDate(System.currentTimeMillis() / 1000)}.bldbak",
                                                ) { ok ->
                                                    if (ok) Toast.success(t("settings.backupChecked", entries))
                                                }
                                                backupBusy = false
                                            }
                                        } else {
                                            val f = encFile
                                            val raw = f?.let {
                                                try {
                                                    vault.importEncryptedBackup(backupPw, it.bytes)
                                                } catch (e: CancellationException) {
                                                    throw e
                                                } catch (_: Exception) {
                                                    null
                                                }
                                            }
                                            backupBusy = false
                                            backupMode = null
                                            encFile = null
                                            if (raw == null) {
                                                Toast.error(t("settings.importFailed"))
                                            } else {
                                                val s = runCatching {
                                                    Json.parseToJsonElement(raw) as JsonObject
                                                }.getOrNull()
                                                val imported = (s?.get("imported") as? JsonPrimitive)?.content ?: "?"
                                                val skipped = (s?.get("skipped") as? JsonPrimitive)?.content ?: "?"
                                                Toast.success(t("settings.importDone", imported, skipped))
                                            }
                                        }
                                    }
                                },
                            ) {
                                Text(t(if (backupMode == "export") "settings.exportBackup" else "settings.import"))
                            }
                        },
                        dismissButton = {
                            TextButton(enabled = !backupBusy, onClick = { backupMode = null }) {
                                Text(t("common.cancel"))
                            }
                        },
                    )
                }

                if (showReprompt) {
                    AlertDialog(
                        onDismissRequest = {
                            showReprompt = false
                            repromptPw = ""
                            repromptError = false
                        },
                        title = { Text(t("detail.repromptTitle")) },
                        text = {
                            OutlinedTextField(
                                value = repromptPw,
                                onValueChange = {
                                    repromptPw = it
                                    repromptError = false
                                },
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                isError = repromptError,
                                supportingText = if (repromptError) {
                                    { Text(t("login.wrongPassword")) }
                                } else null,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                scope.launch {
                                    val ok = try {
                                        vault.repromptVerify(repromptPw)
                                        true
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (_: Exception) {
                                        false
                                    }
                                    if (ok) {
                                        showReprompt = false
                                        repromptPw = ""
                                        repromptError = false
                                        backupMode = "export"
                                    } else {
                                        repromptError = true
                                    }
                                }
                            }) { Text(t("common.continue")) }
                        },
                        dismissButton = {
                            TextButton(onClick = {
                                showReprompt = false
                                repromptPw = ""
                                repromptError = false
                            }) { Text(t("common.cancel")) }
                        },
                    )
                }
            }
            SectionCard(title = t("settings.vaultSection")) {
                var confirmRemove by remember { mutableStateOf(false) }
                var removeError by remember { mutableStateOf<String?>(null) }

                // G21: vault avatar — encrypted at rest by the core;
                // the file picker bytes ride base64 into vault.avatar.set.
                var avatarB64 by remember { mutableStateOf("") }
                var avatarBusy by remember { mutableStateOf(false) }
                var avatarErr by remember { mutableStateOf<String?>(null) }
                LaunchedEffect(vault) {
                    avatarB64 = runCatching { repo?.avatarGet(vault) }.getOrNull() ?: ""
                }
                val avatarPicker = rememberImportFilePicker()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    val decoded = remember(avatarB64) {
                        runCatching {
                            if (avatarB64.isEmpty()) null
                            else decodeImageBitmap(
                                kotlin.io.encoding.Base64.decode(avatarB64),
                            )
                        }.getOrNull()
                    }
                    if (decoded != null) {
                        Image(
                            bitmap = decoded,
                            contentDescription = t("settings.avatarTap"),
                            modifier = Modifier
                                .size(48.dp)
                                .clickable(enabled = !avatarBusy && repo != null) {
                                    avatarPicker(listOf("image/*")) { picked ->
                                        if (picked != null) pickAvatar(
                                            scope,
                                            picked,
                                            vault,
                                            repo,
                                            onDone = { b64 ->
                                                avatarErr = null
                                                avatarB64 = b64
                                            },
                                            onErr = {
                                                avatarErr = when (it) {
                                                    "bad-type" -> t("settings.avatarBadType")
                                                    "too-large" -> t("settings.avatarTooLarge")
                                                    else -> it.ifBlank { t("error.generic") }
                                                }
                                            },
                                            setBusy = { avatarBusy = it },
                                        )
                                    }
                                },
                        )
                    } else {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .clip(CircleShape)
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .clickable(enabled = !avatarBusy && repo != null) {
                                    avatarPicker(listOf("image/*")) { picked ->
                                        if (picked != null) pickAvatar(
                                            scope,
                                            picked,
                                            vault,
                                            repo,
                                            onDone = { b64 ->
                                                avatarErr = null
                                                avatarB64 = b64
                                            },
                                            onErr = {
                                                avatarErr = when (it) {
                                                    "bad-type" -> t("settings.avatarBadType")
                                                    "too-large" -> t("settings.avatarTooLarge")
                                                    else -> it.ifBlank { t("error.generic") }
                                                }
                                            },
                                            setBusy = { avatarBusy = it },
                                        )
                                    }
                                },
                        )
                    }
                    Column {
                        // Level 2 contact check: every member carries a
                        // verification code; guardians compare it out-of-band
                        // before granting admin rank.
                        var myContactCode by remember { mutableStateOf<String?>(null) }
                        LaunchedEffect(vault) {
                            runCatching {
                                val o = repo?.myContactCard(vault) ?: return@runCatching
                                val obj = kotlinx.serialization.json.Json.parseToJsonElement(o)
                                    as? kotlinx.serialization.json.JsonObject
                                myContactCode = (obj?.get("verification_code") as? kotlinx.serialization.json.JsonPrimitive)?.content
                                if (xyz.actitud.baluard.platform.e2eBuild) {
                                    (obj?.get("card") as? kotlinx.serialization.json.JsonPrimitive)?.content?.let {
                                        android.util.Log.e("ContactCard", "card=$it")
                                    }
                                }
                            }
                        }
                        myContactCode?.let { code ->
                            Text(
                                text = t("people.myCode") + " " + code,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text(
                            text = if (avatarB64.isEmpty()) t("settings.avatarTap") else t("settings.avatarChange"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        if (avatarB64.isNotEmpty()) {
                            Text(
                                text = t("settings.avatarRemove"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.clickable(enabled = !avatarBusy && repo != null) {
                                    avatarBusy = true
                                    scope.launch {
                                        runCatching { repo?.avatarSet(vault, "", "png") }
                                            .onSuccess { avatarB64 = "" }
                                            .onFailure { avatarErr = it.message }
                                        avatarBusy = false
                                    }
                                },
                            )
                        }
                        avatarErr?.let {
                            Text(
                                text = it,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                }

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

/** G21: encode a picked image and push it as the vault avatar. The
 *  extension was validated by the caller; the core enforces its own
 *  whitelist and the ~256KB decoded cap. */
private fun pickAvatar(
    scope: kotlinx.coroutines.CoroutineScope,
    picked: PickedFile,
    vault: xyz.actitud.baluard.MobileVault,
    repo: VaultRepository?,
    onDone: (String) -> Unit,
    onErr: (String) -> Unit,
    setBusy: (Boolean) -> Unit,
) {
    setBusy(true)
    scope.launch {
        try {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                // Downscale + recompress: phone photos arrive in the
                // megabytes and the core caps the stored avatar.
                val prepared = xyz.actitud.baluard.platform.prepareAvatarImage(picked.bytes)
                    ?: throw IllegalStateException("bad-type")
                val (bytes, ext) = prepared
                if (bytes.size > 262_144) throw IllegalStateException("too-large")
                @OptIn(ExperimentalEncodingApi::class)
                val b64 = kotlin.io.encoding.Base64.encode(bytes)
                repo?.avatarSet(vault, b64, ext)
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    onDone(b64)
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            val msg = e.message ?: ""
            withContext(kotlinx.coroutines.Dispatchers.Main) {
                onErr(
                    when (msg) {
                        "bad-type" -> "bad-type"
                        "too-large" -> "too-large"
                        else -> msg.removePrefix("detail=").ifBlank { "" }
                    },
                )
            }
        }
        setBusy(false)
    }
}
