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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.TextButton
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
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
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.data.vaultTimeoutLabel
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.Biometric
import xyz.actitud.baluard.platform.ClipboardPrefs
import xyz.actitud.baluard.platform.removeVaultDirectory
import xyz.actitud.baluard.platform.ScreenshotPrefs
import xyz.actitud.baluard.platform.setSecureFlag
import xyz.actitud.baluard.platform.clipboardClearLabel
import xyz.actitud.baluard.platform.clipboardClearPresets
import xyz.actitud.baluard.sync.SyncCoordinator
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.SectionCard

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
    repo: VaultRepository? = null,
    onBack: () -> Unit = {},
) {
    val biometric = remember { Biometric() }
    val config by viewModel.config.collectAsState()
    val status by viewModel.status.collectAsState()
    val scope = rememberCoroutineScope()

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(t("settings.title")) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
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
                    text = t("settings.syncNow"),
                    onClick = {
                        scope.launch {
                            coordinator.pullNow(vault)
                            viewModel.refresh(vault, coordinator)
                        }
                    },
                    leadingIcon = Icons.Default.Sync,
                )
            }

            // Sync Preferences Section
            SectionCard(title = t("settings.sync")) {
                ToggleRow(t("settings.syncOnUnlock"), config.syncOnUnlock) {
                    viewModel.setSyncOnUnlock(it)
                }
                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )
                ToggleRow(t("settings.syncAfterChange"), config.syncAfterChange) {
                    viewModel.setSyncAfterChange(it)
                }
                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )
                ToggleRow(t("settings.syncOnForeground"), config.syncOnForeground) {
                    viewModel.setSyncOnForeground(it)
                }
                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )
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
                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )
                ToggleRow(t("settings.wifiOnly"), config.wifiOnly) {
                    viewModel.setWifiOnly(it)
                }
            }

            // Security Section
            SectionCard(title = t("settings.security")) {
                var autoLockMenu by remember { mutableStateOf(false) }
                Text(
                    t("settings.autoLock"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
                Box(modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = { autoLockMenu = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(t(vaultTimeoutLabel(vaultTimeoutToken)))
                    }
                    DropdownMenu(
                        expanded = autoLockMenu,
                        onDismissRequest = { autoLockMenu = false },
                    ) {
                        VaultRepository.vaultTimeoutPresets.forEach { preset ->
                            DropdownMenuItem(
                                text = { Text(t(preset.labelKey)) },
                                onClick = {
                                    autoLockMenu = false
                                    onVaultTimeoutChange(preset.token)
                                },
                            )
                        }
                    }
                }
                Text(
                    t("settings.autoLockHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )

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

                    androidx.compose.material3.HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                    )
                }

                // Clipboard auto-clear (device-local, desktop parity).
                val clipboardPrefs = remember { ClipboardPrefs() }
                var clipboardSeconds by remember { mutableStateOf(clipboardPrefs.loadSeconds()) }
                var clipboardMenu by remember { mutableStateOf(false) }
                Text(
                    t("settings.clipboardClear"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
                Box(modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = { clipboardMenu = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(t(clipboardClearLabel(clipboardSeconds)))
                    }
                    DropdownMenu(
                        expanded = clipboardMenu,
                        onDismissRequest = { clipboardMenu = false },
                    ) {
                        clipboardClearPresets.forEach { preset ->
                            DropdownMenuItem(
                                text = { Text(t(preset.labelKey)) },
                                onClick = {
                                    clipboardMenu = false
                                    clipboardSeconds = preset.seconds
                                    clipboardPrefs.saveSeconds(preset.seconds)
                                },
                            )
                        }
                    }
                }
                Text(
                    t("settings.clipboardClearHint"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )

                androidx.compose.material3.HorizontalDivider(
                    modifier = Modifier.padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                )

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

            // Vault Section: remove this device's copy (remote is kept).
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

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        Switch(
            checked = checked,
            onCheckedChange = onChecked,
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                checkedTrackColor = MaterialTheme.colorScheme.primary,
            ),
        )
    }
}
