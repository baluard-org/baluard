package xyz.actitud.baluard.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.sync.SyncConfig
import xyz.actitud.baluard.sync.SyncCoordinator
import xyz.actitud.baluard.i18n.t

/**
 * Settings screen with the sync toggles (plan §3.5) + a "Sync now" button.
 * Toggles mutate the [SettingsViewModel] config; the host persists to DataStore.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    vault: MobileVault,
    coordinator: SyncCoordinator,
    viewModel: SettingsViewModel,
    onBack: () -> Unit = {},
) {
    val config by viewModel.config.collectAsState()
    val status by viewModel.status.collectAsState()
    val scope = rememberCoroutineScope()

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(t("settings.title")) },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
                }
            },
        )
    }) { padding ->
        Column(modifier = Modifier.fillMaxWidth().padding(padding).padding(16.dp)) {
            Text(t("settings.sync"), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            ToggleRow(t("settings.syncOnUnlock"), config.syncOnUnlock) {
                viewModel.setSyncOnUnlock(it)
            }
            ToggleRow(t("settings.syncAfterChange"), config.syncAfterChange) {
                viewModel.setSyncAfterChange(it)
            }
            ToggleRow(t("settings.syncOnForeground"), config.syncOnForeground) {
                viewModel.setSyncOnForeground(it)
            }
            ToggleRow(
                t("settings.backgroundSync", config.backgroundIntervalMinutes),
                config.backgroundSyncEnabled,
            ) { viewModel.setBackgroundSync(it) }
            Text(
                t("settings.backgroundHint"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )
            ToggleRow(t("settings.wifiOnly"), config.wifiOnly) {
                viewModel.setWifiOnly(it)
            }

            HorizontalDivider(Modifier.padding(vertical = 16.dp))

            Text(
                t(
                    "settings.status",
                    status.state,
                    if (status.active) "" else t("settings.inactiveSuffix"),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(t("settings.pending", status.pending), style = MaterialTheme.typography.bodySmall)

            Spacer(Modifier.height(16.dp))
            Button(onClick = {
                scope.launch {
                    coordinator.pullNow(vault)
                    viewModel.refresh(vault, coordinator)
                }
            }) { Text(t("settings.syncNow")) }
        }
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    androidx.compose.foundation.layout.Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChecked)
    }
}
