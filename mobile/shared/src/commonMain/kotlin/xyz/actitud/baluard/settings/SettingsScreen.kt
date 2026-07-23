package xyz.actitud.baluard.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
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
) {
    val config by viewModel.config.collectAsState()
    val status by viewModel.status.collectAsState()
    val scope = rememberCoroutineScope()

    Scaffold(topBar = { TopAppBar(title = { Text("Settings") }) }) { padding ->
        Column(modifier = Modifier.fillMaxWidth().padding(padding).padding(16.dp)) {
            Text("Sync", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            ToggleRow("Sync when I unlock the vault", config.syncOnUnlock) {
                viewModel.setSyncOnUnlock(it)
            }
            ToggleRow("Sync after every change I make", config.syncAfterChange) {
                viewModel.setSyncAfterChange(it)
            }
            ToggleRow("Sync when app returns to foreground", config.syncOnForeground) {
                viewModel.setSyncOnForeground(it)
            }
            ToggleRow(
                "Background sync (every ${config.backgroundIntervalMinutes} min)",
                config.backgroundSyncEnabled,
            ) { viewModel.setBackgroundSync(it) }
            Text(
                "Uses more battery. Most users don't need this.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )
            ToggleRow("Sync over Wi-Fi only (advisory)", config.wifiOnly) {
                viewModel.setWifiOnly(it)
            }

            HorizontalDivider(Modifier.padding(vertical = 16.dp))

            Text("Status: ${status.state}${if (status.active) "" else " (inactive)"}", style = MaterialTheme.typography.bodyMedium)
            Text("Pending: ${status.pending}", style = MaterialTheme.typography.bodySmall)

            Spacer(Modifier.height(16.dp))
            Button(onClick = {
                scope.launch {
                    coordinator.pullNow(vault)
                    viewModel.refresh(vault, coordinator)
                }
            }) { Text("Sync now") }
        }
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    androidx.compose.foundation.layout.Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    ) {
        Switch(checked = checked, onCheckedChange = onChecked)
        Spacer(Modifier.height(0.dp))
        Text(label, modifier = Modifier.padding(start = 12.dp))
    }
}
