package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.i18n.t

/**
 * Provider picker + PAT entry (plan §5.2). GitHub and GitLab connect with
 * the browser device flow; Codeberg has no device flow, so it goes straight
 * to token entry. Every provider also accepts a personal access token.
 */
@Composable
fun ProviderConnectScreen(
    vm: ProviderFlowViewModel,
    onDeviceCodeStarted: () -> Unit,
    onPatConnected: () -> Unit,
    onCancelled: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var token by rememberSaveable { mutableStateOf("") }
    var showPat by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(t("provider.title"), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            t("provider.subtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))

        ProviderRow(t("provider.github"), MobileProvider.GIT_HUB, vm)
        Spacer(Modifier.height(8.dp))
        ProviderRow(t("provider.gitlab"), MobileProvider.GIT_LAB, vm)
        Spacer(Modifier.height(8.dp))
        ProviderRow(t("provider.codeberg"), MobileProvider.CODEBERG, vm)

        vm.error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        if (vm.busy) {
            Spacer(Modifier.height(16.dp))
            CircularProgressIndicator()
        } else if (showPat) {
            Spacer(Modifier.height(24.dp))
            OutlinedTextField(
                value = token,
                onValueChange = { token = it },
                label = { Text(t("provider.patLabel")) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { scope.launch { vm.connectPat(token); if (vm.stage is ProviderFlowViewModel.Stage.Repos) onPatConnected() } },
                enabled = token.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(t("provider.patConnect")) }
            TextButton(onClick = { showPat = false }) { Text(t("common.back")) }
        } else {
            Spacer(Modifier.height(16.dp))
            when (vm.provider) {
                MobileProvider.CODEBERG -> Button(
                    onClick = { showPat = true },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(t("provider.continuePat")) }
                else -> {
                    Button(
                        onClick = {
                            scope.launch {
                                vm.startDeviceFlow()
                                if (vm.stage is ProviderFlowViewModel.Stage.DeviceCode) onDeviceCodeStarted()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(t("provider.continueBrowser")) }
                    TextButton(onClick = { showPat = true }) { Text(t("provider.usePatInstead")) }
                }
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onCancelled) { Text(t("common.back")) }
        }
    }
}

@Composable
private fun ProviderRow(label: String, p: MobileProvider, vm: ProviderFlowViewModel) {
    val selected = vm.provider == p
    OutlinedButton(
        onClick = { vm.selectProvider(p) },
        modifier = Modifier.fillMaxWidth(),
        enabled = !vm.busy,
    ) {
        Text(if (selected) t("provider.selected", label) else label)
    }
}
