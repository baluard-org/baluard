package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileRepo
import xyz.actitud.baluard.i18n.t

/**
 * Vault-repo picker + clone (plan §5.3). Lists only repos the runtime
 * detected as Baluard vaults. Selecting one clones it to the local vault
 * path (stage Cloning renders here: indeterminate progress + cancel, since
 * the FFI clone surfaces no percentage).
 */
@Composable
fun RepoPickerScreen(
    vm: ProviderFlowViewModel,
    repos: List<MobileRepo>,
    vaultPath: String,
    onCloneDone: () -> Unit,
    onCancelled: () -> Unit,
) {
    val scope = rememberCoroutineScope()

    if (vm.stage is ProviderFlowViewModel.Stage.Cloning) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(t("repo.cloning"), style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                t("repo.cloningHint"),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator()
            Spacer(Modifier.height(24.dp))
            Button(
                onClick = {
                    vm.cancelClone()
                    onCloneDone() // stage fell back to Repos on failure
                },
            ) { Text(t("common.cancel")) }
        }
        return
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.padding(24.dp)) {
            Text(t("repo.title"), style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                if (repos.isEmpty()) t("repo.empty") else t("repo.subtitle"),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            vm.error?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }

        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(repos, key = { it.fullName }) { repo ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            scope.launch {
                                vm.cloneRepo(repo, vaultPath)
                                if (vm.stage is ProviderFlowViewModel.Stage.Enroll) onCloneDone()
                            }
                        }
                        .padding(horizontal = 24.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(repo.fullName, style = MaterialTheme.typography.bodyLarge)
                        repo.vaultSlug?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                        }
                    }
                    if (repo.private) {
                        Text(t("repo.private"), style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }

        TextButton(
            onClick = onCancelled,
            modifier = Modifier.padding(horizontal = 24.dp),
        ) { Text(t("common.back")) }
    }
}
