package xyz.actitud.baluard.vault

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.i18n.t

/**
 * Vault list screen (Phase 3). Renders cipher metadata from the runtime index.
 * Tapping the lock icon locks the vault and returns to the unlock screen.
 *
 * Detail view (Phase 3 cipher detail for all 8 types) is a follow-up; this is
 * the list shell that proves the index read + render path.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultListScreen(
    vault: MobileVault,
    listViewModel: VaultListViewModel,
    authViewModel: AuthViewModel,
    onLocked: () -> Unit,
) {
    val query by listViewModel.query.collectAsState()
    val scope = rememberCoroutineScope()

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(t("vault.title")) },
            actions = {
                IconButton(onClick = {
                    scope.launch {
                        authViewModel.lock()
                        onLocked()
                    }
                }) {
                    Icon(Icons.Default.Lock, contentDescription = t("vault.lockVault"))
                }
            },
        )
    }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            OutlinedTextField(
                value = query,
                onValueChange = { listViewModel.setQuery(it) },
                label = { Text(t("common.search")) },
                singleLine = true,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(listViewModel.filtered(), key = { it.id }) { meta ->
                    CipherRow(meta)
                }
            }
            if (listViewModel.filtered().isEmpty()) {
                Text(
                    t("vault.empty"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(24.dp),
                )
            }
        }
    }
}

@Composable
private fun CipherRow(meta: xyz.actitud.baluard.MobileCipherMeta) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(meta.name, style = MaterialTheme.typography.bodyLarge)
        meta.username?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}
