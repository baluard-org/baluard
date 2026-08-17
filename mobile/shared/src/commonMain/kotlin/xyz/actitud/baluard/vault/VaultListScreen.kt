package xyz.actitud.baluard.vault

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.detail.normalizeTypeTag
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t

/**
 * Vault list (Phase 3 shell). Rows open the cipher detail; the top bar
 * reaches add-entry, the generator, and settings. Locking returns to the
 * unlock screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultListScreen(
    vault: MobileVault,
    listViewModel: VaultListViewModel,
    authViewModel: AuthViewModel,
    onLocked: () -> Unit,
    onCipherClick: (String) -> Unit = {},
    onAddEntry: () -> Unit = {},
    onOpenGenerator: () -> Unit = {},
    onOpenSettings: () -> Unit = {},
    /** Bumped by the caller after a save so the refresh effect re-fires. */
    revision: Int = 0,
) {
    val query by listViewModel.query.collectAsState()
    val typeFilter by listViewModel.typeFilter.collectAsState()
    val tagFilter by listViewModel.tagFilter.collectAsState()
    val favoritesOnly by listViewModel.favoritesOnly.collectAsState()
    val scope = rememberCoroutineScope()

    // Load on first composition; callers re-enter this screen after mutations,
    // which re-runs this effect and refreshes the list.
    LaunchedEffect(vault, revision) { listViewModel.refresh(vault) }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(t("vault.title")) },
            actions = {
                IconButton(onClick = onAddEntry) {
                    Icon(Icons.Default.Add, contentDescription = t("vault.addEntry"))
                }
                IconButton(onClick = onOpenGenerator) {
                    Icon(Icons.Default.Password, contentDescription = t("generator.title"))
                }
                IconButton(onClick = onOpenSettings) {
                    Icon(Icons.Default.Settings, contentDescription = t("settings.title"))
                }
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
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            )
            FilterChips(
                types = listViewModel.allTypes(),
                tags = listViewModel.allTags(),
                typeFilter = typeFilter,
                tagFilter = tagFilter,
                favoritesOnly = favoritesOnly,
                onType = { listViewModel.setTypeFilter(if (typeFilter == it) null else it) },
                onTag = { listViewModel.setTagFilter(if (tagFilter == it) null else it) },
                onFavorites = { listViewModel.setFavoritesOnly(it) },
            )
            val visible = listViewModel.filtered()
            if (visible.isEmpty()) {
                Text(
                    t("vault.empty"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(24.dp),
                )
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(visible, key = { it.id }) { meta ->
                    CipherRow(meta, onClick = { onCipherClick(meta.id) })
                }
            }
        }
    }
}

@Composable
private fun FilterChips(
    types: List<String>,
    tags: List<String>,
    typeFilter: String?,
    tagFilter: String?,
    favoritesOnly: Boolean,
    onType: (String) -> Unit,
    onTag: (String) -> Unit,
    onFavorites: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = favoritesOnly,
            onClick = { onFavorites(!favoritesOnly) },
            label = { Text(t("vault.favorites")) },
        )
        types.forEach { wire ->
            FilterChip(
                selected = typeFilter == wire,
                onClick = { onType(wire) },
                label = { Text(t(typeLabelKey(normalizeTypeTag(wire)))) },
            )
        }
        tags.forEach { tag ->
            FilterChip(
                selected = tagFilter == tag,
                onClick = { onTag(tag) },
                label = { Text(tag) },
            )
        }
    }
}

@Composable
private fun CipherRow(meta: xyz.actitud.baluard.MobileCipherMeta, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(meta.name, style = MaterialTheme.typography.bodyLarge)
        meta.username?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}
