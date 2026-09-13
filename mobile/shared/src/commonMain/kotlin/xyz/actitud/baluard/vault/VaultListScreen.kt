package xyz.actitud.baluard.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Inbox
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.detail.normalizeTypeTag
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.CategoryBadge
import xyz.actitud.baluard.ui.components.CipherAvatar

/**
 * Vault list styled after Baluard design language.
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
    revision: Int = 0,
    /** Sync-now button: run a full sync cycle + reload the list (plan §3.5). */
    onSyncNow: suspend () -> Unit = {},
    /** Runs once when the unlocked stage is entered (after unlock): sync
     * once + reload, so the list never races the Rust unlock-pull. */
    onStageEntry: suspend () -> Unit = {},
) {
    val query by listViewModel.query.collectAsState()
    val typeFilter by listViewModel.typeFilter.collectAsState()
    val tagFilter by listViewModel.tagFilter.collectAsState()
    val folderFilter by listViewModel.folderFilter.collectAsState()
    val favoritesOnly by listViewModel.favoritesOnly.collectAsState()
    val scope = rememberCoroutineScope()
    var refreshing by remember { mutableStateOf(false) }

    LaunchedEffect(vault, revision) { listViewModel.refresh(vault) }
    LaunchedEffect(vault) { onStageEntry() }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainer)
                                .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = t("vault.title"),
                            style = MaterialTheme.typography.titleLarge.copy(
                                fontWeight = FontWeight.Bold,
                                letterSpacing = (-0.3).sp,
                            ),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                actions = {
                    // Dedicated on-demand sync: a visible button beats the
                    // undiscoverable pull gesture it replaces. The icon
                    // swaps to a spinner while the sync runs.
                    Box(
                        modifier = Modifier
                            .padding(horizontal = 3.dp)
                            .size(36.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainer)
                            .border(
                                width = 1.dp,
                                color = MaterialTheme.colorScheme.outlineVariant,
                                shape = RoundedCornerShape(10.dp),
                            )
                            .clickable(enabled = !refreshing) {
                                scope.launch {
                                    refreshing = true
                                    try {
                                        onSyncNow()
                                    } finally {
                                        refreshing = false
                                    }
                                }
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        if (refreshing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Default.Sync,
                                contentDescription = t("settings.syncNow"),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    TopBarActionButton(
                        icon = Icons.Default.Add,
                        contentDescription = t("vault.addEntry"),
                        onClick = onAddEntry,
                        highlight = true,
                    )
                    TopBarActionButton(
                        icon = Icons.Default.Password,
                        contentDescription = t("generator.title"),
                        onClick = onOpenGenerator,
                    )
                    TopBarActionButton(
                        icon = Icons.Default.Settings,
                        contentDescription = t("settings.title"),
                        onClick = onOpenSettings,
                    )
                    TopBarActionButton(
                        icon = Icons.Default.Lock,
                        contentDescription = t("vault.lockVault"),
                        onClick = {
                            scope.launch {
                                authViewModel.lock()
                                onLocked()
                            }
                        },
                    )
                },
            )
        },
    ) { padding ->
        Box {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(MaterialTheme.colorScheme.background),
        ) {
            // Search Input bar matching desktop styling
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { listViewModel.setQuery(it) },
                    placeholder = { Text(t("common.search")) },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                    trailingIcon = if (query.isNotEmpty()) {
                        {
                            IconButton(onClick = { listViewModel.setQuery("") }) {
                                Icon(
                                    imageVector = Icons.Default.Clear,
                                    contentDescription = t("common.clear"),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(16.dp),
                                )
                            }
                        }
                    } else null,
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = MaterialTheme.colorScheme.surface,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // Filter Chips
            FilterChipsRow(
                types = listViewModel.allTypes(),
                tags = listViewModel.allTags(),
                folders = listViewModel.allFolders(),
                typeFilter = typeFilter,
                tagFilter = tagFilter,
                folderFilter = folderFilter,
                favoritesOnly = favoritesOnly,
                onType = { listViewModel.setTypeFilter(if (typeFilter == it) null else it) },
                onTag = { listViewModel.setTagFilter(if (tagFilter == it) null else it) },
                onFolder = { listViewModel.setFolderFilter(if (folderFilter == it) null else it) },
                onFavorites = { listViewModel.setFavoritesOnly(it) },
            )

            val visible = listViewModel.filtered()

            if (visible.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .clip(RoundedCornerShape(18.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainer)
                                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(18.dp)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Default.Inbox,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(28.dp),
                            )
                        }
                        Spacer(Modifier.height(14.dp))
                        Text(
                            text = t("vault.empty"),
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = t("vault.noMatch"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(16.dp))
                        BaluardPrimaryButton(
                            text = t("vault.addEntry"),
                            onClick = onAddEntry,
                            modifier = Modifier.width(160.dp),
                            leadingIcon = Icons.Default.Add,
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(visible, key = { it.id }) { meta ->
                        CipherRowCard(
                            meta = meta,
                            onClick = { onCipherClick(meta.id) },
                            modifier = Modifier.animateItem(),
                        )
                    }
                    item {
                        Spacer(Modifier.height(16.dp))
                    }
                }
            }
        }
        }
    }
}

@Composable
private fun TopBarActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
    highlight: Boolean = false,
) {
    Box(
        modifier = Modifier
            .padding(horizontal = 3.dp)
            .size(36.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(
                if (highlight) MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
                else MaterialTheme.colorScheme.surfaceContainer,
            )
            .border(
                width = 1.dp,
                color = if (highlight) MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
                else MaterialTheme.colorScheme.outlineVariant,
                shape = RoundedCornerShape(10.dp),
            )
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = if (highlight) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun FilterChipsRow(
    types: List<String>,
    tags: List<String>,
    folders: List<xyz.actitud.baluard.data.MobileFolderInfo>,
    typeFilter: String?,
    tagFilter: String?,
    folderFilter: String?,
    favoritesOnly: Boolean,
    onType: (String) -> Unit,
    onTag: (String) -> Unit,
    onFolder: (String) -> Unit,
    onFavorites: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        FilterChip(
            selected = favoritesOnly,
            onClick = { onFavorites(!favoritesOnly) },
            label = { Text(t("vault.favorites")) },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Star,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                )
            },
            shape = RoundedCornerShape(8.dp),
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f),
                selectedLabelColor = MaterialTheme.colorScheme.primary,
            ),
        )
        types.forEach { wire ->
            val normalized = normalizeTypeTag(wire)
            FilterChip(
                selected = typeFilter == wire,
                onClick = { onType(wire) },
                label = { Text(t(typeLabelKey(normalized))) },
                shape = RoundedCornerShape(8.dp),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f),
                    selectedLabelColor = MaterialTheme.colorScheme.primary,
                ),
            )
        }
        folders.forEach { folder ->
            FilterChip(
                selected = folderFilter == folder.id,
                onClick = { onFolder(folder.id) },
                label = { Text(folder.name) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Folder,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                    )
                },
                shape = RoundedCornerShape(8.dp),
            )
        }
        tags.forEach { tag ->
            FilterChip(
                selected = tagFilter == tag,
                onClick = { onTag(tag) },
                label = { Text("#$tag") },
                shape = RoundedCornerShape(8.dp),
            )
        }
    }
}

@Composable
private fun CipherRowCard(
    meta: xyz.actitud.baluard.MobileCipherMeta,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.7f), RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CipherAvatar(
                name = meta.name,
                typeTag = meta.cipherType,
                size = 42.dp,
            )

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = meta.name,
                        style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                    )
                    if (meta.favorite) {
                        Icon(
                            imageVector = Icons.Default.Star,
                            contentDescription = t("vault.favorite"),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }

                meta.username?.let {
                    if (it.isNotBlank()) {
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                        )
                    }
                }
            }

            CategoryBadge(
                label = t(typeLabelKey(normalizeTypeTag(meta.cipherType))),
                typeTag = meta.cipherType,
            )

            Spacer(Modifier.width(6.dp))

            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
