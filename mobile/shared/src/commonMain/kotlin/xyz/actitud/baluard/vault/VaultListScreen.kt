package xyz.actitud.baluard.vault

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Inbox
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Unarchive
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.normalizeTypeTag
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.CipherRowCard
import xyz.actitud.baluard.ui.toast.Toast
import xyz.actitud.baluard.ui.components.SyncIconButton

/**
 * Generic filtered entry list behind the home hub: renders the slice for
 * [kind] (TOTP, favorites, type, folder, tag, archive, trash) with search,
 * 25-item display chunks that extend as the user scrolls, and row actions
 * for the hidden lists (unarchive / restore).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryListScreen(
    kind: EntryListKind,
    vault: MobileVault,
    listViewModel: VaultListViewModel,
    syncPhase: String,
    onSyncClick: () -> Unit,
    onCipherClick: (String) -> Unit,
    onBack: () -> Unit = {},
    revision: Int = 0,
) {
    val ciphers by listViewModel.ciphers.collectAsState()
    val totp by listViewModel.totp.collectAsState()
    val archived by listViewModel.archived.collectAsState()
    val trash by listViewModel.trash.collectAsState()
    val folders by listViewModel.folders.collectAsState()
    val query by listViewModel.query.collectAsState()
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var confirmEmptyTrash by remember { mutableStateOf(false) }

    // Display chunk: the metadata set is fully in memory; pagination is a
    // rendering courtesy (25 first, +25 as the user approaches the end).
    var loaded by remember(kind) { mutableStateOf(25) }

    LaunchedEffect(vault, kind, revision) {
        when (kind) {
            EntryListKind.Totp -> listViewModel.loadTotp(vault)
            EntryListKind.Archive -> listViewModel.loadArchived(vault)
            EntryListKind.Trash -> listViewModel.loadTrash(vault)
            else -> listViewModel.refresh(vault)
        }
    }

    val base = remember(kind, ciphers, totp, archived, trash) {
        listViewModel.listFor(kind)
    }
    val q = query.trim()
    val visible = if (q.isEmpty()) {
        base
    } else {
        base.filter {
            it.name.contains(q, ignoreCase = true) ||
                (it.username?.contains(q, ignoreCase = true) ?: false)
        }
    }
    val shown = visible.take(loaded)

    // Extend the chunk when the user scrolls near the rendered end.
    LaunchedEffect(listState, visible.size) {
        snapshotFlow { listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0 }
            .collect { last ->
                if (visible.size > loaded && last >= loaded - 3) loaded += 25
            }
    }

    val title = when (kind) {
        EntryListKind.All -> t("home.allEntries")
        EntryListKind.Totp -> t("home.totpRow")
        EntryListKind.Favorites -> t("home.favorites")
        is EntryListKind.Type -> t(typeLabelKey(normalizeTypeTag(kind.tag)))
        is EntryListKind.Folder -> folders.firstOrNull { it.id == kind.id }?.name
            ?: t("home.noFolder")
        is EntryListKind.Tag -> kind.tag
        EntryListKind.Archive -> t("home.archive")
        EntryListKind.Trash -> t("home.trash")
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = t("common.back"),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                actions = {
                    SyncIconButton(phase = syncPhase, onClick = onSyncClick)
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
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
                        Icon(
                            imageVector = Icons.Default.Clear,
                            contentDescription = t("common.clear"),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .size(18.dp)
                                .clickable { listViewModel.setQuery("") },
                        )
                    }
                } else {
                    null
                },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            )

            if (kind == EntryListKind.Trash && visible.isNotEmpty()) {
                TextButton(
                    onClick = { confirmEmptyTrash = true },
                    modifier = Modifier
                        .align(Alignment.End)
                        .padding(horizontal = 16.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = t("list.emptyTrash"),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }

            if (visible.isEmpty()) {
                // Friendly per-section empty state instead of a blank screen.
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(
                        imageVector = when (kind) {
                            EntryListKind.Trash -> Icons.Default.Delete
                            EntryListKind.Archive -> Icons.Default.Unarchive
                            EntryListKind.Totp -> Icons.Default.Timer
                            else -> Icons.Default.Inbox
                        },
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.size(44.dp),
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = when (kind) {
                            EntryListKind.Archive -> t("home.emptyArchive")
                            EntryListKind.Trash -> t("home.emptyTrash")
                            EntryListKind.Totp -> t("home.emptyTotp")
                            else -> t("home.emptyGeneric")
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    )
                }
                return@Column
            }

            LazyColumn(state = listState) {
                items(
                    items = shown,
                    key = { it.id },
                    contentType = { "cipher_row" },
                ) { meta ->
                    CipherRowCard(
                        meta = meta,
                        typeLabel = t(typeLabelKey(normalizeTypeTag(meta.cipherType))),
                        onClick = { onCipherClick(meta.id) },
                        modifier = Modifier
                            .padding(horizontal = 16.dp, vertical = 4.dp)
                            .fillMaxWidth(),
                        trailing = when (kind) {
                            EntryListKind.Archive -> ({
                                IconButton(onClick = {
                                    scope.launch {
                                        if (listViewModel.unarchive(vault, meta.id)) {
                                            Toast.success(t("toast.unarchived"))
                                        } else {
                                            Toast.error(t("toast.actionFailed"))
                                        }
                                    }
                                }) {
                                    Icon(
                                        imageVector = Icons.Default.Unarchive,
                                        contentDescription = t("detail.unarchive"),
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                            })
                            EntryListKind.Trash -> ({
                                IconButton(onClick = {
                                    scope.launch {
                                        if (listViewModel.restore(vault, meta.id)) {
                                            Toast.success(t("toast.restored"))
                                        } else {
                                            Toast.error(t("toast.actionFailed"))
                                        }
                                    }
                                }) {
                                    Icon(
                                        imageVector = Icons.Default.Restore,
                                        contentDescription = t("detail.restore"),
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                            })
                            else -> ({})
                        },
                    )
                }
                if (visible.size > 25) {
                    item(key = "showing") {
                        Text(
                            text = t("list.showing", shown.size, visible.size),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp),
                        )
                    }
                }
            }
        }
    }

    if (confirmEmptyTrash) {
        AlertDialog(
            onDismissRequest = { confirmEmptyTrash = false },
            title = { Text(t("list.emptyTrashTitle")) },
            text = {
                Text(
                    t(
                        if (visible.size == 1) "list.emptyTrashBodyOne" else "list.emptyTrashBody",
                        visible.size,
                    ),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmEmptyTrash = false
                    scope.launch {
                        if (listViewModel.emptyTrash(vault)) {
                            Toast.success(t("toast.trashEmptied"))
                        } else {
                            Toast.error(t("toast.actionFailed"))
                        }
                    }
                }) {
                    Text(t("list.emptyTrash"), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmEmptyTrash = false }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }
}
