package xyz.actitud.baluard.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.normalizeTypeTag
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.CipherRowCard
import xyz.actitud.baluard.ui.components.SyncIconButton

/**
 * Hub screen (Bitwarden-style): instead of a flat entry list, the home page
 * shows sectioned jump-off points — TOTP, Favorites (inline entries), Types,
 * Folders, Tags, and Hidden items (Archive/Trash) — each with live counts.
 * Search overrides the hub with flat results across active entries.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultHomeScreen(
    vault: MobileVault,
    listViewModel: VaultListViewModel,
    syncPhase: String,
    onSyncClick: () -> Unit,
    onAddEntry: () -> Unit = {},
    onOpenGenerator: () -> Unit = {},
    onOpenSettings: () -> Unit = {},
    onLock: () -> Unit = {},
    onOpenKind: (EntryListKind) -> Unit = {},
    onOpenTags: () -> Unit = {},
    onCipherClick: (String) -> Unit = {},
    revision: Int = 0,
) {
    val ciphers by listViewModel.ciphers.collectAsState()
    val folders by listViewModel.folders.collectAsState()
    val totp by listViewModel.totp.collectAsState()
    val archived by listViewModel.archived.collectAsState()
    val trash by listViewModel.trash.collectAsState()
    val query by listViewModel.query.collectAsState()

    val favorites = ciphers.filter { it.favorite }

    // Type rows: raw cipherType values as stored on the metas.
    val typeRows = listOf(
        "login", "card", "identity", "securenote", "sshkey", "bankaccount",
        "driverslicense", "passport",
    ).map { raw -> raw to ciphers.count { it.cipherType.lowercase() == raw } }
        .filter { (_, n) -> n > 0 }

    val tagCounts = ciphers.flatMap { it.tags }
        .groupingBy { it }.eachCount()
        .entries.sortedByDescending { it.value }

    LaunchedEffectHubLoader(vault, revision, listViewModel)

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(t("vault.title")) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                actions = {
                    SyncIconButton(phase = syncPhase, onClick = onSyncClick)
                    TopBarActionIcon(Icons.Default.Add, t("vault.addEntry"), onAddEntry)
                    TopBarActionIcon(Icons.Default.Password, t("generator.title"), onOpenGenerator)
                    TopBarActionIcon(Icons.Default.Settings, t("settings.title"), onOpenSettings)
                    TopBarActionIcon(Icons.Default.Lock, t("vault.lockVault"), onLock)
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState()),
        ) {
            // Search overrides the hub with flat results while typing.
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
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            if (query.isNotBlank()) {
                val results = listViewModel.filtered(ciphers)
                if (results.isEmpty()) {
                    HubEmptyText(t("vault.noResults"))
                } else {
                    results.forEach { meta ->
                        CipherRowCard(
                            meta = meta,
                            typeLabel = t(typeLabelKey(normalizeTypeTag(meta.cipherType))),
                            onClick = { onCipherClick(meta.id) },
                            modifier = Modifier
                                .padding(horizontal = 16.dp, vertical = 4.dp)
                                .fillMaxWidth(),
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                }
                return@Column
            }

            // ── TOTP ──
            HomeSectionHeader(t("home.totp"), totp.size)
            HomeRow(
                label = t("home.totpRow"),
                count = totp.size,
                icon = Icons.Default.Timer,
                onClick = { onOpenKind(EntryListKind.Totp) },
            )

            // ── Favorites (entries inline, capped) ──
            HomeSectionHeader(t("home.favorites"), favorites.size)
            favorites.take(25).forEach { meta ->
                CipherRowCard(
                    meta = meta,
                    typeLabel = t(typeLabelKey(normalizeTypeTag(meta.cipherType))),
                    onClick = { onCipherClick(meta.id) },
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .fillMaxWidth(),
                )
            }
            if (favorites.size > 25) {
                HomeRow(
                    label = t("home.viewAll", favorites.size),
                    count = favorites.size,
                    icon = null,
                    onClick = { onOpenKind(EntryListKind.Favorites) },
                )
            }
            if (favorites.isEmpty()) HubEmptyText(t("home.noneYet"))

            // ── Types ──
            HomeSectionHeader(t("home.types"), typeRows.size)
            typeRows.forEach { (raw, count) ->
                HomeRow(
                    label = t(typeLabelKey(normalizeTypeTag(raw))),
                    count = count,
                    icon = null,
                    onClick = { onOpenKind(EntryListKind.Type(raw)) },
                )
            }

            // ── Folders ──
            HomeSectionHeader(t("home.folders"), folders.size)
            folders.sortedBy { it.name.lowercase() }.forEach { folder ->
                val count = ciphers.count { it.folderId == folder.id }
                HomeRow(
                    label = folder.name,
                    count = count,
                    icon = null,
                    onClick = { onOpenKind(EntryListKind.Folder(folder.id)) },
                )
            }

            // ── Tags ── (single row: opens the tag list, like TOTP)
            HomeSectionHeader(t("home.tags"), tagCounts.size)
            HomeRow(
                label = t("home.allTags"),
                count = tagCounts.size,
                icon = null,
                onClick = onOpenTags,
            )

            // ── Hidden items ──
            HomeSectionHeader(t("home.hidden"), archived.size + trash.size)
            HomeRow(
                label = t("home.archive"),
                count = archived.size,
                icon = null,
                onClick = { onOpenKind(EntryListKind.Archive) },
            )
            HomeRow(
                label = t("home.trash"),
                count = trash.size,
                icon = null,
                onClick = { onOpenKind(EntryListKind.Trash) },
            )

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun TopBarActionIcon(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
) {
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
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun HomeSectionHeader(label: String, count: Int) {
    Text(
        text = "${label.uppercase()} ($count)",
        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, top = 18.dp, bottom = 6.dp),
    )
}

@Composable
private fun HomeRow(
    label: String,
    count: Int,
    icon: androidx.compose.ui.graphics.vector.ImageVector?,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(12.dp))
        }
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun HubEmptyText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

/** Hub-wide data loader: all five sets feed the counts and cards. */
@Composable
private fun LaunchedEffectHubLoader(vault: MobileVault, revision: Int, vm: VaultListViewModel) {
    androidx.compose.runtime.LaunchedEffect(vault, revision) { vm.refresh(vault) }
}

/** Tag list screen: all tags sorted by entry count, descending. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TagListScreen(
    listViewModel: VaultListViewModel,
    onTag: (String) -> Unit = {},
    onBack: () -> Unit = {},
) {
    val ciphers by listViewModel.ciphers.collectAsState()
    val counts = ciphers.flatMap { it.tags }
        .groupingBy { it }.eachCount()
        .entries.sortedByDescending { it.value }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(t("home.tags")) },
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
        if (counts.isEmpty()) {
            HubEmptyText(t("home.noneYet"))
            return@Scaffold
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState()),
        ) {
            counts.forEach { (tag, count) ->
                HomeRow(label = tag, count = count, icon = null, onClick = { onTag(tag) })
            }
        }
    }
}
