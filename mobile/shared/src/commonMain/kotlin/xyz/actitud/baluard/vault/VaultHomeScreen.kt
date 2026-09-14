package xyz.actitud.baluard.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.LocalOffer
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.normalizeTypeTag
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.BaluardBrandLock
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.CipherRowCard
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.components.SyncIconButton
import xyz.actitud.baluard.sync.SyncPhase
import xyz.actitud.baluard.ui.components.BaluardDivider
import xyz.actitud.baluard.ui.components.BaluardSearchField
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.detail.cipherTypeDebugTags
import xyz.actitud.baluard.platform.DiscoveredVault
import xyz.actitud.baluard.platform.VaultRegistry
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import xyz.actitud.baluard.ui.components.cipherTypeTheme

/**
 * Hub screen (Bitwarden-style): instead of a flat entry list, the home page
 * shows sectioned jump-off points — TOTP, Favorites (inline entries), Types,
 * Folders, Tags, and Hidden items (Archive/Trash) — each with live counts.
 * Search overrides the hub with flat results across active entries.
 * Sections use the app's boxed SectionCard language with branded badges.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultHomeScreen(
    vault: MobileVault,
    listViewModel: VaultListViewModel,
    syncPhase: SyncPhase,
    onSyncClick: () -> Unit,
    onAddEntry: () -> Unit = {},
    onOpenGenerator: () -> Unit = {},
    onOpenSettings: () -> Unit = {},
    onLock: () -> Unit = {},
    onOpenKind: (EntryListKind) -> Unit = {},
    onOpenTags: () -> Unit = {},
    onCipherClick: (String) -> Unit = {},
    vaultName: String,
    vaultPath: String,
    onSwitchVault: (String) -> Unit = {},
    onAddVault: () -> Unit = {},
    revision: Int = 0,
) {
    val ciphers by listViewModel.ciphers.collectAsState()
    val folders by listViewModel.folders.collectAsState()
    val totp by listViewModel.totp.collectAsState()
    val archived by listViewModel.archived.collectAsState()
    val trash by listViewModel.trash.collectAsState()
    val query by listViewModel.query.collectAsState()

    var switchOpen by remember { mutableStateOf(false) }

    val favorites = ciphers.filter { it.favorite }

    // Type rows: raw cipherType values as stored on the metas.
    // Type rows: debug-tag form of the cipher types (matches meta.cipherType).
    val typeRows = cipherTypeDebugTags
        .map { raw -> raw to ciphers.count { it.cipherType.lowercase() == raw } }
        .filter { (_, n) -> n > 0 }
    val tagCounts = ciphers.flatMap { it.tags }
        .groupingBy { it }.eachCount()
        .entries.sortedByDescending { it.value }

    LaunchedEffectHubLoader(vault, revision, listViewModel)

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                titleContent = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainer)
                                .border(
                                    width = 1.dp,
                                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f),
                                    shape = RoundedCornerShape(8.dp),
                                ),
                            contentAlignment = Alignment.Center,
                        ) {
                            BaluardBrandLock(modifier = Modifier.size(18.dp))
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
                actions = {
                    SyncIconButton(phase = syncPhase, onClick = onSyncClick)
                    TopBarActionIcon(Icons.Default.Add, t("vault.addEntry"), onAddEntry, highlight = true)
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
            // Vault switch bar (desktop VaultSwitcher parity): shows the
            // vault being viewed; tap to list and switch.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    // Distinct vault-context strip: the detail-panel tone —
                    // visibly lighter than both the surface header and the
                    // page background (the 10% lime wash went muddy on dark).
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .clickable { switchOpen = true }
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Default.Folder,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = vaultName,
                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                Icon(
                    imageVector = Icons.Default.SwapHoriz,
                    contentDescription = t("home.switchVault"),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp),
                )
            }

            if (switchOpen) {
                var discovered by remember { mutableStateOf<List<DiscoveredVault>>(emptyList()) }
                LaunchedEffect(Unit) {
                    discovered = VaultRegistry.listVaults()
                }
                androidx.compose.material3.AlertDialog(
                    onDismissRequest = { switchOpen = false },
                    title = { Text(t("home.vaults")) },
                    text = {
                        Column {
                            if (discovered.isEmpty()) {
                                Text(
                                    text = t("home.noneYet"),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            discovered.forEach { v ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            switchOpen = false
                                            if (v.path != vaultPath) onSwitchVault(v.path)
                                        }
                                        .padding(vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Folder,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(18.dp),
                                    )
                                    Spacer(Modifier.width(12.dp))
                                    Text(
                                        text = v.name,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        modifier = Modifier.weight(1f),
                                    )
                                    if (v.path == vaultPath) {
                                        Icon(
                                            imageVector = Icons.Default.Check,
                                            contentDescription = t("sync.synced"),
                                            tint = MaterialTheme.colorScheme.tertiary,
                                            modifier = Modifier.size(18.dp),
                                        )
                                    }
                                }
                            }
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 6.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                            )
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        switchOpen = false
                                        onAddVault()
                                    }
                                    .padding(vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Add,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                                Spacer(Modifier.width(12.dp))
                                Text(
                                    text = t("home.addVault"),
                                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
                    },
                    confirmButton = {
                        androidx.compose.material3.TextButton(onClick = { switchOpen = false }) {
                            Text(t("common.cancel"))
                        }
                    },
                )
            }

            // Search overrides the hub with flat results while typing.
            BaluardSearchField(
                value = query,
                onValueChange = { listViewModel.setQuery(it) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            )

            if (query.isNotBlank()) {
                val results = listViewModel.filtered(ciphers)
                if (results.isEmpty()) {
                    // Centered empty state (same language as the section
                    // empty states): icon + title + hint.
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 48.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .clip(RoundedCornerShape(16.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainer),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier.size(24.dp),
                            )
                        }
                        Spacer(Modifier.height(12.dp))
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
                    }
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
            SectionCard(
                title = "${t("home.totp")} (${totp.size})",
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                SectionLinkRow(
                    label = t("home.totpRow"),
                    count = totp.size,
                    icon = Icons.Default.Timer,
                    iconColor = MaterialTheme.colorScheme.primary,
                    onClick = { onOpenKind(EntryListKind.Totp) },
                )
            }

            Spacer(Modifier.height(14.dp))

            // ── Favorites (entries inline, capped) ──
            HomeSectionHeader(t("home.favorites"), favorites.size)
            if (favorites.isEmpty()) {
                SectionCard(
                    title = "",
                    modifier = Modifier.padding(horizontal = 16.dp),
                    contentPadding = PaddingValues(14.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Default.Star,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier.size(16.dp),
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = t("home.noneYet"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
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
                BaluardOutlinedButton(
                    text = t("home.viewAll", favorites.size),
                    onClick = { onOpenKind(EntryListKind.Favorites) },
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .fillMaxWidth(),
                )
            }

            Spacer(Modifier.height(14.dp))

            // ── Types ──
            SectionCard(
                title = "${t("home.types")} (${typeRows.size})",
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                typeRows.forEachIndexed { index, (raw, count) ->
                    val (icon, color) = cipherTypeTheme(raw)
                    SectionLinkRow(
                        label = t(typeLabelKey(normalizeTypeTag(raw))),
                        count = count,
                        icon = icon,
                        iconColor = color,
                        onClick = { onOpenKind(EntryListKind.Type(raw)) },
                    )
                    if (index < typeRows.size - 1) {
                        BaluardDivider(
                            modifier = Modifier.padding(start = 58.dp, end = 14.dp),
                            thickness = 0.7.dp,
                            alpha = 0.35f,
                        )
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Folders ──
            SectionCard(
                title = "${t("home.folders")} (${folders.size})",
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                val sorted = folders.sortedBy { it.name.lowercase() }
                sorted.forEachIndexed { index, folder ->
                    val count = ciphers.count { it.folderId == folder.id }
                    SectionLinkRow(
                        label = folder.name,
                        count = count,
                        icon = Icons.Default.Folder,
                        iconColor = MaterialTheme.colorScheme.secondary,
                        onClick = { onOpenKind(EntryListKind.Folder(folder.id)) },
                    )
                    if (index < sorted.size - 1) {
                        BaluardDivider(
                            modifier = Modifier.padding(start = 58.dp, end = 14.dp),
                            thickness = 0.7.dp,
                            alpha = 0.35f,
                        )
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Tags ── (single row: opens the tag list, like TOTP)
            SectionCard(
                title = "${t("home.tags")} (${tagCounts.size})",
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                SectionLinkRow(
                    label = t("home.allTags"),
                    count = tagCounts.size,
                    icon = Icons.Default.LocalOffer,
                    iconColor = Color(0xFF8B5CF6),
                    onClick = onOpenTags,
                )
            }

            Spacer(Modifier.height(14.dp))

            // ── Hidden items ──
            SectionCard(
                title = "${t("home.hidden")} (${archived.size + trash.size})",
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                SectionLinkRow(
                    label = t("home.archive"),
                    count = archived.size,
                    icon = Icons.Default.Archive,
                    iconColor = Color(0xFFD97706),
                    onClick = { onOpenKind(EntryListKind.Archive) },
                )
                BaluardDivider(
                    modifier = Modifier.padding(start = 58.dp, end = 14.dp),
                    thickness = 0.7.dp,
                    alpha = 0.35f,
                )
                SectionLinkRow(
                    label = t("home.trash"),
                    count = trash.size,
                    icon = Icons.Default.DeleteOutline,
                    iconColor = MaterialTheme.colorScheme.error,
                    onClick = { onOpenKind(EntryListKind.Trash) },
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/** Tap-through row inside a SectionCard: branded icon badge + label + count pill + chevron. */
@Composable
private fun SectionLinkRow(
    label: String,
    count: Int,
    icon: ImageVector,
    iconColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Leading rounded icon badge (32x32dp)
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(iconColor.copy(alpha = 0.14f))
                .border(
                    width = 1.dp,
                    color = iconColor.copy(alpha = 0.30f),
                    shape = RoundedCornerShape(8.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = iconColor,
                modifier = Modifier.size(16.dp),
            )
        }

        Spacer(Modifier.width(12.dp))

        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )

        // Count pill badge matching Baluard badge tokens
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                .border(
                    width = 0.5.dp,
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                    shape = RoundedCornerShape(6.dp),
                )
                .padding(horizontal = 8.dp, vertical = 2.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = count.toString(),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.width(8.dp))

        Icon(
            imageVector = Icons.Default.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            modifier = Modifier.size(16.dp),
        )
    }
}

@Composable
private fun TopBarActionIcon(
    icon: ImageVector,
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
private fun HomeSectionHeader(label: String, count: Int) {
    Text(
        text = "${label.uppercase()} ($count)",
        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, top = 18.dp, bottom = 6.dp),
    )
}

@Composable
private fun HubEmptyText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
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
            BaluardTopBar(
                title = t("home.tags"),
                onBack = onBack,
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
            SectionCard(
                title = t("home.tags"),
                modifier = Modifier.padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                counts.forEachIndexed { index, (tag, count) ->
                    SectionLinkRow(
                        label = tag,
                        count = count,
                        icon = Icons.Default.LocalOffer,
                        iconColor = Color(0xFF8B5CF6),
                        onClick = { onTag(tag) },
                    )
                    if (index < counts.size - 1) {
                        BaluardDivider(
                            modifier = Modifier.padding(start = 58.dp, end = 14.dp),
                            thickness = 0.7.dp,
                            alpha = 0.35f,
                        )
                    }
                }
            }
        }
    }
}
