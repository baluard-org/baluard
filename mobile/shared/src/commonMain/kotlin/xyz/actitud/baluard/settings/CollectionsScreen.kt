package xyz.actitud.baluard.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileCatalogInput
import xyz.actitud.baluard.data.MobileCollectionFull
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.toast.Toast

/**
 * Collections (§4.8-9): the mobile admin CRUD surface — mint, rename,
 * delete, and curate the request catalog. Grants live in PeopleScreen;
 * this screen owns the collection lifecycle. The daemon layer stays
 * the only validator.
 */
@Composable
fun CollectionsScreen(
    vault: xyz.actitud.baluard.MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var collections by remember { mutableStateOf<List<MobileCollectionFull>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var createName by remember { mutableStateOf("") }
    var showCreate by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<MobileCollectionFull?>(null) }
    var renameName by remember { mutableStateOf("") }
    var deleteTarget by remember { mutableStateOf<MobileCollectionFull?>(null) }
    var confirmCatalogClear by remember { mutableStateOf(false) }

    LaunchedEffect(vault) {
        collections = repo.listCollectionsFull(vault)
    }

    fun reload() {
        scope.launch { collections = repo.listCollectionsFull(vault) }
    }

    fun act(work: suspend () -> Boolean, done: String) {
        scope.launch {
            busy = true
            val ok = runCatching { work() }.getOrElse { false }
            busy = false
            if (ok) {
                Toast.success(done)
                reload()
            } else {
                Toast.error(t("error.generic"))
            }
        }
    }

    Scaffold(
        topBar = { BaluardTopBar(title = t("collections.title"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                SectionCard(title = t("collections.listTitle")) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (collections.isEmpty()) {
                            Text(
                                text = t("collections.empty"),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        collections.forEach { col ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = col.info.name,
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Text(
                                        text = t("collections.grantCount")
                                            .replace("{0}", col.grants.size.toString()),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                TextButton(
                                    enabled = !busy,
                                    onClick = {
                                        renameTarget = col
                                        renameName = col.info.name
                                    },
                                ) { Text(t("collections.rename")) }
                                TextButton(enabled = !busy, onClick = { deleteTarget = col }) {
                                    Text(t("collections.deleteAction"))
                                }
                            }
                        }
                        Button(
                            onClick = { showCreate = true },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(t("collections.createAction")) }
                    }
                }
            }
            item {
                SectionCard(title = t("collections.catalogTitle")) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = t("collections.catalogHint"),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    val entries = collections.map {
                                        MobileCatalogInput(collectionId = it.info.id, name = it.info.name)
                                    }
                                    act(
                                        { repo.collectionCatalogSet(vault, entries).isNotEmpty() },
                                        t("collections.catalogPublishedToast"),
                                    )
                                },
                                enabled = !busy && collections.isNotEmpty(),
                                modifier = Modifier.weight(1f),
                            ) { Text(t("collections.catalogPublish")) }
                            OutlinedButton(
                                onClick = { confirmCatalogClear = true },
                                enabled = !busy,
                                modifier = Modifier.weight(1f),
                            ) { Text(t("collections.catalogClear")) }
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        AlertDialog(
            onDismissRequest = { showCreate = false },
            title = { Text(t("collections.createAction")) },
            text = {
                BaluardTextField(
                    value = createName,
                    onValueChange = { createName = it },
                    label = t("collections.nameLabel"),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val name = createName.trim()
                        if (name.isEmpty()) return@TextButton
                        showCreate = false
                        createName = ""
                        act(
                            { repo.collectionCreate(vault, name).isNotEmpty() },
                            t("collections.createToast"),
                        )
                    },
                    enabled = createName.isNotBlank(),
                ) { Text(t("collections.createAction")) }
            },
            dismissButton = {
                TextButton(onClick = { showCreate = false }) { Text(t("common.close")) }
            },
        )
    }

    renameTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { renameTarget = null },
            title = { Text(t("collections.renameTitle")) },
            text = {
                BaluardTextField(
                    value = renameName,
                    onValueChange = { renameName = it },
                    label = t("collections.nameLabel"),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val name = renameName.trim()
                        if (name.isEmpty()) return@TextButton
                        renameTarget = null
                        act(
                            { repo.collectionRename(vault, target.info.id, name).isNotEmpty() },
                            t("collections.renameToast"),
                        )
                    },
                    enabled = !busy && renameName.isNotBlank(),
                ) { Text(t("collections.rename")) }
            },
            dismissButton = {
                TextButton(onClick = { renameTarget = null }) { Text(t("common.close")) }
            },
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(t("collections.deleteTitle")) },
            text = {
                Text(
                    t("collections.deleteBody").replace("{0}", target.info.name),
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    deleteTarget = null
                    act(
                        { repo.collectionDelete(vault, target.info.id).isNotEmpty() },
                        t("collections.deleteToast"),
                    )
                }) { Text(t("collections.deleteAction")) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text(t("common.close")) }
            },
        )
    }

    if (confirmCatalogClear) {
        AlertDialog(
            onDismissRequest = { confirmCatalogClear = false },
            title = { Text(t("collections.catalogClear")) },
            text = {
                Text(t("collections.catalogClearBody"), style = MaterialTheme.typography.bodyMedium)
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmCatalogClear = false
                    act(
                        { repo.collectionCatalogSet(vault, emptyList()).isNotEmpty() },
                        t("collections.catalogPublishedToast"),
                    )
                }) { Text(t("collections.catalogClear")) }
            },
            dismissButton = {
                TextButton(onClick = { confirmCatalogClear = false }) { Text(t("common.close")) }
            },
        )
    }
}
