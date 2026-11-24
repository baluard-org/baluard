package app.baluard.mobile.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
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
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.MobileGroupInfo
import app.baluard.mobile.data.MobileMemberInfo
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.toast.Toast

/**
 * G13 admin surface: named member bundles for shared-folder grants.
 */
@Composable
fun GroupsScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
    onSyncNudge: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var groups by remember(vault) { mutableStateOf<List<MobileGroupInfo>>(emptyList()) }
    var members by remember(vault) { mutableStateOf<List<MobileMemberInfo>>(emptyList()) }
    var showCreate by remember { mutableStateOf(false) }
    var newName by remember { mutableStateOf("") }
    var editTarget by remember { mutableStateOf<MobileGroupInfo?>(null) }
    var editName by remember { mutableStateOf("") }
    var deleteArm by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    suspend fun refreshAll() {
        runCatching {
            groups = repo.listGroups(vault)
            members = repo.listMembers(vault)
        }.onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
    }

    LaunchedEffect(vault) { refreshAll() }

    Scaffold(
        topBar = { BaluardTopBar(title = t("people.groups"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "groups") {
                SectionCard(
                    title = t("people.groups"),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                        Text(
                            t("groups.subtitle"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(10.dp))
                        if (groups.isEmpty()) {
                            Text(
                                t("people.groupNone"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        groups.forEach { g ->
                            val names = g.memberIds.mapNotNull { mid ->
                                members.firstOrNull { it.id == mid }?.name
                            }
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        editTarget = g
                                        editName = g.name
                                        deleteArm = false
                                    }
                                    .padding(vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(g.name, style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        if (names.isEmpty()) t("people.groupNone")
                                        else names.joinToString(", "),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = {
                            newName = ""
                            showCreate = true
                        }) { Text(t("people.groupNew")) }
                    }
                }
            }
        }
    }

    if (showCreate) {
        AlertDialog(
            onDismissRequest = { if (!busy) showCreate = false },
            title = { Text(t("people.groupNew")) },
            text = {
                BaluardTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = t("people.groupNameLabel"),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(
                    enabled = !busy && newName.isNotBlank(),
                    onClick = {
                        scope.launch {
                            busy = true
                            runCatching { repo.groupCreate(vault, newName.trim()) }
                                .onSuccess {
                                    showCreate = false
                                    refreshAll()
                                    onSyncNudge()
                                }
                                .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                            busy = false
                        }
                    },
                ) { Text(t("people.groupCreate")) }
            },
            dismissButton = {
                TextButton(onClick = { showCreate = false }) { Text(t("common.cancel")) }
            },
        )
    }

    editTarget?.let { g ->
        val liveMembers = members.filter { !it.removed && !it.reset }
        AlertDialog(
            onDismissRequest = { if (!busy) editTarget = null },
            title = { Text(g.name) },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        BaluardTextField(
                            value = editName,
                            onValueChange = { editName = it },
                            label = t("people.groupNameLabel"),
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            enabled = !busy && editName.isNotBlank() && editName != g.name,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    runCatching { repo.groupRename(vault, g.id, editName.trim()) }
                                        .onSuccess {
                                            editTarget = null
                                            refreshAll()
                                            onSyncNudge()
                                        }
                                        .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                                    busy = false
                                }
                            },
                        ) { Text(t("people.groupSave")) }
                    }
                    Text(
                        t("people.groupMembers"),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val inGroup = g.memberIds.toSet()
                    liveMembers.forEach { m ->
                        val joined = m.id in inGroup
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(m.name, modifier = Modifier.weight(1f))
                            TextButton(
                                enabled = !busy,
                                onClick = {
                                    scope.launch {
                                        busy = true
                                        runCatching {
                                            if (joined) repo.groupMemberRemove(vault, g.id, m.id)
                                            else repo.groupMemberAdd(vault, g.id, m.id)
                                        }
                                            .onSuccess {
                                                editTarget = null
                                                refreshAll()
                                                onSyncNudge()
                                            }
                                            .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                                        busy = false
                                    }
                                },
                            ) {
                                Text(
                                    t(if (joined) "people.groupRemove" else "people.groupAddMember"),
                                    color = if (joined) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
                    }
                    TextButton(
                        enabled = !busy,
                        onClick = { deleteArm = true },
                    ) {
                        Text(t("people.groupDelete"), color = MaterialTheme.colorScheme.error)
                    }
                    if (deleteArm) {
                        Text(
                            t("people.groupDeleteConfirm", g.name),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        TextButton(
                            enabled = !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    runCatching { repo.groupDelete(vault, g.id) }
                                        .onSuccess {
                                            editTarget = null
                                            deleteArm = false
                                            refreshAll()
                                            onSyncNudge()
                                        }
                                        .onFailure {
                                            Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic"))
                                            deleteArm = false
                                        }
                                    busy = false
                                }
                            },
                        ) { Text(t("common.continue")) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { editTarget = null }) { Text(t("common.close")) }
            },
        )
    }
}
