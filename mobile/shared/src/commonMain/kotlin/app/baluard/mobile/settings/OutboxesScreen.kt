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
import androidx.compose.material3.Checkbox
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import app.baluard.mobile.MobileCipherMeta
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.MobileContactRow
import app.baluard.mobile.data.MobileOutboxEntry
import app.baluard.mobile.data.MobileOutboxLink
import app.baluard.mobile.data.MobileOwnerOutbox
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.platform.deriveOutboxTargetPath
import app.baluard.mobile.platform.rememberOutboxFolderBridge
import app.baluard.mobile.ui.components.BaluardDivider
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.toast.Toast

/**
 * S2 Outboxes: owner live-mirrored folders and recipient view-only links.
 */
@Composable
fun OutboxesScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
    onSyncNudge: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    val folderBridge = rememberOutboxFolderBridge()

    var outboxes by remember(vault) { mutableStateOf<List<MobileOwnerOutbox>>(emptyList()) }
    var contacts by remember(vault) { mutableStateOf<List<MobileContactRow>>(emptyList()) }
    var ciphers by remember(vault) { mutableStateOf<List<MobileCipherMeta>>(emptyList()) }
    var links by remember(vault) { mutableStateOf<List<MobileOutboxLink>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }

    var selectedCiphers by remember { mutableStateOf<Set<String>>(emptySet()) }
    var selectedContacts by remember { mutableStateOf<Set<String>>(emptySet()) }
    var pubPath by remember { mutableStateOf("") }
    var showCipherPicker by remember { mutableStateOf(false) }
    var showContactPicker by remember { mutableStateOf(false) }

    var linkPath by remember { mutableStateOf("") }
    var openOutboxId by remember { mutableStateOf<String?>(null) }
    var entries by remember { mutableStateOf<List<MobileOutboxEntry>>(emptyList()) }
    var openedEntry by remember { mutableStateOf<MobileOutboxEntry?>(null) }
    var revokeTarget by remember { mutableStateOf<MobileOwnerOutbox?>(null) }
    var forgetTarget by remember { mutableStateOf<MobileOutboxLink?>(null) }

    fun recipientName(pubkey: String): String =
        contacts.firstOrNull { it.identitySigningPubkey == pubkey }?.displayName
            ?: (pubkey.take(12) + "…")

    suspend fun refreshAll() {
        runCatching { outboxes = repo.outboxList(vault) }
        contacts = repo.contactsParsed(vault)
        runCatching { ciphers = repo.listCiphers(vault) }
        runCatching { links = repo.outboxLinks(vault) }
    }

    LaunchedEffect(vault) { refreshAll() }

    Scaffold(
        topBar = { BaluardTopBar(title = t("outbox.title"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item(key = "owner-list") {
                SectionCard(title = t("outbox.sharedTitle")) {
                    Text(
                        text = t("outbox.sharedHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (outboxes.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            enabled = !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    try {
                                        val count = repo.outboxResync(vault)
                                        withContext(Dispatchers.IO) {
                                            outboxes.forEach { folderBridge.pushMirror(it.path) }
                                        }
                                        Toast.success(t("outbox.resyncedToast", count))
                                        refreshAll()
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                                    } finally {
                                        busy = false
                                    }
                                }
                            },
                        ) { Text(t("outbox.resyncAction")) }
                    }
                    Spacer(Modifier.height(10.dp))
                    if (outboxes.isEmpty()) {
                        Text(
                            text = t("outbox.empty"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        outboxes.forEachIndexed { idx, o ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(recipientName(o.recipientSigningPub), style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        text = o.path,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = if (o.publishedCipherIds.size == 1) {
                                            t("outbox.oneItem")
                                        } else {
                                            t("outbox.itemsCount", o.publishedCipherIds.size)
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                TextButton(
                                    enabled = !busy,
                                    onClick = { revokeTarget = o },
                                ) { Text(t("outbox.revoke"), color = MaterialTheme.colorScheme.error) }
                            }
                            if (idx < outboxes.lastIndex) {
                                BaluardDivider(modifier = Modifier.padding(vertical = 8.dp))
                            }
                        }
                    }
                }
            }

            item(key = "publish") {
                val wrapContacts = contacts.filter { it.hasWrapKey }
                SectionCard(title = t("outbox.publishTitle")) {
                    OutlinedButton(
                        enabled = !busy,
                        onClick = { showCipherPicker = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            if (selectedCiphers.isEmpty()) t("outbox.pickItems")
                            else t("outbox.pickedItemsCount", selectedCiphers.size),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        enabled = !busy,
                        onClick = { showContactPicker = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            if (selectedContacts.isEmpty()) t("outbox.pickRecipients")
                            else t("outbox.pickedRecipientsCount", selectedContacts.size),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        BaluardTextField(
                            value = pubPath,
                            onValueChange = {},
                            readOnly = true,
                            label = t("outbox.pathLabel"),
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedButton(
                            enabled = !busy,
                            onClick = {
                                folderBridge.pickFolder { picked ->
                                    if (picked != null) pubPath = picked
                                }
                            },
                        ) { Text(t("outbox.pickFolder")) }
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = t("outbox.pathHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    BaluardPrimaryButton(
                        text = t("outbox.publishAction"),
                        enabled = !busy && selectedCiphers.isNotEmpty() && selectedContacts.isNotEmpty() && pubPath.isNotBlank(),
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    val recipients = wrapContacts.filter { it.identitySigningPubkey in selectedContacts }
                                    val touchedPaths = mutableListOf<String>()
                                    for (recipient in recipients) {
                                        val targetPath = deriveOutboxTargetPath(
                                            basePath = pubPath,
                                            recipientDisplayName = recipient.displayName,
                                            recipientSigningPubkey = recipient.identitySigningPubkey,
                                            multiRecipient = recipients.size > 1,
                                        )
                                        touchedPaths += targetPath
                                        for (cid in selectedCiphers) {
                                            repo.outboxPublish(vault, targetPath, cid, recipient.identitySigningPubkey)
                                        }
                                    }
                                    withContext(Dispatchers.IO) {
                                        touchedPaths.distinct().forEach { folderBridge.pushMirror(it) }
                                    }
                                    selectedCiphers = emptySet()
                                    selectedContacts = emptySet()
                                    pubPath = ""
                                    Toast.success(t("outbox.publishedToast"))
                                    refreshAll()
                                    onSyncNudge()
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                                } finally {
                                    busy = false
                                }
                            }
                        },
                    )
                }
            }

            item(key = "received") {
                SectionCard(title = t("outbox.receivedTitle")) {
                    if (links.isEmpty()) {
                        Text(
                            text = t("outbox.linksEmpty"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        links.forEachIndexed { idx, l ->
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(l.ownerName, style = MaterialTheme.typography.bodyMedium)
                                        Text(
                                            text = l.path,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    Row {
                                        TextButton(
                                            enabled = !busy,
                                            onClick = {
                                                if (openOutboxId == l.outboxId) {
                                                    openOutboxId = null
                                                    entries = emptyList()
                                                } else {
                                                    scope.launch {
                                                        try {
                                                            withContext(Dispatchers.IO) {
                                                                folderBridge.pullMirror(l.path)
                                                            }
                                                            entries = repo.outboxEntries(vault, l.outboxId)
                                                            openOutboxId = l.outboxId
                                                        } catch (e: CancellationException) {
                                                            throw e
                                                        } catch (e: Exception) {
                                                            Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                                                        }
                                                    }
                                                }
                                            },
                                        ) { Text(t(if (openOutboxId == l.outboxId) "outbox.hideItems" else "outbox.viewItems")) }
                                        TextButton(
                                            enabled = !busy,
                                            onClick = { forgetTarget = l },
                                        ) { Text(t("outbox.forget"), color = MaterialTheme.colorScheme.error) }
                                    }
                                }
                                if (openOutboxId == l.outboxId) {
                                    Spacer(Modifier.height(6.dp))
                                    if (entries.isEmpty()) {
                                        Text(
                                            text = t("outbox.entriesEmpty"),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    } else {
                                        entries.forEach { row ->
                                            Text(
                                                text = row.name.ifBlank { t("outbox.unnamed") },
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .clickable {
                                                        scope.launch {
                                                            try {
                                                                openedEntry = repo.outboxRead(vault, l.outboxId, row.cipherId) ?: row
                                                            } catch (e: CancellationException) {
                                                                throw e
                                                            } catch (e: Exception) {
                                                                Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                                                            }
                                                        }
                                                    }
                                                    .padding(vertical = 6.dp),
                                            )
                                        }
                                    }
                                }
                            }
                            if (idx < links.lastIndex) {
                                BaluardDivider(modifier = Modifier.padding(vertical = 8.dp))
                            }
                        }
                    }
                    BaluardDivider(modifier = Modifier.padding(vertical = 10.dp))
                    Text(t("outbox.linkTitle"), style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        BaluardTextField(
                            value = linkPath,
                            onValueChange = {},
                            readOnly = true,
                            label = t("outbox.pathLabel"),
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedButton(
                            enabled = !busy,
                            onClick = {
                                folderBridge.pickFolder { picked ->
                                    if (picked != null) linkPath = picked
                                }
                            },
                        ) { Text(t("outbox.pickFolder")) }
                    }
                    Spacer(Modifier.height(10.dp))
                    BaluardPrimaryButton(
                        text = t("outbox.linkAction"),
                        enabled = !busy && linkPath.isNotBlank(),
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    val path = linkPath.trim()
                                    withContext(Dispatchers.IO) { folderBridge.pullMirror(path) }
                                    repo.outboxLink(vault, path)
                                    linkPath = ""
                                    Toast.success(t("outbox.linkedToast"))
                                    refreshAll()
                                    onSyncNudge()
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                                } finally {
                                    busy = false
                                }
                            }
                        },
                    )
                }
            }
        }
    }

    if (showCipherPicker) {
        AlertDialog(
            onDismissRequest = { showCipherPicker = false },
            title = { Text(t("outbox.itemLabel")) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    if (ciphers.isEmpty()) {
                        Text(t("outbox.noResults"), style = MaterialTheme.typography.bodySmall)
                    } else {
                        ciphers.forEach { cipher ->
                            val checked = cipher.id in selectedCiphers
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selectedCiphers = if (checked) selectedCiphers - cipher.id else selectedCiphers + cipher.id
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(checked = checked, onCheckedChange = null)
                                Text(cipher.name, modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showCipherPicker = false }) { Text(t("common.done")) }
            },
        )
    }

    if (showContactPicker) {
        val wrapContacts = contacts.filter { it.hasWrapKey }
        AlertDialog(
            onDismissRequest = { showContactPicker = false },
            title = { Text(t("outbox.contactLabel")) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    if (wrapContacts.isEmpty()) {
                        Text(t("contacts.empty"), style = MaterialTheme.typography.bodySmall)
                    } else {
                        wrapContacts.forEach { contact ->
                            val checked = contact.identitySigningPubkey in selectedContacts
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selectedContacts = if (checked) {
                                            selectedContacts - contact.identitySigningPubkey
                                        } else {
                                            selectedContacts + contact.identitySigningPubkey
                                        }
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(checked = checked, onCheckedChange = null)
                                Text(contact.displayName, modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showContactPicker = false }) { Text(t("common.done")) }
            },
        )
    }

    openedEntry?.let { entry ->
        AlertDialog(
            onDismissRequest = { openedEntry = null },
            title = { Text(entry.name.ifBlank { t("outbox.unnamed") }) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = t("outbox.senderValue", entry.senderName),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    entry.username?.let { u ->
                        Text(t("outbox.usernameLabel"), style = MaterialTheme.typography.labelSmall)
                        Text(u, style = MaterialTheme.typography.bodyMedium)
                    }
                    entry.password?.let { pw ->
                        Text(t("outbox.passwordLabel"), style = MaterialTheme.typography.labelSmall)
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = "•".repeat(pw.length.coerceAtMost(12)),
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                            )
                            TextButton(onClick = {
                                copyToClipboard(pw)
                                Toast.success(t("outbox.copiedToast"))
                            }) { Text(t("outbox.copySecret")) }
                        }
                    }
                    entry.notes?.let { n ->
                        Text(t("outbox.notesLabel"), style = MaterialTheme.typography.labelSmall)
                        Text(n, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { openedEntry = null }) { Text(t("common.close")) }
            },
        )
    }

    revokeTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { if (!busy) revokeTarget = null },
            title = { Text(t("outbox.revokeTitle")) },
            text = { Text(t("outbox.revokeBody")) },
            confirmButton = {
                TextButton(
                    enabled = !busy,
                    onClick = {
                        scope.launch {
                            busy = true
                            try {
                                repo.outboxRevoke(vault, target.path)
                                withContext(Dispatchers.IO) { folderBridge.pushMirror(target.path) }
                                revokeTarget = null
                                Toast.success(t("outbox.revokedToast"))
                                refreshAll()
                                onSyncNudge()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                            } finally {
                                busy = false
                            }
                        }
                    },
                ) { Text(t("outbox.revoke"), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { revokeTarget = null }) { Text(t("common.cancel")) }
            },
        )
    }

    forgetTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { if (!busy) forgetTarget = null },
            title = { Text(t("outbox.forgetTitle")) },
            text = { Text(t("outbox.forgetBody")) },
            confirmButton = {
                TextButton(
                    enabled = !busy,
                    onClick = {
                        scope.launch {
                            busy = true
                            try {
                                repo.outboxForget(vault, target.outboxId)
                                if (openOutboxId == target.outboxId) {
                                    openOutboxId = null
                                    entries = emptyList()
                                }
                                forgetTarget = null
                                Toast.success(t("outbox.forgotToast"))
                                refreshAll()
                                onSyncNudge()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error((e.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") })
                            } finally {
                                busy = false
                            }
                        }
                    },
                ) { Text(t("outbox.forget"), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { forgetTarget = null }) { Text(t("common.cancel")) }
            },
        )
    }
}
