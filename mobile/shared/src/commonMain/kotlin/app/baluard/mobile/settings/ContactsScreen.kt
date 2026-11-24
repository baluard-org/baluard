package app.baluard.mobile.settings

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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.MobileContactRow
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.ui.components.BaluardDivider
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.toast.Toast

/**
 * S2 address book: my contact card + verification code, import contact card,
 * Level 2 verification check, and contact removal.
 */
@Composable
fun ContactsScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
    onSyncNudge: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var contacts by remember(vault) { mutableStateOf<List<MobileContactRow>>(emptyList()) }
    var myCard by remember(vault) { mutableStateOf<Pair<String, String>?>(null) }
    var showFullCard by remember { mutableStateOf(false) }
    var cardInput by remember { mutableStateOf("") }
    var revealedPubkey by remember { mutableStateOf<String?>(null) }
    var removeTarget by remember { mutableStateOf<MobileContactRow?>(null) }
    var busy by remember { mutableStateOf(false) }

    suspend fun refreshAll() {
        contacts = repo.contactsParsed(vault)
        myCard = repo.myContactCardParsed(vault)
    }

    LaunchedEffect(vault) { refreshAll() }

    Scaffold(
        topBar = { BaluardTopBar(title = t("contacts.listTitle"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item(key = "my-card") {
                SectionCard(title = t("contacts.myCardTitle")) {
                    Text(
                        text = t("contacts.myCardBody"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    myCard?.let { (card, code) ->
                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = t("contacts.cardCodeLabel"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = card,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            maxLines = if (showFullCard) Int.MAX_VALUE else 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { showFullCard = !showFullCard }) {
                                Text(t(if (showFullCard) "contacts.hideCode" else "contacts.showCode"))
                            }
                            OutlinedButton(onClick = {
                                copyToClipboard(card)
                                Toast.success(t("contacts.cardCopied"))
                            }) {
                                Text(t("contacts.copyCard"))
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = t("contacts.myCodeLabel"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = code,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }

            item(key = "import") {
                SectionCard(title = t("contacts.importTitle")) {
                    BaluardTextField(
                        value = cardInput,
                        onValueChange = { cardInput = it },
                        label = t("contacts.importPlaceholder"),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(10.dp))
                    BaluardPrimaryButton(
                        text = t("contacts.importAction"),
                        enabled = !busy && cardInput.isNotBlank(),
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    repo.contactImportCard(vault, cardInput.trim())
                                    cardInput = ""
                                    Toast.success(t("contacts.importedToast"))
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

            item(key = "list") {
                SectionCard(title = t("contacts.listTitle")) {
                    if (contacts.isEmpty()) {
                        Text(
                            text = t("contacts.empty"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        contacts.forEachIndexed { index, c ->
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(c.displayName, style = MaterialTheme.typography.bodyLarge)
                                        Text(
                                            text = t(if (c.hasWrapKey) "contacts.canReceive" else "contacts.noWrapKey"),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    Text(
                                        text = t(if (c.trust == "verified") "contacts.trustVerified" else "contacts.trustChannel"),
                                        style = MaterialTheme.typography.labelMedium,
                                        color = if (c.trust == "verified") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                if (revealedPubkey == c.identitySigningPubkey) {
                                    Spacer(Modifier.height(6.dp))
                                    Text(
                                        text = t("contacts.theirCode"),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = c.verificationCode,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontFamily = FontFamily.Monospace,
                                    )
                                }
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    TextButton(onClick = {
                                        revealedPubkey = if (revealedPubkey == c.identitySigningPubkey) null else c.identitySigningPubkey
                                    }) {
                                        Text(t(if (revealedPubkey == c.identitySigningPubkey) "contacts.hideCode" else "contacts.showCode"))
                                    }
                                    if (c.trust != "verified") {
                                        TextButton(
                                            enabled = !busy,
                                            onClick = {
                                                scope.launch {
                                                    busy = true
                                                    try {
                                                        repo.contactMarkVerified(vault, c.identitySigningPubkey)
                                                        Toast.success(t("contacts.verifiedToast"))
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
                                        ) { Text(t("contacts.markVerified")) }
                                    }
                                    TextButton(
                                        enabled = !busy,
                                        onClick = { removeTarget = c },
                                    ) { Text(t("contacts.remove"), color = MaterialTheme.colorScheme.error) }
                                }
                            }
                            if (index < contacts.lastIndex) {
                                BaluardDivider(modifier = Modifier.padding(vertical = 8.dp))
                            }
                        }
                    }
                }
            }
        }
    }

    removeTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { if (!busy) removeTarget = null },
            title = { Text(t("contacts.removeTitle")) },
            text = { Text(t("contacts.removeBody", target.displayName)) },
            confirmButton = {
                TextButton(
                    enabled = !busy,
                    onClick = {
                        scope.launch {
                            busy = true
                            try {
                                repo.contactRemove(vault, target.identitySigningPubkey)
                                Toast.success(t("contacts.removedToast"))
                                removeTarget = null
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
                ) { Text(t("contacts.remove"), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { removeTarget = null }) { Text(t("common.cancel")) }
            },
        )
    }
}
