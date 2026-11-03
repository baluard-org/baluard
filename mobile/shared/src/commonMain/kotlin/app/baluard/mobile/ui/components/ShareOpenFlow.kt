package app.baluard.mobile.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.detail.formatEpochDate
import app.baluard.mobile.i18n.t
import app.baluard.mobile.openSharedGuest
import app.baluard.mobile.platform.PickedFile
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.platform.rememberImportFilePicker
import app.baluard.mobile.ui.toast.Toast

/** Handle returned by [rememberShareOpenFlow]. */
class ShareOpenHandle(
    val open: () -> Unit,
    val busy: Boolean,
)

/**
 * G4: open a shared .baluard-share file (desktop OpenSharedModal parity,
 * mobile-shaped). guestOnly renders the pre-vault flow for the onboarding
 * screen: the passphrase dialog opens straight away, no vault needed —
 * a recipient without an account can still open a guest share. The full
 * chain tries the one-shot package, then a view-only contact reveal,
 * then the passphrase leg, surfacing the contact leg's error when the
 * guest open also fails (the desktop contract). Renders only dialogs;
 * call [ShareOpenHandle.open] from any row or button.
 */
@Composable
fun rememberShareOpenFlow(
    guestOnly: Boolean,
    vault: MobileVault?,
    repo: VaultRepository?,
): ShareOpenHandle {
    val scope = rememberCoroutineScope()
    val picker = rememberImportFilePicker()
    var busy by remember { mutableStateOf(false) }
    var passOpen by remember { mutableStateOf(false) }
    var pass by remember { mutableStateOf("") }
    var passB64 by remember { mutableStateOf<String?>(null) }
    var legError by remember { mutableStateOf<String?>(null) }
    var opened by remember { mutableStateOf<String?>(null) }

    fun openRevealFile(file: PickedFile) {
        scope.launch {
            busy = true
            // Desktop caps the webview read at 4 MB; the daemon's wire
            // guards sit behind it. Refuse before base64-encoding a
            // mis-picked monster file into memory.
            if (file.bytes.size > 4 * 1024 * 1024) {
                busy = false
                Toast.error(t("share.fileTooLarge"))
                return@launch
            }
            val b64 = Base64.encode(file.bytes)
            var contactErr: String? = null
            if (!guestOnly && vault != null && repo != null) {
                // 1. One-shot package: imports a fresh entry. A miss is a
                // detection step, not an error (desktop ignores it too).
                try {
                    val raw = repo.importSharedPackage(vault, b64)
                    val s = runCatching { Json.parseToJsonElement(raw) as JsonObject }.getOrNull()
                    val sender = (s?.get("sender") as? JsonPrimitive)?.content ?: ""
                    busy = false
                    Toast.success(t("share.imported", sender))
                    return@launch
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                }
                // 2. Contact reveal: view-only, nothing added. Its failure
                // carries the most specific truth (expired, wrong
                // recipient) — keep it for the guest leg's failure path.
                try {
                    val raw = repo.openSharedContact(vault, b64)
                    busy = false
                    opened = raw
                    return@launch
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    contactErr = e.message
                }
            }
            // 3. Guest reveal: the passphrase dialog decides.
            busy = false
            pass = ""
            passB64 = b64
            legError = contactErr
            passOpen = true
        }
    }

    val handle = ShareOpenHandle(
        open = {
            picker(listOf("*/*")) { file ->
                if (file != null) openRevealFile(file)
            }
        },
        busy = busy,
    )

    // Passphrase leg: a guest reveal names its own passphrase (never the
    // master password, never prefilled).
    if (passOpen) {
        AlertDialog(
            onDismissRequest = {
                passOpen = false
                pass = ""
                passB64 = null
                legError = null
            },
            title = { Text(t("share.passTitle")) },
            text = {
                OutlinedTextField(
                    value = pass,
                    onValueChange = { pass = it },
                    singleLine = true,
                    isError = legError != null,
                    supportingText = if (legError != null) {
                        { Text(t("share.passRequired")) }
                    } else {
                        null
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(
                    enabled = !busy && pass.isNotEmpty() && passB64 != null,
                    onClick = {
                        val b64 = passB64 ?: return@TextButton
                        scope.launch {
                            busy = true
                            val raw = try {
                                openSharedGuest(b64, pass)
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Exception) {
                                null
                            }
                            busy = false
                            if (raw == null) {
                                // A failed guest open over a file the
                                // contact leg already rejected: show that
                                // error — it is the real reason.
                                Toast.error(legError ?: t("share.failed"))
                            } else {
                                passOpen = false
                                pass = ""
                                passB64 = null
                                legError = null
                                opened = raw
                            }
                        }
                    },
                ) { Text(t("common.continue")) }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = {
                    passOpen = false
                    pass = ""
                    passB64 = null
                    legError = null
                }) { Text(t("common.cancel")) }
            },
        )
    }

    // Opened view: the reveal's fields, read-only. Everything is
    // selectable; the password and TOTP code are masked with copy.
    opened?.let { raw ->
        val o = runCatching { Json.parseToJsonElement(raw) as JsonObject }.getOrNull()
        fun field(key: String): String = (o?.get(key) as? JsonPrimitive)?.content ?: ""
        AlertDialog(
            onDismissRequest = { opened = null },
            title = { Text(field("item_name").ifEmpty { t("share.openRow") }) },
            text = {
                SelectionContainer {
                    Column(
                        modifier = Modifier.verticalScroll(rememberScrollState()),
                    ) {
                        ShareFieldRow(t("share.from"), field("sender_name"))
                        ShareFieldRow(t("share.url"), field("url"))
                        ShareFieldRow(t("share.username"), field("username"))
                        ShareSecretRow(t("share.password"), field("password"))
                        ShareSecretRow(t("share.totp"), field("totp_code"))
                        val expires = (o?.get("expires_at") as? JsonPrimitive)?.content?.toLongOrNull()
                        if (expires != null && expires > 0L) {
                            Text(
                                text = t("share.expires") + " " + formatEpochDate(expires),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { opened = null }) { Text(t("common.close")) }
            },
        )
    }

    return handle
}

/** Read-only shared-reveal field row; blank values render nothing. */
@Composable
private fun ShareFieldRow(label: String, value: String) {
    if (value.isEmpty()) return
    Column(Modifier.padding(bottom = 8.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

/** Sensitive shared-reveal row: masked until tapped, with copy. */
@Composable
private fun ShareSecretRow(label: String, value: String) {
    if (value.isEmpty()) return
    var shown by remember { mutableStateOf(false) }
    Column(Modifier.padding(bottom = 8.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (shown) value else "•".repeat(minOf(value.length, 12)),
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { shown = !shown }) {
                Text(t(if (shown) "detail.hide" else "detail.reveal"))
            }
            TextButton(onClick = { copyToClipboard(value) }) {
                Text(t("common.copy"))
            }
        }
    }
}
