package xyz.actitud.baluard.auth

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import xyz.actitud.baluard.data.UnlockResult
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.platformLogE
import xyz.actitud.baluard.platform.copyToClipboard
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.toast.Toast

/**
 * Member-side join ceremony (§4.8-2 parity on mobile). The vault clone
 * already exists (repo picker flow); this dialog collects the invite code
 * and the joiner's chosen master password, writes the introduction, shows
 * the out-of-band intro code for the admin, and polls until approval —
 * then unlocks with the chosen password (the standard member unlock tail).
 */
@Composable
fun JoinSpaceDialog(
    vaultPath: String,
    authViewModel: AuthViewModel,
    onApproved: () -> Unit,
    onDismiss: () -> Unit,
) {
    val repo = remember { VaultRepository() }
    val scope = rememberCoroutineScope()

    // Phase: form -> waiting (intro code shown, poll running).
    var phase by remember { mutableStateOf("form") }
    var code by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var introCode by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    // Poll while waiting. Each join_poll best-effort pulls (locked vault,
    // introduced-not-approved), so the admin's approval arrives without a
    // manual sync. First poll after 10s — the intro was just written.
    if (phase == "waiting") {
        LaunchedEffect(vaultPath) {
            var approved = false
            while (!approved) {
                delay(10_000)
                approved = runCatching {
                    val vault = repo.openVault(vaultPath)
                    val resp = repo.joinPoll(vault)
                    // The waiting loop swallows every failure, so log the
                    // raw response — a stuck join is otherwise invisible.
                    platformLogE("JoinPoll", "resp=$resp")
                    resp.contains("\"approved\":true")
                }.onFailure {
                    platformLogE("JoinPoll", "poll failed", it)
                }.getOrDefault(false)
            }
            // The password lives only in this composable's state; unlock
            // immediately on approval (same discipline as the desktop flow:
            // the password feeds the standard unlock path, then drops).
            when (authViewModel.openAndUnlock(vaultPath, password)) {
                is UnlockResult.Success -> onApproved()
                is UnlockResult.DeviceMismatch -> errorMsg = t("login.deviceMismatch")
                is UnlockResult.Failure -> errorMsg = t("login.wrongPassword")
            }
        }
    }

    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(if (phase == "form") t("join.title") else t("join.waitingTitle"))
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (phase == "form") {
                    BaluardTextField(
                        value = code,
                        onValueChange = { code = it },
                        label = t("join.code"),
                        singleLine = true,
                    )
                    BaluardTextField(
                        value = password,
                        onValueChange = { password = it; errorMsg = null },
                        label = t("join.password"),
                        isPassword = true,
                        singleLine = true,
                    )
                    BaluardTextField(
                        value = confirm,
                        onValueChange = { confirm = it },
                        label = t("join.confirm"),
                        isPassword = true,
                        singleLine = true,
                    )
                    BaluardTextField(
                        value = deviceName,
                        onValueChange = { deviceName = it },
                        label = t("join.deviceName"),
                        placeholder = t("join.devicePlaceholder"),
                        singleLine = true,
                    )
                    BaluardTextField(
                        value = email,
                        onValueChange = { email = it },
                        label = t("join.emailLabel"),
                        placeholder = t("join.emailPlaceholder"),
                        singleLine = true,
                    )
                    errorMsg?.let {
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    BaluardPrimaryButton(
                        text = if (busy) t("common.sending") else t("join.send"),
                        enabled = !busy &&
                            code.isNotBlank() &&
                            password.length >= 8 &&
                            password == confirm,
                        loading = busy,
                        onClick = {
                            busy = true
                            errorMsg = null
                            scope.launch {
                                runCatching {
                                    val vault = repo.openVault(vaultPath)
                                    repo.joinIntroduce(
                                        vault,
                                        code.trim(),
                                        password,
                                        deviceName.trim().ifBlank { "My device" },
                                        email.trim().ifBlank { null },
                                    )
                                }.onSuccess { raw ->
                                    introCode = runCatching {
                                        val el = kotlinx.serialization.json.Json
                                            .parseToJsonElement(raw).jsonObject
                                        el["intro_code"]?.jsonPrimitive?.content ?: ""
                                    }.getOrDefault("")
                                    if (introCode.isBlank()) {
                                        errorMsg = t("error.generic")
                                    } else {
                                        // E2E builds surface the one-time reply
                                        // on logcat so the two-phone harness can
                                        // hand it to the admin without scraping
                                        // the screen. Never compiled into
                                        // release (BuildConfig gate).
                                        if (xyz.actitud.baluard.platform.e2eBuild) {
                                            platformLogE("JoinSpace", "intro=$introCode")
                                        }
                                        phase = "waiting"
                                    }
                                }.onFailure {
                                    // The FFI prefixes every error with
                                    // "detail="; strip it like the other
                                    // surfaces do.
                                    errorMsg = (it.message ?: "").removePrefix("detail=").ifBlank { t("error.generic") }
                                }
                                busy = false
                            }
                        },
                    )
                } else {
                    Text(
                        text = t("join.waitingBody"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = introCode,
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                            ),
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(8.dp))
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = t("join.copyIntro"),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .size(18.dp)
                                .clickable {
                                    copyToClipboard(introCode)
                                    Toast.info(t("join.copied"))
                                },
                        )
                    }
                    Text(
                        text = t("join.waitingHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    errorMsg?.let {
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(t("common.close")) }
        },
    )
}
