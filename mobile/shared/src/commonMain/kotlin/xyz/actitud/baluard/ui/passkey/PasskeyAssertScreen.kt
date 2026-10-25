package xyz.actitud.baluard.ui.passkey

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.passkeys.ListedPasskey
import xyz.actitud.baluard.passkeys.PasskeyLister
import xyz.actitud.baluard.passkeys.PasskeyUiRequest
import xyz.actitud.baluard.ui.BackPressHandler
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.i18n.t

/**
 * Fulfillment for a provider passkey ASSERT (plan §9): credential picker
 * when several match, origin already validated at the trampoline gate,
 * ceremony + consume, result JSON back to the framework. The master-
 * password check gates the ceremony when the RP demands UV or the entry
 * carries the re-prompt flag (§5, §11).
 */
@Composable
fun PasskeyAssertScreen(
    vault: MobileVault,
    request: PasskeyUiRequest.Assert,
    onResult: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var matches by remember { mutableStateOf<List<ListedPasskey>?>(null) }
    var selected by remember { mutableStateOf<ListedPasskey?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var showPassword by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var passwordError by remember { mutableStateOf<String?>(null) }

    // System back must cancel the ceremony with the typed result, not
    // finish the activity untyped (§4).
    BackPressHandler { onCancel() }

    val needsUv = PasskeyLister.userVerificationOf(request.requestJson) == "required"

    LaunchedEffect(request.id) {
        matches = PasskeyLister.list(vault, request.rpId, request.allowCredentialIds)
        // Preselect the entry the user tapped on the system sheet; else a
        // single match; else several demand an explicit pick.
        selected = request.credentialId?.let { id -> matches?.find { it.credentialId == id } }
            ?: matches?.singleOrNull()
    }

    fun fail(e: Throwable) {
        if (e is CancellationException) throw e
        busy = false
        error = e.message?.removePrefix("detail=")?.ifBlank { t("passkey.failed") }
            ?: t("passkey.failed")
    }

    fun runCeremony(credentialId: String) {
        scope.launch {
            busy = true
            try {
                val assert = vault.passkeyProviderAssert(
                    request.requestJson,
                    // The platform-validated origin: the web page for
                    // browser callers, android:apk-key-hash for native
                    // ones (the core ceremony handles both schemes).
                    request.origin,
                    credentialId,
                    null,
                    request.clientDataHash,
                    needsUv,
                )
                val obj = org.json.JSONObject(assert)
                runCatching { vault.passkeyConsumeAssertion(obj.getString("ceremony_id")) }
                onResult(obj.getJSONObject("assertion_response").toString())
            } catch (e: Throwable) {
                fail(e)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            t("passkey.assertTitle"),
            style = MaterialTheme.typography.titleLarge,
        )
        BaluardCard {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(request.rpId, style = MaterialTheme.typography.titleMedium)
                Text(
                    request.origin,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }

        val list = matches
        when {
            list == null -> CircularProgressIndicator()
            list.isEmpty() -> Text(
                t("passkey.noMatch"),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )

            else -> SectionCard(title = t("passkey.pickCredential")) {
                Column {
                    for (pk in list) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selected = pk }
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = selected?.credentialId == pk.credentialId, onClick = { selected = pk })
                            Column(Modifier.padding(start = 8.dp)) {
                                Text(
                                    pk.userName ?: t("passkey.noUsername"),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                                Text(
                                    pk.credentialId.take(12) + "…",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }

        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            BaluardPrimaryButton(
                text = if (busy) t("common.loading") else t("common.continue"),
                onClick = {
                    val pick = selected ?: return@BaluardPrimaryButton
                    if (needsUv || pick.reprompt) {
                        passwordError = null
                        showPassword = true
                    } else {
                        runCeremony(pick.credentialId)
                    }
                },
                enabled = !busy && selected != null,
                modifier = Modifier.weight(1f),
            )
            BaluardOutlinedButton(
                text = t("common.cancel"),
                onClick = onCancel,
                enabled = !busy,
                modifier = Modifier.weight(1f),
            )
        }
        if (busy) CircularProgressIndicator(Modifier.padding(top = 8.dp))
    }

    if (showPassword) {
        AlertDialog(
            onDismissRequest = { if (!busy) showPassword = false },
            title = { Text(t("passkey.verifyTitle")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(t("passkey.verifyBody"))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text(t("passkey.password")) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        isError = passwordError != null,
                        supportingText = { passwordError?.let { Text(it) } },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !busy && password.isNotEmpty(),
                    onClick = {
                        scope.launch {
                            busy = true
                            try {
                                vault.repromptVerify(password)
                                showPassword = false
                                password = ""
                                busy = false
                                runCeremony(selected?.credentialId ?: return@launch)
                            } catch (e: Throwable) {
                                busy = false
                                if (e is CancellationException) throw e
                                passwordError = t("login.wrongPassword")
                            }
                        }
                    },
                ) { Text(t("common.continue")) }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { showPassword = false }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }
}
