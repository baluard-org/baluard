package xyz.actitud.baluard.ui.passkey

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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.passkeys.PasskeyLister
import xyz.actitud.baluard.passkeys.PasskeyUiRequest
import xyz.actitud.baluard.ui.BackPressHandler
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.i18n.t

/**
 * Fulfillment for a provider passkey CREATE (plan §9): shows the relying
 * party, the validated origin, and the username; runs the ceremony into
 * the matching existing Login when one unambiguously matches, else a new
 * one in the active vault. UV rides the master-password check when the RP
 * demands it — a plain tap is never verification (§5).
 */
@Composable
fun PasskeyCreateScreen(
    vault: MobileVault,
    request: PasskeyUiRequest.Create,
    onResult: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var userName by remember { mutableStateOf(request.userName.orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var showPassword by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var passwordError by remember { mutableStateOf<String?>(null) }

    // System back must cancel the ceremony with the typed result, not
    // finish the activity untyped (§4).
    BackPressHandler { onCancel() }

    val needsUv = PasskeyLister.userVerificationOf(request.requestJson) == "required"
    val rpLabel = request.rpName ?: request.rpId

    fun fail(e: Throwable) {
        if (e is CancellationException) throw e
        busy = false
        error = e.message?.removePrefix("detail=")?.ifBlank { t("passkey.failed") }
            ?: t("passkey.failed")
    }

    fun runCeremony() {
        scope.launch {
            busy = true
            try {
                val register = vault.passkeyProviderRegister(
                    request.requestJson,
                    // The platform-validated origin: the web page for
                    // browser callers, android:apk-key-hash for native
                    // ones (the core ceremony handles both schemes).
                    request.origin,
                    null,
                    request.clientDataHash,
                    needsUv, // verified by the password check just performed
                )
                val obj = org.json.JSONObject(register)
                val ceremonyId = obj.getString("ceremony_id")
                val linkTo = PasskeyLister.existingLoginFor(vault, request.rpId, userName)
                if (linkTo != null) {
                    vault.passkeyStoreRegistered(ceremonyId, linkTo, null)
                } else {
                    val newLogin = org.json.JSONObject().apply {
                        put("name", rpLabel)
                        put("username", userName)
                    }.toString()
                    vault.passkeyStoreRegistered(ceremonyId, null, newLogin)
                }
                onResult(obj.getJSONObject("attestation_response").toString())
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
            t("passkey.createTitle"),
            style = MaterialTheme.typography.titleLarge,
        )
        BaluardCard {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(rpLabel, style = MaterialTheme.typography.titleMedium)
                Text(
                    request.rpId,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    t("passkey.savedTo"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        OutlinedTextField(
            value = userName,
            onValueChange = { userName = it },
            label = { Text(t("passkey.username")) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            BaluardPrimaryButton(
                text = if (busy) t("common.loading") else t("common.continue"),
                onClick = {
                    if (needsUv) {
                        passwordError = null
                        showPassword = true
                    } else {
                        runCeremony()
                    }
                },
                enabled = !busy,
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
                                runCeremony()
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
