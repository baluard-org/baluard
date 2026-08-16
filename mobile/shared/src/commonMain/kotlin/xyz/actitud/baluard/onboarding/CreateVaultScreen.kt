package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.i18n.t

/**
 * Vault-creation form (plan §5.5): master password x2 + device name ->
 * create -> RecoveryPhraseScreen -> ack -> vault list.
 *
 * The Argon2id KDF (MobileLow profile) runs on the shared tokio Runtime via
 * the async FFI, never on the UI thread (plan §2.1). The minimum password
 * length matches the desktop wizard (8).
 */
@Composable
fun CreateVaultScreen(
    vaultPath: String,
    authViewModel: AuthViewModel,
    onCreated: () -> Unit,
    onCancelled: () -> Unit,
) {
    val repo = remember { VaultRepository() }
    val vm = remember { CreateVaultViewModel(repo, authViewModel) }
    val scope = rememberCoroutineScope()

    var password by rememberSaveable { mutableStateOf("") }
    var confirm by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf(t("onboarding.defaultDeviceName")) }
    var creating by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    var phraseShown by rememberSaveable { mutableStateOf(false) }

    if (phraseShown) {
        RecoveryPhraseScreen(
            words = vm.recoveryWords,
            onAcknowledged = onCreated,
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(t("onboarding.createVault"), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            t("onboarding.createSubtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(t("login.passwordPlaceholder")) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            isError = password.isNotEmpty() && password.length < MIN_PASSWORD_LEN,
            supportingText = if (password.isNotEmpty() && password.length < MIN_PASSWORD_LEN) {
                { Text(t("onboarding.errorMinLength")) }
            } else {
                null
            },
            enabled = !creating,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = confirm,
            onValueChange = { confirm = it },
            label = { Text(t("onboarding.confirmPassword")) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            isError = confirm.isNotEmpty() && confirm != password,
            supportingText = if (confirm.isNotEmpty() && confirm != password) {
                { Text(t("onboarding.errorMismatch")) }
            } else {
                null
            },
            enabled = !creating,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = deviceName,
            onValueChange = { deviceName = it },
            label = { Text(t("onboarding.deviceName")) },
            singleLine = true,
            enabled = !creating,
            modifier = Modifier.fillMaxWidth(),
        )

        error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(24.dp))
        if (creating) {
            CircularProgressIndicator()
        } else {
            Button(
                onClick = {
                    if (password.length < MIN_PASSWORD_LEN) {
                        error = t("onboarding.errorMinLength")
                        return@Button
                    }
                    if (password != confirm) {
                        error = t("onboarding.errorMismatch")
                        return@Button
                    }
                    creating = true
                    error = null
                    scope.launch {
                        val ok = vm.create(vaultPath, password, deviceName)
                        creating = false
                        if (ok) {
                            phraseShown = true
                        } else {
                            error = t("onboarding.errorCreateFailed")
                        }
                    }
                },
                enabled = password.length >= MIN_PASSWORD_LEN && confirm == password && deviceName.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(t("onboarding.createButton"))
            }
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onCancelled, enabled = !creating) {
            Text(t("common.back"))
        }
    }
}

private const val MIN_PASSWORD_LEN = 8
