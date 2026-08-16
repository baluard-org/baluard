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
import xyz.actitud.baluard.i18n.t

/**
 * Device enrollment (plan §5.4): the clone has no device key (gitignored),
 * so this device must be trusted by the vault. Enter the 24-word recovery
 * phrase + master password -> enroll -> unlocked vault.
 */
@Composable
fun EnrollDeviceScreen(
    vm: ProviderFlowViewModel,
    vaultPath: String,
    onEnrolled: () -> Unit,
    onCancelled: () -> Unit,
) {
    val scope = rememberCoroutineScope()

    var phrase by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf(t("onboarding.defaultDeviceName")) }
    var enrolling by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    val wordCount = phrase.trim().split(Regex("\\s+")).count { it.isNotBlank() }
    val phraseValid = wordCount == 24

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(t("enroll.title"), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            t("enroll.subtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))

        OutlinedTextField(
            value = phrase,
            onValueChange = { phrase = it },
            label = { Text(t("enroll.phraseLabel", wordCount)) },
            isError = phrase.isNotBlank() && !phraseValid,
            supportingText = if (phrase.isNotBlank() && !phraseValid) {
                { Text(t("enroll.phraseHint")) }
            } else {
                null
            },
            enabled = !enrolling,
            minLines = 2,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(t("login.passwordPlaceholder")) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            enabled = !enrolling,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = deviceName,
            onValueChange = { deviceName = it },
            label = { Text(t("onboarding.deviceName")) },
            singleLine = true,
            enabled = !enrolling,
            modifier = Modifier.fillMaxWidth(),
        )

        (error ?: vm.error)?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(24.dp))
        if (enrolling) {
            CircularProgressIndicator()
        } else {
            Button(
                onClick = {
                    enrolling = true
                    error = null
                    scope.launch {
                        val ok = vm.enroll(vaultPath, password, phrase.trim(), deviceName)
                        enrolling = false
                        if (ok) onEnrolled() else error = vm.error
                    }
                },
                enabled = phraseValid && password.isNotEmpty() && deviceName.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(t("enroll.button")) }
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onCancelled, enabled = !enrolling) { Text(t("common.back")) }
    }
}
