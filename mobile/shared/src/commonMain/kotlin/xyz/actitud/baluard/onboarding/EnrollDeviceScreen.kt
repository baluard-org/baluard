package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.deviceDisplayName
import xyz.actitud.baluard.ui.components.BaluardAmbientBackground
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardLogoBadge
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTextField

/**
 * Device enrollment styled after Baluard design language.
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
    // OS-provided name (Pixel 9 Pro, Esteban's iPhone); localized
    // "My device" only when the OS gives nothing. Still editable.
    var deviceName by rememberSaveable {
        mutableStateOf(deviceDisplayName().ifBlank { t("onboarding.defaultDeviceName") })
    }
    var enrolling by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    val wordCount = phrase.trim().split(Regex("\\s+")).count { it.isNotBlank() }
    val phraseValid = wordCount == 24

    BaluardAmbientBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            BaluardLogoBadge(
                size = 64.dp,
                showTitle = true,
                subtitle = t("enroll.subtitle"),
            )

            Spacer(Modifier.height(28.dp))

            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                BaluardTextField(
                    value = phrase,
                    onValueChange = {
                        phrase = it
                        error = null
                    },
                    label = t("enroll.phraseLabel", wordCount),
                    placeholder = "Enter the 24 recovery words...",
                    leadingIcon = Icons.Default.Key,
                    singleLine = false,
                    minLines = 3,
                    isError = phrase.isNotBlank() && !phraseValid,
                    supportingText = if (phrase.isNotBlank() && !phraseValid) {
                        t("enroll.phraseHint")
                    } else null,
                    enabled = !enrolling,
                )

                Spacer(Modifier.height(12.dp))

                BaluardTextField(
                    value = password,
                    onValueChange = {
                        password = it
                        error = null
                    },
                    label = t("login.passwordPlaceholder"),
                    placeholder = t("login.passwordPlaceholder"),
                    leadingIcon = Icons.Default.Lock,
                    isPassword = true,
                    enabled = !enrolling,
                )

                Spacer(Modifier.height(12.dp))

                BaluardTextField(
                    value = deviceName,
                    onValueChange = {
                        deviceName = it
                        error = null
                    },
                    label = t("onboarding.deviceName"),
                    leadingIcon = Icons.Default.PhoneAndroid,
                    enabled = !enrolling,
                )

                (error ?: vm.error)?.let {
                    Spacer(Modifier.height(12.dp))
                    SelectionContainer {
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }

                Spacer(Modifier.height(20.dp))

                BaluardPrimaryButton(
                    text = t("enroll.button"),
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
                    loading = enrolling,
                    leadingIcon = Icons.Default.Key,
                )

                Spacer(Modifier.height(10.dp))

                BaluardOutlinedButton(
                    text = t("common.back"),
                    onClick = onCancelled,
                    enabled = !enrolling,
                )
            }
        }
    }
}
