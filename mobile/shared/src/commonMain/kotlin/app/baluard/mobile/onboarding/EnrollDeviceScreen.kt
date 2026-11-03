package app.baluard.mobile.onboarding

import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import app.baluard.mobile.auth.JoinSpaceDialog
import app.baluard.mobile.auth.AuthViewModel
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.deviceDisplayName
import app.baluard.mobile.ui.components.BaluardAmbientBackground
import app.baluard.mobile.ui.components.BaluardCard
import app.baluard.mobile.ui.components.BaluardLogoBadge
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.components.BaluardTextField

/**
 * Device enrollment styled after Baluard design language.
 */
@Composable
fun EnrollDeviceScreen(
    vm: ProviderFlowViewModel,
    authViewModel: AuthViewModel,
    vaultPath: String,
    onEnrolled: () -> Unit,
    onCancelled: () -> Unit,
) {
    val scope = rememberCoroutineScope()

    // Plain remember, never rememberSaveable: the phrase and the master
    // password must not land in the saved-instance Bundle (M6 rule).
    var phrase by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    // OS-provided name (Pixel 9 Pro, Esteban's iPhone); localized
    // "My device" only when the OS gives nothing. Still editable.
    var deviceName by rememberSaveable {
        mutableStateOf(deviceDisplayName().ifBlank { t("onboarding.defaultDeviceName") })
    }
    var enrolling by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    // A cloned SHARED vault cannot phrase-enroll (team shapes refuse) —
    // the invite code is this clone's only way in.
    var showJoin by remember { mutableStateOf(false) }

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
                    placeholder = t("enroll.phrasePlaceholder"),
                    leadingIcon = Icons.Default.Key,
                    singleLine = false,
                    minLines = 3,
                    keyboardOptions = KeyboardOptions(autoCorrect = false, keyboardType = KeyboardType.Password),
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

                androidx.compose.material3.TextButton(
                    onClick = { showJoin = true },
                    enabled = !enrolling,
                ) {
                    Text(t("join.entry"))
                }

                Spacer(Modifier.height(4.dp))

                BaluardOutlinedButton(
                    text = t("common.back"),
                    onClick = onCancelled,
                    enabled = !enrolling,
                )
            }
        }
    }

    if (showJoin) {
        JoinSpaceDialog(
            vaultPath = vaultPath,
            authViewModel = authViewModel,
            onApproved = {
                showJoin = false
                onEnrolled()
            },
            onDismiss = { showJoin = false },
        )
    }
}
