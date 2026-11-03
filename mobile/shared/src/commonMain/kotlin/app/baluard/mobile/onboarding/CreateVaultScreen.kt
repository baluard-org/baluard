package app.baluard.mobile.onboarding

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import app.baluard.mobile.auth.AuthViewModel
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.deviceDisplayName
import app.baluard.mobile.ui.components.BaluardAmbientBackground
import app.baluard.mobile.ui.components.BaluardCard
import app.baluard.mobile.ui.components.BaluardLogoBadge
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.E2eTags
import app.baluard.mobile.ui.BackPressHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.selection.selectable
import app.baluard.mobile.ui.toast.Toast

/**
 * Vault-creation form styled after Baluard design guidelines.
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

    // Plain remember: the master password never rides the saved-instance
    // Bundle (M6 rule, ProviderConnectScreen parity).
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    // OS-provided name (Pixel 9 Pro, Esteban's iPhone); localized
    // "My device" only when the OS gives nothing. Still editable.
    var deviceName by rememberSaveable {
        mutableStateOf(deviceDisplayName().ifBlank { t("onboarding.defaultDeviceName") })
    }
    // Switcher display name, pre-filled with the CLI's default; blank still
    // resolves to "Personal" inside the FFI.
    var vaultName by rememberSaveable { mutableStateOf("Personal") }
    var creating by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    var phraseShown by rememberSaveable { mutableStateOf(false) }
    var kitShown by rememberSaveable { mutableStateOf(false) }
    var purpose by rememberSaveable { mutableStateOf("personal") }

    if (kitShown) {
        // Family kit words: the second words-once screen. Back falls
        // through to App's chain (same words-once rule as the phrase).
        // Rotation/process death wipes the in-memory words while the
        // saveable phase flags survive, so an empty kit here means the
        // words are gone for good: proceed honestly with a warning —
        // the kit can be replaced from the vault's settings.
        if (vm.kitWords.isEmpty()) {
            Toast.error(t("recovery.kitLost"))
            onCreated()
            return
        }
        RecoveryPhraseScreen(
            words = vm.kitWords,
            onAcknowledged = onCreated,
            title = t("recovery.kitTitle"),
            subtitle = t("recovery.kitSubtitle"),
            warning = t("recovery.kitWarning"),
            fileStem = "baluard-family-kit",
        )
        return
    }

    if (phraseShown) {
        RecoveryPhraseScreen(
            words = vm.recoveryWords,
            onAcknowledged = {
                when {
                    purpose == "family" && vm.kitWords.isNotEmpty() -> {
                        phraseShown = false
                        kitShown = true
                    }
                    purpose == "family" -> {
                        // Words lost to a screen restart: creation itself
                        // succeeded, so proceed with a loud warning.
                        Toast.error(t("recovery.kitLost"))
                        onCreated()
                    }
                    vm.recoveryWords.isEmpty() -> {
                        Toast.error(t("recovery.lostWords"))
                        onCreated()
                    }
                    else -> onCreated()
                }
            },
        )
        return
    }

    // Form-phase back cancels; once the phrase is up this composable has
    // returned, so back falls through to App's (disabled) chain — the
    // words-once rule keeps the phrase phase non-cancellable.
    BackPressHandler(enabled = !creating, onBack = onCancelled)

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
                subtitle = t("onboarding.createSubtitle"),
            )

            Spacer(Modifier.height(28.dp))

            BaluardCard(
                modifier = Modifier.fillMaxWidth(),
            ) {
                BaluardTextField(
                    value = vaultName,
                    modifier = Modifier.testTag(E2eTags.CREATE_NAME),
                    onValueChange = {
                        vaultName = it
                        error = null
                    },
                    label = t("onboarding.vaultName"),
                    placeholder = t("onboarding.vaultName"),
                    leadingIcon = Icons.Default.Folder,
                    enabled = !creating,
                    singleLine = true,
                )

                Spacer(Modifier.height(12.dp))

                BaluardTextField(
                    value = password,
                    modifier = Modifier.testTag(E2eTags.CREATE_PASSWORD),
                    onValueChange = {
                        password = it
                        error = null
                    },
                    label = t("login.passwordPlaceholder"),
                    placeholder = t("login.passwordPlaceholder"),
                    leadingIcon = Icons.Default.Lock,
                    isPassword = true,
                    enabled = !creating,
                    isError = password.isNotEmpty() && password.length < MIN_PASSWORD_LEN,
                    supportingText = if (password.isNotEmpty() && password.length < MIN_PASSWORD_LEN) {
                        t("onboarding.errorMinLength")
                    } else null,
                )

                Spacer(Modifier.height(12.dp))

                BaluardTextField(
                    value = confirm,
                    modifier = Modifier.testTag(E2eTags.CREATE_CONFIRM),
                    onValueChange = {
                        confirm = it
                        error = null
                    },
                    label = t("onboarding.confirmPassword"),
                    placeholder = t("onboarding.confirmPassword"),
                    leadingIcon = Icons.Default.Lock,
                    isPassword = true,
                    enabled = !creating,
                    isError = confirm.isNotEmpty() && confirm != password,
                    supportingText = if (confirm.isNotEmpty() && confirm != password) {
                        t("onboarding.errorMismatch")
                    } else null,
                )

                Spacer(Modifier.height(12.dp))

                BaluardTextField(
                    value = deviceName,
                    modifier = Modifier.testTag(E2eTags.CREATE_DEVICE_NAME),
                    onValueChange = {
                        deviceName = it
                        error = null
                    },
                    label = t("onboarding.deviceName"),
                    leadingIcon = Icons.Default.PhoneAndroid,
                    enabled = !creating,
                )

                Spacer(Modifier.height(12.dp))

                Text(
                    text = t("onboarding.purposeLabel"),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(6.dp))
                Row(Modifier.fillMaxWidth()) {
                    PurposeOption(
                        label = t("onboarding.purposePersonal"),
                        selected = purpose == "personal",
                        enabled = !creating,
                        onClick = { purpose = "personal" },
                        modifier = Modifier.weight(1f).testTag(E2eTags.CREATE_PURPOSE_PERSONAL),
                    )
                    Spacer(Modifier.width(8.dp))
                    PurposeOption(
                        label = t("onboarding.purposeFamily"),
                        selected = purpose == "family",
                        enabled = !creating,
                        onClick = { purpose = "family" },
                        modifier = Modifier.weight(1f).testTag(E2eTags.CREATE_PURPOSE_FAMILY),
                    )
                }

                error?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                Spacer(Modifier.height(20.dp))

                BaluardPrimaryButton(
                    modifier = Modifier.testTag(E2eTags.CREATE_SUBMIT),
                    text = t("onboarding.createButton"),
                    onClick = {
                        if (password.length < MIN_PASSWORD_LEN) {
                            error = t("onboarding.errorMinLength")
                            return@BaluardPrimaryButton
                        }
                        if (password != confirm) {
                            error = t("onboarding.errorMismatch")
                            return@BaluardPrimaryButton
                        }
                        creating = true
                        error = null
                        scope.launch {
                            val ok = vm.create(vaultPath, vaultName, password, deviceName, family = purpose == "family")
                            creating = false
                            if (ok) {
                                phraseShown = true
                            } else {
                                error = vm.error
                            }
                        }
                    },
                    enabled = password.length >= MIN_PASSWORD_LEN && confirm == password && deviceName.isNotBlank(),
                    loading = creating,
                    leadingIcon = Icons.Default.Add,
                )

                Spacer(Modifier.height(10.dp))

                BaluardOutlinedButton(
                    text = t("common.back"),
                    onClick = onCancelled,
                    enabled = !creating,
                )
            }
        }
    }
}

private const val MIN_PASSWORD_LEN = 8

/** One half of the vault-purpose selector (Personal / Family). */
@Composable
private fun PurposeOption(
    label: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .border(
                1.dp,
                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                RoundedCornerShape(10.dp),
            )
            .selectable(
                selected = selected,
                enabled = enabled,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null, enabled = enabled)
        Spacer(Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}
