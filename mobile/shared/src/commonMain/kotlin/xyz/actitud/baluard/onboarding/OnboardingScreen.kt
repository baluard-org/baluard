package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardAmbientBackground
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardLogoBadge
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.GitExplainerDialog
import xyz.actitud.baluard.ui.components.GitWhatLink
import xyz.actitud.baluard.ui.components.rememberShareOpenFlow
import xyz.actitud.baluard.ui.E2eTags
import androidx.compose.ui.platform.testTag
/**
 * First-launch root styled with Baluard brand cards and feature highlights.
 */
@Composable
fun OnboardingScreen(
    onCreateVault: () -> Unit,
    onOpenProvider: () -> Unit = {},
    onRecovered: (path: String) -> Unit = {},
) {
    var gitHelpOpen by remember { mutableStateOf(false) }
    BaluardAmbientBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            BaluardLogoBadge(
                size = 72.dp,
                showTitle = true,
                subtitle = t("onboarding.subtitle"),
            )

            Spacer(Modifier.height(32.dp))

            BaluardCard(
                modifier = Modifier.fillMaxWidth(),
            ) {
                FeatureRow(
                    icon = Icons.Default.Lock,
                    title = t("onboarding.featureEncryptTitle"),
                    desc = t("onboarding.featureEncryptDesc"),
                )
                Spacer(Modifier.height(12.dp))
                FeatureRow(
                    icon = Icons.Default.Shield,
                    title = t("onboarding.featureSyncTitle"),
                    desc = t("onboarding.featureSyncDesc"),
                )
                Spacer(Modifier.height(12.dp))
                FeatureRow(
                    icon = Icons.Default.Key,
                    title = t("onboarding.featureKeysTitle"),
                    desc = t("onboarding.featureKeysDesc"),
                )
            }

            Spacer(Modifier.height(24.dp))

            BaluardPrimaryButton(
                modifier = Modifier.testTag(E2eTags.ONBOARDING_CREATE),
                text = t("onboarding.createVault"),
                onClick = onCreateVault,
                leadingIcon = Icons.Default.Add,
            )

            Spacer(Modifier.height(12.dp))

            BaluardOutlinedButton(
                text = t("onboarding.openExisting"),
                onClick = onOpenProvider,
                leadingIcon = Icons.Default.CloudDownload,
            )

            Spacer(Modifier.height(8.dp))

            Text(
                text = t("onboarding.openExistingHint"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GitWhatLink(onOpen = { gitHelpOpen = true })

            Spacer(Modifier.height(12.dp))

            // G4: pre-vault guest flow — a recipient without an account
            // opens a passphrase share straight from onboarding.
            val shareOpen = rememberShareOpenFlow(guestOnly = true, vault = null, repo = null)
            BaluardOutlinedButton(
                text = t("share.openRow"),
                onClick = shareOpen.open,
                leadingIcon = Icons.Default.Folder,
            )

            Spacer(Modifier.height(8.dp))

            // G6: kit recovery on a fresh device — the vault is on disk
            // (cloned or restored) but this device has no key yet. The
            // kit phrase mints a fresh member row and password.
            var kitRecoverOpen by remember { mutableStateOf(false) }
            BaluardOutlinedButton(
                text = t("onboarding.kitRecoverRow"),
                onClick = { kitRecoverOpen = true },
                leadingIcon = Icons.Default.Key,
            )

            if (kitRecoverOpen) {
                KitRecoverDialog(
                    onDismiss = { kitRecoverOpen = false },
                    onRecovered = onRecovered,
                )
            }
        }
    }
    if (gitHelpOpen) {
        GitExplainerDialog(onDismiss = { gitHelpOpen = false })
    }
}

@Composable
private fun FeatureRow(
    icon: ImageVector,
    title: String,
    desc: String,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
                .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.3f), RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(18.dp),
            )
        }

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = desc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** G6: phrase-only kit recovery for a vault discovered on this device
 * (fresh clone / restored directory). The kit phrase unwraps the Root
 * Key; the new password is THIS device's own master password. */
@Composable
private fun KitRecoverDialog(onDismiss: () -> Unit, onRecovered: (String) -> Unit) {
    val vaults = remember { xyz.actitud.baluard.platform.VaultRegistry.listVaults() }
    var picked by remember { mutableStateOf(vaults.firstOrNull()) }
    var pickerOpen by remember { mutableStateOf(vaults.size > 1) }
    var phrase by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    if (pickerOpen) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(t("onboarding.kitPickTitle")) },
            text = {
                Column {
                    if (vaults.isEmpty()) {
                        Text(t("onboarding.kitPickEmpty"))
                    }
                    vaults.forEach { v ->
                        TextButton(onClick = { picked = v; pickerOpen = false }) {
                            Text(v.name)
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = onDismiss) { Text(t("common.cancel")) }
            },
        )
        return
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(t("onboarding.kitTitle")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    t("onboarding.kitDesc", picked?.name ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (vaults.size > 1) {
                    TextButton(onClick = { pickerOpen = true }) {
                        Text(t("onboarding.kitChangeVault", picked?.name ?: ""))
                    }
                }
                OutlinedTextField(
                    value = phrase,
                    onValueChange = { phrase = it },
                    label = { Text(t("onboarding.kitPhrase")) },
                    isError = error != null,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(t("onboarding.kitPassword")) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text(t("onboarding.kitPasswordConfirm")) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = confirm.isNotEmpty() && password != confirm,
                    supportingText = {
                        if (confirm.isNotEmpty() && password != confirm) Text(t("onboarding.kitPasswordMismatch"))
                    },
                )
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it },
                    label = { Text(t("onboarding.kitDeviceName")) },
                    singleLine = true,
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && picked != null && phrase.isNotBlank() &&
                    password.length >= 8 && password == confirm && deviceName.isNotBlank(),
                onClick = {
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val target = picked!!
                            xyz.actitud.baluard.recoverKitForPath(
                                target.path,
                                phrase.trim(),
                                password,
                                deviceName.trim(),
                            )
                            onDismiss()
                            // Hand off: the recovered vault becomes the
                            // active one and the app moves to the unlock
                            // stage (the password just chosen unlocks it).
                            onRecovered(target.path)
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            error = e.message ?: t("onboarding.kitFailed")
                        }
                        busy = false
                    }
                },
            ) { Text(t("common.continue")) }
        },
        dismissButton = {
            TextButton(onClick = { if (!busy) onDismiss() }) { Text(t("common.cancel")) }
        },
    )
}
