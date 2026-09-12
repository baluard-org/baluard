package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardAmbientBackground
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardLogoBadge
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTextField

/**
 * Provider picker styled after Baluard design language.
 */
@Composable
fun ProviderConnectScreen(
    vm: ProviderFlowViewModel,
    onDeviceCodeStarted: () -> Unit,
    onPatConnected: () -> Unit,
    onCancelled: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    // M6: the typed PAT is a secret — plain `remember` only. Saved instance
    // state persists to disk and must never carry it; losing it on rotation
    // is correct behavior for a secret.
    var token by remember { mutableStateOf("") }
    var showPat by rememberSaveable { mutableStateOf(false) }

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
                subtitle = t("provider.subtitle"),
            )

            Spacer(Modifier.height(28.dp))

            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    ProviderSelectCard(
                        title = t("provider.github"),
                        subtitle = "Fast device-code login",
                        provider = MobileProvider.GIT_HUB,
                        icon = Icons.Default.Public,
                        selected = vm.provider == MobileProvider.GIT_HUB,
                        enabled = !vm.busy,
                        onSelect = { vm.selectProvider(MobileProvider.GIT_HUB) },
                    )
                    ProviderSelectCard(
                        title = t("provider.gitlab"),
                        subtitle = "Cloud or self-hosted GitLab",
                        provider = MobileProvider.GIT_LAB,
                        icon = Icons.Default.Code,
                        selected = vm.provider == MobileProvider.GIT_LAB,
                        enabled = !vm.busy,
                        onSelect = { vm.selectProvider(MobileProvider.GIT_LAB) },
                    )
                    ProviderSelectCard(
                        title = t("provider.codeberg"),
                        subtitle = "Personal access token",
                        provider = MobileProvider.CODEBERG,
                        icon = Icons.Default.Key,
                        selected = vm.provider == MobileProvider.CODEBERG,
                        enabled = !vm.busy,
                        onSelect = { vm.selectProvider(MobileProvider.CODEBERG) },
                    )
                }

                vm.error?.let {
                    Spacer(Modifier.height(12.dp))
                    SelectionContainer {
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }

                Spacer(Modifier.height(18.dp))

                if (vm.busy) {
                    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                    }
                } else if (showPat) {
                    BaluardTextField(
                        value = token,
                        onValueChange = { token = it },
                        label = t("provider.patLabel"),
                        placeholder = "ghp_... / glpat-... / token",
                        singleLine = true,
                        // M6: a pasted PAT must not be legible over the
                        // shoulder or in screenshots.
                        isPassword = true,
                    )
                    Spacer(Modifier.height(12.dp))
                    BaluardPrimaryButton(
                        text = t("provider.patConnect"),
                        onClick = {
                            scope.launch {
                                vm.connectPat(token)
                                if (vm.stage is ProviderFlowViewModel.Stage.Repos) onPatConnected()
                            }
                        },
                        enabled = token.isNotBlank(),
                    )
                    Spacer(Modifier.height(8.dp))
                    BaluardOutlinedButton(
                        text = t("common.back"),
                        onClick = { showPat = false },
                    )
                } else {
                    when (vm.provider) {
                        MobileProvider.CODEBERG -> {
                            BaluardPrimaryButton(
                                text = t("provider.continuePat"),
                                onClick = { showPat = true },
                            )
                        }
                        else -> {
                            BaluardPrimaryButton(
                                text = t("provider.continueBrowser"),
                                onClick = {
                                    scope.launch {
                                        vm.startDeviceFlow()
                                        if (vm.stage is ProviderFlowViewModel.Stage.DeviceCode) onDeviceCodeStarted()
                                    }
                                },
                            )
                            Spacer(Modifier.height(8.dp))
                            BaluardOutlinedButton(
                                text = t("provider.usePatInstead"),
                                onClick = { showPat = true },
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    BaluardOutlinedButton(
                        text = t("common.back"),
                        onClick = onCancelled,
                    )
                }
            }
        }
    }
}

@Composable
private fun ProviderSelectCard(
    title: String,
    subtitle: String,
    provider: MobileProvider,
    icon: ImageVector,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(
                width = if (selected) 1.5.dp else 1.dp,
                color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                shape = RoundedCornerShape(12.dp),
            )
            .clickable(enabled = enabled, onClick = onSelect),
        shape = RoundedCornerShape(12.dp),
        color = if (selected) MaterialTheme.colorScheme.surfaceContainerHigh else MaterialTheme.colorScheme.surface,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(
                        if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
                        else MaterialTheme.colorScheme.surfaceContainer,
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
            }

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (selected) {
                Box(
                    modifier = Modifier
                        .size(22.dp)
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.primary),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = "Selected",
                        tint = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.size(14.dp),
                    )
                }
            }
        }
    }
}
