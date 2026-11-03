package app.baluard.mobile.onboarding

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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import app.baluard.mobile.MobileDeviceFlowStatus
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.platform.platformLogE
import app.baluard.mobile.platform.openUrl
import app.baluard.mobile.ui.components.BaluardAmbientBackground
import app.baluard.mobile.ui.components.BaluardCard
import app.baluard.mobile.ui.components.BaluardLogoBadge
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardPrimaryButton

/**
 * RFC 8628 device-code screen styled after Baluard design language.
 */
@Composable
fun DeviceCodeScreen(
    vm: ProviderFlowViewModel,
    flow: app.baluard.mobile.MobileDeviceFlow,
    onAuthorized: () -> Unit,
    onCancelled: () -> Unit,
) {
    var expired by remember { mutableStateOf(false) }
    var revealed by remember { mutableStateOf(false) }

    LaunchedEffect(revealed) {
        if (revealed) {
            // E2E builds surface the one-time device code on logcat so the
            // two-phone harness can type it into the browser. Logged before
            // the clipboard copy so a clipboard failure can never swallow
            // it. Never compiled into release (BuildConfig gate).
            if (app.baluard.mobile.platform.e2eBuild) {
                platformLogE("DeviceCode", "user_code=" + flow.userCode())
            }
            copyToClipboard(flow.userCode().replace("-", ""))
        }
    }

    LaunchedEffect(flow, vm.error) {
        while (!expired && vm.error == null) {
            delay(vm.pollIntervalMs())
            when (vm.pollDeviceFlow(flow)) {
                MobileDeviceFlowStatus.SUCCESS -> { onAuthorized(); return@LaunchedEffect }
                MobileDeviceFlowStatus.EXPIRED -> expired = true
                // null = the flow failed; vm.error holds the reason. Stop:
                // the device code is spent, more polls cannot recover it.
                null -> return@LaunchedEffect
                else -> Unit
            }
        }
    }

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
                subtitle = t("deviceCode.subtitle"),
            )

            Spacer(Modifier.height(28.dp))

            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                if (!revealed && !expired && vm.error == null) {
                    Text(
                        text = t("deviceCode.title"),
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = t("deviceCode.hint"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(20.dp))
                    BaluardPrimaryButton(
                        text = t("common.continue"),
                        onClick = { revealed = true },
                    )
                    Spacer(Modifier.height(10.dp))
                    BaluardOutlinedButton(
                        text = t("common.cancel"),
                        onClick = onCancelled,
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surface)
                            .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
                            .padding(vertical = 18.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = flow.userCode(),
                            style = MaterialTheme.typography.displaySmall.copy(
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 4.sp,
                            ),
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }

                    Spacer(Modifier.height(16.dp))

                    if (vm.error != null) {
                        SelectionContainer {
                            Text(
                                text = vm.error ?: "",
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                        Spacer(Modifier.height(16.dp))
                        BaluardOutlinedButton(
                            text = t("common.back"),
                            onClick = onCancelled,
                        )
                    } else if (expired) {
                        Text(
                            text = t("deviceCode.expired"),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(16.dp))
                        BaluardOutlinedButton(
                            text = t("common.back"),
                            onClick = onCancelled,
                        )
                    } else {
                        Text(
                            text = t("deviceCode.hint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        Spacer(Modifier.height(16.dp))

                        BaluardOutlinedButton(
                            text = t("deviceCode.copy"),
                            onClick = { copyToClipboard(flow.userCode().replace("-", "")) },
                            leadingIcon = Icons.Default.ContentCopy,
                        )

                        Spacer(Modifier.height(10.dp))

                        BaluardPrimaryButton(
                            text = t("deviceCode.openBrowser"),
                            onClick = { openUrl(flow.verificationUri()) },
                            leadingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                        )

                        Spacer(Modifier.height(20.dp))

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.primary,
                            )
                            Spacer(Modifier.size(10.dp))
                            Text(
                                text = t("deviceCode.waiting"),
                                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }

                        Spacer(Modifier.height(16.dp))

                        BaluardOutlinedButton(
                            text = t("common.cancel"),
                            onClick = onCancelled,
                        )
                    }
                }
            }
        }
    }
}
