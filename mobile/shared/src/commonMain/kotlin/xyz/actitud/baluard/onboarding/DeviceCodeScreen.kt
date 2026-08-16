package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import xyz.actitud.baluard.MobileDeviceFlowStatus
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.openUrl

/**
 * RFC 8628 device-code screen (plan §5.2): shows the user code, opens the
 * browser at the verification URI, and polls until the user approves
 * (SUCCESS -> repos), the code EXPIRED, or the user backs out.
 *
 * The poll interval starts at 5 s and grows 5 s on SLOW_DOWN; backoff state
 * lives in the view model.
 */
@Composable
fun DeviceCodeScreen(
    vm: ProviderFlowViewModel,
    flow: xyz.actitud.baluard.MobileDeviceFlow,
    onAuthorized: () -> Unit,
    onCancelled: () -> Unit,
) {
    var expired by remember { mutableStateOf(false) }

    // Poll loop. Runs while this screen is composed; cancelled on leave.
    LaunchedEffect(flow) {
        while (!expired) {
            delay(vm.pollIntervalMs())
            when (vm.pollDeviceFlow(flow)) {
                MobileDeviceFlowStatus.SUCCESS -> { onAuthorized(); return@LaunchedEffect }
                MobileDeviceFlowStatus.EXPIRED -> expired = true
                else -> Unit // PENDING / SLOW_DOWN: keep waiting
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(t("deviceCode.title"), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        Text(
            t("deviceCode.subtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        Text(
            flow.userCode(),
            style = MaterialTheme.typography.displaySmall,
            fontFamily = FontFamily.Monospace,
        )
        Spacer(Modifier.height(24.dp))

        if (expired) {
            Text(t("deviceCode.expired"), color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(16.dp))
            Button(onClick = onCancelled, modifier = Modifier.fillMaxWidth()) {
                Text(t("common.back"))
            }
        } else {
            Button(
                onClick = { openUrl(flow.verificationUri()) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(t("deviceCode.openBrowser")) }
            Spacer(Modifier.height(16.dp))
            CircularProgressIndicator()
            Spacer(Modifier.height(8.dp))
            Text(
                t("deviceCode.waiting"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            TextButton(onClick = onCancelled) { Text(t("common.cancel")) }
        }
    }
}
