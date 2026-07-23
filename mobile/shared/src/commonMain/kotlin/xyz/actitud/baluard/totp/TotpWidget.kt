package xyz.actitud.baluard.totp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import xyz.actitud.baluard.MobileVault

/**
 * Live TOTP widget: 6-digit code + a countdown bar showing seconds until the
 * next code rolls. Re-fetches from the runtime at each 30s window boundary.
 */
@Composable
fun TotpWidget(
    vault: MobileVault,
    cipherId: String,
    viewModel: TotpViewModel,
) {
    val state by viewModel.state.collectAsState()
    LaunchedEffect(cipherId) { viewModel.start(vault, cipherId) }

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        when (val s = state) {
            is TotpState.Loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp))
                Spacer(Modifier.height(8.dp))
                Text("loading code…", style = MaterialTheme.typography.bodySmall)
            }
            is TotpState.Code -> {
                Text(
                    s.code,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(Modifier.height(4.dp))
                LinearProgressIndicator(
                    progress = { s.secondsRemaining / 30f },
                    modifier = Modifier.fillMaxWidth().height(3.dp),
                )
                Text(
                    "${s.secondsRemaining}s",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline,
                )
            }
            is TotpState.Error -> Text(
                s.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
