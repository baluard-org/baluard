package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import xyz.actitud.baluard.i18n.t

/**
 * First-launch root (plan §5.1). Shown when no vault exists at the default
 * app-private path — replaces the bare unlock screen that had nothing to
 * unlock. Two paths mirror desktop: open an existing vault from a git
 * provider, or create a new one.
 *
 * The provider path is wired to the Slice B FFI surface but its screens are
 * not built yet, so the button stays disabled until ProviderConnectScreen
 * lands; [onOpenProvider] is the hook it plugs into.
 */
@Composable
fun OnboardingScreen(
    onCreateVault: () -> Unit,
    onOpenProvider: () -> Unit = {},
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Baluard", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            t("onboarding.subtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(48.dp))

        Button(
            onClick = onCreateVault,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(t("onboarding.createVault"))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(
            onClick = onOpenProvider,
            enabled = false,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(t("onboarding.openExisting"))
        }
        Text(
            t("onboarding.openExistingHint"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}
