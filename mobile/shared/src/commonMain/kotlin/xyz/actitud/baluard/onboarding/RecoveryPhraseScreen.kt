package xyz.actitud.baluard.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.setSecureFlag

/**
 * Recovery-phrase display (plan §3.5 / §5.5). The 24 words are shown exactly
 * once — the ceremony HPKE-wraps them into meta/recovery.json and they are
 * never rendered again. Continue is gated on the "I wrote it down" checkbox;
 * there is no way forward without acknowledging loss of the phrase means loss
 * of the vault.
 *
 * FLAG_SECURE is set for the lifetime of this screen (screenshot / recents
 * preview shield) and cleared on leave.
 */
@Composable
fun RecoveryPhraseScreen(
    words: List<String>,
    onAcknowledged: () -> Unit,
) {
    DisposableEffect(Unit) {
        setSecureFlag(true)
        onDispose { setSecureFlag(false) }
    }

    var acknowledged by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(t("recovery.title"), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            t("recovery.subtitle"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))

        // Numbered flow layout, 2 words per row: the canonical paper-slips format.
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            words.chunked(2).forEachIndexed { rowIndex, pair ->
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    pair.forEachIndexed { i, word ->
                        val number = rowIndex * 2 + i + 1
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "$number.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                word,
                                style = MaterialTheme.typography.titleMedium,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(start = 4.dp),
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        Text(
            t("recovery.warning"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
        Spacer(Modifier.height(24.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = acknowledged,
                onCheckedChange = { acknowledged = it },
            )
            Text(t("recovery.ack"))
        }
        Spacer(Modifier.height(16.dp))

        Button(
            onClick = onAcknowledged,
            enabled = acknowledged,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(t("common.continue"))
        }
    }
}
