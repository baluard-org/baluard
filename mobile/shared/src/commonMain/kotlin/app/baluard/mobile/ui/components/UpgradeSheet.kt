package app.baluard.mobile.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.window.DialogProperties
import app.baluard.mobile.i18n.t
import app.baluard.mobile.monetization.Entitlements
import app.baluard.mobile.monetization.PurchaseOutcome
import kotlinx.coroutines.launch

/**
 * The single upgrade surface (ADR 0102): every gated screen opens this sheet
 * instead of a dead end. Runs the purchase flow through the entitlement gate;
 * a successful purchase live-applies on dismissal via [Entitlements.refresh].
 */
@Composable
fun UpgradeSheet(
    shown: Boolean,
    onDismiss: () -> Unit,
) {
    if (!shown) return
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var resultLine by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        properties = DialogProperties(dismissOnBackPress = !busy, dismissOnClickOutside = !busy),
        title = { Text(t("upgrade.title")) },
        text = {
            androidx.compose.foundation.layout.Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    t("upgrade.body"),
                    style = MaterialTheme.typography.bodyMedium,
                )
                resultLine?.let { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy,
                onClick = {
                    busy = true
                    resultLine = null
                    scope.launch {
                        when (val outcome = Entitlements.purchase()) {
                            PurchaseOutcome.Purchased -> {
                                busy = false
                                onDismiss()
                            }
                            PurchaseOutcome.Cancelled -> {
                                busy = false
                            }
                            PurchaseOutcome.Unavailable -> {
                                busy = false
                                resultLine = t("upgrade.unavailable")
                            }
                            is PurchaseOutcome.Error -> {
                                busy = false
                                resultLine = t("upgrade.failed")
                            }
                        }
                    }
                },
            ) {
                Text(if (busy) t("upgrade.busy") else t("upgrade.subscribe"))
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text(t("common.cancel")) }
        },
    )
}
