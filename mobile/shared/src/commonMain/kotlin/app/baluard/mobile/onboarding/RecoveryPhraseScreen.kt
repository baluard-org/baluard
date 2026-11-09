package app.baluard.mobile.onboarding

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.baluard.mobile.recoverySheetBytes
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.platform.rememberRecoverySheetSaver
import app.baluard.mobile.ui.components.BaluardAmbientBackground
import app.baluard.mobile.ui.components.BaluardCard
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.toast.Toast
import app.baluard.mobile.ui.E2eTags
import androidx.compose.ui.platform.testTag

/**
 * Recovery-phrase display styled with numbered word cards and security alerts.
 */
@Composable
fun RecoveryPhraseScreen(
    words: List<String>,
    onAcknowledged: () -> Unit,
    // Overridden when reusing this screen for the family kit words.
    title: String = t("recovery.title"),
    subtitle: String = t("recovery.subtitle"),
    warning: String = t("recovery.warning"),
    // Sheet filename stem for the TXT/PDF save buttons.
    fileStem: String = "baluard-recovery-phrase",
) {
    var acknowledged by rememberSaveable { mutableStateOf(false) }
    var showFinalCheck by rememberSaveable { mutableStateOf(false) }

    val saver = rememberRecoverySheetSaver()
    val exportSheet = { mimeType: String, fileName: String, format: String ->
        runCatching {
            recoverySheetBytes(
                format,
                title,
                t("recovery.sheetWarning"),
                words.joinToString(" "),
            )
        }.fold(
            onSuccess = { bytes ->
                saver(bytes, mimeType, fileName) { ok ->
                    if (ok) Toast.success(t("recovery.savedToast"))
                }
            },
            onFailure = { Toast.error(t("recovery.saveFailed")) },
        )
    }

    BaluardAmbientBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(16.dp))

            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.ExtraBold),
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(16.dp))

            // Warning Box (matches desktop box-danger-warning)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0xFF7F1D1D).copy(alpha = 0.2f))
                    .border(1.dp, Color(0xFFEF4444).copy(alpha = 0.4f), RoundedCornerShape(12.dp))
                    .padding(14.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = warning,
                        style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
                        color = Color(0xFFFCA5A5),
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            // 24-word grid in 2 columns
            BaluardCard(
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    words.chunked(2).forEachIndexed { rowIndex, pair ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            pair.forEachIndexed { i, word ->
                                val number = rowIndex * 2 + i + 1
                                WordChip(
                                    number = number,
                                    word = word,
                                    modifier = Modifier.weight(1f),
                                )
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            BaluardOutlinedButton(
                text = t("recovery.copyPhrase"),
                onClick = {
                    copyToClipboard(words.joinToString(" "))
                },
                leadingIcon = Icons.Default.ContentCopy,
            )

            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                BaluardOutlinedButton(
                    text = t("recovery.saveTxt"),
                    onClick = { exportSheet("text/plain", "$fileStem.txt", "txt") },
                    modifier = Modifier.weight(1f),
                )
                BaluardOutlinedButton(
                    text = t("recovery.savePdf"),
                    onClick = { exportSheet("application/pdf", "$fileStem.pdf", "pdf") },
                    modifier = Modifier.weight(1f),
                )
            }

            Spacer(Modifier.height(8.dp))
            Text(
                text = t("recovery.fileRisk"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(16.dp))

            // Acknowledgment Card
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainer)
                    .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
                    .testTag(E2eTags.RECOVERY_ACK)
                    .clickable { acknowledged = !acknowledged }
                    .padding(12.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = acknowledged,
                        onCheckedChange = { acknowledged = it },
                        colors = CheckboxDefaults.colors(
                            checkedColor = MaterialTheme.colorScheme.primary,
                            checkmarkColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = t("recovery.ack"),
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            Spacer(Modifier.height(20.dp))

            BaluardPrimaryButton(
                modifier = Modifier.testTag(E2eTags.RECOVERY_CONTINUE),
                text = t("common.continue"),
                // The final check keeps the words on screen unless the
                // user explicitly confirms they are stored.
                onClick = { showFinalCheck = true },
                enabled = acknowledged,
            )

            Spacer(Modifier.height(24.dp))
        }
    }

    if (showFinalCheck) {
        AlertDialog(
            onDismissRequest = { showFinalCheck = false },
            title = {
                Text(
                    text = t("recovery.finalTitle"),
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                )
            },
            text = {
                Text(
                    text = t("recovery.finalBody"),
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showFinalCheck = false
                    onAcknowledged()
                }) {
                    Text(t("recovery.finalConfirm"))
                }
            },
            dismissButton = {
                TextButton(onClick = { showFinalCheck = false }) {
                    Text(t("recovery.finalDecline"))
                }
            },
        )
    }
}

@Composable
private fun WordChip(
    number: Int,
    word: String,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 6.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(
                modifier = Modifier
                    .size(20.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "$number",
                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(8.dp))
            Text(
                text = word,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
