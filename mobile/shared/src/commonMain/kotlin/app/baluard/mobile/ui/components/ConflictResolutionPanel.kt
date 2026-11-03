package app.baluard.mobile.ui.components

import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.baluard.mobile.i18n.t
import app.baluard.mobile.sync.ConflictVerdict
import app.baluard.mobile.sync.PendingConflictDto

/**
 * Conflict decision overlay (B4; Compose port of the desktop
 * ConflictResolutionPanel). Rendered on top of the app by `App.kt` whenever
 * [ConflictViewModel.current] is non-null — a paused conflict blocks the sync
 * cycle, so the decision is unavoidable by design.
 *
 * Cross-epoch conflicts ([PendingConflictDto.crossEpoch]) hide "keep both":
 * the runtime cannot decrypt the unreachable side, so cloning it would
 * produce garbage; only the raw-blob verdicts are safe.
 */
@Composable
fun ConflictResolutionPanel(
    conflict: PendingConflictDto,
    queued: Int,
    resolving: Boolean,
    error: String?,
    onVerdict: (ConflictVerdict) -> Unit,
) {
    // Scrim + centered card. No dismiss control: the decision gates sync.
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.6f)),
        contentAlignment = Alignment.Center,
    ) {
        BaluardCard(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
        ) {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(24.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = t(
                            if (conflict.crossEpoch) "conflict.crossEpochTitle" else "conflict.title",
                        ),
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }

                Spacer(Modifier.height(12.dp))

                Text(
                    text = if (conflict.crossEpoch) {
                        t("conflict.crossEpochBody", conflict.name ?: "")
                    } else {
                        t("conflict.body", conflict.name ?: "")
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (!conflict.crossEpoch && conflict.fields.isNotEmpty()) {
                    Spacer(Modifier.height(16.dp))
                    Text(
                        text = t("conflict.fieldsHeader"),
                        style = MaterialTheme.typography.labelMedium.copy(
                            fontWeight = FontWeight.Bold,
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    conflict.fields.forEach { field ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = field.label,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            if (field.sensitive) {
                                Text(
                                    text = t("conflict.sensitiveField"),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }

                if (queued > 1) {
                    Spacer(Modifier.height(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(MaterialTheme.colorScheme.tertiary.copy(alpha = 0.12f))
                            .padding(horizontal = 8.dp, vertical = 3.dp),
                    ) {
                        Text(
                            text = t("conflict.moreQueued", queued - 1),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.tertiary,
                        )
                    }
                }

                error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = t("conflict.error"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                Spacer(Modifier.height(20.dp))

                if (resolving) {
                    Box(
                        modifier = Modifier.fillMaxWidth(),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(28.dp),
                            strokeWidth = 3.dp,
                        )
                    }
                } else {
                    BaluardPrimaryButton(
                        text = t("conflict.keepLocal"),
                        onClick = { onVerdict(ConflictVerdict.KEEP_LOCAL) },
                    )
                    Spacer(Modifier.height(8.dp))
                    BaluardOutlinedButton(
                        text = t("conflict.keepRemote"),
                        onClick = { onVerdict(ConflictVerdict.KEEP_REMOTE) },
                    )
                    if (!conflict.crossEpoch) {
                        Spacer(Modifier.height(8.dp))
                        BaluardOutlinedButton(
                            text = t("conflict.keepBoth"),
                            onClick = { onVerdict(ConflictVerdict.KEEP_BOTH) },
                        )
                    }
                }
            }
        }
    }
}
