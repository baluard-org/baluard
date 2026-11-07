package app.baluard.mobile.totp

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import app.baluard.mobile.MobileVault
import app.baluard.mobile.i18n.t
import app.baluard.mobile.monetization.Entitlements
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.CopiedBadge
import app.baluard.mobile.ui.components.rememberCopied

/**
 * Live TOTP widget styled with Baluard card, progress bar, and copy-on-tap.
 */
@Composable
fun TotpWidget(
    vault: MobileVault,
    cipherId: String,
    viewModel: TotpViewModel,
    onUpgradeRequired: () -> Unit = {},
) {
    val state by viewModel.state.collectAsState()
    val copied = rememberCopied()
    // ADR 0102: the entitlement is an effect key so a purchase from the
    // locked card's own sheet restarts start() and the live code appears
    // without leaving the screen.
    val entitlement by Entitlements.state.collectAsState()

    // Nothing else starts the fetch: without this the state sits on Loading
    // forever (spinner + "loading code"). Leaving the screen cancels the
    // countdown loop via the CancellationException path in start().
    LaunchedEffect(vault, cipherId, entitlement.totpUnlocked) { viewModel.start(vault, cipherId) }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
        ) {
            when (val s = state) {
                is TotpState.Loading -> Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = t("totp.loading"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                is TotpState.Code -> {
                    val formattedCode = if (s.code.length == 6) {
                        "${s.code.substring(0, 3)} ${s.code.substring(3)}"
                    } else s.code

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .clickable { copied.copy(s.code) },
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Timer,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(14.dp),
                                )
                                Spacer(Modifier.width(4.dp))
                                Text(
                                    text = t("totp.oneTimeCode"),
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontWeight = FontWeight.ExtraBold,
                                        letterSpacing = 0.5.sp,
                                    ),
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = formattedCode,
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.headlineMedium.copy(
                                    fontWeight = FontWeight.ExtraBold,
                                    letterSpacing = 2.sp,
                                ),
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CopiedBadge(visible = copied.visible)

                            IconButton(
                                onClick = {
                                    copied.copy(s.code)
                                },
                            ) {
                                Icon(
                                    imageVector = Icons.Default.ContentCopy,
                                    contentDescription = t("detail.copy"),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(8.dp))

                    LinearProgressIndicator(
                        progress = { (s.secondsRemaining.toFloat() / s.periodSeconds.toFloat()).coerceIn(0f, 1f) },
                        color = if (s.secondsRemaining <= 5) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.outlineVariant,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp)),
                    )

                    Spacer(Modifier.height(4.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = t("totp.nextCodeIn"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            text = "${s.secondsRemaining}s",
                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                            color = if (s.secondsRemaining <= 5) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        )
                    }
                }

                is TotpState.Locked -> Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = t("totp.locked"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    s.trialDaysLeft?.let { days ->
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = t("upgrade.trialDaysLeft", days),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    BaluardOutlinedButton(
                        text = t("upgrade.subscribe"),
                        onClick = onUpgradeRequired,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                is TotpState.Error -> Text(
                    text = s.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
