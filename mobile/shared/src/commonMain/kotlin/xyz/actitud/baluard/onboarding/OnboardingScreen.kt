package xyz.actitud.baluard.onboarding

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardAmbientBackground
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardLogoBadge
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.GitExplainerDialog
import xyz.actitud.baluard.ui.components.GitWhatLink
import xyz.actitud.baluard.ui.components.rememberShareOpenFlow
import xyz.actitud.baluard.ui.E2eTags
import androidx.compose.ui.platform.testTag
/**
 * First-launch root styled with Baluard brand cards and feature highlights.
 */
@Composable
fun OnboardingScreen(
    onCreateVault: () -> Unit,
    onOpenProvider: () -> Unit = {},
) {
    var gitHelpOpen by remember { mutableStateOf(false) }
    BaluardAmbientBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            BaluardLogoBadge(
                size = 72.dp,
                showTitle = true,
                subtitle = t("onboarding.subtitle"),
            )

            Spacer(Modifier.height(32.dp))

            BaluardCard(
                modifier = Modifier.fillMaxWidth(),
            ) {
                FeatureRow(
                    icon = Icons.Default.Lock,
                    title = t("onboarding.featureEncryptTitle"),
                    desc = t("onboarding.featureEncryptDesc"),
                )
                Spacer(Modifier.height(12.dp))
                FeatureRow(
                    icon = Icons.Default.Shield,
                    title = t("onboarding.featureSyncTitle"),
                    desc = t("onboarding.featureSyncDesc"),
                )
                Spacer(Modifier.height(12.dp))
                FeatureRow(
                    icon = Icons.Default.Key,
                    title = t("onboarding.featureKeysTitle"),
                    desc = t("onboarding.featureKeysDesc"),
                )
            }

            Spacer(Modifier.height(24.dp))

            BaluardPrimaryButton(
                modifier = Modifier.testTag(E2eTags.ONBOARDING_CREATE),
                text = t("onboarding.createVault"),
                onClick = onCreateVault,
                leadingIcon = Icons.Default.Add,
            )

            Spacer(Modifier.height(12.dp))

            BaluardOutlinedButton(
                text = t("onboarding.openExisting"),
                onClick = onOpenProvider,
                leadingIcon = Icons.Default.CloudDownload,
            )

            Spacer(Modifier.height(8.dp))

            Text(
                text = t("onboarding.openExistingHint"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GitWhatLink(onOpen = { gitHelpOpen = true })

            Spacer(Modifier.height(12.dp))

            // G4: pre-vault guest flow — a recipient without an account
            // opens a passphrase share straight from onboarding.
            val shareOpen = rememberShareOpenFlow(guestOnly = true, vault = null, repo = null)
            BaluardOutlinedButton(
                text = t("share.openRow"),
                onClick = shareOpen.open,
                leadingIcon = Icons.Default.Folder,
            )
        }
    }
    if (gitHelpOpen) {
        GitExplainerDialog(onDismiss = { gitHelpOpen = false })
    }
}

@Composable
private fun FeatureRow(
    icon: ImageVector,
    title: String,
    desc: String,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
                .border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.3f), RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(18.dp),
            )
        }

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = desc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
