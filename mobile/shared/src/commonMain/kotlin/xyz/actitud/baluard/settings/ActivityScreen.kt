package xyz.actitud.baluard.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import xyz.actitud.baluard.data.MobileActivityRow
import xyz.actitud.baluard.data.MobileNotice
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.detail.formatEpochDate
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.SectionCard

/**
 * S1b surfaces: needs-attention notices, this device's share-event
 * log, and its refusal log. Every member sees their own activity —
 * the data is per-device and local; no admin gate applies.
 */
@Composable
fun ActivityScreen(
    vault: xyz.actitud.baluard.MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
) {
    var notices by remember(vault) { mutableStateOf<List<MobileNotice>>(emptyList()) }
    var events by remember(vault) { mutableStateOf<List<MobileActivityRow>>(emptyList()) }
    var refusals by remember(vault) { mutableStateOf<List<String>>(emptyList()) }
    var loaded by remember(vault) { mutableStateOf(false) }

    LaunchedEffect(vault) {
        notices = repo.noticesList(vault)
        events = repo.activityEvents(vault)
        refusals = repo.activityRefusals(vault)
        loaded = true
    }

    Scaffold(
        topBar = { BaluardTopBar(title = t("activity.title"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Blank while loading: a false "no data" would read as a
            // clean bill of health during the fetch window.
            if (loaded) {
                item(key = "notices") {
                    SectionCard(title = t("activity.noticesTitle")) {
                        if (notices.isEmpty()) {
                            Text(
                                text = t("activity.noNotices"),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                notices.forEach { n ->
                                    Text(
                                        text = noticeText(n),
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                }
                            }
                        }
                    }
                }
                item(key = "events") {
                    SectionCard(title = t("activity.eventsTitle")) {
                        if (events.isEmpty()) {
                            Text(
                                text = t("activity.noEvents"),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                events.forEach { e ->
                                    Column {
                                        Text(
                                            text = formatEpochDate(e.at),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                        Text(
                                            text = e.detail,
                                            style = MaterialTheme.typography.bodyMedium,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                item(key = "refusals") {
                    SectionCard(title = t("activity.refusalsTitle")) {
                        if (refusals.isEmpty()) {
                            Text(
                                text = t("activity.noRefusals"),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                refusals.forEach { line ->
                                    Text(
                                        text = line,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Fixed when-mapping over known notice kinds; unknown falls to a
 * sensible default (the mobile i18n convention — no dynamic keys). */
private fun noticeText(n: MobileNotice): String = when (n.kind) {
    "reset_pending" -> t("activity.noticeResetPending", n.name ?: "")
    "stale_invite" -> t("activity.noticeStaleInvite", (n.count ?: 0).toString())
    "malformed_requests" -> t("activity.noticeMalformed", (n.count ?: 0).toString())
    "grant_expiring" -> t("activity.noticeGrantExpiring", (n.count ?: 0).toString())
    "grant_expired" -> t("activity.noticeGrantExpired", (n.count ?: 0).toString())
    else -> n.kind
}
