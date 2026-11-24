package app.baluard.mobile.settings

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.baluard.mobile.i18n.t
import app.baluard.mobile.detail.formatEpochDate
import app.baluard.mobile.detail.str
import app.baluard.mobile.platform.Clock
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.MobileVault
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/**
 * Full-screen vault diagnostics (desktop sync tab parity): per-device
 * sync state plus the copy-to-clipboard support report. Lives under
 * About > Advanced; the report is redacted by construction in the
 * runtime (host-only remote, sanitized commit subjects, no entry
 * names), so pasting it into an issue is safe.
 */
@Composable
fun VaultDiagnosticsScreen(
    vault: MobileVault,
    repo: VaultRepository,
    clientEnv: () -> String,
    onBack: () -> Unit,
) {
    var snap by remember(vault) { mutableStateOf<JsonObject?>(null) }
    var failed by remember(vault) { mutableStateOf<String?>(null) }
    var refreshKey by remember(vault) { mutableStateOf(0) }
    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    val copied = remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(vault, refreshKey) {
        repo.vaultDiagnostics(vault).fold(
            onSuccess = { raw ->
                val parsed = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
                if (parsed == null) {
                    failed = t("diag.error")
                    snap = null
                } else {
                    failed = null
                    snap = parsed
                }
            },
            onFailure = { failed = t("diag.error") },
        )
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                title = t("diag.title"),
                onBack = onBack,
                actions = {
                    IconButton(onClick = { refreshKey++ }) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = t("diag.refresh"),
                            tint = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            failed?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            } ?: run {
                val s = snap
                if (s == null) {
                    Text(
                        text = t("diag.loading"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    val verdict = s.str("verdict")
                    Text(
                        text = verdictText(verdict),
                        style = MaterialTheme.typography.titleMedium,
                        color = verdictColor(verdict),
                    )
                    Spacer(Modifier.height(4.dp))
                    val auto = s.get("autosync") as? JsonObject
                    @Composable
                    fun row(label: String, value: String) {
                        Row(verticalAlignment = Alignment.Top) {
                            Text(
                                label,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                value,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(start = 24.dp),
                                textAlign = TextAlign.End,
                            )
                        }
                    }
                    row(t("diag.deviceId"), (s.str("deviceId") ?: "").take(7))
                    row(t("diag.head"), s.str("headOid")?.take(7) ?: t("diag.never"))
                    if (s.str("hasRemote") == "true") {
                        val neverFetched = s.str("upstreamOid") == null
                        val behind = s.str("behind")?.toIntOrNull() ?: 0
                        val ahead = s.str("ahead")?.toIntOrNull() ?: 0
                        row(
                            t("diag.remoteState"),
                            when {
                                neverFetched -> t("diag.never")
                                behind > 0 && ahead > 0 ->
                                    t("diag.behindCount", behind) + " / " + t("diag.aheadCount", ahead)
                                behind > 0 -> t("diag.behindCount", behind)
                                ahead > 0 -> t("diag.aheadCount", ahead)
                                else -> t("diag.inSync")
                            },
                        )
                        s.str("upstreamAt")?.toLongOrNull()?.let {
                            row(t("diag.upstream"), ago(it))
                        }
                    } else {
                        row(t("diag.remote"), t("diag.noneConfigured"))
                    }
                    val lastSync = auto?.get("last_sync")?.jsonPrimitive?.content?.toLongOrNull()
                    row(
                        t("diag.lastSync"),
                        if (lastSync == null) t("diag.never")
                        else ago(lastSync) + " (" + formatEpochDate(lastSync) + ")",
                    )
                    row(
                        t("diag.autosync"),
                        if (auto?.get("active")?.jsonPrimitive?.content == "true") t("diag.on") else t("diag.off"),
                    )
                    (auto?.get("access_denied_streak")?.jsonPrimitive?.content?.toIntOrNull() ?: 0).takeIf { it > 0 }?.let {
                        row(t("diag.rejections"), it.toString())
                    }
                    (auto?.get("conflicts_resolved")?.jsonPrimitive?.content?.toIntOrNull() ?: 0).takeIf { it > 0 }?.let {
                        row(t("diag.conflicts"), it.toString())
                    }
                    val dirty = (s.str("staged")?.toIntOrNull() ?: 0) + (s.str("unstaged")?.toIntOrNull() ?: 0)
                    if (dirty > 0) row(t("diag.localChanges"), dirty.toString())
                    (s.get("dirtyPaths") as? JsonArray)
                        ?.takeIf { it.isNotEmpty() }
                        ?.let { paths ->
                            row(
                                t("diag.dirtyPaths"),
                                paths.mapNotNull { p -> (p as? JsonPrimitive)?.content }
                                    .joinToString(", "),
                            )
                        }
                    (s.str("unpublishedAttachments")?.toIntOrNull() ?: 0).takeIf { it > 0 }?.let {
                        row(t("diag.unpublishedAttachments"), it.toString())
                    }
                    row(
                        t("diag.versions"),
                        t("diag.versionsValue", s.str("formatVersion") ?: "?", s.str("coreVersion") ?: "?"),
                    )
                    row(
                        t("diag.os"),
                        s.str("osVersion")?.let { osv -> (s.str("os") ?: "?") + " " + (s.str("arch") ?: "?") + " (" + osv + ")" }
                            ?: ((s.str("os") ?: "?") + " " + (s.str("arch") ?: "?")),
                    )
                    s.str("headCiphers")?.toLongOrNull()?.let { n ->
                        row(
                            t("diag.headTree"),
                            t("diag.headTreeValue", n, s.str("headTrash")?.toLongOrNull() ?: 0L),
                        )
                    }
                    s.str("lastError")?.let { le ->
                        val at = s.str("lastErrorAt")?.toLongOrNull()
                        row(t("diag.lastError"), if (at != null) le + " (" + ago(at) + ")" else le)
                    }
                    if (s.str("kitSignerFile") == "true") {
                        row(t("diag.kitSigner"), t("diag.kitSignerPresent"))
                    }
                    s.str("entries")?.toIntOrNull()?.let { n -> row(t("diag.entries"), n.toString()) }
                    (s.str("archived")?.toIntOrNull() ?: 0).takeIf { it > 0 }?.let { row(t("diag.archived"), it.toString()) }
                    (s.str("trashed")?.toIntOrNull() ?: 0).takeIf { it > 0 }?.let { row(t("diag.trashed"), it.toString()) }

                    Spacer(Modifier.height(12.dp))
                    BaluardOutlinedButton(
                        text = if (copied.value) t("diag.copied") else t("diag.copy"),
                        onClick = {
                            s.str("report")?.let { report ->
                                val env = clientEnv()
                                val full = if (env.isBlank()) report else env + report
                                clipboard.setText(AnnotatedString(full))
                                copied.value = true
                                scope.launch {
                                    delay(3000)
                                    copied.value = false
                                }
                            }
                        },
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = t("diag.privacyNote"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

private fun ago(secs: Long?): String {
    secs ?: return t("diag.never")
    val d = (Clock.currentTimeMillis() / 1000 - secs).coerceAtLeast(0)
    return when {
        d < 90 -> t("diag.agoSecs", d)
        d < 5400 -> t("diag.agoMins", d / 60)
        d < 129600 -> t("diag.agoHours", d / 3600)
        else -> t("diag.agoDays", d / 86_400)
    }
}

private fun verdictText(v: String?): String = t(
    when (v) {
        "up_to_date" -> "diag.verdict.upToDate"
        "behind" -> "diag.verdict.behind"
        "local_pending" -> "diag.verdict.localPending"
        "failing" -> "diag.verdict.failing"
        "unfetched" -> "diag.verdict.unfetched"
        "needs_decision" -> "diag.verdict.needsDecision"
        "no_remote" -> "diag.verdict.noRemote"
        else -> "diag.verdict.unknown"
    },
)

@Composable
private fun verdictColor(v: String?): Color = when (v) {
    "up_to_date" -> MaterialTheme.colorScheme.primary
    "behind", "local_pending", "needs_decision", "unfetched" -> MaterialTheme.colorScheme.tertiary
    "failing" -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}
