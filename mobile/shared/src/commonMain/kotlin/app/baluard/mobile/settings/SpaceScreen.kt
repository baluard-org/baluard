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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.MobilePendingOp
import app.baluard.mobile.data.MobileSpaceSettings
import app.baluard.mobile.data.MobileSpaceStatus
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.ui.components.BaluardDivider
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.theme.BaluardTheme
import app.baluard.mobile.ui.toast.Toast

/**
 * Shared vault rules, team mode, recovery kit, and admin approvals.
 */
@Composable
fun SpaceScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
    onSyncNudge: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var spaceSettings by remember(vault) { mutableStateOf<MobileSpaceSettings?>(null) }
    var spaceBusy by remember(vault) { mutableStateOf(false) }
    var pendingOps by remember(vault) { mutableStateOf(listOf<MobilePendingOp>()) }
    var spacePolicies by remember(vault) { mutableStateOf(mapOf<String, String>()) }
    var spaceTeam by remember(vault) { mutableStateOf<MobileSpaceStatus?>(null) }
    var teamBusy by remember(vault) { mutableStateOf(false) }
    var showFlipConfirm by remember(vault) { mutableStateOf(false) }
    var flipWord by remember(vault) { mutableStateOf("") }
    var kitEnabled by remember(vault) { mutableStateOf<Boolean?>(null) }
    var kitBusy by remember(vault) { mutableStateOf(false) }
    var kitConfirm by remember(vault) { mutableStateOf<String?>(null) }
    var kitWords by remember(vault) { mutableStateOf<List<String>?>(null) }

    LaunchedEffect(vault) {
        spaceSettings = repo.spaceSettingsGet(vault)
        pendingOps = repo.approvalsPending(vault)
        spacePolicies = repo.policiesList(vault)
        spaceTeam = repo.spaceStatus(vault)
        runCatching {
            val json = repo.spaceKitStatus(vault)
            kitEnabled = (Json.parseToJsonElement(json) as? JsonObject)
                ?.get("enabled")?.jsonPrimitive?.content == "true"
        }
    }

    fun runPrepare() {
        if (teamBusy) return
        teamBusy = true
        scope.launch {
            try {
                val r = repo.spacePrepare(vault)
                spaceTeam = repo.spaceStatus(vault)
                when {
                    r == null -> Toast.error(t("error.generic"))
                    r.missing > 0 -> Toast.error(t("space.teamMissing", r.missing.toString()))
                    else -> Toast.success(t("space.teamPrepared"))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                Toast.error(t("error.generic"))
            } finally {
                teamBusy = false
            }
        }
    }

    fun runFlip() {
        if (teamBusy || flipWord.trim() != "team") return
        teamBusy = true
        scope.launch {
            try {
                repo.spaceFlip(vault)
                spaceTeam = repo.spaceStatus(vault)
                Toast.success(t("space.teamDone"))
                showFlipConfirm = false
                onSyncNudge()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val raw = e.message ?: ""
                val detail = if (raw.startsWith("detail=")) raw.removePrefix("detail=") else raw
                Toast.error(detail.ifBlank { t("error.generic") })
            } finally {
                teamBusy = false
            }
        }
    }

    fun setSpace(
        inviteAuthority: String? = null,
        allowViewerExport: Boolean? = null,
        guestEnabled: Boolean? = null,
        trashPolicy: String? = null,
        joinApproval: String? = null,
        quorumAdminOps: ULong? = null,
        collectionCreateAuthority: String? = null,
    ) {
        if (spaceBusy) return
        if (inviteAuthority != null && spaceSettings?.inviteAuthority == inviteAuthority) return
        if (trashPolicy != null && spaceSettings?.trashPolicy == trashPolicy) return
        if (joinApproval != null && spaceSettings?.joinApproval == joinApproval) return
        if (quorumAdminOps != null && spaceSettings?.quorumAdminOps == quorumAdminOps.toInt()) return
        if (collectionCreateAuthority != null && spaceSettings?.collectionCreateAuthority == collectionCreateAuthority) return
        spaceBusy = true
        scope.launch {
            try {
                repo.spaceSettingsSet(
                    vault,
                    inviteAuthority,
                    allowViewerExport,
                    guestEnabled,
                    trashPolicy,
                    joinApproval,
                    quorumAdminOps,
                    collectionCreateAuthority,
                )
                spaceSettings = repo.spaceSettingsGet(vault)
                pendingOps = repo.approvalsPending(vault)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                Toast.error(t("error.generic"))
            } finally {
                spaceBusy = false
            }
        }
    }

    Scaffold(
        topBar = { BaluardTopBar(title = t("space.title"), onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SectionCard(title = t("space.title")) {
                Text(t("space.teamLabel"), style = MaterialTheme.typography.bodyMedium)
                if (spaceTeam?.flipped == true) {
                    Text(
                        text = t("space.teamOn"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Text(
                        text = t("space.teamOff"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val missing = spaceTeam?.missingWrapPubkey ?: 0
                    if (missing > 0) {
                        Text(
                            text = t("space.teamMissing", missing.toString()),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !teamBusy && spaceTeam != null,
                            onClick = { runPrepare() },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(t("space.teamPrepare"))
                        }
                        OutlinedButton(
                            enabled = !teamBusy && spaceTeam?.prepared == true && missing == 0,
                            onClick = {
                                flipWord = ""
                                showFlipConfirm = true
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(t("space.teamUpgrade"))
                        }
                    }
                }
                if (showFlipConfirm) {
                    AlertDialog(
                        onDismissRequest = { if (!teamBusy) showFlipConfirm = false },
                        title = { Text(t("space.teamConfirmTitle")) },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(t("space.teamConfirmBody"))
                                BaluardTextField(
                                    value = flipWord,
                                    onValueChange = { flipWord = it },
                                    label = t("space.teamConfirmWord"),
                                )
                            }
                        },
                        confirmButton = {
                            TextButton(
                                enabled = !teamBusy && flipWord.trim() == "team",
                                onClick = { runFlip() },
                            ) { Text(t("space.teamUpgrade")) }
                        },
                        dismissButton = {
                            TextButton(enabled = !teamBusy, onClick = { showFlipConfirm = false }) {
                                Text(t("common.cancel"))
                            }
                        },
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(text = t("space.inviteAuthorityLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.inviteAuthorityDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(inviteAuthority = "admins") },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(t("space.authorityAdmins")) }
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(inviteAuthority = "owners") },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(t("space.authorityOwners")) }
                }
                if (spaceSettings != null) {
                    Text(
                        text = t(
                            if (spaceSettings!!.inviteAuthority == "owners") "space.authorityOwners"
                            else "space.authorityAdmins",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(t("space.viewerExportLabel"), style = MaterialTheme.typography.bodyMedium)
                        Text(
                            text = t("space.viewerExportDesc"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        enabled = !spaceBusy && spaceSettings != null,
                        checked = spaceSettings?.allowViewerExport == true,
                        onCheckedChange = { setSpace(allowViewerExport = it) },
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(t("space.guestLabel"), style = MaterialTheme.typography.bodyMedium)
                        Text(
                            text = t("space.guestDesc"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        enabled = !spaceBusy && spaceSettings != null,
                        checked = spaceSettings?.guestEnabled == true,
                        onCheckedChange = { setSpace(guestEnabled = it) },
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(t("space.kitLabel"), style = MaterialTheme.typography.bodyMedium)
                        Text(
                            text = t("space.kitDesc"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    val kitRunEnable: () -> Unit = kitRunEnable@{
                        kitBusy = true
                        scope.launch {
                            try {
                                val json = repo.spaceKitEnable(vault)
                                val words = (Json.parseToJsonElement(json) as? JsonObject)
                                    ?.get("phrase")?.jsonPrimitive?.content
                                    ?.trim()?.split(Regex("\\s+")).orEmpty()
                                kitWords = if (words.size == 24) words else null
                                kitEnabled = true
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Toast.error(e.message ?: t("space.kitFailed"))
                            }
                            kitBusy = false
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(
                            enabled = !kitBusy && kitEnabled != null,
                            onClick = { kitRunEnable() },
                        ) {
                            Text(
                                when (kitEnabled) {
                                    true -> t("space.kitReplace")
                                    false -> t("space.kitEnable")
                                    null -> t("common.loading")
                                },
                            )
                        }
                        if (kitEnabled == true) {
                            TextButton(
                                enabled = !kitBusy,
                                onClick = { kitConfirm = "disable" },
                            ) { Text(t("space.kitDisable"), color = MaterialTheme.colorScheme.error) }
                        }
                    }
                }
                if (kitEnabled == false) {
                    Text(
                        t("space.kitOffHint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                if (kitConfirm == "disable") {
                    AlertDialog(
                        onDismissRequest = { if (!kitBusy) kitConfirm = null },
                        title = { Text(t("space.kitDisableTitle")) },
                        text = { Text(t("space.kitDisableBody")) },
                        confirmButton = {
                            TextButton(enabled = !kitBusy, onClick = {
                                kitBusy = true
                                scope.launch {
                                    try {
                                        repo.spaceKitDisable(vault)
                                        kitEnabled = false
                                        Toast.success(t("space.kitDisabled"))
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Toast.error(e.message ?: t("space.kitFailed"))
                                    }
                                    kitBusy = false
                                    kitConfirm = null
                                }
                            }) { Text(t("space.kitDisable"), color = MaterialTheme.colorScheme.error) }
                        },
                        dismissButton = {
                            TextButton(onClick = { kitConfirm = null }) { Text(t("common.cancel")) }
                        },
                    )
                }

                kitWords?.let { words ->
                    AlertDialog(
                        onDismissRequest = {},
                        title = { Text(t("space.kitPhraseTitle")) },
                        text = {
                            Column {
                                Text(
                                    t("space.kitPhraseBody"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    words.chunked(2).forEachIndexed { rowIdx, pair ->
                                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                            pair.forEachIndexed { colIdx, w ->
                                                Text(
                                                    text = "${rowIdx * 2 + colIdx + 1}. $w",
                                                    style = MaterialTheme.typography.bodyMedium,
                                                    fontFamily = FontFamily.Monospace,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                copyToClipboard(words.joinToString(" "))
                                Toast.success(t("common.copied"))
                            }) { Text(t("recovery.copyPhrase")) }
                        },
                        dismissButton = {
                            TextButton(onClick = { kitWords = null }) { Text(t("common.done")) }
                        },
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(t("space.trashPolicyLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.trashPolicyDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(trashPolicy = "write_scope_can_trash") },
                    ) { Text(t("space.trashWriteScope")) }
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(trashPolicy = "admins_only") },
                    ) { Text(t("space.trashAdminsOnly")) }
                }
                if (spaceSettings != null) {
                    Text(
                        text = t(
                            if (spaceSettings!!.trashPolicy == "admins_only") "space.trashAdminsOnly"
                            else "space.trashWriteScope",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(t("space.joinApprovalLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.joinApprovalDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(joinApproval = "manual") },
                    ) { Text(t("space.joinManual")) }
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(joinApproval = "code") },
                    ) { Text(t("space.joinCode")) }
                }
                if (spaceSettings != null) {
                    Text(
                        text = t(
                            if (spaceSettings!!.joinApproval == "code") "space.joinCode"
                            else "space.joinManual",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(t("space.quorumLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.quorumDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(1UL, 2UL, 3UL).forEach { n ->
                        OutlinedButton(
                            enabled = !spaceBusy,
                            onClick = { setSpace(quorumAdminOps = n) },
                        ) { Text(n.toString()) }
                    }
                }
                if (spaceSettings != null) {
                    Text(
                        text = t("space.quorumCurrent", spaceSettings!!.quorumAdminOps),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(t("space.createAuthLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.createAuthDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(collectionCreateAuthority = "admins") },
                    ) { Text(t("space.createAdmins")) }
                    OutlinedButton(
                        enabled = !spaceBusy,
                        onClick = { setSpace(collectionCreateAuthority = "editors") },
                    ) { Text(t("space.createEditors")) }
                }
                if (spaceSettings != null) {
                    Text(
                        text = t(
                            if (spaceSettings!!.collectionCreateAuthority == "editors") "space.createEditors"
                            else "space.createAdmins",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                val policyDiffs = spacePolicies.entries.mapNotNull { (key, rec) ->
                    val label = when (key) {
                        "space_invite_authority" -> t("space.inviteAuthorityLabel")
                        "allow_viewer_export" -> t("space.viewerExportLabel")
                        "guest_enabled" -> t("space.guestLabel")
                        "trash_policy" -> t("space.trashPolicyLabel")
                        "join_approval" -> t("space.joinApprovalLabel")
                        "quorum_admin_ops" -> t("space.quorumLabel")
                        "collection_create_authority" -> t("space.createAuthLabel")
                        else -> return@mapNotNull null
                    }
                    val current = when (key) {
                        "space_invite_authority" -> spaceSettings?.inviteAuthority
                        "allow_viewer_export" -> spaceSettings?.allowViewerExport?.toString()
                        "guest_enabled" -> spaceSettings?.guestEnabled?.toString()
                        "trash_policy" -> spaceSettings?.trashPolicy
                        "join_approval" -> spaceSettings?.joinApproval
                        "quorum_admin_ops" -> spaceSettings?.quorumAdminOps?.toString()
                        "collection_create_authority" -> spaceSettings?.collectionCreateAuthority
                        else -> null
                    }
                    val recLabel = when (rec) {
                        "admins" -> t("space.authorityAdmins")
                        "owners" -> t("space.authorityOwners")
                        "editors" -> t("space.createEditors")
                        "write_scope_can_trash" -> t("space.trashWriteScope")
                        "admins_only" -> t("space.trashAdminsOnly")
                        "manual" -> t("space.joinManual")
                        "code" -> t("space.joinCode")
                        "true" -> t("settings.enabled")
                        "false" -> t("settings.disabled")
                        else -> rec
                    }
                    if (current != null && current != rec) label to recLabel else null
                }
                if (policyDiffs.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(t("space.policyTitle"), style = MaterialTheme.typography.bodyMedium)
                    policyDiffs.forEach { (label, rec) ->
                        Text(
                            text = t("space.policyHint", "$label: $rec"),
                            style = MaterialTheme.typography.bodySmall,
                            color = BaluardTheme.colors.textPrimary,
                        )
                    }
                }

                if (pendingOps.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(t("space.pendingTitle"), style = MaterialTheme.typography.bodyMedium)
                    pendingOps.forEach { op ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(t(s4OpLabel(op.kind)), style = MaterialTheme.typography.bodySmall)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = t("space.pendingItem", op.approvals, op.required),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                op.claimantId?.let { claimantId ->
                                    if (op.kind == "ownership_claim") {
                                        TextButton(onClick = {
                                            scope.launch {
                                                try {
                                                    repo.memberClaim(vault, claimantId)
                                                    pendingOps = repo.approvalsPending(vault)
                                                } catch (e: Exception) {
                                                    Toast.error(e.message ?: t("error.generic"))
                                                }
                                            }
                                        }) { Text(t("people.approve")) }
                                    }
                                }
                                if (op.kind == "kit.replace" || op.kind == "kit.disable") {
                                    TextButton(onClick = {
                                        scope.launch {
                                            try {
                                                if (op.kind == "kit.replace") {
                                                    val json = repo.spaceKitEnable(vault)
                                                    val words = (Json.parseToJsonElement(json) as? JsonObject)
                                                        ?.get("phrase")?.jsonPrimitive?.content
                                                        ?.trim()?.split(Regex("\\s+")).orEmpty()
                                                    kitWords = if (words.size == 24) words else null
                                                    kitEnabled = true
                                                } else {
                                                    repo.spaceKitDisable(vault)
                                                    kitEnabled = false
                                                }
                                                pendingOps = repo.approvalsPending(vault)
                                                Toast.success(t("space.kitConfirmed"))
                                            } catch (e: CancellationException) {
                                                throw e
                                            } catch (e: Exception) {
                                                Toast.error(e.message ?: t("space.kitFailed"))
                                            }
                                        }
                                    }) { Text(t("people.approve")) }
                                }
                                op.transferTarget?.let { target ->
                                    if (op.kind == "transfer_ownership") {
                                        TextButton(onClick = {
                                            scope.launch {
                                                try {
                                                    repo.memberTransfer(vault, target)
                                                    pendingOps = repo.approvalsPending(vault)
                                                } catch (e: Exception) {
                                                    Toast.error(e.message ?: t("error.generic"))
                                                }
                                            }
                                        }) { Text(t("people.approve")) }
                                    }
                                }
                            }
                        }
                    }
                }

                BaluardDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(t("space.restorePolicyLabel"), style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = t("space.restorePolicyDesc"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = t("space.restoreAdminsOnly"),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
