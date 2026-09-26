package xyz.actitud.baluard.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlinx.serialization.json.jsonObject
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.MobileJoinRequest
import xyz.actitud.baluard.data.MobileMemberInfo
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.detail.formatEpochDate
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.Clock
import xyz.actitud.baluard.platform.copyToClipboard
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.toast.Toast

/**
 * People & access (§4.8-7): the mobile admin surface. Invite members,
 * approve or deny join introductions, work the access-request inbox,
 * and manage collection grants. Thin over the same repository wrappers
 * the desktop daemon routes through — the daemon layer stays the only
 * validator, so every payload here must match its contract exactly.
 */
@Composable
fun PeopleScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var members by remember { mutableStateOf<List<MobileMemberInfo>>(emptyList()) }
    var joinRequests by remember { mutableStateOf(emptyList<MobileJoinRequest>()) }
    var accessAsks by remember { mutableStateOf(emptyList<xyz.actitud.baluard.data.MobileAccessAsk>()) }
    var collections by remember { mutableStateOf(emptyList<xyz.actitud.baluard.data.MobileCollectionFull>()) }
    var loadError by remember { mutableStateOf<String?>(null) }

    // Invite form
    var inviteRole by remember { mutableStateOf("editor") }
    var transportUsername by remember { mutableStateOf("") }
    var inviteBusy by remember { mutableStateOf(false) }
    var inviteCode by remember { mutableStateOf<String?>(null) }

    // Grant form (one open collection at a time)
    var grantCollectionId by remember { mutableStateOf<String?>(null) }
    var grantMemberId by remember { mutableStateOf<String?>(null) }
    var grantMemberMenu by remember { mutableStateOf(false) }
    var grantAccess by remember { mutableStateOf("read") }
    var grantExpiryDays by remember { mutableStateOf("") }
    var grantBusy by remember { mutableStateOf(false) }

    suspend fun refreshAll() {
        runCatching {
            members = repo.listMembers(vault)
            joinRequests = repo.listJoinRequests(vault)
            accessAsks = repo.listAccessAsks(vault)
            collections = repo.listCollectionsFull(vault)
        }.onFailure { loadError = it.message }
    }

    LaunchedEffect(vault) { refreshAll() }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = { BaluardTopBar(title = t("people.title"), onBack = onBack) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (loadError != null) {
                item {
                    Text(
                        loadError ?: "",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            // ── Join queue ── introductions waiting for approval.
            if (joinRequests.isNotEmpty()) {
                item {
                    SectionCard(
                        title = t("people.joinRequests"),
                        contentPadding = PaddingValues(vertical = 4.dp),
                    ) {
                        joinRequests.forEach { req ->
                            Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                                Text(req.displayName, style = MaterialTheme.typography.bodyLarge)
                                if (!req.secretOk) {
                                    Text(
                                        t("people.secretMismatch"),
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    modifier = Modifier.padding(top = 6.dp),
                                ) {
                                    Button(onClick = {
                                        scope.launch {
                                            runCatching {
                                                repo.joinRequestsApprove(vault, req.reqId)
                                            }.onSuccess {
                                                Toast.success(t("people.joinApproved"))
                                                refreshAll()
                                            }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                        }
                                    }) { Text(t("people.approve")) }
                                    OutlinedButton(onClick = {
                                        scope.launch {
                                            runCatching {
                                                repo.joinRequestsDeny(vault, req.reqId)
                                            }.onSuccess {
                                                Toast.success(t("people.joinDenied"))
                                                refreshAll()
                                            }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                        }
                                    }) { Text(t("people.deny")) }
                                }
                            }
                        }
                    }
                }
            }

            // ── Access-request inbox ── members asking for collections.
            if (accessAsks.isNotEmpty()) {
                item {
                    SectionCard(
                        title = t("people.accessAsks"),
                        contentPadding = PaddingValues(vertical = 4.dp),
                    ) {
                        accessAsks.forEach { ask ->
                            Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                                Text(
                                    t("people.askRow", ask.requesterName, ask.collectionName),
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                                Text(
                                    when (ask.access) {
                                        "write" -> t("people.askWrite")
                                        "manage" -> t("people.askManage")
                                        else -> t("people.askRead")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                                if (ask.note.isNotBlank()) {
                                    Text(
                                        "\"${ask.note}\"",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    modifier = Modifier.padding(top = 6.dp),
                                ) {
                                    Button(onClick = {
                                        scope.launch {
                                            runCatching {
                                                repo.collectionRequestApprove(vault, ask.requestId, ask.requesterMemberId, "read")
                                            }.onSuccess {
                                                Toast.success(t("people.askApproved", ask.requesterName))
                                                refreshAll()
                                            }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                        }
                                    }) { Text(t("people.grantRead")) }
                                    OutlinedButton(onClick = {
                                        scope.launch {
                                            runCatching {
                                                repo.collectionRequestApprove(vault, ask.requestId, ask.requesterMemberId, "write")
                                            }.onSuccess {
                                                Toast.success(t("people.askApproved", ask.requesterName))
                                                refreshAll()
                                            }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                        }
                                    }) { Text(t("people.grantWrite")) }
                                    OutlinedButton(onClick = {
                                        scope.launch {
                                            runCatching {
                                                repo.collectionRequestDeny(vault, ask.requestId, ask.requesterMemberId)
                                            }.onSuccess {
                                                Toast.success(t("people.askDenied"))
                                                refreshAll()
                                            }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                        }
                                    }) { Text(t("people.deny")) }
                                }
                            }
                        }
                    }
                }
            }

            // ── Members ── live rows plus greyed tombstones.
            item {
                SectionCard(
                    title = t("people.members"),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    val live = members.filter { !it.removed && !it.reset }
                    val gone = members.filter { it.removed || it.reset }
                    live.forEach { m ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    m.name + if (m.isSelf) " (${t("people.you")})" else "",
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                                Text(
                                    when (m.role) {
                                        "owner" -> t("people.roleOwner")
                                        "admin" -> t("people.roleAdmin")
                                        "viewer" -> t("people.roleViewer")
                                        else -> t("people.roleEditor")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    gone.forEach { m ->
                        Text(
                            m.name + " (" + t(if (m.removed) "people.removed" else "people.reset") + ")",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                        )
                    }
                }
            }

            // ── Invites ── mint a one-time code.
            item {
                SectionCard(
                    title = t("people.inviteTitle"),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("viewer", "editor", "admin").forEach { role ->
                                FilterChip(
                                    selected = inviteRole == role,
                                    onClick = { inviteRole = role },
                                    label = {
                                        Text(
                                            when (role) {
                                                "viewer" -> t("people.roleViewer")
                                                "admin" -> t("people.roleAdmin")
                                                else -> t("people.roleEditor")
                                            },
                                        )
                                    },
                                )
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        BaluardTextField(
                            value = transportUsername,
                            onValueChange = { transportUsername = it },
                            label = t("people.transportUsername"),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(
                            enabled = !inviteBusy,
                            onClick = {
                                scope.launch {
                                    inviteBusy = true
                                    runCatching {
                                        val user = transportUsername.trim()
                                        val payload = if (user.isEmpty()) {
                                            "{\"role\":\"$inviteRole\"}"
                                        } else {
                                            // Backslash first, then the quote —
                                            // the review caught the quote-only
                                            // escape letting a pasted
                                            // backslash terminate the string
                                            // early and inject keys.
                                            val safe = user.replace("\\", "\\\\").replace("\"", "\\\"")
                                            "{\"role\":\"$inviteRole\",\"transport_username\":\"$safe\"}"
                                        }
                                        repo.memberInvite(vault, payload)
                                    }.onSuccess { raw ->
                                        inviteCode = extractInviteCode(raw)
                                        if (inviteCode == null) Toast.error(t("error.generic"))
                                    }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                    inviteBusy = false
                                }
                            },
                        ) { Text(t("people.inviteAction")) }
                    }
                }
            }

            // ── Collection grants ── per-collection editor.
            item {
                SectionCard(
                    title = t("people.grantsTitle"),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                        collections.forEach { col ->
                            val grants = col.grants
                            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                                Text(col.info.name, style = MaterialTheme.typography.bodyLarge)
                                grants.forEach { g ->
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        Text(
                                            memberName(members, g.memberId) + " · " +
                                                when (g.access) {
                                                    "write" -> t("people.accessWrite")
                                                    "manage" -> t("people.accessManage")
                                                    else -> t("people.accessRead")
                                                } + expirySuffix(g.expiresAt),
                                            style = MaterialTheme.typography.bodySmall,
                                            modifier = Modifier.weight(1f),
                                        )
                                        TextButton(onClick = {
                                            scope.launch {
                                                runCatching {
                                                    repo.collectionRevoke(vault, "{\"id\":\"${col.info.id}\",\"member_id\":\"${g.memberId}\"}")
                                                }.onSuccess {
                                                    Toast.success(t("people.revoked"))
                                                    refreshAll()
                                                }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                            }
                                        }) { Text(t("people.revoke")) }
                                    }
                                }
                                if (grantCollectionId == col.info.id) {
                                    // Inline add-grant form for this collection.
                                    Spacer(Modifier.height(6.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        OutlinedButton(onClick = { grantMemberMenu = true }) {
                                            Text(
                                                grantMemberId?.let { memberName(members, it) }
                                                    ?: t("people.pickMember"),
                                            )
                                        }
                                        DropdownMenu(expanded = grantMemberMenu, onDismissRequest = { grantMemberMenu = false }) {
                                            members.filter { !it.removed && !it.reset }.forEach { m ->
                                                DropdownMenuItem(
                                                    text = { Text(m.name) },
                                                    onClick = {
                                                        grantMemberId = m.id
                                                        grantMemberMenu = false
                                                    },
                                                )
                                            }
                                        }
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                                        listOf("read", "write", "manage").forEach { access ->
                                            FilterChip(
                                                selected = grantAccess == access,
                                                onClick = { grantAccess = access },
                                                label = {
                                                    Text(
                                                        when (access) {
                                                            "write" -> t("people.accessWrite")
                                                            "manage" -> t("people.accessManage")
                                                            else -> t("people.accessRead")
                                                        },
                                                    )
                                                },
                                            )
                                        }
                                    }
                                    BaluardTextField(
                                        value = grantExpiryDays,
                                        onValueChange = { grantExpiryDays = it.filter(Char::isDigit).take(4) },
                                        label = t("people.expiryDays"),
                                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                                        Button(
                                            enabled = !grantBusy && grantMemberId != null,
                                            onClick = {
                                                scope.launch {
                                                    grantBusy = true
                                                    runCatching {
                                                        val cid = grantCollectionId ?: return@launch
                                                        val mid = grantMemberId ?: return@launch
                                                        val days = grantExpiryDays.toIntOrNull()
                                                        val expires = if (days != null && days > 0) {
                                                            ",\"expires_at\":${Clock.currentTimeMillis() / 1000 + days * 86400}"
                                                        } else ""
                                                        repo.collectionGrant(
                                                            vault,
                                                            "{\"id\":\"$cid\",\"member_id\":\"$mid\",\"access\":\"$grantAccess\"$expires}",
                                                        )
                                                    }.onSuccess {
                                                        Toast.success(t("people.granted"))
                                                        grantCollectionId = null
                                                        grantMemberId = null
                                                        grantExpiryDays = ""
                                                        refreshAll()
                                                    }.onFailure { Toast.error(it.message ?: t("error.generic")) }
                                                    grantBusy = false
                                                }
                                            },
                                        ) { Text(t("people.grantAction")) }
                                        OutlinedButton(onClick = { grantCollectionId = null }) {
                                            Text(t("common.cancel"))
                                        }
                                    }
                                } else {
                                    TextButton(onClick = {
                                        grantCollectionId = col.info.id
                                        grantMemberId = null
                                        grantAccess = "read"
                                        grantExpiryDays = ""
                                    }) { Text(t("people.addGrant")) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Invite-code dialog: show once, copy, done.
    inviteCode?.let { code ->
        AlertDialog(
            onDismissRequest = { inviteCode = null },
            title = { Text(t("people.inviteCodeTitle")) },
            text = {
                Column {
                    Text(t("people.inviteCodeBody"), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        code,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    copyToClipboard(code)
                    Toast.success(t("people.codeCopied"))
                    inviteCode = null
                }) { Text(t("people.copyCode")) }
            },
            dismissButton = {
                TextButton(onClick = { inviteCode = null }) { Text(t("common.close")) }
            },
        )
    }
}

/** Pull `{code}` out of the invite response. */
private fun extractInviteCode(raw: String): String? = runCatching {
    (kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject["code"]
        as? kotlinx.serialization.json.JsonPrimitive)?.content
}.getOrNull()

private fun memberName(members: List<MobileMemberInfo>, id: String): String =
    members.firstOrNull { it.id == id }?.name ?: id.take(8)

private fun expirySuffix(expiresAt: Long?): String =
    if (expiresAt != null && expiresAt > 0L) " · ${formatEpochDate(expiresAt)}" else ""
