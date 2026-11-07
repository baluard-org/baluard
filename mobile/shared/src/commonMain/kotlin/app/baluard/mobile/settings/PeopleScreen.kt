package app.baluard.mobile.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
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
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.MobileJoinRequest
import app.baluard.mobile.data.MobileMemberInfo
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.detail.formatEpochDate
import app.baluard.mobile.i18n.t
import app.baluard.mobile.monetization.Entitlements
import app.baluard.mobile.platform.Clock
import app.baluard.mobile.platform.copyToClipboard
import app.baluard.mobile.platform.platformLogE
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.components.UpgradeSheet
import app.baluard.mobile.ui.toast.Toast

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
    onSyncNudge: () -> Unit = {},
) {
    // ADR 0102: member surfaces are paid on store builds. A single-user vault
    // stays fully usable — this screen just shows the upgrade path when locked.
    if (!Entitlements.current().sharingUnlocked) {
        Scaffold(
            topBar = { BaluardTopBar(title = t("people.title"), onBack = onBack) },
        ) { padding ->
            var showUpgrade by remember { mutableStateOf(false) }
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            ) {
                SectionCard(title = t("upgrade.title")) {
                    Text(
                        t("upgrade.body"),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    BaluardOutlinedButton(
                        text = t("upgrade.subscribe"),
                        onClick = { showUpgrade = true },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            UpgradeSheet(shown = showUpgrade, onDismiss = { showUpgrade = false })
        }
        return
    }
    val scope = rememberCoroutineScope()
    var members by remember { mutableStateOf<List<MobileMemberInfo>>(emptyList()) }
    var joinRequests by remember { mutableStateOf(emptyList<MobileJoinRequest>()) }
    var accessAsks by remember { mutableStateOf(emptyList<app.baluard.mobile.data.MobileAccessAsk>()) }
    var collections by remember { mutableStateOf(emptyList<app.baluard.mobile.data.MobileCollectionFull>()) }
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

    // §4.8-8 offboarding: one typed-confirm dialog at a time. The confirm
    // word is the member's name, mirroring the desktop TypedConfirmModal;
    // a failed provider seat strike keeps the dialog open with the
    // override switch UNCHECKED — explicit consent, never pre-ticked.
    var pendingKind by remember { mutableStateOf<String?>(null) }
    var pendingMember by remember { mutableStateOf<MobileMemberInfo?>(null) }
    var confirmWord by remember { mutableStateOf("") }
    var removeOverride by remember { mutableStateOf(false) }
    var lastRemoveError by remember { mutableStateOf<String?>(null) }
    var offboardBusy by remember { mutableStateOf(false) }
    var resetResult by remember { mutableStateOf<VaultRepository.MobileResetResult?>(null) }

    // G26 stolen-device replace: confirm dialog + one-time result dialog.
    var replaceTarget by remember { mutableStateOf<MobileMemberInfo?>(null) }
    var replaceBusy by remember { mutableStateOf(false) }
    var replaceErr by remember { mutableStateOf<String?>(null) }
    var replaceResult by remember { mutableStateOf<VaultRepository.MobileReplaceReport?>(null) }

    // Grant revoke (forces collection-key rotation): confirm first.
    var revokeAsk by remember { mutableStateOf<Pair<String, String>?>(null) } // (collectionId, memberId)
    var revokeBusy by remember { mutableStateOf(false) }

    // G13: user groups (admin-managed).
    var groups by remember { mutableStateOf<List<app.baluard.mobile.data.MobileGroupInfo>>(emptyList()) }
    var showGroupCreate by remember { mutableStateOf(false) }
    var groupName by remember { mutableStateOf("") }
    var groupEdit by remember { mutableStateOf<app.baluard.mobile.data.MobileGroupInfo?>(null) }
    var groupEditName by remember { mutableStateOf("") }
    var groupDeleteArm by remember { mutableStateOf(false) }
    var groupBusy by remember { mutableStateOf(false) }

    // Role change (admin surface): target row + chosen role + busy/error.
    var roleTarget by remember { mutableStateOf<MobileMemberInfo?>(null) }
    var rolePick by remember { mutableStateOf("editor") }
    var roleBusy by remember { mutableStateOf(false) }
    var roleErr by remember { mutableStateOf<String?>(null) }

    // Level 2 contact check: this device's code (both sides compare),
    // and the admin's per-member verify dialog with the member's code.
    var myCode by remember { mutableStateOf<String?>(null) }
    var verifyTarget by remember { mutableStateOf<MobileMemberInfo?>(null) }
    var verifyCode by remember { mutableStateOf<String?>(null) }
    var verifyBusy by remember { mutableStateOf(false) }
    var verifyErr by remember { mutableStateOf<String?>(null) }

    suspend fun refreshAll() {
        runCatching {
            members = repo.listMembers(vault)
            joinRequests = repo.listJoinRequests(vault)
            accessAsks = repo.listAccessAsks(vault)
            collections = repo.listCollectionsFull(vault)
            groups = repo.listGroups(vault)
            myCode = runCatching {
                val o = repo.myContactCard(vault)
                ((kotlinx.serialization.json.Json.parseToJsonElement(o)
                    as? kotlinx.serialization.json.JsonObject)
                    ?.get("verification_code") as? kotlinx.serialization.json.JsonPrimitive)?.content
            }.getOrNull()
        }.onFailure { loadError = it.message }
    }

    LaunchedEffect(vault) { refreshAll() }

    val myRole = members.firstOrNull { it.isSelf }?.role
    val canOffboard = myRole == "owner" || myRole == "admin"
    val canTransfer = myRole == "owner"

    fun openOffboard(kind: String, m: MobileMemberInfo) {
        pendingKind = kind
        pendingMember = m
        confirmWord = ""
        removeOverride = false
        lastRemoveError = null
    }

    fun closeOffboard() {
        pendingKind = null
        pendingMember = null
        confirmWord = ""
        removeOverride = false
        lastRemoveError = null
    }

    suspend fun runConfirmedOffboard() {
        val m = pendingMember ?: return
        val kind = pendingKind ?: return
        offboardBusy = true
        try {
            when (kind) {
                "remove" -> {
                    val raw = repo.memberRemove(vault, listOf(m.id), removeOverride)
                    val report = repo.parseRemoveReport(raw)
                    if (report == null) {
                        // Malformed payload: never dress it up as success.
                        Toast.error(t("error.generic"))
                    } else {
                        val unstruck = report.unstruckSeats
                        if (unstruck.isNotEmpty()) {
                            Toast.error(t("people.seatUnstruck") + " " + unstruck.joinToString(", "))
                        } else {
                            Toast.success(t("people.removedToast"))
                        }
                    }
                    closeOffboard()
                }
                "reset" -> {
                    val raw = repo.memberReset(vault, m.id)
                    val parsed = repo.parseResetResult(raw)
                    if (parsed == null || parsed.resetCode.isEmpty()) {
                        // The reset already happened core-side; a lost code
                        // would lock the successor out, so a bad payload
                        // must never read as success.
                        Toast.error(t("error.generic"))
                    } else {
                        resetResult = parsed
                        Toast.success(t("people.resetDone"))
                    }
                    closeOffboard()
                }
                "transfer" -> {
                    repo.memberTransfer(vault, m.id)
                    Toast.success(t("people.transferDone"))
                    closeOffboard()
                }
                "claim" -> {
                    val selfId = members.firstOrNull { it.isSelf }?.id
                    if (selfId == null) {
                        Toast.error(t("error.generic"))
                    } else {
                        repo.memberClaim(vault, selfId)
                        Toast.success(t("people.claimDone"))
                        closeOffboard()
                    }
                }
            }
            refreshAll()
        } catch (e: Exception) {
            // ifBlank: an FFI error carrying only the "detail=" prefix
            // would otherwise surface an empty message in the dialog.
            val msg = (e.message ?: t("error.generic")).ifBlank { t("error.generic") }
            // A failed seat strike is not a dead end: the dialog stays
            // open so the admin can read why and opt into the override.
            if (kind == "remove" && msg.contains("provider seat removal failed")) {
                lastRemoveError = msg
                removeOverride = false
            } else {
                Toast.error(msg)
            }
        } finally {
            offboardBusy = false
        }
    }

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

            // ── Join queue ── the admin pastes the joiner's out-of-band
            // intro code here; staged requests wait below for approval.
            // Admin surface: staging is manage-gated daemon-side.
            if (canOffboard) item {
                var stageIntro by remember { mutableStateOf("") }
                var stageBusy by remember { mutableStateOf(false) }
                var stageMsg by remember { mutableStateOf<String?>(null) }
                SectionCard(
                    title = t("people.joinRequests"),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
                    ) {
                        BaluardTextField(
                            value = stageIntro,
                            onValueChange = { stageIntro = it; stageMsg = null },
                            label = t("people.stageIntro"),
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            enabled = !stageBusy,
                        )
                        Spacer(Modifier.width(8.dp))
                        TextButton(
                            onClick = {
                                stageBusy = true
                                stageMsg = null
                                scope.launch {
                                    try {
                                        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                                            repo.joinRequestsStage(vault, stageIntro.trim())
                                        }
                                        stageIntro = ""
                                        stageMsg = t("people.staged")
                                        refreshAll()
                                    } catch (e: kotlinx.coroutines.CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        val msg = e.message?.removePrefix("detail=") ?: ""
                                        stageMsg = msg.ifBlank { t("error.generic") }
                                    }
                                    stageBusy = false
                                }
                            },
                            enabled = !stageBusy && stageIntro.isNotBlank(),
                        ) {
                            Text(if (stageBusy) t("common.sending") else t("common.save"))
                        }
                    }
                    stageMsg?.let {
                        Text(
                            it,
                            color = if (it == t("people.staged")) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 14.dp),
                        )
                    }
                    joinRequests.forEach { req ->
                            Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                                Text(req.displayName, style = MaterialTheme.typography.bodyLarge)
                                req.email?.let {
                                    Text(
                                        it,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
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
                                                onSyncNudge()
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
                                                onSyncNudge()
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
                                                onSyncNudge()
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
                    myCode?.let { code ->
                        Text(
                            t("people.myCode") + " " + code,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                        )
                    }
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
                                m.email?.let {
                                    Text(
                                        it,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
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
                            // §4.8-8: never on the viewer's own row.
                            // Transfer sits on the TARGET row (owner makes
                            // someone else the owner); reset/remove for
                            // owner and admins.
                            if (!m.isSelf) {
                                Row {
                                    if (canTransfer && m.role != "owner") {
                                        TextButton(onClick = { openOffboard("transfer", m) }) {
                                            Text(t("people.actionTransfer"))
                                        }
                                    }
                                    // §13: an admin viewing the OWNER row sees
                                    // exactly one action, Take Over — contextual
                                    // labels so nobody faces both.
                                    if (myRole == "admin" && m.role == "owner") {
                                        TextButton(onClick = { openOffboard("claim", m) }) {
                                            Text(t("people.actionClaim"))
                                        }
                                    }
                                    // §13: an admin may RESET an owner row
                                    // (the successor inherits Owner), but
                                    // removal still requires the owner row
                                    // gone first.
                                    if (canOffboard &&
                                        m.role != "owner" &&
                                        m.identityPub.isNotEmpty()
                                    ) {
                                        TextButton(onClick = {
                                            verifyTarget = m
                                            verifyCode = null
                                            verifyErr = null
                                        }) {
                                            Text(t("people.actionVerify"))
                                        }
                                    }
                                    if (canOffboard && m.role != "owner") {
                                        TextButton(onClick = {
                                            roleTarget = m
                                            rolePick = m.role
                                            roleErr = null
                                        }) {
                                            Text(t("people.actionRole"))
                                        }
                                    }
                                    if (canOffboard) {
                                        TextButton(onClick = { openOffboard("reset", m) }) {
                                            Text(t("people.actionReset"))
                                        }
                                    }
                                    if (canOffboard) {
                                        TextButton(onClick = {
                                            replaceTarget = m
                                            replaceErr = null
                                        }) {
                                            Text(t("people.actionReplace"))
                                        }
                                    }
                                    if (canOffboard && m.role != "owner") {
                                        TextButton(onClick = { openOffboard("remove", m) }) {
                                            Text(
                                                t("people.actionRemove"),
                                                color = MaterialTheme.colorScheme.error,
                                            )
                                        }
                                    }
                                }
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

            // ── G13: Groups ── admin-managed member bundles.
            if (canOffboard) {
                item {
                    SectionCard(
                        title = t("people.groups"),
                        contentPadding = PaddingValues(vertical = 4.dp),
                    ) {
                        Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp)) {
                            if (groups.isEmpty()) {
                                Text(
                                    t("people.groupNone"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            groups.forEach { g ->
                                val names = g.memberIds.mapNotNull { mid ->
                                    members.firstOrNull { it.id == mid }?.name
                                }
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            groupEdit = g
                                            groupEditName = g.name
                                            groupDeleteArm = false
                                        }
                                        .padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(g.name, style = MaterialTheme.typography.bodyLarge)
                                        Text(
                                            if (names.isEmpty()) t("people.groupNone")
                                            else names.joinToString(", "),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = {
                                groupName = ""
                                showGroupCreate = true
                            }) { Text(t("people.groupNew")) }
                        }
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
                                        if (inviteCode == null) {
                                            Toast.error(t("error.generic"))
                                        } else if (app.baluard.mobile.platform.e2eBuild) {
                                            // harness reads the one-time code from logcat (JoinInvite.*invite=)
                                            platformLogE("JoinInvite", "invite=$inviteCode")
                                        }
                                        // The pending-invite file is a local
                                        // artifact; only the debounced push
                                        // carries it to the remote.
                                        onSyncNudge()
                                    }.onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
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
                                            revokeAsk = col.info.id to g.memberId
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
                                                    }.onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
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

    // Grant revoke: a simple confirm — the action rotates the collection
    // key, so a mis-tap must not be instant.
    revokeAsk?.let { (collectionId, memberId) ->
        AlertDialog(
            onDismissRequest = { if (!revokeBusy) revokeAsk = null },
            title = { Text(t("people.revokeConfirmTitle")) },
            text = { Text(t("people.revokeConfirmBody", memberName(members, memberId))) },
            confirmButton = {
                TextButton(enabled = !revokeBusy, onClick = {
                    scope.launch {
                        revokeBusy = true
                        runCatching {
                            repo.collectionRevoke(vault, "{\"id\":\"$collectionId\",\"member_id\":\"$memberId\"}")
                        }.onSuccess {
                            Toast.success(t("people.revoked"))
                            refreshAll()
                            onSyncNudge()
                        }.onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                        revokeBusy = false
                        revokeAsk = null
                    }
                }) { Text(t("people.revoke")) }
            },
            dismissButton = {
                TextButton(onClick = { revokeAsk = null }) { Text(t("common.cancel")) }
            },
        )
    }

    // §4.8-8: typed confirmation for destructive member actions. The
    // confirm button stays disabled until the typed word matches the
    // member's name exactly — a mis-tap cannot destroy access.
    val pm = pendingMember
    if (pendingKind != null && pm != null) {
        val body = when (pendingKind) {
            "remove" -> t("people.removeBody", pm.name)
            "reset" -> t("people.resetBody", pm.name)
            "claim" -> t("people.claimBody", pm.name)
            else -> t("people.transferBody", pm.name)
        }
        AlertDialog(
            onDismissRequest = { if (!offboardBusy) closeOffboard() },
            title = { Text(t("people." + pendingKind + "Title")) },
            text = {
                Column {
                    Text(body, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    BaluardTextField(
                        value = confirmWord,
                        onValueChange = { confirmWord = it },
                        label = t("people.confirmWordLabel"),
                        singleLine = true,
                    )
                    if (pendingKind == "remove" && lastRemoveError != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            lastRemoveError.orEmpty(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = removeOverride,
                                onCheckedChange = { removeOverride = it },
                            )
                            Text(t("people.overrideLabel"), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    // Desktop TypedConfirmModal parity: the word must be
                    // non-empty AND trim-match the member name, so an
                    // empty-name row or keyboard whitespace cannot
                    // pre-enable or lock out the confirm.
                    enabled = !offboardBusy &&
                        pm.name.isNotEmpty() &&
                        confirmWord.trim() == pm.name,
                    onClick = { scope.launch { runConfirmedOffboard() } },
                ) {
                    Text(
                        when (pendingKind) {
                            "remove" -> t("people.confirmRemove")
                            "reset" -> t("people.confirmReset")
                            "claim" -> t("people.confirmClaim")
                            else -> t("people.confirmTransfer")
                        },
                    )
                }
            },
            dismissButton = {
                TextButton(
                    enabled = !offboardBusy,
                    onClick = { closeOffboard() },
                ) { Text(t("common.close")) }
            },
        )
    }

    // One-time reset code: hand back to the member out of band.
    resetResult?.let { r ->
        AlertDialog(
            onDismissRequest = { resetResult = null },
            title = { Text(t("people.resetCodeTitle")) },
            text = {
                Column {
                    Text(t("people.resetCodeBody"), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        r.resetCode,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    copyToClipboard(r.resetCode)
                    Toast.success(t("people.codeCopied"))
                    resetResult = null
                }) { Text(t("people.copyCode")) }
            },
            dismissButton = {
                TextButton(onClick = { resetResult = null }) { Text(t("common.close")) }
            },
        )
    }

    // ── G26 stolen-device replace: confirm, then the one-time code. ──
    replaceTarget?.let { m ->
        AlertDialog(
            onDismissRequest = { if (!replaceBusy) replaceTarget = null },
            title = { Text(t("people.replaceTitle", m.name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(t("people.replaceBody"), style = MaterialTheme.typography.bodyMedium)
                    if (replaceErr != null) {
                        Text(
                            replaceErr!!.removePrefix("detail="),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !replaceBusy,
                    onClick = {
                        scope.launch {
                            replaceBusy = true
                            try {
                                val raw = repo.memberReplaceDevice(vault, m.id)
                                val report = repo.parseReplaceReport(raw)
                                if (report == null || report.inviteCode.isEmpty()) {
                                    // The reset already happened core-side; a
                                    // lost code would lock the successor out,
                                    // so a bad payload must never read as success.
                                    replaceErr = t("error.generic")
                                } else {
                                    replaceTarget = null
                                    replaceResult = report
                                    Toast.success(t("people.replaceDone"))
                                    refreshAll()
                                }
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                replaceErr = (e.message ?: t("error.generic"))
                                    .removePrefix("detail=")
                                    .ifBlank { t("error.generic") }
                            } finally {
                                replaceBusy = false
                            }
                        }
                    },
                ) { Text(t("people.replaceConfirm")) }
            },
            dismissButton = {
                TextButton(onClick = { if (!replaceBusy) replaceTarget = null }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }
    replaceResult?.let { r ->
        AlertDialog(
            onDismissRequest = { replaceResult = null },
            title = { Text(t("people.replaceCodeTitle")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(t("people.replaceCodeBody"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        r.inviteCode,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                    )
                    Text(
                        t("people.replaceSuccessor") + " " + r.successor,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (r.revokeError != null || r.rotationFailed.isNotEmpty()) {
                        Text(
                            t("people.replaceWarn"),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        r.revokeError?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall)
                        }
                        for (f in r.rotationFailed) {
                            Text(f, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    copyToClipboard(r.inviteCode)
                    Toast.success(t("people.codeCopied"))
                    replaceResult = null
                }) { Text(t("people.copyCode")) }
            },
            dismissButton = {
                TextButton(onClick = { replaceResult = null }) { Text(t("common.close")) }
            },
        )
    }

    // ── G13 group dialogs ── create, manage (rename / members / delete).
    if (showGroupCreate) {
        AlertDialog(
            onDismissRequest = { if (!groupBusy) showGroupCreate = false },
            title = { Text(t("people.groupNew")) },
            text = {
                BaluardTextField(
                    value = groupName,
                    onValueChange = { groupName = it },
                    label = t("people.groupNameLabel"),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(
                    enabled = !groupBusy && groupName.isNotBlank(),
                    onClick = {
                        scope.launch {
                            groupBusy = true
                            runCatching { repo.groupCreate(vault, groupName.trim()) }
                                .onSuccess {
                                    showGroupCreate = false
                                    refreshAll()
                                }
                                .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                            groupBusy = false
                        }
                    },
                ) { Text(t("people.groupCreate")) }
            },
            dismissButton = {
                TextButton(onClick = { showGroupCreate = false }) { Text(t("common.cancel")) }
            },
        )
    }

    verifyTarget?.let { m ->
        AlertDialog(
            onDismissRequest = { if (!verifyBusy) verifyTarget = null },
            title = { Text(t("people.verifyTitle", m.name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        t("people.verifyDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (verifyCode == null && verifyErr == null) {
                        LaunchedEffect(m.id) {
                            runCatching {
                                val o = kotlinx.serialization.json.Json.parseToJsonElement(
                                    repo.contactsList(vault),
                                ) as? kotlinx.serialization.json.JsonObject
                                val rows = o?.get("contacts") as? kotlinx.serialization.json.JsonArray
                                val row = rows?.firstOrNull { el ->
                                    (el as? kotlinx.serialization.json.JsonObject)
                                        ?.get("identity_signing_pubkey")
                                        ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content } == m.identityPub
                                } as? kotlinx.serialization.json.JsonObject
                                verifyCode = row?.get("verification_code")
                                    ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                                if (verifyCode == null) {
                                    verifyErr = t("people.verifyMissing")
                                }
                            }.onFailure { verifyErr = t("error.generic") }
                        }
                    }
                    verifyCode?.let { code ->
                        Text(
                            code,
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        )
                    }
                    verifyErr?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !verifyBusy && verifyCode != null,
                    onClick = {
                        scope.launch {
                            verifyBusy = true
                            try {
                                repo.contactMarkVerified(vault, m.identityPub)
                                verifyTarget = null
                                Toast.success(t("people.verifiedToast"))
                                refreshAll()
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                verifyErr = e.message?.removePrefix("detail=") ?: t("error.generic")
                            }
                            verifyBusy = false
                        }
                    },
                ) { Text(t("people.verifyConfirm")) }
            },
            dismissButton = {
                TextButton(onClick = { verifyTarget = null }) { Text(t("common.cancel")) }
            },
        )
    }

    roleTarget?.let { m ->
        AlertDialog(
            onDismissRequest = { if (!roleBusy) roleTarget = null },
            title = { Text(m.name) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        t("people.roleDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    listOf("viewer", "editor", "admin").forEach { role ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { rolePick = role }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = rolePick == role,
                                onClick = null,
                            )
                            Text(
                                when (role) {
                                    "owner" -> t("people.roleOwner")
                                    "admin" -> t("people.roleAdmin")
                                    "viewer" -> t("people.roleViewer")
                                    else -> t("people.roleEditor")
                                },
                                modifier = Modifier.padding(start = 8.dp),
                            )
                        }
                    }
                    if (m.role == "admin" && rolePick != "admin") {
                        Text(
                            t("people.roleDemoteWarn"),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    roleErr?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !roleBusy,
                    onClick = {
                        scope.launch {
                            roleBusy = true
                            try {
                                repo.memberSetRole(vault, m.id, rolePick)
                                roleTarget = null
                                refreshAll()
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                roleErr = e.message?.removePrefix("detail=") ?: t("error.generic")
                            }
                            roleBusy = false
                        }
                    },
                ) { Text(t("common.save")) }
            },
            dismissButton = {
                TextButton(onClick = { roleTarget = null }) { Text(t("common.cancel")) }
            },
        )
    }

    groupEdit?.let { g ->
        val liveMembers = members.filter { !it.removed && !it.reset }
        AlertDialog(
            onDismissRequest = { if (!groupBusy) groupEdit = null },
            title = { Text(g.name) },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        BaluardTextField(
                            value = groupEditName,
                            onValueChange = { groupEditName = it },
                            label = t("people.groupNameLabel"),
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            enabled = !groupBusy && groupEditName.isNotBlank() && groupEditName != g.name,
                            onClick = {
                                scope.launch {
                                    groupBusy = true
                                    runCatching { repo.groupRename(vault, g.id, groupEditName.trim()) }
                                        .onSuccess { groupEdit = null; refreshAll() }
                                        .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                                    groupBusy = false
                                }
                            },
                        ) { Text(t("people.groupSave")) }
                    }
                    Text(
                        t("people.groupMembers"),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val inGroup = g.memberIds.toSet()
                    liveMembers.forEach { m ->
                        val joined = m.id in inGroup
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(m.name, modifier = Modifier.weight(1f))
                            TextButton(
                                enabled = !groupBusy,
                                onClick = {
                                    scope.launch {
                                        groupBusy = true
                                        runCatching {
                                            if (joined) repo.groupMemberRemove(vault, g.id, m.id)
                                            else repo.groupMemberAdd(vault, g.id, m.id)
                                        }
                                            .onSuccess {
                                                groupEdit = null
                                                refreshAll()
                                            }
                                            .onFailure { Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic")) }
                                        groupBusy = false
                                    }
                                },
                            ) {
                                Text(
                                    t(if (joined) "people.groupRemove" else "people.groupAddMember"),
                                    color = if (joined) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
                    }
                    TextButton(
                        enabled = !groupBusy,
                        onClick = { groupDeleteArm = true },
                    ) {
                        Text(
                            t("people.groupDelete"),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (groupDeleteArm) {
                        Text(
                            t("people.groupDeleteConfirm", g.name),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        TextButton(
                            enabled = !groupBusy,
                            onClick = {
                                scope.launch {
                                    groupBusy = true
                                    runCatching { repo.groupDelete(vault, g.id) }
                                        .onSuccess {
                                            groupEdit = null
                                            groupDeleteArm = false
                                            refreshAll()
                                        }
                                        .onFailure {
                                            Toast.error(it.message?.removePrefix("detail=") ?: t("error.generic"))
                                            groupDeleteArm = false
                                        }
                                    groupBusy = false
                                }
                            },
                        ) { Text(t("common.continue")) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { groupEdit = null }) { Text(t("common.close")) }
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
    members.firstOrNull { it.id == id }?.name
        ?: app.baluard.mobile.i18n.t("shared.unknownMember", id.take(8))

private fun expirySuffix(expiresAt: Long?): String =
    if (expiresAt != null && expiresAt > 0L) " · ${formatEpochDate(expiresAt)}" else ""
