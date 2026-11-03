package app.baluard.mobile.detail

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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.OpenInFull
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.baluard.mobile.ui.components.BaluardDivider
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.platform.rememberRecoverySheetSaver
import app.baluard.mobile.ui.toast.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import app.baluard.mobile.MobileVault
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.Clock
import app.baluard.mobile.platform.UriVerdict
import app.baluard.mobile.platform.classifyUri
import app.baluard.mobile.platform.openUrl
import app.baluard.mobile.totp.TotpViewModel
import app.baluard.mobile.totp.TotpWidget
import app.baluard.mobile.ui.components.BaluardCard
import app.baluard.mobile.ui.components.CategoryBadge
import app.baluard.mobile.ui.components.CipherAvatar
import app.baluard.mobile.ui.components.CopyableFieldRow
import app.baluard.mobile.ui.components.SectionCard

/**
 * Decrypted cipher detail styled after Baluard design language.
 */
@OptIn(ExperimentalMaterial3Api::class, kotlin.io.encoding.ExperimentalEncodingApi::class)
@Composable
fun CipherDetailScreen(
    vault: MobileVault,
    cipherId: String,
    detailViewModel: CipherDetailViewModel,
    totpViewModel: TotpViewModel,
    onEdit: () -> Unit,
    onDeleted: (id: String, permanent: Boolean) -> Unit,
    onBack: () -> Unit,
    revision: Int = 0,
) {
    LaunchedEffect(cipherId, revision) { detailViewModel.load(vault, cipherId) }

    val state = detailViewModel.state
    val scope = rememberCoroutineScope()
    var confirmDelete by remember { mutableStateOf(false) }
    // M7: a non-browser URI waiting for the user's confirmation to launch.
    var pendingExternalUri by remember { mutableStateOf<String?>(null) }
    var showNotesView by remember { mutableStateOf(false) }

    // Notes links ride the same M7 gate as vault URIs: browser schemes
    // open directly, others ask first, refused schemes do nothing.
    val handleNoteLink: (String) -> Unit = { uri ->
        when (classifyUri(uri)) {
            UriVerdict.OpenInBrowser -> openUrl(uri)
            is UriVerdict.ConfirmExternal -> pendingExternalUri = uri
            UriVerdict.Refuse -> Unit
        }
    }

    // G18: per-cipher master-password re-prompt. The grant is a 30s window
    // (matching the daemon reprompt grant); before it opens, sensitive rows
    // render as a lock strip instead of their values. Fail-closed: the
    // re-lock effect resets the grant at expiry, so a recomposition re-locks.
    var repromptGrantedUntil by remember { mutableStateOf(0L) }
    var showReprompt by remember { mutableStateOf(false) }
    var repromptPw by remember { mutableStateOf("") }
    var repromptError by remember { mutableStateOf(false) }
    LaunchedEffect(repromptGrantedUntil) {
        if (repromptGrantedUntil > 0L) {
            delay((repromptGrantedUntil - Clock.currentTimeMillis()).coerceAtLeast(50L))
            repromptGrantedUntil = 0L
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                title = state?.name ?: "",
                onBack = onBack,
                actions = {
                    IconButton(onClick = {
                        // G18: protected entries gate the edit flow too.
                        if (state?.reprompt == true && Clock.currentTimeMillis() >= repromptGrantedUntil) {
                            showReprompt = true
                        } else {
                            onEdit()
                        }
                    }) {
                        Icon(Icons.Default.Edit, contentDescription = t("detail.edit"))
                    }
                    IconButton(onClick = { confirmDelete = true }, enabled = state != null) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = t("detail.delete"),
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                },
            )
        },
    ) { padding ->
        val s = state
        if (s == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                detailViewModel.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
            return@Scaffold
        }

        // One-shot error toast: side effects never run in composition.
        LaunchedEffect(detailViewModel.error) {
            detailViewModel.error?.let { err ->
                Toast.error(err.removePrefix("detail=").ifBlank { t("error.generic") })
                detailViewModel.ackError()
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Header Overview Card
            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CipherAvatar(
                        name = s.name,
                        typeTag = s.typeTag,
                        size = 52.dp,
                    )

                    Spacer(Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(
                                text = s.name,
                                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            if (s.favorite) {
                                Icon(
                                    imageVector = Icons.Default.Star,
                                    contentDescription = t("vault.favorite"),
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }

                        Spacer(Modifier.height(4.dp))

                        CategoryBadge(
                            label = t(typeLabelKey(s.typeTag)),
                            typeTag = s.typeTag,
                        )
                    }
                }
            }

            // TOTP Live Code Card if applicable
            if (s.hasTotp) {
                TotpWidget(vault = vault, cipherId = s.id, viewModel = totpViewModel)
            }

            // Share as file: passphrase-guest reveal (Login-only; the
            // passphrase opens it and travels by voice, never in the file).
            if (s.typeTag == "login") {
                val repo = remember { VaultRepository() }
                val saver = rememberRecoverySheetSaver()
                val shareScope = rememberCoroutineScope()
                var shareBusy by remember { mutableStateOf(false) }
                var sharePass by remember { mutableStateOf<String?>(null) }
                BaluardOutlinedButton(
                    text = t("share.exportRow"),
                    onClick = {
                        if (shareBusy) return@BaluardOutlinedButton
                        shareBusy = true
                        shareScope.launch {
                            try {
                                val expiresAt = Clock.currentTimeMillis() / 1000 + 7 * 86_400L
                                val (revealB64, passphrase) =
                                    repo.exportGuestReveal(vault, s.id, expiresAt, false)
                                val bytes = kotlin.io.encoding.Base64.decode(revealB64)
                                val stem = s.name.map { if (it.isLetterOrDigit()) it else '-' }
                                    .joinToString("").trim('-').take(40).ifBlank { "entry" }
                                saver(bytes, "application/octet-stream", "$stem.baluard-share") { saved ->
                                    shareBusy = false
                                    if (saved) sharePass = passphrase
                                }
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                shareBusy = false
                                Toast.error(
                                    (e.message ?: "").removePrefix("detail=").ifBlank { t("share.exportFailed") },
                                )
                            }
                        }
                    },
                    enabled = !shareBusy,
                )
                sharePass?.let { pass ->
                    AlertDialog(
                        // Shown once: outside-tap and back must not
                        // discard the passphrase before it is copied.
                        onDismissRequest = {},
                        title = { Text(t("share.exportPassTitle")) },
                        text = {
                            Column {
                                Text(
                                    t("share.exportPassBody"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    pass,
                                    style = MaterialTheme.typography.bodyLarge,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = { sharePass = null }) { Text(t("common.done")) }
                        },
                    )
                }
            }

            // Credentials / Key Details Section
            if (s.fields.isNotEmpty()) {
                SectionCard(title = t("detail.sectionCredentials")) {
                    var lockStripShown = false
                    s.fields.forEachIndexed { index, row ->
                        val locked = s.reprompt && row.spec.sensitive &&
                            Clock.currentTimeMillis() >= repromptGrantedUntil
                        var rendered = false
                        if (locked) {
                            if (!lockStripShown) {
                                lockStripShown = true
                                RepromptLockStrip(onClick = { showReprompt = true })
                                rendered = true
                            }
                        } else {
                            CopyableFieldRow(
                                label = t(row.spec.labelKey),
                                value = row.value,
                                mono = row.spec.mono,
                                sensitive = row.spec.sensitive,
                            )
                            rendered = true
                        }
                        if (rendered && index < s.fields.size - 1) {
                            BaluardDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                alpha = 0.5f,
                            )
                        }
                    }
                }
            }
            // Password History (desktop parity: past passwords, masked)
            if (s.passwordHistory.isNotEmpty()) {
                SectionCard(title = t("detail.passwordHistory")) {
                    if (s.reprompt && Clock.currentTimeMillis() >= repromptGrantedUntil) {
                        RepromptLockStrip(onClick = { showReprompt = true })
                    } else {
                        s.passwordHistory.forEachIndexed { index, h ->
                            CopyableFieldRow(
                                label = h.usedOn ?: t("detail.passwordHistoryUnknown"),
                                value = h.password,
                                mono = true,
                                sensitive = true,
                            )
                            if (index < s.passwordHistory.size - 1) {
                                BaluardDivider(
                                    modifier = Modifier.padding(vertical = 4.dp),
                                    alpha = 0.5f,
                                )
                            }
                        }
                    }
                }
            }

            // Custom Fields Section (desktop parity)
            if (s.customFields.isNotEmpty()) {
                SectionCard(title = t("detail.customFields")) {
                    s.customFields.forEachIndexed { index, field ->
                        if (field.boolean) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = field.name,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurface,
                                )
                                Surface(
                                    shape = RoundedCornerShape(50),
                                    color = if (field.value == "true") MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f)
                                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                ) {
                                    Text(
                                        text = t(
                                            if (field.value == "true") "detail.booleanYes"
                                            else "detail.booleanNo",
                                        ),
                                        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                                        color = MaterialTheme.colorScheme.onSurface,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                                    )
                                }
                            }
                        } else {
                            val locked = s.reprompt && field.hidden &&
                                Clock.currentTimeMillis() >= repromptGrantedUntil
                            if (locked) {
                                RepromptLockStrip(onClick = { showReprompt = true })
                            } else {
                                CopyableFieldRow(
                                    label = field.name,
                                    value = field.value,
                                    sensitive = field.hidden,
                                )
                            }
                        }
                        if (index < s.customFields.size - 1) {
                            BaluardDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                alpha = 0.5f,
                            )
                        }
                    }
                }
            }

            // Passkeys Section (display-only; delete stays desktop-only)
            if (s.passkeys.isNotEmpty()) {
                SectionCard(title = t("detail.passkeys")) {
                    s.passkeys.forEachIndexed { index, pk ->
                        Column(modifier = Modifier.padding(vertical = 6.dp)) {
                            Text(
                                text = pk.name,
                                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            InfoLine(t("detail.passkey.rp"), pk.rpId)
                            if (pk.user.isNotBlank()) InfoLine(t("detail.passkey.user"), pk.user)
                            pk.created?.let { InfoLine(t("detail.passkey.created"), it) }
                            if (pk.missingKey) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = t("detail.passkey.missingKey"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                        if (index < s.passkeys.size - 1) {
                            BaluardDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                alpha = 0.5f,
                            )
                        }
                    }
                }
            }

            // Attachments Section (metadata display; download lands with the
            // mobile attachment FFI)
            if (s.attachments.isNotEmpty()) {
                SectionCard(title = t("detail.attachments")) {
                    s.attachments.forEachIndexed { index, att ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.InsertDriveFile,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = att.filename,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            Text(
                                text = att.sizeLabel,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (index < s.attachments.size - 1) {
                            BaluardDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                alpha = 0.5f,
                            )
                        }
                    }
                }
            }

            // Websites & URIs Section
            if (s.uris.isNotEmpty()) {
                SectionCard(title = t("detail.sectionWebsites")) {
                    s.uris.forEachIndexed { index, uri ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                imageVector = Icons.Default.Link,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = t("detail.f.uri"),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = uri,
                                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                                    color = MaterialTheme.colorScheme.onSurface,
                                )
                            }
                            IconButton(
                                onClick = {
                                    // M7: vault URIs are untrusted. http/https
                                    // open directly; other schemes (which may
                                    // launch another app) are confirmed first.
                                    when (classifyUri(uri)) {
                                        UriVerdict.OpenInBrowser -> openUrl(uri)
                                        is UriVerdict.ConfirmExternal -> pendingExternalUri = uri
                                        UriVerdict.Refuse -> Unit
                                    }
                                },
                                modifier = Modifier.size(36.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.OpenInNew,
                                    contentDescription = t("detail.openInBrowser"),
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        if (index < s.uris.size - 1) {
                            BaluardDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                alpha = 0.5f,
                            )
                        }
                    }
                }
            }

            // Notes Section
            s.notes?.let { notes ->
                if (notes.isNotBlank()) {
                    SectionCard(title = t("edit.notes")) {
                        if (looksLikeMarkdown(notes)) {
                            MarkdownText(
                                text = notes,
                                modifier = Modifier.padding(vertical = 4.dp),
                                onLinkClick = { uri -> handleNoteLink(uri) },
                            )
                        } else {
                            Text(
                                text = notes,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(vertical = 4.dp),
                            )
                        }
                        TextButton(
                            onClick = { showNotesView = true },
                            modifier = Modifier.align(Alignment.End),
                        ) {
                            Icon(
                                imageVector = Icons.Default.OpenInFull,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(14.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = t("detail.viewNotes"),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmDelete && state != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(t(if (detailViewModel.inTrash) "detail.deletePermanentTitle" else "detail.deleteTitle")) },
            text = { Text(t(if (detailViewModel.inTrash) "detail.deletePermanentBody" else "detail.deleteBody", state.name)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmDelete = false
                        scope.launch {
                            detailViewModel.delete(vault, state.id)
                            if (detailViewModel.error == null) onDeleted(state.id, detailViewModel.inTrash)
                        }
                    },
                ) {
                    Text(t("detail.delete"), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }

    // G18: master-password re-prompt for protected entries. Verify via the
    // vault's own unlock (idempotent on an unlocked vault, desktop parity
    // with RepromptModal); a wrong password leaves the current state intact.
    if (showReprompt) {
        AlertDialog(
            onDismissRequest = { showReprompt = false; repromptPw = ""; repromptError = false },
            title = { Text(t("detail.repromptTitle")) },
            text = {
                Column {
                    Text(
                        t("detail.repromptLocked"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = repromptPw,
                        onValueChange = { repromptPw = it; repromptError = false },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        isError = repromptError,
                        placeholder = { Text(t("login.passwordPlaceholder")) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (repromptError) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            t("login.wrongPassword"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            // repromptVerify opens a temporary handle and
                            // truly checks the password; vault.unlock would
                            // short-circuit on an already-unlocked vault.
                            val ok = repromptPw.isNotEmpty() &&
                                runCatching { vault.repromptVerify(repromptPw) }.isSuccess
                            if (ok) {
                                repromptGrantedUntil = Clock.currentTimeMillis() + 30_000L
                                showReprompt = false
                                repromptPw = ""
                                repromptError = false
                            } else {
                                repromptError = true
                            }
                        }
                    },
                    enabled = repromptPw.isNotEmpty(),
                ) {
                    Text(t("common.continue"))
                }
            },
            dismissButton = {
                TextButton(onClick = { showReprompt = false; repromptPw = ""; repromptError = false }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }

    // M7: user-confirmed launch of a non-browser scheme (mailto:, ssh:, ...).
    pendingExternalUri?.let { uri ->
        val scheme = classifyUri(uri).let {
            (it as? UriVerdict.ConfirmExternal)?.scheme ?: ""
        }
        AlertDialog(
            onDismissRequest = { pendingExternalUri = null },
            title = { Text(t("detail.openExternalTitle")) },
            text = { Text(t("detail.openExternalBody", scheme)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingExternalUri = null
                        openUrl(uri)
                    },
                ) {
                    Text(t("detail.openExternalConfirm"))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingExternalUri = null }) {
                    Text(t("common.cancel"))
                }
            },
        )
    }

    // Notes reading view (expand): a roomier surface for long notes.
    if (showNotesView && state != null) {
        Dialog(
            onDismissRequest = { showNotesView = false },
            properties = DialogProperties(usePlatformDefaultWidth = false),
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 32.dp)
                    .heightIn(max = 720.dp),
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 6.dp,
            ) {
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 20.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = t("edit.notes").uppercase(),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                text = state.name,
                                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        IconButton(onClick = { showNotesView = false }) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = t("common.close"),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    BaluardDivider()
                    Column(
                        modifier = Modifier
                            .verticalScroll(rememberScrollState())
                            .padding(20.dp),
                    ) {
                        if (looksLikeMarkdown(state.notes ?: "")) {
                            MarkdownText(text = state.notes ?: "", onLinkClick = { uri -> handleNoteLink(uri) })
                        } else {
                            Text(
                                text = state.notes ?: "",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    }
                }
            }
        }
    }
}

/** G18: stand-in for a sensitive row while the master-password grant is
 * closed. Tapping it opens the re-prompt dialog. */
@Composable
private fun RepromptLockStrip(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(16.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text = t("detail.repromptLocked"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Small label/value line inside a passkey block. */
@Composable
private fun InfoLine(label: String, value: String) {
    Row(
        modifier = Modifier.padding(top = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(72.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
