package xyz.actitud.baluard.detail

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.UriVerdict
import xyz.actitud.baluard.platform.classifyUri
import xyz.actitud.baluard.platform.openUrl
import xyz.actitud.baluard.totp.TotpViewModel
import xyz.actitud.baluard.totp.TotpWidget
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.CategoryBadge
import xyz.actitud.baluard.ui.components.CipherAvatar
import xyz.actitud.baluard.ui.components.CopyableFieldRow
import xyz.actitud.baluard.ui.components.SectionCard

/**
 * Decrypted cipher detail styled after Baluard design language.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CipherDetailScreen(
    vault: MobileVault,
    cipherId: String,
    detailViewModel: CipherDetailViewModel,
    totpViewModel: TotpViewModel,
    onEdit: () -> Unit,
    onDeleted: () -> Unit,
    onBack: () -> Unit,
    revision: Int = 0,
) {
    LaunchedEffect(cipherId, revision) { detailViewModel.load(vault, cipherId) }

    val state = detailViewModel.state
    val scope = rememberCoroutineScope()
    var confirmDelete by remember { mutableStateOf(false) }
    // M7: a non-browser URI waiting for the user's confirmation to launch.
    var pendingExternalUri by remember { mutableStateOf<String?>(null) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(state?.name ?: "") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                actions = {
                    IconButton(onClick = onEdit) {
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
                                    contentDescription = "Favorite",
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

            // Credentials / Key Details Section
            if (s.fields.isNotEmpty()) {
                SectionCard(title = "Credentials & Details") {
                    s.fields.forEachIndexed { index, row ->
                        CopyableFieldRow(
                            label = t(row.spec.labelKey),
                            value = row.value,
                            mono = row.spec.mono,
                            sensitive = row.spec.sensitive,
                        )
                        if (index < s.fields.size - 1) {
                            androidx.compose.material3.HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )
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
                            CopyableFieldRow(
                                label = field.name,
                                value = field.value,
                                sensitive = field.hidden,
                            )
                        }
                        if (index < s.customFields.size - 1) {
                            androidx.compose.material3.HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
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
                            androidx.compose.material3.HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
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
                                imageVector = Icons.Default.InsertDriveFile,
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
                            androidx.compose.material3.HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )
                        }
                    }
                }
            }

            // Websites & URIs Section
            if (s.uris.isNotEmpty()) {
                SectionCard(title = "Websites") {
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
                                    contentDescription = "Open in browser",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        if (index < s.uris.size - 1) {
                            androidx.compose.material3.HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )
                        }
                    }
                }
            }

            // Notes Section
            s.notes?.let { notes ->
                if (notes.isNotBlank()) {
                    SectionCard(title = t("edit.notes")) {
                        Text(
                            text = notes,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(vertical = 4.dp),
                        )
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmDelete && state != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(t("detail.deleteTitle")) },
            text = { Text(t("detail.deleteBody", state.name)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmDelete = false
                        scope.launch {
                            detailViewModel.delete(vault, state.id)
                            if (detailViewModel.error == null) onDeleted()
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
