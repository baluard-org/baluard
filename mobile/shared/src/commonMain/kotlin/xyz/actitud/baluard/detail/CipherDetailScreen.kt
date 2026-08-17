package xyz.actitud.baluard.detail

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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.copyToClipboard
import xyz.actitud.baluard.totp.TotpViewModel
import xyz.actitud.baluard.totp.TotpWidget

/**
 * Decrypted cipher detail (plan §3 remaining UI: all 8 types). Field rows
 * come from [fieldsFor]; sensitive values are masked until revealed, every
 * row copies on tap. Logins with a TOTP seed show the live code widget (the
 * seed itself never crosses the FFI).
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
    /** Bumped by the caller after a save so the reload effect re-fires. */
    revision: Int = 0,
) {
    LaunchedEffect(cipherId, revision) { detailViewModel.load(vault, cipherId) }

    LaunchedEffect(cipherId, revision) { detailViewModel.load(vault, cipherId) }

    val state = detailViewModel.state
    val scope = rememberCoroutineScope()
    var confirmDelete by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(state?.name ?: "", style = MaterialTheme.typography.titleLarge)
                        state?.let {
                            Text(
                                t(typeLabelKey(it.typeTag)),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
                    }
                },
                actions = {
                    state?.let { s ->
                        if (s.favorite) {
                            Icon(
                                Icons.Filled.Star,
                                contentDescription = t("edit.favorite"),
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                    IconButton(onClick = onEdit) {
                        Icon(Icons.Filled.Edit, contentDescription = t("detail.edit"))
                    }
                    IconButton(onClick = { confirmDelete = true }, enabled = state != null) {
                        Icon(Icons.Filled.Delete, contentDescription = t("detail.delete"))
                    }
                },
            )
        },
    ) { padding ->
        val s = state
        if (s == null) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                detailViewModel.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            if (s.hasTotp) {
                TotpWidget(vault = vault, cipherId = s.id, viewModel = totpViewModel)
                Spacer(Modifier.height(8.dp))
            }

            s.uris.forEach { uri -> FieldRow(label = t("detail.f.uri"), value = uri, mono = true, onCopy = { copyToClipboard(uri) }) }

            s.fields.forEach { row ->
                FieldRow(
                    label = t(row.spec.labelKey),
                    value = row.value,
                    mono = row.spec.mono,
                    sensitive = row.spec.sensitive,
                    onCopy = { copyToClipboard(row.value) },
                )
            }

            s.notes?.let { notes ->
                Spacer(Modifier.height(16.dp))
                Text(t("edit.notes"), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                Text(notes, style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(32.dp))
        }
    }

    if (confirmDelete && state != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(t("detail.deleteTitle")) },
            text = { Text(t("detail.deleteBody", state.name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        detailViewModel.delete(vault, state.id)
                        if (detailViewModel.error == null) onDeleted()
                    }
                }) { Text(t("detail.delete")) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text(t("common.cancel")) }
            },
        )
    }
}

/** One label + value row; sensitive values mask until revealed. */
@Composable
private fun FieldRow(
    label: String,
    value: String,
    mono: Boolean = false,
    sensitive: Boolean = false,
    onCopy: () -> Unit,
) {
    var revealed by remember(label) { mutableStateOf(!sensitive) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                if (revealed) value else "••••••••",
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (mono) FontFamily.Monospace else null,
            )
        }
        if (sensitive) {
            IconButton(onClick = { revealed = !revealed }) {
                Icon(
                    if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                    contentDescription = if (revealed) t("detail.hide") else t("detail.reveal"),
                )
            }
        }
        IconButton(onClick = onCopy) {
            Icon(Icons.Filled.ContentCopy, contentDescription = t("detail.copy"))
        }
    }
}
