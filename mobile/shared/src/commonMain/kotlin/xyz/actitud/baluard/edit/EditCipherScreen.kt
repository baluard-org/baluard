package xyz.actitud.baluard.edit

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
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.FieldSpec
import xyz.actitud.baluard.detail.fieldsFor
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t

/** Wire tags in UI order; the dropdown labels come from i18n. */
private val TYPE_TAGS = listOf(
    "login", "card", "identity", "secureNote", "sshKey", "bankAccount", "driversLicense", "passport",
)

/**
 * Edit form for all 8 cipher types (plan §3). Field rows render from the
 * same schema as the detail screen ([fieldsFor]); sensitive inputs are
 * masked with a visibility toggle. The type is pickable only on new entries;
 * editing keeps the stored type. See EditCipherViewModel for the
 * merge-on-save semantics that preserve fields the form does not model.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditCipherScreen(
    vault: MobileVault,
    cipherId: String?, // null = new
    viewModel: EditCipherViewModel,
    onSaved: () -> Unit,
    onCancelled: () -> Unit = {},
) {
    val form by viewModel.form.collectAsState()
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(cipherId) {
        if (cipherId != null) viewModel.load(vault, cipherId) else viewModel.reset()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (cipherId == null) t("edit.newEntry") else t("edit.editEntry")) },
                navigationIcon = {
                    IconButton(onClick = onCancelled) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
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
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TypePicker(form.typeTag, editable = cipherId == null, onSelected = { viewModel.setType(it) })

            OutlinedTextField(
                value = form.name,
                onValueChange = { viewModel.setName(it) },
                label = { Text(t("edit.name")) },
                singleLine = true,
                enabled = !saving,
                modifier = Modifier.fillMaxWidth(),
            )

            fieldsFor(form.typeTag).forEach { spec ->
                FieldInput(
                    spec = spec,
                    value = form.values[spec.wireKey].orEmpty(),
                    enabled = !saving,
                    onValue = { viewModel.setField(spec.wireKey, it) },
                )
            }

            OutlinedTextField(
                value = form.notes,
                onValueChange = { viewModel.setNotes(it) },
                label = { Text(t("edit.notes")) },
                minLines = 2,
                enabled = !saving,
                modifier = Modifier.fillMaxWidth(),
            )

            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Checkbox(checked = form.favorite, onCheckedChange = { viewModel.setFavorite(it) })
                Text(t("edit.favorite"))
            }

            if (saving) {
                androidx.compose.material3.CircularProgressIndicator()
            } else {
                Button(
                    onClick = {
                        saving = true
                        error = null
                        scope.launch {
                            viewModel.save(vault)
                                .onSuccess { saving = false; onSaved() }
                                .onFailure { saving = false; error = it.message }
                        }
                    },
                    enabled = form.name.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(t("common.save")) }
            }
            TextButton(onClick = onCancelled, enabled = !saving) {
                Text(t("common.back"))
            }
            error?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TypePicker(tag: String, editable: Boolean, onSelected: (String) -> Unit) {
    if (!editable) {
        // Editing keeps the stored type; show it read-only for context.
        OutlinedTextField(
            value = t(typeLabelKey(tag)),
            onValueChange = {},
            readOnly = true,
            label = { Text(t("edit.typeLabel")) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        return
    }

    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = t(typeLabelKey(tag)),
            onValueChange = {},
            readOnly = true,
            label = { Text(t("edit.typeLabel")) },
            singleLine = true,
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            TYPE_TAGS.forEach { candidate ->
                DropdownMenuItem(
                    text = { Text(t(typeLabelKey(candidate))) },
                    onClick = {
                        onSelected(candidate)
                        expanded = false
                    },
                )
            }
        }
    }
}

/** One schema-driven input; sensitive values get a mask + visibility toggle. */
@Composable
private fun FieldInput(spec: FieldSpec, value: String, enabled: Boolean, onValue: (String) -> Unit) {
    var revealed by remember(spec.wireKey) { mutableStateOf(!spec.sensitive) }
    OutlinedTextField(
        value = value,
        onValueChange = onValue,
        label = { Text(t(spec.labelKey)) },
        singleLine = true,
        enabled = enabled,
        visualTransformation = if (revealed) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = if (spec.sensitive) {
            {
                IconButton(onClick = { revealed = !revealed }) {
                    Icon(
                        if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (revealed) t("detail.hide") else t("detail.reveal"),
                    )
                }
            }
        } else {
            null
        },
        modifier = Modifier.fillMaxWidth(),
    )
}
