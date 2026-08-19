package xyz.actitud.baluard.edit

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
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.FieldSpec
import xyz.actitud.baluard.detail.fieldsFor
import xyz.actitud.baluard.detail.typeLabelKey
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.components.CipherAvatar
import xyz.actitud.baluard.ui.components.SectionCard

/** Wire tags in UI order; dropdown labels come from i18n. */
private val TYPE_TAGS = listOf(
    "login", "card", "identity", "secureNote", "sshKey", "bankAccount", "driversLicense", "passport",
)

/**
 * Edit form for all 8 cipher types styled after Baluard design language.
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
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(if (cipherId == null) t("edit.newEntry") else t("edit.editEntry")) },
                navigationIcon = {
                    IconButton(onClick = onCancelled) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Category / Type Selector Card
            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                TypePicker(form.typeTag, editable = cipherId == null, onSelected = { viewModel.setType(it) })
            }

            // Basic Information Section
            SectionCard(title = "Item Details") {
                BaluardTextField(
                    value = form.name,
                    onValueChange = { viewModel.setName(it) },
                    label = t("edit.name"),
                    placeholder = "e.g. GitHub, Netflix, Main Card",
                    enabled = !saving,
                )

                Spacer(Modifier.height(12.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.surface)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
                        .clickable(enabled = !saving) { viewModel.setFavorite(!form.favorite) }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Star,
                                contentDescription = null,
                                tint = if (form.favorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = t("edit.favorite"),
                                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                        Checkbox(
                            checked = form.favorite,
                            onCheckedChange = { viewModel.setFavorite(it) },
                            enabled = !saving,
                            colors = CheckboxDefaults.colors(
                                checkedColor = MaterialTheme.colorScheme.primary,
                                checkmarkColor = MaterialTheme.colorScheme.onPrimary,
                            ),
                        )
                    }
                }
            }

            // Schema-driven Fields Section
            val fields = fieldsFor(form.typeTag)
            if (fields.isNotEmpty()) {
                SectionCard(title = "Credentials") {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        fields.forEach { spec ->
                            BaluardTextField(
                                value = form.values[spec.wireKey].orEmpty(),
                                onValueChange = { viewModel.setField(spec.wireKey, it) },
                                label = t(spec.labelKey),
                                isPassword = spec.sensitive,
                                enabled = !saving,
                            )
                        }
                    }
                }
            }

            // Notes Section
            SectionCard(title = t("edit.notes")) {
                BaluardTextField(
                    value = form.notes,
                    onValueChange = { viewModel.setNotes(it) },
                    label = t("edit.notes"),
                    placeholder = "Additional private notes...",
                    singleLine = false,
                    minLines = 3,
                    enabled = !saving,
                )
            }

            error?.let {
                Text(
                    text = it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Spacer(Modifier.height(8.dp))

            BaluardPrimaryButton(
                text = if (saving) t("common.saving") else t("common.save"),
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
                loading = saving,
                leadingIcon = Icons.Default.Save,
            )

            BaluardOutlinedButton(
                text = t("common.cancel"),
                onClick = onCancelled,
                enabled = !saving,
            )

            Spacer(Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TypePicker(tag: String, editable: Boolean, onSelected: (String) -> Unit) {
    if (!editable) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CipherAvatar(name = tag, typeTag = tag, size = 36.dp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    text = t("edit.typeLabel"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = t(typeLabelKey(tag)),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
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
            leadingIcon = {
                CipherAvatar(name = tag, typeTag = tag, size = 26.dp)
            },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = MaterialTheme.colorScheme.surface,
                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh),
        ) {
            TYPE_TAGS.forEach { candidate ->
                DropdownMenuItem(
                    leadingIcon = {
                        CipherAvatar(name = candidate, typeTag = candidate, size = 24.dp)
                    },
                    text = {
                        Text(
                            text = t(typeLabelKey(candidate)),
                            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                        )
                    },
                    onClick = {
                        onSelected(candidate)
                        expanded = false
                    },
                )
            }
        }
    }
}
