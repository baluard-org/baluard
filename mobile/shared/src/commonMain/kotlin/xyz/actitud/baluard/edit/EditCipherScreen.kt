package xyz.actitud.baluard.edit

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Scaffold
import xyz.actitud.baluard.detail.cipherTypeWireTags
import xyz.actitud.baluard.ui.components.BaluardTopBar
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.data.MobileFolderInfo
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
import xyz.actitud.baluard.ui.E2eTags
import androidx.compose.ui.platform.testTag

// Wire tags in UI order come from the shared schema (detail/cipherTypeWireTags);
// dropdown labels come from i18n.

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
    // Autofill save handoff (Phase 6 P4): seeds the create form once, then
    // the caller drops the handoff so it cannot re-seed later.
    initialPrefill: xyz.actitud.baluard.platform.AutofillSavePrefill? = null,
    onPrefillConsumed: () -> Unit = {},
) {
    val form by viewModel.form.collectAsState()
    val folders by viewModel.folders.collectAsState()
    val allTags by viewModel.allTags.collectAsState()
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // Password generator knobs (desktop parity: 8-64 slider + 3 toggles).
    var genLen by remember { mutableStateOf(16) }
    var genUpper by remember { mutableStateOf(true) }
    var genNums by remember { mutableStateOf(true) }
    var genSyms by remember { mutableStateOf(true) }
    var showGenOptions by remember { mutableStateOf(false) }

    LaunchedEffect(cipherId) {
        if (cipherId != null) {
            viewModel.load(vault, cipherId)
        } else {
            viewModel.reset()
            if (initialPrefill != null) {
                viewModel.prefillFromAutofill(initialPrefill)
                onPrefillConsumed()
            }
        }
        viewModel.loadFolders(vault)
        viewModel.loadTags(vault)
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                title = if (cipherId == null) t("edit.newEntry") else t("edit.editEntry"),
                onBack = onCancelled,
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
            SectionCard(title = t("edit.sectionItemDetails")) {
                BaluardTextField(
                    value = form.name,
                    onValueChange = { viewModel.setName(it) },
                    modifier = Modifier.testTag(E2eTags.EDIT_NAME),
                    label = t("edit.name"),
                    placeholder = t("edit.namePlaceholder"),
                    enabled = !saving,
                )

                Spacer(Modifier.height(12.dp))

                CheckboxRow(
                    label = t("edit.favorite"),
                    checked = form.favorite,
                    enabled = !saving,
                    onToggle = { viewModel.setFavorite(it) },
                )

                Spacer(Modifier.height(12.dp))

                CheckboxRow(
                    label = t("edit.reprompt"),
                    checked = form.reprompt,
                    enabled = !saving,
                    onToggle = { viewModel.setReprompt(it) },
                )

                Spacer(Modifier.height(12.dp))

                FolderPicker(
                    selectedId = form.folderId,
                    folders = folders,
                    enabled = !saving,
                    onSelect = { viewModel.setFolderId(it) },
                )
            }

            // Schema-driven Fields Section
            val fields = fieldsFor(form.typeTag)
            if (fields.isNotEmpty()) {
                SectionCard(title = t("edit.sectionCredentials")) {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        fields.forEach { spec ->
                            when {
                                form.typeTag == "login" && spec.wireKey == "password" -> {
                                    PasswordWithGenerator(
                                        value = form.values[spec.wireKey].orEmpty(),
                                        enabled = !saving,
                                        genLen = genLen,
                                        genUpper = genUpper,
                                        genNums = genNums,
                                        genSyms = genSyms,
                                        showOptions = showGenOptions,
                                        onValueChange = { viewModel.setField(spec.wireKey, it) },
                                        onLengthChange = { genLen = it },
                                        onUpperChange = { genUpper = it },
                                        onNumsChange = { genNums = it },
                                        onSymsChange = { genSyms = it },
                                        onToggleOptions = { showGenOptions = !showGenOptions },
                                        onGenerate = {
                                            scope.launch {
                                                viewModel.setField(
                                                    spec.wireKey,
                                                    viewModel.generatePassword(genLen, genUpper, genNums, genSyms),
                                                )
                                            }
                                        },
                                    )
                                }

                                form.typeTag == "card" && spec.wireKey == "number" -> {
                                    CardNumberField(
                                        value = form.values[spec.wireKey].orEmpty(),
                                        enabled = !saving,
                                        onValueChange = { viewModel.setField(spec.wireKey, it) },
                                    )
                                }

                                form.typeTag == "card" && spec.wireKey == "exp_month" -> {
                                    DropdownField(
                                        label = t("detail.f.expMonth"),
                                        selected = form.values[spec.wireKey].orEmpty(),
                                        options = listOf("" to "MM") + (1..12).map {
                                            "%02d".format(it) to "%02d".format(it)
                                        },
                                        enabled = !saving,
                                        onSelect = { viewModel.setField(spec.wireKey, it) },
                                    )
                                }

                                form.typeTag == "passport" && spec.wireKey == "sex" -> {
                                    DropdownField(
                                        label = t("detail.f.sex"),
                                        selected = form.values[spec.wireKey].orEmpty(),
                                        options = listOf("" to "--", "M" to "M", "F" to "F", "X" to "X"),
                                        enabled = !saving,
                                        onSelect = { viewModel.setField(spec.wireKey, it) },
                                    )
                                }

                                else -> BaluardTextField(
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
            }

            // Login-only: multi-URI list with match strategy + TOTP seed
            if (form.typeTag == "login") {
                SectionCard(title = t("edit.uris")) {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        form.uris.forEachIndexed { index, row ->
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    BaluardTextField(
                                        value = row.uri,
                                        onValueChange = { viewModel.setUri(index, it) },
                                        label = t("edit.uriField"),
                                        placeholder = t("edit.uriPlaceholder"),
                                        enabled = !saving,
                                        modifier = Modifier.weight(1f),
                                    )
                                    RemoveButton(t("edit.removeUri"), !saving) { viewModel.removeUri(index) }
                                }
                                DropdownField(
                                    label = t("edit.match"),
                                    selected = row.matchStrategy.orEmpty(),
                                    options = MATCH_STRATEGIES,
                                    enabled = !saving,
                                    onSelect = { viewModel.setUriMatch(index, it.ifEmpty { null }) },
                                )
                            }
                        }
                        AddButton(t("edit.addUri"), !saving) { viewModel.addUri() }
                    }
                }

                SectionCard(title = t("edit.totpUri")) {
                    BaluardTextField(
                        value = form.totpUri,
                        onValueChange = { viewModel.setTotpUri(it) },
                        label = null,
                        placeholder = t("edit.totpUriPlaceholder"),
                        enabled = !saving,
                    )
                }
            }

            // SSH keypair generation (desktop SshKeyGenerator parity)
            if (form.typeTag == "sshKey") {
                SectionCard(title = t("edit.sshGenerator")) {
                    var sshBusy by remember { mutableStateOf(false) }
                    var sshType by remember { mutableStateOf("ed25519") }
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        DropdownField(
                            label = t("edit.sshAlgorithm"),
                            selected = sshType,
                            options = listOf(
                                "ed25519" to "edit.sshEd25519",
                                "ecdsa256" to "edit.sshEcdsa",
                            ),
                            enabled = !saving && !sshBusy,
                            onSelect = { sshType = it },
                        )
                        TextButton(
                            onClick = {
                                sshBusy = true
                                scope.launch {
                                    val ok = viewModel.generateSshKey(vault, sshType)
                                    sshBusy = false
                                    if (!ok) error = t("edit.sshGenerateFailed")
                                }
                            },
                            enabled = !saving && !sshBusy,
                        ) {
                            Text(if (sshBusy) t("common.saving") else t("edit.sshGenerate"))
                        }
                    }
                }
            }

            // Tags
            SectionCard(title = t("edit.tags")) {
                TagsEditor(
                    tags = form.tags,
                    suggestions = allTags,
                    enabled = !saving,
                    onAdd = { viewModel.addTag(it) },
                    onRemove = { viewModel.removeTag(it) },
                )
            }

            // Custom Fields
            SectionCard(title = t("edit.customFields")) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    form.customFields.forEachIndexed { index, field ->
                        CustomFieldEditor(
                            field = field,
                            enabled = !saving,
                            onName = { viewModel.setCustomFieldName(index, it) },
                            onValue = { viewModel.setCustomFieldValue(index, it) },
                            onType = { viewModel.setCustomFieldType(index, it) },
                            onLinkedTarget = { viewModel.setCustomFieldLinkedTarget(index, it) },
                            onRemove = { viewModel.removeCustomField(index) },
                        )
                    }
                    AddButton(t("edit.addField"), !saving) { viewModel.addCustomField() }
                }
            }

            // Notes Section
            SectionCard(title = t("edit.notes")) {
                BaluardTextField(
                    value = form.notes,
                    onValueChange = { viewModel.setNotes(it) },
                    // The section header names it; a field label would double it.
                    label = null,
                    placeholder = t("edit.notesPlaceholder"),
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
            viewModel.loadError?.let {
                Text(
                    text = it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(Modifier.height(8.dp))

            BaluardPrimaryButton(
                modifier = Modifier.testTag(E2eTags.EDIT_SAVE),
                text = if (saving) t("common.saving") else t("common.save"),
                onClick = {
                    saving = true
                    error = null
                    scope.launch {
                        viewModel.save(vault)
                            .onSuccess { saving = false; onSaved() }
                            .onFailure {
                                saving = false
                                error = it.message?.removePrefix("detail=") ?: it.message
                            }
                    }
                },
                // A failed load leaves an empty form; saving would overwrite
                // the entry with blank data.
                enabled = form.name.isNotBlank() && viewModel.loadError == null,
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
            cipherTypeWireTags.forEach { candidate ->
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

/** URI match strategies on the wire; "" = desktop's "Default" (absent key). */
private val MATCH_STRATEGIES = listOf(
    "" to "edit.match.default",
    "domain" to "edit.match.domain",
    "host" to "edit.match.host",
    "startsWith" to "edit.match.startsWith",
    "exact" to "edit.match.exact",
    "regex" to "edit.match.regex",
    "never" to "edit.match.never",
)

/** Custom-field Linked targets, desktop AddEditCipherForm parity. */
private val LINKED_TARGETS: List<String> = listOf(
    "LoginUsername", "LoginPassword",
    "CardCardholderName", "CardNumber", "CardExpMonth", "CardExpYear", "CardCvv",
    "IdentityTitle", "IdentityFirstName", "IdentityMiddleName", "IdentityLastName",
    "IdentityUsername", "IdentityCompany", "IdentityEmail", "IdentityPhone",
    "IdentityAddress1", "IdentityAddress2", "IdentityAddress3",
    "IdentityCity", "IdentityState", "IdentityPostalCode", "IdentityCountry",
    "BankAccountBankName", "BankAccountNameOnAccount", "BankAccountAccountType",
    "BankAccountAccountNumber", "BankAccountRoutingNumber", "BankAccountBranchNumber",
    "BankAccountPin", "BankAccountSwiftCode", "BankAccountIban", "BankAccountBankContactPhone",
    "DriversLicenseFirstName", "DriversLicenseMiddleName", "DriversLicenseLastName",
    "DriversLicenseDateOfBirth", "DriversLicenseLicenseNumber", "DriversLicenseIssuingCountry",
    "DriversLicenseIssuingState",
    "DriversLicenseIssueDate", "DriversLicenseExpirationDate", "DriversLicenseIssuingAuthority",
    "DriversLicenseLicenseClass",
    "PassportSurname", "PassportGivenName", "PassportDateOfBirth", "PassportSex",
    "PassportBirthPlace", "PassportNationality", "PassportIssuingCountry",
    "PassportPassportNumber", "PassportPassportType", "PassportNationalIdNumber",
    "PassportIssuingAuthority", "PassportIssueDate", "PassportExpirationDate",
)

private fun linkedTargetLabelKey(target: String): String = when (target) {
    "LoginUsername", "IdentityUsername" -> "edit.username"
    "LoginPassword" -> "edit.password"
    "CardCardholderName" -> "detail.f.cardholder"
    "CardNumber" -> "detail.f.number"
    "CardExpMonth" -> "detail.f.expMonth"
    "CardExpYear" -> "detail.f.expYear"
    "CardCvv" -> "detail.f.code"
    "IdentityTitle" -> "detail.f.title"
    "IdentityFirstName" -> "detail.f.firstName"
    "IdentityMiddleName" -> "detail.f.middleName"
    "IdentityLastName" -> "detail.f.lastName"
    "IdentityCompany" -> "detail.f.company"
    "IdentityEmail" -> "detail.f.email"
    "IdentityPhone" -> "detail.f.phone"
    "IdentityAddress1" -> "detail.f.address1"
    "IdentityAddress2" -> "detail.f.address2"
    "IdentityAddress3" -> "detail.f.address3"
    "IdentityCity" -> "detail.f.city"
    "IdentityState" -> "detail.f.state"
    "IdentityPostalCode" -> "detail.f.postalCode"
    "IdentityCountry" -> "detail.f.country"
    "BankAccountBankName" -> "detail.f.bankName"
    "BankAccountNameOnAccount" -> "detail.f.nameOnAccount"
    "BankAccountAccountType" -> "detail.f.accountType"
    "BankAccountAccountNumber" -> "detail.f.accountNumber"
    "BankAccountRoutingNumber" -> "detail.f.routingNumber"
    "BankAccountBranchNumber" -> "detail.f.branchNumber"
    "BankAccountPin" -> "detail.f.pin"
    "BankAccountSwiftCode" -> "detail.f.swiftCode"
    "BankAccountIban" -> "detail.f.iban"
    "BankAccountBankContactPhone" -> "detail.f.bankPhone"
    "DriversLicenseFirstName" -> "detail.f.firstName"
    "DriversLicenseMiddleName" -> "detail.f.middleName"
    "DriversLicenseLastName" -> "detail.f.lastName"
    "DriversLicenseDateOfBirth" -> "detail.f.dateOfBirth"
    "DriversLicenseLicenseNumber" -> "detail.f.licenseNumber"
    "DriversLicenseIssuingCountry" -> "detail.f.issuingCountry"
    "DriversLicenseIssuingState" -> "detail.f.issuingState"
    "DriversLicenseIssueDate" -> "detail.f.issueDate"
    "DriversLicenseExpirationDate" -> "detail.f.expirationDate"
    "DriversLicenseIssuingAuthority" -> "detail.f.issuingAuthority"
    "DriversLicenseLicenseClass" -> "detail.f.licenseClass"
    "PassportSurname" -> "detail.f.surname"
    "PassportGivenName" -> "detail.f.givenName"
    "PassportDateOfBirth" -> "detail.f.dateOfBirth"
    "PassportSex" -> "detail.f.sex"
    "PassportBirthPlace" -> "detail.f.birthPlace"
    "PassportNationality" -> "detail.f.nationality"
    "PassportIssuingCountry" -> "detail.f.issuingCountry"
    "PassportPassportNumber" -> "detail.f.passportNumber"
    "PassportPassportType" -> "detail.f.passportType"
    "PassportNationalIdNumber" -> "detail.f.nationalId"
    "PassportIssuingAuthority" -> "detail.f.issuingAuthority"
    "PassportIssueDate" -> "detail.f.issueDate"
    "PassportExpirationDate" -> "detail.f.expirationDate"
    else -> target
}

@Composable
private fun CheckboxRow(label: String, checked: Boolean, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
            color = MaterialTheme.colorScheme.onSurface,
        )
        Checkbox(
            checked = checked,
            onCheckedChange = onToggle,
            enabled = enabled,
            colors = CheckboxDefaults.colors(
                checkedColor = MaterialTheme.colorScheme.primary,
                checkmarkColor = MaterialTheme.colorScheme.onPrimary,
            ),
        )
    }
}

@Composable
private fun FolderPicker(
    selectedId: String?,
    folders: List<MobileFolderInfo>,
    enabled: Boolean,
    onSelect: (String?) -> Unit,
) {
    // Desktop flatFolderTree parity: DFS order, parents before children,
    // depth shown as non-breaking-space indentation.
    val withDepth = foldersWithDepth(folders)
    val options: List<Pair<String, String>> =
        listOf("" to "edit.noFolder") + withDepth.map { (folder, depth) ->
            folder.id to "\u00A0".repeat(depth * 2) + folder.name
        }
    DropdownField(
        label = t("edit.folder"),
        selected = selectedId.orEmpty(),
        options = options,
        enabled = enabled,
        onSelect = { onSelect(it.ifEmpty { null }) },
    )
}

/** Labeled dropdown over (value, i18n key) options. Empty value = "unset". */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownField(
    label: String,
    selected: String,
    options: List<Pair<String, String>>,
    enabled: Boolean,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = options.firstOrNull { it.first == selected }?.second?.let { t(it) } ?: selected
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { if (enabled) expanded = it }) {
        OutlinedTextField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            singleLine = true,
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
            options.forEach { (value, labelKey) ->
                DropdownMenuItem(
                    text = { Text(if (labelKey.contains(".")) t(labelKey) else labelKey) },
                    onClick = {
                        onSelect(value)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun PasswordWithGenerator(
    value: String,
    enabled: Boolean,
    genLen: Int,
    genUpper: Boolean,
    genNums: Boolean,
    genSyms: Boolean,
    showOptions: Boolean,
    onValueChange: (String) -> Unit,
    onLengthChange: (Int) -> Unit,
    onUpperChange: (Boolean) -> Unit,
    onNumsChange: (Boolean) -> Unit,
    onSymsChange: (Boolean) -> Unit,
    onToggleOptions: () -> Unit,
    onGenerate: () -> Unit,
) {
    Column {
        BaluardTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.testTag(E2eTags.EDIT_PASSWORD),
            label = t("edit.password"),
            isPassword = true,
            enabled = enabled,
        )
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onGenerate, enabled = enabled) {
                Text(t("edit.generatePassword"))
            }
            TextButton(onClick = onToggleOptions, enabled = enabled) {
                Text(t("edit.generatorOptions"))
            }
        }
        if (showOptions) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = t("edit.genLength", genLen.toString()),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Slider(
                    value = genLen.toFloat(),
                    onValueChange = { onLengthChange(it.toInt()) },
                    valueRange = 8f..64f,
                    enabled = enabled,
                )
                SwitchRow(t("edit.genUpper"), genUpper, enabled, onUpperChange)
                SwitchRow(t("edit.genNumbers"), genNums, enabled, onNumsChange)
                SwitchRow(t("edit.genSymbols"), genSyms, enabled, onSymsChange)
            }
        }
    }
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Switch(checked = checked, onCheckedChange = onToggle, enabled = enabled)
    }
}

@Composable
private fun CardNumberField(value: String, enabled: Boolean, onValueChange: (String) -> Unit) {
    Column {
        detectCardBrand(value)?.let { brand ->
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
            ) {
                Text(
                    text = brand,
                    style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                )
            }
            Spacer(Modifier.height(4.dp))
        }
        BaluardTextField(
            value = formatCardNumber(value),
            onValueChange = { raw -> onValueChange(raw.filter(Char::isDigit).take(19)) },
            label = t("detail.f.number"),
            enabled = enabled,
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TagsEditor(
    tags: List<String>,
    suggestions: List<String>,
    enabled: Boolean,
    onAdd: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var input by remember { mutableStateOf("") }
    // Desktop parity: existing tags minus chosen ones, prefix match, max 5.
    val suggestionsToShow = suggestions
        .filter { s -> input.isNotBlank() && s.contains(input.trim(), ignoreCase = true) }
        .filter { s -> tags.none { it.equals(s, ignoreCase = true) } }
        .take(5)
    Column {
        if (tags.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                tags.forEach { tag ->
                    InputChip(
                        selected = false,
                        onClick = { onRemove(tag) },
                        label = { Text(tag) },
                        trailingIcon = {
                            Icon(Icons.Default.Close, contentDescription = t("edit.removeTag"), Modifier.size(14.dp))
                        },
                        enabled = enabled,
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
        }
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = null,
            placeholder = { Text(t("edit.tagPlaceholder")) },
            enabled = enabled,
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = MaterialTheme.colorScheme.surface,
                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
            ),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = {
                if (input.isNotBlank()) { onAdd(input); input = "" }
            }),
            modifier = Modifier.fillMaxWidth(),
        )
        if (suggestionsToShow.isNotEmpty()) {
            Column {
                suggestionsToShow.forEach { s ->
                    DropdownMenuItem(
                        text = { Text(s) },
                        onClick = { onAdd(s); input = "" },
                    )
                }
            }
        }
        TextButton(
            onClick = {
                onAdd(input)
                input = ""
            },
            enabled = enabled && input.isNotBlank(),
        ) {
            Text(t("edit.addTag"))
        }
    }
}

@Composable
private fun CustomFieldEditor(
    field: CustomFieldEdit,
    enabled: Boolean,
    onName: (String) -> Unit,
    onValue: (String) -> Unit,
    onType: (String) -> Unit,
    onLinkedTarget: (String) -> Unit,
    onRemove: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            BaluardTextField(
                value = field.name,
                onValueChange = onName,
                label = t("edit.fieldName"),
                enabled = enabled,
                modifier = Modifier.weight(1f),
            )
            RemoveButton(t("edit.removeField"), enabled, onRemove)
        }
        DropdownField(
            label = t("edit.fieldType"),
            selected = field.fieldType,
            options = listOf(
                "Text" to "edit.fieldType.text",
                "Hidden" to "edit.fieldType.hidden",
                "Boolean" to "edit.fieldType.boolean",
                "Linked" to "edit.fieldType.linked",
            ),
            enabled = enabled,
            onSelect = onType,
        )
        when {
            field.isLinked -> DropdownField(
                label = t("edit.linkedTarget"),
                selected = field.linkedTarget.orEmpty(),
                options = LINKED_TARGETS.map { it to linkedTargetLabelKey(it) },
                enabled = enabled,
                onSelect = onLinkedTarget,
            )
            field.isBoolean -> Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = field.name.ifBlank { t("edit.fieldType.boolean") },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Switch(
                    checked = field.value == "true",
                    onCheckedChange = { onValue(if (it) "true" else "false") },
                    enabled = enabled,
                )
            }
            else -> BaluardTextField(
                value = field.value,
                onValueChange = onValue,
                label = t("edit.fieldValue"),
                isPassword = field.isHidden,
                enabled = enabled,
            )
        }
    }
}

@Composable
private fun AddButton(label: String, enabled: Boolean, onClick: () -> Unit) {
    TextButton(onClick = onClick, enabled = enabled) {
        Icon(Icons.Default.Add, contentDescription = null, Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(label)
    }
}

@Composable
private fun RemoveButton(label: String, enabled: Boolean, onClick: () -> Unit) {
    TextButton(onClick = onClick, enabled = enabled) {
        Icon(Icons.Default.Close, contentDescription = label, Modifier.size(16.dp))
    }
}
