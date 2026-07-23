package xyz.actitud.baluard.edit

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MobileVault

/**
 * Edit cipher screen (Phase 4). Login form is fully modeled (name, username,
 * password, notes, favorite); the other 7 cipher types reuse this shell with
 * type-specific field additions to follow. The save button builds the daemon-
 * wire JSON and calls addCipher/updateCipher.
 *
 * NOTE: the `kotlinx-serialization-json` dependency must be added to commonMain
 * in shared/build.gradle.kts for the JSON builder in EditCipherViewModel to
 * resolve (host-build fixup; this scaffold is blind-compiled).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditCipherScreen(
    vault: MobileVault,
    cipherId: String?, // null = new
    viewModel: EditCipherViewModel,
    onSaved: () -> Unit,
) {
    val form by viewModel.form.collectAsState()
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(cipherId) {
        if (cipherId != null) viewModel.load(vault, cipherId)
    }

    Scaffold(topBar = { TopAppBar(title = { Text(if (cipherId == null) "New entry" else "Edit entry") }) }) { padding ->
        Column(modifier = Modifier.fillMaxWidth().padding(padding).padding(16.dp)) {
            OutlinedTextField(
                value = form.name,
                onValueChange = viewModel::setName,
                label = { Text("Name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = form.username,
                onValueChange = viewModel::setUsername,
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = form.password,
                onValueChange = viewModel::setPassword,
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = form.notes,
                onValueChange = viewModel::setNotes,
                label = { Text("Notes") },
                modifier = Modifier.fillMaxWidth().height(96.dp),
            )
            Spacer(Modifier.height(8.dp))
            androidx.compose.foundation.layout.Row {
                Checkbox(checked = form.favorite, onCheckedChange = viewModel::setFavorite)
                Text("Favorite", modifier = Modifier.padding(top = 12.dp))
            }
            Spacer(Modifier.height(16.dp))
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
                enabled = form.name.isNotBlank() && !saving,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (saving) "Saving…" else "Save") }
            error?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = androidx.compose.material3.MaterialTheme.colorScheme.error)
            }
        }
    }
}
