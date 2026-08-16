package xyz.actitud.baluard.generator

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.PassphraseConfig
import xyz.actitud.baluard.PasswordConfig
import xyz.actitud.baluard.i18n.t

/**
 * Password + passphrase generator (Phase 4). Uses the Rust generator
 * (`baluard-core::generator`, single source of truth ported from desktop JS)
 * via `baluard-uniffi`. Output is crypto-strong (OsRng).
 *
 * Two tabs via [GeneratorMode]: password (length + char-class toggles) and
 * passphrase (word count + separator + capitalize/number/symbol transforms,
 * EFF-EN + BIP-39-ES wordlist).
 */
@Composable
fun GeneratorScreen(viewModel: GeneratorViewModel, onBack: () -> Unit = {}) {
    val state by viewModel.state.collectAsState()
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = t("common.back"))
            }
            Spacer(Modifier.width(8.dp))
            Checkbox(checked = state.mode == GeneratorMode.PASSWORD, onCheckedChange = {
                viewModel.setMode(GeneratorMode.PASSWORD)
            })
            Text(t("generator.password"))
            Spacer(Modifier.width(16.dp))
            Checkbox(checked = state.mode == GeneratorMode.PASSPHRASE, onCheckedChange = {
                viewModel.setMode(GeneratorMode.PASSPHRASE)
            })
            Text(t("generator.passphrase"))
        }

        Spacer(Modifier.height(16.dp))

        if (state.mode == GeneratorMode.PASSWORD) {
            PasswordControls(state, viewModel)
        } else {
            PassphraseControls(state, viewModel)
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { scope.launch { viewModel.generate() } },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(t("generator.generate")) }

        Spacer(Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = state.result ?: "—",
                modifier = Modifier.padding(16.dp),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.titleMedium,
            )
        }
    }
}

@Composable
private fun PasswordControls(state: GeneratorUiState, viewModel: GeneratorViewModel) {
    Text(t("generator.length", state.length))
    Slider(
        value = state.length.toFloat(),
        onValueChange = { viewModel.setLength(it.toInt()) },
        valueRange = 8f..64f,
        steps = 0,
    )
    ToggleRow(t("generator.upper"), state.upper) { viewModel.setUpper(it) }
    ToggleRow(t("generator.numbers"), state.numbers) { viewModel.setNumbers(it) }
    ToggleRow(t("generator.symbols"), state.symbols) { viewModel.setSymbols(it) }
}

@Composable
private fun PassphraseControls(state: GeneratorUiState, viewModel: GeneratorViewModel) {
    Text(t("generator.wordCount", state.wordCount))
    Slider(
        value = state.wordCount.toFloat(),
        onValueChange = { viewModel.setWordCount(it.toInt()) },
        valueRange = 3f..10f,
    )
    OutlinedTextField(
        value = state.separator,
        onValueChange = { viewModel.setSeparator(it) },
        label = { Text(t("generator.separator")) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    ToggleRow(t("generator.capitalize"), state.ppUpper) { viewModel.setPpUpper(it) }
    ToggleRow(t("generator.insertNumber"), state.ppNumber) { viewModel.setPpNumber(it) }
    ToggleRow(t("generator.insertSymbol"), state.ppSymbol) { viewModel.setPpSymbol(it) }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 4.dp).fillMaxWidth(),
    ) {
        Checkbox(checked = checked, onCheckedChange = onChecked)
        Spacer(Modifier.width(8.dp))
        Text(label)
    }
}
