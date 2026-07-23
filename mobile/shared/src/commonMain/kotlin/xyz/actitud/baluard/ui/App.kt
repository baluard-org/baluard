package xyz.actitud.baluard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import xyz.actitud.baluard.data.VaultRepository

/**
 * Phase 1 hello-world screen.
 *
 * Proves the Rust → Kotlin round-trip: tapping the button calls
 * `VaultRepository.generateRecoveryPhrase()` → UniFFI →
 * `baluard_uniffi::generate_recovery_phrase()` → `baluard_core::recovery::RecoveryPhrase::generate()`
 * and renders the 24-word BIP-39 phrase. Once this renders on-device, the
 * toolchain is proven end-to-end and Phases 2+ can build on it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App() {
    val repo = remember { VaultRepository() }
    var phrase by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(topBar = { TopAppBar(title = { Text("Baluard") }) }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "Rust ↔ Kotlin bridge",
                style = MaterialTheme.typography.headlineSmall,
            )
            Spacer(Modifier.height(24.dp))
            Button(onClick = {
                runCatching { repo.generateRecoveryPhrase().phrase }
                    .onSuccess { phrase = it; error = null }
                    .onFailure { error = it.message ?: it.toString(); phrase = null }
            }) {
                Text("Generate recovery phrase")
            }
            Spacer(Modifier.height(24.dp))
            phrase?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            error?.let {
                Text(
                    "Error: $it",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
