package xyz.actitud.baluard.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.data.AuthState
import xyz.actitud.baluard.data.UnlockResult
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.Biometric

/**
 * Master-password unlock screen.
 *
 * On submit: opens the vault at [vaultPath] and runs the Argon2id KDF. The
 * spinner shows during [AuthState.Unlocking]. A biometric button appears only
 * when a biometric authenticator is available (the actual KEK-retrieval path
 * is wired when the platform `actual` impls land).
 *
 * Per plan §3.7, biometric quick-unlock MUST use the KEK path (never the
 * master-password KDF) — the memory-capped KDF would OOM an autofill/extension
 * process. The main app can run the full KDF, but biometric is the fast path.
 */
@Composable
fun UnlockScreen(
    vaultPath: String,
    authViewModel: AuthViewModel,
    onUnlocked: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var state by remember { mutableStateOf<AuthState>(AuthState.Init) }
    val scope = rememberCoroutineScope()
    val biometric = remember { Biometric() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Baluard", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(32.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(t("login.passwordPlaceholder")) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            enabled = state !is AuthState.Unlocking,
        )
        Spacer(Modifier.height(16.dp))

        Button(
            onClick = {
                state = AuthState.Unlocking
                scope.launch {
                    when (authViewModel.openAndUnlock(vaultPath, password)) {
                        is UnlockResult.Success -> {
                            state = AuthState.Unlocked
                            onUnlocked()
                        }
                        is UnlockResult.Failure -> {
                            state = AuthState.Error(t("login.wrongPassword"))
                        }
                    }
                }
            },
            enabled = password.isNotEmpty() && state !is AuthState.Unlocking,
        ) {
            Text(t("login.unlock"))
        }

        if (state is AuthState.Unlocking) {
            Spacer(Modifier.height(16.dp))
            CircularProgressIndicator()
        }

        if (biometric.isAvailable()) {
            Spacer(Modifier.height(24.dp))
            Button(onClick = {
                biometric.prompt(
                    title = t("login.biometricTitle"),
                    onSuccess = {
                        // TODO Phase 2 biometric: retrieve KEK from keychain,
                        // call repo.unlockWithKek (skips Argon2id KDF).
                        scope.launch {
                            // Placeholder: real path retrieves the wrapped KEK
                            // and calls the runtime's unlock_with_kek.
                        }
                    },
                    onError = { state = AuthState.Error(it) },
                )
            }) {
                Text(t("login.unlockBiometric"))
            }
        }

        (state as? AuthState.Error)?.let {
            Spacer(Modifier.height(16.dp))
            Text(
                it.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
