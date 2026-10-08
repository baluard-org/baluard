package xyz.actitud.baluard.auth

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import xyz.actitud.baluard.data.AuthState
import xyz.actitud.baluard.data.UnlockResult
import xyz.actitud.baluard.i18n.t
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.LocalLifecycleOwner
import xyz.actitud.baluard.platform.Biometric
import xyz.actitud.baluard.platform.platformLogE
import xyz.actitud.baluard.ui.components.BaluardAmbientBackground
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardLogoBadge
import xyz.actitud.baluard.ui.components.BaluardOutlinedButton
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTextField
import xyz.actitud.baluard.ui.E2eTags
import androidx.compose.ui.platform.testTag

/** Local UI states layered over [AuthState]: enroll offer after unlock. */
private enum class UnlockPhase { Input, EnrollOffer, Enrolling }

/**
 * Master-password unlock screen styled after Baluard design guidelines.
 *
 * Quick unlock (B5): when a KEK is enrolled behind biometrics, the biometric
 * button opens the vault via `unlockWithKek` (no Argon2id). After a
 * master-password unlock on a device WITHOUT enrollment, the screen offers a
 * one-time enroll (runs the KDF once, explicitly, in the main app — plan §3.7).
 */
@Composable
fun UnlockScreen(
    vaultPath: String,
    authViewModel: AuthViewModel,
    onUnlocked: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var state by remember { mutableStateOf<AuthState>(AuthState.Init) }
    var phase by remember { mutableStateOf(UnlockPhase.Input) }
    var showJoin by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val biometric = remember { Biometric() }
    var biometricEnrolled by remember(vaultPath) { mutableStateOf(biometric.isEnrolled(vaultPath)) }

    fun finishUnlock() = onUnlocked()

    // Auto-prompt (Bitwarden-style): as soon as the app opens on a locked
    // vault with biometrics enrolled, raise the platform prompt. Runs once
    // per lock-session: dismissing it must not loop. Two triggers are
    // needed because composition can land before (cold start) or after
    // (soft-lock while already resumed) ON_RESUME; the guard dedupes.
    var autoPrompted by remember(vaultPath) { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current

    fun launchBiometricUnlock() {
        biometric.unlock(
            vaultKey = vaultPath,
            title = t("login.biometricTitle"),
            onSuccess = { kek ->
                state = AuthState.Unlocking
                scope.launch {
                    when (authViewModel.openAndUnlockWithKek(vaultPath, kek)) {
                        is UnlockResult.Success -> {
                            state = AuthState.Unlocked
                            finishUnlock()
                        }
                        is UnlockResult.DeviceMismatch -> {
                            state = AuthState.Error(t("login.deviceMismatch"))
                        }
                        is UnlockResult.Failure -> {
                            // Stale KEK (password changed elsewhere) fails closed.
                            state = AuthState.Error(t("login.biometricStale"))
                        }
                    }
                }
            },
            onError = { code, message ->
                // User-dismissed prompts (5 = cancel, 10 = negative button)
                // fall back to the password form silently; real failures show.
                if (code != 5 && code != 10) {
                    state = AuthState.Error(message)
                }
            },
        )
    }

    fun maybeAutoPrompt() {
        if (autoPrompted) return
        if (!biometricEnrolled || !biometric.isAvailable()) return
        if (!lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        autoPrompted = true
        launchBiometricUnlock()
    }

    LaunchedEffect(vaultPath, biometricEnrolled) { maybeAutoPrompt() }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { maybeAutoPrompt() }

    BaluardAmbientBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            BaluardLogoBadge(
                size = 72.dp,
                showTitle = true,
                subtitle = t("onboarding.subtitle"),
            )

            Spacer(Modifier.height(32.dp))

            BaluardCard(
                modifier = Modifier.fillMaxWidth(),
            ) {
                BaluardTextField(
                    value = password,
                    modifier = Modifier.testTag(E2eTags.UNLOCK_PASSWORD),
                    onValueChange = {
                        password = it
                        if (state is AuthState.Error) state = AuthState.Init
                    },
                    label = t("login.passwordPlaceholder"),
                    placeholder = t("login.passwordPlaceholder"),
                    leadingIcon = Icons.Default.Lock,
                    isPassword = true,
                    enabled = state !is AuthState.Unlocking,
                    isError = state is AuthState.Error,
                    supportingText = (state as? AuthState.Error)?.message,
                )

                Spacer(Modifier.height(16.dp))

                BaluardPrimaryButton(
                    modifier = Modifier.testTag(E2eTags.UNLOCK_SUBMIT),
                    text = t("login.unlock"),
                    onClick = {
                        state = AuthState.Unlocking
                        scope.launch {
                            when (authViewModel.openAndUnlock(vaultPath, password)) {
                                is UnlockResult.Success -> {
                                    state = AuthState.Unlocked
                                    // Offer quick-unlock enrollment once, right
                                    // after the user proved the master password.
                                    // E2E builds skip the enrollment
                                    // offer: no human to answer it, and
                                    // the flows assert straight through
                                    // to the list screen.
                                    if (!xyz.actitud.baluard.platform.e2eBuild &&
                                        biometric.isAvailable() &&
                                        !biometricEnrolled
                                    ) {
                                        phase = UnlockPhase.EnrollOffer
                                    } else {
                                        finishUnlock()
                                    }
                                }
                                is UnlockResult.DeviceMismatch -> {
                                    state = AuthState.Error(t("login.deviceMismatch"))
                                }
                                is UnlockResult.Failure -> {
                                    state = AuthState.Error(t("login.wrongPassword"))
                                }
                            }
                        }
                    },
                    enabled = password.isNotEmpty(),
                    loading = state is AuthState.Unlocking,
                    leadingIcon = Icons.Default.Lock,
                )

                if (biometric.isAvailable() && biometricEnrolled) {
                    Spacer(Modifier.height(12.dp))
                    BaluardOutlinedButton(
                        text = t("login.unlockBiometric"),
                        onClick = { launchBiometricUnlock() },
                        enabled = state !is AuthState.Unlocking,
                        leadingIcon = Icons.Default.Fingerprint,
                    )
                }

                // Member-side join (§4.8-6): a cloned vault awaiting approval
                // cannot unlock yet — this is the only way in.
                Spacer(Modifier.height(12.dp))
                androidx.compose.material3.TextButton(onClick = { showJoin = true }) {
                    Text(t("join.entry"))
                }
            }

            if (showJoin) {
                JoinSpaceDialog(
                    vaultPath = vaultPath,
                    authViewModel = authViewModel,
                    onApproved = {
                        showJoin = false
                        finishUnlock()
                    },
                    onDismiss = { showJoin = false },
                )
            }

            // One-time quick-unlock enrollment offer (B5). The KDF runs once
            // here, in the main app, as an explicit user action.
            AnimatedVisibility(visible = phase != UnlockPhase.Input) {
                Column {
                    Spacer(Modifier.height(16.dp))
                    BaluardCard(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = t("login.enableBiometricTitle"),
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                            ),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = t("login.enableBiometricBody"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(14.dp))
                        BaluardPrimaryButton(
                            text = t("login.enableBiometric"),
                            loading = phase == UnlockPhase.Enrolling,
                            leadingIcon = Icons.Default.Fingerprint,
                            onClick = {
                                phase = UnlockPhase.Enrolling
                                scope.launch {
                                    val kek = runCatching {
                                        authViewModel.deriveKek(vaultPath, password)
                                    }.onFailure {
                                        platformLogE("UnlockScreen", "deriveKek failed for vault: $vaultPath", it)
                                    }.getOrNull()
                                    if (kek == null) {
                                        platformLogE("UnlockScreen", "enroll: KEK derivation returned null, aborting enroll")
                                        phase = UnlockPhase.Input
                                        finishUnlock()
                                        return@launch
                                    }
                                    biometric.enroll(
                                        vaultKey = vaultPath,
                                        kek = kek,
                                        title = t("login.biometricTitle"),
                                        onSuccess = {
                                            biometricEnrolled = true
                                            phase = UnlockPhase.Input
                                            finishUnlock()
                                        },
                                        onError = { code, err ->
                                            platformLogE("UnlockScreen", "biometric enroll failed: code=$code $err")
                                            // Enrollment failed: quick unlock
                                            // stays off; the vault IS unlocked.
                                            phase = UnlockPhase.Input
                                            finishUnlock()
                                        },
                                    )
                                }
                            },
                        )
                        Spacer(Modifier.height(8.dp))
                        BaluardOutlinedButton(
                            text = t("login.notNow"),
                            onClick = { phase = UnlockPhase.Input; finishUnlock() },
                        )
                    }
                }
            }
        }
    }
}
