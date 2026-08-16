package xyz.actitud.baluard.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.auth.UnlockScreen
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.onboarding.CreateVaultScreen
import xyz.actitud.baluard.onboarding.OnboardingScreen
import xyz.actitud.baluard.platform.AppPaths
import xyz.actitud.baluard.ui.theme.BaluardTheme
import xyz.actitud.baluard.vault.VaultListScreen
import xyz.actitud.baluard.vault.VaultListViewModel

/**
 * Root navigation (plan §5): no vault at the default path -> OnboardingScreen;
 * vault exists -> UnlockScreen; unlocked -> VaultListScreen. The create flow
 * replaces the onboarding root until its recovery-phrase ack completes, then
 * lands directly in the vault list (the FFI returns the vault unlocked).
 *
 * [vaultPath] overrides the platform default (host intent / debug builds).
 */
@Composable
fun App(vaultPath: String? = null) {
    BaluardTheme {
        val path = remember(vaultPath) {
            vaultPath?.takeIf { it.isNotBlank() } ?: AppPaths.defaultVaultPath()
        }
        var hasVault by remember { mutableStateOf(AppPaths.vaultExists(path)) }
        var showCreate by remember { mutableStateOf(false) }
        var unlocked by remember { mutableStateOf(false) }

        val repo = remember { VaultRepository() }
        val auth = remember { AuthViewModel(repo) }
        val listVm = remember { VaultListViewModel(repo) }

        when {
            unlocked -> auth.vault()?.let { vault ->
                VaultListScreen(
                    vault = vault,
                    listViewModel = listVm,
                    authViewModel = auth,
                    onLocked = { unlocked = false },
                )
            }

            showCreate -> CreateVaultScreen(
                vaultPath = path,
                authViewModel = auth,
                onCreated = {
                    hasVault = true
                    showCreate = false
                    unlocked = true
                },
                onCancelled = { showCreate = false },
            )

            !hasVault -> OnboardingScreen(
                onCreateVault = { showCreate = true },
            )

            else -> UnlockScreen(
                vaultPath = path,
                authViewModel = auth,
                onUnlocked = { unlocked = true },
            )
        }
    }
}
