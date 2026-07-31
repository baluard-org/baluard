package xyz.actitud.baluard.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import xyz.actitud.baluard.auth.AuthViewModel
import xyz.actitud.baluard.auth.UnlockScreen
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.ui.theme.BaluardTheme
import xyz.actitud.baluard.vault.VaultListScreen
import xyz.actitud.baluard.vault.VaultListViewModel

/**
 * Root navigation. Phase 2-3 skeleton: unlock screen -> vault list.
 *
 * [vaultPath] is the on-disk vault directory. For the hello-world scaffold
 * this is a fixed path (set by the host build / intent); the vault-creation
 * wizard (init -> creating -> recovery -> setup states, plan "Auth State
 * Machine") lands with the full onboarding flow.
 */
@Composable
fun App(vaultPath: String = "") {
    BaluardTheme {
        val repo = remember { VaultRepository() }
        val auth = remember { AuthViewModel(repo) }
        val listVm = remember { VaultListViewModel(repo) }
        var unlocked by remember { mutableStateOf(false) }

        if (!unlocked) {
            UnlockScreen(
                vaultPath = vaultPath,
                authViewModel = auth,
                onUnlocked = {
                    auth.vault()?.let { v ->
                        unlocked = true
                        listVm
                    }
                },
            )
        } else {
            auth.vault()?.let { vault ->
                VaultListScreen(
                    vault = vault,
                    listViewModel = listVm,
                    authViewModel = auth,
                    onLocked = { unlocked = false },
                )
            }
        }
    }
}
