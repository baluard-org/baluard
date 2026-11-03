package app.baluard.mobile

import androidx.compose.ui.uikit.OnTopPlacementStrategy
import androidx.compose.ui.window.ComposeUIViewController

/**
 * iOS entry point. Kotlin/Native builds this into the BaluardShared.framework
 * consumed by the Xcode target. The Swift host calls the top-level
 * `MainViewController()` function (Kotlin objects it as
 * `MainViewControllerKt.MainViewController()`); the iosApp host project is
 * not in this repository.
 *
 * Compose-on-iOS is fine for the MAIN app (this). The credential-provider
 * EXTENSION (Phase 7) must use native UIKit instead — extensions have strict
 * memory limits and Compose is too heavy there (plan §3.7).
 */
fun MainViewController() = ComposeUIViewController(
    configure = {
        onTopPlacementStrategy = OnTopPlacementStrategy.None
    },
) {
    // Keep the vault root out of iCloud/iTunes backups before any vault
    // touch (the ciphertext must stay device-local).
    app.baluard.mobile.platform.AppPaths.excludeVaultRootFromBackup()
    app.baluard.mobile.ui.App()
}
