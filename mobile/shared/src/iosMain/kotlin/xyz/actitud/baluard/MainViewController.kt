package xyz.actitud.baluard

import androidx.compose.ui.uikit.OnTopPlacementStrategy
import androidx.compose.ui.window.ComposeUIViewController

/**
 * iOS entry point. Kotlin/Native builds this into the BaluardShared.framework
 * consumed by the Xcode target. The Swift app calls `MainViewControllerKt()
 * .createViewController()` from `ContentView.swift` to host the Compose UI.
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
    xyz.actitud.baluard.ui.App()
}
