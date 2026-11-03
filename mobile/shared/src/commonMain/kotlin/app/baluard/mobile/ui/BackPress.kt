package app.baluard.mobile.ui

import androidx.compose.runtime.Composable

/**
 * Intercept the system back gesture/button while [enabled].
 *
 * No-op on platforms without a back concept (iOS swipes are per-app
 * navigation, handled in-screen).
 */
@Composable
expect fun BackPressHandler(enabled: Boolean = true, onBack: () -> Unit)
