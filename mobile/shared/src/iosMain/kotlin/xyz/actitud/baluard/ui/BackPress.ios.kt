package xyz.actitud.baluard.ui

import androidx.compose.runtime.Composable

/** iOS `actual`: no system back gesture to intercept. */
@Composable
actual fun BackPressHandler(enabled: Boolean, onBack: () -> Unit) {
    // No iOS equivalent wired yet.
}
