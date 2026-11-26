package app.baluard.mobile.ui

import androidx.compose.runtime.Composable

/** iOS `actual`: no system back gesture to intercept. */
@Composable
actual fun BackPressHandler(enabled: Boolean, onBack: () -> Unit) {
    // No iOS equivalent wired yet.
}

/**
 * iOS `actual`: no system back gesture, so there is nothing predictive to
 * stream; the call is a no-op like [BackPressHandler].
 */
@Composable
actual fun PredictiveBackHandler(
    enabled: Boolean,
    onBack: () -> Unit,
    onProgress: ((PredictiveBackEvent) -> Unit)?,
    onCancelled: (() -> Unit)?,
) {
    // No iOS equivalent wired yet.
}
