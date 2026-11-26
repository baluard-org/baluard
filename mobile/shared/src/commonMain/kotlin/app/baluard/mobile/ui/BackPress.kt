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

/** One frame of an active predictive back gesture (Android 13+). */
data class PredictiveBackEvent(
    /** Gesture completion, 0f at touch-down through 1f at commit threshold. */
    val progress: Float,
    /** True when the gesture started at the screen's left edge. */
    val fromLeftEdge: Boolean,
)

/**
 * Predictive variant of [BackPressHandler]: [onProgress] streams gesture
 * frames so callers can animate the outgoing screen while the user swipes
 * (in-app preview of the destination). [onBack] fires only when the gesture
 * commits; [onCancelled] when the user releases before the threshold.
 * Platforms without the gesture degrade to plain back handling: progress
 * and cancellation never fire.
 */
@Composable
expect fun PredictiveBackHandler(
    enabled: Boolean = true,
    onBack: () -> Unit,
    onProgress: ((PredictiveBackEvent) -> Unit)? = null,
    onCancelled: (() -> Unit)? = null,
)
