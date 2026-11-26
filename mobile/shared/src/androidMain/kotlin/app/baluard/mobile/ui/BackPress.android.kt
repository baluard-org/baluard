package app.baluard.mobile.ui

import androidx.activity.BackEventCompat
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import kotlin.coroutines.cancellation.CancellationException

/** Android `actual`: BackHandler over the activity's OnBackPressedDispatcher. */
@Composable
actual fun BackPressHandler(enabled: Boolean, onBack: () -> Unit) {
    BackHandler(enabled = enabled, onBack = onBack)
}

/** Android `actual`: predictive back over the activity's dispatcher. */
@Composable
actual fun PredictiveBackHandler(
    enabled: Boolean,
    onBack: () -> Unit,
    onProgress: ((PredictiveBackEvent) -> Unit)?,
    onCancelled: (() -> Unit)?,
) {
    // Qualified: our own expect function shares this package and name.
    androidx.activity.compose.PredictiveBackHandler(enabled = enabled) { events ->
        try {
            events.collect { event ->
                onProgress?.invoke(
                    PredictiveBackEvent(
                        progress = event.progress,
                        fromLeftEdge = event.swipeEdge == BackEventCompat.EDGE_LEFT,
                    ),
                )
            }
            // Flow finished without cancellation: gesture crossed the commit
            // threshold.
            onBack()
        } catch (_: CancellationException) {
            onCancelled?.invoke()
        }
    }
}
