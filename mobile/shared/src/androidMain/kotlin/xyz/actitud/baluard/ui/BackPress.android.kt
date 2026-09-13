package xyz.actitud.baluard.ui

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable

/** Android `actual`: BackHandler over the activity's OnBackPressedDispatcher. */
@Composable
actual fun BackPressHandler(enabled: Boolean, onBack: () -> Unit) {
    BackHandler(enabled = enabled, onBack = onBack)
}
