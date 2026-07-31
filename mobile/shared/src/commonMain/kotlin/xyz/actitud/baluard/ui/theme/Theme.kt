package xyz.actitud.baluard.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

/**
 * App theme. Follows the OS dark-mode setting via Material 3 color schemes.
 *
 * Brand palette from docs/brand-guidelines.md lands in Phase 8 polish; until
 * then the M3 defaults are the correct baseline (no hardcoded light scheme).
 */
@Composable
fun BaluardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) darkColorScheme() else lightColorScheme(),
        content = content,
    )
}
