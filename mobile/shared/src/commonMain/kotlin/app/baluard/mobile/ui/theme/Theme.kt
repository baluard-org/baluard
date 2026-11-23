package app.baluard.mobile.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import baluard_mobile.shared.generated.resources.Res
import baluard_mobile.shared.generated.resources.morris_roman
import org.jetbrains.compose.resources.Font

// ── Baluard brand palette ────────────────────────────────────────────────────
// Synced with desktop/src/app.css. Desktop dark layout: page bg #091315,
// sidebar #0F2022, list column #14292C, detail #193236. Mobile maps the LIST
// column as its page bg and the sidebar tone as cards/inputs (Esteban's
// mapping: app bg #14292C, search input and cards #0F2022).
//   Light: Catppuccin Latte with Green Accent (#40a02b)

private val Lime          = Color(0xFFB3E55C)   // primary action (dark)
private val DeepTeal      = Color(0xFF102427)   // on-primary text (both modes)
private val SidebarSurf   = Color(0xFF0F2022)   // dark cards + inputs (desktop sidebar tone)
private val ListPanel     = Color(0xFF14292C)   // dark page background (desktop list column)
private val DetailPanel   = Color(0xFF193236)   // dark focused / strip / surfaceContainerHigh
private val Border        = Color(0xFF1D3A3D)   // dark borders / outline
private val ErrorDark     = Color(0xFFF87171)   // dark error text/icons (4.9-6.8:1 on all surfaces)
private val TextPrimary   = Color(0xFFF3F4F6)   // on-dark primary text
private val TextSecondary = Color(0xFFD3DDDE)   // on-dark secondary text
private val MutedDark     = Color(0xFFA2B7BA)   // on-dark muted text
private val Lavender      = Color(0xFFCFC6F9)   // dark accent (secondary)
private val WarningDark   = Color(0xFFFCD34D)   // dark warning
private val Success       = Color(0xFF10B981)   // dark success / tertiary
private val White         = Color(0xFFFFFFFF)

private val LatteBase     = Color(0xFFEFF1F5)   // light page background
private val LatteMantle   = Color(0xFFE6E9EF)   // light surface / cards
private val LatteCrust    = Color(0xFFDCE0E8)   // light inputs / surfaceVariant
private val LatteSurface0 = Color(0xFFCCD0DA)   // light focused / surfaceContainerHigh
private val LatteSurface1 = Color(0xFFBCC0CC)   // light borders / outline
private val LatteText     = Color(0xFF4C4F69)   // light primary text
private val LatteSubtext1 = Color(0xFF5C5F77)   // light secondary / muted (>=4.5:1 on Mantle)
private val LatteGreen    = Color(0xFF40A02B)   // light primary action
private val LatteGreenSoft= Color(0xFF66BF4F)   // light accent (secondary)
private val LatteYellow   = Color(0xFFDF8E1D)   // light warning
private val LatteYellowFg = Color(0xFF854D0E)   // light warning text
private val LatteRed      = Color(0xFFB70F2A)   // light error (5.1-5.5:1 on light surfaces)
private val LatteGreenDeep= Color(0xFF256015)   // light green as text/icons (4.9-6.7:1 on all surfaces)

@Immutable
data class BaluardSemanticColors(
    val isDark: Boolean,
    val warning: Color,
    val warningContainer: Color,
    val onWarning: Color,
    val success: Color,
    val textSecondary: Color,
    /** Primary as ink (text/icons): lime in dark, deep green in light (WCAG 1.4.3). */
    val textPrimary: Color,
    /** Primary as a fill (buttons/progress): lime in dark, Latte green in light. */
    val fillPrimary: Color,
    /** Ink on fillPrimary: deep teal in both modes. */
    val onFillPrimary: Color,
)

private val DarkSemanticColors = BaluardSemanticColors(
    isDark = true,
    warning = WarningDark,
    warningContainer = Color(0xFF78350F).copy(alpha = 0.25f),
    onWarning = WarningDark,
    success = Success,
    textSecondary = TextSecondary,
    textPrimary = Lime,
    fillPrimary = Lime,
    onFillPrimary = DeepTeal,
)

private val LightSemanticColors = BaluardSemanticColors(
    isDark = false,
    warning = LatteYellow,
    warningContainer = Color(0xFFFEF3C7),
    onWarning = LatteYellowFg,
    success = LatteGreen,
    textSecondary = LatteSubtext1,
    textPrimary = LatteGreenDeep,
    fillPrimary = LatteGreen,
    onFillPrimary = DeepTeal,
)

private val LocalBaluardColors = staticCompositionLocalOf { DarkSemanticColors }

object BaluardTheme {
    val colors: BaluardSemanticColors
        @Composable get() = LocalBaluardColors.current
}

private val BaluardDark = darkColorScheme(
    primary                = Lime,
    onPrimary              = DeepTeal,
    primaryContainer       = Border,
    onPrimaryContainer     = Lime,
    secondary              = Lavender,
    onSecondary            = DeepTeal,
    secondaryContainer     = ListPanel,
    onSecondaryContainer   = Lavender,
    tertiary               = Success,
    onTertiary             = DeepTeal,
    tertiaryContainer      = ListPanel,
    onTertiaryContainer    = Success,
    background             = ListPanel,
    onBackground           = TextPrimary,
    surface                = ListPanel,
    onSurface              = TextPrimary,
    surfaceVariant         = SidebarSurf,
    onSurfaceVariant       = MutedDark,
    surfaceContainer       = SidebarSurf,
    surfaceContainerHigh   = DetailPanel,
    surfaceContainerHighest= DetailPanel,
    outline                = Border,
    outlineVariant         = Border,
    error                  = ErrorDark,
    onError                = White,
    errorContainer         = Color(0xFF7F1D1D).copy(alpha = 0.35f),
    onErrorContainer       = Color(0xFFFCA5A5),
)

private val BaluardLight = lightColorScheme(
    primary                = LatteGreenDeep,
    onPrimary              = White,
    primaryContainer       = Color(0xFFD9EED3),
    onPrimaryContainer     = DeepTeal,
    secondary              = LatteGreenSoft,
    onSecondary            = DeepTeal,
    secondaryContainer     = LatteCrust,
    onSecondaryContainer   = LatteText,
    tertiary               = LatteGreen,
    onTertiary             = DeepTeal,
    tertiaryContainer      = Color(0xFFD9EED3),
    onTertiaryContainer    = Color(0xFF065F46),
    background             = LatteBase,
    onBackground           = LatteText,
    surface                = LatteMantle,
    onSurface              = LatteText,
    surfaceVariant         = LatteCrust,
    onSurfaceVariant       = LatteSubtext1,
    surfaceContainer       = LatteMantle,
    surfaceContainerHigh   = LatteSurface0,
    surfaceContainerHighest= LatteSurface0,
    outline                = LatteSurface1,
    outlineVariant         = LatteSurface1,
    error                  = LatteRed,
    onError                = White,
    errorContainer         = Color(0xFFFEE2E2),
    onErrorContainer       = Color(0xFF991B1B),
)

/**
 * Baluard brand theme.
 *
 * Colors: synced with desktop/src/app.css (dark: Deep Forest Teal / Lime Accent;
 * light: Catppuccin Latte with Green Accent). Follows OS dark-mode by default.
 */
@Composable
fun BaluardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val semantic = if (darkTheme) DarkSemanticColors else LightSemanticColors
    CompositionLocalProvider(LocalBaluardColors provides semantic) {
        MaterialTheme(
            colorScheme = if (darkTheme) BaluardDark else BaluardLight,
            content = content,
        )
    }
}

/**
 * Baluard brand typeface (Morris Roman Blackletter).
 * Used when mentioning "Baluard" alone in headings/brand headers.
 */
@Composable
fun brandFontFamily(): FontFamily {
    return FontFamily(
        Font(Res.font.morris_roman),
    )
}
