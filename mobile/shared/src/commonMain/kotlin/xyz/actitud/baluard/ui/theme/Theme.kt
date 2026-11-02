package xyz.actitud.baluard.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import baluard_mobile.shared.generated.resources.Res
import baluard_mobile.shared.generated.resources.morris_roman
import org.jetbrains.compose.resources.Font

// ── Baluard brand palette ────────────────────────────────────────────────────
// Source of truth: docs/brand/brand-guidelines.md + docs/brand/design-language-tokens.json
//
// Dark: Deep Forest Teal / Lime Accent / Soft Lavender
// Light: Clean White / Slate / Dark Teal

private val Lime          = Color(0xFFB3E55C)   // primary action
private val DeepTeal      = Color(0xFF102427)   // primary text on light / text on lime
private val ForestBg      = Color(0xFF091315)   // dark page background
private val SidebarSurf   = Color(0xFF0F2022)   // sidebar / M3 surface
private val ListPanel     = Color(0xFF14292C)   // list pane / surfaceVariant
private val DetailPanel   = Color(0xFF193236)   // detail pane / surfaceContainerHigh
private val CardBg        = Color(0xFF0B1517)   // cards / surfaceContainer
private val Border        = Color(0xFF1D3A3D)   // borders / outline
private val TextPrimary   = Color(0xFFF3F4F6)   // on-dark text
private val MutedDark     = Color(0xFFA2B7BA)   // secondary text dark
private val Lavender      = Color(0xFFCFC6F9)   // accent (secondary)
private val Danger        = Color(0xFFEF4444)   // errors / destructive
private val Success       = Color(0xFF10B981)   // success / tertiary
private val White         = Color(0xFFFFFFFF)

private val LightBg       = Color(0xFFF4F6F6)
private val LightSidebar  = Color(0xFFE9ECEC)
private val LightList     = Color(0xFFFFFFFF)
private val LightDetail   = Color(0xFFF8FAFC)
private val LightBorder   = Color(0xFFD1DBDB)
private val MutedLight    = Color(0xFF495C5F)
private val Violet        = Color(0xFF7C3AED)   // accent on light

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
    background             = ForestBg,
    onBackground           = TextPrimary,
    surface                = SidebarSurf,
    onSurface              = TextPrimary,
    surfaceVariant         = ListPanel,
    onSurfaceVariant       = MutedDark,
    surfaceContainer       = CardBg,
    surfaceContainerHigh   = DetailPanel,
    surfaceContainerHighest= ListPanel,
    outline                = Border,
    outlineVariant         = Border,
    error                  = Danger,
    onError                = White,
    errorContainer         = Color(0xFF7F1D1D),
    onErrorContainer       = Color(0xFFFCA5A5),
)

private val BaluardLight = lightColorScheme(
    primary                = DeepTeal,
    onPrimary              = White,
    primaryContainer       = LightSidebar,
    onPrimaryContainer     = DeepTeal,
    secondary              = Violet,
    onSecondary            = White,
    secondaryContainer     = LightBg,
    onSecondaryContainer   = Violet,
    tertiary               = Success,
    onTertiary             = White,
    tertiaryContainer      = Color(0xFFD1FAE5),
    onTertiaryContainer    = Color(0xFF065F46),
    background             = LightBg,
    onBackground           = DeepTeal,
    surface                = LightSidebar,
    onSurface              = DeepTeal,
    surfaceVariant         = LightList,
    onSurfaceVariant       = MutedLight,
    surfaceContainer       = LightList,
    surfaceContainerHigh   = LightDetail,
    surfaceContainerHighest= LightSidebar,
    outline                = LightBorder,
    outlineVariant         = LightBorder,
    error                  = Danger,
    onError                = White,
    errorContainer         = Color(0xFFFEE2E2),
    onErrorContainer       = Color(0xFF991B1B),
)

/**
 * Baluard brand theme.
 *
 * Colors: docs/brand/brand-guidelines.md (dark: Deep Forest Teal / Lime Accent;
 * light: Clean White / Slate / Dark Teal). Follows OS dark-mode by default.
 */
@Composable
fun BaluardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) BaluardDark else BaluardLight,
        content = content,
    )
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
