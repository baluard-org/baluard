package xyz.actitud.baluard.platform

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/**
 * The Baluard brand lock glyph (gradients baked in), sized by [modifier].
 * Expect/actual: Android renders the official vector drawable; iOS falls
 * back to the generic lock until the brand assets land there too.
 */
@Composable
expect fun BaluardBrandLock(modifier: Modifier = Modifier)
