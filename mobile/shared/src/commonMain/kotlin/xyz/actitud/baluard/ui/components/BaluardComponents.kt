package xyz.actitud.baluard.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DirectionsCar
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FlightTakeoff
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.copyToClipboard

/**
 * Ambient background container reproducing desktop glow gradients.
 */
@Composable
fun BaluardAmbientBackground(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        // Top-left lime ambient glow
        Box(
            modifier = Modifier
                .size(240.dp)
                .offset(x = (-60).dp, y = (-60).dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                            Color.Transparent,
                        ),
                    ),
                ),
        )

        // Bottom-right lavender accent glow
        Box(
            modifier = Modifier
                .size(260.dp)
                .align(Alignment.BottomEnd)
                .offset(x = 80.dp, y = 80.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            MaterialTheme.colorScheme.secondary.copy(alpha = 0.10f),
                            Color.Transparent,
                        ),
                    ),
                ),
        )

        content()
    }
}

/**
 * Polished Baluard lock emblem badge rendering the authentic fortress lock and B.
 */
@Composable
fun BaluardLogoBadge(
    modifier: Modifier = Modifier,
    size: Dp = 64.dp,
    showTitle: Boolean = true,
    subtitle: String? = null,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Canvas(
            modifier = Modifier.size(size),
        ) {
            val w = this.size.width
            val h = this.size.height
            val scale = w / 512f

            // 1. Shackle: lavender gradient arc
            val shacklePath = Path().apply {
                moveTo(172f * scale, 205f * scale)
                lineTo(172f * scale, 150f * scale)
                cubicTo(172f * scale, 103f * scale, 209f * scale, 66f * scale, 256f * scale, 66f * scale)
                cubicTo(303f * scale, 66f * scale, 340f * scale, 103f * scale, 340f * scale, 150f * scale)
                lineTo(340f * scale, 205f * scale)
                lineTo(294f * scale, 205f * scale)
                lineTo(294f * scale, 150f * scale)
                cubicTo(294f * scale, 128f * scale, 277f * scale, 111f * scale, 256f * scale, 111f * scale)
                cubicTo(235f * scale, 111f * scale, 218f * scale, 128f * scale, 218f * scale, 150f * scale)
                lineTo(218f * scale, 205f * scale)
                close()
            }
            drawPath(
                path = shacklePath,
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFFDED8FC), Color(0xFFCFC6F9)),
                    start = Offset.Zero,
                    end = Offset(w, h),
                ),
            )

            // 2. Lock Body with Fortress Crenellations: vibrant lime gradient
            val bodyPath = Path().apply {
                moveTo(136f * scale, 205f * scale)
                lineTo(184f * scale, 205f * scale)
                lineTo(184f * scale, 228f * scale)
                lineTo(228f * scale, 228f * scale)
                lineTo(228f * scale, 205f * scale)
                lineTo(284f * scale, 205f * scale)
                lineTo(284f * scale, 228f * scale)
                lineTo(328f * scale, 228f * scale)
                lineTo(328f * scale, 205f * scale)
                lineTo(376f * scale, 205f * scale)
                cubicTo(384f * scale, 205f * scale, 388f * scale, 209f * scale, 388f * scale, 217f * scale)
                lineTo(388f * scale, 405f * scale)
                cubicTo(388f * scale, 424f * scale, 374f * scale, 438f * scale, 355f * scale, 438f * scale)
                lineTo(157f * scale, 438f * scale)
                cubicTo(138f * scale, 438f * scale, 124f * scale, 424f * scale, 124f * scale, 405f * scale)
                lineTo(124f * scale, 217f * scale)
                cubicTo(124f * scale, 209f * scale, 128f * scale, 205f * scale, 136f * scale, 205f * scale)
                close()
            }
            drawPath(
                path = bodyPath,
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFFC5F279), Color(0xFFB3E55C), Color(0xFF9DCE47)),
                    start = Offset(w * 0.2f, 0f),
                    end = Offset(w * 0.8f, h),
                ),
            )

            // 3. Exact Authentic Morris Roman Blackletter B: dark contrast cutout
            val bPath = Path().apply {
                moveTo(317.84f * scale, 361.56f * scale)
                quadraticTo(317.84f * scale, 347.19f * scale, 304.99f * scale, 337.61f * scale)
                lineTo(281.69f * scale, 320.41f * scale)
                lineTo(295.63f * scale, 309.53f * scale)
                quadraticTo(303.03f * scale, 303.65f * scale, 303.03f * scale, 294.50f * scale)
                quadraticTo(303.03f * scale, 280.57f * scale, 288.88f * scale, 272.08f * scale)
                quadraticTo(276.68f * scale, 264.89f * scale, 262.10f * scale, 264.89f * scale)
                quadraticTo(248.60f * scale, 264.89f * scale, 226.82f * scale, 273.38f * scale)
                quadraticTo(211.80f * scale, 279.04f * scale, 203.09f * scale, 282.31f * scale)
                quadraticTo(194.38f * scale, 285.58f * scale, 191.99f * scale, 286.01f * scale)
                lineTo(191.99f * scale, 291.02f * scale)
                quadraticTo(205.05f * scale, 296.90f * scale, 205.05f * scale, 315.62f * scale)
                lineTo(205.05f * scale, 377.46f * scale)
                quadraticTo(205.05f * scale, 383.99f * scale, 199.17f * scale, 394.00f * scale)
                lineTo(193.51f * scale, 403.80f * scale)
                lineTo(193.51f * scale, 408.37f * scale)
                quadraticTo(202.00f * scale, 404.67f * scale, 204.18f * scale, 404.02f * scale)
                quadraticTo(208.10f * scale, 402.28f * scale, 216.37f * scale, 402.28f * scale)
                quadraticTo(223.12f * scale, 402.28f * scale, 237.71f * scale, 405.33f * scale)
                quadraticTo(252.30f * scale, 408.37f * scale, 259.05f * scale, 408.37f * scale)
                quadraticTo(276.25f * scale, 408.37f * scale, 296.28f * scale, 393.79f * scale)
                quadraticTo(317.84f * scale, 377.89f * scale, 317.84f * scale, 361.56f * scale)
                close()

                moveTo(278.64f * scale, 294.50f * scale)
                quadraticTo(278.64f * scale, 302.99f * scale, 269.72f * scale, 311.92f * scale)
                quadraticTo(264.71f * scale, 316.93f * scale, 250.34f * scale, 325.20f * scale)
                quadraticTo(244.68f * scale, 328.47f * scale, 240.32f * scale, 331.41f * scale)
                quadraticTo(235.97f * scale, 334.35f * scale, 232.92f * scale, 336.74f * scale)
                lineTo(231.61f * scale, 336.31f * scale)
                lineTo(229.44f * scale, 336.74f * scale)
                lineTo(229.00f * scale, 319.54f * scale)
                lineTo(228.78f * scale, 302.12f * scale)
                quadraticTo(228.35f * scale, 290.58f * scale, 238.15f * scale, 282.31f * scale)
                quadraticTo(247.51f * scale, 274.69f * scale, 259.05f * scale, 274.69f * scale)
                quadraticTo(262.97f * scale, 274.69f * scale, 266.56f * scale, 276.32f * scale)
                quadraticTo(270.15f * scale, 277.95f * scale, 272.77f * scale, 280.68f * scale)
                quadraticTo(275.38f * scale, 283.40f * scale, 277.01f * scale, 286.99f * scale)
                quadraticTo(278.64f * scale, 290.58f * scale, 278.64f * scale, 294.50f * scale)
                close()

                moveTo(288.44f * scale, 372.88f * scale)
                quadraticTo(288.44f * scale, 382.47f * scale, 279.30f * scale, 389.87f * scale)
                quadraticTo(269.93f * scale, 397.49f * scale, 260.57f * scale, 397.49f * scale)
                quadraticTo(244.24f * scale, 397.49f * scale, 236.19f * scale, 383.55f * scale)
                quadraticTo(229.44f * scale, 372.23f * scale, 229.44f * scale, 354.81f * scale)
                quadraticTo(229.44f * scale, 351.77f * scale, 240.54f * scale, 344.14f * scale)
                quadraticTo(251.86f * scale, 336.74f * scale, 255.78f * scale, 336.74f * scale)
                quadraticTo(262.75f * scale, 336.74f * scale, 275.60f * scale, 351.11f * scale)
                quadraticTo(288.44f * scale, 365.70f * scale, 288.44f * scale, 372.88f * scale)
                close()
            }
            drawPath(
                path = bPath,
                color = Color(0xFF091315),
            )
        }

        if (showTitle) {
            Spacer(Modifier.height(14.dp))
            Text(
                text = "Baluard",
                style = MaterialTheme.typography.headlineLarge.copy(
                    fontFamily = xyz.actitud.baluard.ui.theme.brandFontFamily(),
                    letterSpacing = 0.5.sp,
                ),
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        if (subtitle != null) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Standard elevated card container matching desktop surface tokens.
 */
@Composable
fun BaluardCard(
    modifier: Modifier = Modifier,
    shape: RoundedCornerShape = RoundedCornerShape(16.dp),
    backgroundColor: Color = MaterialTheme.colorScheme.surfaceContainer,
    borderColor: Color = MaterialTheme.colorScheme.outlineVariant,
    animateSize: Boolean = true,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .border(width = 1.dp, color = borderColor, shape = shape),
        shape = shape,
        color = backgroundColor,
    ) {
        Column(
            modifier = Modifier
                .then(
                    if (animateSize) {
                        Modifier.animateContentSize(
                            animationSpec = tween(220, easing = FastOutSlowInEasing)
                        )
                    } else {
                        Modifier
                    }
                )
                .padding(contentPadding),
            content = content,
        )
    }
}

/**
 * Primary action button with Baluard Lime theme styling.
 */
@Composable
fun BaluardPrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    leadingIcon: ImageVector? = null,
) {
    Button(
        onClick = onClick,
        enabled = enabled && !loading,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
            disabledContainerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.35f),
            disabledContentColor = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.5f),
        ),
        modifier = modifier
            .fillMaxWidth()
            .height(50.dp),
    ) {
        if (loading) {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
            )
        } else {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                if (leadingIcon != null) {
                    Icon(
                        imageVector = leadingIcon,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(
                    text = text,
                    style = MaterialTheme.typography.labelLarge.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                    ),
                )
            }
        }
    }
}

/**
 * Secondary outlined button with brand borders and hover/active states.
 */
@Composable
fun BaluardOutlinedButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    leadingIcon: ImageVector? = null,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = ButtonDefaults.outlinedButtonBorder(enabled).copy(
            brush = Brush.linearGradient(
                colors = listOf(
                    MaterialTheme.colorScheme.outline,
                    MaterialTheme.colorScheme.outlineVariant,
                ),
            ),
        ),
        modifier = modifier
            .fillMaxWidth()
            .height(48.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            if (leadingIcon != null) {
                Icon(
                    imageVector = leadingIcon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(8.dp))
            }
            Text(
                text = text,
                style = MaterialTheme.typography.labelLarge.copy(
                    fontWeight = FontWeight.SemiBold,
                ),
            )
        }
    }
}

/**
 * Styled text input with brand outlines and background.
 */
@Composable
fun BaluardTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String?,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    leadingIcon: ImageVector? = null,
    isPassword: Boolean = false,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    minLines: Int = 1,
    isError: Boolean = false,
    supportingText: String? = null,
) {
    var passwordVisible by remember { mutableStateOf(!isPassword) }

    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = label?.let { { Text(it) } },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = singleLine,
        minLines = minLines,
        enabled = enabled,
        isError = isError,
        shape = RoundedCornerShape(12.dp),
        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
        leadingIcon = leadingIcon?.let {
            {
                Icon(
                    imageVector = it,
                    contentDescription = null,
                    tint = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
            }
        },
        trailingIcon = if (isPassword) {
            {
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(
                        imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (passwordVisible) t("detail.hide") else t("detail.reveal"),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            null
        },
        supportingText = supportingText?.let {
            {
                Text(
                    text = it,
                    color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceContainer.copy(alpha = 0.5f),
            focusedBorderColor = MaterialTheme.colorScheme.primary,
            unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
            errorBorderColor = MaterialTheme.colorScheme.error,
        ),
        modifier = modifier.fillMaxWidth(),
    )
}

/**
 * Avatar badge for a cipher item matching desktop category styling.
 */
@Composable
fun CipherAvatar(
    name: String,
    typeTag: String = "login",
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    val (icon, gradientBrush) = cipherTypeVisuals(typeTag)

    val initials = name.trim().take(2).uppercase().ifEmpty { "?" }

    Box(
        modifier = modifier
            .size(size)
            .clip(RoundedCornerShape(12.dp))
            .background(gradientBrush)
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                shape = RoundedCornerShape(12.dp),
            ),
        contentAlignment = Alignment.Center,
    ) {
        if (typeTag == "login" || typeTag == "identity") {
            Text(
                text = initials,
                style = MaterialTheme.typography.titleSmall.copy(
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = (size.value * 0.38f).sp,
                ),
                color = Color.White,
            )
        } else {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(size * 0.52f),
            )
        }
    }
}

/** Cached gradient brushes: one allocation per type, not per composition. */
private val typeBrushes = mapOf(
    "login" to Brush.linearGradient(listOf(Color(0xFF0D9488), Color(0xFF0F766E))),
    "card" to Brush.linearGradient(listOf(Color(0xFF2563EB), Color(0xFF1D4ED8))),
    "identity" to Brush.linearGradient(listOf(Color(0xFF7C3AED), Color(0xFF6D28D9))),
    "securenote" to Brush.linearGradient(listOf(Color(0xFFD97706), Color(0xFFB45309))),
    "sshkey" to Brush.linearGradient(listOf(Color(0xFF059669), Color(0xFF047857))),
    "passkeys" to Brush.linearGradient(listOf(Color(0xFF8B5CF6), Color(0xFF7C3AED))),
    "bankaccount" to Brush.linearGradient(listOf(Color(0xFF0284C7), Color(0xFF0369A1))),
    "driverslicense" to Brush.linearGradient(listOf(Color(0xFF4F46E5), Color(0xFF4338CA))),
    "passport" to Brush.linearGradient(listOf(Color(0xFFE11D48), Color(0xFFBE123C))),
)

private val defaultBrush = Brush.linearGradient(listOf(Color(0xFF475569), Color(0xFF334155)))

/** Accent colors for the category badge pill (first color = accent). */
private val typeAccentColors = mapOf(
    "login" to listOf(Color(0xFF0D9488), Color(0xFF0F766E)),
    "card" to listOf(Color(0xFF2563EB), Color(0xFF1D4ED8)),
    "identity" to listOf(Color(0xFF7C3AED), Color(0xFF6D28D9)),
    "securenote" to listOf(Color(0xFFD97706), Color(0xFFB45309)),
    "sshkey" to listOf(Color(0xFF059669), Color(0xFF047857)),
    "passkeys" to listOf(Color(0xFF8B5CF6), Color(0xFF7C3AED)),
    "bankaccount" to listOf(Color(0xFF0284C7), Color(0xFF0369A1)),
    "driverslicense" to listOf(Color(0xFF4F46E5), Color(0xFF4338CA)),
    "passport" to listOf(Color(0xFFE11D48), Color(0xFFBE123C)),
)

private val defaultAccentColors = listOf(Color(0xFF475569), Color(0xFF334155))

/** Returns visual icon and cached gradient brush for cipher types. */
private fun cipherTypeVisuals(typeTag: String): Pair<ImageVector, Brush> {
    return when (typeTag.lowercase()) {
        "login" -> Pair(Icons.Default.Lock, typeBrushes.getValue("login"))
        "card" -> Pair(Icons.Default.CreditCard, typeBrushes.getValue("card"))
        "identity" -> Pair(Icons.Default.Person, typeBrushes.getValue("identity"))
        "securenote", "note" -> Pair(Icons.Default.Description, typeBrushes.getValue("securenote"))
        "sshkey" -> Pair(Icons.Default.Key, typeBrushes.getValue("sshkey"))
        "passkeys", "passkey" -> Pair(Icons.Default.Fingerprint, typeBrushes.getValue("passkeys"))
        "bankaccount" -> Pair(Icons.Default.AccountBalance, typeBrushes.getValue("bankaccount"))
        "driverslicense" -> Pair(Icons.Default.DirectionsCar, typeBrushes.getValue("driverslicense"))
        "passport" -> Pair(Icons.Default.FlightTakeoff, typeBrushes.getValue("passport"))
        else -> Pair(Icons.Default.Shield, defaultBrush)
    }
}

/** Visual icon and primary accent color for a cipher type tag. */
fun cipherTypeTheme(typeTag: String): Pair<ImageVector, Color> {
    val (icon, _) = cipherTypeVisuals(typeTag)
    val color = (typeAccentColors[typeTag.lowercase()] ?: defaultAccentColors).first()
    return Pair(icon, color)
}

/**
 * Category badge pill matching desktop badge-green/badge-blue tokens.
 */
@Composable
fun CategoryBadge(
    label: String,
    modifier: Modifier = Modifier,
    typeTag: String = "login",
) {
    val accentColor = (typeAccentColors[typeTag.lowercase()] ?: defaultAccentColors)
        .firstOrNull() ?: MaterialTheme.colorScheme.primary

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(accentColor.copy(alpha = 0.15f))
            .border(1.dp, accentColor.copy(alpha = 0.35f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.Bold,
                fontSize = 11.sp,
            ),
            color = accentColor,
        )
    }
}

/**
 * Grouped section container with clean uppercase header.
 */
@Composable
fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        if (title.isNotBlank()) {
            Text(
                text = title.uppercase(),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp,
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, bottom = 8.dp),
            )
        }
        BaluardCard(
            contentPadding = contentPadding,
            content = content,
        )
    }
}

/**
 * Field row with copy button and animated "Copied!" feedback badge.
 */
@Composable
fun CopyableFieldRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
    sensitive: Boolean = false,
    onCopy: (() -> Unit)? = null,
) {
    var revealed by remember(label) { mutableStateOf(!sensitive) }
    var copied by remember { mutableStateOf(false) }

    LaunchedEffect(copied) {
        if (copied) {
            delay(1500)
            copied = false
        }
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .clickable {
                    if (sensitive && !revealed) revealed = true
                },
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(2.dp))
            AnimatedContent(
                targetState = revealed,
                transitionSpec = {
                    fadeIn(animationSpec = tween(180, easing = FastOutSlowInEasing))
                        .togetherWith(fadeOut(animationSpec = tween(120)))
                },
                label = "RevealAnimation",
            ) { isRevealed ->
                Text(
                    text = if (isRevealed) value else "••••••••••••",
                    style = MaterialTheme.typography.bodyLarge.copy(
                        fontWeight = FontWeight.Medium,
                    ),
                    fontFamily = if (mono || (sensitive && !isRevealed)) FontFamily.Monospace else null,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            AnimatedVisibility(
                visible = copied,
                enter = fadeIn() + scaleIn(),
                exit = fadeOut() + scaleOut(),
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f))
                        .border(1.dp, MaterialTheme.colorScheme.tertiary.copy(alpha = 0.35f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Check,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.tertiary,
                            modifier = Modifier.size(12.dp),
                        )
                        Spacer(Modifier.width(3.dp))
                        Text(
                            text = "Copied",
                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.tertiary,
                        )
                    }
                }
            }

            if (sensitive) {
                IconButton(
                    onClick = { revealed = !revealed },
                    modifier = Modifier.size(36.dp),
                ) {
                    Icon(
                        imageVector = if (revealed) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (revealed) t("detail.hide") else t("detail.reveal"),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }

            IconButton(
                onClick = {
                    copyToClipboard(value)
                    copied = true
                    onCopy?.invoke()
                },
                modifier = Modifier.size(36.dp),
            ) {
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = t("detail.copy"),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}


/**
 * Row card for an entry in any list (home search results, filtered lists).
 * [typeLabel] is the localized category label; [trailing] renders extra row
 * actions (unarchive/restore) after the chevron.
 */
@Composable
fun CipherRowCard(
    meta: xyz.actitud.baluard.MobileCipherMeta,
    typeLabel: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    trailing: @Composable () -> Unit = {},
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            // Surface(shape) clips; an extra Modifier.clip doubles the path work.
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.7f), RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CipherAvatar(
                name = meta.name,
                typeTag = meta.cipherType,
                size = 42.dp,
            )

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = meta.name,
                        style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                    )
                    if (meta.favorite) {
                        Icon(
                            imageVector = Icons.Default.Star,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }

                meta.username?.let {
                    if (it.isNotBlank()) {
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                        )
                    }
                }
            }

            CategoryBadge(
                label = typeLabel,
                typeTag = meta.cipherType,
            )

            Spacer(Modifier.width(6.dp))

            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.size(18.dp),
            )

            trailing()
        }
    }
}

/**
 * Sync top-bar button with phase feedback (desktop AutoSyncIndicator
 * parity): spinner while syncing, check when synced, cloud-off when
 * offline, resting sync icon otherwise.
 */
@Composable
fun SyncIconButton(phase: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .padding(horizontal = 3.dp)
            .size(36.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outlineVariant,
                shape = RoundedCornerShape(10.dp),
            )
            .clickable(enabled = phase == "idle", onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        when (phase) {
            "syncing" -> CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp,
            )
            "synced" -> Icon(
                imageVector = Icons.Default.Check,
                contentDescription = t("sync.synced"),
                tint = MaterialTheme.colorScheme.tertiary,
                modifier = Modifier.size(18.dp),
            )
            "offline" -> Icon(
                imageVector = Icons.Default.CloudOff,
                contentDescription = t("sync.offline"),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
            else -> Icon(
                imageVector = Icons.Default.Sync,
                contentDescription = t("settings.syncNow"),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
