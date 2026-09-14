package xyz.actitud.baluard.ui.toast

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutLinearInEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

/**
 * Standalone toast signal (desktop context/toastSignal.js parity): any layer
 * fires `Toast.success(...)` / `Toast.error(...)` / ... and the single
 * [ToastHost] at the app root renders them — stacked, auto-dismissed, with
 * a manual dismiss button on errors.
 */
data class ToastEntry(
    val id: Long,
    val type: String,  // success | error | warning | info
    val message: String,
    val manual: Boolean,
)

object Toast {
    private var nextId = 0L

    var entries by mutableStateOf<List<ToastEntry>>(emptyList())
        private set

    private var exiting by mutableStateOf<Set<Long>>(emptySet())
    /** Push a toast. Errors wait for a manual dismiss; the rest auto-dismiss. */
    fun show(type: String, message: String, manual: Boolean = false) {
        val id = ++nextId
        entries = entries + ToastEntry(id, type, message, manual)
    }

    /** Phase 1: flag for the exit animation; the row removes itself after it plays. */
    fun dismiss(id: Long) {
        exiting = exiting + id
    }

    fun isExiting(id: Long) = id in exiting

    /** Phase 2: drop the entry from the list (called post-animation). */
    fun remove(id: Long) {
        entries = entries.filter { it.id != id }
        exiting = exiting - id
    }
    fun success(message: String) = show("success", message)
    fun error(message: String) = show("error", message, manual = true)
    fun info(message: String) = show("info", message)
}

private val typeIcon: Map<String, ImageVector> = mapOf(
    "success" to Icons.Default.Check,
    "error" to Icons.Default.ErrorOutline,
    "info" to Icons.Default.Info,
)

data class ToastColorScheme(
    val accent: Color,
    val iconBg: Color,
    val stroke: Color,
)

@Composable
private fun toastColors(type: String): ToastColorScheme {
    val accent = when (type) {
        "success" -> MaterialTheme.colorScheme.tertiary
        "error" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.secondary
    }
    return ToastColorScheme(
        accent = accent,
        iconBg = accent.copy(alpha = 0.14f),
        stroke = accent.copy(alpha = 0.35f),
    )
}

/**
 * Renders [Toast.entries] stacked at the top of the screen. Render once
 * at the app root; auto-dismiss timers run per toast (manual toasts wait for
 * their dismiss button).
 */
@Composable
fun ToastHost(modifier: Modifier = Modifier) {
    val toasts = Toast.entries
    Column(
        modifier = modifier
            .fillMaxWidth()
            .statusBarsPadding()
            // Pinned to the main header's bottom edge: toasts emerge from
            // under it, never covering it.
            .padding(top = 64.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        toasts.forEach { entry ->
            key(entry.id) {
                AutoDismissingToast(entry)
            }
        }
    }
}

@Composable
private fun AutoDismissingToast(entry: ToastEntry) {
    // Desktop setTimeout parity: the host drives the dismiss timer.
    LaunchedEffect(entry.id) {
        if (!entry.manual) {
            delay(if (entry.type == "error") 6000L else 4000L)
            Toast.dismiss(entry.id)
        }
    }

    val exiting = Toast.isExiting(entry.id)
    LaunchedEffect(exiting) {
        if (exiting) {
            delay(200)
            Toast.remove(entry.id)
        }
    }

    // Emerges from under the header (top edge pinned to the header's bottom
    // line) and retracts back up into it on dismiss.
    val state = remember { MutableTransitionState(false) }
    state.targetState = !exiting
    AnimatedVisibility(
        visibleState = state,
        enter = expandVertically(
            animationSpec = tween(220, easing = FastOutSlowInEasing),
            expandFrom = Alignment.Top,
        ) + slideInVertically(
            animationSpec = tween(220, easing = FastOutSlowInEasing),
            initialOffsetY = { -it / 3 },
        ) + fadeIn(tween(220)),
        exit = shrinkVertically(
            animationSpec = tween(200, easing = FastOutLinearInEasing),
            shrinkTowards = Alignment.Top,
        ),
    ) {
        val colors = toastColors(entry.type)
        val toastShape = RoundedCornerShape(bottomStart = 14.dp, bottomEnd = 14.dp)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(toastShape)
                .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                .border(1.dp, colors.stroke, toastShape)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(colors.iconBg),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = typeIcon[entry.type] ?: Icons.Default.Info,
                    contentDescription = null,
                    tint = colors.accent,
                    modifier = Modifier.size(18.dp),
                )
            }
            Spacer(Modifier.width(12.dp))
            Text(
                text = entry.message,
                style = MaterialTheme.typography.bodyMedium.copy(
                    fontWeight = FontWeight.Medium,
                    lineHeight = 20.sp,
                ),
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f),
            )
            if (entry.manual) {
                IconButton(
                    onClick = { Toast.dismiss(entry.id) },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}
