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
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.fadeOut
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
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
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

    /** Push a toast. [durationMs] 0 = manual dismiss only. */
    fun show(type: String, message: String, durationMs: Long = 4000, manual: Boolean = false) {
        val id = ++nextId
        entries = entries + ToastEntry(id, type, message, manual)
    }

    fun dismiss(id: Long) {
        entries = entries.filter { it.id != id }
    }

    fun success(message: String) = show("success", message)
    fun error(message: String) = show("error", message, durationMs = 6000, manual = true)
    fun warning(message: String) = show("warning", message, durationMs = 5000)
    fun info(message: String) = show("info", message)
}

private val typeIcon: Map<String, ImageVector> = mapOf(
    "success" to Icons.Default.Check,
    "error" to Icons.Default.ErrorOutline,
    "warning" to Icons.Default.Warning,
    "info" to Icons.Default.Info,
)

@Composable
private fun toastStyle(type: String): Pair<Color, Color> {
    // Muted container wash + bright content tone, tuned for the dark theme.
    return when (type) {
        "success" -> Pair(Color(0xFF10B981).copy(alpha = 0.16f), Color(0xFF6EE7B7))
        "error" -> Pair(Color(0xFFEF4444).copy(alpha = 0.16f), Color(0xFFFCA5A5))
        "warning" -> Pair(Color(0xFFF59E0B).copy(alpha = 0.16f), Color(0xFFFCD34D))
        else -> Pair(MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.colorScheme.onSurface)
    }
}

@Composable
private fun typeTint(type: String): Color = toastStyle(type).second

/**
 * Renders [Toast.entries] stacked at the bottom of the screen. Render once
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

    // Slides out from under the header: the toast's top edge stays pinned
    // to the header's bottom line while it expands downward, then retracts
    // back up on dismiss.
    val state = remember { MutableTransitionState(false).apply { targetState = true } }
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
            animationSpec = tween(180, easing = FastOutLinearInEasing),
            shrinkTowards = Alignment.Top,
        ) + slideOutVertically(
            animationSpec = tween(180, easing = FastOutLinearInEasing),
            targetOffsetY = { -it / 3 },
        ) + fadeOut(tween(180)),
    ) {
        val (container, content) = toastStyle(entry.type)
        Surface(
            shape = RoundedCornerShape(bottomStart = 12.dp, bottomEnd = 12.dp),
            color = container,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = typeIcon[entry.type] ?: Icons.Default.Info,
                    contentDescription = null,
                    tint = content,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    text = entry.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = content,
                    modifier = Modifier.weight(1f),
                )
                if (entry.manual) {
                    IconButton(onClick = { Toast.dismiss(entry.id) }, modifier = Modifier.size(24.dp)) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
            }
        }
    }
}
