package app.baluard.mobile.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

actual object OutboxFolderSupport {
    actual fun isSupported(): Boolean = false
}

@Composable
actual fun rememberOutboxFolderBridge(): OutboxFolderBridge = remember {
    object : OutboxFolderBridge {
        override fun pickFolder(onReady: (String?) -> Unit) {
            onReady(null)
        }

        override fun pushMirror(mirrorPath: String) = Unit

        override fun pullMirror(mirrorPath: String) = Unit
    }
}
