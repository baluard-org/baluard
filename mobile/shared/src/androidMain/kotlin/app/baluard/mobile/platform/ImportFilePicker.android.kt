package app.baluard.mobile.platform

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Android `actual`: the Storage Access Framework open-document picker.
 * Reads the picked document's bytes + display name on Dispatchers.IO; the
 * callback fires on the main one. No storage permission — SAF hands back a
 * document the provider owns and the resolver stream is the platform read
 * path.
 */
@Composable
actual fun rememberImportFilePicker(): ImportFilePicker {
    var pending by remember { mutableStateOf<((Uri?) -> Unit)?>(null) }
    val scope = rememberCoroutineScope()
    val openDoc = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> pending?.invoke(uri) }
    return remember {
        ImportFilePicker { mimeTypes, maxBytes, onResult ->
            pending = { uri ->
                if (uri == null) {
                    onResult(null)
                } else {
                    scope.launch {
                        val file = withContext(Dispatchers.IO) { readFromUri(uri, maxBytes) }
                        onResult(file)
                    }
                }
            }
            openDoc.launch(mimeTypes.toTypedArray())
        }
    }
}

private fun readFromUri(uri: Uri, maxBytes: Long): PickedFile? {
    return try {
        val ctx = AppContextHolder.require()
        val stream = ctx.contentResolver.openInputStream(uri)
        val bytes = if (stream != null) {
            stream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) {
                        // When a caller sets a tight cap (e.g. attachments),
                        // stop reading early and return the over-cap prefix
                        // so the caller can surface a size-limit error.
                        if (maxBytes < 300L * 1024 * 1024) {
                            val rem = (maxBytes + 1 - out.size()).toInt().coerceAtLeast(0).coerceAtMost(n)
                            if (rem > 0) out.write(buf, 0, rem)
                            break
                        }
                        return null
                    }
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
        } else {
            return null
        }
        var name = "import"
        val cursor = ctx.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )
        if (cursor != null) {
            cursor.use { c ->
                if (c.moveToFirst()) {
                    val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0 && !c.isNull(idx)) name = c.getString(idx)
                }
            }
        }
        PickedFile(name, bytes)
    } catch (e: Exception) {
        platformLogE("ImportFilePicker", "import read failed", e)
        null
    }
}
