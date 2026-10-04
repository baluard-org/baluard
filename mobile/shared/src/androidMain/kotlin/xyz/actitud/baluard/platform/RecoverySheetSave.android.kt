package xyz.actitud.baluard.platform

import android.net.Uri
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
 * Android `actual`: the Storage Access Framework create-document picker. Two
 * launchers (the contract fixes the mime at construction), one pending-
 * callback slot — the system picker is modal, so a single slot cannot
 * interleave. Writes on Dispatchers.IO; the callback fires on the main one.
 */
@Composable
actual fun rememberRecoverySheetSaver(): RecoverySheetSaver {
    var pending by remember { mutableStateOf<((Uri?) -> Unit)?>(null) }
    val scope = rememberCoroutineScope()
    // One launcher per concrete MIME: the contract fixes the type at
    // construction. JSON/CSV serve the G2 vault export (same saver).
    val createTxt = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri -> pending?.invoke(uri) }
    val createPdf = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/pdf"),
    ) { uri -> pending?.invoke(uri) }
    val createJson = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> pending?.invoke(uri) }
    val createCsv = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv"),
    ) { uri -> pending?.invoke(uri) }
    return remember {
        RecoverySheetSaver { bytes, mimeType, suggestedName, onResult ->
            pending = { uri ->
                if (uri == null) {
                    onResult(false)
                } else {
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) { writeToUri(uri, bytes) }
                        onResult(ok)
                    }
                }
            }
            val launcher = when (mimeType) {
                "application/pdf" -> createPdf
                "application/json" -> createJson
                "text/csv" -> createCsv
                else -> createTxt
            }
            launcher.launch(suggestedName)
        }
    }
}

/**
 * SAF hands back a document the provider owns; the resolver stream is the
 * platform-native write path, so no storage permission and no path cross
 * the boundary. "wt" truncates in case a provider reuses an entry.
 */
private fun writeToUri(uri: Uri, bytes: ByteArray): Boolean {
    return try {
        val out = AppContextHolder.require().contentResolver.openOutputStream(uri, "wt")
            ?: return false
        out.use { stream -> stream.write(bytes) }
        true
    } catch (e: Exception) {
        platformLogE("RecoverySheetSave", "sheet write failed", e)
        false
    }
}
