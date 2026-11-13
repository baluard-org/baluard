package app.baluard.mobile.platform

import androidx.compose.runtime.Composable

/** A picked import file: display name + raw bytes. */
class PickedFile(val name: String, val bytes: ByteArray)

/**
 * Platform document-open for imports (G2). Invoke with the accepted mime
 * types; [onResult] receives the file, or null on cancel and when the
 * platform surface is unavailable (iOS until its picker slice lands).
 * Callers stay silent on null — same contract as the saver's false.
 */
fun interface ImportFilePicker {
    fun pick(mimeTypes: List<String>, maxBytes: Long, onResult: (PickedFile?) -> Unit)

    operator fun invoke(mimeTypes: List<String>, onResult: (PickedFile?) -> Unit) {
        pick(mimeTypes, 300L * 1024 * 1024, onResult)
    }

    operator fun invoke(mimeTypes: List<String>, maxBytes: Long, onResult: (PickedFile?) -> Unit) {
        pick(mimeTypes, maxBytes, onResult)
    }
}

/**
 * Composable factory so the Android actual can hold its SAF launcher for
 * the composable's lifetime.
 */
@Composable
expect fun rememberImportFilePicker(): ImportFilePicker

/**
 * Platform document-save for recovery-sheet exports (D77: TXT / PDF bytes
 * rendered core-side via `recoverySheetBytes`). Invoke with the raw bytes;
 * [onResult] receives true when the file was written. A false result covers
 * both user cancel and an unavailable platform surface, and the caller stays
 * silent on it — same contract as the desktop command's Ok(false).
 */
fun interface RecoverySheetSaver {
    operator fun invoke(bytes: ByteArray, mimeType: String, suggestedName: String, onResult: (Boolean) -> Unit)
}

/**
 * Composable factory so the Android actual can hold its SAF launchers for
 * the composable's lifetime. iOS reports false until its picker slice lands.
 */
@Composable
expect fun rememberRecoverySheetSaver(): RecoverySheetSaver
