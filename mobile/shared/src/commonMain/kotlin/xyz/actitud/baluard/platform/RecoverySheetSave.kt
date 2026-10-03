package xyz.actitud.baluard.platform

import androidx.compose.runtime.Composable

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
