package app.baluard.mobile.platform

import androidx.compose.runtime.Composable

/**
 * iOS `actual`: the document-picker slice ships with the iOS phase. Reports
 * false (callers stay silent — desktop parity contract) instead of pretending
 * success; fail closed, never a phantom saved file.
 */
@Composable
actual fun rememberRecoverySheetSaver(): RecoverySheetSaver =
    RecoverySheetSaver { _, _, _, onResult -> onResult(false) }
