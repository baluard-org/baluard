package app.baluard.mobile.platform

import androidx.compose.runtime.Composable

/**
 * iOS `actual`: the document-picker slice ships with the iOS phase. Reports
 * null (callers stay silent — same contract as the saver's false) instead
 * of pretending a file was picked; fail closed.
 */
@Composable
actual fun rememberImportFilePicker(): ImportFilePicker =
    ImportFilePicker { _, _, onResult -> onResult(null) }
