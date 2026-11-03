package app.baluard.mobile.platform

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager

@OptIn(ExperimentalForeignApi::class)
/** iOS `actual`: NSFileManager recursive removal. */
actual fun removeVaultDirectory(path: String): Boolean =
    NSFileManager.defaultManager.removeItemAtPath(path, null)
