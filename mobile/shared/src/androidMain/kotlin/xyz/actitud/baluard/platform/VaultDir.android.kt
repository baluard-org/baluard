package xyz.actitud.baluard.platform

import java.io.File

/** Android `actual`: recursive delete via java.io.File. */
actual fun removeVaultDirectory(path: String): Boolean =
    runCatching { File(path).deleteRecursively() }.getOrDefault(false)
