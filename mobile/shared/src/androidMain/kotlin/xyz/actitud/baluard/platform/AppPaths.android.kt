package xyz.actitud.baluard.platform

import java.io.File

/**
 * Android `actual` for [AppPaths] (plan §5.1: androidMain actual via
 * `Context.filesDir`). The vault lives in app-private storage; `allowBackup`
 * is false in the manifest, so it never leaves the device.
 */
actual object AppPaths {
    actual fun defaultVaultPath(): String =
        File(AppContextHolder.require().filesDir, "vault").absolutePath

    actual fun vaultExists(path: String): Boolean = File(path, ".baluard").exists()
}
