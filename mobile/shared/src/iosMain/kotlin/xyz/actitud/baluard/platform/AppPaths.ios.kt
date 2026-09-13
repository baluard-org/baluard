package xyz.actitud.baluard.platform

import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSString
import platform.Foundation.NSUserDomainMask
import platform.Foundation.stringByAppendingPathComponent

/**
 * iOS `actual` for [AppPaths]. The vault lives in the app-sandboxed
 * Documents directory. Untested in this container (Kotlin/Native builds on a
 * macOS host per docs/mobile-dev-setup.md); follows the same sandbox path the
 * iOS slice will pin down.
 */
actual object AppPaths {
    actual fun defaultVaultPath(): String {
        val docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            expandTilde = true,
        ).firstOrNull() as? String ?: ""
        return docs.stringByAppendingPathComponent("vault")
    }

    actual fun vaultExists(path: String): Boolean =
        NSFileManager.defaultManager.fileExistsAtPath(
            (path as NSString).stringByAppendingPathComponent(".baluard"),
        )

    actual fun nextVaultPath(owner: String, repo: String): String {
        val docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask,
            expandTilde = true,
        ).firstOrNull() as? String ?: ""
        val slug = ((owner + "-" + repo).lowercase()
            .map { if (it.isLetterOrDigit()) it else '-' }.joinToString(""))
            .trim('-').take(48).ifEmpty { "vault" }
        return docs.stringByAppendingPathComponent("vaults/$slug")
    }
}
