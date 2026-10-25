package xyz.actitud.baluard.platform

import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.stringByAppendingPathComponent

/**
 * iOS `actual` for [AppPaths]. The vault lives under Application Support
 * (NOT Documents: that directory syncs to iCloud/iTunes backups and shows
 * in the Files app), with the vault root excluded from backups so the
 * ciphertext stays device-local. Reads of the K/N Objective-C bridges are
 * verified against the binding surface, not compiled — K/N builds need a
 * macOS host (docs/mobile-dev-setup.md).
 */
actual object AppPaths {

    private fun appSupport(): String {
        val dir = NSSearchPathForDirectoriesInDomains(
            NSApplicationSupportDirectory,
            NSUserDomainMask,
            expandTilde = true,
        ).firstOrNull() as? String
        // Fail closed: a missing Application Support must not resolve the
        // vault against the process cwd (the old "" fallback did exactly
        // that, silently misplacing every file).
        return dir ?: throw IllegalStateException("no Application Support directory")
    }

    internal fun filesRoot(): String = appSupport()
    internal fun vaultsRoot(): String = appSupport().stringByAppendingPathComponent("vaults")
    internal fun detachedRoot(): String = appSupport().stringByAppendingPathComponent("detached")

    actual fun defaultVaultPath(): String = appSupport().stringByAppendingPathComponent("vault")

    actual fun vaultExists(path: String): Boolean =
        NSFileManager.defaultManager.fileExistsAtPath(
            path.stringByAppendingPathComponent(".baluard"),
        )

    /** Owner and repo slugified separately, matching the Android shape. */
    private fun slugify(part: String): String =
        part.lowercase().map { if (it.isLetterOrDigit()) it else '-' }
            .joinToString("").trim('-').take(48)

    actual fun nextVaultPath(owner: String, repo: String): String {
        // Collision loop like Android (-2, -3): a failed re-clone or the
        // same owner/repo from two providers must never merge directories.
        val ownerSlug = slugify(owner)
        val repoSlug = slugify(repo)
        val slug = listOf(ownerSlug, repoSlug).filter { it.isNotEmpty() }
            .joinToString("-").ifEmpty { "vault" }
        val vaults = vaultsRoot()
        NSFileManager.defaultManager.createDirectoryAtPath(
            vaults, withIntermediateDirectories = true, attributes = null, error = null,
        )
        var candidate = vaults.stringByAppendingPathComponent(slug)
        var n = 2
        while (NSFileManager.defaultManager.fileExistsAtPath(candidate)) {
            candidate = vaults.stringByAppendingPathComponent("$slug-$n")
            n += 1
        }
        return candidate
    }

    actual fun nextCreatedVaultPath(): String {
        val vaults = vaultsRoot()
        val detached = detachedRoot()
        NSFileManager.defaultManager.createDirectoryAtPath(
            vaults, withIntermediateDirectories = true, attributes = null, error = null,
        )
        var n = 2
        while (true) {
            val name = "vault-$n"
            val inVaults = NSFileManager.defaultManager.fileExistsAtPath(
                vaults.stringByAppendingPathComponent(name),
            )
            val inDetached = NSFileManager.defaultManager.fileExistsAtPath(
                detached.stringByAppendingPathComponent(name),
            )
            if (!inVaults && !inDetached) {
                return vaults.stringByAppendingPathComponent(name)
            }
            n += 1
        }
    }

    /** Called once at startup: keep the vault root out of iCloud/iTunes backups. */
    fun excludeVaultRootFromBackup() {
        val url = NSURL.fileURLWithPath(filesRoot())
        url.setResourceValue(
            true,
            forKey = platform.Foundation.NSURLIsExcludedFromBackupKey,
            error = null,
        )
    }
}
