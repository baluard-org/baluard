package app.baluard.mobile.platform

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

    private fun vaultsRoot(): File = File(AppContextHolder.require().filesDir, "vaults")

    private fun sanitizeSlug(raw: String): String =
        raw.lowercase().map { if (it.isLetterOrDigit()) it else '-' }
            .joinToString("").trim('-').take(48)

    /**
     * Fresh clone target for a repo: "<owner>-<repo>" (owner/name is unique
     * per forge, so collisions are impossible from the same account) with a
     * -2/-3 fallback for cross-provider clashes. Never returns an existing
     * directory.
     */
    actual fun nextVaultPath(owner: String, repo: String): String {
        val ownerSlug = sanitizeSlug(owner)
        val repoSlug = sanitizeSlug(repo).ifEmpty { "vault" }
        val base = if (ownerSlug.isEmpty()) repoSlug else "$ownerSlug-$repoSlug"
        var candidate = vaultsRoot().resolve(base)
        var n = 2
        while (candidate.exists()) {
            candidate = vaultsRoot().resolve("$base-$n")
            n += 1
        }
        return candidate.absolutePath
    }

    /**
     * Machine directory for a created vault ("vault-2", "vault-3", ...); the
     * display name comes from the marker slug, never from this name. Detach
     * moves directories into detached/, so the collision scan covers both
     * roots — otherwise a reused name would drift to "vault-2-1" on a later
     * detach.
     */
    actual fun nextCreatedVaultPath(): String {
        val detachedRoot = File(AppContextHolder.require().filesDir, "detached")
        var n = 2
        while (true) {
            val candidate = vaultsRoot().resolve("vault-$n")
            if (!candidate.exists() && !File(detachedRoot, "vault-$n").exists()) {
                return candidate.absolutePath
            }
            n += 1
        }
    }
}
