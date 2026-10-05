package xyz.actitud.baluard.platform

import android.content.Context
import java.io.File

/** SharedPreferences-backed vault discovery + active-vault persistence. */
actual object VaultRegistry {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_local_prefs", Context.MODE_PRIVATE)

    private fun vaultsRoot(): File = File(AppContextHolder.require().filesDir, "vaults")

    private fun defaultVault(): File = File(AppContextHolder.require().filesDir, "vault")

    private fun isVault(dir: File): Boolean = File(dir, ".baluard").exists()

    /** Marker slug → display name ("baluard-personal" → "Personal"). */
    private fun displayName(dir: File): String {
        val slug = runCatching {
            val text = File(dir, ".baluard").readText()
            Regex("\"slug\"\\s*:\\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1)
        }.getOrNull().orEmpty()
        val base = if (slug.isNotEmpty()) slug else dir.name
        return base.removePrefix("baluard-").replaceFirstChar { it.uppercase() }
    }

    actual fun listVaults(): List<DiscoveredVault> {
        val found = LinkedHashMap<String, DiscoveredVault>()
        val defaultDir = defaultVault()
        if (isVault(defaultDir)) {
            found[defaultDir.absolutePath] =
                DiscoveredVault(defaultDir.absolutePath, displayName(defaultDir))
        }
        val vaultsDir = vaultsRoot()
        if (vaultsDir.exists()) {
            vaultsDir.listFiles { f -> f.isDirectory && isVault(f) }
                ?.sortedBy { it.name.lowercase() }
                ?.forEach { dir ->
                    found.putIfAbsent(
                        dir.absolutePath,
                        DiscoveredVault(dir.absolutePath, displayName(dir)),
                    )
                }
        }
        return found.values.toList()
    }

    actual fun loadActiveVault(): String? {
        val path = prefs().getString(KEY, null) ?: return null
        // Stale-pointer self-heal (the prune equivalent on a filesystem-
        // scanned list): a directory that vanished can never come back,
        // so forget it instead of launching into a missing vault.
        if (!File(path).hasMarker()) {
            prefs().edit().remove(KEY).apply()
            return null
        }
        return path
    }

    actual fun saveActiveVault(path: String) {
        prefs().edit().putString(KEY, path).apply()
    }

    actual fun detach(path: String): Boolean {
        val src = File(path)
        if (!src.hasMarker()) return false
        val detachedRoot = File(AppContextHolder.require().filesDir, "detached")
        if (!detachedRoot.exists() && !detachedRoot.mkdirs()) return false
        // Collision-guard: appending keeps every detached copy on disk.
        var target = File(detachedRoot, src.name)
        var n = 1
        while (target.exists()) {
            target = File(detachedRoot, "${src.name}-$n")
            n += 1
        }
        if (!src.renameTo(target)) return false
        if (prefs().getString(KEY, null) == path) {
            prefs().edit().remove(KEY).apply()
        }
        return true
    }

    private fun File.hasMarker(): Boolean = File(this, ".baluard").exists()

    private const val KEY = "activeVaultPath"
}
