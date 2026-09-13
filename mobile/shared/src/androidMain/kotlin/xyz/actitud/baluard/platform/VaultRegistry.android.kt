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

    actual fun loadActiveVault(): String? =
        prefs().getString(KEY, null)

    actual fun saveActiveVault(path: String) {
        prefs().edit().putString(KEY, path).apply()
    }

    private const val KEY = "activeVaultPath"
}
