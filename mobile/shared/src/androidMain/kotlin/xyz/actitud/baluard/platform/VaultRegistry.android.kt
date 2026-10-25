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

    actual fun isMergeEligible(path: String): Boolean {
        return runCatching {
            val dir = java.io.File(path)
            // Flipped team shape (org made by the flip button): never merges.
            if (java.io.File(dir, "meta/space-shape.json").exists()) return@runCatching false
            val pub = java.io.File(dir, "meta/settings-pub.json")
            if (!pub.exists()) return@runCatching true // personal: always eligible
            val obj = org.json.JSONObject(pub.readText())
            when {
                obj.optString("purpose") == "family" -> true
                obj.optString("purpose") == "org" -> false
                obj.optString("purpose") == "pair" -> false
                // Legacy pair flag without a purpose: a pair Space.
                obj.optBoolean("space", false) -> false
                else -> true
            }
        }.getOrDefault(false)
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
        // Cross-process read: :autofill must see a switch made in the app
        // without a process restart (prefs cache per process).
        val path = CrossProcessPrefs.read(KEY) ?: run {
            val legacy = prefs().getString(KEY, null)
            if (legacy != null) CrossProcessPrefs.write(KEY, legacy)
            legacy
        } ?: return null
        // Stale-pointer self-heal (the prune equivalent on a filesystem-
        // scanned list): a directory that vanished can never come back,
        // so forget it instead of launching into a missing vault.
        if (!File(path).hasMarker()) {
            CrossProcessPrefs.remove(KEY)
            prefs().edit().remove(KEY).apply()
            return null
        }
        return path
    }

    actual fun saveActiveVault(path: String) {
        CrossProcessPrefs.write(KEY, path)
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
        if (CrossProcessPrefs.read(KEY) == path) {
            CrossProcessPrefs.remove(KEY)
            prefs().edit().remove(KEY).apply()
        }
        return true
    }

    private fun File.hasMarker(): Boolean = File(this, ".baluard").exists()

    private const val KEY = "activeVaultPath"
}
