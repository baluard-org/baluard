package app.baluard.mobile.platform

import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.stringByAppendingPathComponent
import platform.Foundation.NSUserDefaults

/**
 * iOS `actual`: NSFileManager scan of the vault directories with the active
 * pointer in NSUserDefaults — semantic parity with the Android registry.
 * Previously an in-memory stub: vaults created or cloned on iOS never
 * appeared in the switcher and were orphaned on disk after restart.
 */
actual object VaultRegistry {
    private val fm = NSFileManager.defaultManager
    private val d = NSUserDefaults.standardUserDefaults

    private fun vaultsRoot(): String = AppPaths.vaultsRoot()
    private fun defaultVault(): String = AppPaths.defaultVaultPath()
    private fun detachedRoot(): String = AppPaths.detachedRoot()

    private fun isVault(dir: String): Boolean =
        fm.fileExistsAtPath(dir.stringByAppendingPathComponent(".baluard"))

    /** Marker slug -> display name ("baluard-personal" -> "Personal"). */
    private fun displayName(dir: String): String {
        val marker = dir.stringByAppendingPathComponent(".baluard")
        val text = NSString.create(
            contentsOfFile = marker,
            encoding = NSUTF8StringEncoding,
            error = null,
        ) as? String ?: ""
        val slug = Regex("\"slug\"\s*:\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1).orEmpty()
        val base = slug.ifEmpty { dir.substringAfterLast('/') }
        return base.removePrefix("baluard-").replaceFirstChar { it.uppercase() }
    }

    private fun scanInto(found: LinkedHashMap<String, DiscoveredVault>, root: String) {
        val contents = fm.contentsOfDirectoryAtPath(root, error = null) ?: return
        (contents as? List<*>)?.filterIsInstance<String>()?.sorted()?.forEach { name ->
            val dir = root.stringByAppendingPathComponent(name)
            if (isVault(dir)) found.putIfAbsent(dir, DiscoveredVault(dir, displayName(dir)))
        }
    }

    actual fun listVaults(): List<DiscoveredVault> {
        val found = LinkedHashMap<String, DiscoveredVault>()
        if (isVault(defaultVault())) {
            found[defaultVault()] = DiscoveredVault(defaultVault(), displayName(defaultVault()))
        }
        scanInto(found, vaultsRoot())
        return found.values.toList()
    }

    actual fun isMergeEligible(path: String): Boolean = false // fail closed

    actual fun loadActiveVault(): String? {
        val path = d.stringForKey(KEY) ?: return null
        // Stale-pointer self-heal, matching Android.
        if (!isVault(path)) {
            d.removeObjectForKey(KEY)
            return null
        }
        return path
    }

    actual fun saveActiveVault(path: String) {
        d.setObject(path, forKey = KEY)
    }

    actual fun detach(path: String): Boolean {
        if (!isVault(path)) return false
        val root = detachedRoot()
        fm.createDirectoryAtPath(root, withIntermediateDirectories = true, attributes = null, error = null)
        // Collision-guard: appending keeps every detached copy on disk.
        val base = path.substringAfterLast('/')
        var name = base
        var n = 1
        while (fm.fileExistsAtPath(root.stringByAppendingPathComponent(name))) {
            name = "$base-$n"
            n += 1
        }
        val target = root.stringByAppendingPathComponent(name)
        if (!fm.moveItemAtPath(path, toPath = target, error = null)) return false
        if (d.stringForKey(KEY) == path) d.removeObjectForKey(KEY)
        return true
    }

    private const val KEY = "activeVaultPath"
}
