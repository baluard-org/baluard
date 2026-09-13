package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [VaultRegistry]. In-memory stub until the iOS host build
 * (plan §1.1), matching the other platform stores.
 */
actual object VaultRegistry {
    private val vaults = mutableListOf<DiscoveredVault>()
    private var active: String? = null

    actual fun listVaults(): List<DiscoveredVault> = vaults.toList()

    actual fun loadActiveVault(): String? = active

    actual fun saveActiveVault(path: String) {
        active = path
    }
}
