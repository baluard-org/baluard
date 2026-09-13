package xyz.actitud.baluard.platform

/**
 * Vault discovery + active-vault persistence (desktop VaultSwitcher parity).
 *
 * Android scans the app sandbox for vault directories (marker-checked) and
 * persists the last-used path so the app reopens on the same vault.
 */
data class DiscoveredVault(
    val path: String,
    val name: String,
)

expect object VaultRegistry {
    /** All vault directories found on this device (marker-checked). */
    fun listVaults(): List<DiscoveredVault>

    /** Last-used vault path, or null (fall back to the platform default). */
    fun loadActiveVault(): String?

    /** Persist the active vault path for the next cold start. */
    fun saveActiveVault(path: String)
}
