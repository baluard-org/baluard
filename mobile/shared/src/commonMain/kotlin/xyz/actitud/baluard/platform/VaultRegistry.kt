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

    /**
     * G24 §4.2 merge-eligibility sniff for merged search. Keyless read of
     * the plaintext classification surfaces only; anything damaged fails
     * closed.
     */
    fun isMergeEligible(path: String): Boolean

    /** Last-used vault path, or null (fall back to the platform default). */
    fun loadActiveVault(): String?

    /** Persist the active vault path for the next cold start. */
    fun saveActiveVault(path: String)

    /**
     * Detach a vault from the switcher list WITHOUT deleting it: the
     * directory moves aside (data preserved, never auto-deleted) so the
     * list stays clean and a future clone of the same slug cannot
     * collide with stale files. Returns false when the path is unknown
     * or the move failed.
     */
    fun detach(path: String): Boolean
}
