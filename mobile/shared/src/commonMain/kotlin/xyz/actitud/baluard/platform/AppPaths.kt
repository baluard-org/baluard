package xyz.actitud.baluard.platform

/**
 * Platform-resolved app paths for the onboarding root (plan §5.1).
 *
 * `defaultVaultPath` is the first vault's home; later vaults (created or
 * cloned) live under the vaults root the registry scans. `vaultExists` checks
 * the `.baluard` marker directory, the same verification
 * `providers::clone_and_register` enforces on clone.
 */
expect object AppPaths {
    /** App-private default vault directory. */
    fun defaultVaultPath(): String

    /** True when [path] holds a Baluard vault (`.baluard` marker present). */
    fun vaultExists(path: String): Boolean

    /**
     * Fresh home for a vault created on this device: a new directory under
     * the vaults root, guaranteed not to collide with an existing or detached
     * vault directory.
     */
    fun nextCreatedVaultPath(): String

    /**
     * Fresh clone target for a repo: a new directory under the vaults root,
     * named "<owner>-<repo>" (slugified — owner/name is unique per forge),
     * guaranteed not to collide with an existing directory.
     */
    fun nextVaultPath(owner: String, repo: String): String
}
