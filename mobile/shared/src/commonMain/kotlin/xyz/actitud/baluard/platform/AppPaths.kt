package xyz.actitud.baluard.platform

/**
 * Platform-resolved app paths for the onboarding root (plan §5.1).
 *
 * `defaultVaultPath` is the single-vault home used on first launch; mobile is
 * one-vault-at-a-time (plan §10) so this is a fixed location, not a registry
 * scan. `vaultExists` checks the `.baluard` marker directory, the same
 * verification `providers::clone_and_register` enforces on clone.
 */
expect object AppPaths {
    /** App-private default vault directory. */
    fun defaultVaultPath(): String

    /** True when [path] holds a Baluard vault (`.baluard` marker present). */
    fun vaultExists(path: String): Boolean

    /**
     * Fresh clone target for a repo: a new directory under the vaults root,
     * named "<owner>-<repo>" (slugified — owner/name is unique per forge),
     * guaranteed not to collide with an existing directory.
     */
    fun nextVaultPath(owner: String, repo: String): String
}
