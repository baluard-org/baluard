package xyz.actitud.baluard.platform

/**
 * Recursively delete a vault directory (remove-from-device flow). The
 * caller MUST have locked the vault + disenrolled biometrics first.
 * Returns false when deletion failed (caller keeps the vault usable).
 */
expect fun removeVaultDirectory(path: String): Boolean
