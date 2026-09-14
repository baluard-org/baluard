package xyz.actitud.baluard.platform

/**
 * Copy [text] to the system clipboard (field copy buttons on the detail
 * screen). Fire-and-forget; toast feedback comes from the caller.
 */
expect fun copyToClipboard(text: String)
