package xyz.actitud.baluard.platform

/**
 * Copy [text] to the system clipboard (field copy buttons on the detail
 * screen). Fire-and-forget; no confirmation surface (toasts land with the
 * mobile design pass).
 */
expect fun copyToClipboard(text: String)
