package app.baluard.mobile.platform

/**
 * Copy [text] to the system clipboard (field copy buttons on the detail
 * screen). Returns whether the write landed: Android blocks clipboard
 * writes from a context without focus, so callers must not claim success
 * (or toast) before checking.
 */
expect fun copyToClipboard(text: String): Boolean
