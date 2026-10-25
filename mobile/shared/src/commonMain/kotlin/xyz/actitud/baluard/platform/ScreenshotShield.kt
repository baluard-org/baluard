package xyz.actitud.baluard.platform

/**
 * True only when the platform actually implements a screenshot shield.
 * Gates the "allow screenshots" Settings row: an OS without the shield
 * must not offer a toggle that silently does nothing.
 */
expect fun screenshotShieldSupported(): Boolean
