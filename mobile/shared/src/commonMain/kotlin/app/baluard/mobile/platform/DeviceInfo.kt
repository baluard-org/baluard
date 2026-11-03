package app.baluard.mobile.platform

/**
 * Human-readable device name from the OS (enroll + vault-create flows).
 * Prefills the device-name field so users don't type "My device"; the
 * field stays editable. Returns "" when the OS gives nothing usable —
 * the caller falls back to the localized default.
 */
expect fun deviceDisplayName(): String
