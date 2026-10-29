package xyz.actitud.baluard.data

/**
 * H12: a hardware-sealed vault can never serve autofill (the :autofill
 * process has no security-key transport, and unlocking the main app does
 * not change that). The dataset chip is honest only when the sealed vault
 * was the ONLY candidate — one sealed vault must never hide other vaults'
 * matches.
 */
fun securityKeyChipRequired(
    securityKeyRequired: Boolean,
    matchCount: Int,
    suggestionCount: Int,
): Boolean = securityKeyRequired && matchCount == 0 && suggestionCount == 0
