package app.baluard.mobile.platform

/**
 * Deep-link to the OS credential-provider page (the row only renders when
 * [credentialProviderSupported]). Expect/actual because the intent class is
 * Android-only and commonMain must stay Kotlin/Native-clean.
 */
expect fun openCredentialProviderSettings(): Boolean
