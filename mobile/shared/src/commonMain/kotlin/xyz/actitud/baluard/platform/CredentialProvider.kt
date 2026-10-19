package xyz.actitud.baluard.platform

/**
 * True when this device can host a third-party credential provider
 * (Android 14 / API 34+). Gates the Settings deep-link row; the provider
 * service itself is inert below 34 by construction.
 */
expect val credentialProviderSupported: Boolean
