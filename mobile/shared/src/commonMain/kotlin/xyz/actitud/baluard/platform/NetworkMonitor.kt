package xyz.actitud.baluard.platform

/**
 * Wi-Fi-only sync gating (plan §3.5: advisory — the host gates the trigger
 * before calling the runtime; the runtime does not police it).
 *
 * @return true when the current network is metered (cellular in practice).
 * Automatic sync triggers are skipped while metered; explicit user gestures
 * ("Sync now", pull-to-refresh) always run.
 */
expect fun isMeteredNetwork(): Boolean
