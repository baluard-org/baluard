package app.baluard.mobile.platform

/**
 * iOS `actual` for the Wi-Fi-only sync gate. Stub until the iOS host build;
 * returns unmetered so the advisory gate stays inactive (plan §3.5).
 */
actual fun isMeteredNetwork(): Boolean = false
