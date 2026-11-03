package app.baluard.mobile.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/**
 * Metered-network check for the Wi-Fi-only sync gate (plan §3.5 advisory).
 * Runs on the calling thread; ConnectivityManager active-network queries are
 * cheap cached reads (no blocking I/O).
 */
actual fun isMeteredNetwork(): Boolean {
    val cm = AppContextHolder.require()
        .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        ?: return false // fail open: never block sync on a missing service
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        ?: return cm.isActiveNetworkMetered
    return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
}
