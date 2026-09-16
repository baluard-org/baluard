package xyz.actitud.baluard

import android.app.Application
import xyz.actitud.baluard.platform.AppContextHolder

/**
 * Process-wide init for BOTH processes: the main app process and `:autofill`
 * (BaluardAutofillService + AutofillActivity). Without this the autofill
 * process never initializes [AppContextHolder], and every platform actual
 * that reads it (Keystore glue, vault registry, biometric) fails (plan gap 1).
 */
class BaluardApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppContextHolder.set(this)
    }
}
