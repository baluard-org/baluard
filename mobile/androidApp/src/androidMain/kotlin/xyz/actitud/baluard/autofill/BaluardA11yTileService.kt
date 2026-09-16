package xyz.actitud.baluard.autofill

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.AccessibilityFill

/**
 * Quick-settings fill tile (Phase 6.5, Bitwarden-current model): the only
 * user-facing trigger of the accessibility flow. Tapping it arms the parse
 * action in the shared `:autofill` process and fires the NoDisplay
 * trampoline whose window change the armed service acts on.
 *
 * Tile state mirrors the feature: active only while BOTH the Baluard-side
 * flag and the system accessibility switch are on.
 */
class BaluardA11yTileService : TileService() {

    override fun onClick() {
        super.onClick()
        if (!AccessibilityFill.enabled()) {
            toast(t("a11y.toastEnableBaluardFirst"))
            return
        }
        if (!AccessibilityFill.serviceEnabledInSystem()) {
            toast(t("a11y.toastEnableSystem"))
            AccessibilityFill.openSystemA11ySettings()
            return
        }
        AutofillA11yBridge.armParse()
        val intent = android.content.Intent(this, A11yTileTrampoline::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        // API 34 requires the PendingIntent overload for targetSdk 34+ apps
        // (Agy finding #2); older releases keep the Intent variant.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = android.app.PendingIntent.getActivity(
                this,
                0,
                intent,
                android.app.PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    private fun updateTile() {
        val active = AccessibilityFill.enabled() && AccessibilityFill.serviceEnabledInSystem()
        qsTile?.apply {
            state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            updateTile()
        }
    }

    private fun toast(message: String) {
        android.widget.Toast.makeText(applicationContext, message, android.widget.Toast.LENGTH_SHORT).show()
    }
}
