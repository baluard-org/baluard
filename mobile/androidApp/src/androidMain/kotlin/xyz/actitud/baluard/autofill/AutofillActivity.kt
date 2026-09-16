package xyz.actitud.baluard.autofill

import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import xyz.actitud.baluard.MainActivity
import xyz.actitud.baluard.R
import xyz.actitud.baluard.i18n.t
import xyz.actitud.baluard.platform.AppContextHolder
import xyz.actitud.baluard.platform.Biometric
import xyz.actitud.baluard.platform.VaultRegistry

/**
 * Transparent trampoline hosting the BiometricPrompt ceremony for the
 * `:autofill` process (plan D6). A Service cannot show BiometricPrompt; this
 * activity is launched by the OS through the response-level authentication
 * PendingIntent built in [AutofillResponseBuilder].
 *
 * Same process as the service (`android:process=":autofill"` in the
 * manifest) so [AutofillSession] is genuinely shared. Plain Views only, no
 * Compose: cold start must stay well under the 500 ms budget.
 *
 * NOT a NoDisplay theme: BiometricPrompt requires a visible window.
 */
class AutofillActivity : FragmentActivity() {

    companion object {
        const val EXTRA_TARGET = "baluard.autofill.extra.TARGET"
        const val EXTRA_IDS = "baluard.autofill.extra.IDS"
        private const val TAG = "BaluardAutofill"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The service process never runs MainActivity, so the context holder
        // and the FragmentActivity host (BiometricPrompt requirement) must be
        // wired here as well.
        AppContextHolder.set(this)
        AppContextHolder.setActivity(this)
        setContentView(R.layout.autofill_activity)

        val target = intent?.getStringExtra(EXTRA_TARGET)
        val ids = intent?.getParcelableArrayListExtra<AutofillId>(EXTRA_IDS)
        val fields = AutofillResponseBuilder.TargetFields(
            usernameId = ids?.getOrNull(0),
            passwordId = ids?.getOrNull(1),
        )
        if (target == null || (fields.usernameId == null && fields.passwordId == null)) {
            finish()
            return
        }

        val status = findViewById<TextView>(R.id.autofill_status)
        val path = VaultRegistry.loadActiveVault()
        if (path == null) {
            status.text = t("autofill.openAppToSetup")
            openMainAndFinishDelayed()
            return
        }

        val biometric = Biometric()
        if (!biometric.isAvailable() || !biometric.isEnrolled(path)) {
            // Quick unlock was never set up (or biometrics changed). Autofill
            // has no master-password path by design (plan D5); send the user
            // to the app to enroll.
            status.text = t("autofill.openAppToSetup")
            openMainAndFinishDelayed()
            return
        }

        status.text = t("autofill.unlockHint")
        biometric.unlock(
            vaultKey = path,
            title = t("login.biometricTitle"),
            onSuccess = { kek ->
                AutofillSession.scope.launch {
                    val unlocked = AutofillSession.unlock(kek)
                    if (!unlocked) {
                        failOnUiThread(t("autofill.unlockFailed"))
                        return@launch
                    }
                    val response = AutofillResponseBuilder.filledResponse(
                        applicationContext,
                        fields,
                        target,
                    ) ?: AutofillResponseBuilder.saveOnlyResponse(applicationContext, fields, target)
                    deliverOnUiThread(response)
                }
            },
            onError = { _, message ->
                // User cancel (codes 5/10) and real failures both land here;
                // the message is only echoed to our own status view.
                failOnUiThread(message.ifBlank { t("autofill.unlockFailed") })
            },
        )
    }

    override fun onDestroy() {
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }

    private fun deliverOnUiThread(response: android.service.autofill.FillResponse) {
        runOnUiThread {
            val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            setResult(RESULT_OK, result)
            finish()
            overridePendingTransition(0, 0)
        }
    }

    private fun failOnUiThread(message: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.autofill_status).text = message
            // Leave a beat to read the message, then release the fill request
            // with no result (the OS falls back to its keyboard).
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ finish() }, 1500)
        }
    }

    private fun openMainAndFinishDelayed() {
        // Guide setup: opening the app lands on unlock/quick-unroll flows.
        val launch = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivity(launch)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ finish() }, 1200)
    }
}
