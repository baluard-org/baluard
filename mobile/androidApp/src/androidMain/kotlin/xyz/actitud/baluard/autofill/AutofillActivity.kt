package xyz.actitud.baluard.autofill

import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.LinearLayout
import android.widget.ScrollView
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
 * Trampoline + picker host for the `:autofill` process.
 *
 * Dataset mode (Phase 6 fill path): biometric ceremony, real datasets back
 * via EXTRA_AUTHENTICATION_RESULT (plan D6).
 * A11Y picker mode (Phase 6.5 tile flow): after the same biometric unlock,
 * a plain-Views list of matching logins; the chosen id goes back through
 * [AutofillA11yBridge] and the service types it into the target app (plan
 * D10/D12). Plain Views only, no Compose in this process (D9).
 */
class AutofillActivity : FragmentActivity() {

    companion object {
        const val EXTRA_TARGET = "baluard.autofill.extra.TARGET"
        const val EXTRA_IDS = "baluard.autofill.extra.IDS"
        const val EXTRA_MODE = "baluard.autofill.extra.MODE"
        const val EXTRA_TARGET_PACKAGE = "baluard.autofill.extra.TARGET_PACKAGE"
        const val MODE_DATASETS = "datasets"
        const val MODE_A11Y_PICKER = "a11y_picker"
        private const val TAG = "BaluardAutofill"
    }

    private var pickerTarget: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The service process never runs MainActivity, so the context holder
        // and the FragmentActivity host (BiometricPrompt requirement) must be
        // wired here as well.
        AppContextHolder.set(this)
        AppContextHolder.setActivity(this)
        // Mirror the app-wide FLAG_SECURE policy (peer-review finding #6):
        // the picker shows entry names/usernames and must stay out of
        // screenshots, recents and recordings when the user opted for it.
        if (!xyz.actitud.baluard.platform.ScreenshotPrefs().allowScreenshots()) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContentView(R.layout.autofill_activity)

        val mode = intent?.getStringExtra(EXTRA_MODE) ?: MODE_DATASETS
        val target = intent?.getStringExtra(EXTRA_TARGET)
        if (target == null) {
            finish()
            return
        }

        if (mode == MODE_A11Y_PICKER) {
            pickerTarget = target
            startA11yPickerFlow(target)
            return
        }

        // ── Dataset mode (autofill framework response-level auth) ──
        val ids = intent?.getParcelableArrayListExtra<AutofillId>(EXTRA_IDS)
        val fields = AutofillResponseBuilder.TargetFields(
            usernameId = ids?.getOrNull(0),
            passwordId = ids?.getOrNull(1),
        )
        if (fields.usernameId == null && fields.passwordId == null) {
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
        unlockThen(path) {
            AutofillSession.scope.launch {
                val response = AutofillResponseBuilder.filledResponse(
                    applicationContext,
                    fields,
                    target,
                    // Specs cached from the original request (plan 2b/S2);
                    // empty list renders popup-only, same as the direct path.
                    InlineStyle(AutofillInlineCache.specs, AutofillInlineCache.maxCount)
                        .takeIf { AutofillInlineCache.specs.isNotEmpty() },
                ) ?: AutofillResponseBuilder.saveOnlyResponse(applicationContext, fields, target)
                runOnUiThread { deliverDatasetResponse(response) }
            }
        }
    }

    // ── Shared biometric unlock (plan D5: the KEK path, never the KDF) ──

    private fun unlockThen(path: String, onUnlocked: () -> Unit) {
        val status = findViewById<TextView>(R.id.autofill_status)
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
                    runOnUiThread { onUnlocked() }
                }
            },
            onError = { _, message ->
                // User cancel (codes 5/10) and real failures both land here;
                // the message is only echoed to our own status view.
                failOnUiThread(message.ifBlank { t("autofill.unlockFailed") })
            },
        )
    }

    // ── A11Y picker mode (Phase 6.5 tile flow, plan D10/D12) ──

    private fun startA11yPickerFlow(target: String) {
        AutofillSession.scope.launch {
            if (AutofillSession.ensureOpen()) {
                // Session still inside its auto-lock window: no prompt.
                runOnUiThread { showPicker(target) }
            } else {
                val path = VaultRegistry.loadActiveVault()
                if (path == null) {
                    failOnUiThread(t("autofill.openAppToSetup"))
                    return@launch
                }
                runOnUiThread { unlockThen(path) { showPicker(target) } }
            }
        }
    }

    /** Plain-Views list of matching logins; selection rides the bridge. */
    private fun showPicker(target: String) {
        AutofillSession.scope.launch {
            val matches = AutofillSession.matches(target)
            runOnUiThread {
                statusView().visibility = View.GONE
                findViewById<View>(R.id.autofill_progress).visibility = View.GONE
                findViewById<View>(R.id.autofill_picker_scroll).visibility = View.VISIBLE
                val list = findViewById<LinearLayout>(R.id.autofill_picker_list)
                list.visibility = View.VISIBLE
                if (matches.isEmpty()) {
                    list.addView(rowText(t("a11y.noMatches")))
                } else {
                    for (match in matches) {
                        list.addView(
                            entryRow(
                                title = match.name,
                                subtitle = match.username,
                                onClick = {
                                    AutofillA11yBridge.startPendingFill(
                                        AutofillA11yBridge.PendingFill(match.id, target, targetPackage()),
                                    )
                                    finish()
                                },
                            ),
                        )
                    }
                }
                list.addView(
                    rowText(t("common.cancel")).apply {
                        setOnClickListener { finish() }
                        gravity = Gravity.CENTER
                    },
                )
            }
        }
    }

    private fun targetPackage(): String? = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)

    private fun statusView(): TextView = findViewById(R.id.autofill_status)

    private fun entryRow(title: String, subtitle: String?, onClick: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 32)
            isClickable = true
            isFocusable = true
            // System touch highlight for free a11y feedback.
            setBackgroundResource(android.R.attr.selectableItemBackground)
            setOnClickListener { onClick() }
            contentDescription = "$title, ${subtitle ?: t("autofill.noUsername")}"
        }
        val name = TextView(this).apply {
            text = title
            textSize = 16f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        val user = TextView(this).apply {
            text = subtitle?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername")
            textSize = 13f
        }
        row.addView(name)
        row.addView(user)
        return row
    }

    private fun rowText(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 15f
        setPadding(48, 32, 48, 32)
    }

    // ── Dataset-mode result delivery ──

    private fun deliverDatasetResponse(response: android.service.autofill.FillResponse) {
        val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
        setResult(RESULT_OK, result)
        finish()
        overridePendingTransition(0, 0)
    }

    private fun failOnUiThread(message: String) {
        runOnUiThread {
            findViewById<View>(R.id.autofill_progress).visibility = View.GONE
            statusView().text = message
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

    override fun onDestroy() {
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }
}
