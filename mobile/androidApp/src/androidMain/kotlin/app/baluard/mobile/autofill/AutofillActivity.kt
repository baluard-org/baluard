package app.baluard.mobile.autofill

import android.app.ActivityOptions
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.text.Editable
import android.text.TextWatcher
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import app.baluard.mobile.MainActivity
import app.baluard.mobile.R
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.AppContextHolder
import app.baluard.mobile.platform.Biometric
import app.baluard.mobile.platform.VaultRegistry

/**
 * Trampoline + picker host for the `:autofill` process.
 *
 * Dataset mode (Phase 6 fill path): biometric ceremony, real datasets back
 * via EXTRA_AUTHENTICATION_RESULT (ADR 0090).
 * A11Y picker mode (Phase 6.5 tile flow): after the same biometric unlock,
 * a plain-Views list of matching logins; the chosen id goes back through
 * [AutofillA11yBridge] and the service types it into the target app (plan
 * D10/D12). Plain Views only, no Compose in this process (D9).
 * Fallback picker mode (zero-match popup, plan go-to-vault parity): same
 * list over ALL logins; the chosen entry comes back as an
 * EXTRA_AUTHENTICATION_RESULT dataset for the framework to fill.
 */
class AutofillActivity : FragmentActivity() {

    companion object {
        const val EXTRA_TARGET = "baluard.autofill.extra.TARGET"
        const val EXTRA_USERNAME_ID = "baluard.autofill.extra.USERNAME_ID"
        const val EXTRA_PASSWORD_ID = "baluard.autofill.extra.PASSWORD_ID"
        const val EXTRA_MODE = "baluard.autofill.extra.MODE"
        const val EXTRA_TARGET_PACKAGE = "baluard.autofill.extra.TARGET_PACKAGE"
const val EXTRA_VAULT_PATH = "baluard.autofill.extra.VAULT_PATH"
        const val MODE_DATASETS = "datasets"

        /** Search never renders more than this many rows: a vault with
         *  thousands of hits must not build a view per hit per keystroke. */
        private val MAX_SEARCH_RESULTS = 50

        private val MN_REGEX = Regex("\\p{Mn}+")
        const val MODE_A11Y_PICKER = "a11y_picker"
        const val MODE_FALLBACK_PICK = "fallback_pick"
        private const val TAG = "BaluardAutofill"
    }

    private var pickerMode: String = MODE_A11Y_PICKER
    private var pickerTarget: String? = null

    /** One load backing both views: direct matches for the default list,
     *  the full login universe for the search box. */
    private data class PickerData(
        val matches: List<AutofillSession.Match>,
        val allLogins: List<AutofillSession.Match>,
        val suggestions: List<AutofillSession.AppSuggestion>,
    )

    private var pickerData: PickerData? = null
    private var searchQuery: String = ""
    private var searchHooked = false

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
        // E2E builds skip the flag for Maestro screenshots (E12).
        if (!app.baluard.mobile.BuildConfig.BALUARD_E2E &&
            !app.baluard.mobile.platform.ScreenshotPrefs().allowScreenshots()
        ) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContentView(R.layout.autofill_activity)

        val mode = intent?.getStringExtra(EXTRA_MODE) ?: MODE_DATASETS
        val target = intent?.getStringExtra(EXTRA_TARGET)
        if (target == null) {
            finish()
            return
        }

        if (mode == MODE_A11Y_PICKER || mode == MODE_FALLBACK_PICK) {
            pickerMode = mode
            pickerTarget = target
            startPickerFlow(target, all = mode == MODE_FALLBACK_PICK)
            return
        }

        // ── Dataset mode (autofill framework response-level auth) ──
        val usernameId = intent?.getParcelableExtra<AutofillId>(EXTRA_USERNAME_ID)
        val passwordId = intent?.getParcelableExtra<AutofillId>(EXTRA_PASSWORD_ID)
        val fields = AutofillResponseBuilder.TargetFields(
            usernameId = usernameId,
            passwordId = passwordId,
        )
        if (fields.usernameId == null && fields.passwordId == null) {
            finish()
            return
        }
        val status = findViewById<TextView>(R.id.autofill_status)
        // Per-vault auth datasets pin the vault; without one, the last-active
        // vault is the unlock target (ADR 0098 §4.8).
        val path = intent?.getStringExtra(EXTRA_VAULT_PATH)
            ?: VaultRegistry.loadActiveVault()
        if (path == null) {
            status.text = t("autofill.openAppToSetup")
            openMainAndFinish()
            return
        }

        val biometric = Biometric()
        if (!biometric.isAvailable() || !biometric.isEnrolled(path)) {
            // Quick unlock was never set up (or biometrics changed). Autofill
            // has no master-password path by design (plan D5); send the user
            // to the app to enroll.
            status.text = t("autofill.openAppToSetup")
            openMainAndFinish()
            return
        }

        status.text = t("autofill.unlockHint")
        unlockThen(path) {
            AutofillSession.scope.launch {
                // The :autofill process may have died during the prompt:
                // reopen so merge eligibility and the vault map are live.
                AutofillSession.ensureOpen()
                val response = AutofillResponseBuilder.filledResponse(
                    applicationContext,
                    fields,
                    target,
                    // Specs cached from the original request (plan 2b/S2);
                    // empty list renders popup-only, same as the direct path.
                    InlineStyle(AutofillInlineCache.specs, AutofillInlineCache.maxCount)
                        .takeIf { AutofillInlineCache.specs.isNotEmpty() },
                ) ?: AutofillResponseBuilder.saveOnlyResponse(applicationContext, fields, target)
                // Bitwarden-parity clipboard copy (Claude review, minimal
                // shape): the framework sheet gives no per-dataset pick
                // callback, so copy only when exactly one match carries
                // TOTP - guessing a favorite would put the wrong entry's
                // code on the clipboard. Runs while this activity still
                // holds focus (Android 10+ drops unfocused clipboard
                // writes); the copied-toast fires from copyTotpFor.
                runCatching {
                    val totpMatches = AutofillSession.query(target).matches
                        .take(MAX_SHEET_DATASETS)
                        .filter { it.totp }
                    if (totpMatches.size == 1) {
                        AutofillResponseBuilder.copyTotpFor(applicationContext, totpMatches[0])
                    }
                }
                runOnUiThread { deliverDatasetResponse(response) }
            }
        }
    }

    // ── Shared biometric unlock (plan D5: the KEK path, never the KDF) ──

    private fun unlockThen(path: String, onUnlocked: () -> Unit) {
        val status = findViewById<TextView>(R.id.autofill_status)
        status.text = t("autofill.unlockHint")
        AutofillSession.scope.launch {
            // H12: a hardware-sealed vault can never fill from this
            // process — skip the biometric prompt the KEK path would
            // waste and hand the user to the main app with honest copy.
            if (AutofillSession.hardwareSealed(path)) {
                runOnUiThread {
                    status.text = t("autofill.securityKeyHint")
                    openMainAndFinish()
                }
                return@launch
            }
            runOnUiThread { biometricThen(path, onUnlocked) }
        }
    }

    private fun biometricThen(path: String, onUnlocked: () -> Unit) {
        val status = findViewById<TextView>(R.id.autofill_status)
        val biometric = Biometric()
        if (!biometric.isAvailable() || !biometric.isEnrolled(path)) {
            // Quick unlock was never set up (or biometrics changed). Autofill
            // has no master-password path by design (plan D5); send the user
            // to the app to enroll.
            status.text = t("autofill.openAppToSetup")
            openMainAndFinish()
            return
        }
        status.text = t("autofill.unlockHint")
        biometric.unlock(
            vaultKey = path,
            title = t("login.biometricTitle"),
            onSuccess = { kek ->
                AutofillSession.scope.launch {
                    val unlocked = AutofillSession.unlockPath(path, kek)
                    if (!unlocked) {
                        failOnUiThread(t("autofill.unlockFailed"))
                        return@launch
                    }
                    runOnUiThread { onUnlocked() }
                }
            },
            onError = { code, _ ->
                // User cancel (codes 5/10) and real failures both land here;
                // messages are localized by code — the platform actuals'
                // internal strings never reach users.
                failOnUiThread(
                    when (code) {
                        androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED,
                        androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        -> t("autofill.unlockCancelled")
                        androidx.biometric.BiometricPrompt.ERROR_LOCKOUT,
                        androidx.biometric.BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                        -> t("autofill.unlockLockedOut")
                        else -> t("autofill.unlockFailed")
                    },
                )
            },
        )
    }

    // ── Picker modes (Phase 6.5 tile flow + zero-match fallback) ──

    private fun startPickerFlow(target: String, all: Boolean) {
        AutofillSession.scope.launch {
            AutofillSession.lockIfExpired()
            if (AutofillSession.ensureOpen()) {
                // Session still inside its auto-lock window: no prompt.
                runOnUiThread { showList(target, all) }
            } else {
                val path = VaultRegistry.loadActiveVault()
                if (path == null) {
                    failOnUiThread(t("autofill.openAppToSetup"))
                    return@launch
                }
                runOnUiThread { unlockThen(path) { showList(target, all) } }
            }
        }
    }

    /**
     * Plain-Views login picker. The default view shows ONLY entries that
     * match the fill target (plus path-B app-to-web suggestions under
     * their trust banner); the search box reaches the whole vault, so the
     * old dump-everything fallback list is gone - unrelated logins were
     * the 0.2.1 noise complaint. A11Y selection rides the bridge;
     * fallback selection returns a dataset response for the framework.
     */
    private fun showList(target: String, all: Boolean) {
        AutofillSession.scope.launch {
            val result = AutofillSession.query(target)
            val logins = AutofillSession.logins()
            // Suggestion membership keys on (vault, id): a bare id match
            // would hide a same-UUID entry from a different vault.
            val suggestionKeys = result.suggestions
                .flatMap { it.matches }
                .map { it.vaultPath to it.id }
                .toSet()
            // Direct matches come daemon-ranked and are used in place:
            // refiltering logins by id would flatten that order and mix
            // same-UUID entries across vaults.
            pickerData = PickerData(
                matches = result.matches,
                allLogins = logins.filter { (it.vaultPath to it.id) !in suggestionKeys },
                suggestions = result.suggestions,
            )
            runOnUiThread { renderList(target) }
        }
    }

    /** Accent-insensitive fold so "inició" finds "inicio" (mirrors the
     *  FieldHeuristics fold). */
    internal fun fold(s: String): String =
        java.text.Normalizer.normalize(s, java.text.Normalizer.Form.NFD)
            .replace(MN_REGEX, "")

    /** Search rank: 2 = name hit, 1 = username hit, 0 = no match. Name
     *  hits outrank the rest (Bitwarden's priority model). */
    internal fun searchRank(
        m: AutofillSession.Match,
        q: String,
    ): Int =
        when {
            fold(m.name).contains(fold(q), ignoreCase = true) -> 2
            m.username?.let { fold(it).contains(fold(q), ignoreCase = true) } == true -> 1
            else -> 0
        }

    private fun renderList(target: String) {
        val matches: List<AutofillSession.Match>
        val suggestions: List<AutofillSession.AppSuggestion>
        val data = pickerData
        if (data == null) {
            matches = emptyList()
            suggestions = emptyList()
        } else {
            val q = searchQuery.trim()
            if (q.isEmpty()) {
                matches = data.matches
                suggestions = data.suggestions
            } else {
                matches = data.allLogins
                    .map { it to searchRank(it, q) }
                    .filter { it.second > 0 }
                    .sortedWith(compareBy({ -it.second }, { it.first.name.lowercase() }))
                    .map { it.first }
                    .take(MAX_SEARCH_RESULTS)
                suggestions = emptyList()
            }
        }
        statusView().visibility = View.GONE
        findViewById<View>(R.id.autofill_progress).visibility = View.GONE
        val title = findViewById<TextView>(R.id.autofill_picker_title)
        title.text = t("autofill.pickerTitle")
        title.visibility = View.VISIBLE
        findViewById<View>(R.id.autofill_picker_scroll).visibility = View.VISIBLE
        findViewById<EditText>(R.id.autofill_picker_search).apply {
            visibility = View.VISIBLE
            hint = t("autofill.searchHint")
            // After a rotation the field restores its own text while the
            // activity's field reset to empty: the box is the truth.
            val shown = text?.toString().orEmpty()
            if (shown != searchQuery) searchQuery = shown
            if (!searchHooked) {
                searchHooked = true
                addTextChangedListener(object : TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                    override fun afterTextChanged(s: Editable?) {
                        val q = s?.toString() ?: ""
                        if (q != searchQuery) {
                            searchQuery = q
                            pickerTarget?.let { renderList(it) }
                        }
                    }
                })
            }
        }
        val list = findViewById<LinearLayout>(R.id.autofill_picker_list)
        list.removeAllViews()
        val pkg = targetPackage()
        // Path-B trust banners: one per untrusted candidate domain. Tapping
        // an entry fills but records nothing; only Trust / Not-now persist
        // a decision (trust is explicit, never implied).
        for (suggestion in suggestions) {
            list.addView(
                suggestionBanner(
                    suggestion,
                    onTrust = {
                        if (pkg != null) {
                            AutofillSession.scope.launch {
                                AutofillSession.trustApp(pkg, suggestion.domain, suggestion.vaultPath)
                                showList(target, all = true)
                            }
                        }
                    },
                    onNotNow = {
                        if (pkg != null) {
                            AutofillSession.scope.launch {
                                AutofillSession.rejectApp(pkg, suggestion.domain, suggestion.vaultPath)
                                showList(target, all = true)
                            }
                        }
                    },
                ),
            )
            for (match in suggestion.matches) {
                list.addView(entryRow(match) { onPicked(target, all = true, match) })
            }
        }
        if (matches.isEmpty() && suggestions.isEmpty()) {
            list.addView(
                rowText(
                    if (searchQuery.isBlank()) t("autofill.noMatchesSearch") else t("autofill.searchEmpty"),
                ).apply { gravity = Gravity.CENTER },
            )
        }
        for (match in matches) {
            list.addView(entryRow(match) { onPicked(target, all = true, match) })
        }
        list.addView(
            rowText(t("common.cancel")).apply {
                setOnClickListener { finish() }
                gravity = Gravity.CENTER
            },
        )
    }

    /** Trust banner for one candidate domain: informative line plus
     *  explicit Trust / Not-now actions. */
    private fun suggestionBanner(
        suggestion: AutofillSession.AppSuggestion,
        onTrust: () -> Unit,
        onNotNow: () -> Unit,
    ): View {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 16)
        }
        wrap.addView(TextView(this).apply {
            text = "${t("autofill.appSuggests")} ${suggestion.domain}"
            textSize = 13f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        buttons.addView(Button(this).apply {
            text = t("autofill.appTrust")
            setOnClickListener { onTrust() }
        })
        buttons.addView(Button(this).apply {
            text = t("autofill.appNotNow")
            setOnClickListener { onNotNow() }
        })
        wrap.addView(buttons)
        return wrap
    }

    private fun onPicked(target: String, all: Boolean, match: AutofillSession.Match) {
        if (pickerMode == MODE_A11Y_PICKER) {
            // Tile flow: hand the cipher id to the service via the bridge;
            // the service types it into the target app.
            AutofillA11yBridge.startPendingFill(
                AutofillA11yBridge.PendingFill(match.id, target, targetPackage(), match.vaultPath),
            )
            finish()
            return
        }
        // Fallback flow: build the response for the picked entry, copy its
        // TOTP to the clipboard, and return it through
        // EXTRA_AUTHENTICATION_RESULT.
        AutofillSession.scope.launch {
            val usernameId = intent?.getParcelableExtra<AutofillId>(EXTRA_USERNAME_ID)
            val passwordId = intent?.getParcelableExtra<AutofillId>(EXTRA_PASSWORD_ID)
            val fields = AutofillResponseBuilder.TargetFields(
                usernameId = usernameId,
                passwordId = passwordId,
            )
            val response = AutofillResponseBuilder.singleMatchResponse(applicationContext, fields, match)
            if (response == null) {
                failOnUiThread(t("autofill.unlockFailed"))
                return@launch
            }
            AutofillResponseBuilder.copyTotpFor(applicationContext, match)
            runOnUiThread { deliverDatasetResponse(response) }
        }
    }

    private fun targetPackage(): String? {
        intent?.getStringExtra(EXTRA_TARGET_PACKAGE)?.let { return it }
        // Fallback: derive from the target itself (review finding #1).
        val target = intent?.getStringExtra(EXTRA_TARGET) ?: return null
        if (!target.startsWith("androidapp://")) return null
        return target.removePrefix("androidapp://").substringBefore('/')
    }

    private fun statusView(): TextView = findViewById(R.id.autofill_status)

    private fun Int.dp(): Int = (this * resources.displayMetrics.density).toInt()

    /** App-style card row: rounded card, teal initials avatar, bold name
     *  with a lime star for favorites, muted username - the same shape as
     *  the vault list's CipherRowCard (D9: plain Views, no Compose). */
    private fun entryRow(
        match: AutofillSession.Match,
        onClick: () -> Unit,
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(14.dp(), 12.dp(), 14.dp(), 12.dp())
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(16.dp(), 6.dp(), 16.dp(), 6.dp()) }
            background = androidx.core.content.ContextCompat.getDrawable(
                this@AutofillActivity,
                R.drawable.autofill_card_bg,
            )
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
            contentDescription = "${match.name}, ${match.username ?: t("autofill.noUsername")}"
        }
        row.addView(avatarView(match.name))

        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f,
            ).apply { marginStart = 12.dp() }
        }
        val nameLine = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        nameLine.addView(TextView(this).apply {
            text = match.name
            textSize = 16f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(
                androidx.core.content.ContextCompat.getColor(
                    this@AutofillActivity,
                    R.color.autofill_text,
                ),
            )
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f,
            )
        })
        if (match.favorite) {
            nameLine.addView(TextView(this).apply {
                text = "\u2605"
                textSize = 14f
                setTextColor(
                    androidx.core.content.ContextCompat.getColor(
                        this@AutofillActivity,
                        R.color.autofill_lime,
                    ),
                )
                contentDescription = null
            })
        }
        col.addView(nameLine)
        col.addView(TextView(this).apply {
            text = match.username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername")
            textSize = 13f
            setTextColor(
                androidx.core.content.ContextCompat.getColor(
                    this@AutofillActivity,
                    R.color.autofill_muted_text,
                ),
            )
        })
        row.addView(col)
        return row
    }

    /** 42dp rounded teal tile with the entry's initials, mirroring the
     *  app's CipherAvatar. */
    private fun avatarView(name: String): View {
        val size = 42.dp()
        val initials = name.trim().take(2).uppercase().ifEmpty { "?" }
        return FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(size, size)
            addView(View(this@AutofillActivity).apply {
                layoutParams = FrameLayout.LayoutParams(size, size)
                setBackgroundResource(R.drawable.autofill_avatar_bg)
            })
            addView(TextView(this@AutofillActivity).apply {
                text = initials
                textSize = 16f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
                setTextColor(android.graphics.Color.WHITE)
                gravity = Gravity.CENTER
                layoutParams = FrameLayout.LayoutParams(size, size)
            })
        }
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

    private fun openMainAndFinish() {
        // Guide setup: opening the app lands on unlock/quick-unroll flows.
        val launch = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        // Finish immediately: the old 1200 ms delayed finish kept this
        // translucent activity mounted while MainActivity opened, and on real
        // hardware the whole app rendered see-through over the previous app.
        // The explicit zero animation opens it at full alpha with no ramp.
        startActivity(
            launch,
            ActivityOptions.makeCustomAnimation(this, 0, 0).toBundle(),
        )
        finish()
        overridePendingTransition(0, 0)
    }

    override fun onDestroy() {
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }
}
