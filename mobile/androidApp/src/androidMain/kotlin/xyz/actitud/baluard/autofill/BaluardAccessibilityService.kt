package xyz.actitud.baluard.autofill

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.annotation.RequiresApi
import kotlinx.coroutines.launch
import xyz.actitud.baluard.platform.A11yUri
import xyz.actitud.baluard.platform.FieldHeuristics
import xyz.actitud.baluard.platform.FieldKind
import xyz.actitud.baluard.platform.FieldView
import xyz.actitud.baluard.platform.copyToClipboard
import xyz.actitud.baluard.i18n.t

/**
 * Accessibility fill service (Phase 6.5, plan-android-accessibility-tile,
 * Bitwarden-current model). Listens ONLY for window-state changes and idles
 * unless the user armed the quick-settings fill tile
 * ([AutofillA11yBridge.parseArmed]) or a fill is pending
 * ([AutofillA11yBridge.pendingFill]). Gated by the Baluard-side opt-in flag
 * on every event; the system switch alone does nothing.
 *
 * Security posture (plan 0/§1): no draw-over permission, no field-focus
 * monitoring, content parsed strictly after an explicit user action, own
 * package + systemui + launchers exempt, nothing logged, and the
 * master-password KDF never runs here (unlock rides [AutofillSession]).
 */
@RequiresApi(Build.VERSION_CODES.N)
class BaluardAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "BaluardA11y"
        private const val MAX_DEPTH = 100
        private const val MAX_CHILDREN = 100
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || event.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        if (!xyz.actitud.baluard.platform.AccessibilityFill.enabled()) return

        val pkg = event.packageName?.toString() ?: return
        if (isExempt(pkg)) return

        val fill = AutofillA11yBridge.pendingFill
        if (fill != null) {
            // TTL: a pick made for the screen in front of the user must
            // never type into a page navigated to later.
            if (!AutofillA11yBridge.fresh(fill.createdAt)) {
                AutofillA11yBridge.clear()
                return
            }
            if (pkg == fill.targetPackage) performFill(fill)
            return
        }
        if (AutofillA11yBridge.parseArmed) {
            if (!AutofillA11yBridge.fresh(AutofillA11yBridge.parseArmedAt)) {
                AutofillA11yBridge.parseArmed = false
                AutofillA11yBridge.parseArmedAt = 0L
                return
            }
            parseAndPick(pkg)
        }
    }

    override fun onInterrupt() = Unit

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        // Service torn down (user disabled it system-side): never leave an
        // armed action behind.
        AutofillA11yBridge.clear()
        return super.onUnbind(intent)
    }

    /** Packages the service must never act on. */
    private fun isExempt(pkg: String): Boolean {
        if (pkg == packageName) return true
        if (pkg == "com.android.systemui") return true
        if (pkg.startsWith("com.google.android.launcher") ||
            pkg.startsWith("com.android.launcher")
        ) return true
        return false
    }

    // ── Tile armed: scrape URI + check fillable fields + open picker ──

    private fun parseAndPick(pkg: String) {
        if (!isInteractive()) {
            return // screen off: keep the arm, the user is not looking yet
        }
        val root = rootInActiveWindow ?: return
        if (root.packageName != pkg) return

        AutofillA11yBridge.parseArmed = false
        if (!hasFillableFields(root)) {
            android.widget.Toast.makeText(applicationContext, t("a11y.toastNoFields"), android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        // URL-bar text is trusted only for known browsers (a hostile app
        // can name a view id url_bar); everything else fills as its package.
        val target = (if (A11yUri.isBrowserPackage(pkg)) scrapeUri(root) else null)
        ?: A11yUri.forPackage(pkg)
        val intent = Intent(this, AutofillActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(AutofillActivity.EXTRA_MODE, AutofillActivity.MODE_A11Y_PICKER)
            putExtra(AutofillActivity.EXTRA_TARGET, target)
            putExtra(AutofillActivity.EXTRA_TARGET_PACKAGE, pkg)
        }
        startActivity(intent)
    }

    /** Browser address bar first (plan D7 starter table), package fallback. */
    private fun scrapeUri(root: AccessibilityNodeInfo): String? {
        var found: String? = null
        walk(root) { node ->
            if (found == null) {
                found = A11yUri.fromBrowserBar(
                    node.viewIdResourceName,
                    node.text?.toString(),
                    node.contentDescription?.toString(),
                )
            }
        }
        return found
    }

    private fun hasFillableFields(root: AccessibilityNodeInfo): Boolean {
        var found = false
        walk(root) { node ->
            if (!found && node.isEditable && isLoginField(node)) found = true
        }
        return found
    }

    // ── Picker selection done: fill the freshly scanned tree ──

    private fun performFill(fill: AutofillA11yBridge.PendingFill) {
        val root = rootInActiveWindow ?: return
        if (root.packageName != fill.targetPackage) return
        // Origin re-check: the fill was armed for a scraped target; the
        // current screen must still scrape to the same one, so credentials
        // can never land on a page navigated to after the pick.
        if (fill.target.startsWith("https://") && A11yUri.isBrowserPackage(fill.targetPackage)) {
            if (scrapeUri(root) != fill.target) {
                AutofillA11yBridge.clear()
                return
            }
        }
        // Only attempt on screens that actually show login fields (review
        // finding #6): never inject credentials into arbitrary inputs.
        if (!hasFillableFields(root)) return
        // Retry budget: 3 bounded attempts, then the pending fill dies (the
        // user re-taps the tile instead of risking stray fills).
        if (!AutofillA11yBridge.registerAttempt()) return

        // Session work runs off the main thread (a11y events arrive on it);
        // decrypt + clipboard must never block it (peer-review finding #1).
        AutofillSession.scope.launch {
            val (username, password) = AutofillSession.credential(fill.vaultPath, fill.cipherId)
            ?: run {
                // Reprompt-protected (or vanished): the master-password gate
                // only exists in the app.
                toastMain(t("a11y.entryNeedsApp"))
                AutofillA11yBridge.pendingFill = null
                return@launch
            }

            val filled = fillFields(root, username, password)
            if (filled) {
                AutofillA11yBridge.pendingFill = null
                AutofillA11yBridge.pendingFillAttempts = 0
                AutofillSession.totpCode(fill.vaultPath, fill.cipherId)?.let { code ->
                    copyToClipboard(code)
                    toastMain(t("a11y.totpCopied"))
                }
            }
            // Fill failed: the attempt is already counted; the budget clears
            // the pending fill after 3. Process death fails secure.
        }
    }

    private fun runOnUiThread(block: () -> Unit) {
        android.os.Handler(android.os.Looper.getMainLooper()).post(block)
    }

    private fun toastMain(message: String) {
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            android.widget.Toast.makeText(applicationContext, message, android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Fresh scan of the CURRENT tree (never reuse nodes across the activity
     * round-trip, Bitwarden's lesson). Username into the first username
     * node, password into every password node (Bitwarden parity).
     */
    private fun fillFields(
        root: AccessibilityNodeInfo,
        username: String?,
        password: String?,
    ): Boolean {
        var usernameNode: AccessibilityNodeInfo? = null
        var editableBeforePassword: AccessibilityNodeInfo? = null
        val passwordNodes = mutableListOf<AccessibilityNodeInfo>()
        walk(root) { node ->
            if (!node.isEditable) return@walk
            if (node.isPassword || kindOf(node) == FieldKind.Password) {
                passwordNodes += node
                return@walk
            }
            if (usernameNode == null && kindOf(node) == FieldKind.Username) {
                usernameNode = node
            }
            // Preceding-field promotion (Bitwarden parity): when the form
            // has password fields but no username signal, the editable node
            // directly before the first password becomes the username.
            if (usernameNode == null && passwordNodes.isEmpty()) {
                editableBeforePassword = node
            }
        }
        if (usernameNode == null && passwordNodes.isNotEmpty()) {
            usernameNode = editableBeforePassword
        }
        var any = false
        if (username != null) {
            usernameNode?.let {
                any = setText(it, username) || any
            }
        }
        if (password != null) {
            for (node in passwordNodes) {
                any = setText(node, password) || any
            }
        }
        return any
    }

    private fun setText(node: AccessibilityNodeInfo, value: String): Boolean = runCatching {
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }.getOrDefault(false)

    // ── Node classification (maps a11y nodes onto FieldHeuristics) ──

    /**
     * A11y nodes carry no inputType and no autofill hints; the platform
     * `isPassword` flag plus the keyword/value heuristics carry detection.
     */
    private fun kindOf(node: AccessibilityNodeInfo): FieldKind {
        if (node.isPassword) return FieldKind.Password
        return FieldHeuristics.classify(
            FieldView(
                autofillId = null,
                hints = emptyList(),
                inputType = 0,
                idEntry = node.viewIdResourceName,
                hint = node.hintText?.toString(),
                text = node.text?.toString(),
                htmlAutocomplete = null,
                webDomain = null,
            ),
        )
    }

    private fun isLoginField(node: AccessibilityNodeInfo): Boolean {
        if (node.isPassword) return true
        val isEditText = node.className?.toString()?.contains("EditText") == true
        if (!isEditText) return false
        return kindOf(node) != FieldKind.Other
    }

    private fun isInteractive(): Boolean = runCatching {
        (getSystemService(PowerManager::class.java))?.isInteractive ?: false
    }.getOrDefault(false)

    private fun walk(
        node: AccessibilityNodeInfo?,
        depth: Int = 0,
        visit: (AccessibilityNodeInfo) -> Unit,
    ) {
        if (node == null || depth > MAX_DEPTH) return
        visit(node)
        val count = node.childCount.coerceAtMost(MAX_CHILDREN)
        for (i in 0 until count) {
            walk(node.getChild(i), depth + 1, visit)
        }
    }
}
