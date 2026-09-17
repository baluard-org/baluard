package xyz.actitud.baluard.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import androidx.annotation.RequiresApi
import java.util.concurrent.Executors
import kotlinx.coroutines.runBlocking
import xyz.actitud.baluard.MainActivity
import xyz.actitud.baluard.platform.AutofillSavePrefill
import xyz.actitud.baluard.platform.FieldHeuristics
import xyz.actitud.baluard.platform.FieldKind
import xyz.actitud.baluard.platform.FieldView
import xyz.actitud.baluard.platform.platformLogE

/**
 * Baluard Android Autofill Service (plan §3.7, Phase 6).
 *
 * CRITICAL SECURITY INVARIANT (plan §3.2): this service runs as a SEPARATE OS
 * process (`:autofill`, enforced in the manifest and asserted by
 * AutofillProcessIsolationTest) with strict memory limits. It MUST unlock via
 * [AutofillSession.unlock], fed by the biometric-gated KEK from
 * [AutofillActivity]. The master-password Argon2id KDF (64-256 MB) never runs
 * here; it would OOM the process before completing.
 *
 * No network on the fill hot path: matching is `VaultState::autofill_query`
 * over the local vault only (plan D1/D9). Picker UI is RemoteViews only, no
 * Compose in this process (plan D7).
 *
 * Unlock model (plan D6): cold session -> response-level authentication, the
 * OS launches [AutofillActivity] for the BiometricPrompt ceremony, real
 * datasets come back through EXTRA_AUTHENTICATION_RESULT. Unlocked session ->
 * datasets are served directly. Every request re-checks the vault's own
 * auto-lock policy first.
 */
@RequiresApi(Build.VERSION_CODES.O)
class BaluardAutofillService : AutofillService() {

    private val executor = Executors.newSingleThreadExecutor()

    companion object {
        private const val TAG = "BaluardAutofill"
        private const val MAX_CONTAINER_DEPTH = 10

        // M10: onFailure messages can surface in system autofill diagnostics.
        // Static codes only; the real reason goes to logcat, never the callback.
        private const val ERR_NO_STRUCTURE = "no_structure"
        private const val ERR_NO_FIELDS = "no_fields"
        private const val ERR_FILL_FAILED = "fill_failed"
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            Log.w(TAG, "fill request had no structure")
            callback.onFailure(ERR_NO_STRUCTURE)
            return
        }

        executor.execute {
            try {
                val form = parseForm(structure)
                if (form == null) {
                    Log.i(TAG, "no autofillable fields; ignoring")
                    callback.onFailure(ERR_NO_FIELDS)
                    return@execute
                }

                // Inline style (plan 2b/S2): pref-gated; cache the specs for
                // the post-biometric rebuild in AutofillActivity.
                val inlineRequest = request.inlineSuggestionsRequest
                val inline = if (xyz.actitud.baluard.platform.AutofillSuggestions.inlineEnabled()) {
                    InlineStyle(
                        specs = inlineRequest?.inlinePresentationSpecs.orEmpty(),
                        maxCount = inlineRequest?.maxSuggestionCount ?: 0,
                    )
                } else null
                AutofillInlineCache.update(inline?.specs ?: emptyList(), inline?.maxCount ?: 0)

                val response = runBlocking {
                    AutofillSession.lockIfExpired()
                    if (AutofillSession.ensureOpen()) {
                        AutofillResponseBuilder.filledResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                            inline,
                            form.ignoredIds,
                        ) ?: AutofillResponseBuilder.saveOnlyResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                            form.ignoredIds,
                        )
                    } else {
                        AutofillResponseBuilder.authenticationResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                        )
                    }
                }

                if (cancellationSignal.isCanceled) return@execute
                callback.onSuccess(response)
            } catch (e: Exception) {
                Log.w(TAG, "autofill fill failed", e)
                callback.onFailure(ERR_FILL_FAILED)
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Phase 6 P4: capture the committed values and hand them to the main
        // app as a prefilled create form. The editor IS the confirmation:
        // nothing saves without the user tapping Save there.
        executor.execute {
            try {
                val captured = parseSave(request)
                if (captured != null) {
                    val launch = Intent(this, MainActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                        // One-time sandbox token: the receiving activity only
                        // honors this handoff when the token matches (spoof
                        // guard, review finding #1).
                        putExtra(MainActivity.EXTRA_SAVE_TOKEN, AutofillSaveToken.mint())
                        putExtra(MainActivity.EXTRA_SAVE_USERNAME, captured.username)
                        putExtra(MainActivity.EXTRA_SAVE_PASSWORD, captured.password)
                        putExtra(MainActivity.EXTRA_SAVE_URI, captured.uri)
                    }
                    startActivity(launch)
                }
            } catch (e: Exception) {
                Log.w(TAG, "save handoff failed", e)
            } finally {
                // Acknowledge either way: a failed capture must not wedge the
                // target app's save flow.
                callback.onSuccess()
            }
        }
    }

    /** Best-effort capture of the committed username/password plus origin. */
    private fun parseSave(request: SaveRequest): AutofillSavePrefill? {
        var username: String? = null
        var password: String? = null
        var webDomain: String? = null
        var packageName: String? = null

        for (context in request.fillContexts) {
            val structure = context.structure ?: continue
            packageName = packageName ?: structure.activityComponent?.packageName
            for (i in 0 until structure.windowNodeCount) {
                val window = structure.getWindowNodeAt(i)
                walkNode(window.rootViewNode) { node ->
                    val kind = FieldHeuristics.classify(adapt(node))
                    // autofillValue carries the value the target app actually
                    // committed; blank values (password re-type prompts) are
                    // skipped so a confirm-password field cannot win.
                    val value = node.autofillValue?.textValue?.toString()
                        ?.takeIf { it.isNotBlank() }
                    if (value != null) {
                        when (kind) {
                            FieldKind.Password -> password = password ?: value
                            FieldKind.Username -> username = username ?: value
                            FieldKind.Other -> Unit
                        }
                    }
                    if (webDomain == null) node.webDomain?.let { webDomain = it }
                }
            }
        }

        // Compat-mode masked capture guard (Bitwarden SaveInfoBuilderImpl
        // parity): browsers running in compatibility mode report bullet
        // glyphs instead of the real password - saving those would store
        // garbage. A real password can consist of those chars too, but then
        // EVERY char matches one mask glyph, which never happens by chance.
        if (password != null && password.all { it == '•' || it == '●' || it == '⋅' || it == '·' }) {
            platformLogE(TAG, "compat-mode masked password capture; skipping password only")
            password = null
        }

        if (username == null && password == null) return null
        val target = FieldHeuristics.targetFor(packageName, webDomain)
        return AutofillSavePrefill(username, password, target)
    }

    /** Parsed login form: the fields to fill plus the match target. */
    data class Form(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val target: String,
        val ignoredIds: List<AutofillId> = emptyList(),
    ) {
        val fields: AutofillResponseBuilder.TargetFields
            get() = AutofillResponseBuilder.TargetFields(usernameId, passwordId)
    }

    /**
     * Walk the AssistStructure with the layered heuristics in
     * [FieldHeuristics]. Real ViewNodes are adapted onto [FieldView] so the
     * classification logic stays unit-testable (plan P3).
     */
    private fun parseForm(structure: AssistStructure): Form? {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var webDomain: String? = null
        var urlBarText: String? = null
        // Last editable input-like field seen BEFORE the first password
        // field: the preceding-field username promotion candidate.
        var editableBeforePasswordId: AutofillId? = null
        val ignored = mutableListOf<AutofillId>()

        val packageName = structure.activityComponent?.packageName

        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            walkNode(window.rootViewNode) { node ->
                // Material TextInputLayout redirection (Bitwarden parity):
                // hint-carrying containers cannot accept values - redirect
                // to the first text-autofillable descendant.
                val container = isHintContainer(node)
                val effective = if (container) firstTextDescendant(node) else node
                val field = adapt(effective ?: node).let { fv ->
                    if (container && node.hint != null) fv.copy(hint = node.hint) else fv
                }
                val kind = FieldHeuristics.classify(field)
                val id = field.autofillId as? AutofillId
                when (kind) {
                    FieldKind.Password -> {
                        if (passwordId == null) {
                            passwordId = id
                            // Prefer the password field's own web origin.
                            node.webDomain?.let { webDomain = it }
                        }
                    }
                    FieldKind.Username -> {
                        if (usernameId == null) usernameId = id
                    }
                    FieldKind.Other -> {
                        if (id != null && isEditableInput(effective ?: node)) {
                            ignored += id
                            if (passwordId == null) editableBeforePasswordId = id
                        }
                    }
                }
                // Browser address bar fallback (plan A1/D7 starter table):
                // scrape when the page origin is missing.
                if (urlBarText == null && xyz.actitud.baluard.platform.A11yUri.isUrlBar(node.idEntry)) {
                    node.text?.toString()?.takeIf { it.isNotBlank() }?.let { urlBarText = it }
                }
                // WebView containers report the origin without being fields.
                if (webDomain == null) node.webDomain?.let { webDomain = it }
            }
        }

        // Preceding-field promotion (Bitwarden parity): password present but
        // no username signal - the editable field above it becomes username.
        if (passwordId != null && usernameId == null && editableBeforePasswordId != null) {
            usernameId = editableBeforePasswordId
            // A promoted username must not stay in the ignored list (review #2):
            // setIgnoredIds would suppress the very field we intend to fill.
            ignored.removeAll { it == usernameId }
        }

        if (usernameId == null && passwordId == null) return null
        val target = webDomain?.let { FieldHeuristics.targetFor(packageName, it) }
            ?: urlBarText?.let { xyz.actitud.baluard.platform.A11yUri.normalize(it) }
            ?: FieldHeuristics.targetFor(packageName, null)
            ?: return null
        return Form(usernameId, passwordId, target, ignored)
    }

    private fun isEditableInput(node: AssistStructure.ViewNode): Boolean =
        node.autofillType != android.view.View.AUTOFILL_TYPE_NONE &&
            node.className?.toString()?.contains("EditText") == true

    /**
     * Hint-carrying container that cannot accept values itself (Material
     * TextInputLayout pattern): redirects classification to its inner text
     * field (Bitwarden findFirstAutofillableChild parity).
     */
    private fun isHintContainer(node: AssistStructure.ViewNode): Boolean =
        node.autofillType == android.view.View.AUTOFILL_TYPE_NONE &&
            node.childCount > 0 &&
            (!node.hint.isNullOrBlank() || !node.autofillHints.isNullOrEmpty())

    private fun firstTextDescendant(
        node: AssistStructure.ViewNode,
        depth: Int = 0,
    ): AssistStructure.ViewNode? {
        if (depth > MAX_CONTAINER_DEPTH) return null
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i) ?: continue
            if (child.autofillType == android.view.View.AUTOFILL_TYPE_TEXT) return child
            firstTextDescendant(child, depth + 1)?.let { return it }
        }
        return null
    }

    private fun adapt(node: AssistStructure.ViewNode): FieldView {
        val attrs = node.htmlInfo?.attributes.orEmpty()
        fun attr(name: String): String? = attrs
            .firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

        return FieldView(
            autofillId = node.autofillId,
            hints = node.autofillHints?.toList().orEmpty(),
            inputType = node.inputType,
            idEntry = node.idEntry,
            hint = node.hint,
            text = node.text?.toString(),
            htmlAutocomplete = attr("autocomplete"),
            webDomain = node.webDomain,
            htmlTag = node.htmlInfo?.tag,
            htmlType = attr("type"),
            htmlName = attr("name"),
            htmlId = attr("id"),
            htmlLabel = attr("label"),
        )
    }

    private fun walkNode(node: AssistStructure.ViewNode, visit: (AssistStructure.ViewNode) -> Unit) {
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }
}
