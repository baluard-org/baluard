package app.baluard.mobile.autofill

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
import app.baluard.mobile.MainActivity
import app.baluard.mobile.platform.AutofillSavePrefill
import app.baluard.mobile.platform.FieldHeuristics
import app.baluard.mobile.platform.FieldKind
import app.baluard.mobile.platform.FieldView
import app.baluard.mobile.platform.platformLogE

/**
 * Baluard Android Autofill Service (plan §3.7, Phase 6).
 *
 * CRITICAL SECURITY INVARIANT (plan §3.2): this service runs as a SEPARATE OS
 * process (`:autofill`, enforced in the manifest and asserted by
 * AutofillProcessIsolationTest) with strict memory limits. It MUST unlock via
 * [AutofillSession.unlock], fed by the biometric-gated KEK from
 * [AutofillActivity]. The master-password Argon2id KDF (32-256 MiB) never runs
 * here; it would OOM the process before completing.
 *
 * No network on the fill hot path: matching is `VaultState::autofill_query`
 * over the local vault only (plan D1/D9). Picker UI is RemoteViews only, no
 * Compose in this process (plan D7).
 *
 * Unlock model (ADR 0090): cold session -> response-level authentication, the
 * OS launches [AutofillActivity] for the BiometricPrompt ceremony, real
 * datasets come back through EXTRA_AUTHENTICATION_RESULT. Unlocked session ->
 * datasets are served directly. Every request re-checks the vault's own
 * auto-lock policy first.
 */
@RequiresApi(Build.VERSION_CODES.O)
class BaluardAutofillService : AutofillService() {

    private val executor = Executors.newSingleThreadExecutor()

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "BaluardAutofill"
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
                    // Normal case (no login form on the page): an empty
                    // response tells the system to offer its own save/fill.
                    callback.onSuccess(null)
                    return@execute
                }

                // Inline style (plan 2b/S2): pref-gated; cache the specs for
                // the post-biometric rebuild in AutofillActivity.
                val inlineRequest = request.inlineSuggestionsRequest
                val inline = if (app.baluard.mobile.platform.AutofillSuggestions.inlineEnabled()) {
                    InlineStyle(
                        specs = inlineRequest?.inlinePresentationSpecs.orEmpty(),
                        maxCount = inlineRequest?.maxSuggestionCount ?: 0,
                    )
                } else null
                AutofillInlineCache.update(inline?.specs ?: emptyList(), inline?.maxCount ?: 0)

                val response = runBlocking {
                    AutofillSession.lockIfExpired()
                    // Save-capture flag policy follows the request mode: the
                    // invisibility flag is a compat-mode bridge (Bitwarden
                    // parity); sending it on native responses fires the save
                    // dialog on any view transition, submitted or not.
                    val compat = request.flags and FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST != 0
                    if (AutofillSession.ensureOpen()) {
                        AutofillResponseBuilder.filledResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                            inline,
                            form.ignoredIds,
                            compat,
                        ) ?: AutofillResponseBuilder.saveOnlyResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                            form.ignoredIds,
                            inline,
                            compat,
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
                        // The captured secret travels in the one-time sandbox
                        // token file, never in intent extras (extras live in
                        // system_server and the task base intent).
                        putExtra(
                            MainActivity.EXTRA_SAVE_TOKEN,
                            AutofillSaveToken.mint(captured.username, captured.password, captured.uri),
                        )
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
                AutofillFormParser.walkNode(window.rootViewNode) { node ->
                    val kind = FieldHeuristics.classify(AutofillFormParser.adapt(node))
                    // autofillValue carries the value the target app actually
                    // committed; blank values (password re-type prompts) are
                    // skipped so a confirm-password field cannot win.
                    val value = node.autofillValue?.textValue?.toString()
                        ?.takeIf { it.isNotBlank() }
                    if (value != null) {
                        when (kind) {
                            FieldKind.Password -> password = password ?: value
                            FieldKind.Username -> username = username ?: value
                            // A verification-code box's content is never a saved credential.
                            FieldKind.Otp -> Unit
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

    /**
     * Walk the AssistStructure with the layered heuristics in
     * [FieldHeuristics]. Real ViewNodes are adapted onto [FieldView] so the
     * classification logic stays unit-testable (plan P3).
     */
    private fun parseForm(structure: AssistStructure): AutofillFormParser.Form? =
        AutofillFormParser.parse(structure)

}
