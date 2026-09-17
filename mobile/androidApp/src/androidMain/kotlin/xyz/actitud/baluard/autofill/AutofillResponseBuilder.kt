package xyz.actitud.baluard.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.FillResponse
import android.graphics.drawable.Icon
import android.service.autofill.InlinePresentation
import android.service.autofill.Presentations
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.inline.InlinePresentationSpec
import android.widget.RemoteViews
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import xyz.actitud.baluard.R
import xyz.actitud.baluard.i18n.t

/**
 * Inline-chip parameters for one fill response (plan 2b/S2): the IME's
 * presentation specs from the original FillRequest, distributed across
 * datasets with last-spec reuse, capped like Bitwarden at 5 slots.
 */
data class InlineStyle(val specs: List<InlinePresentationSpec>, val maxCount: Int)

/**
 * Shared FillResponse construction for the service (direct path, session
 * already unlocked) and [AutofillActivity] (post-biometric path). One builder,
 * one presentation layout, save-info only where capture makes sense.
 *
 * Dataset shape (Agy review round 2): Chromium's native 3P autofill renderer
 * (Brave/Chrome 135+) only surfaces PER-FIELD presentations bound by
 * autofill id - dataset-level setValue + presentation is the legacy shape
 * and renders nothing there. Every field carries menu + dialog + inline
 * presentations from the same variant-locked views.
 */
object AutofillResponseBuilder {

    /** Fields worth filling, as passed between service and activity. */
    data class TargetFields(val usernameId: AutofillId?, val passwordId: AutofillId?) {
        val ids: Array<AutofillId>
            get() = listOfNotNull(usernameId, passwordId).toTypedArray()
    }

    /**
     * Locked-session response (plan D6). Response-level setAuthentication is
     * NOT rendered by Chromium's native path, so auth is a PER-DATASET
     * "Unlock Baluard" dataset: presentations-only fields (no values) plus
     * Dataset.setAuthentication pointing at [AutofillActivity], which runs
     * the biometric unlock and returns the real filled response. No SaveInfo
     * here: nothing has been submitted yet (device-pass finding).
     */
    fun authenticationResponse(context: Context, fields: TargetFields, target: String): FillResponse {
        val intent = Intent(context, AutofillActivity::class.java).apply {
            putExtra(AutofillActivity.EXTRA_TARGET, target)
            putParcelableArrayListExtra(AutofillActivity.EXTRA_IDS, ArrayList(fields.ids.toList()))
        }
        val pending = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val views = unlockPresentation(context)

        val dataset = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder()
                .setMenuPresentation(views)
                .setDialogPresentation(views)
                .build()
            val b = Dataset.Builder()
            for (id in fields.ids) {
                // Auth field: presentations only, no value.
                b.setField(id, Field.Builder().setPresentations(presentations).build())
            }
            b
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(views)
        }

        return FillResponse.Builder()
            .addDataset(dataset.setAuthentication(pending.intentSender).build())
            .build()
    }

    /**
     * Direct datasets for an unlocked session. One dataset per match; each
     * field carries value + presentations bound to its autofill id. When
     * [inline] carries IME specs, the fields ALSO carry a keyboard chip
     * (never instead of the menu row); unsupported IMEs silently render the
     * menu only. A final "Open Baluard" dataset is always appended
     * (Bitwarden's go-to-vault parity): zero-match or wrong-match pages keep
     * a one-tap path to the app. Returns null only when the query yielded
     * nothing, in which case the caller falls back to [saveOnlyResponse].
     */
    suspend fun filledResponse(
        context: Context,
        fields: TargetFields,
        target: String,
        inline: InlineStyle? = null,
        ignored: List<AutofillId> = emptyList(),
    ): FillResponse? {
        val matches = AutofillSession.matches(target)
        if (matches.isEmpty()) return null

        // Every matched entry is decrypted up front so each dataset carries
        // its values: inherent to multi-dataset responses (Bitwarden does the
        // same); per-dataset authentication would add a prompt per row.
        // Plan D2 holds where it matters: the QUERY never returns passwords.
        val builder = FillResponse.Builder()
        matches.forEachIndexed { index, match ->
            val (username, password) = AutofillSession.credential(match.id) ?: return@forEachIndexed
            val chip = inline?.let { inlineChipOrNull(context, it, index, match.name, username) }
            val views = datasetPresentation(context, match.name, username)
            val ds = Dataset.Builder().setId("fill-" + match.id)
            var hasValue = false

            fun addField(id: AutofillId, value: String) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val presentations = Presentations.Builder()
                        .setMenuPresentation(views)
                        .setDialogPresentation(views)
                        .apply { chip?.let { setInlinePresentation(it) } }
                        .build()
                    ds.setField(
                        id,
                        Field.Builder()
                            .setValue(AutofillValue.forText(value))
                            .setPresentations(presentations)
                            .build(),
                    )
                } else {
                    @Suppress("DEPRECATION")
                    ds.setValue(id, AutofillValue.forText(value), views)
                    chip?.let { @Suppress("DEPRECATION") ds.setInlinePresentation(it) }
                }
                hasValue = true
            }

            if (fields.usernameId != null && username != null) addField(fields.usernameId, username)
            if (fields.passwordId != null && password != null) addField(fields.passwordId, password)
            // Dataset.build() throws IllegalStateException with zero field
            // values (Agy finding #3): skip datasets that would be empty.
            if (hasValue) {
                builder.addDataset(ds.setId("fill-" + match.id).build())
            }
        }

        builder.addDataset(openBaluardDataset(context, fields, target).build())
        return applyIgnored(builder.setSaveInfo(saveInfo(fields)), ignored).build()
    }

    /**
     * Zero-match fallback: save capture (SaveInfo) plus an "Open Baluard"
     * auth dataset that opens the in-app picker - a wrong-match page is a
     * one-tap recovery instead of a dead end (Bitwarden go-to-vault parity).
     */
    fun saveOnlyResponse(
        context: Context,
        fields: TargetFields,
        target: String,
        ignored: List<AutofillId> = emptyList(),
    ): FillResponse {
        val builder = FillResponse.Builder()
            .addDataset(openBaluardDataset(context, fields, target).build())
        return applyIgnored(builder.setSaveInfo(saveInfo(fields)), ignored).build()
    }

    /**
     * Response for one manually picked entry (fallback picker flow): the
     * picker lists all logins, the chosen one is built here and returned via
     * EXTRA_AUTHENTICATION_RESULT.
     */
    suspend fun singleMatchResponse(
        context: Context,
        fields: TargetFields,
        match: AutofillSession.Match,
        inline: InlineStyle? = null,
    ): FillResponse? {
        val (username, password) = AutofillSession.credential(match.id) ?: return null
        val chip = inline?.let { inlineChipOrNull(context, it, 0, match.name, username) }
        val views = datasetPresentation(context, match.name, username)
        val ds = Dataset.Builder().setId("fill-" + match.id)
        var hasValue = false

        fun addField(id: AutofillId, value: String) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val presentations = Presentations.Builder()
                    .setMenuPresentation(views)
                    .setDialogPresentation(views)
                    .apply { chip?.let { setInlinePresentation(it) } }
                    .build()
                ds.setField(
                    id,
                    Field.Builder()
                        .setValue(AutofillValue.forText(value))
                        .setPresentations(presentations)
                        .build(),
                )
            } else {
                @Suppress("DEPRECATION")
                ds.setValue(id, AutofillValue.forText(value), views)
                chip?.let { @Suppress("DEPRECATION") ds.setInlinePresentation(it) }
            }
            hasValue = true
        }

        if (fields.usernameId != null && username != null) addField(fields.usernameId, username)
        if (fields.passwordId != null && password != null) addField(fields.passwordId, password)
        if (!hasValue) return null
        return FillResponse.Builder()
            .addDataset(ds.setId("fill-" + match.id).build())
            .setSaveInfo(saveInfo(fields))
            .build()
    }

    /**
     * TOTP auto-copy for the manually-picked entry (Bitwarden parity): after
     * selection, the entry's code goes to the clipboard with a toast.
     */
    suspend fun copyTotpFor(context: Context, match: AutofillSession.Match) {
        AutofillSession.totpCode(match.id)?.let { code ->
            xyz.actitud.baluard.platform.copyToClipboard(code)
            android.widget.Toast.makeText(
                context,
                t("a11y.totpCopied"),
                android.widget.Toast.LENGTH_SHORT,
            ).show()
        }
    }

    /**
     * "Open Baluard" auth dataset: presentations-only fields plus
     * Dataset.setAuthentication into the fallback picker. Tapping it never
     * fills; it opens Baluard's login list.
     */
    private fun openBaluardDataset(
        context: Context,
        fields: TargetFields,
        target: String,
    ): Dataset.Builder {
        val views = openBaluardPresentation(context)
        val intent = Intent(context, AutofillActivity::class.java).apply {
            putExtra(AutofillActivity.EXTRA_MODE, AutofillActivity.MODE_FALLBACK_PICK)
            putExtra(AutofillActivity.EXTRA_TARGET, target)
            putParcelableArrayListExtra(AutofillActivity.EXTRA_IDS, ArrayList(fields.ids.toList()))
        }
        val pending = PendingIntent.getActivity(
            context,
            1002,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val dataset = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder().setMenuPresentation(views).build()
            val b = Dataset.Builder()
            for (id in fields.ids) {
                b.setField(id, Field.Builder().setPresentations(presentations).build())
            }
            b
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(views)
        }
        return dataset.setAuthentication(pending.intentSender)
    }

    private fun applyIgnored(
        builder: FillResponse.Builder,
        ignored: List<AutofillId>,
    ): FillResponse.Builder {
        // setIgnoredIds is API 33+; below that the framework manages request
        // churn itself.
        if (ignored.isEmpty() || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return builder
        return builder.setIgnoredIds(*ignored.toTypedArray())
    }

    /** Password required; username optional when both exist (Agy finding #4). */
    private fun saveInfo(fields: TargetFields): SaveInfo {
        // Required: the password field (or username for username-only forms).
        // Optional: the username, so multi-step flows still save when only
        // one of the two was submitted in this step.
        val required = listOfNotNull(fields.passwordId ?: fields.usernameId)
        val optional = listOfNotNull(
            fields.usernameId?.takeIf { fields.passwordId != null && required.singleOrNull() == fields.passwordId },
        )
        val builder = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, required.toTypedArray())
        if (optional.isNotEmpty()) builder.setOptionalIds(optional.toTypedArray())
        return builder
            .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .build()
    }

    /**
     * Keyboard chip for one dataset, or null when the IME does not support
     * inline UI v1 or the spec budget ran out (silent popup fallback).
     */
    private fun inlineChipOrNull(
        context: Context,
        inline: InlineStyle,
        index: Int,
        name: String,
        username: String?,
    ): InlinePresentation? {
        val budget = (inline.maxCount - 1).coerceIn(0, 5)
        val spec = if (index < budget) inline.specs.getOrNull(index) else inline.specs.lastOrNull()
        spec ?: return null
        val styleOk = runCatching {
            UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)
        }.getOrDefault(false)
        if (!styleOk) return null
        // Placeholder launch: tapping a chip fills through the dataset itself;
        // some IMEs fire this intent for their own UI affordances.
        val pi = PendingIntent.getActivity(
            context,
            1001,
            Intent(context, xyz.actitud.baluard.MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val content = InlineSuggestionUi.newContentBuilder(pi)
            .setTitle(name)
            .setSubtitle(username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername"))
            .setStartIcon(Icon.createWithResource(context, R.mipmap.ic_launcher))
            .build()
        return InlinePresentation(content.slice, spec, false)
    }

    private fun unlockPresentation(context: Context): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, t("login.biometricTitle"))
            setTextViewText(R.id.autofill_item_subtitle, t("autofill.unlockHint"))
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }

    private fun openBaluardPresentation(context: Context): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, t("autofill.openBaluard"))
            setTextViewText(R.id.autofill_item_subtitle, t("autofill.pickLogin"))
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }

    private fun datasetPresentation(context: Context, name: String, username: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, name)
            setTextViewText(
                R.id.autofill_item_subtitle,
                username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername"),
            )
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }
}
