package app.baluard.mobile.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
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
import app.baluard.mobile.R
import app.baluard.mobile.data.securityKeyChipRequired
import app.baluard.mobile.i18n.t

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
 * Dataset shape (hardening review round 2): Chromium's native 3P autofill renderer
 * (Brave/Chrome 135+) only surfaces PER-FIELD presentations bound by
 * autofill id - dataset-level setValue + presentation is the legacy shape
 * and renders nothing there. Every field carries menu + dialog + inline
 * presentations from the same variant-locked views.
 */
object AutofillResponseBuilder {

    /** Fields worth filling, as passed between service and activity. */
    data class TargetFields(val usernameId: AutofillId?, val passwordId: AutofillId?) {
        /** Separate extras, never a packed array: a password-only form would
         *  shift the password into the username slot at index 0 (review #1). */
        fun putInto(intent: Intent) {
            usernameId?.let { intent.putExtra(AutofillActivity.EXTRA_USERNAME_ID, it) }
            passwordId?.let { intent.putExtra(AutofillActivity.EXTRA_PASSWORD_ID, it) }
        }
    }

    /**
     * Locked-session response (ADR 0090). Response-level setAuthentication is
     * NOT rendered by Chromium's native path, so auth is a PER-DATASET
     * "Unlock Baluard" dataset: presentations-only fields (no values) plus
     * Dataset.setAuthentication pointing at [AutofillActivity], which runs
     * the biometric unlock and returns the real filled response. No SaveInfo
     * here: nothing has been submitted yet (device-pass finding).
     */
    fun authenticationResponse(
        context: Context,
        fields: TargetFields,
        target: String,
        securityKeyRequired: Boolean = false,
    ): FillResponse {
        val intent = if (securityKeyRequired) {
            Intent(context, app.baluard.mobile.MainActivity::class.java)
        } else {
            Intent(context, AutofillActivity::class.java).apply {
                putExtra(AutofillActivity.EXTRA_TARGET, target)
                fields.usernameId?.let { putExtra(AutofillActivity.EXTRA_USERNAME_ID, it) }
                fields.passwordId?.let { putExtra(AutofillActivity.EXTRA_PASSWORD_ID, it) }
            }
        }
        // PendingIntent identity is (filterEquals, requestCode): a shared
        // code lets a later fill request's FLAG_UPDATE_CURRENT rewrite the
        // extras of a still-visible dropdown's intent. Scope the code to
        // this request (32-bit collisions merely alias two live requests).
        val pending = PendingIntent.getActivity(
            context,
            listOf(target, fields.usernameId?.toString(), fields.passwordId?.toString())
                .joinToString("\u0000").hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val views = unlockPresentation(context, securityKeyRequired)

        val dataset = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder()
                .setMenuPresentation(views)
                .setDialogPresentation(views)
                .build()
            val b = Dataset.Builder()
            listOfNotNull(fields.usernameId, fields.passwordId).forEach { autofillId ->
                // Auth field: presentations only, no value.
                b.setField(autofillId, Field.Builder().setPresentations(presentations).build())
            }
            b
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(views)
        }

        return FillResponse.Builder()
            .addDataset(dataset.setId("baluard-unlock").setAuthentication(pending.intentSender).build())
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
        val result = AutofillSession.query(target)
        if (securityKeyChipRequired(result.securityKeyRequired, result.matches.size, result.suggestions.size)) {
            return authenticationResponse(context, fields, target, securityKeyRequired = true)
        }
        val matches = result.matches
        if (matches.isEmpty()) return null

        // Every matched entry is decrypted up front so each dataset carries
        // its values: inherent to multi-dataset responses (Bitwarden does the
        // same); per-dataset authentication would add a prompt per row.
        // Plan D2 holds where it matters: the QUERY never returns passwords.
        // G24 §4.11: vault attribution renders only when two or more vaults
        // contribute, so a single-vault user never sees merge machinery.
        val multiVault = matches.mapNotNull { it.vaultPath }.distinct().size > 1
        val builder = FillResponse.Builder()
        matches.forEachIndexed { index, match ->
            val (username, password) = AutofillSession.credential(match.vaultPath, match.id) ?: return@forEachIndexed
            val title = match.vaultName
                ?.takeIf { multiVault }
                ?.let { "${match.name} ($it)" }
                ?: match.name
            val chip = inline?.let { inlineChipOrNull(context, it, index, title, username) }
            val views = datasetPresentation(context, title, username, match.totp)
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
            // values (review finding #3): skip datasets that would be empty.
            if (hasValue) {
                builder.addDataset(ds.setId("fill-" + match.id).build())
            }
        }

        // Per-vault unlock datasets (ADR 0098 §4.8): a locked
        // vault contributes nothing to the merge, but shows up here as its
        // own auth dataset - one explicit biometric prompt each.
        for ((lockedPath, lockedName) in AutofillSession.lockedVaults()) {
            builder.addDataset(
                lockedVaultDataset(context, fields, target, lockedPath, lockedName).build(),
            )
        }
        builder.addDataset(openBaluardDataset(context, fields, target).build())
        return applyIgnored(builder.setSaveInfo(saveInfo(fields)), ignored).build()
    }

    /**
     * Auth dataset for one LOCKED vault: presentations-only fields plus
     * Dataset.setAuthentication into [AutofillActivity] with the vault path
     * pinned, so the biometric prompt unlocks THAT vault's KEK.
     */
    private fun lockedVaultDataset(
        context: Context,
        fields: TargetFields,
        target: String,
        vaultPath: String,
        vaultName: String,
    ): Dataset.Builder {
        val intent = Intent(context, AutofillActivity::class.java).apply {
            putExtra(AutofillActivity.EXTRA_TARGET, target)
            putExtra(AutofillActivity.EXTRA_VAULT_PATH, vaultPath)
            fields.usernameId?.let { putExtra(AutofillActivity.EXTRA_USERNAME_ID, it) }
            fields.passwordId?.let { putExtra(AutofillActivity.EXTRA_PASSWORD_ID, it) }
        }
        // Distinct request code per (vault, request): PendingIntents with
        // the same code and filterEquals collapse, and FLAG_UPDATE_CURRENT
        // would point every locked-vault dataset at the LAST request.
        val pending = PendingIntent.getActivity(
            context,
            listOf(vaultPath, target, fields.usernameId?.toString(), fields.passwordId?.toString())
                .joinToString("\u0000").hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val views = RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(
                R.id.autofill_item_title,
                t("autofill.unlockVault", vaultName),
            )
            setTextViewText(R.id.autofill_item_subtitle, t("autofill.unlockHint"))
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }
        val ds = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder()
                .setMenuPresentation(views)
                .setDialogPresentation(views)
                .build()
            val b = Dataset.Builder()
            listOfNotNull(fields.usernameId, fields.passwordId).forEach { autofillId ->
                b.setField(autofillId, Field.Builder().setPresentations(presentations).build())
            }
            b
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(views)
        }
        // A dataset with presentation-only fields and no authentication
        // throws on build() (API 32+); the auth intent is the whole point
        // of this row.
        return ds
            .setId("unlock-" + vaultPath.hashCode())
            .setAuthentication(pending.intentSender)
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
        val (username, password) = AutofillSession.credential(match.vaultPath, match.id) ?: return null
        val chip = inline?.let { inlineChipOrNull(context, it, 0, match.name, username) }
        val views = datasetPresentation(context, match.name, username, match.totp)
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
     * selection, the entry's code goes to the clipboard with a toast. The
     * toast fires only when the write landed - Android drops clipboard
     * writes from an unfocused context, and a false "copied" would send the
     * user hunting for a code that is nowhere.
     */
    suspend fun copyTotpFor(context: Context, match: AutofillSession.Match) {
        AutofillSession.totpCode(match.vaultPath, match.id)?.let { code ->
            if (app.baluard.mobile.platform.copyToClipboard(code)) {
                // This runs on Dispatchers.Default; Toast needs a Looper.
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    android.widget.Toast.makeText(
                        context,
                        t("a11y.totpCopied"),
                        android.widget.Toast.LENGTH_SHORT,
                    ).show()
                }
            }
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
            // The picker's Trust / Not-now actions need the raw package
            // (review finding #1): without it both buttons were silent no-ops.
            if (target.startsWith("androidapp://")) {
                putExtra(
                    AutofillActivity.EXTRA_TARGET_PACKAGE,
                    target.removePrefix("androidapp://").substringBefore('/'),
                )
            }
            fields.usernameId?.let { putExtra(AutofillActivity.EXTRA_USERNAME_ID, it) }
            fields.passwordId?.let { putExtra(AutofillActivity.EXTRA_PASSWORD_ID, it) }
        }
        val pending = PendingIntent.getActivity(
            context,
            ("pick\u0000" + target + "\u0000" + fields.usernameId?.toString() + "\u0000" +
                fields.passwordId?.toString()).hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val dataset = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder().setMenuPresentation(views).build()
            val b = Dataset.Builder()
            listOfNotNull(fields.usernameId, fields.passwordId).forEach { autofillId ->
                b.setField(autofillId, Field.Builder().setPresentations(presentations).build())
            }
            b
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(views)
        }
        return dataset.setId("baluard-open").setAuthentication(pending.intentSender)
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

    /** Password required; username optional when both exist (review finding #4). */
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
            Intent(context, app.baluard.mobile.MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val content = InlineSuggestionUi.newContentBuilder(pi)
            .setTitle(name)
            .setSubtitle(username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername"))
            .setStartIcon(Icon.createWithResource(context, R.mipmap.ic_launcher))
            .build()
        return InlinePresentation(content.slice, spec, false)
    }

    private fun unlockPresentation(context: Context, securityKeyRequired: Boolean = false): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(
                R.id.autofill_item_title,
                t(if (securityKeyRequired) "autofill.securityKeyTitle" else "login.biometricTitle"),
            )
            setTextViewText(
                R.id.autofill_item_subtitle,
                t(if (securityKeyRequired) "autofill.securityKeyHint" else "autofill.unlockHint"),
            )
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }

    private fun openBaluardPresentation(context: Context): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, t("autofill.openBaluard"))
            setTextViewText(R.id.autofill_item_subtitle, t("autofill.pickLogin"))
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }

    private fun datasetPresentation(context: Context, name: String, username: String?, totp: Boolean = false): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, name)
            setTextViewText(
                R.id.autofill_item_subtitle,
                buildString {
                    append(username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername"))
                    // Static promise, never the code itself: the response
                    // RemoteViews are frozen at build time, so digits would
                    // sit stale in the sheet (Claude review Q3).
                    if (totp) append(" (").append(t("autofill.totpWillCopy")).append(")")
                },
            )
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }
}
