package app.baluard.mobile.platform

/**
 * Login-form decision logic over flat field rows, shared by the fill path
 * and the fallback-pick return path (the layering the autofill service and
 * the picker adapter both use). AssistStructure cannot be constructed
 * off-device; the adapter surfaces [FlatField] rows and this parser owns
 * ordering, promotion, ignored ids and target resolution.
 */
/** One form row: the classified field view plus whether it accepts input. */
data class FlatField(val field: FieldView, val editable: Boolean)

object FormParser {
    /** Parsed login form: the ids to fill plus the match target. */
    data class ParsedForm(
        val usernameId: Any?,
        val passwordId: Any?,
        val target: String,
        val ignoredIds: List<Any?> = emptyList(),
    )

    /** Per-slot structure-first resolution for the pick-return dataset. */
    data class FillIds(val usernameId: Any?, val passwordId: Any?)

    fun resolveFillIds(
        structureUsername: Any?,
        structurePassword: Any?,
        pinnedUsername: Any?,
        pinnedPassword: Any?,
    ): FillIds {
        // No password slot on either side means nothing to fill (pick
        // datasets need the password); a username alone is dropped too.
        val password = structurePassword ?: pinnedPassword ?: return FillIds(null, null)
        return FillIds(
            usernameId = structureUsername ?: pinnedUsername,
            passwordId = password,
        )
    }

    fun parse(
        fields: List<FlatField>,
        packageName: String?,
        browser: Boolean,
    ): ParsedForm? {
        var usernameId: Any? = null
        var passwordId: Any? = null
        var webDomain: String? = null
        var urlBarText: String? = null
        // Last editable input-like row BEFORE the first password row: the
        // preceding-field username promotion candidate.
        var editableBeforePasswordId: Any? = null
        val ignored = mutableListOf<Any?>()

        for (row in fields) {
            val node = row.field
            when (FieldHeuristics.classify(node)) {
                FieldKind.Password -> {
                    if (passwordId == null && row.editable) {
                        passwordId = node.autofillId
                        // Browsers report per-field origins; the password
                        // field's own domain beats the document-level one.
                        if (browser) node.webDomain?.let { webDomain = it }
                    }
                }
                FieldKind.Username -> {
                    if (usernameId == null && row.editable) usernameId = node.autofillId
                }
                // A verification-code box is never a fill target, never a
                // promotion candidate, and deliberately not in the ignored
                // list (it is not a login field).
                FieldKind.Otp -> {}
                FieldKind.Other -> {
                    if (node.autofillId != null && row.editable) {
                        ignored += node.autofillId
                        // Address bars are not credential fields.
                        if (passwordId == null && !A11yUri.isUrlBar(node.idEntry)) {
                            editableBeforePasswordId = node.autofillId
                        }
                    }
                }
            }
            // Browser address bar fallback (plan A1/D7 starter table):
            // scrape when the page origin is missing, browsers only.
            if (urlBarText == null && browser && A11yUri.isUrlBar(node.idEntry)) {
                node.text?.toString()?.takeIf { it.isNotBlank() }?.let { urlBarText = it }
            }
            if (webDomain == null) node.webDomain?.let { webDomain = it }
        }

        // Preceding-field promotion (Bitwarden parity): password present but
        // no username signal - the editable row above it becomes username.
        if (passwordId != null && usernameId == null && editableBeforePasswordId != null) {
            usernameId = editableBeforePasswordId
            // A promoted row must not stay in the ignored list (review #2):
            // setIgnoredIds would suppress the very field we intend to fill.
            ignored.removeAll { it == usernameId }
        }

        if (usernameId == null && passwordId == null) return null
        val target = webDomain?.let { FieldHeuristics.targetFor(packageName, it) }
            ?: urlBarText?.let { A11yUri.normalize(it) }
            ?: FieldHeuristics.targetFor(packageName, null)
            ?: return null
        return ParsedForm(usernameId, passwordId, target, ignored)
    }
}
