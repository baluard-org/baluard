package app.baluard.mobile.platform

import android.text.InputType

/**
 * Minimal view description the autofill parser needs. Decoupled from
 * `AssistStructure.ViewNode` (which cannot be constructed in JVM unit
 * tests) so [FieldHeuristics] is fully testable; the service adapts real
 * nodes onto this shape.
 */
data class FieldView(
    val autofillId: Any?,
    val hints: List<String>,
    val inputType: Int,
    val idEntry: String?,
    val hint: String?,
    val text: String?,
    val htmlAutocomplete: String?,
    val webDomain: String?,
    // Chromium compat fields carry HTML metadata via htmlInfo and NOTHING
    // else (no class name, no inputType, no hints) - these drive detection
    // for Brave/Chrome fills.
    val htmlTag: String? = null,
    val htmlType: String? = null,
    val htmlName: String? = null,
    val htmlId: String? = null,
    val htmlLabel: String? = null,
)

enum class FieldKind { Username, Password, Otp, Other }

/**
 * Layered login-form heuristics (plan P3, risk: AssistStructure variance).
 *
 * Order: html autocomplete > autofill hints > input type > keyword sniffing
 * of id > hint > text. Password checks precede username checks (a field
 * never both). Anything unrecognized is Other and ignored.
 *
 * Fail closed: only fields classified Username/Password ever receive
 * credentials.
 */
object FieldHeuristics {

    private val passwordHints = setOf("password", "current-password", "new-password")
    private val usernameHints = setOf("username", "email", "emailaddress", "e-mail")
    private val passwordKeywords = listOf("password", "passwd", "pwd", "contrase", "senha")
    private val usernameKeywords = listOf("email", "username", "user_name", "login", "account", "usuario", "correo")

    fun classify(f: FieldView): FieldKind {
        // 1. Authoritative field metadata first: HTML autocomplete, then the
        // HTML input type itself (Chromium compat exposes type=password
        // even when everything else is empty).
        when (f.htmlAutocomplete?.lowercase()?.trim()) {
            "one-time-code" -> return FieldKind.Otp
            "current-password", "new-password" -> return FieldKind.Password
            "username", "email", "login" -> return FieldKind.Username
        }
        if (f.htmlTag?.lowercase() == "input" && f.htmlType?.lowercase() == "password") {
            return FieldKind.Password
        }

        // 2. Platform autofill hints (well-behaved native apps).
        val hints = f.hints.map { it.lowercase() }
        if (hints.any { it in passwordHints } ||
            hints.contains(android.view.View.AUTOFILL_HINT_PASSWORD.lowercase())
        ) {
            return FieldKind.Password
        }
        // The documented OTP hint is the literal "smsOtpCode"; android-36
        // ships no View constant for it (grep-verified 2026-11-08).
        if ("smsotpcode" in hints) {
            return FieldKind.Otp
        }
        if (hints.any { it in usernameHints } ||
            hints.contains(android.view.View.AUTOFILL_HINT_USERNAME.lowercase()) ||
            hints.contains(android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase())
        ) {
            return FieldKind.Username
        }

        // 2b. OTP-name guard: a verification-code box must never be a fill
        // target or a promotion candidate on any path (the 2026-11-08
        // incident put a username into a TOTP box). Explicit password
        // metadata above still wins.

        // 3. Input type (works even when apps set no hints at all).
        if (isOtpField(f)) return FieldKind.Otp
        val variation = f.inputType and InputType.TYPE_MASK_VARIATION
        val cls = f.inputType and InputType.TYPE_MASK_CLASS
        if (cls == InputType.TYPE_CLASS_TEXT &&
            (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)
        ) {
            return FieldKind.Password
        }
        if (cls == InputType.TYPE_CLASS_NUMBER &&
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
        ) {
            return FieldKind.Password
        }
        if (cls == InputType.TYPE_CLASS_TEXT &&
            (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
        ) {
            return FieldKind.Username
        }

        // 4. Keywords: DOM name/id (Chromium compat), developer resource id,
        // visible hint, label, existing text. Bounded to 64 chars; text can
        // be huge.
        for (source in listOf(f.idEntry, f.htmlName, f.htmlId, f.htmlLabel, f.hint, f.text?.take(64))) {
            val s = source?.lowercase()?.trim().takeUnless { it.isNullOrEmpty() } ?: continue
            if (passwordKeywords.any { s.contains(it) }) return FieldKind.Password
            if (usernameKeywords.any { s.contains(it) }) return FieldKind.Username
        }

        // 5. A text field whose value looks like an email address is the
        // username field on real forms (reset/prefill flows), regardless of
        // what the developer named it.
        if (f.text?.contains('@') == true) return FieldKind.Username

        return FieldKind.Other
    }

    /** Diacritic fold so "Código" matches the latin-script phrase list. */
    private fun foldDiacritics(raw: String): String =
        java.text.Normalizer.normalize(raw, java.text.Normalizer.Form.NFD)
            .replace(Regex("\\p{M}+"), "")

    /** Lowercase tokens with camelCase and digit boundaries split first. */
    private fun tokens(folded: String): Set<String> {
        val spaced = StringBuilder()
        for ((i, c) in folded.withIndex()) {
            if (i > 0) {
                val prev = folded[i - 1]
                if ((c.isDigit() != prev.isDigit()) ||
                    (c.isUpperCase() && (prev.isLowerCase() || prev.isDigit()))
                ) {
                    spaced.append(' ')
                }
            }
            spaced.append(c)
        }
        return spaced.toString()
            .lowercase(java.util.Locale.ROOT)
            .split(Regex("[^a-z0-9]+"))
            .filter { it.isNotEmpty() }
            .toSet()
    }

    private val otpTokens = setOf("otp", "otc", "totp", "hotp", "2fa", "mfa")

    // Matched on the space-normalized folded form, so hyphenated and
    // spaced spellings share one entry.
    private val otpPhrases = listOf(
        "one time", "onetime", "verification code", "security code",
        "temporary code", "codigo de verificacion", "codigo de seguridad",
        "codigo temporal", "codigo enviado", "codigo de autenticacion",
        "codigo de dois fatores", "two factor", "two step", "twofactor",
        "authenticator code", "codigo unico",
    )

    private val codeTokens = setOf("code", "codigo", "token")

    private val identityTokens = setOf(
        "email", "correo", "username", "user", "login", "account", "usuario", "conta",
    )

    /**
     * True when a field names a verification-code box. Field CONTENT is
     * never metadata here: an address like a.2fa@example.com must stay a
     * username. The prose rule (code + identity wording on a label or hint)
     * covers prompts like "code sent to your email" whose identifier
     * carries no OTP token.
     */
    fun isOtpField(f: FieldView): Boolean {
        for (source in listOfNotNull(f.idEntry, f.htmlName, f.htmlId, f.htmlLabel, f.hint)) {
            val raw = source.trim().takeIf { it.isNotEmpty() } ?: continue
            val folded = foldDiacritics(raw)
            val normalized = folded.lowercase(java.util.Locale.ROOT).replace(Regex("[^a-z0-9]+"), " ").trim()
            val toks = tokens(folded)
            if (toks.any { it in otpTokens }) return true
            if (otpPhrases.any { normalized.contains(it) }) return true
            val isProse = source == f.htmlLabel || source == f.hint
            if (isProse && toks.any { it in codeTokens } && toks.any { it in identityTokens }) {
                return true
            }
        }
        return false
    }

    /**
     * Fill-request target (plan D4): web origins from the WebView's reported
     * domain (assumed https; stored URIs are https-scoped), native apps from
     * the package name.
     */
    fun targetFor(packageName: String?, webDomain: String?): String? {
        val domain = webDomain?.trim()?.lowercase()
        if (!domain.isNullOrEmpty()) return "https://$domain"
        val pkg = packageName?.trim()
        if (!pkg.isNullOrEmpty()) return "androidapp://$pkg"
        return null
    }
}
