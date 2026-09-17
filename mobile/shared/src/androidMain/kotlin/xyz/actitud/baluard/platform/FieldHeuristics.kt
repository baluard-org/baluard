package xyz.actitud.baluard.platform

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

enum class FieldKind { Username, Password, Other }

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
        if (hints.any { it in usernameHints } ||
            hints.contains(android.view.View.AUTOFILL_HINT_USERNAME.lowercase()) ||
            hints.contains(android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase())
        ) {
            return FieldKind.Username
        }

        // 3. Input type (works even when apps set no hints at all).
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
