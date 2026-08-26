package xyz.actitud.baluard.platform

/** M7 verdict for where a URI may be sent. */
sealed interface UriVerdict {
    /** http/https: opens in the browser, no ceremony. */
    data object OpenInBrowser : UriVerdict

    /**
     * Any other scheme (mailto:, ssh:, intent://, ...): may launch another
     * app, so the user confirms first. Carries the lowercased scheme for the
     * confirmation prompt.
     */
    data class ConfirmExternal(val scheme: String) : UriVerdict

    /** No parseable scheme: refused silently. */
    data object Refuse : UriVerdict
}

/**
 * Schemes that legitimately appear WITHOUT the `//` authority marker
 * (`mailto:support@x`, `tel:+1...`). Everything else must carry `://`
 * after the scheme to count as a scheme at all.
 */
private val NON_HIERARCHICAL_SCHEMES = setOf("mailto", "tel", "sms", "geo")

/**
 * M7: vault entries (including imported ones) carry untrusted URIs. Handing
 * them straight to ACTION_VIEW lets a crafted intent:// or custom-scheme URI
 * redirect to an attacker-chosen app from a trusted tap. http/https go to the
 * browser directly; every other real scheme is confirmed by the user before
 * the launch; schemeless, bare host:port, or malformed input is refused
 * (peer-review follow-up: `myserver.local:8080` is a real shape in imported
 * vault data and must not masquerade as a "myserver.local" scheme).
 *
 * Used by the UI before calling [openUrl]. The platform actuals stay dumb
 * launchers: the decision belongs to one shared, testable place.
 */
fun classifyUri(url: String): UriVerdict {
    val trimmed = url.trim()
    if (trimmed.isEmpty()) return UriVerdict.Refuse
    val idx = trimmed.indexOf(':')
    if (idx <= 0) return UriVerdict.Refuse
    val scheme = trimmed.substring(0, idx).lowercase()
    val schemeCharsOk =
        scheme.isNotEmpty() &&
            scheme.first().isLetter() &&
            scheme.all { it.isLetterOrDigit() || it in "+-." }
    if (!schemeCharsOk) return UriVerdict.Refuse
    val hierarchical = trimmed.startsWith("//", idx + 1)
    val isRealScheme = hierarchical || scheme in NON_HIERARCHICAL_SCHEMES
    if (!isRealScheme) return UriVerdict.Refuse
    return when (scheme) {
        "http", "https" -> UriVerdict.OpenInBrowser
        else -> UriVerdict.ConfirmExternal(scheme)
    }
}
