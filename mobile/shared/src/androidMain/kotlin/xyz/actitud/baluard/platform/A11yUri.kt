package xyz.actitud.baluard.platform

/**
 * URI scraping for the accessibility fill tile (plan A1/D10, Bitwarden's
 * BrowserUtil reduced to a starter table). Browsers expose the address bar
 * as an EditText with a known resource id; everything else is matched as
 * `androidapp://<package>`. Pure Kotlin so androidUnitTest can drive it.
 */
object A11yUri {

    /** Address-bar resource-id suffixes of the browsers we recognize. */
    private val URL_BAR_SUFFIXES = listOf(
        // Chromium family (Chrome, Chromium, Brave, Edge, Vivaldi)
        "id/url_bar",
        // Firefox family (Fenix/Mozac toolbar) - also GeckoView url_bar
        "mozac_browser_toolbar_url_view",
        // Opera
        "id/url_field",
        // Samsung Internet
        "id/location_bar_edit_text",
    )

    /** Whether [viewIdResourceName] belongs to a known browser address bar. */
    fun isUrlBar(viewIdResourceName: String?): Boolean =
        viewIdResourceName != null && URL_BAR_SUFFIXES.any { viewIdResourceName.endsWith(it) }

    /**
     * The scraped URI when [viewIdResourceName] is a known address bar, else
     * null (caller falls back to the package form). [text] wins over
     * [description]; Firefox appends a localized hint after a space+dot, cut
     * at the first space since URLs never contain spaces.
     */
    fun fromBrowserBar(
        viewIdResourceName: String?,
        text: String?,
        description: String?,
    ): String? {
        if (viewIdResourceName == null) return null
        val isBar = URL_BAR_SUFFIXES.any { viewIdResourceName.endsWith(it) }
        if (!isBar) return null
        return normalize(text) ?: normalize(description)
    }

    /**
     * Normalize an address-bar string into a matchable URI. A URL never
     * contains spaces, so anything after the first space (Firefox's
     * " . Search or enter address" suffix, page titles) is dropped. Scheme
     * less inputs get https://; strings without a dot are not URLs.
     */
    fun normalize(raw: String?): String? {
        val trimmed = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val candidate = trimmed.substringBefore(" ")
        if (!candidate.contains('.')) return null
        return when {
            candidate.contains("://") -> candidate
            else -> "https://$candidate"
        }
    }

    /** Native app matching target (plan D4). */
    fun forPackage(pkg: String): String = "androidapp://$pkg"
}
